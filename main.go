package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/docker/libcompose/docker"
	"github.com/docker/libcompose/docker/ctx"
	"github.com/docker/libcompose/project"
	"github.com/garyburd/redigo/redis"
	"github.com/gorilla/mux"
	"github.com/lestrrat-go/file-rotatelogs"
	"github.com/patrickmn/go-cache"
	"github.com/tsileo/broxy/pkg/req"
	"github.com/tsileo/defender"
	"github.com/ziutek/syslog"

	"golang.org/x/crypto/acme/autocert"

	"gopkg.in/yaml.v2"

	"a4.io/gluapp"
	"a4.io/ssse/pkg/server"
)

// TODO(tsileo):
// - [ ] dynamic image resizing for static image
// - [ ] PaaS like for static content assuming dns *.domain.com points to server
// - [ ] Plugin support (for serving BlobStash FS?)

type Interval int

const (
	All Interval = iota
	Year
	Month
	Day
)

var Intervals = []Interval{All, Day, Month, Year}

var iToFmt = map[Interval]string{
	Year:  "2006",
	Month: "2006-01",
	Day:   "2006-01-02",
}

func fmtTime(i Interval, t time.Time) string {
	if i == All {
		return ""
	}
	return t.Format(iToFmt[i])
}

func newPool(addr string) *redis.Pool {
	return &redis.Pool{
		MaxIdle:     3,
		IdleTimeout: 240 * time.Second,
		Dial:        func() (redis.Conn, error) { return redis.Dial("tcp", addr) },
	}
}

var (
	pool       *redis.Pool
	serverName = "Broxy (+https://github.com/tsileo/broxy)"
)

var tmpl = template.Must(template.New("main").Parse(`
<!doctype html><meta charset=utf-8>
<meta name="go-import" content="{{.ImportPrefix}} {{.VCS}} {{.RepoRoot}}">
<meta http-equiv="refresh" content="0; url=https://godoc.org/{{.URL}}">
<p>Redirecting to docs at <a href="https://godoc.org/{{.URL}}">godoc.org/{{.URL}}</a>...</p>
`))

// Remote import path config (https://golang.org/cmd/go/#hdr-Remote_import_paths)
type GoRedirector struct {
	ImportPrefix string `yaml:"import_prefix"`
	VCS          string `yaml:"vcs"`
	RepoRoot     string `yaml:"repo_root"`
}

func (gr *GoRedirector) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r.URL.Host = r.Host
	u := r.URL.String()[2:] // Remove the `//`
	d := &goRedirectorData{gr, u}
	var buf bytes.Buffer
	err := tmpl.Execute(&buf, d)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Write(buf.Bytes())
}

func (gr *GoRedirector) Check(r *http.Request) bool {
	r.URL.Host = r.Host
	return strings.HasPrefix(r.URL.String()[2:], gr.ImportPrefix)
}

type goRedirectorData struct {
	*GoRedirector
	URL string
}

type goRedirectors []*GoRedirector

func (grs goRedirectors) CheckAndServe(w http.ResponseWriter, r *http.Request) bool {
	for _, gr := range grs {
		if gr.Check(r) {
			gr.ServeHTTP(w, r)
			return true
		}
	}
	return false
}

// secureCompare performs a constant time compare of two strings to limit timing attacks.
func secureCompare(given string, actual string) bool {
	givenSha := sha256.Sum256([]byte(given))
	actualSha := sha256.Sum256([]byte(actual))

	return subtle.ConstantTimeCompare(givenSha[:], actualSha[:]) == 1
}

type Proxy struct {
	conf      *broxyConfig
	apps      map[string]*App
	hostIndex map[string]*App

	// Some stats
	startedAt time.Time
	reqs      uint64

	authDefender *defender.Defender // brute force protection
	defender     *defender.Defender

	quit          chan struct{}
	hostWhitelist map[string]bool
	router        *mux.Router
	adminMux      *mux.Router
	sse           *server.SSEServer

	sync.Mutex
}

func (p *Proxy) reset() error {
	p.Lock()
	defer p.Unlock()
	for _, oldApp := range p.apps {
		if err := oldApp.cleanup(); err != nil {
			return err
		}
	}
	p.apps = map[string]*App{}
	p.hostIndex = map[string]*App{}
	p.hostWhitelist = map[string]bool{}
	newConf, err := loadBroxyConfig("broxy.yaml")
	if err != nil {
		return err
	}

	for _, app := range newConf.Apps {
		if err := app.init(p); err != nil {
			return err
		}
		p.apps[app.ID] = app
		for _, domain := range app.Domains {
			p.hostIndex[domain] = app
			p.hostWhitelist[domain] = true
		}
	}

	return nil
}

func (p *Proxy) appStats(i Interval) ([]*stats, error) {
	p.Lock()
	defer p.Unlock()
	out := []*stats{}
	for _, app := range p.apps {
		s, err := app.stats(i)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

func (p *Proxy) stats() map[string]interface{} {
	p.Lock()
	defer p.Unlock()
	return map[string]interface{}{
		"uptime": time.Since(p.startedAt).String(),
		"reqs":   p.reqs,
	}
}

func (p *Proxy) hostPolicy() autocert.HostPolicy {
	return func(_ context.Context, host string) error {
		if p.conf.ExposeAdmin != nil {
			if host == p.conf.ExposeAdmin.Domain {
				return nil
			}
		}
		if !p.hostWhitelist[host] {
			return errors.New("blobstash: tls host not configured")
		}
		return nil
	}
}

type syslogHandler struct {
	// To simplify implementation of our handler we embed helper
	// syslog.BaseHandler struct.
	*syslog.BaseHandler
	handler func(m *syslog.Message) error
}

// Simple fiter for named/bind messages which can be used with BaseHandler
func filter(m *syslog.Message) bool {
	return true
}

func newSyslogHandler(handler func(m *syslog.Message) error) *syslogHandler {
	h := syslogHandler{syslog.NewBaseHandler(5, filter, false), handler}
	go h.mainLoop() // BaseHandler needs some gorutine that reads from its queue
	return &h
}

// mainLoop reads from BaseHandler queue using h.Get and logs messages to stdout
func (h *syslogHandler) mainLoop() {
	for {
		m := h.Get()
		if m == nil {
			break
		}
		h.handler(m)
	}
	h.End()
}

func spawnSyslogHandler(port int, handler func(m *syslog.Message) error) func() {
	// Create a server with one handler and run one listen gorutine
	s := syslog.NewServer()
	s.AddHandler(newSyslogHandler(handler))
	s.Listen(fmt.Sprintf("127.0.0.1:%d", port))
	return s.Shutdown
}

type App struct {
	ID         string   `yaml:"id" json:"appid"`
	Name       string   `yaml:"name" json:"name"`
	ServeStats bool     `yaml:"serve_stats" json:"-"`
	Domains    []string `yaml:"domains" json:"domains"`

	GoRedirectors goRedirectors `yaml:"go_redirectors" json:"-"`

	Proxy string `yaml:"proxy" json:"proxy"`

	SyslogPort     int `yaml:"syslog_port" json:"syslog_port"`
	syslogShutdown func()

	DockerComposeFile    string `yaml:"docker_compose_file" json:"-"`
	DockerComposeProject string `yaml:"docker_compose_project" json:"-"`

	// Move this to `static_files`
	Path string `yaml:"path" json:"-"`

	AppConfig *gluapp.Config `yaml:"app" json:"-"`

	Stats *stats `yaml:"-" json:"stats,omitempty"`

	Auth                   *Auth             `yaml:"auth" json:"-"`
	Cache                  *Cache            `yaml:"cache" json:"-"`
	DisableSecurityHeaders bool              `yaml:"disable_security_headers" json:"-"`
	AddHeaders             map[string]string `yaml:"add_headers" json:"add_headers"`

	rproxy    *httputil.ReverseProxy
	transport *Transport
	static    http.Handler
	app       *gluapp.App
	p         *Proxy
	log       *rotatelogs.RotateLogs
}

func (app *App) cleanup() error {
	if app.syslogShutdown != nil {
		app.syslogShutdown()
	}
	return app.log.Close()
}

func (app *App) init(p *Proxy) error {
	app.p = p
	if app.ID == "" {
		return fmt.Errorf("misisng app ID")
	}
	if app.Cache == nil {
		app.Cache = &Cache{}
	}
	if err := app.Cache.Init(); err != nil {
		return err
	}
	if app.Path != "" {
		app.static = http.FileServer(http.Dir(app.Path))
	}
	var err error

	rl, err := rotatelogs.New(
		filepath.Join(p.conf.LogsDir, app.ID+".log.%Y%m%d"),
		rotatelogs.WithLinkName(filepath.Join(p.conf.LogsDir, app.ID+".log")),
		rotatelogs.WithMaxAge(-1),
		rotatelogs.WithRotationCount(15), // TODO(tsileo): make it a config item
	)
	if err != nil {
		return err
	}
	app.log = rl

	if app.SyslogPort > 0 {
		fmt.Printf("spawning syslog server at :%d for app %v\n", app.SyslogPort, app.ID)
		app.syslogShutdown = spawnSyslogHandler(app.SyslogPort, func(m *syslog.Message) error {
			var logLine string
			if strings.HasPrefix(m.Hostname, "broxy-docker/") {
				t := m.Time.Format("2006-01-02 15:04:05")
				parts := strings.Split(m.Hostname, "/")
				logLine = fmt.Sprintf("docker-compose - %s - %s - %s %s \n", parts[1], t, strings.Join(parts[2:], "/"), m.Content)
			} else {
				logLine = "syslog - " + m.String() + "\n"
			}
			app.log.Write([]byte(logLine))
			fmt.Printf(logLine)
			return nil
		})
	}

	if app.AppConfig != nil {
		app.app, err = gluapp.NewApp(app.AppConfig)
		if err != nil {
			return err
		}
	}
	if app.Proxy != "" {
		target, err := url.Parse(app.Proxy)
		if err != nil {
			return err
		}
		// borrowed from https://golang.org/src/net/http/httputil/reverseproxy.go
		targetQuery := target.RawQuery
		director := func(req *http.Request) {
			req.Header.Set("Broxy-Req-Host", req.URL.Host)
			req.Header.Set("Broxy-Req-Scheme", req.URL.Scheme)
			req.Header.Set("Broxy-Req-Path", req.URL.Path)
			req.URL.Scheme = target.Scheme
			req.URL.Host = target.Host
			req.URL.Path = singleJoiningSlash(target.Path, req.URL.Path)
			req.Header.Set("Host", target.Host)
			if targetQuery == "" || req.URL.RawQuery == "" {
				req.URL.RawQuery = targetQuery + req.URL.RawQuery
			} else {
				req.URL.RawQuery = targetQuery + "&" + req.URL.RawQuery
			}
		}
		app.transport = &Transport{
			app:   app,
			cache: cache.New(app.Cache.duration, 1*time.Minute),
		}
		app.rproxy = &httputil.ReverseProxy{Director: director, Transport: app.transport}
	}
	return nil
}

type topStats []struct {
	Key   string `json:"key"`
	Value int    `json:"value"`
}

type stats struct {
	Reqs       int      `redis:"reqs" json:"reqs"`
	Written    int      `redis:"written" json:"written"`
	CacheHit   int      `redis:"cache:hit" json:"cache_hit"`
	CacheMiss  int      `redis:"cache:miss" json:"cache_miss"`
	CacheTotal int      `redis:"cache:total" json:"cache_total"`
	TopStatus  topStats `json:"top_status,omitempty"`
	TopPath    topStats `json:"top_path,omitempty"`
	TopMethod  topStats `json:"top_method,omitempty"`
	TopReferer topStats `json:"top_referer,omitempty"`
	ID         string   `json:"id"`
	Name       string   `json:"name"`
}

func (a *App) stats(interval Interval) (*stats, error) {
	t := time.Now()
	hkey := a.cacheKey(interval, t)
	c := pool.Get()
	defer c.Close()
	values, err := redis.Values(c.Do("HGETALL", hkey+":stats"))
	if err != nil {
		return nil, err
	}
	stats := &stats{ID: a.ID, Name: a.Name}
	if err := redis.ScanStruct(values, stats); err != nil {
		return nil, err
	}
	// scan slice to get the top
	values, err = redis.Values(c.Do("ZREVRANGE", hkey+":status", "0", "-1", "WITHSCORES"))
	if err != nil {
		return nil, err
	}
	stats.TopStatus = topStats{}
	if err := redis.ScanSlice(values, &stats.TopStatus); err != nil {
		return nil, err
	}
	// Top method
	values, err = redis.Values(c.Do("ZREVRANGE", hkey+":method", "0", "-1", "WITHSCORES"))
	if err != nil {
		return nil, err
	}
	stats.TopMethod = topStats{}
	if err := redis.ScanSlice(values, &stats.TopMethod); err != nil {
		return nil, err
	}
	// Top path
	values, err = redis.Values(c.Do("ZREVRANGE", hkey+":path", "0", "-1", "WITHSCORES"))
	if err != nil {
		return nil, err
	}
	stats.TopPath = topStats{}
	if err := redis.ScanSlice(values, &stats.TopPath); err != nil {
		return nil, err
	}
	// Top Referer
	values, err = redis.Values(c.Do("ZREVRANGE", hkey+":referer", "0", "-1", "WITHSCORES"))
	if err != nil {
		return nil, err
	}
	stats.TopReferer = topStats{}
	if err := redis.ScanSlice(values, &stats.TopReferer); err != nil {
		return nil, err
	}
	return stats, nil
}

func (a *App) cacheKey(interval Interval, t time.Time) string {
	return fmt.Sprintf("app:%s:%d:%s", a.ID, interval, fmtTime(interval, t))
}

type Cache struct {
	CacheProxy      bool          `yaml:"cache_proxy"`
	CacheApp        bool          `yaml:"cache_app"`
	Time            string        `yaml:"time"`
	duration        time.Duration `yaml:"-"`
	StatusCode      []int         `yaml:"status_code"`
	statusCodeIndex map[int]bool
}

func (c *Cache) Init() error {
	c.duration = cache.DefaultExpiration
	if c.Time != "" {
		d, err := time.ParseDuration(c.Time)
		if err != nil {
			return err
		}
		c.duration = d
	}
	if c.StatusCode == nil {
		// TODO(tsileo): default cached status code in a constant
		c.StatusCode = []int{200, 203, 204, 206, 300, 301, 404, 405, 410, 414, 501}
	}
	c.statusCodeIndex = map[int]bool{}
	for _, status := range c.StatusCode {
		c.statusCodeIndex[status] = true
	}
	return nil
}

type Auth struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

func (a *App) AuthEmpty() bool {
	return a.Auth == nil || a.Auth.Username == "" && a.Auth.Password == ""
}

func checkAuth(a *Auth, req *http.Request) bool {
	if a == nil || a.Username == "" && a.Password == "" {
		return true
	}
	auth := req.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Basic ") {
		siteAuth := base64.StdEncoding.EncodeToString([]byte(a.Username + ":" + a.Password))
		if secureCompare(auth, "Basic "+siteAuth) {
			return true
		}
	}
	return false
}

func (a *App) authFunc(req *http.Request) bool {
	return checkAuth(a.Auth, req)
}

// borrowed from https://golang.org/src/net/http/httputil/reverseproxy.go
func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}

func (p *Proxy) deleteIndex(app *App) {
	p.Lock()
	defer p.Unlock()
	if err := app.cleanup(); err != nil {
		panic(err)
	}
	if oldApp, ok := p.apps[app.ID]; ok {
		for _, oldDomain := range oldApp.Domains {
			delete(p.hostWhitelist, oldDomain)
			delete(p.hostIndex, oldDomain)
		}
		delete(p.apps, app.ID)
	}
}

func (p *Proxy) updateIndex(app *App) {
	p.deleteIndex(app)
	p.Lock()
	defer p.Unlock()
	p.apps[app.ID] = app
	for _, domain := range app.Domains {
		p.hostIndex[domain] = app
		p.hostWhitelist[domain] = true
	}
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Accept")
		w.Header().Set("Access-Control-Allow-Methods", "POST, PATCH, GET, OPTIONS, DELETE, PUT")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		if r.Method == "OPTIONS" {
			w.WriteHeader(200)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func proxyMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
	})
}

func getFreePort() int {
	addr, err := net.ResolveTCPAddr("tcp", "localhost:0")
	if err != nil {
		panic(err)
	}

	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		panic(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func (p *Proxy) apiFreePortHandler(w http.ResponseWriter, r *http.Request) {
	freePort := getFreePort()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]interface{}{"free_port": freePort}); err != nil {
		panic(err)
	}

}

func (p *Proxy) apiReloadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if err := p.reset(); err != nil {
		panic(err)
	}
	log.Printf("config reloaded via HTTP")
}

func (p *Proxy) apiAppHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	appID := vars["appid"]
	if appID == "" {
		panic("missing appid")
	}
	switch r.Method {
	case "POST":
		app := &App{ID: appID}
		if err := json.NewDecoder(r.Body).Decode(app); err != nil {
			panic(err)
		}
		app.init(p)
		p.updateIndex(app)
		fmt.Printf("app=%+v\n%+v\n", app, p.apps)
	case "DELETE":
		p.Lock()
		app, ok := p.apps[appID]
		p.Unlock()
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		p.deleteIndex(app)
		fmt.Printf("app=%+v\n%+v\n", app, p.apps)
	case "GET":
		p.Lock()
		defer p.Unlock()
		app, ok := p.apps[appID]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		stats, err := app.stats(All)
		if err != nil {
			panic(err)
		}
		app.Stats = stats
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(app); err != nil {
			panic(err)
		}
		return
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (p *Proxy) apiAppDockerComposeHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	appID := vars["appid"]
	if appID == "" {
		panic("missing appid")
	}
	switch r.Method {
	case "GET":
		p.Lock()
		defer p.Unlock()
		app, ok := p.apps[appID]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		var infos project.InfoSet
		if app.DockerComposeFile != "" {
			pctx := project.Context{
				ComposeFiles: []string{app.DockerComposeFile},
			}
			if app.DockerComposeProject != "" {
				pctx.ProjectName = app.DockerComposeProject
			}
			project, err := docker.NewProject(&ctx.Context{
				Context: pctx,
			}, nil)
			if err != nil {
				panic(err)
			}

			infos, err = project.Ps(context.Background())
			if err != nil {
				panic(err)
			}
			// TODO(tsileo): un-capitalize the keys
		}

		if err := json.NewEncoder(w).Encode(map[string]interface{}{
			"ps": infos,
		}); err != nil {
			panic(err)
		}
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (p *Proxy) apiAppCacheHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	appID := vars["appid"]
	if appID == "" {
		panic("missing appid")
	}
	switch r.Method {
	case "GET":
		p.Lock()
		defer p.Unlock()
		app, ok := p.apps[appID]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		var enabled bool
		keys := []string{}
		if app.transport != nil {
			enabled = true
			for k, _ := range app.transport.cache.Items() {
				keys = append(keys, k)
			}

		}
		if err := json.NewEncoder(w).Encode(map[string]interface{}{
			"enabled": enabled,
			"keys":    keys,
		}); err != nil {
			panic(err)
		}
	case "PURGE":
		p.Lock()
		defer p.Unlock()
		app, ok := p.apps[appID]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if app.transport == nil {
			w.WriteHeader(http.StatusBadRequest)

		}
		app.transport.FlushCache()
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (p *Proxy) serveAdminAPI() {
	log.Printf("Starting admin API on 127.0.0.1:8021")
	http.ListenAndServe("127.0.0.1:8021", p.adminMux)
}

func (p *Proxy) serve() {
	go p.serveAdminAPI()
	go func() {
		if p.conf.AutoTLS {
			// FIXME(tsileo): cache from config and listen and auto tls too
			cacheDir := autocert.DirCache("le.cache")

			m := autocert.Manager{
				// TODO(tsileo): set email
				Prompt:     autocert.AcceptTOS,
				HostPolicy: p.hostPolicy(),
				Cache:      cacheDir,
			}

			// Spawn a webserver :80 to handle HTTP -> HTTPS redirections
			go func() {
				if err := http.ListenAndServe(":http", m.HTTPHandler(nil)); err != nil {
					panic(err)
				}
			}()

			s := &http.Server{
				Addr:      ":https",
				Handler:   p.router,
				TLSConfig: &tls.Config{GetCertificate: m.GetCertificate},
			}
			s.ListenAndServeTLS("", "")
		} else {
			http.ListenAndServe(p.conf.Listen, p.router)
		}
	}()
	p.tillShutdown()
}

func (p *Proxy) tillShutdown() {
	// Listen for shutdown signal
	cs := make(chan os.Signal, 1)
	signal.Notify(cs, os.Interrupt,
		syscall.SIGHUP,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT)
	for {
		select {
		case <-cs:
			return
		case <-p.quit:
			return
		}
	}
}

type Transport struct {
	cache *cache.Cache
	app   *App
	// The RoundTripper interface actually used to make requests
	// If nil, http.DefaultTransport is used
	Transport http.RoundTripper
}

func (t *Transport) cacheKey(req *http.Request) string {
	return fmt.Sprintf("proxy:%s", req.URL.String())
}

func (t *Transport) FlushCache() {
	t.cache.Flush()
}

func (t *Transport) RoundTrip(req *http.Request) (resp *http.Response, err error) {
	transport := t.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}

	cacheable := t.app.Cache.CacheProxy && (req.Method == "GET" || req.Method == "HEAD") && req.Header.Get("range") == "" && len(req.Cookies()) == 0
	// FIXME(tsileo): handle caching header

	if cacheable {
		if data, ok := t.cache.Get(t.cacheKey(req)); ok {
			b := bytes.NewBuffer(data.([]byte))
			resp, err := http.ReadResponse(bufio.NewReader(b), req)
			resp.Header.Set("X-Cache", "HIT")
			// resp.Header.Set("Server", serverName)
			return resp, err
		}
	}

	resp, err = transport.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	_, shouldCache := t.app.Cache.statusCodeIndex[resp.StatusCode]
	shouldCache = shouldCache && len(resp.Cookies()) == 0
	if cacheable && shouldCache {
		dumpedResp, err := httputil.DumpResponse(resp, true)
		if err != nil {
			return nil, err
		}
		t.cache.Set(t.cacheKey(req), dumpedResp, t.app.Cache.duration)
		resp.Header.Set("X-Cache", "MISS")
	}

	return resp, nil
}

var p *Proxy

type responseWriter struct {
	rw      http.ResponseWriter
	app     *App
	status  int
	written int
}

func (rw *responseWriter) Header() http.Header {
	return rw.rw.Header()
}

func (rw *responseWriter) Write(data []byte) (int, error) {
	rw.written += len(data)
	return rw.rw.Write(data)
}

func (rw *responseWriter) WriteHeader(header int) {
	// Set the Server name
	rw.rw.Header().Set("Server", serverName)

	// Security headers
	if !rw.app.DisableSecurityHeaders {
		rw.rw.Header().Set("Strict-Transport-Security", "max-age=63072000; preload")
		rw.rw.Header().Set("X-Content-Type-Options", "nosniff")
		rw.rw.Header().Set("X-Frame-Options", "DENY")
		rw.rw.Header().Set("X-XSS-Protection", "1; mode=block")
		rw.rw.Header().Set("Referrer-Policy", "strict-origin")
	}

	// Custom headers
	if rw.app.AddHeaders != nil {
		for k, v := range rw.app.AddHeaders {
			rw.rw.Header().Set(k, v)
		}
	}

	// Save the status
	rw.status = header

	// Actually write the header
	rw.rw.WriteHeader(header)
}

type reqStats struct {
	path   string
	status int

	cacheHit  bool
	cacheMiss bool
}

type broxyConfig struct {
	AutoTLS     bool                `yaml:"auto_tls"`
	Listen      string              `yaml:"listen"`
	Apps        []*App              `yaml:"apps"`
	ExposeAdmin *exposeDomainConfig `yaml:"expose_admin"`
	LogsDir     string              `yaml:"logs_dir"`
}

type exposeDomainConfig struct {
	Domain string `yaml:"domain"`
	Auth   *Auth  `yaml:"auth"`
}

func loadBroxyConfig(path string) (*broxyConfig, error) {
	conf := &broxyConfig{}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, err
	}
	if err := yaml.Unmarshal(data, conf); err != nil {
		return nil, err
	}
	if conf.LogsDir != "" {
		conf.LogsDir, _ = filepath.Abs(conf.LogsDir)
	}
	return conf, nil
}

func adminAuthMiddleware(next http.Handler, conf *broxyConfig) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if checkAuth(conf.ExposeAdmin.Auth, r) {
			next.ServeHTTP(w, r)
		} else {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(http.StatusText(http.StatusUnauthorized)))

		}
	})
}

func main() {
	// TODO(tsileo): handle the config of the proxy
	pool = newPool(":6379")
	conf, err := loadBroxyConfig("broxy.yaml")
	if err != nil {
		panic(err)
	}
	sseServer := server.New()
	sseServer.Start()
	p = &Proxy{
		sse:           sseServer,
		apps:          map[string]*App{},
		hostIndex:     map[string]*App{},
		startedAt:     time.Now(),
		quit:          make(chan struct{}),
		router:        mux.NewRouter(),
		hostWhitelist: map[string]bool{},
		// 10 fails authentication in 1 hour will cause 12 hours ban
		authDefender: defender.New(10, 60*time.Minute, 12*60*time.Minute),
		// more than 50 reqs/s for 5min will cause a 12 hours ban
		defender: defender.New(15000, 300*time.Second, 12*60*time.Minute),
		conf:     conf,
	}
	p.adminMux = mux.NewRouter()
	p.adminMux.Handle("/pageviews", p.sse)
	p.adminMux.HandleFunc("/reload", p.apiReloadHandler)
	p.adminMux.HandleFunc("/app/{appid}", p.apiAppHandler)
	p.adminMux.HandleFunc("/app/{appid}/cache", p.apiAppCacheHandler)
	p.adminMux.HandleFunc("/app/{appid}/docker_compose", p.apiAppDockerComposeHandler)
	p.adminMux.HandleFunc("/free_port", p.apiFreePortHandler)

	if err := p.reset(); err != nil {
		panic(err)
	}

	q1 := make(chan struct{})
	go p.authDefender.CleanupTask(q1)
	q2 := make(chan struct{})
	go p.defender.CleanupTask(q2)

	con := pool.Get()
	if _, err := con.Do("PING"); err != nil {
		panic(err)
	}
	con.Close()

	// Bind to the NotFoundHandler to catch all the requests
	// TODO(tsileo): make the rate limit configurable

	if conf.ExposeAdmin != nil && conf.ExposeAdmin.Domain != "" {
		amux := p.router.Host(conf.ExposeAdmin.Domain).Subrouter()
		amux.Handle("/pageviews", adminAuthMiddleware(p.sse, p.conf))
		amux.Handle("/app/{appid}", adminAuthMiddleware(http.HandlerFunc(p.apiAppHandler), p.conf))
		amux.Handle("/app/{appid}/cache", adminAuthMiddleware(http.HandlerFunc(p.apiAppCacheHandler), p.conf))
		amux.Handle("/app/{appid}/docker_compose", adminAuthMiddleware(http.HandlerFunc(p.apiAppDockerComposeHandler), p.conf))
		amux.Handle("/reload", adminAuthMiddleware(http.HandlerFunc(p.apiReloadHandler), p.conf))
		amux.Handle("/free_port", adminAuthMiddleware(http.HandlerFunc(p.apiFreePortHandler), p.conf))
	}

	p.router.NotFoundHandler = proxyMiddleware(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		start := time.Now()

		p.Lock()
		app, appOk := p.hostIndex[r.Host]
		p.Unlock()

		if !appOk {
			rw.WriteHeader(http.StatusBadRequest)
			return
		}

		host := r.Host
		ourl := r.URL.String()
		// FIXME(tsileo): only one config file
		referer := ""
		if oreferer := r.Header.Get("Referer"); oreferer != "" {
			uref, err := url.Parse(oreferer)
			if err == nil {
				if uref.Host != r.Host {
					referer = oreferer
				}
			}
		}

		ua := r.Header.Get("User-Agent")
		w := &responseWriter{
			app:    app,
			rw:     rw,
			status: 200,
		}

		p.Lock()
		p.reqs++
		p.Unlock()

		var authSucceed bool

		defer func() {
			cached := w.Header().Get("X-Cache")
			if cached == "" {
				cached = "NOCACHE"
			}

			// stats handling
			c := pool.Get()
			defer c.Close()
			t := time.Now().UTC()
			c.Send("MULTI")

			// FIXME(tsileo): move this elsewhere
			c.Send("SADD", "apps", app.ID)

			for _, interval := range Intervals {
				hkey := app.cacheKey(interval, t)
				// Basic stats
				statsKey := hkey + ":stats"
				c.Send("HINCRBY", statsKey, "written", w.written)
				c.Send("HINCRBY", statsKey, "reqs", 1)
				// TODO(tsileo): other metrics?

				// Cache stats
				switch cached {
				case "HIT":
					c.Send("HINCRBY", statsKey, "cache:hit", 1)
					c.Send("HINCRBY", statsKey, "cache:total", 1)
				case "MISS":
					c.Send("HINCRBY", statsKey, "cache:miss", 1)
					c.Send("HINCRBY", statsKey, "cache:total", 1)
				}

				if !app.AuthEmpty() {
					if authSucceed {
						c.Send("HINCRBY", statsKey, "auth:success", 1)
						c.Send("ZADD", hkey+":auth:log:success", t, r.RemoteAddr)
					} else {
						c.Send("HINCRBY", statsKey, "auth:fail", 1)
						c.Send("ZADD", hkey+":auth:log:fail", t, r.RemoteAddr)
					}
				}

				// Increment the various tops
				c.Send("ZINCRBY", hkey+":status", 1, w.status)
				c.Send("ZINCRBY", hkey+":method", 1, r.Method)
				c.Send("ZINCRBY", hkey+":path", 1, r.URL.Path)
				if referer != "" {
					c.Send("ZINCRBY", hkey+":referer", 1, referer)
				}
				// XXX(tsileo): track the country with freegeoip embedded?
				// XXX(tsileo): track mobile/desktop share (via the user agent)?
			}
			if _, err := c.Do("EXEC"); err != nil {
				panic(err)
			}

			duration := time.Since(start)
			// TODO(tsileo): improve logging format
			// FIXME(tsileo): put this in a middleware
			remoteAddr := strings.Split(r.RemoteAddr, ":")[0]
			username, _, _ := r.BasicAuth()
			ereq := &req.Req{
				AppID:      app.ID,
				RemoteAddr: remoteAddr,
				Proto:      r.Proto,
				UserAgent:  ua,
				Method:     r.Method,
				Host:       host,
				URL:        ourl,
				Status:     w.status,
				Referer:    referer,
				RespTime:   duration.String(),
				RespSize:   w.written,
				Time:       start.Format(time.RFC3339),
				Username:   username,
			}
			if username == "" {
				username = "-"
			}
			// TODO(tsileo): write to a special log file for each appid (without the appid/duration, or optioal?), create broxy-tail that uses this format
			app.log.Write([]byte("req - " + ereq.ApacheFmt()))
			fmt.Printf("req - %s - %s [%s] \"%s %s %s\" %d %d \"%s\" \"%s\" %s %s\n", remoteAddr, username, start.Format("02/Jan/2006 03:04:05"), r.Method, ourl, r.Proto,
				w.status, w.written, referer, ua, app.ID, duration)
			evt, err := json.Marshal(ereq)
			if err != nil {
				panic(err)
			}
			p.sse.Publish(app.ID, evt)
		}()

		if client, ok := p.defender.Client(r.RemoteAddr); ok && client.Banned() {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if banned := p.defender.Inc(r.RemoteAddr); banned {
			// TODO(tsileo): log the ban in redis
			w.WriteHeader(http.StatusForbidden)
			return
		}

		// First handle auth
		client, ok := p.authDefender.Client(r.RemoteAddr)
		if ok && client.Banned() {
			w.WriteHeader(http.StatusForbidden)
			return
		}

		if app.authFunc(r) {
			authSucceed = true
		} else {
			// Check for brute force
			if banned := p.authDefender.Inc(r.RemoteAddr); banned {
				// FIXME(tsileo): log the ban in redis
				w.WriteHeader(http.StatusForbidden)
				return
			}
			w.Header().Set("WWW-Authenticate", `Basic realm="`+app.Name+`"`)
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(http.StatusText(http.StatusUnauthorized)))
			return
		}

		if !appOk {
			// The app is not found
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(http.StatusText(http.StatusNotFound)))

		}

		if app.GoRedirectors != nil {
			if ok := app.GoRedirectors.CheckAndServe(w, r); ok {
				return
			}
		}
		if app.app != nil {

			// FIXME(tsileo): store a cache.Cache in the app
			//cacheable := app.Cache.CacheApp && (r.Method == "GET" || r.Method == "HEAD") && r.Header.Get("range") == ""
			// FIXME(tsileo): handle caching header

			//if cacheable {
			//	if iresp, ok := p.cache.Get(fmt.Sprintf("app:%v:app:%v", app.ID, r.URL.String())); ok {
			//		resp := iresp.(*gluapp.Response)
			//		resp.Header.Set("X-Cache", "HIT")
			//		resp.WriteTo(rw)
			//		return
			//	}
			//}

			resp, err := app.app.Exec(w, r)
			if err != nil {
				panic(err)
			}
			//resp.Header.Set("X-Cache", "MISS")
			resp.WriteTo(w)

			//_, shouldCache := app.Cache.statusCodeIndex[resp.StatusCode]
			//if cacheable && shouldCache {
			//	p.cache.Set(fmt.Sprintf("app:%v:app:%v", app.ID, r.URL.String()), resp, app.Cache.duration)
			//}

			return
		}

		if app.static != nil {
			// TODO(tsileo): caching for static file?
			app.static.ServeHTTP(w, r)
			return
		}

		// FIXME(tsileo): what to do about the Set-Cookie header and caching?
		// rate-limiting handling?

		// proxy handling
		app.rproxy.ServeHTTP(w, r)
		return

	}))
	p.serve()
}
