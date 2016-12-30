package main

import (
	"bufio"
	"bytes"
	_ "context"
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

	"github.com/fsnotify/fsnotify"
	"github.com/garyburd/redigo/redis"
	"github.com/gorilla/mux"
	"github.com/patrickmn/go-cache"
	"github.com/tsileo/defender"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/net/context"
	_ "golang.org/x/time/rate"
	"gopkg.in/yaml.v2"
)

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
	serverName = "Broxy"
)

// secureCompare performs a constant time compare of two strings to limit timing attacks.
func secureCompare(given string, actual string) bool {
	givenSha := sha256.Sum256([]byte(given))
	actualSha := sha256.Sum256([]byte(actual))

	return subtle.ConstantTimeCompare(givenSha[:], actualSha[:]) == 1
}

type Proxy struct {
	apps      map[string]*App
	hostIndex map[string]*App

	// Some stats
	startedAt time.Time
	reqs      uint64

	cache    *cache.Cache
	defender *defender.Defender

	quit          chan struct{}
	hostWhitelist map[string]bool
	router        *mux.Router

	sync.Mutex
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
		if !p.hostWhitelist[host] {
			return errors.New("blobstash: tls host not configured")
		}
		return nil
	}
}

type App struct {
	ID                     string            `yaml:"-"`
	Name                   string            `yaml:"name"`
	ServeStats             bool              `yaml:"serve_stats"`
	Domains                []string          `yaml:"domains"`
	Proxy                  string            `yaml:"proxy"`
	Auth                   *Auth             `yaml:"auth"`
	Cache                  *Cache            `yaml:"cache"`
	DisableSecurityHeaders bool              `yaml:"disable_security_headers"`
	AddHeaders             map[string]string `yaml:"add_headers"`

	rproxy *httputil.ReverseProxy
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
	Enabled         bool          `yaml:"enabled"`
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
		c.StatusCode = []int{200, 404}
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

func (a *App) authFunc(req *http.Request) bool {
	if a.AuthEmpty() {
		return true
	}
	auth := req.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Basic ") {
		siteAuth := base64.StdEncoding.EncodeToString([]byte(a.Auth.Username + ":" + a.Auth.Password))
		if secureCompare(auth, "Basic "+siteAuth) {
			return true
		}
	}
	return false
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

func open(p string) (*App, error) {
	f, err := os.Open(p)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	data, err := ioutil.ReadAll(f)
	if err != nil {
		panic(err)
	}
	app := &App{ID: filepath.Base(p)[0 : len(filepath.Base(p))-5]}
	if err := yaml.Unmarshal(data, app); err != nil {
		panic(err)
	}
	if app.Cache == nil {
		app.Cache = &Cache{}
	}
	if err := app.Cache.Init(); err != nil {
		panic(err)
	}
	if app.Proxy != "" {
		target, err := url.Parse(app.Proxy)
		if err != nil {
			return nil, err
		}
		// borrowed from https://golang.org/src/net/http/httputil/reverseproxy.go
		targetQuery := target.RawQuery
		director := func(req *http.Request) {
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
		transport := &Transport{app: app}
		app.rproxy = &httputil.ReverseProxy{Director: director, Transport: transport}
	}

	return app, nil
}

func (p *Proxy) updateIndex(app *App) {
	p.Lock()
	defer p.Unlock()
	if oldApp, ok := p.apps[app.ID]; ok {
		for _, oldDomain := range oldApp.Domains {
			delete(p.hostWhitelist, oldDomain)
			delete(p.hostIndex, oldDomain)
		}
	}
	p.apps[app.ID] = app
	for _, domain := range app.Domains {
		p.hostIndex[domain] = app
		p.hostWhitelist[domain] = true
	}
}

func (p *Proxy) loadConfig() error {
	// Initial config loading
	d, err := os.Open("etc/proxy")
	if err != nil {
		panic(err)
	}
	fis, err := d.Readdir(-1)
	for _, fi := range fis {
		n := fi.Name()
		if strings.HasSuffix(n, ".yaml") {
			app, err := open(filepath.Join("etc/proxy", n))
			if err != nil {
				panic(err)
			}
			p.updateIndex(app)
			log.Printf("loaded app %s", app.ID)
		}
	}
	// fmt.Printf("apps=%+v\n", p.apps)

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal(err)
	}
	defer watcher.Close()

	// Handle hot-reloading
	done := make(chan bool)
	go func() {
		for {
			select {
			case <-p.quit:
				return
			case event := <-watcher.Events:
				// log.Println("event:", event)
				if event.Op&fsnotify.Write == fsnotify.Write || event.Op&fsnotify.Create == fsnotify.Create {
					// log.Println("modified file:", event.Name)
					if strings.HasSuffix(event.Name, ".yaml") {
						func() {
							app, err := open(event.Name)
							if err != nil {
								panic(err)
							}
							log.Printf("app %s reloaded", app.ID)
							p.updateIndex(app)
						}()
					}
				}
				// TODO(tsileo): handle remove
			case err := <-watcher.Errors:
				log.Println("error:", err)
			}
		}
	}()

	err = watcher.Add("./etc/proxy")
	if err != nil {
		log.Fatal(err)
	}
	<-done
	return nil
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

func redirectTLS(w http.ResponseWriter, r *http.Request) {
	r.URL.Host = r.Host
	r.URL.Scheme = "https"
	http.Redirect(w, r, r.URL.String(), http.StatusMovedPermanently)
}

func (p *Proxy) serve() {
	go func() {
		autoTLS := false
		listen := "127.0.0.1:8020"
		if autoTLS {
			// Spawn a webserver :80 to handle HTTP -> HTTPS redirections
			go func() {
				if err := http.ListenAndServe(":80", http.HandlerFunc(redirectTLS)); err != nil {
					panic(err)
				}
			}()

			// FIXME(tsileo): cache from config and listen and auto tls too
			cacheDir := autocert.DirCache("le.cache")

			m := autocert.Manager{
				// TODO(tsileo): set email
				Prompt:     autocert.AcceptTOS,
				HostPolicy: p.hostPolicy(),
				Cache:      cacheDir,
			}

			s := &http.Server{
				Addr:    listen,
				Handler: p.router,
				// FIXME(tsileo): create a custom GetCertificate wrapper to log cert generatio in Redis
				TLSConfig:    &tls.Config{GetCertificate: m.GetCertificate},
				WriteTimeout: 15 * time.Second,
				ReadTimeout:  15 * time.Second,
			}
			s.ListenAndServeTLS("", "")
		} else {
			http.ListenAndServe(listen, p.router)
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
	app *App
	// The RoundTripper interface actually used to make requests
	// If nil, http.DefaultTransport is used
	Transport http.RoundTripper
}

func (t *Transport) cacheKey(req *http.Request) string {
	return req.URL.String()
}

func (t *Transport) RoundTrip(req *http.Request) (resp *http.Response, err error) {
	transport := t.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}

	cacheable := t.app.Cache.Enabled && (req.Method == "GET" || req.Method == "HEAD") && req.Header.Get("range") == ""
	// FIXME(tsileo): handle caching header

	if cacheable {
		if data, ok := p.cache.Get(t.cacheKey(req)); ok {
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
	if cacheable && shouldCache {
		dumpedResp, err := httputil.DumpResponse(resp, true)
		if err != nil {
			return nil, err
		}
		p.cache.Set(t.cacheKey(req), dumpedResp, t.app.Cache.duration)
		resp.Header.Set("X-Cache", "MISS")
	}

	// resp.Header.Set("Server", serverName)

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

func main() {
	// TODO(tsileo): handle the config of the proxy
	pool = newPool(":6379")
	p = &Proxy{
		apps:          map[string]*App{},
		hostIndex:     map[string]*App{},
		startedAt:     time.Now(),
		cache:         cache.New(30*time.Minute, 1*time.Minute),
		quit:          make(chan struct{}),
		router:        mux.NewRouter(),
		hostWhitelist: map[string]bool{},
		defender:      defender.New(10, 30*time.Second, 45*time.Second),
	}

	con := pool.Get()
	if _, err := con.Do("PING"); err != nil {
		panic(err)
	}
	con.Close()

	// FIXME(tsileo): handle static file

	// Bind to the NotFoundHandler to catch all the requests
	// TODO(tsileo): make the rate limit configurable
	p.router.NotFoundHandler = proxyMiddleware(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		start := time.Now()

		p.Lock()
		app, appOk := p.hostIndex[r.Host]
		p.Unlock()

		host := r.Host
		ourl := r.URL.String()
		// FIXME(tsileo): only one config file
		// FIXME(tsileo): only keep the referer if the host is not in app.Domains
		referer := r.Header.Get("Referer")
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
			log.Printf("%s %s %s %s %s %s %d %s %d %s %s", app.ID, r.RemoteAddr, ua, r.Method, host, ourl, w.status, cached, w.written, referer, duration)

		}()

		if !appOk {
			// The app is not found
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(http.StatusText(http.StatusNotFound)))

		}
		if p.defender.Banned(r.RemoteAddr) {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}

		if r.URL.Path == "/_broxy_ui" {
			t, err := template.New("ui.html").ParseFiles("ui.html")
			if err != nil {
				panic(err)
			}
			appStats, err := p.appStats(All)
			if err != nil {
				panic(err)
			}
			if err := t.Execute(w, map[string]interface{}{
				"server": p.stats(),
				"apps":   appStats,
			}); err != nil {
				panic(err)
			}
			return
		}
		// TODO(tsileo): use config to enable this
		if r.URL.Path == "/_broxy_stats" {
			data, err := app.stats(All)
			if err != nil {
				panic(err)
			}
			js, err := json.Marshal(data)
			if err != nil {
				http.Error(rw, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write(js)
			return
		}

		// FIXME(tsileo): what to do about the Set-Cookie header and caching?

		// First handle auth
		if app.authFunc(r) {
			authSucceed = true
		} else {
			// Check for brute force
			if p.defender.Banned(r.RemoteAddr) {
				w.WriteHeader(http.StatusTooManyRequests)
				return
			}

			w.Header().Set("WWW-Authenticate", `Basic realm="`+app.Name+`"`)
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(http.StatusText(http.StatusUnauthorized)))
			return
		}

		// rate-limiting handling?

		// proxy handling
		app.rproxy.ServeHTTP(w, r)
		return

	}))
	go p.loadConfig()
	p.serve()
	// FIXME(tsileo): package to prevent bruteforce baisc auth, log bad ip auth and successful auth
}
