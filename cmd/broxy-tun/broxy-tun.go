package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"a4.io/ssse/pkg/client"
	"github.com/rivo/tview"
)

type Stats struct {
	Reqs       int    `redis:"reqs" json:"reqs"`
	Written    int    `redis:"written" json:"written"`
	CacheHit   int    `redis:"cache:hit" json:"cache_hit"`
	CacheMiss  int    `redis:"cache:miss" json:"cache_miss"`
	CacheTotal int    `redis:"cache:total" json:"cache_total"`
	ID         string `json:"id"`
	Name       string `json:"name"`
}

type App struct {
	ID         string   `json:"appid"`
	Name       string   `json:"name"`
	ServeStats bool     `json:"-"`
	Domains    []string `json:"domains"`
	Proxy      string   `json:"proxy"`
	// Move this to `static_files`
	Stats      *Stats            `json:"stats,omitempty"`
	AddHeaders map[string]string `json:"add_headers"`
}

func getApp(localPort, remotePort, name string) (*App, error) {
	appid := fmt.Sprintf("tun-%s", remotePort)
	app := &App{}
	req, err := http.NewRequest("GET", fmt.Sprintf("http://localhost:8021/app/%s", appid), nil)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	if err := json.NewDecoder(resp.Body).Decode(app); err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return app, nil
}

func registerApp(localPort, remotePort, name string) error {
	appid := fmt.Sprintf("tun-%s", remotePort)
	app := &App{
		ID:      appid,
		Name:    name,
		Domains: []string{fmt.Sprintf("%s.tun.a4.io", name)},
		Proxy:   fmt.Sprintf("http://localhost:%s", remotePort),
	}
	js, err := json.Marshal(app)
	if err != nil {
		return err
	}
	req, err := http.NewRequest("POST", fmt.Sprintf("http://localhost:8021/app/%s", appid), bytes.NewBuffer(js))
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	return nil
}

func deleteApp(localPort, remotePort, name string) error {
	appid := fmt.Sprintf("tun-%s", remotePort)
	req, err := http.NewRequest("DELETE", fmt.Sprintf("http://localhost:8021/app/%s", appid), nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	return nil
}

var header = "[yellow]Broxy Tunnel[white]\n\n"

func main() {
	args := strings.Split(os.Args[2], " ")
	localPort := args[0]
	remotePort := args[1]
	name := args[2]

	dat := header + fmt.Sprintf("\t%s.tun.a4.io -> localhost:%s\n\n", name, localPort)

	app := tview.NewApplication()
	textView := tview.NewTextView().
		SetText(dat).
		SetDynamicColors(true).
		SetRegions(true).
		SetWordWrap(true).
		SetChangedFunc(func() {
			app.Draw()
		})

	go func() {
		if err := app.SetRoot(textView, true).Run(); err != nil {
			panic(err)
		}
	}()

	if err := registerApp(localPort, remotePort, name); err != nil {
		panic(err)
	}
	defer deleteApp(localPort, remotePort, name)
	reqs := []*client.Event{}

	go func() {
		c := client.New("http://localhost:8021/pageviews")
		c.Subscribe(nil, func(msg *client.Event) error {
			reqs = append(reqs, msg)
			textView.SetText(dat + fmt.Sprintf("reqs: %d\n\n%s", len(reqs), msg.Data))
			return nil
		})
	}()

	cs := make(chan os.Signal, 1)
	signal.Notify(cs, os.Interrupt,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT)
	for {
		select {
		case <-cs:
			fmt.Println("quitting...")
			return
		}
	}
}
