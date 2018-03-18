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
	"time"

	tm "github.com/buger/goterm"
	"github.com/r3labs/sse"
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

var header = "Broxy Tunnel\n\n"

func main() {
	args := strings.Split(os.Args[2], " ")
	localPort := args[0]
	remotePort := args[1]
	name := args[2]

	tm.Clear()
	tm.MoveCursor(1, 1)
	dat := header + fmt.Sprintf("\t%s.tun.a4.io -> localhost:%s\n\n", name, localPort)
	tm.Println(dat)
	tm.Flush()

	if err := registerApp(localPort, remotePort, name); err != nil {
		panic(err)
	}
	defer deleteApp(localPort, remotePort, name)
	var reqs int

	go func() {
		client := sse.NewClient("http://localhost:8021/events")
		stream := fmt.Sprintf("tun-%s", remotePort)

		client.Subscribe(stream, func(msg *sse.Event) {
			tm.MoveCursor(1, 1)
			tm.Println(dat)
			tm.Printf("reqs: %d\n", reqs)
			tm.Printf("\n\n%s", msg.Data)
		})
	}()

	go func() {
		for {
			a, err := getApp(localPort, remotePort, name)
			if err != nil {
				panic(err)
			}
			tm.MoveCursor(1, 1)
			tm.Println(dat)
			reqs = a.Stats.Reqs
			tm.Printf("reqs: %d\n", a.Stats.Reqs)
			tm.Flush()
			time.Sleep(1 * time.Second)
		}
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
