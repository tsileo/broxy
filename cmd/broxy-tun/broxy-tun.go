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

	tm "github.com/buger/goterm"
)

type Stats struct{}

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
	dat := header + fmt.Sprintf("fowarding: %s.tun.a4.io -> localhost:%s", name, localPort)
	tm.Println(dat)
	tm.Flush()

	if err := registerApp(localPort, remotePort, name); err != nil {
		panic(err)
	}
	defer deleteApp(localPort, remotePort, name)

	cs := make(chan os.Signal, 1)
	signal.Notify(cs, os.Interrupt,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT)
	for {
		select {
		case sig := <-cs:
			fmt.Printf("quitting", sig)
			return
		}
	}
}
