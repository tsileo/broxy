package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/rivo/tview"
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

var header = "[yellow]Broxy Tunnel[white]\n\nstatus: [green]ONLINE[white]\n\n"

func main() {
	localPort := os.Args[2]
	remotePort := os.Args[3]
	name := os.Args[4]

	if err := registerApp(localPort, remotePort, name); err != nil {
		panic(err)
	}
	defer deleteApp(localPort, remotePort, name)

	app := tview.NewApplication()
	textView := tview.NewTextView().
		SetDynamicColors(true).
		SetRegions(true).
		SetWordWrap(true).
		SetChangedFunc(func() {
			app.Draw()
		})
	go func() {
		for i := range []int{1, 2, 3, 4, 5, 6, 7} {
			textView.SetText(fmt.Sprintf(header+"[green]%d[white]", i))
			time.Sleep(2 * time.Second)
		}
	}()
	if err := app.SetRoot(textView, true).Run(); err != nil {
		panic(err)
	}
}
