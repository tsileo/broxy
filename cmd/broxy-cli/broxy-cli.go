package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"a4.io/ssse/pkg/client"
	"github.com/google/subcommands"
	"github.com/tsileo/broxy/pkg/req"
)

// TODO(tsileo): a "reload" subcommand, a "info" subcommand

type tunCmd struct {
	host, apiKey string
	subdomain    string
	port         int
}

func (*tunCmd) Name() string     { return "tunnel" }
func (*tunCmd) Synopsis() string { return "Create a SSH tunnel and a reverse proxy app to share it" }
func (*tunCmd) Usage() string {
	return `tunnel <port> <subdomain>:
  Create a SSH tunnel and a reverse proxy app to share it.
`
}

func (t *tunCmd) SetFlags(_ *flag.FlagSet) {
}

type freePortResp struct {
	FreePort int `json:"free_port"`
}

func (t *tunCmd) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	if f.NArg() != 2 {
		return subcommands.ExitUsageError
	}

	localPort, err := strconv.Atoi(f.Arg(0))
	if err != nil {
		panic(err)
	}

	// Query Broxy to get a free port on the remote server
	req, err := http.NewRequest("POST", t.host+"/free_port", nil)
	if err != nil {
		panic(err)
	}
	req.SetBasicAuth("", t.apiKey)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		panic(err)
	}
	fresp := &freePortResp{}
	if err := json.NewDecoder(resp.Body).Decode(fresp); err != nil {
		panic(err)
	}
	remotePort := fresp.FreePort
	appid := f.Arg(1)

	// Start the SSH tunnel, the server must have been configured to use broxy-tun as a shell
	host := strings.Split(t.host, "://")[1]
	cmd := exec.Command("ssh", "-t", "-R", fmt.Sprintf("%d:localhost:%d", remotePort, localPort), "tun@"+host, strconv.Itoa(localPort), strconv.Itoa(remotePort), appid)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	if err := cmd.Run(); err != nil {
		fmt.Printf("err=%+v\n", err)
		return subcommands.ExitFailure
	}

	return subcommands.ExitSuccess
}

type tailCmd struct {
	host, apiKey string
	appid        string
}

func (*tailCmd) Name() string     { return "tail" }
func (*tailCmd) Synopsis() string { return "Tail logs" }
func (*tailCmd) Usage() string {
	return `tail [-app <appid>]:
  Tail logs in real-time.
`
}

func (t *tailCmd) SetFlags(f *flag.FlagSet) {
	f.StringVar(&t.appid, "appid", "", "appid")
}

func (t *tailCmd) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	c := client.New(t.host + "/pageviews")
	c.Password = t.apiKey

	req := &req.Req{}
	filter := []string{}
	if t.appid != "" {
		filter = append(filter, t.appid)
	}
	if err := c.Subscribe(nil, func(e *client.Event) error {
		if err := json.Unmarshal(e.Data, req); err != nil {
			return err
		}
		// FIXME(tsileo): use ApacheFmt only if there's an appid od use the BroxyFmt
		fmt.Printf(req.ApacheFmt())
		return nil
	}, filter...); err != nil {
		panic(err)
	}

	return subcommands.ExitSuccess
}

func main() {
	host := "http://localhost:8021"
	if h := os.Getenv("BROXY_API_HOST"); h != "" {
		host = h
	}
	apiKey := ""
	if k := os.Getenv("BROXY_API_KEY"); k != "" {
		apiKey = k
	}
	subcommands.Register(subcommands.HelpCommand(), "")
	subcommands.Register(subcommands.FlagsCommand(), "")
	subcommands.Register(subcommands.CommandsCommand(), "")
	subcommands.Register(&tailCmd{host: host, apiKey: apiKey}, "")
	subcommands.Register(&tunCmd{host: host, apiKey: apiKey}, "")

	flag.Parse()
	ctx := context.Background()
	os.Exit(int(subcommands.Execute(ctx)))
}
