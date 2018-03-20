package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"a4.io/ssse/pkg/client"
	"github.com/google/subcommands"
	"github.com/tsileo/broxy/pkg/req"
)

type tailCmd struct {
	host, apiKey string
}

func (*tailCmd) Name() string     { return "tail" }
func (*tailCmd) Synopsis() string { return "Tail logs" }
func (*tailCmd) Usage() string {
	return `tail [-app <appid>]:
  Tail logs in real-time.
`
}

func (t *tailCmd) SetFlags(f *flag.FlagSet) {
	//f.BoolVar(&p.capitalize, "capitalize", false, "capitalize output")
}

func (t *tailCmd) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	c := client.New(t.host + "/pageviews")
	c.Password = t.apiKey

	req := &req.Req{}
	if err := c.Subscribe(nil, func(e *client.Event) error {
		if err := json.Unmarshal(e.Data, req); err != nil {
			return err
		}
		fmt.Printf(req.ApacheFmt())
		return nil
	}); err != nil {
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
	subcommands.Register(&tailCmd{host, apiKey}, "")

	flag.Parse()
	ctx := context.Background()
	os.Exit(int(subcommands.Execute(ctx)))
}
