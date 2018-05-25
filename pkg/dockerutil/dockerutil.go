package dockerutil

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
)

type DockerClient struct {
	client *http.Client
}

func New() *DockerClient {
	httpc := http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", "/var/run/docker.sock")
			},
		},
	}
	return &DockerClient{&httpc}
}

func (c *DockerClient) query(path string, out interface{}) error {
	resp, err := c.client.Get(fmt.Sprintf("http://unix%s", path))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	//out := []map[string]interface{}{}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return err
	}
	return nil
}

type ListOps struct {
	DockerComposeProject string
}

func (c *DockerClient) ListContainers(ops *ListOps) ([]map[string]interface{}, error) {
	out := []map[string]interface{}{}

	if err := c.query("/containers/json", &out); err != nil {
		return nil, err
	}

	if ops == nil || ops.DockerComposeProject == "" {
		return out, nil
	}

	res := []map[string]interface{}{}
	for _, container := range out {
		if strings.HasPrefix(container["Names"].([]interface{})[0].(string), "/"+ops.DockerComposeProject) {
			res = append(res, container)
		}
	}

	return res, nil
}
