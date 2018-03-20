package req

import (
	"fmt"
	"time"
)

// Req holds the request/response info for a Broxy request
type Req struct {
	AppID      string `json:"appid"`
	RemoteAddr string `json:"remote_addr"`
	UserAgent  string `json:"user_agent"`
	Method     string `json:"method"`
	Host       string `json:"host"`
	URL        string `json:"url"`
	Status     int    `json:"status"`
	Referer    string `json:"referer"`
	RespTime   string `json:"resp_time"`
	RespSize   int    `json:"resp_size"`
	Time       string `json:"time"`
	Proto      string `json:"proto"`
	Username   string `json:"username"`
}

// ApacheFmt returns the request formatted in the Apache Combined Log Format
func (r *Req) ApacheFmt() string {
	t, err := time.Parse(time.RFC3339, r.Time)
	if err != nil {
		panic(err)
	}
	u := r.Username
	if u == "" {
		u = "-"
	}
	return fmt.Sprintf("%s - %s [%s] \"%s %s %s\" %d %d \"%s\" \"%s\"\n", r.RemoteAddr, u, t.Format("02/Jan/2006 03:04:05"),
		r.Method, r.URL, r.Proto, r.Status, r.RespSize, r.Referer, r.UserAgent)
}
