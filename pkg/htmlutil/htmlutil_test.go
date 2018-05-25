package htmlutil

import "testing"

func TestParseTitle(t *testing.T) {
	title := ParseTitle([]byte(`<html><head><title>Hello</title></head><body><h1>No</h1></body></html>`))
	if title != "Hello" {
		t.Errorf("failed to parse title, expected \"Hello\", got %q", title)
	}
}
