package htmlutil

import (
	"bytes"

	"golang.org/x/net/html"
)

func getTitle(doc *html.Node) *html.Node {
	var b *html.Node
	var f func(*html.Node)
	f = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "title" {
			b = n
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c)
		}
	}
	f(doc)
	if b != nil {
		return b
	}
	return nil
}

func plainText(n *html.Node) string {
	out := ""
	if n.Type == html.TextNode {
		out += n.Data
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if cout := plainText(c); cout != "" {
			out += cout
		}
	}
	return out
}

func ParseTitle(h []byte) string {
	doc, err := html.Parse(bytes.NewReader(h))
	if err != nil {
		return ""
	}
	t := getTitle(doc)
	if t == nil {
		return ""
	}
	return plainText(t)
}
