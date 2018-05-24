/*

Package server implements a server-sent event API server.

*/
package server // import "a4.io/ssse/pkg/server"

import (
	"fmt"
	"net/http"
	"sync"
	"time"
)

// SSEServer holds the broker and implement the http.Handler interface
type SSEServer struct {
	heartbeat *time.Ticker
	started   bool
	clients   map[chan *Event]bool
	mu        sync.Mutex

	newClients     chan chan *Event
	defunctClients chan chan *Event

	events chan *Event
}

// Event holds the event fields
type Event struct {
	Event string // Type of the event (i.e. "hearbeat", or you custom event type)
	Data  []byte // Data field
}

// New initialize a new server
func New() *SSEServer {
	return &SSEServer{
		heartbeat:      time.NewTicker(20 * time.Second),
		clients:        make(map[chan *Event]bool),
		newClients:     make(chan (chan *Event)),
		defunctClients: make(chan (chan *Event)),
		events:         make(chan *Event),
	}
}

// Events returns the channel as send-only, that can be used to publish events
func (s *SSEServer) Events() chan<- *Event {
	return s.events
}

// Publish publishes an event
func (s *SSEServer) Publish(event string, data []byte) {
	s.events <- &Event{Event: event, Data: data}
}

// Start start the broker and the heartbeat goroutine
func (s *SSEServer) Start() {
	s.mu.Lock()
	if s.started {
		return
	}
	s.started = true
	s.mu.Unlock()

	go func() {
		for {
			select {
			case client := <-s.newClients:
				// There is a new client attached and we
				// want to start sending them messages.
				s.mu.Lock()
				s.clients[client] = true
				s.mu.Unlock()

			case client := <-s.defunctClients:
				// A client has dettached and we want to
				// stop sending them messages.
				s.mu.Lock()
				delete(s.clients, client)
				s.mu.Unlock()
				close(client)

			case event := <-s.events:
				// There is a new message to send.  For each
				// attached client, push the new message
				// into the client's message channel.
				s.mu.Lock()
				for client := range s.clients {
					client <- event
				}
				s.mu.Unlock()
			}
		}
	}()

	// Heartbeat goroutine, needed to keep the connection alive (most browsers will close inactive connection)
	go func() {
		for {
			<-s.heartbeat.C
			// Only send the heartbeat if there is any client
			s.mu.Lock()
			clientsCnt := len(s.clients)
			s.mu.Unlock()
			if clientsCnt > 0 {
				s.events <- &Event{Event: "heartbeat"}
			}
		}
	}()
}

// ServeHTTP implements HandlerFunc
func (s *SSEServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported!", http.StatusInternalServerError)
		return
	}

	var filter map[string]struct{}
	if f := r.URL.Query().Get("event"); f != "" {
		filter = map[string]struct{}{}
		for _, evt := range r.URL.Query()["event"] {
			filter[evt] = struct{}{}
		}
	}

	eventsChan := make(chan *Event)

	s.newClients <- eventsChan

	// Get notified when the connection gets closed
	notify := w.(http.CloseNotifier).CloseNotify()
	go func() {
		<-notify
		// Remove the client
		s.defunctClients <- eventsChan
	}()

	// Set the headers related to event streaming.
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	// Send an initial heartbeat
	fmt.Fprintf(w, "event: heartbeat\ndata: \n\n")
	f.Flush()

	for {

		// Read from our messageChan.
		event, open := <-eventsChan

		if !open {
			// A closed channel means the client has disconnected
			break
		}

		if filter != nil {
			if _, ok := filter[event.Event]; !ok {
				continue
			}
		}

		// Write the response
		fmt.Fprintf(w, "event: %s\n", event.Event)
		fmt.Fprintf(w, "data: %s\n\n", event.Data)

		// Flush the response
		f.Flush()
	}
}
