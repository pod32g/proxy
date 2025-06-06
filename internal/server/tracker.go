package server

import (
	"net"
	"net/http"
	"sync"
)

// ClientTracker tracks the number of active client connections.
type ClientTracker struct {
	mu   sync.Mutex
	cnt  int
	subs map[chan int]struct{}
}

// NewClientTracker creates a new ClientTracker.
func NewClientTracker() *ClientTracker {
	return &ClientTracker{subs: make(map[chan int]struct{})}
}

// Count returns the current number of active connections.
func (c *ClientTracker) Count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cnt
}

// Subscribe returns a channel that receives connection count updates.
func (c *ClientTracker) Subscribe() chan int {
	ch := make(chan int, 1)
	c.mu.Lock()
	c.subs[ch] = struct{}{}
	ch <- c.cnt
	c.mu.Unlock()
	return ch
}

// Unsubscribe removes the channel from updates.
func (c *ClientTracker) Unsubscribe(ch chan int) {
	c.mu.Lock()
	if _, ok := c.subs[ch]; ok {
		delete(c.subs, ch)
		close(ch)
	}
	c.mu.Unlock()
}

func (c *ClientTracker) notify() {
	for ch := range c.subs {
		select {
		case ch <- c.cnt:
		default:
		}
	}
}

// ConnState is intended to be used as http.Server.ConnState callback.
func (c *ClientTracker) ConnState(_ net.Conn, state http.ConnState) {
	switch state {
	case http.StateNew:
		c.mu.Lock()
		c.cnt++
		c.notify()
		c.mu.Unlock()
	case http.StateHijacked, http.StateClosed:
		c.mu.Lock()
		if c.cnt > 0 {
			c.cnt--
		}
		c.notify()
		c.mu.Unlock()
	}
}
