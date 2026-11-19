package gate

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/yorvolabs/yorvogate/internal/config"
)

// One scope can't starve the others: on a scoped listener, each scope may have at most so many
// requests in flight (limits.requests, streams included) and so many connections open
// (limits.connections); and every scoped listener's connections together are bounded (limits.connections at
// the top level), whatever the number of scopes.
//
// On a token or mTLS listener a connection is no scope's until its first request authenticates:
// until then it holds one of the listener's MaxConnections slots, and once it's a scope's it holds
// one of that scope's instead, so scopes' open connections never wait behind a flood of connections
// that don't authenticate. A connection stays the scope it was first: a request on it with another
// scope's credentials is refused, and the connection closed. On scope_sockets the scope is the
// socket, and each socket accepts its scope's limit.

// slots bound what's held at once, under a limit that may change (a reload).
type slots struct {
	mu    sync.Mutex
	used  int
	limit func() int
	// Closed and replaced each time a slot is freed: what a waiter waits on
	wake chan struct{}
}

func newSlots(limit func() int) *slots {
	return &slots{limit: limit, wake: make(chan struct{})}
}

// wait takes a slot, waiting for one to be freed, until done.
func (s *slots) wait(done <-chan struct{}) bool {
	for {
		s.mu.Lock()
		if s.used < s.limit() {
			s.used++
			s.mu.Unlock()

			return true
		}

		wake := s.wake
		s.mu.Unlock()

		select {
		case <-wake:
		case <-done:
			return false
		}
	}
}

func (s *slots) give() {
	s.mu.Lock()
	s.used--
	close(s.wake)
	s.wake = make(chan struct{})
	s.mu.Unlock()
}

// totalLimit is every scoped listener's connections' bound together (LimitConnections).
var totalLimit atomic.Int64

func init() { totalLimit.Store(config.DefaultConnections) }

// total is every scoped listener's connections together.
var total = newSlots(func() int { return int(totalLimit.Load()) })

// LimitConnections bounds every scoped listener's connections together (the configuration's
// limits.connections), from the next one accepted.
func LimitConnections(n int) {
	totalLimit.Store(int64(n))
}

// scopeCounts counts what each scope holds on a listener, each under the listener's limit.
type scopeCounts struct {
	mu sync.Mutex
	n  map[string]int
}

func newScopeCounts() *scopeCounts {
	return &scopeCounts{n: map[string]int{}}
}

// take is one more for the scope, and how to give it back, or false at its limit.
func (c *scopeCounts) take(scope string, limit int) (func(), bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.n[scope] >= limit {
		return nil, false
	}

	c.n[scope]++

	var once sync.Once

	return func() {
		once.Do(func() {
			c.mu.Lock()
			defer c.mu.Unlock()

			if c.n[scope]--; c.n[scope] <= 0 {
				delete(c.n, scope)
			}
		})
	}, true
}

// of is what the scope holds now.
func (c *scopeCounts) of(scope string) int {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.n[scope]
}

// all is what every scope holds together.
func (c *scopeCounts) all() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	sum := 0
	for _, n := range c.n {
		sum += n
	}

	return sum
}

// heldKey holds, in a request's context, what it holds until it's answered (its scope's request
// slot): ServeHTTP gives it back when the request ends, whichever way.
type heldKey struct{}

type held struct {
	mu       sync.Mutex
	releases []func()
}

func (h *held) add(release func()) {
	h.mu.Lock()
	h.releases = append(h.releases, release)
	h.mu.Unlock()
}

func (h *held) release() {
	h.mu.Lock()
	releases := h.releases
	h.releases = nil
	h.mu.Unlock()

	for _, r := range releases {
		r()
	}
}

func heldOf(ctx context.Context) *held {
	h, _ := ctx.Value(heldKey{}).(*held)

	return h
}

// limited takes a request slot of the scope's for the request (until it's answered), and on a
// token or mTLS listener makes its connection the scope's: refused when the scope is at its limit,
// or when the connection is another scope's.
func (g *Gate) limited(r *http.Request, scope string) error {
	if !g.listener.SocketBound() {
		if c := limitedConnOf(r.Context()); c != nil {
			if err := c.attribute(scope, g.connections, g.listener.ScopeConnections()); err != nil {
				return err
			}
		}
	}

	limit := g.listener.ScopeRequests()

	release, ok := g.requests.take(scope, limit)
	if !ok {
		refused := refuse(http.StatusTooManyRequests, CodeScopeRequests, nowhere, allowAtMost(int64(limit), "requests"),
			"this scope has %d requests in flight, as many as this listener allows (limits.requests): retry when one ends", limit)
		refused.retryAfter = 1

		return refused
	}

	g.metrics.requestInFlight(g.listener.Name, scope, 1)

	ended := func() {
		release()
		g.metrics.requestInFlight(g.listener.Name, scope, -1)
	}

	if h := heldOf(r.Context()); h != nil {
		h.add(ended)
	} else {
		ended()
	}

	return nil
}

// LimitListener accepts at most n connections at once; past that, Accept waits for one to close.
// A trusted listener's, or the admin listener's: they keep answering whatever scoped clients hold, so
// an operator and the monitoring can act when scopes are at the bound.
func LimitListener(l net.Listener, n int) net.Listener {
	return &limitListener{Listener: l, slots: newSlots(func() int { return n }), done: make(chan struct{})}
}

// ScopedLimitListener is LimitListener for a scoped listener: each of its connections also holds
// one of every scoped listener's together (LimitConnections).
func ScopedLimitListener(l net.Listener, n int) net.Listener {
	return limitListenerBy(l, func() int { return n })
}

// limitListenerBy is a scoped listener's, under a limit that may change (a scope's socket's).
func limitListenerBy(l net.Listener, limit func() int) *limitListener {
	return &limitListener{Listener: l, slots: newSlots(limit), total: total, done: make(chan struct{})}
}

type limitListener struct {
	net.Listener

	slots *slots
	// Every scoped listener's together (nil: a trusted or admin listener's, not bound by them)
	total *slots
	done  chan struct{}
	once  sync.Once
}

func (l *limitListener) Accept() (net.Conn, error) {
	if !l.slots.wait(l.done) {
		return nil, net.ErrClosed
	}

	if l.total != nil && !l.total.wait(l.done) {
		l.slots.give()

		return nil, net.ErrClosed
	}

	conn, err := l.Listener.Accept()
	if err != nil {
		l.slots.give()

		if l.total != nil {
			l.total.give()
		}

		return nil, err
	}

	return &limitConn{Conn: conn, listener: l, slot: true}, nil
}

func (l *limitListener) Close() error {
	l.once.Do(func() { close(l.done) })

	return l.Listener.Close()
}

// limitConn is a connection holding its slots: its listener's until it's a scope's (or for as
// long as it's open, on a listener whose connections are no scope's), every listener's, and its
// scope's once it's one.
type limitConn struct {
	net.Conn

	listener *limitListener

	mu     sync.Mutex
	slot   bool
	scope  string
	scoped func()
	closed bool
}

func (c *limitConn) wrapped() net.Conn { return c.Conn }

func (c *limitConn) Close() error {
	err := c.Conn.Close()

	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.closed {
		c.closed = true

		if c.slot {
			c.listener.slots.give()
		}

		if c.listener.total != nil {
			c.listener.total.give()
		}

		if c.scoped != nil {
			c.scoped()
		}
	}

	return err
}

// attribute makes the connection the scope's, from its first authenticated request: it then holds
// one of the scope's connections instead of one of the listener's.
func (c *limitConn) attribute(scope string, counts *scopeCounts, limit int) *refusal {
	c.mu.Lock()
	defer c.mu.Unlock()

	switch {
	case c.closed || c.scope == scope:
		return nil
	case c.scope != "":
		refused := refuse(http.StatusForbidden, CodeScopeConnectionBound, nowhere, nothingAllowed,
			"this connection is another scope's (a connection is the scope of its first request): open a new one")
		refused.closes = true

		c.freeSlot()

		return refused
	}

	release, ok := counts.take(scope, limit)
	if !ok {
		refused := refuse(http.StatusTooManyRequests, CodeScopeConnections, nowhere, allowAtMost(int64(limit), "connections"),
			"this scope has %d connections open, as many as this listener allows (limits.connections): use one of them", limit)
		refused.retryAfter = 1
		refused.closes = true

		// Closed after its answer (which the server may take half a second to do): it's authenticated,
		// so it doesn't hold back connections that haven't, meanwhile
		c.freeSlot()

		return refused
	}

	c.scope, c.scoped = scope, release
	c.freeSlot()

	return nil
}

// freeSlot gives back the listener's slot the connection took (it's authenticated). Held c.mu.
func (c *limitConn) freeSlot() {
	if c.slot {
		c.slot = false
		c.listener.slots.give()
	}
}

// limitedKey holds, in a request's context, its connection's limitConn.
type limitedKey struct{}

func limitedConnOf(ctx context.Context) *limitConn {
	c, _ := ctx.Value(limitedKey{}).(*limitConn)

	return c
}

// unwrapLimited finds a connection's limitConn, through TLS and every wrapper.
func unwrapLimited(c net.Conn) *limitConn {
	for c != nil {
		switch v := c.(type) {
		case *limitConn:
			return v
		case *tls.Conn:
			c = v.NetConn()
		case interface{ wrapped() net.Conn }:
			c = v.wrapped()
		default:
			return nil
		}
	}

	return nil
}

// closeLinger is how long a connection closed after a refusal reads on (and discards) before it's
// closed: long enough that its client reads the answer rather than a reset, as the server's own linger
// does, a fifth of it.
var closeLinger atomic.Int64

func init() { closeLinger.Store(int64(100 * time.Millisecond)) }

// closeSoon closes the connection of a request just answered: its write side at once, then the whole
// connection once its client has closed, or after closeLinger.
func closeSoon(w http.ResponseWriter) {
	rc := http.NewResponseController(w)

	// The answer, written to the connection before it's taken from the server
	if err := rc.Flush(); err != nil {
		return
	}

	conn, buffered, err := rc.Hijack()
	if err != nil {
		return
	}

	_ = buffered.Flush()

	if half, ok := underlying(conn).(interface{ CloseWrite() error }); ok {
		_ = half.CloseWrite()
	}

	_ = conn.SetReadDeadline(time.Now().Add(time.Duration(closeLinger.Load())))
	_, _ = io.Copy(io.Discard, buffered)
	_ = conn.Close()
}

// underlying is a connection under every wrapper of the gate's (a limit, the tracking). A TLS
// connection is its own: its CloseWrite sends TLS's close_notify.
func underlying(c net.Conn) net.Conn {
	for {
		w, ok := c.(interface{ wrapped() net.Conn })
		if !ok {
			return c
		}

		c = w.wrapped()
	}
}
