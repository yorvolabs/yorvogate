package gate

import (
	"io"
	"net"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yorvolabs/yorvogate/internal/config"
	"github.com/yorvolabs/yorvogate/internal/route"
)

// A non-stream body that never arrives is refused once the read deadline passes, not read forever
// (so a slow client can't hold a connection open — slowloris).
func TestReadBodyDeadline(t *testing.T) {
	old := bodyReadTimeout
	bodyReadTimeout = 100 * time.Millisecond

	defer func() { bodyReadTimeout = old }()

	g := &Gate{config: &config.Config{BodyLimit: 1 << 20}}

	pr, pw := io.Pipe()
	defer pw.Close()

	r := httptest.NewRequest("POST", "/v1.56/containers/create", pr)
	if _, err := g.readBody(r, &route.Endpoint{}); err == nil {
		t.Fatal("a body that never arrives should be refused, not read forever")
	}
}

// A scope loads one archive at a time: a second acquire for the same scope waits for the first to
// release, while a different scope is never blocked.
func TestLoadLimiter(t *testing.T) {
	l := newLoadLimiter()

	release := l.acquire("jane")

	// A different scope isn't blocked.
	otherDone := make(chan struct{})
	go func() { l.acquire("blog")(); close(otherDone) }()

	select {
	case <-otherDone:
	case <-time.After(time.Second):
		t.Fatal("a different scope's load was blocked")
	}

	// A second load for jane waits until the first releases.
	second := make(chan struct{})
	go func() { l.acquire("jane")(); close(second) }()

	select {
	case <-second:
		t.Fatal("a second load for the same scope ran before the first released")
	case <-time.After(200 * time.Millisecond):
	}

	release()

	select {
	case <-second:
	case <-time.After(time.Second):
		t.Fatal("the second load didn't run after the first released")
	}

	// Each scope's entry goes with its last load
	if n := l.loading(); n != 0 {
		t.Errorf("%d scopes left after every load released", n)
	}
}

// A load waiting keeps its scope's entry: a third load, coming after the first released while the
// second waits or runs, still goes one at a time. Run with -race.
func TestLoadLimiterEvictsOnlyWhenIdle(t *testing.T) {
	l := newLoadLimiter()

	var running atomic.Int32

	var overlapped atomic.Bool

	var wg sync.WaitGroup
	for range 50 {
		wg.Add(1)

		go func() {
			defer wg.Done()

			release := l.acquire("jane")
			if running.Add(1) > 1 {
				overlapped.Store(true)
			}

			time.Sleep(time.Millisecond)
			running.Add(-1)
			release()
		}()
	}

	wg.Wait()

	if overlapped.Load() {
		t.Error("two of one scope's loads ran at once")
	}

	if n := l.loading(); n != 0 {
		t.Errorf("%d scopes left after every load released", n)
	}
}

// LimitListener accepts up to its limit at once; a connection past it waits for one to close.
func TestLimitListener(t *testing.T) {
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	defer inner.Close()

	l := LimitListener(inner, 1)
	accepted := make(chan net.Conn, 2)

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}

			accepted <- conn
		}
	}()

	c1, err := net.Dial("tcp", inner.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	defer c1.Close()

	var first net.Conn
	select {
	case first = <-accepted:
	case <-time.After(time.Second):
		t.Fatal("the first connection wasn't accepted")
	}

	c2, err := net.Dial("tcp", inner.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	defer c2.Close()

	select {
	case <-accepted:
		t.Fatal("a connection past the limit of 1 was accepted while the first was open")
	case <-time.After(200 * time.Millisecond):
	}

	// Closing the first frees a slot: the second is accepted.
	first.Close()

	select {
	case <-accepted:
	case <-time.After(time.Second):
		t.Fatal("the second connection wasn't accepted after the first closed")
	}
}
