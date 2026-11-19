package gate

import (
	"bufio"
	"context"
	"errors"
	"net"
	"net/http"
	"sync/atomic"
	"time"
)

// A stream (a request upgraded to a connection of its own: attach, exec, a builder's dial-stdio) is
// logged when it opens and when it closes, with how long it lasted, the bytes each way, and whether
// it ended, was ended because its scope no longer allows it (revoked), or was closed by YorvoGate
// stopping (shutdown) or by a reload that removed or moved its listener (reload).

// counted is a response writer whose hijacked connection counts its bytes.
type counted struct {
	http.ResponseWriter
	in, out atomic.Int64
}

func (c *counted) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	conn, rw, err := http.NewResponseController(c.ResponseWriter).Hijack()
	if err != nil {
		return nil, nil, err
	}

	// The stream's bytes go through the connection (the proxy copies between it and Docker's); its
	// answer's headers, written through rw, aren't counted.
	return &countingConn{Conn: conn, c: c}, rw, nil
}

func (c *counted) Flush() { _ = http.NewResponseController(c.ResponseWriter).Flush() }

type countingConn struct {
	net.Conn
	c *counted
}

func (cc *countingConn) Read(b []byte) (int, error) {
	n, err := cc.Conn.Read(b)
	cc.c.in.Add(int64(n))

	return n, err
}

func (cc *countingConn) Write(b []byte) (int, error) {
	n, err := cc.Conn.Write(b)
	cc.c.out.Add(int64(n))

	return n, err
}

// forwardStream forwards an upgraded request, logging it open and closed.
func (g *Gate) forwardStream(w http.ResponseWriter, forward *http.Request, log func(msg string, fields ...any)) {
	c := &counted{ResponseWriter: w}
	started := time.Now()

	log("stream opened")
	g.upstream.Forward(c, forward)

	by := "ended"

	switch why := g.closing.Load(); {
	case errors.Is(context.Cause(forward.Context()), errRevoked):
		by = "revoked"
	case why != nil:
		// Its listener closed it: YorvoGate stopping, or a reload that removed or moved the listener
		by = *why
	}

	log("stream closed", "duration_ms", float64(time.Since(started).Microseconds())/1000, "bytes_in", c.in.Load(), "bytes_out", c.out.Load(), "by", by)
}
