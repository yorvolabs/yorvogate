package gate

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"regexp"
	"strconv"
	"time"
)

// Each request's log line says which request it is (request_id, also answered as X-Request-Id),
// where it came from (source), and how long the gate took to decide (decision_ms). Values a client
// chose are cut short (cut): JSON escapes them, so a line can't be split or forged, and cutting keeps
// one from being huge.

// LogVersion is the log line's format (schemas/yorvogate-log.v1.schema.json): open for added
// fields within a version, as answers are.
const LogVersion = 1

// RequestIDHeader carries a request's ID: the gate's in its answer, a client's own in its request.
const RequestIDHeader = "X-Request-Id"

var clientRequestID = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// startKey holds, in a request's context, when the gate started on it.
type startKey struct{}

func newRequestID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])

	return hex.EncodeToString(b[:])
}

// cut shortens a value a client chose to n bytes, marking that it was cut.
func cut(s string, n int) string {
	if len(s) <= n {
		return s
	}

	return s[:n] + "…"
}

// source is where a request came from: its TCP peer's address, or on a unix socket the peer's user.
func source(r *http.Request) string {
	if uid, ok := peerOf(r.Context()); ok {
		return "uid=" + strconv.FormatUint(uint64(uid), 10)
	}

	if r.RemoteAddr == "" || r.RemoteAddr == "@" {
		return "unix"
	}

	return r.RemoteAddr
}

// decisionMS is how long since the gate started on the request, in milliseconds.
func decisionMS(ctx context.Context) float64 {
	started, ok := ctx.Value(startKey{}).(time.Time)
	if !ok {
		return 0
	}

	return float64(time.Since(started).Microseconds()) / 1000
}

// requestFields start a request's log line, and give its ID.
func requestFields(r *http.Request) (string, []any) {
	id := newRequestID()
	fields := []any{"log_version", LogVersion, "request_id", id, "source", source(r), "method", r.Method, "path", cut(r.URL.EscapedPath(), 256)}

	if theirs := r.Header.Get(RequestIDHeader); clientRequestID.MatchString(theirs) {
		fields = append(fields, "client_request_id", theirs)
	}

	return id, fields
}
