// Package gate is YorvoGate's request handling: each request is mapped to an endpoint, decided on
// by its listener's policy, and only then forwarded to Docker. Every refusal is an answer Docker's
// clients show (a JSON message), and every decision is logged.
package gate

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/yorvolabs/yorvogate/internal/config"
	"github.com/yorvolabs/yorvogate/internal/route"
	"github.com/yorvolabs/yorvogate/internal/scope"
)

const (
	// ScopeHeader names the scope a request is for (scoped listeners).
	ScopeHeader = "X-Yorvogate-Scope"
	// TokenHeader proves it.
	TokenHeader = "X-Yorvogate-Token"
)

// Gate handles one listener's requests.
type Gate struct {
	config   *config.Config
	listener config.Listener
	scopes   *scope.Store
	upstream *Upstream
	log      *slog.Logger
}

// New makes the handler of a listener.
func New(c *config.Config, l config.Listener, upstream *Upstream, log *slog.Logger) *Gate {
	g := &Gate{config: c, listener: l, upstream: upstream, log: log.With("listener", l.Name)}
	if l.Mode == config.Scoped {
		g.scopes = scope.NewStore(l.Scopes)
	}

	return g
}

// refusal is a request not forwarded: its HTTP status and why.
type refusal struct {
	status int
	reason string
}

func (r *refusal) Error() string { return r.reason }

func refuse(status int, format string, args ...any) *refusal {
	return &refusal{status: status, reason: fmt.Sprintf(format, args...)}
}

// ServeHTTP decides on a request, and forwards it if it's allowed.
func (g *Gate) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	entry := g.log.With("method", r.Method, "path", r.URL.EscapedPath())

	forward, err := g.decide(r, entry)
	if err != nil {
		var refused *refusal
		if !errors.As(err, &refused) {
			refused = refuse(http.StatusInternalServerError, "the request couldn't be decided on: %v", err)
		}

		entry.Warn("refused", "status", refused.status, "reason", refused.reason)
		answer(w, refused.status, refused.reason)

		return
	}

	g.upstream.Forward(w, forward)
}

// decide returns the request to forward (with what YorvoGate checked as its body), or why not.
func (g *Gate) decide(r *http.Request, entry *slog.Logger) (*http.Request, error) {
	lowest, highest := g.config.Versions()

	req, err := route.Parse(r.Method, r.URL.EscapedPath(), lowest, highest)
	if err != nil {
		if errors.Is(err, route.ErrUnknown) {
			return nil, refuse(http.StatusForbidden, "%v", err)
		}

		return nil, refuse(http.StatusBadRequest, "%v", err)
	}

	if req.Endpoint.Upgrade && !upgrading(r) {
		return nil, refuse(http.StatusBadRequest, "%s is a stream: it's allowed only as an HTTP upgrade", req.Endpoint.Name)
	}

	switch g.listener.Mode {
	case config.Trusted:
		if !g.listener.Allows(req.Endpoint) {
			return nil, refuse(http.StatusForbidden, "%s isn't allowed on this listener", req.Endpoint.Name)
		}

		entry.Info("allowed", "endpoint", req.Endpoint.Name)

		// A trusted client's body goes as it came (streams included).
		return withoutGateHeaders(r), nil
	case config.Scoped:
		s, err := g.scopes.Authenticate(r.Header.Get(ScopeHeader), r.Header.Get(TokenHeader))
		if err != nil {
			if errors.Is(err, scope.ErrUnknown) {
				return nil, refuse(http.StatusUnauthorized, "no such scope, or not its token")
			}

			return nil, err
		}

		entry = entry.With("scope", s.Name)

		body, err := g.readBody(r, req.Endpoint)
		if err != nil {
			return nil, err
		}

		checked, err := scoped(req, s, body)
		if err != nil {
			return nil, err
		}

		entry.Info("allowed", "endpoint", req.Endpoint.Name)

		return withBody(withoutGateHeaders(r), checked), nil
	}

	return nil, refuse(http.StatusInternalServerError, "the listener has no mode")
}

// readBody reads a body whole, up to the limit. A stream isn't read here: its endpoint's rule decides
// how (or whether) it's looked into.
func (g *Gate) readBody(r *http.Request, e *route.Endpoint) ([]byte, error) {
	if e.Stream {
		return nil, nil
	}

	body, err := io.ReadAll(http.MaxBytesReader(nil, r.Body, g.config.BodyLimit))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return nil, refuse(http.StatusRequestEntityTooLarge, "the request's body is larger than %d bytes", g.config.BodyLimit)
		}

		return nil, refuse(http.StatusBadRequest, "the request's body couldn't be read: %v", err)
	}

	return body, nil
}

// scoped is a scoped listener's policy: what a scope may do, and the body to forward. Until the
// rules for each endpoint are in place, a scope may only ask whether Docker answers, and its version.
func scoped(req route.Request, s *scope.Scope, body []byte) ([]byte, error) {
	switch req.Endpoint.Name {
	case "system.ping", "system.version":
		if len(body) != 0 {
			return nil, refuse(http.StatusBadRequest, "%s has no body", req.Endpoint.Name)
		}

		return nil, nil
	}

	return nil, refuse(http.StatusForbidden, "%s isn't allowed for scope %s", req.Endpoint.Name, s.Name)
}

// upgrading tells whether a request asks for an HTTP upgrade (Docker's hijacked streams).
func upgrading(r *http.Request) bool {
	if r.Header.Get("Upgrade") == "" {
		return false
	}

	for _, v := range r.Header.Values("Connection") {
		for _, token := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(token), "upgrade") {
				return true
			}
		}
	}

	return false
}

// withoutGateHeaders drops YorvoGate's own headers: Docker never sees a scope's token.
func withoutGateHeaders(r *http.Request) *http.Request {
	out := r.Clone(r.Context())
	for name := range out.Header {
		if strings.HasPrefix(http.CanonicalHeaderKey(name), "X-Yorvogate-") {
			out.Header.Del(name)
		}
	}

	return out
}

// withBody sets the body that's forwarded: what was checked, never what came.
func withBody(r *http.Request, body []byte) *http.Request {
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	r.TransferEncoding = nil
	r.Header.Del("Transfer-Encoding")

	if len(body) == 0 {
		r.Body = http.NoBody
		r.Header.Del("Content-Length")
		r.Header.Del("Content-Type")
	}

	return r
}

// answer refuses as Docker answers errors, so its clients show why.
func answer(w http.ResponseWriter, status int, reason string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"message": "yorvogate: " + reason})
}
