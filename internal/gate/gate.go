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
	docker   *Docker
	upstream *Upstream
	log      *slog.Logger
}

// New makes the handler of a listener.
func New(c *config.Config, l config.Listener, upstream *Upstream, log *slog.Logger) *Gate {
	g := &Gate{config: c, listener: l, upstream: upstream, log: log.With("listener", l.Name)}
	if l.Mode == config.Scoped {
		g.scopes = scope.NewStore(l.Scopes)
		g.docker = NewDocker(c.UpstreamSocket())
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

	switch g.listener.Mode {
	case config.Trusted:
		if !g.listener.Allows(req.Endpoint) {
			return nil, refuse(http.StatusForbidden, "%s isn't allowed on this listener", req.Endpoint.Name)
		}

		if err := upgradeOnly(r, req.Endpoint); err != nil {
			return nil, err
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

		decision := &scoped{
			ctx: r.Context(), req: req, scope: s, policy: g.listener.Containers, docker: g.docker,
			path: r.URL.EscapedPath(), query: r.URL.Query(), upgrading: upgrading(r),
		}
		if req.Version != nil {
			decision.version = req.Version.String()
		}

		checked, err := decision.decide(body)
		if err != nil {
			return nil, err
		}

		if err := upgradeOnly(r, req.Endpoint); err != nil {
			return nil, err
		}

		entry.Info("allowed", "endpoint", req.Endpoint.Name)
		out := withoutGateHeaders(r)
		out.URL.Path, out.URL.RawPath = decision.path, ""
		out.URL.RawQuery = decision.query.Encode()

		// A stream (an archive put into one of its containers) goes as it came.
		if req.Endpoint.Stream {
			return out, nil
		}

		return withBody(out, checked), nil
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

// upgradeOnly refuses a stream asked for without an HTTP upgrade: YorvoGate passes streams both ways
// only once Docker has switched protocols.
func upgradeOnly(r *http.Request, e *route.Endpoint) error {
	if e.Upgrade && !upgrading(r) {
		return refuse(http.StatusBadRequest, "%s is a stream: it's allowed only as an HTTP upgrade", e.Name)
	}

	return nil
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
