// Package gate is YorvoGate's request handling: each request is mapped to an endpoint, decided on
// by its listener's policy, and only then forwarded to Docker. Every refusal is an answer Docker's
// clients show (a JSON message), and every decision is logged.
package gate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"strings"
	"time"

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
	registry *scope.Registry
	scopes   *scope.Store
	docker   *Docker
	upstream *Upstream
	loads    *loadLimiter
	log      *slog.Logger
}

// Registry holds the scopes of every scoped listener of a configuration: they share one Docker, so
// their claims are decided together. Reload it before serving, and on each scan.
func Registry(c *config.Config) *scope.Registry {
	var folders []scope.Folder

	for _, l := range c.Listeners {
		if l.Mode == config.Scoped {
			folders = append(folders, scope.Folder{Listener: l.Name, Dir: l.Scopes, Tokenless: l.SocketBound()})
		}
	}

	return scope.NewRegistry(folders, c.StateFile)
}

// New makes the handler of a listener; a scoped one's scopes are the registry's.
func New(c *config.Config, l config.Listener, upstream *Upstream, scopes *scope.Registry, log *slog.Logger) *Gate {
	g := &Gate{config: c, listener: l, upstream: upstream, registry: scopes, log: log.With("listener", l.Name)}
	if l.Mode == config.Scoped {
		g.scopes = scopes.Store(l.Name)
		g.docker = NewDocker(c.UpstreamSocket())
		g.loads = newLoadLimiter()
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

	if strings.HasPrefix(r.URL.EscapedPath(), "/_yorvogate/") {
		g.own(w, r, entry)

		return
	}

	forward, done, err := g.decide(r, entry)
	if done != nil {
		defer done()
	}

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

// decide returns the request to forward (with what YorvoGate checked as its body), and what to do
// once it's forwarded; or why not.
func (g *Gate) decide(r *http.Request, entry *slog.Logger) (*http.Request, func(), error) {
	forward, decision, err := g.decided(r, entry)
	if decision == nil {
		return forward, nil, err
	}

	return forward, decision.cleanup, err
}

func (g *Gate) decided(r *http.Request, entry *slog.Logger) (*http.Request, *scoped, error) {
	lowest, highest := g.config.Versions()

	req, err := route.Parse(r.Method, r.URL.EscapedPath(), lowest, highest)
	if err != nil {
		if errors.Is(err, route.ErrUnknown) {
			return nil, nil, refuse(http.StatusForbidden, "%v", err)
		}

		return nil, nil, refuse(http.StatusBadRequest, "%v", err)
	}

	switch g.listener.Mode {
	case config.Trusted:
		if !g.listener.Allows(req.Endpoint) {
			return nil, nil, refuse(http.StatusForbidden, "%s isn't allowed on this listener", req.Endpoint.Name)
		}

		if err := upgradeOnly(r, req.Endpoint); err != nil {
			return nil, nil, err
		}

		entry.Info("allowed", "endpoint", req.Endpoint.Name)

		// A trusted client's body goes as it came (streams included).
		return withoutGateHeaders(r), nil, nil
	case config.Scoped:
		s, err := g.scope(r)
		if err != nil {
			return nil, nil, err
		}

		entry = entry.With("scope", s.Name)

		if err := notAForm(r); err != nil {
			return nil, nil, err
		}

		body, err := g.readBody(r, req.Endpoint)
		if err != nil {
			return nil, nil, err
		}

		decision := &scoped{
			ctx: r.Context(), req: req, scope: s, policy: g.listener.Containers, docker: g.docker,
			builderProfiles: g.listener.BuilderAppArmorProfiles, anyBuilder: g.listener.AllowPrivilegedBuilders,
			path: r.URL.EscapedPath(), query: r.URL.Query(), upgrading: upgrading(r),
			stream: r.Body, hasBody: r.ContentLength != 0, loadLimit: g.config.LoadLimit, loads: g.loads,
		}
		if req.Version != nil {
			decision.version = req.Version.String()
		}

		checked, err := decision.decide(body)
		if err != nil {
			return nil, decision, err
		}

		if err := upgradeOnly(r, req.Endpoint); err != nil {
			return nil, decision, err
		}

		entry.Info("allowed", "endpoint", req.Endpoint.Name)
		out := withoutGateHeaders(r)
		out.URL.Path, out.URL.RawPath = decision.path, ""
		out.URL.RawQuery = decision.query.Encode()

		if decision.answer != nil {
			out = out.WithContext(context.WithValue(out.Context(), answerKey{}, decision.answer))
		}

		// Docker reads a request's parameters from its body too when the Content-Type says it's a
		// form, and those win over the query YorvoGate checked. So the Content-Type Docker gets is
		// YorvoGate's, from what's forwarded, never the client's.
		switch {
		case decision.forwardBody != nil:
			// What was checked in place of what came (an archive kept on disk)
			out.Body, out.ContentLength = decision.forwardBody, decision.forwardLength
			out.TransferEncoding = nil
			out.Header.Del("Transfer-Encoding")
			out.Header.Set("Content-Type", "application/x-tar")

			return out, decision, nil
		case sendsArchive[req.Endpoint.Name]:
			// An archive put into one of its containers goes as it comes: YorvoGate doesn't read it.
			out.Header.Set("Content-Type", "application/x-tar")

			return out, decision, nil
		}

		// Any other stream (an image.create) has no body, and goes without one.
		return withBody(out, checked), decision, nil
	}

	return nil, nil, refuse(http.StatusInternalServerError, "the listener has no mode")
}

// boundKey carries, in the context of a request that came on a scope's own socket, the scope's name.
type boundKey struct{}

// scope is the scope a request is for: the one whose socket it came on, or the one it names, with
// its token.
func (g *Gate) scope(r *http.Request) (*scope.Scope, error) {
	if !g.listener.SocketBound() {
		s, err := g.scopes.Authenticate(r.Header.Get(ScopeHeader), r.Header.Get(TokenHeader))
		if errors.Is(err, scope.ErrUnknown) {
			return nil, refuse(http.StatusUnauthorized, "no such scope, or not its token")
		}

		return s, err
	}

	name, ok := r.Context().Value(boundKey{}).(string)
	if !ok {
		return nil, refuse(http.StatusInternalServerError, "the request didn't come on a scope's socket")
	}

	if named := r.Header.Get(ScopeHeader); named != "" && named != name {
		return nil, refuse(http.StatusForbidden, "this socket is scope %s's: a request on it can't name another", name)
	}

	s, err := g.scopes.Get(name)
	if err != nil {
		return nil, refuse(http.StatusForbidden, "scope %s isn't valid now: its socket closes", name)
	}

	return s, nil
}

// readBody reads a body whole, up to the limit. A stream isn't read here: its endpoint's rule decides
// how (or whether) it's looked into.
func (g *Gate) readBody(r *http.Request, e *route.Endpoint) ([]byte, error) {
	if e.Stream {
		return nil, nil
	}

	// A body to check is small; a client that trickles one keeps a connection (and a file
	// descriptor) for as long as it likes, which is how a scope can exhaust the gate for the others
	// (slowloris). Reading has a deadline: closing the body unblocks a stuck read. Streams, which
	// are large or long by design, are already returned above and keep no such deadline.
	timer := time.AfterFunc(bodyReadTimeout, func() { _ = r.Body.Close() })
	defer timer.Stop()

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

// notAForm refuses a scoped request whose body Docker would read as a form: its parameters would
// override the query YorvoGate checks (Go's Request.ParseForm, which Docker's handlers call). A
// Content-Type that doesn't parse is refused too, since Go reads the form even when only the
// type's parameters are malformed; so is a Content-Type given twice.
func notAForm(r *http.Request) error {
	types := r.Header.Values("Content-Type")
	if len(types) == 0 {
		return nil
	}

	if len(types) > 1 {
		return refuse(http.StatusBadRequest, "the request has more than one Content-Type")
	}

	media, _, err := mime.ParseMediaType(types[0])
	if err != nil {
		return refuse(http.StatusBadRequest, "the request's Content-Type %q isn't valid: %v", types[0], err)
	}

	if media == "application/x-www-form-urlencoded" || strings.HasPrefix(media, "multipart/") {
		return refuse(http.StatusUnsupportedMediaType, "a form body (%s) isn't allowed: Docker would read parameters from it that YorvoGate doesn't check", media)
	}

	return nil
}

// withBody sets the body that's forwarded, and its Content-Type: what was checked (a JSON value),
// never what came.
func withBody(r *http.Request, body []byte) *http.Request {
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	r.TransferEncoding = nil
	r.Header.Del("Transfer-Encoding")
	r.Header.Set("Content-Type", "application/json")

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
