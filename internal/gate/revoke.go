package gate

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/yorvolabs/yorvogate/internal/scope"
)

// streams are a token or mTLS listener's requests being answered, each with the scope and the
// credential it was allowed with. A scope removed, no longer valid, given another token, or no
// longer pinning the client certificate, and a client certificate expired or whose CA is no longer
// the listener's, ends its requests at the next Revoke: streams too (attach, exec, logs that
// follow), as closing a scope's socket does on a socket listener. A trusted mTLS listener's
// requests end with their client certificate the same way. Each new request is decided on the
// scopes and CAs as they are, so only those already being answered need ending.
type streams struct {
	mu   sync.Mutex
	open map[*stream]struct{}
}

type stream struct {
	scope string // "" on a trusted listener
	token string
	// A client certificate's stream (an mTLS listener): what it was taken with
	cert *credential
	end  context.CancelFunc
}

// track gives the request to forward, ended at once if its allowance goes, and what to call once
// it's answered. allowed is its scope, nil on a trusted listener.
func (s *streams) track(store *scope.Store, files *TLSFiles, allowed *scope.Scope, r *http.Request) (*http.Request, func()) {
	ctx, cancel := context.WithCancel(r.Context())
	st := &stream{end: cancel}

	if allowed != nil {
		st.scope, st.token = allowed.Name, allowed.TokenSHA256
	}

	if c, ok := credentialOf(r.TLS); ok {
		st.cert = &c
	}

	s.mu.Lock()
	if s.open == nil {
		s.open = map[*stream]struct{}{}
	}
	s.open[st] = struct{}{}
	s.mu.Unlock()

	// A reload between the request's decision and here would have missed it: it's checked again,
	// now that a Revoke after any reload sees it.
	if !st.current(store, files) {
		cancel()
	}

	return r.WithContext(ctx), func() {
		cancel()
		s.mu.Lock()
		delete(s.open, st)
		s.mu.Unlock()
	}
}

// revoke ends the requests whose scope no longer allows them, and says how many it ended of each
// scope.
func (s *streams) revoke(store *scope.Store, files *TLSFiles) map[string]int {
	s.mu.Lock()
	defer s.mu.Unlock()

	ended := map[string]int{}

	for st := range s.open {
		if !st.current(store, files) {
			st.end()
			delete(s.open, st)

			ended[st.scope]++
		}
	}

	return ended
}

// current says whether the request is still allowed: its scope, as last loaded, valid and with the
// token it was allowed with, or a client certificate the listener still admits (see admits). A
// trusted listener's request has its client certificate alone.
func (st *stream) current(store *scope.Store, files *TLSFiles) bool {
	if st.scope == "" {
		return st.cert != nil && files.admits(*st.cert, nil)
	}

	now, err := store.Get(st.scope)
	if err != nil {
		return false
	}

	if st.cert != nil {
		return files.admits(*st.cert, now)
	}

	return now.TokenSHA256 == st.token
}

// clock is the time streams' credentials expire by (a test sets it).
var clock = time.Now

// Revoke ends the requests being answered on a token or mTLS listener whose scope was removed, isn't
// valid now, has a new token, or no longer pins the client certificate, or whose client certificate
// expired or has a CA no longer the listener's: streams included. On a trusted mTLS listener, those
// whose client certificate expired or whose CA went. Call it after each reload; socket listeners
// do the same by closing the scope's socket.
func (g *Gate) Revoke() {
	if g.listener.SocketBound() || g.scopes == nil && !g.listener.MutualTLS() {
		return
	}

	for name, n := range g.streams.revoke(g.scopes, g.tls) {
		if name == "" {
			g.log.Info("requests ended: their client certificate expired, or its CA is no longer the listener's", "requests", n)

			continue
		}

		g.log.Info("requests ended: their scope was removed, isn't valid, or no longer takes their credential", "scope", name, "requests", n)
	}
}
