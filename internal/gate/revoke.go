package gate

import (
	"context"
	"crypto/sha256"
	"net/http"
	"sync"
	"time"

	"github.com/yorvolabs/yorvogate/internal/scope"
)

// streams are a token or mTLS listener's requests being answered, each with the scope and the
// credential it was allowed with. A scope removed, no longer valid, given another token, no longer
// pinning the client certificate, or whose certificate has expired ends its requests at the next
// Revoke: streams too (attach, exec, logs that follow), as closing a scope's socket does on a
// socket listener. Each new request is decided on the scopes as they are, so only those already
// being answered need ending.
type streams struct {
	mu   sync.Mutex
	open map[*stream]struct{}
}

type stream struct {
	scope string
	token string
	// A client certificate's stream (an mTLS listener): its public key, and when the first of its
	// chain's certificates expires.
	certified bool
	key       [sha256.Size]byte
	expires   time.Time
	end       context.CancelFunc
}

// track gives the request to forward, ended at once if the scope's allowance goes, and what to call
// once it's answered.
func (s *streams) track(store *scope.Store, allowed *scope.Scope, r *http.Request) (*http.Request, func()) {
	ctx, cancel := context.WithCancel(r.Context())
	st := &stream{scope: allowed.Name, token: allowed.TokenSHA256, end: cancel}

	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		st.certified, st.key, st.expires = true, SPKI(r.TLS.PeerCertificates[0]), r.TLS.PeerCertificates[0].NotAfter
		for _, chain := range r.TLS.VerifiedChains {
			for _, c := range chain {
				if c.NotAfter.Before(st.expires) {
					st.expires = c.NotAfter
				}
			}
		}
	}

	s.mu.Lock()
	if s.open == nil {
		s.open = map[*stream]struct{}{}
	}
	s.open[st] = struct{}{}
	s.mu.Unlock()

	// A reload between the request's decision and here would have missed it: it's checked again,
	// now that a Revoke after any reload sees it.
	if !st.current(store) {
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
func (s *streams) revoke(store *scope.Store) map[string]int {
	s.mu.Lock()
	defer s.mu.Unlock()

	ended := map[string]int{}

	for st := range s.open {
		if !st.current(store) {
			st.end()
			delete(s.open, st)

			ended[st.scope]++
		}
	}

	return ended
}

// current says whether the scope, as last loaded, still allows the request: valid, with the token
// it was allowed with, or with a client certificate it still pins and that hasn't expired.
func (st *stream) current(store *scope.Store) bool {
	now, err := store.Get(st.scope)
	if err != nil {
		return false
	}

	if st.certified {
		return now.Pinned(st.key) && clock().Before(st.expires)
	}

	return now.TokenSHA256 == st.token
}

// clock is the time streams' credentials expire by (a test sets it).
var clock = time.Now

// Revoke ends the requests being answered on a token or mTLS listener whose scope was removed, isn't
// valid now, has a new token, no longer pins the client certificate, or whose certificate expired:
// streams included. Call it after each reload; socket listeners do the
// same by closing the scope's socket.
func (g *Gate) Revoke() {
	if g.scopes == nil || g.listener.SocketBound() {
		return
	}

	for name, n := range g.streams.revoke(g.scopes) {
		g.log.Info("requests ended: their scope was removed, isn't valid, or no longer takes their credential", "scope", name, "requests", n)
	}
}
