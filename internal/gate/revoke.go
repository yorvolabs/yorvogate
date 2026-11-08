package gate

import (
	"context"
	"net/http"
	"sync"

	"github.com/yorvolabs/yorvogate/internal/scope"
)

// streams are a token listener's requests being answered, each with the scope and token it was
// allowed as. A scope removed, no longer valid, or given another token ends its requests at the
// next Revoke: streams too (attach, exec, logs that follow), as closing a scope's socket does on a
// socket listener. Each new request is decided on the scopes as they are, so only those already
// being answered need ending.
type streams struct {
	mu   sync.Mutex
	open map[*stream]struct{}
}

type stream struct {
	scope string
	token string
	end   context.CancelFunc
}

// track gives the request to forward, ended at once if the scope's allowance goes, and what to call
// once it's answered.
func (s *streams) track(store *scope.Store, allowed *scope.Scope, r *http.Request) (*http.Request, func()) {
	ctx, cancel := context.WithCancel(r.Context())
	st := &stream{scope: allowed.Name, token: allowed.TokenSHA256, end: cancel}

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
// it was allowed with.
func (st *stream) current(store *scope.Store) bool {
	now, err := store.Get(st.scope)

	return err == nil && now.TokenSHA256 == st.token
}

// Revoke ends the requests being answered on a token listener whose scope was removed, isn't valid
// now, or has a new token: streams included. Call it after each reload; socket listeners do the
// same by closing the scope's socket.
func (g *Gate) Revoke() {
	if g.scopes == nil || g.listener.SocketBound() {
		return
	}

	for name, n := range g.streams.revoke(g.scopes) {
		g.log.Info("requests ended: their scope was removed, isn't valid, or has a new token", "scope", name, "requests", n)
	}
}
