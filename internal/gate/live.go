package gate

import (
	"context"
	"sync/atomic"

	"github.com/yorvolabs/yorvogate/internal/config"
)

// Live is the configuration in effect: one snapshot for the whole process, swapped whole by a
// reload. A request loads it once, at its start, and everything that decides on it (its gate, the
// upstream, Docker's defaults, the spool) reads that one, passed down in its context: no request is
// decided half by one configuration and half by the next.
type Live struct {
	current  atomic.Pointer[Runtime]
	draining atomic.Bool
}

// Runtime is one configuration as it's in effect: its content's SHA-256, and which it is (each
// reload's is the next).
type Runtime struct {
	Config     *config.Config
	SHA256     string
	Generation uint64
}

// NewLive is the configuration in effect at the start.
func NewLive(c *config.Config, sha256 string) *Live {
	l := &Live{}
	l.current.Store(&Runtime{Config: c, SHA256: sha256, Generation: 1})

	return l
}

// Load is the configuration in effect now.
func (l *Live) Load() *Runtime {
	return l.current.Load()
}

// Swap puts a new configuration in effect, and gives it.
func (l *Live) Swap(c *config.Config, sha256 string) *Runtime {
	next := &Runtime{Config: c, SHA256: sha256, Generation: l.current.Load().Generation + 1}
	l.current.Store(next)

	return next
}

// Drain marks the process stopping: readiness fails from now on.
func (l *Live) Drain() {
	l.draining.Store(true)
}

// Draining says whether the process is stopping.
func (l *Live) Draining() bool {
	return l.draining.Load()
}

// Listener is the listener of that name in this configuration.
func (r *Runtime) Listener(name string) (config.Listener, bool) {
	for _, l := range r.Config.Listeners {
		if l.Name == name {
			return l, true
		}
	}

	return config.Listener{}, false
}

// runtimeKey holds, in a request's context, the configuration it's decided by.
type runtimeKey struct{}

func withRuntime(ctx context.Context, c *config.Config) context.Context {
	return context.WithValue(ctx, runtimeKey{}, c)
}

// configOf is the configuration a request is decided by, or fallback for one that isn't a request's
// (a test's, Docker's defaults read by Watch).
func configOf(ctx context.Context, fallback *config.Config) *config.Config {
	if c, ok := ctx.Value(runtimeKey{}).(*config.Config); ok && c != nil {
		return c
	}

	return fallback
}
