package gate

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

// A refused decision is answered no sooner than the slowest of the endpoint's recent decisions that
// found an object. Whether a name is another scope's object or nothing at all is answered the same,
// but not in the same time: Docker inspects an object that exists (and YorvoGate reads its answer),
// and answers at once for one that doesn't. Timed often enough, the difference would tell a scope
// which of another's names exist. Held as long as the slowest lookup of an object that exists, a
// refusal of a name that's nothing takes as long as one of another's object.
//
// Only decisions that found an object are remembered: a refusal of a name that's nothing never is,
// or a scope could fill the window with its own fast refusals, and an object that exists would show
// again by its time. What's left: a lookup slower than every one remembered still shows, about once
// in as many as are remembered, so the difference is bounded, not closed. A decision allowed isn't
// held: the object is the scope's own.
type decisionTimes struct {
	mu sync.Mutex
	by map[string]*recentTimes
}

// How many of an endpoint's decisions are remembered, and the longest a refusal is held
const (
	decisionsRemembered = 256
	longestHold         = 250 * time.Millisecond
)

type recentTimes struct {
	took [decisionsRemembered]time.Duration
	next int
}

// record returns how long a refusal of a decision on an endpoint is held: the slowest of those
// remembered, at most longestHold. A decision that found an object is remembered first.
func (d *decisionTimes) record(endpoint string, took time.Duration, found bool) time.Duration {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.by == nil {
		d.by = map[string]*recentTimes{}
	}

	r := d.by[endpoint]
	if r == nil {
		r = &recentTimes{}
		d.by[endpoint] = r
	}

	if found {
		r.took[r.next] = took
		r.next = (r.next + 1) % decisionsRemembered
	}

	slowest := time.Duration(0)
	for _, t := range r.took {
		slowest = max(slowest, t)
	}

	return min(slowest, longestHold)
}

// foundKey carries, in the context of a decision, whether a lookup of it found an object.
type foundKey struct{}

// lookingUp returns a decision's context, which tells found whether Docker found an object it was
// asked about.
func lookingUp(ctx context.Context) (context.Context, *atomic.Bool) {
	found := &atomic.Bool{}

	return context.WithValue(ctx, foundKey{}, found), found
}

// foundObject marks the decision a lookup is for as one that found an object.
func foundObject(ctx context.Context) {
	if found, ok := ctx.Value(foundKey{}).(*atomic.Bool); ok {
		found.Store(true)
	}
}

// hold waits until a refused decision that started then has taken as long as given, or the client
// is gone.
func hold(ctx context.Context, started time.Time, hold time.Duration) {
	wait := time.Until(started.Add(hold))
	if wait <= 0 {
		return
	}

	timer := time.NewTimer(wait)
	defer timer.Stop()

	select {
	case <-timer.C:
	case <-ctx.Done():
	}
}
