package gate

import (
	"context"
	"sync"
)

// inflight counts a listener's requests being handled (streams included), so a shutdown can wait
// for them, and know when the last has logged its end.
type inflight struct {
	mu   sync.Mutex
	n    int
	idle chan struct{} // closed while none is
}

func newInflight() *inflight {
	idle := make(chan struct{})
	close(idle)

	return &inflight{idle: idle}
}

// begin counts a request in, and gives what counts it out.
func (f *inflight) begin() func() {
	f.mu.Lock()
	if f.n == 0 {
		f.idle = make(chan struct{})
	}
	f.n++
	f.mu.Unlock()

	return func() {
		f.mu.Lock()
		f.n--
		if f.n == 0 {
			close(f.idle)
		}
		f.mu.Unlock()
	}
}

// wait waits until none is being handled, or the context ends.
func (f *inflight) wait(ctx context.Context) error {
	f.mu.Lock()
	idle := f.idle
	f.mu.Unlock()

	select {
	case <-idle:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
