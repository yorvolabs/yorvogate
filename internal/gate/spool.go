package gate

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/yorvolabs/yorvogate/internal/config"
)

// The spool is where image archives are kept while they're checked, shared by every scope of every
// listener: in one folder, within one budget of bytes, a few loads at a time (spool.loads), each
// scope one at a time. A load waits a bounded time for its turn, then is told to retry.
type Spool struct {
	dir    string
	limit  int64
	global chan struct{}
	scopes *loadLimiter

	mu       sync.Mutex
	reserved int64
}

// How long a load waits for its turn, and how long its upload may go silent; how long checking an
// archive may take, whatever it holds. Variables, for tests.
var (
	loadWait  = 30 * time.Second
	loadStall = 60 * time.Second
	loadCheck = 10 * time.Minute
)

// onSpool is called when a load has its turn and starts spooling (a test's hook).
var onSpool = func(string) {}

// spoolPrefix names an archive's file in the spool, so one left by a crash can be told and removed.
const spoolPrefix = "yorvogate-load-"

// spools holds the one spool of each configuration: every listener made from a configuration shares
// it, so its bounds hold across listeners.
var spools sync.Map

// spoolOf is the configuration's spool.
func spoolOf(c *config.Config) *Spool {
	if s, ok := spools.Load(c); ok {
		return s.(*Spool)
	}

	s, _ := spools.LoadOrStore(c, &Spool{dir: c.Spool.Dir, limit: c.Spool.Limit, global: make(chan struct{}, c.Spool.Loads), scopes: newLoadLimiter()})

	return s.(*Spool)
}

// needsSpool is whether a configuration has a scoped listener, whose scopes may load images.
func needsSpool(c *config.Config) bool {
	for _, l := range c.Listeners {
		if l.Mode == config.Scoped {
			return true
		}
	}

	return false
}

// PrepareSpool makes the spool's folder (only its owner's), removes what a previous run left in it,
// and checks it can be written. serve refuses to start without it, as check does.
func PrepareSpool(c *config.Config) error {
	if !needsSpool(c) {
		return nil
	}

	dir := c.Spool.Dir
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return spoolError(dir, err)
	}

	if left, err := filepath.Glob(filepath.Join(dir, spoolPrefix+"*")); err == nil {
		for _, f := range left {
			_ = os.Remove(f)
		}
	}

	f, err := os.CreateTemp(dir, spoolPrefix+"check-*")
	if err != nil {
		return spoolError(dir, err)
	}

	_ = f.Close()

	return os.Remove(f.Name())
}

// CheckSpool checks, without changing anything, that serve could make and write the spool's folder:
// it exists and can be written, or its nearest existing parent can.
func CheckSpool(c *config.Config) error {
	if !needsSpool(c) {
		return nil
	}

	dir := c.Spool.Dir
	for path := dir; ; path = filepath.Dir(path) {
		info, err := os.Stat(path)
		if errors.Is(err, os.ErrNotExist) && path != "/" {
			continue
		}

		if err != nil {
			return spoolError(dir, err)
		}

		if !info.IsDir() {
			return spoolError(dir, fmt.Errorf("%s isn't a folder", path))
		}

		if err := syscall.Access(path, 2 /* W_OK */); err != nil {
			return spoolError(dir, fmt.Errorf("%s can't be written: %w", path, err))
		}

		return nil
	}
}

func spoolError(dir string, err error) error {
	return fmt.Errorf("spool.dir %s: %w (image loads are kept there while they're checked: mount a volume there, or set spool.dir)", dir, err)
}

// turn waits for the scope's turn to load, and a free one of spool.loads, at most loadWait (or until
// the client goes). It gives the function that ends the turn.
func (s *Spool) turn(ctx context.Context, scope string) (func(), error) {
	timer := time.NewTimer(loadWait)
	defer timer.Stop()

	busy := func() error {
		return &refusal{status: http.StatusServiceUnavailable, retryAfter: 5, reason: "image.load: too many image loads at once: retry"}
	}

	release, err := s.scopes.acquireBy(ctx, timer.C, scope)
	if err != nil {
		return nil, busy()
	}

	select {
	case s.global <- struct{}{}:
	case <-timer.C:
		release()

		return nil, busy()
	case <-ctx.Done():
		release()

		return nil, busy()
	}

	return func() { <-s.global; release() }, nil
}

// reservation is one load's share of the spool's budget.
type reservation struct {
	spool *Spool
	held  int64
}

// reserve takes n more bytes of the budget for the load, or says why it can't: the spool is full
// now (retry), or the archive would never fit (it holds the whole budget alone).
func (r *reservation) reserve(n int64) error {
	s := r.spool
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.reserved+n <= s.limit {
		s.reserved += n
		r.held += n

		return nil
	}

	if r.held+n > s.limit || s.reserved == r.held {
		return refuse(http.StatusRequestEntityTooLarge, "image.load: the archive is larger than the image spool (spool.limit, %d bytes)", s.limit)
	}

	return &refusal{status: http.StatusServiceUnavailable, retryAfter: 10, reason: "image.load: the image spool is full: retry"}
}

// release gives the load's bytes back.
func (r *reservation) release() {
	s := r.spool
	s.mu.Lock()
	s.reserved -= r.held
	r.held = 0
	s.mu.Unlock()
}

// spoolFile makes an archive's file in the spool.
func (s *Spool) spoolFile() (*os.File, error) {
	return os.CreateTemp(s.dir, spoolPrefix+"*")
}

// stalled reads a stream, failing once no byte has come for loadStall: each read is given a
// deadline on the connection (deadline), or, where the connection can't take one, the stream is
// closed when the time passes.
type stalled struct {
	r        io.Reader
	deadline func(time.Time) error
	timer    *time.Timer
	fired    chan struct{}
}

var errStalled = errors.New("the archive stopped arriving")

func newStalled(r io.Reader, closer func() error, deadline func(time.Time) error) *stalled {
	s := &stalled{r: r, deadline: deadline, fired: make(chan struct{})}

	if deadline == nil || deadline(time.Now().Add(loadStall)) != nil {
		s.deadline = nil
		s.timer = time.AfterFunc(loadStall, func() { close(s.fired); _ = closer() })
	}

	return s
}

// Read reads on, giving the next byte loadStall to come.
func (s *stalled) Read(p []byte) (int, error) {
	if s.deadline != nil {
		_ = s.deadline(time.Now().Add(loadStall))
	}

	n, err := s.r.Read(p)

	if s.timer != nil {
		select {
		case <-s.fired:
			return n, errStalled
		default:
		}

		if n > 0 {
			s.timer.Reset(loadStall)
		}
	}

	if err != nil && errors.Is(err, os.ErrDeadlineExceeded) {
		return n, errStalled
	}

	return n, err
}

// stop ends the timeout: the connection's deadline goes, for what's left of the request.
func (s *stalled) stop() {
	if s.timer != nil {
		s.timer.Stop()
	}

	if s.deadline != nil {
		_ = s.deadline(time.Time{})
	}
}

// controllerKey holds the request's http.ResponseController in its context, for read deadlines.
type controllerKey struct{}

// readDeadline is how a request's connection is given a read deadline, or nil.
func readDeadline(ctx context.Context) func(time.Time) error {
	if rc, ok := ctx.Value(controllerKey{}).(*http.ResponseController); ok {
		return rc.SetReadDeadline
	}

	return nil
}
