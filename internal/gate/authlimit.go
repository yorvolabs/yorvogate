package gate

import (
	"net"
	"sync"
	"time"
)

// The auth failed log line is limited, so a client that doesn't authenticate can't flood the log:
// at most perSource lines a minute from one source (an IPv6 source by its /64, which one host has
// many of), at most globally a minute from all of them, then the rest only counted. Sources are kept
// in a table of at most sources; a source that doesn't fit counts toward the global limit alone. The
// refusal itself is never limited, nor is the metric that counts it.
const (
	authLinesPerSource = 10
	authLinesGlobal    = 600
	authSources        = 4096
)

type authLimiter struct {
	mu      sync.Mutex
	window  time.Time
	sources map[string]int
	total   int
	dropped int
}

func newAuthLimiter() *authLimiter {
	return &authLimiter{sources: map[string]int{}}
}

// sourceKey is what a source is limited by: its IP (an IPv6 one by its /64), or its user.
func sourceKey(source string) string {
	host, _, err := net.SplitHostPort(source)
	if err != nil {
		return source // uid=…, unix
	}

	ip := net.ParseIP(host)
	if ip == nil || ip.To4() != nil {
		return host
	}

	return ip.Mask(net.CIDRMask(64, 128)).String() + "/64"
}

// allow tells whether an auth failed line from source may be logged now. When a new minute starts,
// it gives what the last one dropped, to be logged once.
func (a *authLimiter) allow(source string, now time.Time) (ok bool, droppedBefore int) {
	if a == nil {
		return true, 0
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	if minute := now.Truncate(time.Minute); !minute.Equal(a.window) {
		droppedBefore = a.dropped
		a.window, a.total, a.dropped = minute, 0, 0
		clear(a.sources)
	}

	key := sourceKey(source)
	n, known := a.sources[key]

	switch {
	case a.total >= authLinesGlobal, known && n >= authLinesPerSource:
		a.dropped++

		return false, droppedBefore
	case !known && len(a.sources) >= authSources:
		// No room to tell it apart: the global limit alone holds it
	default:
		a.sources[key] = n + 1
	}

	a.total++

	return true, droppedBefore
}

// flush gives what the minute before now dropped, once, when no line came since to give it.
func (a *authLimiter) flush(now time.Time) int {
	if a == nil {
		return 0
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	if now.Truncate(time.Minute).Equal(a.window) || a.dropped == 0 {
		return 0
	}

	dropped := a.dropped
	a.dropped = 0

	return dropped
}
