package gate

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/yorvolabs/yorvogate/internal/config"
	"github.com/yorvolabs/yorvogate/internal/scope"
)

// statusWait is the longest a scope-status request waits for what it asks.
var statusWait = 10 * time.Second

var (
	statusPath = regexp.MustCompile(`^/_yorvogate/v1/scopes/([a-z0-9][a-z0-9_.-]{0,62})$`)
	sha256Hex  = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// scopeStatus is the scope-status answer (schemas/yorvogate-scope-status.v1.schema.json).
type scopeStatus struct {
	Version    int    `json:"version"`
	Generation uint64 `json:"generation"`
	Listener   string `json:"listener"`
	Scope      string `json:"scope"`
	FileSHA256 string `json:"file_sha256,omitempty"`
	State      string `json:"state"`
	Reason     string `json:"reason,omitempty"`
	// Set when the request waited: whether what it waited for came
	Matched *bool `json:"matched,omitempty"`
}

// own answers YorvoGate's own endpoints, which aren't Docker's: on a trusted listener only, as
// they tell about every scope.
//
//	GET /_yorvogate/v1/scopes/<name>[?listener=<scoped listener>][&sha256=<hex> | &absent]
//
// tells whether a scope is in effect on a scoped listener, from the snapshot whose sockets are open
// too. sha256 waits (statusWait at most) until that listener's scope file is the one with that
// SHA-256, absent until it has none; a wait that ends without it answers 408 and "matched": false.
func (g *Gate) own(w http.ResponseWriter, r *http.Request, entry *slog.Logger) {
	if g.listener.Mode != config.Trusted {
		entry.Warn("refused", "status", http.StatusForbidden, "reason", "YorvoGate's own endpoints")
		answer(w, http.StatusForbidden, "YorvoGate's own endpoints are a trusted listener's only")

		return
	}

	m := statusPath.FindStringSubmatch(r.URL.EscapedPath())
	if m == nil {
		answer(w, http.StatusNotFound, "no such endpoint of YorvoGate's (/_yorvogate/v1/scopes/<name>)")

		return
	}

	if r.Method != http.MethodGet {
		answer(w, http.StatusMethodNotAllowed, "/_yorvogate/v1/scopes/<name> is GET only")

		return
	}

	query := r.URL.Query()
	for key, values := range query {
		if (key != "listener" && key != "sha256" && key != "absent") || len(values) > 1 {
			answer(w, http.StatusBadRequest, "the parameters are listener, and sha256 or absent, each once")

			return
		}
	}

	listener := query.Get("listener")
	if listener == "" {
		if scoped := g.registry.Listeners(); len(scoped) == 1 {
			listener = scoped[0]
		} else {
			answer(w, http.StatusBadRequest, "listener: which scoped listener ("+strings.Join(scoped, ", ")+")")

			return
		}
	}

	want, absent := query.Get("sha256"), query.Has("absent")
	if (want != "" && absent) || (query.Has("sha256") && !sha256Hex.MatchString(want)) || (absent && query.Get("absent") != "") {
		answer(w, http.StatusBadRequest, "sha256 is the scope file's SHA-256 (64 lowercase hex), or absent alone; not both")

		return
	}

	matches := func(state string, digest string) bool {
		if absent {
			return state == "unknown"
		}

		return digest == want
	}

	status, next, ok := g.registry.Status(listener, m[1])
	if !ok {
		answer(w, http.StatusBadRequest, "listener: "+listener+" isn't a scoped listener")

		return
	}

	code, waited := http.StatusOK, (*bool)(nil)

	if want != "" || absent {
		// A scan now, rather than at the next tick: the orchestrator just wrote (or removed) the file.
		g.registry.RequestReload()

		timeout := time.NewTimer(statusWait)
		defer timeout.Stop()

		matched := matches(status.State, status.FileSHA256)

	wait:
		for !matched {
			select {
			case <-next:
				status, next, _ = g.registry.Status(listener, m[1])
				matched = matches(status.State, status.FileSHA256)
			case <-timeout.C:
				code = http.StatusRequestTimeout

				break wait
			case <-r.Context().Done():
				return
			}
		}

		waited = &matched
	}

	entry.Info("scope status", "scope", m[1], "state", status.State, "status", code)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(answerOf(status, waited))
}

func answerOf(s scope.Status, matched *bool) scopeStatus {
	return scopeStatus{
		Version: 1, Generation: s.Generation, Listener: s.Listener, Scope: s.Scope,
		FileSHA256: s.FileSHA256, State: s.State, Reason: s.Reason, Matched: matched,
	}
}
