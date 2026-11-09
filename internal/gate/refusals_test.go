package gate

import (
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestARefusalIsHeldAsLongAsTheSlowestRecentDecision(t *testing.T) {
	var d decisionTimes

	if held := d.record("container.inspect", 3*time.Millisecond, true); held != 3*time.Millisecond {
		t.Errorf("held %v, not as long as the one decision", held)
	}

	if held := d.record("container.inspect", time.Millisecond, true); held != 3*time.Millisecond {
		t.Errorf("held %v, not as long as the slowest", held)
	}

	if held := d.record("network.inspect", time.Millisecond, true); held != time.Millisecond {
		t.Errorf("held %v: another endpoint's decisions counted", held)
	}

	// The slowest is forgotten once as many decisions came after it as are remembered.
	for range decisionsRemembered - 1 {
		d.record("container.inspect", time.Millisecond, true)
	}

	if held := d.record("container.inspect", 2*time.Millisecond, true); held != 2*time.Millisecond {
		t.Errorf("held %v: the slowest wasn't forgotten", held)
	}

	if held := d.record("container.inspect", time.Hour, true); held != longestHold {
		t.Errorf("held %v, longer than the longest hold", held)
	}
}

// A scope can't make a refusal quicker by refusals of names that are nothing: they aren't remembered.
func TestDecisionsThatFoundNothingArentRemembered(t *testing.T) {
	var d decisionTimes

	d.record("container.inspect", 5*time.Millisecond, true)

	for range 2 * decisionsRemembered {
		if held := d.record("container.inspect", time.Microsecond, false); held != 5*time.Millisecond {
			t.Fatalf("held %v: a decision that found nothing was remembered", held)
		}
	}

	if held := d.record("network.inspect", time.Millisecond, false); held != 0 {
		t.Errorf("held %v with nothing found yet", held)
	}
}

// Another scope's container takes longer to look up than a name that's nothing: the refusal of
// both takes as long.
func TestAnotherScopesObjectIsRefusedInTheTimeOfOneThatIsntThere(t *testing.T) {
	const slow = 150 * time.Millisecond

	d := startDocker(t)
	server := gate(t, d, "sites")

	d.mu.Lock()
	d.slow = slow
	d.mu.Unlock()

	timed := func(path string) (int, time.Duration) {
		t.Helper()

		started := time.Now()
		status, _ := send(t, server, "GET", path, "", asJane)

		return status, time.Since(started)
	}

	if status, took := timed("/v1.56/containers/blog-php-1/json"); status != http.StatusNotFound || took < slow {
		t.Fatalf("another scope's container: %d in %v", status, took)
	}

	if status, took := timed("/v1.56/containers/blog-nothing-1/json"); status != http.StatusNotFound || took < slow {
		t.Errorf("a container that isn't there: %d in %v, sooner than another scope's", status, took)
	}

	// Only the lookup that found a container is remembered, not the one that found nothing.
	g := server.Config.Handler.(*Gate)
	g.decisions.mu.Lock()
	remembered := 0
	for _, took := range g.decisions.by["container.inspect"].took {
		if took > 0 {
			remembered++
		}
	}
	g.decisions.mu.Unlock()

	if remembered != 1 {
		t.Errorf("%d decisions remembered, not the one that found a container", remembered)
	}

	// An allowed decision isn't held: Docker answers it at once once it's fast again.
	d.mu.Lock()
	d.slow = 0
	d.mu.Unlock()

	if status, took := timed("/v1.56/containers/jane-php-1/json"); status != http.StatusOK || took >= slow {
		t.Errorf("the scope's own container: %d in %v, held", status, took)
	}
}

// A client of a listener with an address that names a scope whose file isn't valid is answered as
// one naming no scope: nothing says the file is there, nor where. The log says why.
func TestAScopeFileThatIsntValidIsAnUnknownScope(t *testing.T) {
	d := startDocker(t)

	var log logs
	server := gateLogging(t, d, "sites", slog.New(slog.NewTextHandler(&log, nil)))
	g := server.Config.Handler.(*Gate)

	if err := os.WriteFile(filepath.Join(g.listener.Scopes, "broken.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := g.registry.Reload(); err != nil {
		t.Fatal(err)
	}

	status, answer := send(t, server, "GET", "/v1.56/version", "", map[string]string{"X-YorvoGate-Scope": "broken", "X-YorvoGate-Token": token})
	if status != http.StatusUnauthorized || message(t, answer) != "yorvogate: no such scope, or not its token" || strings.Contains(answer, g.listener.Scopes) {
		t.Errorf("%d %s", status, answer)
	}

	if !strings.Contains(log.String(), "scope_error=") || !strings.Contains(log.String(), "broken.json") {
		t.Errorf("the log doesn't say why: %s", log.String())
	}

	// A scope that isn't there: nothing more to say.
	log.Reset()
	if status, _ := send(t, server, "GET", "/v1.56/version", "", map[string]string{"X-YorvoGate-Scope": "nobody", "X-YorvoGate-Token": token}); status != http.StatusUnauthorized || strings.Contains(log.String(), "scope_error") {
		t.Errorf("%d %s", status, log.String())
	}
}

// What couldn't be decided on is said in the log, not to a client of a listener with an address.
func TestWhatCouldntBeDecidedOnIsntSaidToAClient(t *testing.T) {
	d := startDocker(t)

	var log logs
	server := gateLogging(t, d, "sites", slog.New(slog.NewTextHandler(&log, nil)))
	_ = os.Remove(d.socket)

	status, answer := send(t, server, "GET", "/v1.56/containers/jane-php-1/json", "", asJane)
	if status != http.StatusInternalServerError || message(t, answer) != "yorvogate: the request couldn't be decided on" {
		t.Errorf("%d %s", status, answer)
	}

	if !strings.Contains(log.String(), "asking Docker") {
		t.Errorf("the log doesn't say why: %s", log.String())
	}
}
