package gate

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yorvolabs/yorvogate/internal/config"
)

// Under concurrent requests while the configuration flips between two, every request is decided by
// one of them, never by half of each: here the API versions of one and the endpoint groups of the
// other would refuse the request as the listener's (listener.denies), which neither does alone.
func TestNoRequestIsDecidedByHalfOfEach(t *testing.T) {
	d := startDocker(t)
	parse := func(api, allow string, load int64) *config.Config {
		c, err := config.Parse([]byte("version: 1\nupstream: unix://" + d.socket + "\napi: {max: '" + api + "'}\nload_limit: " + itoa(load) + "\nspool: {limit: " + itoa(load) + "}\nlisteners:\n  - {name: ops, address: 'tcp://127.0.0.1:2375', mode: trusted, allow: {" + allow + "}}\n"))
		if err != nil {
			t.Fatal(err)
		}

		return c
	}

	a, b := parse("1.56", "containers: write", 2<<20), parse("1.50", "system: read", 3<<20)
	live := NewLive(a, "a")
	log := slog.New(slog.DiscardHandler)
	g := New(a, a.Listeners[0], NewUpstream(a, log), Registry(a), NewDefaults(a), NewSpool(a), log)
	g.Follow(live)

	stop := make(chan struct{})
	flipped := make(chan struct{})

	go func() {
		defer close(flipped)

		for i := range 100 {
			if i%2 == 0 {
				live.Swap(b, "b")
			} else {
				live.Swap(a, "a")
			}

			select {
			case <-stop:
				return
			case <-time.After(time.Millisecond):
			}
		}
	}()

	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		decided = map[int]int{}
	)

	for range 1000 {
		wg.Go(func() {
			// The limits a load would be held to come from one configuration
			if view, _ := g.now(); view.config.LoadLimit != view.config.Spool.Limit {
				t.Errorf("load_limit %d with spool.limit %d", view.config.LoadLimit, view.config.Spool.Limit)
			}

			w := httptest.NewRecorder()
			g.ServeHTTP(w, httptest.NewRequest("GET", "/v1.53/containers/json", nil))

			var answer struct{ Code Code }
			_ = json.Unmarshal(w.Body.Bytes(), &answer)

			mu.Lock()
			decided[w.Code]++
			mu.Unlock()

			switch {
			case w.Code == http.StatusOK:
			case answer.Code == CodeListenerDenies:
				t.Errorf("decided by half of each: %d %s", w.Code, w.Body)
			case w.Code == http.StatusBadRequest && answer.Code == CodeInvalidRoute:
			default:
				t.Errorf("an answer neither gives: %d %s", w.Code, w.Body)
			}
		})
	}

	wg.Wait()
	close(stop)
	<-flipped

	if decided[http.StatusOK] == 0 || decided[http.StatusBadRequest] == 0 {
		t.Errorf("not both configurations decided: %v", decided)
	}
}

func itoa(n int64) string {
	b, _ := json.Marshal(n)

	return string(b)
}

// A request on a listener a reload removed (its connections being closed) is refused, not decided by
// the configuration before.
func TestARemovedListenersRequestIsRefused(t *testing.T) {
	d := startDocker(t)
	c, err := config.Parse([]byte("version: 1\nupstream: unix://" + d.socket + "\nlisteners:\n  - {name: ops, address: 'tcp://127.0.0.1:2375', mode: trusted, allow: {system: read}}\n  - {name: other, address: 'tcp://127.0.0.1:2376', mode: trusted, allow: {system: read}}\n"))
	if err != nil {
		t.Fatal(err)
	}

	without, err := config.Parse([]byte("version: 1\nupstream: unix://" + d.socket + "\nlisteners:\n  - {name: other, address: 'tcp://127.0.0.1:2376', mode: trusted, allow: {system: read}}\n"))
	if err != nil {
		t.Fatal(err)
	}

	live := NewLive(c, "")
	log := slog.New(slog.DiscardHandler)
	g := New(c, c.Listeners[0], NewUpstream(c, log), Registry(c), NewDefaults(c), NewSpool(c), log)
	g.Follow(live)

	w := httptest.NewRecorder()
	g.ServeHTTP(w, httptest.NewRequest("GET", "/v1.56/_ping", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("before: %d %s", w.Code, w.Body)
	}

	live.Swap(without, "")

	w = httptest.NewRecorder()
	g.ServeHTTP(w, httptest.NewRequest("GET", "/v1.56/_ping", nil))

	if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "removed by a reload") {
		t.Errorf("after: %d %s", w.Code, w.Body)
	}
}

// Lowering spool.loads and spool.limit by a reload keeps the loads in flight: they keep their turn
// and their bytes; new ones wait, or are told to retry, until what's held is under the new limits.
func TestLoweringTheSpoolsLimitsKeepsLoadsInFlight(t *testing.T) {
	defer func(w time.Duration) { loadWait = w }(loadWait)
	loadWait = 50 * time.Millisecond

	c, err := config.Parse([]byte("version: 1\nupstream: unix:///var/run/docker.sock\nspool: {dir: " + t.TempDir() + ", loads: 3, limit: 3145728}\nlisteners:\n  - {name: sites, address: 'tcp://127.0.0.1:2376', mode: scoped, scopes: /etc/sites}\n"))
	if err != nil {
		t.Fatal(err)
	}

	spool := NewSpool(c)
	ctx := context.Background()

	var releases []func()

	for _, scope := range []string{"a", "b", "c"} {
		release, err := spool.turn(ctx, scope, 3)
		if err != nil {
			t.Fatalf("%s's turn under loads 3: %v", scope, err)
		}

		releases = append(releases, release)
	}

	// A reload lowers spool.loads to 1: the three keep their turn, a fourth is told to retry
	if _, err := spool.turn(ctx, "d", 1); err == nil {
		t.Fatal("a fourth load had a turn with 3 in flight under loads 1")
	}

	releases[0]()
	releases[1]()

	if _, err := spool.turn(ctx, "e", 1); err == nil {
		t.Error("a load had a turn with 1 in flight under loads 1")
	}

	releases[2]()

	release, err := spool.turn(ctx, "f", 1)
	if err != nil {
		t.Fatalf("once they've ended, a load under loads 1: %v", err)
	}

	release()

	// The bytes: 3 MiB held under the old limit; the new limit is 1 MiB
	held := &reservation{spool: spool, scope: "a", limit: 3 << 20}
	if err := held.reserve(3 << 20); err != nil {
		t.Fatal(err)
	}

	small := &reservation{spool: spool, scope: "b", limit: 1 << 20}

	var r *refusal
	if err := small.reserve(1); err == nil || !asRefusal(err, &r) || r.code != CodeLoadSpoolFull {
		t.Errorf("a load under the lowered limit while 3 MiB are held: %v", err)
	}

	held.release()

	if err := small.reserve(1 << 20); err != nil {
		t.Errorf("once they're given back, a load within the lowered limit: %v", err)
	}
}

func asRefusal(err error, r **refusal) bool {
	got, ok := err.(*refusal)
	*r = got

	return ok
}

// A reload that changes what Docker's defaults are judged by (daemon.without_lsm) takes effect for
// the next request, from the last read: no request waits for Docker to be read again.
func TestAReloadJudgesDockersDefaultsAgain(t *testing.T) {
	d := startDocker(t)
	d.info = map[string]any{"SecurityOptions": []string{"name=seccomp,profile=builtin", "name=cgroupns"}, "DefaultRuntime": "runc"}

	parse := func(daemon string) *config.Config {
		c, err := config.Parse([]byte("version: 1\nupstream: unix://" + d.socket + "\n" + daemon + "listeners:\n  - {name: sites, address: 'tcp://127.0.0.1:2376', mode: scoped, scopes: /etc/sites}\n"))
		if err != nil {
			t.Fatal(err)
		}

		return c
	}

	strict, lenient := parse(""), parse("daemon: {without_lsm: true}\n")
	defaults := readDefaults(strict)

	if _, err := defaults.current(strict); err == nil {
		t.Fatal("no AppArmor nor SELinux was safe without daemon.without_lsm")
	}

	d.mu.Lock()
	d.down = true // a new read would fail: the next answer must come from the last one
	d.mu.Unlock()

	if _, err := defaults.current(lenient); err != nil {
		t.Errorf("with daemon.without_lsm after a reload: %v", err)
	}

	if _, err := defaults.current(strict); err == nil {
		t.Error("judged by the reloaded configuration for a request of the one before")
	}
}

// A reload that removes a trusted listener's client pin ends the requests and streams that came with
// it (revoked); another pinned client's go on.
func TestARemovedClientPinEndsItsStreams(t *testing.T) {
	d := startDocker(t)
	m := mtlsGate(t, d, "")
	kept, _, _ := m.admins.issue(t, client("kept"))
	removed, _, _ := m.admins.issue(t, client("removed"))

	parse := func(pins ...tls.Certificate) *config.Config {
		var list []string
		for _, p := range pins {
			list = append(list, "{sha256: "+pin(p)+"}")
		}

		c, err := config.Parse([]byte("version: 1\nupstream: unix://" + d.socket + "\nlisteners:\n  - name: admin\n    address: tcp://0.0.0.0:2375\n    mode: trusted\n    allow: {system: read, exec: write}\n    tls: {certificate: " + m.dir + "/server.pem, key: " + m.dir + "/server.key, client_ca: " + m.dir + "/admins.pem}\n    clients: [" + strings.Join(list, ", ") + "]\n"))
		if err != nil {
			t.Fatal(err)
		}

		return c
	}

	both := parse(kept, removed)

	set, err := LoadTLS(both, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}

	live := NewLive(both, "")
	log, lines := checkedLog(t)
	g := New(both, both.Listeners[0], NewUpstream(both, log), Registry(both), readDefaults(both), NewSpool(both), log)
	g.UseTLS(set.For("admin"))
	g.Follow(live)

	raw, _ := net.Listen("tcp", "127.0.0.1:0")
	server := NewServer(g)
	go func() { _ = server.Serve(tls.NewListener(raw, set.For("admin").Config())) }()
	t.Cleanup(func() { _ = server.Close() })

	keptConn, keptReader := m.tlsStream(t, raw.Addr().String(), "exec-jane", kept)
	removedConn, removedReader := m.tlsStream(t, raw.Addr().String(), "exec-blog", removed)

	// The reload: the configuration, then the files' listeners, then the scan's revocation
	one := parse(kept)
	if err := set.Reconfigure(one, nil); err != nil {
		t.Fatal(err)
	}

	live.Swap(one, "")
	g.Revoke()

	if !ended(t, removedConn, removedReader) {
		t.Error("the removed pin's stream is still open")
	}

	echoes(t, keptConn, keptReader)

	lines.waitFor(t, func(l map[string]any) bool { return l["msg"] == "stream closed" && l["by"] == "revoked" })

	if status, _, err := m.get(t, raw.Addr().String(), &removed, "/_ping", nil); err == nil && status == http.StatusOK {
		t.Error("the removed pin's certificate is still taken")
	}
}
