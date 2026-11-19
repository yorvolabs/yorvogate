package gate

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yorvolabs/yorvogate/internal/config"
)

// kimToken is the second scope's token in these tests (jane's is token).
const kimToken = "kim-long-random-token-0123456789abcdef"

// limitedGate serves a token listener with the limits given, behind a LimitListener accepting
// unauthenticated connections at once, in front of the fake Docker: its scopes jane and kim.
func limitedGate(t *testing.T, d *docker, limits string, unauthenticated int) (string, *Gate, *config.Config) {
	t.Helper()

	scopes := t.TempDir()
	write := func(name, tok string) {
		sum := sha256.Sum256([]byte(tok))
		file := `{"token_sha256": "` + hex.EncodeToString(sum[:]) + `", "owner": {"label": "com.docker.compose.project", "value": "` + name + `"}, "prefixes": ["` + name + `-"], "images": ["quire-sites/` + name + `/"]}`

		if err := os.WriteFile(filepath.Join(scopes, name+".json"), []byte(file), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("jane", token)
	write("kim", kimToken)

	c := limitedConfig(t, d, scopes, limits)

	registry := Registry(c)
	if err := registry.Reload(); err != nil {
		t.Fatal(err)
	}

	log, _ := checkedLog(t)
	g := New(c, c.Listeners[0], NewUpstream(c, log), registry, readDefaults(c), NewSpool(c), log)
	g.UseMetrics(NewMetrics(true))

	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	server := NewServer(g)
	listener := LimitListener(raw, unauthenticated)

	go func() { _ = server.Serve(listener) }()

	t.Cleanup(func() { _ = server.Close() })

	return raw.Addr().String(), g, c
}

func limitedConfig(t *testing.T, d *docker, scopes, limits string) *config.Config {
	t.Helper()

	c, err := config.Parse([]byte(`
version: 1
upstream: unix://` + d.socket + `
spool: {dir: ` + t.TempDir() + `}
listeners:
  - name: tenants
    address: tcp://127.0.0.1:2390
    mode: scoped
    scopes: ` + scopes + `
    limits: ` + limits + `
`))
	if err != nil {
		t.Fatal(err)
	}

	return c
}

// peer is one connection to the gate, its requests sent and their answers read in turn.
type peer struct {
	t    *testing.T
	conn net.Conn
	read *bufio.Reader
}

func dial(t *testing.T, addr string) *peer {
	t.Helper()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = conn.Close() })

	return &peer{t: t, conn: conn, read: bufio.NewReader(conn)}
}

// send sends a container list as the scope (by its token).
func (c *peer) send(scope, tok string) {
	c.t.Helper()

	if _, err := io.WriteString(c.conn, "GET /v1.56/containers/json HTTP/1.1\r\nHost: docker\r\nX-YorvoGate-Scope: "+scope+"\r\nX-YorvoGate-Token: "+tok+"\r\n\r\n"); err != nil {
		c.t.Fatal(err)
	}
}

// answer reads the next answer: its status, code (a refusal's) and headers.
func (c *peer) answer() (int, string, http.Header) {
	c.t.Helper()

	_ = c.conn.SetReadDeadline(time.Now().Add(10 * time.Second))

	res, err := http.ReadResponse(c.read, nil)
	if err != nil {
		c.t.Fatal(err)
	}
	defer res.Body.Close()

	body, _ := io.ReadAll(res.Body)

	var refused struct{ Code string }
	_ = json.Unmarshal(body, &refused)

	// ReadResponse takes Connection: close from the headers, into Close
	if res.Close {
		res.Header.Set("Connection", "close")
	}

	return res.StatusCode, refused.Code, res.Header
}

// ask sends a container list as the scope, and reads its answer.
func (c *peer) ask(scope, tok string) (int, string, http.Header) {
	c.t.Helper()
	c.send(scope, tok)

	return c.answer()
}

// closed says whether the gate closed the connection (after an answer that said it would).
func (c *peer) closed() bool {
	_ = c.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err := c.read.ReadByte()

	return err == io.EOF
}

// eventually waits for cond, failing after 5 s.
func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()

	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
		if cond() {
			return
		}
	}

	t.Fatalf("not within 5 s: %s", what)
}

// A scope may have limits.requests in flight, streams included: one more is refused (429, to retry),
// another scope's isn't held back, and every slot is given back once its request is answered.
func TestAScopesRequestsInFlightAreBounded(t *testing.T) {
	d := startDocker(t)
	d.hold = make(chan struct{})
	addr, g, _ := limitedGate(t, d, "{requests: 2}", MaxConnections)

	held := []*peer{dial(t, addr), dial(t, addr)}
	for _, c := range held {
		c.send("jane", token)
	}

	eventually(t, "jane's two requests at Docker", func() bool { return d.holding.Load() == 2 })

	status, code, header := dial(t, addr).ask("jane", token)
	if status != http.StatusTooManyRequests || code != string(CodeScopeRequests) || header.Get("Retry-After") != "1" {
		t.Fatalf("jane's third: %d %s, Retry-After %q", status, code, header.Get("Retry-After"))
	}

	kim := dial(t, addr)
	kim.send("kim", kimToken)
	eventually(t, "kim's request at Docker, jane's at her limit", func() bool { return d.holding.Load() == 3 })

	var metrics strings.Builder
	_ = g.metrics.Write(&metrics)

	for _, want := range []string{`yorvogate_requests_in_flight{listener="tenants",scope="jane"} 2`, `yorvogate_requests_in_flight{listener="tenants",scope="kim"} 1`} {
		if !strings.Contains(metrics.String(), want+"\n") {
			t.Errorf("the metrics don't say %s:\n%s", want, metrics.String())
		}
	}

	close(d.hold)

	for _, c := range append(held, kim) {
		if status, code, _ := c.answer(); status != http.StatusOK {
			t.Fatalf("a held request: %d %s", status, code)
		}
	}

	eventually(t, "every request slot given back", func() bool { return g.requests.all() == 0 })

	if status, _, _ := dial(t, addr).ask("jane", token); status != http.StatusOK {
		t.Fatalf("jane, once her requests ended: %d", status)
	}
}

// A refused request, and one whose client goes before Docker answers, give their slots back too.
func TestARequestSlotIsGivenBackOnEveryPath(t *testing.T) {
	d := startDocker(t)
	d.hold = make(chan struct{})
	defer close(d.hold)

	addr, g, _ := limitedGate(t, d, "{requests: 1}", MaxConnections)

	// Refused by its policy: a query it may not send
	c := dial(t, addr)
	if _, err := io.WriteString(c.conn, "GET /v1.56/containers/json?nosuchkey=1 HTTP/1.1\r\nHost: docker\r\nX-YorvoGate-Scope: jane\r\nX-YorvoGate-Token: "+token+"\r\n\r\n"); err != nil {
		t.Fatal(err)
	}

	if status, _, _ := c.answer(); status < 400 {
		t.Fatalf("a refused request: %d", status)
	}

	eventually(t, "the refused request's slot", func() bool { return g.requests.of("jane") == 0 })

	// Gone while Docker holds it
	gone := dial(t, addr)
	gone.send("jane", token)
	eventually(t, "jane's request at Docker", func() bool { return d.holding.Load() == 1 })

	_ = gone.conn.Close()

	eventually(t, "the slot of a request whose client went", func() bool { return g.requests.of("jane") == 0 })
}

// On a token listener a connection is the scope of its first request: a request on it with another
// scope's token is refused, and the connection closed.
func TestAConnectionStaysItsFirstScopes(t *testing.T) {
	d := startDocker(t)
	addr, _, _ := limitedGate(t, d, "{}", MaxConnections)

	c := dial(t, addr)
	if status, _, _ := c.ask("jane", token); status != http.StatusOK {
		t.Fatalf("jane: %d", status)
	}

	if status, _, _ := c.ask("jane", token); status != http.StatusOK {
		t.Fatalf("jane again, on her connection: %d", status)
	}

	status, code, header := c.ask("kim", kimToken)
	if status != http.StatusForbidden || code != string(CodeScopeConnectionBound) || header.Get("Connection") != "close" {
		t.Fatalf("kim on jane's connection: %d %s, Connection %q", status, code, header.Get("Connection"))
	}

	if !c.closed() {
		t.Fatal("the connection is still open")
	}
}

// A scope may have limits.connections open on a token listener: one more is refused and closed,
// another scope connects, and a connection closed gives its slot back.
func TestAScopesConnectionsAreBounded(t *testing.T) {
	d := startDocker(t)
	addr, g, _ := limitedGate(t, d, "{connections: 2}", MaxConnections)

	first, second := dial(t, addr), dial(t, addr)
	for _, c := range []*peer{first, second} {
		if status, _, _ := c.ask("jane", token); status != http.StatusOK {
			t.Fatalf("jane: %d", status)
		}
	}

	third := dial(t, addr)

	status, code, header := third.ask("jane", token)
	if status != http.StatusTooManyRequests || code != string(CodeScopeConnections) || header.Get("Connection") != "close" {
		t.Fatalf("jane's third connection: %d %s, Connection %q", status, code, header.Get("Connection"))
	}

	if !third.closed() {
		t.Fatal("the third connection is still open")
	}

	if status, _, _ := dial(t, addr).ask("kim", kimToken); status != http.StatusOK {
		t.Fatalf("kim, jane at her limit: %d", status)
	}

	_ = first.conn.Close()

	eventually(t, "the closed connection's slot", func() bool { return g.connections.of("jane") == 1 })

	if status, _, _ := dial(t, addr).ask("jane", token); status != http.StatusOK {
		t.Fatalf("jane, a connection closed: %d", status)
	}
}

// The listener's own bound counts only connections that haven't authenticated: a flood of
// connections that send nothing holds new connections back, never a scope's open ones; a scope's
// connection, once it's one, frees the listener's slot it took.
func TestConnectionsThatDontAuthenticateDontHoldScopesBack(t *testing.T) {
	d := startDocker(t)
	addr, _, _ := limitedGate(t, d, "{}", 2)

	jane, kim := dial(t, addr), dial(t, addr)
	if status, _, _ := jane.ask("jane", token); status != http.StatusOK {
		t.Fatalf("jane: %d", status)
	}

	if status, _, _ := kim.ask("kim", kimToken); status != http.StatusOK {
		t.Fatalf("kim: %d", status)
	}

	// Both of the listener's slots, taken by connections that send nothing
	silent := []net.Conn{dial(t, addr).conn, dial(t, addr).conn}

	for _, c := range []*peer{jane, kim} {
		if status, _, _ := c.ask(map[*peer]string{jane: "jane", kim: "kim"}[c], map[*peer]string{jane: token, kim: kimToken}[c]); status != http.StatusOK {
			t.Fatalf("a scope's open connection, the listener's slots taken: %d", status)
		}
	}

	// A new connection waits for a slot...
	waiting := dial(t, addr)
	waiting.send("jane", token)

	_ = waiting.conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if _, err := waiting.read.Peek(1); err == nil {
		t.Fatal("a new connection was served with the listener's slots all taken")
	}

	// ... and is served once one is free
	_ = silent[0].Close()

	if status, _, _ := waiting.answer(); status != http.StatusOK {
		t.Fatalf("the new connection, a slot freed: %d", status)
	}
}

// A lowered limit takes from the next request: those in flight stay, and are answered.
func TestALoweredLimitKeepsRequestsInFlight(t *testing.T) {
	d := startDocker(t)
	d.hold = make(chan struct{})
	addr, g, c := limitedGate(t, d, "{requests: 4}", MaxConnections)

	live := NewLive(c, "one")
	g.Follow(live)

	held := []*peer{dial(t, addr), dial(t, addr), dial(t, addr)}
	for _, h := range held {
		h.send("jane", token)
	}

	eventually(t, "three at Docker", func() bool { return d.holding.Load() == 3 })

	lowered := limitedConfig(t, d, c.Listeners[0].Scopes, "{requests: 1}")
	live.Swap(lowered, "two")

	if status, code, _ := dial(t, addr).ask("jane", token); status != http.StatusTooManyRequests || code != string(CodeScopeRequests) {
		t.Fatalf("a new request, the limit lowered under three in flight: %d %s", status, code)
	}

	close(d.hold)

	for _, h := range held {
		if status, _, _ := h.answer(); status != http.StatusOK {
			t.Fatalf("a request in flight when the limit was lowered: %d", status)
		}
	}

	eventually(t, "the slots given back", func() bool { return g.requests.of("jane") == 0 })

	if status, _, _ := dial(t, addr).ask("jane", token); status != http.StatusOK {
		t.Fatalf("jane under the lowered limit: %d", status)
	}
}
