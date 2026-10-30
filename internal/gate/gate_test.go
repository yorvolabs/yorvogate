package gate

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/yorvolabs/yorvogate/internal/config"
)

const token = "a-long-random-token-0123456789abcdef"

// docker is a fake Docker on a unix socket: it records each request it gets, answers 200, and for
// an upgrade it hijacks the connection and echoes what it reads.
type docker struct {
	mu       sync.Mutex
	requests []seen
	socket   string
}

type seen struct {
	method, path string
	header       http.Header
	body         string
}

func startDocker(t *testing.T) *docker {
	t.Helper()
	d := &docker{socket: filepath.Join(t.TempDir(), "docker.sock")}

	listener, err := net.Listen("unix", d.socket)
	if err != nil {
		t.Fatal(err)
	}

	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		d.mu.Lock()
		d.requests = append(d.requests, seen{r.Method, r.URL.Path, r.Header.Clone(), string(body)})
		d.mu.Unlock()

		if r.Header.Get("Upgrade") == "tcp" {
			conn, buffered, _ := w.(http.Hijacker).Hijack()
			_, _ = buffered.WriteString("HTTP/1.1 101 UPGRADED\r\nContent-Type: application/vnd.docker.raw-stream\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n")
			_ = buffered.Flush()
			_, _ = io.Copy(conn, buffered)
			_ = conn.Close()

			return
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	})}

	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })

	return d
}

func (d *docker) last() seen {
	d.mu.Lock()
	defer d.mu.Unlock()

	if len(d.requests) == 0 {
		return seen{}
	}

	return d.requests[len(d.requests)-1]
}

func (d *docker) count() int {
	d.mu.Lock()
	defer d.mu.Unlock()

	return len(d.requests)
}

// gate serves one listener in front of the fake Docker.
func gate(t *testing.T, d *docker, listener string) *httptest.Server {
	t.Helper()
	scopes := t.TempDir()
	sum := sha256.Sum256([]byte(token))
	scopeFile := `{"token_sha256": "` + hex.EncodeToString(sum[:]) + `", "owner": {"label": "com.docker.compose.project", "value": "jane"}, "prefixes": ["jane-", "jane_"]}`

	if err := os.WriteFile(filepath.Join(scopes, "jane.json"), []byte(scopeFile), 0o600); err != nil {
		t.Fatal(err)
	}

	c, err := config.Parse([]byte(`
upstream: unix://` + d.socket + `
body_limit: 4096
listeners:
  - name: server
    address: tcp://127.0.0.1:2375
    mode: trusted
    allow: {system: read, containers: write, exec: write}
  - name: sites
    address: tcp://127.0.0.1:2376
    mode: scoped
    scopes: ` + scopes + `
`))
	if err != nil {
		t.Fatal(err)
	}

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	for _, l := range c.Listeners {
		if l.Name == listener {
			server := httptest.NewServer(New(c, l, NewUpstream(c.UpstreamSocket(), log), log))
			t.Cleanup(server.Close)

			return server
		}
	}

	t.Fatalf("no listener %s", listener)

	return nil
}

func send(t *testing.T, server *httptest.Server, method, path, body string, header map[string]string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(method, server.URL+path, strings.NewReader(body))
	for k, v := range header {
		req.Header.Set(k, v)
	}

	res, err := server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()

	answer, _ := io.ReadAll(res.Body)

	return res.StatusCode, string(answer)
}

func message(t *testing.T, answer string) string {
	t.Helper()
	var m struct{ Message string }
	if err := json.Unmarshal([]byte(answer), &m); err != nil {
		t.Fatalf("not Docker's error format: %q", answer)
	}

	return m.Message
}

func TestATrustedListenerForwardsWhatItAllows(t *testing.T) {
	d := startDocker(t)
	server := gate(t, d, "server")

	status, _ := send(t, server, "POST", "/v1.56/containers/create?name=x", `{"Image":"alpine","HostConfig":{"Privileged":true}}`, map[string]string{"X-YorvoGate-Token": "secret"})
	if status != 200 {
		t.Fatalf("allowed: %d", status)
	}

	got := d.last()
	if got.method != "POST" || got.path != "/v1.56/containers/create" || got.body != `{"Image":"alpine","HostConfig":{"Privileged":true}}` {
		t.Errorf("forwarded %+v", got)
	}

	if got.header.Get("X-Yorvogate-Token") != "" {
		t.Error("YorvoGate's headers reached Docker")
	}

	for _, c := range [][3]string{
		{"GET", "/v1.56/images/json", "image.list isn't allowed on this listener"},
		{"POST", "/v1.56/auth", "system.auth isn't allowed on this listener"},
		{"GET", "/v1.56/containers/x/some-new-endpoint", "not an endpoint YorvoGate knows"},
	} {
		status, answer := send(t, server, c[0], c[1], "", nil)
		if status != http.StatusForbidden || !strings.Contains(message(t, answer), c[2]) {
			t.Errorf("%s %s: %d %s", c[0], c[1], status, answer)
		}
	}

	if d.count() != 1 {
		t.Errorf("%d requests reached Docker, want 1", d.count())
	}
}

func TestMalformedRequestsNeverReachDocker(t *testing.T) {
	d := startDocker(t)
	server := gate(t, d, "server")

	for _, path := range []string{"/containers/json", "/v1.57/containers/json", "/v1.56/containers/../json", "/v1.56/containers%2Fjson"} {
		if status, answer := send(t, server, "GET", path, "", nil); status != http.StatusBadRequest {
			t.Errorf("%s: %d %s", path, status, answer)
		}
	}

	if d.count() != 0 {
		t.Errorf("%d requests reached Docker", d.count())
	}
}

func TestAScopedListenerNeedsTheScopesToken(t *testing.T) {
	d := startDocker(t)
	server := gate(t, d, "sites")

	for name, header := range map[string]map[string]string{
		"nothing":       nil,
		"no token":      {"X-YorvoGate-Scope": "jane"},
		"a wrong token": {"X-YorvoGate-Scope": "jane", "X-YorvoGate-Token": "guess"},
		"another scope": {"X-YorvoGate-Scope": "blog", "X-YorvoGate-Token": token},
		"a path":        {"X-YorvoGate-Scope": "../jane", "X-YorvoGate-Token": token},
	} {
		if status, answer := send(t, server, "GET", "/_ping", "", header); status != http.StatusUnauthorized || !strings.Contains(message(t, answer), "no such scope") {
			t.Errorf("%s: %d %s", name, status, answer)
		}
	}

	jane := map[string]string{"X-YorvoGate-Scope": "jane", "X-YorvoGate-Token": token}
	if status, _ := send(t, server, "GET", "/v1.56/version", "", jane); status != 200 {
		t.Fatalf("its own scope: %d", status)
	}

	if h := d.last().header; h.Get("X-Yorvogate-Token") != "" || h.Get("X-Yorvogate-Scope") != "" {
		t.Error("the scope's token reached Docker")
	}

	if d.count() != 1 {
		t.Errorf("%d requests reached Docker, want 1", d.count())
	}
}

// Until each endpoint's rules are in place, a scope may do nothing but ping and ask the version.
func TestAScopeIsRefusedWhatItsRulesDontAllow(t *testing.T) {
	d := startDocker(t)
	server := gate(t, d, "sites")
	jane := map[string]string{"X-YorvoGate-Scope": "jane", "X-YorvoGate-Token": token}

	for _, c := range [][2]string{
		{"POST", "/v1.56/containers/create"},
		{"GET", "/v1.56/containers/json"},
		{"GET", "/v1.56/info"},
		{"POST", "/v1.56/images/x/push"},
	} {
		if status, answer := send(t, server, c[0], c[1], "", jane); status != http.StatusForbidden || !strings.Contains(message(t, answer), "isn't allowed for scope jane") {
			t.Errorf("%s %s: %d %s", c[0], c[1], status, answer)
		}
	}

	if status, _ := send(t, server, "GET", "/v1.56/version", "smuggled", jane); status != http.StatusBadRequest {
		t.Errorf("a body where there's none: %d", status)
	}

	if status, answer := send(t, server, "POST", "/v1.56/containers/create", strings.Repeat("x", 5000), jane); status != http.StatusRequestEntityTooLarge {
		t.Errorf("a body above the limit: %d %s", status, answer)
	}

	if d.count() != 0 {
		t.Errorf("%d requests reached Docker", d.count())
	}
}

// Attach and exec are streams both ways, through an HTTP upgrade only.
func TestStreamsAreUpgrades(t *testing.T) {
	d := startDocker(t)
	server := gate(t, d, "server")

	if status, answer := send(t, server, "POST", "/v1.56/exec/abc/start", `{"Detach":false}`, nil); status != http.StatusBadRequest || !strings.Contains(message(t, answer), "only as an HTTP upgrade") {
		t.Errorf("without an upgrade: %d %s", status, answer)
	}

	conn, err := net.Dial("tcp", strings.TrimPrefix(server.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	_, _ = conn.Write([]byte("POST /v1.56/exec/abc/start HTTP/1.1\r\nHost: docker\r\nContent-Type: application/json\r\nConnection: Upgrade\r\nUpgrade: tcp\r\nContent-Length: 16\r\n\r\n{\"Detach\":false}"))
	reader := bufio.NewReader(conn)

	res, err := http.ReadResponse(reader, nil)
	if err != nil || res.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade: %v %v", res, err)
	}

	_, _ = conn.Write([]byte("hello"))
	echo := make([]byte, 5)

	if _, err := io.ReadFull(reader, echo); err != nil || string(echo) != "hello" {
		t.Fatalf("the stream: %q %v", echo, err)
	}
}

func TestDockerNotAnsweringIsSaid(t *testing.T) {
	d := startDocker(t)
	server := gate(t, d, "server")
	_ = os.Remove(d.socket)

	if status, answer := send(t, server, "GET", "/v1.56/version", "", nil); status != http.StatusBadGateway || !strings.Contains(message(t, answer), "Docker didn't answer") {
		t.Errorf("%d %s", status, answer)
	}
}
