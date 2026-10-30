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
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/yorvolabs/yorvogate/internal/config"
)

const token = "a-long-random-token-0123456789abcdef"

// IDs of the fake Docker's objects
const (
	janePHP     = "aaaa000000000000000000000000000000000000000000000000000000000001"
	blogPHP     = "bbbb000000000000000000000000000000000000000000000000000000000002"
	janeBuilder = "cccc000000000000000000000000000000000000000000000000000000000003"
	janeNet     = "dddd000000000000000000000000000000000000000000000000000000000004"
	blogNet     = "eeee000000000000000000000000000000000000000000000000000000000005"
	linkNet     = "ffff000000000000000000000000000000000000000000000000000000000006"
)

// docker is a fake Docker on a unix socket. It knows two scopes' objects (jane's and blog's, by
// Compose's project label), a shared network and jane's builder; it answers inspections of them, and
// records every other request it gets (what YorvoGate forwarded), answering 200. For an upgrade it
// hijacks the connection and echoes.
type docker struct {
	mu        sync.Mutex
	forwarded []seen
	socket    string
}

type seen struct {
	method, path, query string
	header              http.Header
	body                string
}

type fakeObject struct {
	id, name string
	labels   map[string]string
}

var (
	jane = map[string]string{"com.docker.compose.project": "jane"}
	blog = map[string]string{"com.docker.compose.project": "blog"}

	containers = []fakeObject{{janePHP, "jane-php-1", jane}, {blogPHP, "blog-php-1", blog}, {janeBuilder, "buildx_buildkit_jane-0", nil}}
	networks   = []fakeObject{{janeNet, "jane_default", jane}, {blogNet, "blog_default", blog}, {linkNet, "quire-link-jane", nil}}
	volumes    = []fakeObject{{"jane_data", "jane_data", jane}, {"blog_data", "blog_data", blog}}
	execs      = map[string]string{"exec-jane": janePHP, "exec-blog": blogPHP}
	images     = []fakeImage{
		{"sha256:" + strings.Repeat("1", 64), []string{"alpine:3.22"}},
		{"sha256:" + strings.Repeat("2", 64), []string{"quire-sites/jane/php-prod:latest"}},
		{"sha256:" + strings.Repeat("3", 64), []string{"quire-sites/blog/php-prod:latest"}},
		{"sha256:" + strings.Repeat("4", 64), nil}, // a build's leftover, anyone's
	}

	inspection  = regexp.MustCompile(`^/v[0-9.]+/(containers|networks|volumes|exec)/([^/]+)(/json)?$`)
	imageLookup = regexp.MustCompile(`^/v[0-9.]+/images/(.+)/json$`)
)

type fakeImage struct {
	id   string
	tags []string
}

func findImage(ref string) *fakeImage {
	for i := range images {
		img := &images[i]
		if img.id == ref || strings.TrimPrefix(img.id, "sha256:")[:12] == strings.TrimPrefix(ref, "sha256:") {
			return img
		}

		for _, tag := range img.tags {
			if tag == ref || strings.TrimSuffix(tag, ":latest") == ref {
				return img
			}
		}
	}

	return nil
}

func find(objects []fakeObject, key string) *fakeObject {
	for i := range objects {
		if objects[i].id == key || objects[i].name == key || (len(key) >= 4 && strings.HasPrefix(objects[i].id, key)) {
			return &objects[i]
		}
	}

	return nil
}

func startDocker(t *testing.T) *docker {
	t.Helper()
	d := &docker{socket: filepath.Join(t.TempDir(), "docker.sock")}

	listener, err := net.Listen("unix", d.socket)
	if err != nil {
		t.Fatal(err)
	}

	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("User-Agent") == "yorvogate" {
			d.inspect(w, r)

			return
		}

		body, _ := io.ReadAll(r.Body)
		d.mu.Lock()
		d.forwarded = append(d.forwarded, seen{r.Method, r.URL.Path, r.URL.RawQuery, r.Header.Clone(), string(body)})
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

		// Answers a rule changes: the image list, and the shared network with every scope on it
		switch r.URL.Path {
		case "/v1.56/images/json":
			list := []map[string]any{}
			for _, img := range images {
				list = append(list, map[string]any{"Id": img.id, "RepoTags": img.tags})
			}

			_ = json.NewEncoder(w).Encode(list)
		case "/v1.56/networks/" + linkNet:
			_ = json.NewEncoder(w).Encode(map[string]any{"Name": "quire-link-jane", "Id": linkNet, "Containers": map[string]any{
				janePHP: map[string]any{"Name": "jane-php-1", "IPv4Address": "10.213.0.4/27"},
				blogPHP: map[string]any{"Name": "blog-php-1", "IPv4Address": "10.213.0.5/27"},
			}})
		default:
			_, _ = w.Write([]byte(`{"ok":true}`))
		}
	})}

	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })

	return d
}

// inspect answers YorvoGate's lookups, as Docker's inspect endpoints do.
func (d *docker) inspect(w http.ResponseWriter, r *http.Request) {
	if m := imageLookup.FindStringSubmatch(r.URL.Path); m != nil {
		img := findImage(m[1])
		if img == nil {
			http.Error(w, `{"message":"No such image"}`, http.StatusNotFound)

			return
		}

		_ = json.NewEncoder(w).Encode(map[string]any{"Id": img.id, "RepoTags": img.tags})

		return
	}

	m := inspection.FindStringSubmatch(r.URL.Path)
	if m == nil {
		http.Error(w, `{"message":"unexpected lookup"}`, http.StatusInternalServerError)

		return
	}

	var answer any

	switch m[1] {
	case "containers":
		if o := find(containers, m[2]); o != nil {
			answer = map[string]any{"Id": o.id, "Name": "/" + o.name, "Config": map[string]any{"Labels": o.labels}}
		}
	case "networks":
		if o := find(networks, m[2]); o != nil {
			answer = map[string]any{"Id": o.id, "Name": o.name, "Labels": o.labels}
		}
	case "volumes":
		if o := find(volumes, m[2]); o != nil {
			answer = map[string]any{"Name": o.name, "Labels": o.labels}
		}
	case "exec":
		if c, ok := execs[m[2]]; ok {
			answer = map[string]any{"ID": m[2], "ContainerID": c}
		}
	}

	if answer == nil {
		http.Error(w, `{"message":"no such object"}`, http.StatusNotFound)

		return
	}

	_ = json.NewEncoder(w).Encode(answer)
}

func (d *docker) last() seen {
	d.mu.Lock()
	defer d.mu.Unlock()

	if len(d.forwarded) == 0 {
		return seen{}
	}

	return d.forwarded[len(d.forwarded)-1]
}

func (d *docker) count() int {
	d.mu.Lock()
	defer d.mu.Unlock()

	return len(d.forwarded)
}

const scopeFile = `{
	"token_sha256": "%s",
	"owner": {"label": "com.docker.compose.project", "value": "jane"},
	"prefixes": ["jane-", "jane_"],
	"images": ["quire-sites/jane/"],
	"networks": {"quire-link-jane": {"aliases": ["jane.example.quire.internal"], "addresses": ["10.213.0.4"]}},
	"containers": ["buildx_buildkit_jane-*"],
	"subnets": ["10.213.0.32/27", "10.213.0.64/27"]
}`

// gate serves one listener in front of the fake Docker.
func gate(t *testing.T, d *docker, listener string) *httptest.Server {
	t.Helper()
	scopes := t.TempDir()
	sum := sha256.Sum256([]byte(token))

	if err := os.WriteFile(filepath.Join(scopes, "jane.json"), []byte(strings.Replace(scopeFile, "%s", hex.EncodeToString(sum[:]), 1)), 0o600); err != nil {
		t.Fatal(err)
	}

	c, err := config.Parse([]byte(`
upstream: unix://` + d.socket + `
body_limit: 4096
load_limit: 1048576
listeners:
  - name: server
    address: tcp://127.0.0.1:2375
    mode: trusted
    allow: {system: read, containers: write, exec: write}
  - name: sites
    address: tcp://127.0.0.1:2376
    mode: scoped
    scopes: ` + scopes + `
    containers:
      capabilities: [NET_BIND_SERVICE, CHOWN]
      drop_all_capabilities: true
      no_new_privileges: true
      ulimits: [nofile]
      max_memory: 1073741824
      max_pids: 512
      protected_images: [quire-sites/]
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

var asJane = map[string]string{"X-YorvoGate-Scope": "jane", "X-YorvoGate-Token": token}

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

	if status, _ := send(t, server, "GET", "/v1.56/version", "", asJane); status != 200 {
		t.Fatalf("its own scope: %d", status)
	}

	if h := d.last().header; h.Get("X-Yorvogate-Token") != "" || h.Get("X-Yorvogate-Scope") != "" {
		t.Error("the scope's token reached Docker")
	}

	if d.count() != 1 {
		t.Errorf("%d requests reached Docker, want 1", d.count())
	}
}

// What no rule allows a scope is refused, and bodies come only where an endpoint takes one.
func TestAScopeIsRefusedWhatNoRuleAllows(t *testing.T) {
	d := startDocker(t)
	server := gate(t, d, "sites")

	for _, c := range [][2]string{
		{"POST", "/v1.56/images/x/push"},
		{"POST", "/v1.56/images/prune"},
		{"PUT", "/v1.56/volumes/jane_data"},
		{"POST", "/v1.56/build"},
		{"GET", "/v1.56/events"},
		{"POST", "/v1.56/auth"},
		{"POST", "/v1.56/commit?container=jane-php-1"},
		{"GET", "/v1.56/swarm"},
		{"POST", "/v1.56/session"},
	} {
		if status, answer := send(t, server, c[0], c[1], "", asJane); status != http.StatusForbidden || !strings.Contains(message(t, answer), "isn't allowed for scope jane") {
			t.Errorf("%s %s: %d %s", c[0], c[1], status, answer)
		}
	}

	if status, _ := send(t, server, "GET", "/v1.56/version", "smuggled", asJane); status != http.StatusBadRequest {
		t.Errorf("a body where there's none: %d", status)
	}

	if status, answer := send(t, server, "POST", "/v1.56/containers/create?name=jane-x", strings.Repeat("x", 5000), asJane); status != http.StatusRequestEntityTooLarge {
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

	if status, answer := send(t, server, "POST", "/v1.56/containers/abc/attach?stream=1", "", nil); status != http.StatusBadRequest || !strings.Contains(message(t, answer), "only as an HTTP upgrade") {
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
