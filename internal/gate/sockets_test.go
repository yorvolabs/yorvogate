package gate

import (
	"bufio"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/yorvolabs/yorvogate/internal/config"
)

const (
	tokenlessJane = `{"owner": {"label": "com.docker.compose.project", "value": "jane"}, "prefixes": ["jane-", "jane_"], "builders": ["buildx_buildkit_jane0"]}`
	tokenlessBlog = `{"owner": {"label": "com.docker.compose.project", "value": "blog"}, "prefixes": ["blog-", "blog_"]}`
)

// boundGate serves a socket-bound listener in front of the fake Docker: its scope files' folder and
// its sockets' folder.
func boundGate(t *testing.T, d *docker, group string) (*Sockets, string, string) {
	t.Helper()
	scopes := t.TempDir()

	// A socket's path is at most 107 bytes: a short folder of its own
	sockets, err := os.MkdirTemp("", "yg")
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = os.RemoveAll(sockets) })

	writeScope(t, scopes, "jane", tokenlessJane)
	writeScope(t, scopes, "blog", tokenlessBlog)

	listener := "  - {name: sites, scope_sockets: " + sockets + ", mode: scoped, scopes: " + scopes
	if group != "" {
		listener += ", socket_group: '" + group + "'"
	}

	c, err := config.Parse([]byte("upstream: unix://" + d.socket + "\nlisteners:\n" + listener + "}\n"))
	if err != nil {
		t.Fatal(err)
	}

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	s, err := NewSockets(New(c, c.Listeners[0], NewUpstream(c, log), Registry(c), readDefaults(c), log), log)
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { s.Shutdown(context.Background()) })

	if err := rescan(s); err != nil {
		t.Fatal(err)
	}

	return s, scopes, sockets
}

// rescan reloads the scope files and brings the sockets in line, as serve's scan does.
func rescan(s *Sockets) error {
	if err := s.gate.registry.Reload(); err != nil {
		return err
	}

	return s.Scan()
}

func writeScope(t *testing.T, dir, name, content string) {
	t.Helper()

	if err := os.WriteFile(filepath.Join(dir, name+".json"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// on sends a request on a socket.
func on(t *testing.T, socket, method, path, body string, header map[string]string) (int, string, error) {
	t.Helper()

	client := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}}
	defer client.CloseIdleConnections()

	req, _ := http.NewRequest(method, "http://docker"+path, strings.NewReader(body))
	for k, v := range header {
		req.Header.Set(k, v)
	}

	res, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer res.Body.Close()

	answer, _ := io.ReadAll(res.Body)

	return res.StatusCode, string(answer), nil
}

func sockets(t *testing.T, dir string) string {
	t.Helper()

	files, _ := filepath.Glob(filepath.Join(dir, "*.sock"))
	names := make([]string, len(files))

	for i, f := range files {
		names[i] = filepath.Base(f)
	}

	return strings.Join(names, ",")
}

// A socket per scope file: it comes with the file, and goes with it.
func TestASocketPerScope(t *testing.T) {
	d := startDocker(t)
	s, scopes, dir := boundGate(t, d, "")

	if got := sockets(t, dir); got != "blog.sock,jane.sock" {
		t.Fatalf("sockets: %s", got)
	}

	writeScope(t, scopes, "ci", `{"owner": {"label": "example.ci.job", "value": "7"}, "prefixes": ["ci-"]}`)
	_ = os.Remove(filepath.Join(scopes, "blog.json"))

	if err := rescan(s); err != nil {
		t.Fatal(err)
	}

	if got := sockets(t, dir); got != "ci.sock,jane.sock" {
		t.Errorf("after a scope came and one went: %s", got)
	}

	if _, _, err := on(t, filepath.Join(dir, "blog.sock"), "GET", "/_ping", "", nil); err == nil {
		t.Error("a removed scope's socket still answers")
	}

	// A scan that changes nothing keeps the sockets (and their connections) as they are.
	before, _ := os.Stat(filepath.Join(dir, "jane.sock"))
	if err := rescan(s); err != nil {
		t.Fatal(err)
	}

	if after, _ := os.Stat(filepath.Join(dir, "jane.sock")); !os.SameFile(before, after) {
		t.Error("jane's socket was made again")
	}
}

// A request on jane's socket is jane's, with no header or token; one that names another scope is
// refused, never re-scoped.
func TestARequestOnAScopesSocketIsTheScopes(t *testing.T) {
	d := startDocker(t)
	_, _, dir := boundGate(t, d, "")
	jane := filepath.Join(dir, "jane.sock")

	status, answer, err := on(t, jane, "POST", "/v1.56/containers/jane-php-1/start", "", nil)
	if err != nil || status != http.StatusOK || d.last().path != "/v1.56/containers/"+janePHP+"/start" {
		t.Fatalf("jane's start: %d %s %v", status, answer, err)
	}

	if d.last().header.Get("X-Yorvogate-Scope") != "" {
		t.Error("Docker got YorvoGate's header")
	}

	before := d.count()

	for name, c := range map[string]struct {
		path   string
		header map[string]string
		want   int
	}{
		"blog's container (hidden)":         {"/v1.56/containers/blog-php-1/start", nil, http.StatusNotFound},
		"naming blog":                       {"/v1.56/containers/blog-php-1/start", map[string]string{"X-YorvoGate-Scope": "blog"}, http.StatusForbidden},
		"naming blog, for jane's":           {"/v1.56/containers/jane-php-1/start", map[string]string{"X-YorvoGate-Scope": "blog"}, http.StatusForbidden},
		"naming a scope that doesn't exist": {"/v1.56/containers/jane-php-1/start", map[string]string{"X-YorvoGate-Scope": "nobody"}, http.StatusForbidden},
	} {
		status, answer, err := on(t, jane, "POST", c.path, "", c.header)
		if err != nil || status != c.want || !strings.HasPrefix(message(t, answer), "yorvogate: ") {
			t.Errorf("%s: %d %s %v", name, status, answer, err)
		}
	}

	if d.count() != before {
		t.Errorf("%d refused requests reached Docker", d.count()-before)
	}

	// Naming its own scope is no harm; a token isn't needed.
	if status, answer, _ := on(t, jane, "POST", "/v1.56/containers/jane-php-1/stop", "", map[string]string{"X-YorvoGate-Scope": "jane", "X-YorvoGate-Token": "whatever"}); status != http.StatusOK {
		t.Errorf("naming itself: %d %s", status, answer)
	}

	if h := d.last().header; h.Get("X-Yorvogate-Token") != "" || h.Get("X-Yorvogate-Scope") != "" {
		t.Error("Docker got YorvoGate's headers")
	}
}

// A scope file that's no longer valid closes its socket, and every connection on it: a stream (an
// exec, BuildKit's dial-stdio) included.
func TestAnInvalidScopeClosesItsSocket(t *testing.T) {
	d := startDocker(t)
	s, scopes, dir := boundGate(t, d, "")

	conn, err := net.Dial("unix", filepath.Join(dir, "jane.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	_, _ = conn.Write([]byte("POST /v1.56/exec/exec-jane/start HTTP/1.1\r\nHost: docker\r\nContent-Type: application/json\r\nConnection: Upgrade\r\nUpgrade: tcp\r\nContent-Length: 16\r\n\r\n{\"Detach\":false}"))
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

	// jane's file loses its prefixes: it's no longer valid.
	writeScope(t, scopes, "jane", strings.Replace(tokenlessJane, `["jane-", "jane_"]`, `[]`, 1))

	if err := rescan(s); err != nil {
		t.Fatal(err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := reader.ReadByte(); !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) && !errors.Is(err, syscall.ECONNRESET) {
		t.Errorf("the stream is still open: %v", err)
	}

	if got := sockets(t, dir); got != "blog.sock" {
		t.Errorf("sockets: %s", got)
	}

	// Valid again: its socket comes back.
	writeScope(t, scopes, "jane", tokenlessJane)

	if err := rescan(s); err != nil {
		t.Fatal(err)
	}

	if status, _, err := on(t, filepath.Join(dir, "jane.sock"), "GET", "/_ping", "", nil); err != nil || status != http.StatusOK {
		t.Errorf("jane valid again: %d %v", status, err)
	}
}

// Sockets are their owner's and group's only (0660), the group as configured; a stale socket is
// replaced, anything else at its path is left alone, and tried again at the next scan.
func TestASocketsPermissions(t *testing.T) {
	d := startDocker(t)
	gid := os.Getgid()

	groups, _ := os.Getgroups()
	for _, g := range groups {
		if g != gid {
			gid = g

			break
		}
	}

	s, scopes, dir := boundGate(t, d, strconv.Itoa(gid))

	for _, name := range []string{"jane.sock", "blog.sock"} {
		info, err := os.Lstat(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}

		if info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0o660 || int(info.Sys().(*syscall.Stat_t).Gid) != gid {
			t.Errorf("%s: %v, group %d (want %d)", name, info.Mode(), info.Sys().(*syscall.Stat_t).Gid, gid)
		}
	}

	// A stale socket is replaced; a file that isn't a socket isn't.
	stale, _ := net.Listen("unix", filepath.Join(dir, "ci.sock"))
	stale.(*net.UnixListener).SetUnlinkOnClose(false)
	_ = stale.Close()
	_ = os.WriteFile(filepath.Join(dir, "web.sock"), []byte("not a socket"), 0o600)

	writeScope(t, scopes, "ci", `{"owner": {"label": "example.ci.job", "value": "7"}, "prefixes": ["ci-"]}`)
	writeScope(t, scopes, "web", `{"owner": {"label": "example.web", "value": "1"}, "prefixes": ["web-"]}`)

	if err := rescan(s); err == nil || !strings.Contains(err.Error(), "scope web's socket") || strings.Contains(err.Error(), "scope ci's") {
		t.Errorf("a scan with web.sock taken: %v", err)
	}

	if status, _, err := on(t, filepath.Join(dir, "ci.sock"), "GET", "/_ping", "", nil); err != nil || status != http.StatusOK {
		t.Errorf("ci's socket, made over a stale one: %d %v", status, err)
	}

	if content, _ := os.ReadFile(filepath.Join(dir, "web.sock")); string(content) != "not a socket" {
		t.Error("a file that isn't a socket was replaced")
	}

	_ = os.Remove(filepath.Join(dir, "web.sock"))
	if err := rescan(s); err != nil {
		t.Errorf("tried again: %v", err)
	}

	if status, _, err := on(t, filepath.Join(dir, "web.sock"), "GET", "/_ping", "", nil); err != nil || status != http.StatusOK {
		t.Errorf("web's socket, tried again: %d %v", status, err)
	}
}
