package gate

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yorvolabs/yorvogate/internal/config"
	"github.com/yorvolabs/yorvogate/internal/scope"
)

// unixGate serves a scoped listener on a unix address, scope jane by token, with these peer users
// (none when empty): the socket's path, its gate, and the scope files' folder.
func unixGate(t *testing.T, d *docker, uids string) (string, *Gate, string) {
	t.Helper()
	scopes, dir := t.TempDir(), t.TempDir()
	writeScope(t, scopes, "jane", janeWithPeers(uids))
	socket := filepath.Join(dir, "sites.sock")

	c, err := config.Parse([]byte("upstream: unix://" + d.socket + "\nlisteners:\n  - {name: sites, address: 'unix://" + socket + "', mode: scoped, scopes: " + scopes + "}\n"))
	if err != nil {
		t.Fatal(err)
	}

	registry := Registry(c)
	if err := registry.Reload(); err != nil {
		t.Fatal(err)
	}

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	g := New(c, c.Listeners[0], NewUpstream(c, log), registry, readDefaults(c), log)

	raw, err := Listen(socket, -1)
	if err != nil {
		t.Fatal(err)
	}

	server := NewServer(g)
	// Wrapped as serve wraps it: Listen's limit, then the listener's
	go func() { _ = server.Serve(LimitListener(raw, MaxConnections)) }()
	t.Cleanup(func() { _ = server.Close() })

	return socket, g, scopes
}

func janeWithPeers(uids string) string {
	peers := ""
	if uids != "" {
		peers = `"peer_uids": [` + uids + `], `
	}

	return `{"token_sha256": "` + sha(token) + `", ` + peers + `"owner": {"label": "com.docker.compose.project", "value": "jane"}, "prefixes": ["jane-", "jane_"]}`
}

// getUnix sends a request as jane over the unix socket: its status and YorvoGate's message.
func getUnix(t *testing.T, socket, path string) (int, string) {
	t.Helper()
	c := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}, Timeout: 5 * time.Second}

	req, _ := http.NewRequest("GET", "http://docker"+path, nil)
	for k, v := range asJane {
		req.Header.Set(k, v)
	}

	res, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()

	body, _ := io.ReadAll(res.Body)

	return res.StatusCode, string(body)
}

// A scope that lists peer users is the scope, its token proved, only over a connection from one of
// them; the refusal names the connection's user. One that lists none is any user's.
func TestAScopesPeerUsers(t *testing.T) {
	me := os.Getuid()

	for _, c := range []struct {
		name, uids string
		status     int
		want       string
	}{
		{"none listed", "", 200, ""},
		{"its user listed", fmt.Sprint(me), 200, ""},
		{"among others", fmt.Sprintf("0, %d, 4242", me), 200, ""},
		{"another user", fmt.Sprint(me + 4242), http.StatusForbidden, fmt.Sprintf("this connection's user (UID %d) isn't one of scope jane's peer_uids", me)},
	} {
		t.Run(c.name, func(t *testing.T) {
			d := startDocker(t)
			socket, _, _ := unixGate(t, d, c.uids)

			if status, body := getUnix(t, socket, "/v1.56/exec/exec-jane/json"); status != c.status || !strings.Contains(body, c.want) {
				t.Errorf("%d %s", status, body)
			}
		})
	}
}

// A stream's peer user is checked again at each scan: no longer listed, its stream ends.
func TestAPeerUsersStreamEndsWhenItsNoLongerListed(t *testing.T) {
	d := startDocker(t)
	socket, g, scopes := unixGate(t, d, fmt.Sprint(os.Getuid()))

	conn, reader := execStreamOn(t, "unix", socket, "exec-jane", asJane)

	revoke(t, g)
	echoes(t, conn, reader)

	writeScope(t, scopes, "jane", janeWithPeers(fmt.Sprint(os.Getuid()+4242)))
	revoke(t, g)

	if !ended(t, conn, reader) {
		t.Error("the stream is still open")
	}
}

// A scope with peer users refuses a connection whose peer isn't known; and a folder may have them
// only where every listener of it is on a unix address, and must where one of them requires them.
func TestPeerUsersAreForUnixAddressesOnly(t *testing.T) {
	if s := (&scope.Scope{PeerUIDs: []uint32{1000}}); s.PeerAllowed(1000, false) {
		t.Error("an unknown peer, allowed")
	}

	for _, c := range []struct {
		name, listeners string
		with, without   bool // a scope with peer_uids valid; one without
	}{
		{"a unix address", "  - {name: a, address: 'unix:///run/a.sock', mode: scoped, scopes: DIR}\n", true, true},
		{"one requiring", "  - {name: a, address: 'unix:///run/a.sock', mode: scoped, scopes: DIR, require_peer_uids: true}\n  - {name: b, address: 'unix:///run/b.sock', mode: scoped, scopes: DIR}\n", true, false},
		{"and TCP", "  - {name: a, address: 'unix:///run/a.sock', mode: scoped, scopes: DIR}\n  - {name: b, address: 'tcp://127.0.0.1:2376', mode: scoped, scopes: DIR}\n", false, true},
		{"and scope sockets", "  - {name: a, address: 'unix:///run/a.sock', mode: scoped, scopes: DIR}\n  - {name: b, scope_sockets: /run/b, mode: scoped, scopes: DIR}\n", false, true},
	} {
		for _, peers := range []bool{true, false} {
			dir := t.TempDir()
			uids := ""
			if peers {
				uids = "1000"
			}

			writeScope(t, dir, "jane", janeWithPeers(uids))

			cfg, err := config.Parse([]byte("upstream: unix:///run/docker.sock\nlisteners:\n" + strings.ReplaceAll(c.listeners, "DIR", dir)))
			if err != nil {
				t.Fatalf("%s: %v", c.name, err)
			}

			registry := Registry(cfg)
			if err := registry.Reload(); err != nil {
				t.Fatal(err)
			}

			want := c.without
			if peers {
				want = c.with
			}

			if _, err := registry.Store("a").Get("jane"); (err == nil) != want {
				t.Errorf("%s, peer_uids %v: %v", c.name, peers, err)
			}
		}
	}
}
