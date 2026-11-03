package main

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestVersion(t *testing.T) {
	var out, errs bytes.Buffer
	if code := run([]string{"version"}, &out, &errs); code != 0 || out.String() != "yorvogate dev\n" {
		t.Fatalf("%d %q %q", code, out.String(), errs.String())
	}
}

func TestCheckReadsTheConfigurationAndEveryScope(t *testing.T) {
	dir := t.TempDir()
	scopes := filepath.Join(dir, "scopes")
	_ = os.Mkdir(scopes, 0o700)
	configFile := filepath.Join(dir, "yorvogate.yaml")
	_ = os.WriteFile(configFile, []byte("upstream: unix:///var/run/docker.sock\nlisteners:\n  - {name: server, address: 'tcp://127.0.0.1:2375', mode: trusted, allow: {system: read}}\n  - {name: sites, address: 'tcp://127.0.0.1:2376', mode: scoped, scopes: "+scopes+"}\n"), 0o600)
	_ = os.WriteFile(filepath.Join(scopes, "jane.json"), []byte(`{"token_sha256": "`+strings.Repeat("a", 64)+`", "owner": {"label": "com.docker.compose.project", "value": "jane"}, "prefixes": ["jane-"]}`), 0o600)

	var out, errs bytes.Buffer
	if code := run([]string{"check", "--config", configFile}, &out, &errs); code != 0 || !strings.Contains(out.String(), "sites (scoped, tcp://127.0.0.1:2376): ok, 1 scopes") {
		t.Fatalf("%d %q %q", code, out.String(), errs.String())
	}

	_ = os.WriteFile(filepath.Join(scopes, "blog.json"), []byte(`{"owner": {}}`), 0o600)
	out.Reset()

	if code := run([]string{"check", "--config", configFile}, &out, &errs); code != 1 || !strings.Contains(errs.String(), "blog.json") {
		t.Fatalf("a broken scope: %d %q", code, errs.String())
	}
}

func TestCheckRefusesCrossListenerCollision(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a")
	b := filepath.Join(dir, "b")
	_ = os.Mkdir(a, 0o700)
	_ = os.Mkdir(b, 0o700)
	configFile := filepath.Join(dir, "yorvogate.yaml")
	_ = os.WriteFile(configFile, []byte("upstream: unix:///var/run/docker.sock\nlisteners:\n  - {name: one, address: 'tcp://127.0.0.1:2376', mode: scoped, scopes: "+a+"}\n  - {name: two, address: 'tcp://127.0.0.1:2377', mode: scoped, scopes: "+b+"}\n"), 0o600)
	// Two scopes on two listeners that share the owner label "shared": each passes its own folder,
	// but one listener's scope could then reach the other's objects.
	_ = os.WriteFile(filepath.Join(a, "alpha.json"), []byte(`{"token_sha256": "`+strings.Repeat("a", 64)+`", "owner": {"label": "com.docker.compose.project", "value": "shared"}, "prefixes": ["alpha-"]}`), 0o600)
	_ = os.WriteFile(filepath.Join(b, "beta.json"), []byte(`{"token_sha256": "`+strings.Repeat("b", 64)+`", "owner": {"label": "com.docker.compose.project", "value": "shared"}, "prefixes": ["beta-"]}`), 0o600)

	var out, errs bytes.Buffer
	if code := run([]string{"check", "--config", configFile}, &out, &errs); code != 1 || !strings.Contains(errs.String(), "owner label") {
		t.Fatalf("a cross-listener owner-label collision: %d %q %q", code, out.String(), errs.String())
	}
}

func TestCheckAllowsSameScopesOnTwoListeners(t *testing.T) {
	dir := t.TempDir()
	scopes := filepath.Join(dir, "scopes")
	_ = os.Mkdir(scopes, 0o700)
	configFile := filepath.Join(dir, "yorvogate.yaml")
	// One scopes folder served by two listeners (a token one and a socket one): the same scope on
	// both, which is allowed — a client is that one scope either way.
	_ = os.WriteFile(configFile, []byte("upstream: unix:///var/run/docker.sock\nlisteners:\n  - {name: tenants, address: 'tcp://127.0.0.1:2376', mode: scoped, scopes: "+scopes+"}\n  - {name: sockets, scope_sockets: "+filepath.Join(dir, "sock")+", socket_group: '0', mode: scoped, scopes: "+scopes+"}\n"), 0o600)
	_ = os.WriteFile(filepath.Join(scopes, "jane.json"), []byte(`{"token_sha256": "`+strings.Repeat("a", 64)+`", "owner": {"label": "com.docker.compose.project", "value": "jane"}, "prefixes": ["jane-"]}`), 0o600)

	var out, errs bytes.Buffer
	if code := run([]string{"check", "--config", configFile}, &out, &errs); code != 0 {
		t.Fatalf("the same scope on two listeners should be allowed: %d %q %q", code, out.String(), errs.String())
	}
}

func TestCheckWarnsOnDangerousConfig(t *testing.T) {
	dir := t.TempDir()
	scopes := filepath.Join(dir, "scopes")
	_ = os.Mkdir(scopes, 0o700)
	configFile := filepath.Join(dir, "yorvogate.yaml")
	// A scoped TCP listener open to the world, with privileged builders allowed: valid, but dangerous.
	_ = os.WriteFile(configFile, []byte("upstream: unix:///var/run/docker.sock\nlisteners:\n  - {name: sites, address: 'tcp://0.0.0.0:2376', mode: scoped, scopes: "+scopes+", allow_privileged_builders: true}\n"), 0o600)
	_ = os.WriteFile(filepath.Join(scopes, "jane.json"), []byte(`{"token_sha256": "`+strings.Repeat("a", 64)+`", "owner": {"label": "com.docker.compose.project", "value": "jane"}, "prefixes": ["jane-"]}`), 0o600)

	var out, errs bytes.Buffer
	if code := run([]string{"check", "--config", configFile}, &out, &errs); code != 0 {
		t.Fatalf("check should still pass (warnings, not errors): %d %q", code, errs.String())
	}

	for _, want := range []string{"cleartext", "allow_privileged_builders"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing warning %q in: %s", want, out.String())
		}
	}
}

func TestUsage(t *testing.T) {
	var out, errs bytes.Buffer
	if run(nil, &out, &errs) != 2 || run([]string{"open"}, &out, &errs) != 2 || run([]string{"check", "--nope"}, &out, &errs) != 2 {
		t.Fatal("usage errors exit 2")
	}
}

// serve answers on its listeners (a stale socket replaced, the new one its group's only), and stops
// when its context ends.
func TestServe(t *testing.T) {
	dir := t.TempDir()
	upstream := filepath.Join(dir, "docker.sock")
	gateSocket := filepath.Join(dir, "gate.sock")

	docker, err := net.Listen("unix", upstream)
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		_ = http.Serve(docker, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("OK")) }))
	}()
	defer docker.Close()

	stale, _ := net.Listen("unix", gateSocket)
	stale.(*net.UnixListener).SetUnlinkOnClose(false)
	_ = stale.Close()

	configFile := filepath.Join(dir, "yorvogate.yaml")
	_ = os.WriteFile(configFile, []byte("upstream: unix://"+upstream+"\nlisteners:\n  - {name: server, address: 'unix://"+gateSocket+"', mode: trusted, allow: {system: read}}\n"), 0o600)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)

	go func() { done <- serve(ctx, configFile, slog.New(slog.NewTextHandler(io.Discard, nil))) }()

	client := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", gateSocket)
	}}}

	var answer string
	for range 50 {
		if res, err := client.Get("http://gate/_ping"); err == nil {
			body, _ := io.ReadAll(res.Body)
			_ = res.Body.Close()
			answer = string(body)

			break
		}

		time.Sleep(20 * time.Millisecond)
	}

	if answer != "OK" {
		t.Fatalf("through the gate: %q", answer)
	}

	if info, err := os.Stat(gateSocket); err != nil || info.Mode().Perm() != 0o660 {
		t.Errorf("the socket's mode: %v %v", info.Mode(), err)
	}

	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("stopped with %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("it didn't stop")
	}
}

func TestServeRefusesABadConfiguration(t *testing.T) {
	configFile := filepath.Join(t.TempDir(), "yorvogate.yaml")
	_ = os.WriteFile(configFile, []byte("upstream: tcp://docker:2375\n"), 0o600)

	if err := serve(context.Background(), configFile, slog.New(slog.NewTextHandler(io.Discard, nil))); err == nil {
		t.Fatal("it started")
	}
}

// A socket-bound listener: a socket for each scope at start, one for a scope added when SIGHUP
// comes (not waiting for the next scan), and none left once it stops.
func TestServeScopeSockets(t *testing.T) {
	dir := t.TempDir()
	upstream := filepath.Join(dir, "docker.sock")

	docker, err := net.Listen("unix", upstream)
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		_ = http.Serve(docker, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("OK")) }))
	}()
	defer docker.Close()

	scopes, sockets := filepath.Join(dir, "scopes"), filepath.Join(dir, "s")
	_ = os.Mkdir(scopes, 0o700)
	_ = os.Mkdir(sockets, 0o700)
	_ = os.WriteFile(filepath.Join(scopes, "jane.json"), []byte(`{"owner": {"label": "com.docker.compose.project", "value": "jane"}, "prefixes": ["jane-"]}`), 0o600)

	configFile := filepath.Join(dir, "yorvogate.yaml")
	_ = os.WriteFile(configFile, []byte("upstream: unix://"+upstream+"\nlisteners:\n  - {name: sites, scope_sockets: "+sockets+", mode: scoped, scopes: "+scopes+"}\n"), 0o600)

	var out, errs bytes.Buffer
	if code := run([]string{"check", "--config", configFile}, &out, &errs); code != 0 || !strings.Contains(out.String(), "sites (scoped, scope_sockets "+sockets+"): ok, 1 scopes") {
		t.Fatalf("check: %d %q %q", code, out.String(), errs.String())
	}

	interval := scanInterval
	scanInterval = time.Hour
	defer func() { scanInterval = interval }()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)

	go func() { done <- serve(ctx, configFile, slog.New(slog.NewTextHandler(io.Discard, nil))) }()

	ping := func(scope string) string {
		client := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", filepath.Join(sockets, scope+".sock"))
		}}}

		for range 100 {
			if res, err := client.Get("http://gate/_ping"); err == nil {
				body, _ := io.ReadAll(res.Body)
				_ = res.Body.Close()

				return string(body)
			}

			time.Sleep(20 * time.Millisecond)
		}

		return ""
	}

	if answer := ping("jane"); answer != "OK" {
		t.Fatalf("on jane's socket: %q", answer)
	}

	_ = os.WriteFile(filepath.Join(scopes, "blog.json"), []byte(`{"owner": {"label": "com.docker.compose.project", "value": "blog"}, "prefixes": ["blog-"]}`), 0o600)
	_ = syscall.Kill(os.Getpid(), syscall.SIGHUP)

	if answer := ping("blog"); answer != "OK" {
		t.Fatalf("on blog's socket, after SIGHUP: %q", answer)
	}

	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("stopped with %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("it didn't stop")
	}

	if left, _ := filepath.Glob(filepath.Join(sockets, "*")); len(left) != 0 {
		t.Errorf("left behind: %v", left)
	}
}
