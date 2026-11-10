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
	// but one listener's scope could then reach the other's objects. Neither held it: both are
	// refused, and check names both.
	_ = os.WriteFile(filepath.Join(a, "alpha.json"), []byte(`{"token_sha256": "`+strings.Repeat("a", 64)+`", "owner": {"label": "com.docker.compose.project", "value": "shared"}, "prefixes": ["alpha-"]}`), 0o600)
	_ = os.WriteFile(filepath.Join(b, "beta.json"), []byte(`{"token_sha256": "`+strings.Repeat("b", 64)+`", "owner": {"label": "com.docker.compose.project", "value": "shared"}, "prefixes": ["beta-"]}`), 0o600)

	var out, errs bytes.Buffer
	if code := run([]string{"check", "--config", configFile}, &out, &errs); code != 1 || !strings.Contains(errs.String(), "owner: com.docker.compose.project=shared") || !strings.Contains(errs.String(), "alpha.json") || !strings.Contains(errs.String(), "beta.json") {
		t.Fatalf("a cross-listener owner-label collision: %d %q %q", code, out.String(), errs.String())
	}
}

// Nested scopes on two listeners pass check, resolved as in one folder; a nested file that isn't
// valid is named, and with a state file its claims are held.
func TestCheckNestedScopesOnTwoListeners(t *testing.T) {
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	_ = os.Mkdir(a, 0o700)
	_ = os.Mkdir(b, 0o700)
	state := filepath.Join(dir, "state.json")
	configFile := filepath.Join(dir, "yorvogate.yaml")
	_ = os.WriteFile(configFile, []byte("upstream: unix:///var/run/docker.sock\nstate_file: "+state+"\nlisteners:\n  - {name: one, address: 'tcp://127.0.0.1:2376', mode: scoped, scopes: "+a+"}\n  - {name: two, address: 'tcp://127.0.0.1:2377', mode: scoped, scopes: "+b+"}\n"), 0o600)
	_ = os.WriteFile(filepath.Join(a, "jane.json"), []byte(`{"token_sha256": "`+strings.Repeat("a", 64)+`", "owner": {"label": "com.docker.compose.project", "value": "jane"}, "prefixes": ["jane-"]}`), 0o600)
	_ = os.WriteFile(filepath.Join(b, "jane-blog.json"), []byte(`{"token_sha256": "`+strings.Repeat("b", 64)+`", "owner": {"label": "com.docker.compose.project", "value": "jane-blog"}, "prefixes": ["jane-blog-"]}`), 0o600)

	var out, errs bytes.Buffer
	if code := run([]string{"check", "--config", configFile}, &out, &errs); code != 0 || strings.Contains(out.String(), "state_file") {
		t.Fatalf("nested on two listeners: %d %q %q", code, out.String(), errs.String())
	}

	// check never writes the state file
	if _, err := os.Stat(state); err == nil {
		t.Error("check wrote the state file")
	}

	_ = os.WriteFile(filepath.Join(b, "jane-blog.json"), []byte(`{"token_sha256": `), 0o600)
	out.Reset()

	if code := run([]string{"check", "--config", configFile}, &out, &errs); code != 1 || !strings.Contains(errs.String(), "jane-blog.json") {
		t.Fatalf("a half-written nested file: %d %q", code, errs.String())
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
		_ = http.Serve(docker, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Docker's defaults, as YorvoGate reads them before it answers a scope
			if strings.HasSuffix(r.URL.Path, "/info") {
				_, _ = w.Write([]byte(`{"SecurityOptions": ["name=apparmor,profile=default", "name=seccomp,profile=builtin", "name=cgroupns"], "DefaultRuntime": "runc"}`))

				return
			}

			_, _ = w.Write([]byte("OK"))
		}))
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
		_ = http.Serve(docker, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Docker's defaults, as YorvoGate reads them before it answers a scope
			if strings.HasSuffix(r.URL.Path, "/info") {
				_, _ = w.Write([]byte(`{"SecurityOptions": ["name=apparmor,profile=default", "name=seccomp,profile=builtin", "name=cgroupns"], "DefaultRuntime": "runc"}`))

				return
			}

			_, _ = w.Write([]byte("OK"))
		}))
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

// check names what has no version, and refuses what has one it doesn't read.
func TestCheckFormatVersions(t *testing.T) {
	dir := t.TempDir()
	scopes := filepath.Join(dir, "scopes")
	_ = os.Mkdir(scopes, 0o700)
	configFile := filepath.Join(dir, "yorvogate.yaml")
	body := "upstream: unix:///var/run/docker.sock\nlisteners:\n  - {name: sites, address: 'tcp://127.0.0.1:2376', mode: scoped, scopes: " + scopes + "}\n"
	_ = os.WriteFile(configFile, []byte(body), 0o600)
	_ = os.WriteFile(filepath.Join(scopes, "jane.json"), []byte(`{"token_sha256": "`+strings.Repeat("a", 64)+`", "owner": {"label": "com.docker.compose.project", "value": "jane"}, "prefixes": ["jane-"]}`), 0o600)

	var out, errs bytes.Buffer
	if code := run([]string{"check", "--config", configFile}, &out, &errs); code != 0 || !strings.Contains(out.String(), "the configuration has no version") || !strings.Contains(out.String(), "1 scope files have no version (jane)") {
		t.Fatalf("no versions: %d %q %q", code, out.String(), errs.String())
	}

	_ = os.WriteFile(configFile, []byte("version: 1\n"+body), 0o600)
	_ = os.WriteFile(filepath.Join(scopes, "jane.json"), []byte(`{"version": 1, "token_sha256": "`+strings.Repeat("a", 64)+`", "owner": {"label": "com.docker.compose.project", "value": "jane"}, "prefixes": ["jane-"]}`), 0o600)
	out.Reset()

	if code := run([]string{"check", "--config", configFile}, &out, &errs); code != 0 || strings.Contains(out.String(), "no version") {
		t.Fatalf("versioned: %d %q %q", code, out.String(), errs.String())
	}

	_ = os.WriteFile(configFile, []byte("version: 2\n"+body), 0o600)
	errs.Reset()

	if code := run([]string{"check", "--config", configFile}, &out, &errs); code != 1 || !strings.Contains(errs.String(), "version: 2 isn't a format this build reads") {
		t.Fatalf("version 2: %d %q", code, errs.String())
	}
}

// A scope whose image namespaces are on a registry its listener doesn't list gets a notice: its
// pulls from there are refused. It's no error: the scope still works.
func TestCheckNamesRegistriesNotListed(t *testing.T) {
	dir := t.TempDir()
	scopes := filepath.Join(dir, "scopes")
	_ = os.Mkdir(scopes, 0o700)
	configFile := filepath.Join(dir, "yorvogate.yaml")
	config := "upstream: unix:///var/run/docker.sock\nlisteners:\n  - {name: sites, address: 'tcp://127.0.0.1:2376', mode: scoped, scopes: " + scopes + "%s}\n"
	_ = os.WriteFile(configFile, []byte(strings.Replace(config, "%s", "", 1)), 0o600)
	_ = os.WriteFile(filepath.Join(scopes, "jane.json"), []byte(`{"token_sha256": "`+strings.Repeat("a", 64)+`", "owner": {"label": "com.docker.compose.project", "value": "jane"}, "prefixes": ["jane-"], "images": ["quire-sites/jane/", "ghcr.io/jane/", "ghcr.io/jane-tools/", "registry.local/jane/"]}`), 0o600)
	_ = os.WriteFile(filepath.Join(scopes, "blog.json"), []byte(`{"token_sha256": "`+strings.Repeat("b", 64)+`", "owner": {"label": "com.docker.compose.project", "value": "blog"}, "prefixes": ["blog-"], "images": ["quire-sites/blog/"]}`), 0o600)

	var out, errs bytes.Buffer
	if code := run([]string{"check", "--config", configFile}, &out, &errs); code != 0 || !strings.Contains(out.String(), "  notice: scope jane's images are on ghcr.io, registry.local, which pulls.registries doesn't list: its pulls from there are refused\n") || strings.Contains(out.String(), "blog's") {
		t.Fatalf("%d %q %q", code, out.String(), errs.String())
	}

	_ = os.WriteFile(configFile, []byte(strings.Replace(config, "%s", ", pulls: {registries: [docker.io, ghcr.io, registry.local]}", 1)), 0o600)
	out.Reset()

	if code := run([]string{"check", "--config", configFile}, &out, &errs); code != 0 || strings.Contains(out.String(), "notice") {
		t.Fatalf("every registry listed: %d %q %q", code, out.String(), errs.String())
	}
}

// check --docker reads Docker's defaults through the upstream: notes for what's only worth knowing,
// and an error, naming the opt-out, for what would widen what scopes may do.
func TestCheckReadsDockersDefaults(t *testing.T) {
	dir := t.TempDir()
	scopes := filepath.Join(dir, "scopes")
	_ = os.Mkdir(scopes, 0o700)
	socket := filepath.Join(dir, "docker.sock")
	info := `{"SecurityOptions": ["name=apparmor,profile=default", "name=seccomp,profile=/etc/docker/seccomp.json", "name=cgroupns"], "DefaultRuntime": "runc"}`

	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}

	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/info") {
			http.NotFound(w, r)

			return
		}

		_, _ = w.Write([]byte(info))
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })

	configFile := filepath.Join(dir, "yorvogate.yaml")
	write := func(extra string) {
		_ = os.WriteFile(configFile, []byte("upstream: unix://"+socket+"\n"+extra+"listeners:\n  - {name: sites, address: 'tcp://127.0.0.1:2376', mode: scoped, scopes: "+scopes+"}\n"), 0o600)
	}
	write("")

	var out, errs bytes.Buffer
	if code := run([]string{"check", "--config", configFile, "--docker"}, &out, &errs); code != 0 || !strings.Contains(out.String(), "Docker's defaults: ok\n  notice: Docker's own seccomp profile is /etc/docker/seccomp.json") {
		t.Fatalf("safe, with a note: %d %q %q", code, out.String(), errs.String())
	}

	// Without --docker, check doesn't ask Docker.
	out.Reset()
	if code := run([]string{"check", "--config", configFile}, &out, &errs); code != 0 || strings.Contains(out.String(), "Docker's defaults") {
		t.Fatalf("offline: %d %q", code, out.String())
	}

	info = `{"SecurityOptions": ["name=seccomp,profile=builtin", "name=cgroupns"], "DefaultRuntime": "runc"}`
	out.Reset()
	errs.Reset()

	if code := run([]string{"check", "--config", configFile, "--docker"}, &out, &errs); code != 1 || !strings.Contains(out.String(), "Docker's defaults: unsafe") || !strings.Contains(errs.String(), "Docker has neither AppArmor nor SELinux (set daemon.without_lsm: true to accept that)") {
		t.Fatalf("no LSM: %d %q %q", code, out.String(), errs.String())
	}

	write("daemon: {without_lsm: true}\n")
	out.Reset()
	errs.Reset()

	if code := run([]string{"check", "--config", configFile, "--docker"}, &out, &errs); code != 0 || !strings.Contains(out.String(), "as daemon.without_lsm accepts") {
		t.Fatalf("no LSM, accepted: %d %q %q", code, out.String(), errs.String())
	}
}
