package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/yorvolabs/yorvogate/internal/config"
)

// lines is serve's log, read as it's written.
type lines struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *lines) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	return l.buf.Write(p)
}

// all is every line so far, decoded.
func (l *lines) all() []map[string]any {
	l.mu.Lock()
	defer l.mu.Unlock()

	var out []map[string]any

	for _, line := range strings.Split(l.buf.String(), "\n") {
		var m map[string]any
		if json.Unmarshal([]byte(line), &m) == nil {
			out = append(out, m)
		}
	}

	return out
}

// count is how many lines match.
func (l *lines) count(match func(map[string]any) bool) int {
	n := 0

	for _, m := range l.all() {
		if match(m) {
			n++
		}
	}

	return n
}

// wait waits up to 5 s for the n-th line that matches, and gives it.
func (l *lines) wait(t *testing.T, n int, match func(map[string]any) bool) map[string]any {
	t.Helper()

	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		seen := 0

		for _, m := range l.all() {
			if match(m) {
				if seen++; seen == n {
					return m
				}
			}
		}
	}

	t.Fatalf("no line %d matched in:\n%s", n, l.buf.String())

	return nil
}

func msg(want string) func(map[string]any) bool {
	return func(m map[string]any) bool { return m["msg"] == want }
}

func streamClosed(by string) func(map[string]any) bool {
	return func(m map[string]any) bool { return m["msg"] == "stream closed" && m["by"] == by }
}

// fakeDocker answers on a unix socket: _ping, /info and /version for a scoped listener's defaults, a
// container list, an inspection that takes 300 ms, and an attach that upgrades and echoes.
func fakeDocker(t *testing.T, dir string) string {
	t.Helper()
	socket := filepath.Join(dir, "docker.sock")
	ended := make(chan struct{})
	t.Cleanup(func() { close(ended) })

	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}

	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/info"):
			_, _ = w.Write([]byte(`{"SecurityOptions": ["name=apparmor,profile=default", "name=seccomp,profile=builtin", "name=cgroupns"], "DefaultRuntime": "runc", "LoggingDriver": "json-file"}`))
		case strings.HasSuffix(r.URL.Path, "/version"):
			_, _ = w.Write([]byte(`{"ApiVersion": "1.56", "MinAPIVersion": "1.24"}`))
		case strings.HasSuffix(r.URL.Path, "/slow/json"):
			time.Sleep(300 * time.Millisecond)
			_, _ = w.Write([]byte(`{"Id": "slow"}`))
		case strings.HasSuffix(r.URL.Path, "/silent/attach"):
			// As Docker's exec of a command that runs on: the client's end of input changes nothing,
			// and the stream lasts until its connection is closed
			conn, rw, err := http.NewResponseController(w).Hijack()
			if err != nil {
				return
			}

			_, _ = rw.WriteString("HTTP/1.1 101 UPGRADED\r\nContent-Type: application/vnd.docker.raw-stream\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n")
			_ = rw.Flush()
			_, _ = io.Copy(io.Discard, rw)
			<-ended
			_ = conn.Close()
		case strings.HasSuffix(r.URL.Path, "/attach"):
			conn, rw, err := http.NewResponseController(w).Hijack()
			if err != nil {
				return
			}

			_, _ = rw.WriteString("HTTP/1.1 101 UPGRADED\r\nContent-Type: application/vnd.docker.raw-stream\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n")
			_ = rw.Flush()
			_, _ = io.Copy(conn, rw)
			_ = conn.Close()
		case strings.HasSuffix(r.URL.Path, "/containers/c1/json"):
			// A container of scope site's
			_, _ = w.Write([]byte(`{"Id": "c1c1c1c1c1c1", "Name": "/site-web-1", "Config": {"Labels": {"com.docker.compose.project": "site"}}, "HostConfig": {}}`))
		case strings.HasSuffix(r.URL.Path, "/containers/json"):
			_, _ = w.Write([]byte(`[]`))
		default:
			_, _ = w.Write([]byte("OK"))
		}
	})}

	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })

	return socket
}

// running is serve, started on a configuration file.
type running struct {
	config string
	log    *lines
	cancel context.CancelFunc
	done   chan error
}

func start(t *testing.T, dir, content string) *running {
	t.Helper()

	r := &running{config: filepath.Join(dir, "yorvogate.yaml"), log: &lines{}, done: make(chan error, 1)}
	r.write(t, content)

	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel

	go func() { r.done <- serve(ctx, r.config, slog.New(slog.NewJSONHandler(r.log, nil))) }()

	// SIGHUP is taken before the first listener opens: from then on, it may be sent
	r.log.wait(t, 1, msg("listening"))

	t.Cleanup(func() {
		cancel()

		select {
		case <-r.done:
		case <-time.After(15 * time.Second):
			t.Error("serve didn't stop")
		}
	})

	return r
}

func (r *running) write(t *testing.T, content string) {
	t.Helper()

	if err := os.WriteFile(r.config, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func hup(t *testing.T) {
	t.Helper()

	if err := syscall.Kill(syscall.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
}

// over is an HTTP client of a unix socket.
func over(socket string) *http.Client {
	return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}}
}

func status(t *testing.T, c *http.Client, path string) (int, string) {
	t.Helper()

	res, err := c.Get("http://gate" + path)
	if err != nil {
		return 0, err.Error()
	}
	defer res.Body.Close()

	body, _ := io.ReadAll(res.Body)

	return res.StatusCode, string(body)
}

// attach opens an attach stream on a connection and checks it echoes.
func attach(t *testing.T, conn net.Conn) *bufio.Reader {
	t.Helper()

	_, _ = conn.Write([]byte("POST /v1.56/containers/c1/attach?stream=1&stdin=1&stdout=1 HTTP/1.1\r\nHost: docker\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n"))
	reader := bufio.NewReader(conn)

	res, err := http.ReadResponse(reader, nil)
	if err != nil || res.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("attach: %v %v", res, err)
	}

	echo(t, conn, reader)

	return reader
}

func echo(t *testing.T, conn net.Conn, reader *bufio.Reader) {
	t.Helper()

	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = conn.Write([]byte("hello"))

	got := make([]byte, 5)
	if _, err := io.ReadFull(reader, got); err != nil || string(got) != "hello" {
		t.Fatalf("the stream: %q %v", got, err)
	}
}

// closedWithin says whether the stream ends within d.
func closedWithin(conn net.Conn, reader *bufio.Reader, d time.Duration) bool {
	_ = conn.SetReadDeadline(time.Now().Add(d))
	_, err := reader.ReadByte()

	return errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || errors.Is(err, syscall.ECONNRESET)
}

func dialUnix(t *testing.T, socket string) net.Conn {
	t.Helper()

	conn, err := net.Dial("unix", socket)
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = conn.Close() })

	return conn
}

func noScans(t *testing.T) {
	t.Helper()

	defer func(d time.Duration) { t.Cleanup(func() { scanInterval = d }) }(scanInterval)
	scanInterval = time.Hour
}

// SIGHUP puts a valid configuration in effect: a policy changed takes effect on the next request; a
// trusted listener added answers; one removed refuses connections, its stream closed (by: reload);
// readiness and the metrics name the new file.
func TestAReloadChangesPoliciesAndListeners(t *testing.T) {
	noScans(t)
	dir := t.TempDir()
	docker := fakeDocker(t, dir)
	a, b, c, admin := filepath.Join(dir, "a.sock"), filepath.Join(dir, "b.sock"), filepath.Join(dir, "c.sock"), filepath.Join(dir, "admin.sock")

	head := "version: 1\nupstream: unix://" + docker + "\nadmin: {address: 'unix://" + admin + "'}\nlisteners:\n"
	first := head + "  - {name: a, address: 'unix://" + a + "', mode: trusted, allow: {system: read}}\n  - {name: b, address: 'unix://" + b + "', mode: trusted, allow: {containers: write}}\n"
	second := head + "  - {name: a, address: 'unix://" + a + "', mode: trusted, allow: {system: read, containers: read}}\n  - {name: c, address: 'unix://" + c + "', mode: trusted, allow: {system: read}}\n"

	r := start(t, dir, first)

	if code, body := status(t, over(a), "/v1.56/containers/json"); code != http.StatusForbidden {
		t.Fatalf("a's containers before: %d %s", code, body)
	}

	conn := dialUnix(t, b)
	reader := attach(t, conn)

	_, before := status(t, over(admin), "/readyz")

	r.write(t, second)
	hup(t)

	reloaded := r.log.wait(t, 1, msg("configuration reloaded"))
	if added, removed, changed := reloaded["added"], reloaded["removed"], reloaded["changed"]; !strings.Contains(encoded(added), `"c"`) || !strings.Contains(encoded(removed), `"b"`) || !strings.Contains(encoded(changed), `"a"`) {
		t.Errorf("the line: %v", reloaded)
	}

	if code, body := status(t, over(a), "/v1.56/containers/json"); code != http.StatusOK {
		t.Errorf("a's containers after: %d %s", code, body)
	}

	if !closedWithin(conn, reader, 5*time.Second) {
		t.Error("b's stream is still open")
	}

	r.log.wait(t, 1, streamClosed("reload"))

	if _, err := net.Dial("unix", b); err == nil {
		t.Error("b still takes connections")
	}

	if code, body := status(t, over(c), "/v1.56/_ping"); code != http.StatusOK {
		t.Errorf("c: %d %s", code, body)
	}

	_, after := status(t, over(admin), "/readyz")
	if before == after || !strings.Contains(after, `"config_sha256":"`+digest([]byte(second))+`"`) {
		t.Errorf("readiness before %s after %s", before, after)
	}

	if _, metrics := status(t, over(admin), "/metrics"); !strings.Contains(metrics, `yorvogate_config_reloads_total{result="reloaded"} 1`) || !strings.Contains(metrics, "yorvogate_config_last_reload_success 1") || !strings.Contains(metrics, `yorvogate_config_info{sha256="`+digest([]byte(second))+`"} 1`) {
		t.Errorf("metrics: %s", metrics)
	}
}

func encoded(v any) string {
	b, _ := json.Marshal(v)

	return string(b)
}

// A reload that isn't valid, or changes what only a restart may, is refused: the running
// configuration stays, it's logged and counted, and the scope folders are still rescanned.
func TestARefusedReloadKeepsTheRunningConfiguration(t *testing.T) {
	noScans(t)
	dir := t.TempDir()
	docker := fakeDocker(t, dir)
	ops, admin, sockets, scopes := filepath.Join(dir, "ops.sock"), filepath.Join(dir, "admin.sock"), filepath.Join(dir, "sites"), filepath.Join(dir, "scopes")
	_ = os.Mkdir(sockets, 0o700)
	_ = os.Mkdir(scopes, 0o700)

	good := "version: 1\nupstream: unix://" + docker + "\nadmin: {address: 'unix://" + admin + "'}\ndaemon: {without_lsm: true}\nlisteners:\n  - {name: ops, address: 'unix://" + ops + "', mode: trusted, allow: {system: read}}\n  - {name: sites, scope_sockets: " + sockets + ", mode: scoped, scopes: " + scopes + "}\n"
	r := start(t, dir, good)

	for i, tc := range []struct{ name, content, reason string }{
		{"it doesn't parse", good + "listeners: [", "isn't valid"},
		{"an unknown key", good + "colour: blue\n", "colour"},
		{"check refuses it", strings.Replace(good, "mode: trusted, ", "", 1), "mode"},
		{"a restart-only key", strings.Replace(good, "unix://"+docker, "unix://"+dir+"/other.sock", 1), "upstream can't change"},
		{"a scoped listener's folder", strings.Replace(good, "scopes: "+scopes, "scopes: "+dir, 1), "listener sites's scopes can't change"},
		{"a bad grace", good + "shutdown_grace: forever\n", "shutdown_grace"},
	} {
		// A scope file comes before the signal: the rescan after the refused reload opens its socket
		name := "site" + string(rune('a'+i))
		_ = os.WriteFile(filepath.Join(scopes, name+".json"), []byte(`{"owner": {"label": "com.docker.compose.project", "value": "`+name+`"}, "prefixes": ["`+name+`-"]}`), 0o600)

		r.write(t, tc.content)
		hup(t)

		line := r.log.wait(t, i+1, msg("configuration not reloaded"))
		if reason, _ := line["reason"].(string); !strings.Contains(reason, tc.reason) {
			t.Errorf("%s: the reason %q, want %q", tc.name, reason, tc.reason)
		}

		if code, body := status(t, over(ops), "/v1.56/containers/json"); code != http.StatusForbidden {
			t.Errorf("%s: the running policy isn't the one in effect: %d %s", tc.name, code, body)
		}

		socket := filepath.Join(sockets, name+".sock")
		for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
			if _, err := os.Stat(socket); err == nil {
				break
			}
		}

		if _, err := os.Stat(socket); err != nil {
			t.Errorf("%s: the scopes weren't rescanned: %v", tc.name, err)
		}
	}

	if _, metrics := status(t, over(admin), "/metrics"); !strings.Contains(metrics, `yorvogate_config_reloads_total{result="refused"} 6`) || !strings.Contains(metrics, "yorvogate_config_last_reload_success 0") || !strings.Contains(metrics, `yorvogate_config_info{sha256="`+digest([]byte(good))+`"} 1`) {
		t.Errorf("metrics: %s", metrics)
	}

	if n := r.log.count(msg("configuration reloaded")); n != 0 {
		t.Errorf("%d reloads taken", n)
	}
}

// SIGHUPs that come while a reload runs make one more reload after it, not one each.
func TestSighupsDuringAReloadCoalesce(t *testing.T) {
	noScans(t)
	dir := t.TempDir()
	docker := fakeDocker(t, dir)
	content := "version: 1\nupstream: unix://" + docker + "\nlisteners:\n  - {name: ops, address: 'unix://" + filepath.Join(dir, "ops.sock") + "', mode: trusted, allow: {system: read}}\n"

	entered, release := make(chan struct{}, 10), make(chan struct{})
	first := true

	reloading = func() {
		entered <- struct{}{}

		if first {
			first = false
			<-release
		}
	}
	t.Cleanup(func() { reloading = func() {} })

	start(t, dir, content)

	hup(t)
	<-entered

	// Each delivered on its own (signals that come together are merged before they're handed on)
	for range 5 {
		hup(t)
		time.Sleep(30 * time.Millisecond)
	}

	close(release)

	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("no reload after the first")
	}

	time.Sleep(300 * time.Millisecond)

	if n := len(entered); n != 0 {
		t.Errorf("%d more reloads for 6 SIGHUPs, 5 of them during the first: want 2 in all", n+2)
	}
}

// A SIGHUP with the file in effect unchanged is only a rescan: nothing is logged or counted.
func TestASighupWithTheSameFileIsOnlyARescan(t *testing.T) {
	noScans(t)
	dir := t.TempDir()
	docker := fakeDocker(t, dir)
	admin := filepath.Join(dir, "admin.sock")
	r := start(t, dir, "version: 1\nupstream: unix://"+docker+"\nadmin: {address: 'unix://"+admin+"'}\nlisteners:\n  - {name: ops, address: 'unix://"+filepath.Join(dir, "ops.sock")+"', mode: trusted, allow: {system: read}}\n")

	hup(t)
	time.Sleep(300 * time.Millisecond)

	if n := r.log.count(func(m map[string]any) bool { return strings.HasPrefix(fmt.Sprint(m["msg"]), "configuration") }); n != 0 {
		t.Errorf("%d configuration lines for an unchanged file", n)
	}

	if _, metrics := status(t, over(admin), "/metrics"); strings.Contains(metrics, "yorvogate_config_reloads_total{") {
		t.Errorf("an unchanged file counted: %s", metrics)
	}
}

// A trusted listener whose transport changes is moved: client_ca added to a plaintext TCP listener
// closes its connections (by: reload), and it takes only clients with a certificate from then on.
func TestATrustedListenersNewTransportMovesIt(t *testing.T) {
	noScans(t)
	dir := t.TempDir()
	docker := fakeDocker(t, dir)
	certs := tlsFiles(t)

	free, _ := net.Listen("tcp", "127.0.0.1:0")
	address := free.Addr().String()
	_ = free.Close()

	head := "version: 1\nupstream: unix://" + docker + "\nlisteners:\n  - {name: ops, address: 'tcp://" + address + "', mode: trusted, allow: {containers: write}"
	r := start(t, dir, head+"}\n")

	conn, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	reader := attach(t, conn)

	r.write(t, head+", tls: {certificate: "+certs+"/server.pem, key: "+certs+"/server.key, client_ca: "+certs+"/scopes-ca.pem}}\n")
	hup(t)

	if line := r.log.wait(t, 1, msg("configuration reloaded")); !strings.Contains(encoded(line["moved"]), `"ops"`) {
		t.Errorf("the line: %v", line)
	}

	if !closedWithin(conn, reader, 5*time.Second) {
		t.Error("the plaintext stream is still open")
	}

	r.log.wait(t, 1, streamClosed("reload"))

	// Without a certificate, the handshake is refused
	var refused bool

	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline) && !refused; time.Sleep(20 * time.Millisecond) {
		c, err := tls.Dial("tcp", address, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // the test's own server
		if err != nil {
			continue
		}

		_, _ = c.Write([]byte("GET /v1.56/_ping HTTP/1.1\r\nHost: docker\r\n\r\n"))
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, err = http.ReadResponse(bufio.NewReader(c), nil)
		_ = c.Close()
		refused = err != nil
	}

	if !refused {
		t.Error("a client without a certificate was answered")
	}

	if res, err := (&http.Client{Timeout: time.Second}).Get("http://" + address + "/v1.56/_ping"); err == nil && res.StatusCode == http.StatusOK {
		t.Error("a plaintext client was answered")
	}
}

// A stop stops accepting at once (the socket's file goes), fails readiness, lets a request finish
// within the grace, then closes the stream still open (by: shutdown), and returns.
func TestAStopDrainsThenClosesStreams(t *testing.T) {
	noScans(t)
	dir := t.TempDir()
	docker := fakeDocker(t, dir)
	ops, admin := filepath.Join(dir, "ops.sock"), filepath.Join(dir, "admin.sock")
	r := start(t, dir, "version: 1\nupstream: unix://"+docker+"\nshutdown_grace: 600ms\nadmin: {address: 'unix://"+admin+"'}\nlisteners:\n  - {name: ops, address: 'unix://"+ops+"', mode: trusted, allow: {containers: write}}\n")

	conn := dialUnix(t, ops)
	reader := attach(t, conn)

	slow := make(chan int, 1)

	go func() {
		code, _ := status(t, over(ops), "/v1.56/containers/slow/json")
		slow <- code
	}()

	time.Sleep(50 * time.Millisecond)

	stopped := time.Now()
	r.cancel()
	r.log.wait(t, 1, msg("stopping"))

	if code, body := status(t, over(admin), "/readyz"); code != http.StatusServiceUnavailable || !strings.Contains(body, `"draining":true`) {
		t.Errorf("readiness while stopping: %d %s", code, body)
	}

	if _, err := os.Stat(ops); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the socket's file is still there: %v", err)
	}

	if code := <-slow; code != http.StatusOK {
		t.Errorf("the request being answered: %d", code)
	}

	echo(t, conn, reader) // within the grace, the stream goes on

	if !closedWithin(conn, reader, 5*time.Second) {
		t.Fatal("the stream is still open")
	}

	if took := time.Since(stopped); took < 500*time.Millisecond {
		t.Errorf("the stream was closed after %v, before the grace", took)
	}

	select {
	case err := <-r.done:
		if err != nil {
			t.Errorf("stopped with %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serve didn't return")
	}

	r.done <- nil // for the cleanup

	if n := r.log.count(streamClosed("shutdown")); n != 1 {
		t.Errorf("%d streams logged as closed by shutdown", n)
	}

	if r.log.count(msg("stopped")) != 1 {
		t.Error("no stopped line")
	}
}

// A second SIGTERM ends the wait at once.
func TestASecondSignalEndsTheWait(t *testing.T) {
	noScans(t)
	dir := t.TempDir()
	docker := fakeDocker(t, dir)
	ops := filepath.Join(dir, "ops.sock")
	r := start(t, dir, "version: 1\nupstream: unix://"+docker+"\nshutdown_grace: 1m\nlisteners:\n  - {name: ops, address: 'unix://"+ops+"', mode: trusted, allow: {containers: write}}\n")

	conn := dialUnix(t, ops)
	reader := attach(t, conn)

	r.cancel()
	r.log.wait(t, 1, msg("stopping"))

	stopped := time.Now()

	if err := syscall.Kill(syscall.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}

	if !closedWithin(conn, reader, 5*time.Second) || time.Since(stopped) > 4*time.Second {
		t.Error("the stream wasn't closed at once")
	}

	r.log.wait(t, 1, streamClosed("shutdown"))
}

// A stop closes the streams of every kind of listener at the grace's end: a scope socket's and a token
// listener's as a trusted one's.
func TestAStopClosesEveryListenersStreams(t *testing.T) {
	noScans(t)
	dir := t.TempDir()
	docker := fakeDocker(t, dir)
	sockets, scopes, tokens := filepath.Join(dir, "sites"), filepath.Join(dir, "scopes"), filepath.Join(dir, "tokens")
	_ = os.Mkdir(sockets, 0o700)
	_ = os.Mkdir(scopes, 0o700)
	_ = os.Mkdir(tokens, 0o700)

	scope := `{"owner": {"label": "com.docker.compose.project", "value": "site"}, "prefixes": ["site-"]}`
	_ = os.WriteFile(filepath.Join(scopes, "site.json"), []byte(scope), 0o600)
	_ = os.WriteFile(filepath.Join(tokens, "site.json"), []byte(strings.Replace(scope, "{", `{"token_sha256": "`+digest([]byte("the-token"))+`", `, 1)), 0o600)

	tenants := filepath.Join(dir, "tenants.sock")
	r := start(t, dir, "version: 1\nupstream: unix://"+docker+"\nshutdown_grace: 300ms\ndaemon: {without_lsm: true}\nlisteners:\n  - {name: sites, scope_sockets: "+sockets+", mode: scoped, scopes: "+scopes+"}\n  - {name: tenants, address: 'unix://"+tenants+"', mode: scoped, scopes: "+tokens+"}\n")

	onSocket := dialUnix(t, filepath.Join(sockets, "site.sock"))
	socketReader := attach(t, onSocket)

	onTokens := dialUnix(t, tenants)
	_, _ = onTokens.Write([]byte("POST /v1.56/containers/c1/attach?stream=1&stdin=1&stdout=1 HTTP/1.1\r\nHost: docker\r\nX-Yorvogate-Scope: site\r\nX-Yorvogate-Token: the-token\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n"))
	tokenReader := bufio.NewReader(onTokens)

	if res, err := http.ReadResponse(tokenReader, nil); err != nil || res.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("the token listener's attach: %v %v", res, err)
	}

	echo(t, onTokens, tokenReader)

	r.cancel()

	for name, s := range map[string]struct {
		conn   net.Conn
		reader *bufio.Reader
	}{"the scope socket's": {onSocket, socketReader}, "the token listener's": {onTokens, tokenReader}} {
		if !closedWithin(s.conn, s.reader, 5*time.Second) {
			t.Errorf("%s stream is still open", name)
		}
	}

	r.log.wait(t, 2, streamClosed("shutdown"))
}

// A stream whose client sends nothing more (it closed its end of input, as the Docker CLI does for an
// exec without -i) while Docker's side runs on is ended by a stop too: its Docker side is closed with
// it, and it's logged.
func TestAStopEndsAStreamWhoseClientSendsNothing(t *testing.T) {
	noScans(t)
	dir := t.TempDir()
	docker := fakeDocker(t, dir)
	ops := filepath.Join(dir, "ops.sock")
	r := start(t, dir, "version: 1\nupstream: unix://"+docker+"\nshutdown_grace: 200ms\nlisteners:\n  - {name: ops, address: 'unix://"+ops+"', mode: trusted, allow: {containers: write}}\n")

	conn := dialUnix(t, ops)
	_, _ = conn.Write([]byte("POST /v1.56/containers/silent/attach?stream=1&stdout=1 HTTP/1.1\r\nHost: docker\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n"))

	if res, err := http.ReadResponse(bufio.NewReader(conn), nil); err != nil || res.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("attach: %v %v", res, err)
	}

	_ = conn.(*net.UnixConn).CloseWrite()

	r.cancel()

	r.log.wait(t, 1, streamClosed("shutdown"))
	r.log.wait(t, 1, msg("stopped"))
}

// freeTCP is a loopback address nothing listens on (now).
func freeTCP(t *testing.T) string {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	address := l.Addr().String()
	_ = l.Close()

	return address
}

// takenTCP is a loopback address something else listens on.
func takenTCP(t *testing.T) string {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = l.Close() })

	return l.Addr().String()
}

// A reload opens every listener it names, or isn't taken (R4): a listener added, or one moved, to
// an address that can't be opened refuses the reload; every running listener stays open, the
// running configuration in effect, the refusal counted.
func TestAReloadThatCantOpenAListenerIsRefused(t *testing.T) {
	for _, tc := range []struct{ name, change string }{
		{"a listener added at an address in use", "  - {name: more, address: 'tcp://TAKEN', mode: trusted, allow: {system: read}}\n"},
		{"a listener moved to an address in use", "MOVE"},
		{"a listener added in a folder that isn't there", "  - {name: more, address: 'unix:///nonexistent/more.sock', mode: trusted, allow: {system: read}}\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			noScans(t)
			dir := t.TempDir()
			docker := fakeDocker(t, dir)
			admin, ops := filepath.Join(dir, "admin.sock"), freeTCP(t)

			first := "version: 1\nupstream: unix://" + docker + "\nadmin: {address: 'unix://" + admin + "'}\nlisteners:\n  - {name: ops, address: 'tcp://" + ops + "', mode: trusted, allow: {system: read}}\n"
			r := start(t, dir, first)

			second := first + strings.Replace(tc.change, "TAKEN", takenTCP(t), 1)
			if tc.change == "MOVE" {
				second = strings.Replace(first, ops, takenTCP(t), 1)
			}

			r.write(t, second)
			hup(t)

			line := r.log.wait(t, 1, msg("configuration not reloaded"))
			if reason := fmt.Sprint(line["reason"]); !strings.Contains(reason, "can't be opened") {
				t.Errorf("the reason: %s", reason)
			}

			if res, err := (&http.Client{Timeout: 2 * time.Second}).Get("http://" + ops + "/v1.56/_ping"); err != nil || res.StatusCode != http.StatusOK {
				t.Errorf("ops at its running address: %v %v", res, err)
			}

			if code, body := status(t, over(admin), "/readyz"); code != http.StatusOK || !strings.Contains(body, `"config_sha256":"`+digest([]byte(first))+`"`) {
				t.Errorf("readiness: %d %s", code, body)
			}

			if _, metrics := status(t, over(admin), "/metrics"); !strings.Contains(metrics, `yorvogate_config_reloads_total{result="refused"} 1`) {
				t.Errorf("metrics: %s", metrics)
			}
		})
	}
}

// A listener moved on its own address (tls added) whose reopening fails undoes the reload: it's open
// again with its running settings, and the reload refused. When even that fails, readiness says so.
func TestAMoveThatCantReopenIsUndone(t *testing.T) {
	for _, tc := range []struct {
		name  string
		fails int // how many openings of the address after the start fail
		ready bool
	}{
		{"opened again as it was", 1, true},
		{"not even as it was", 2, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			noScans(t)
			dir := t.TempDir()
			docker := fakeDocker(t, dir)
			certs := tlsFiles(t)
			admin, ops := filepath.Join(dir, "admin.sock"), freeTCP(t)

			var (
				mu     sync.Mutex
				opened int
			)

			listenOn = func(l config.Listener) (net.Listener, error) {
				if l.Name == "ops" {
					mu.Lock()
					opened++
					n := opened
					mu.Unlock()

					// The first is the start's
					if n > 1 && n <= 1+tc.fails {
						return nil, errors.New("the address is taken now")
					}
				}

				return listen(l)
			}
			t.Cleanup(func() { listenOn = listen })

			head := "version: 1\nupstream: unix://" + docker + "\nadmin: {address: 'unix://" + admin + "'}\nlisteners:\n  - {name: ops, address: 'tcp://" + ops + "', mode: trusted, allow: {system: read}"
			first := head + "}\n"
			r := start(t, dir, first)

			r.write(t, head+", tls: {certificate: "+certs+"/server.pem, key: "+certs+"/server.key, client_ca: "+certs+"/scopes-ca.pem}}\n")
			hup(t)

			line := r.log.wait(t, 1, msg("configuration not reloaded"))
			if reason := fmt.Sprint(line["reason"]); !strings.Contains(reason, "the reload is undone") {
				t.Errorf("the reason: %s", reason)
			}

			res, err := (&http.Client{Timeout: 2 * time.Second}).Get("http://" + ops + "/v1.56/_ping")
			if answers := err == nil && res.StatusCode == http.StatusOK; answers != tc.ready {
				t.Errorf("ops, plaintext as it was: answers %v (%v %v)", answers, res, err)
			}

			code, body := status(t, over(admin), "/readyz")
			if !strings.Contains(body, `"config_sha256":"`+digest([]byte(first))+`"`) {
				t.Errorf("not the running configuration's: %s", body)
			}

			if tc.ready && code != http.StatusOK || !tc.ready && (code != http.StatusServiceUnavailable || !strings.Contains(body, "couldn't be opened again")) {
				t.Errorf("readiness: %d %s", code, body)
			}

			if tc.ready {
				return
			}

			// The file in effect written back: a SIGHUP opens what isn't open, though the file is the same
			r.write(t, first)
			hup(t)
			r.log.wait(t, 1, msg("configuration reloaded"))

			if code, body := status(t, over(admin), "/readyz"); code != http.StatusOK {
				t.Errorf("readiness once it's open again: %d %s", code, body)
			}

			if res, err := (&http.Client{Timeout: 2 * time.Second}).Get("http://" + ops + "/v1.56/_ping"); err != nil || res.StatusCode != http.StatusOK {
				t.Errorf("ops, open again: %v %v", res, err)
			}
		})
	}
}
