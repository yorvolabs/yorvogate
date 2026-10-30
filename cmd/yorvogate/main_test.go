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
