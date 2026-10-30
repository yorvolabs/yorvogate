package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
