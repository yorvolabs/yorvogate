package gate

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/yorvolabs/yorvogate/internal/config"
)

const blogToken = "blog-token-0123456789abcdef0123456789"

func tokenScope(owner, tok string) string {
	sum := sha256.Sum256([]byte(tok))

	return `{"token_sha256": "` + hex.EncodeToString(sum[:]) + `", "owner": {"label": "com.docker.compose.project", "value": "` + owner + `"}, "prefixes": ["` + owner + `-", "` + owner + `_"]}`
}

var asBlog = map[string]string{"X-YorvoGate-Scope": "blog", "X-YorvoGate-Token": blogToken}

// tokenGate serves a token listener with scopes jane and blog in front of the fake Docker: the
// server, its gate, and the scope files' folder.
func tokenGate(t *testing.T, d *docker) (*httptest.Server, *Gate, string) {
	t.Helper()
	scopes := t.TempDir()
	writeScope(t, scopes, "jane", tokenScope("jane", token))
	writeScope(t, scopes, "blog", tokenScope("blog", blogToken))

	c, err := config.Parse([]byte("upstream: unix://" + d.socket + "\nlisteners:\n  - {name: sites, address: 'tcp://127.0.0.1:2376', mode: scoped, scopes: " + scopes + "}\n"))
	if err != nil {
		t.Fatal(err)
	}

	registry := Registry(c)
	if err := registry.Reload(); err != nil {
		t.Fatal(err)
	}

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	g := New(c, c.Listeners[0], NewUpstream(c, log), registry, log)
	server := httptest.NewServer(g)
	t.Cleanup(server.Close)

	return server, g, scopes
}

// revoke reloads the scope files and ends what they no longer allow, as serve's scan does.
func revoke(t *testing.T, g *Gate) {
	t.Helper()

	if err := g.registry.Reload(); err != nil {
		t.Fatal(err)
	}

	g.Revoke()
}

// execStream starts an exec's stream (an HTTP upgrade) as a scope, and checks it echoes.
func execStream(t *testing.T, server *httptest.Server, exec string, header map[string]string) (net.Conn, *bufio.Reader) {
	t.Helper()

	conn, err := net.Dial("tcp", strings.TrimPrefix(server.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = conn.Close() })

	request := "POST /v1.56/exec/" + exec + "/start HTTP/1.1\r\nHost: docker\r\nContent-Type: application/json\r\nConnection: Upgrade\r\nUpgrade: tcp\r\nContent-Length: 16\r\n"
	for k, v := range header {
		request += k + ": " + v + "\r\n"
	}

	_, _ = conn.Write([]byte(request + "\r\n{\"Detach\":false}"))
	reader := bufio.NewReader(conn)

	res, err := http.ReadResponse(reader, nil)
	if err != nil || res.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade: %v %v", res, err)
	}

	echoes(t, conn, reader)

	return conn, reader
}

func echoes(t *testing.T, conn net.Conn, reader *bufio.Reader) {
	t.Helper()

	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = conn.Write([]byte("hello"))
	echo := make([]byte, 5)

	if _, err := io.ReadFull(reader, echo); err != nil || string(echo) != "hello" {
		t.Fatalf("the stream: %q %v", echo, err)
	}
}

func ended(t *testing.T, conn net.Conn, reader *bufio.Reader) bool {
	t.Helper()

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err := reader.ReadByte()

	return errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || errors.Is(err, syscall.ECONNRESET)
}

// A scope removed, no longer valid, or given a new token ends its streams on a token listener;
// another scope's go on.
func TestATokenListenerEndsAScopesStreamsWhenItsAllowanceGoes(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(t *testing.T, scopes string)
	}{
		{"removed", func(t *testing.T, scopes string) { _ = os.Remove(filepath.Join(scopes, "jane.json")) }},
		{"not valid", func(t *testing.T, scopes string) {
			writeScope(t, scopes, "jane", strings.Replace(tokenScope("jane", token), `["jane-", "jane_"]`, `[]`, 1))
		}},
		{"a new token", func(t *testing.T, scopes string) {
			writeScope(t, scopes, "jane", tokenScope("jane", "another-token-0123456789abcdef0123"))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := startDocker(t)
			server, g, scopes := tokenGate(t, d)

			jane, janeReader := execStream(t, server, "exec-jane", asJane)
			blog, blogReader := execStream(t, server, "exec-blog", asBlog)

			// A reload that changes nothing ends nothing
			revoke(t, g)
			echoes(t, jane, janeReader)

			tc.change(t, scopes)
			revoke(t, g)

			if !ended(t, jane, janeReader) {
				t.Error("jane's stream is still open")
			}

			echoes(t, blog, blogReader)
		})
	}
}

// Logs that follow are an answer, not an upgrade: they end too.
func TestATokenListenerEndsAScopesFollowedLogs(t *testing.T) {
	d := startDocker(t)
	server, g, scopes := tokenGate(t, d)

	req, _ := http.NewRequest("GET", server.URL+"/v1.56/containers/jane-php-1/logs?follow=1&stdout=1", nil)
	for k, v := range asJane {
		req.Header.Set(k, v)
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil || res.StatusCode != http.StatusOK {
		t.Fatalf("logs: %v %v", res, err)
	}
	defer res.Body.Close()

	reader := bufio.NewReader(res.Body)
	if line, err := reader.ReadString('\n'); err != nil || line != "log line\n" {
		t.Fatalf("the first line: %q %v", line, err)
	}

	_ = os.Remove(filepath.Join(scopes, "jane.json"))
	revoke(t, g)

	done := make(chan error, 1)
	go func() { _, err := io.ReadAll(reader); done <- err }()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Error("jane's logs still follow")
	}
}

// A reload between a request's decision and its tracking doesn't let it through: it's ended at
// once.
func TestARequestDecidedBeforeAReloadIsCheckedAgain(t *testing.T) {
	d := startDocker(t)
	_, g, scopes := tokenGate(t, d)

	allowed, err := g.scopes.Authenticate("jane", token)
	if err != nil {
		t.Fatal(err)
	}

	_ = os.Remove(filepath.Join(scopes, "jane.json"))
	revoke(t, g)

	req, _ := http.NewRequest("GET", "http://docker/v1.56/containers/jane-php-1/logs", nil)
	forward, answered := g.streams.track(g.scopes, allowed, req)

	if forward.Context().Err() == nil {
		t.Error("a request of a removed scope goes on")
	}

	answered()

	// One that's current isn't ended, and once answered it's no longer tracked
	blog, _ := g.scopes.Authenticate("blog", blogToken)
	forward, done := g.streams.track(g.scopes, blog, req)

	if forward.Context().Err() != nil {
		t.Error("blog's request was ended")
	}

	done()

	if open := len(g.streams.open); open != 0 {
		t.Errorf("%d requests still tracked once answered", open)
	}
}
