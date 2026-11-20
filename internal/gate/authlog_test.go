package gate

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yorvolabs/yorvogate/internal/config"
)

// Every authentication failure is answered alike (auth.rejected, the same status and message), so a
// client learns nothing of which scopes exist; the log says why, after the answer, with the scope it
// claimed and where it came from, never the token.
func TestAuthFailuresAreAnsweredAlikeAndLoggedApart(t *testing.T) {
	d := startDocker(t)
	scopes := t.TempDir()
	digest := func(s string) string { sum := sha256.Sum256([]byte(s)); return hex.EncodeToString(sum[:]) }

	for name, file := range map[string]string{
		"jane":   `{"token_sha256": "` + digest(token) + `", "owner": {"label": "com.docker.compose.project", "value": "jane"}, "prefixes": ["jane-"]}`,
		"old":    `{"tokens": [{"sha256": "` + digest(blogToken) + `", "expires": "2020-01-01T00:00:00Z"}], "owner": {"label": "com.docker.compose.project", "value": "old"}, "prefixes": ["old-"]}`,
		"broken": `{"token_sha256": "` + digest(token) + `", "owner": {}}`,
	} {
		if err := os.WriteFile(filepath.Join(scopes, name+".json"), []byte(file), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	c, err := config.Parse([]byte("version: 1\nupstream: unix://" + d.socket + "\nlisteners:\n  - {name: sites, address: 'tcp://127.0.0.1:2376', mode: scoped, scopes: " + scopes + "}\n"))
	if err != nil {
		t.Fatal(err)
	}

	registry := Registry(c)
	_ = registry.Reload() // broken.json is refused, as it should be

	log, lines := checkedLog(t)
	server := httptest.NewServer(New(c, c.Listeners[0], NewUpstream(c, log), registry, readDefaults(c), NewSpool(c), log))
	t.Cleanup(server.Close)

	var first string

	for cause, header := range map[string]map[string]string{
		"no-credentials":     {},
		"unknown-scope":      {"X-YorvoGate-Scope": "nobody", "X-YorvoGate-Token": token},
		"wrong-token":        {"X-YorvoGate-Scope": "jane", "X-YorvoGate-Token": blogToken},
		"token-expired":      {"X-YorvoGate-Scope": "old", "X-YorvoGate-Token": blogToken},
		"scope-file-invalid": {"X-YorvoGate-Scope": "broken", "X-YorvoGate-Token": token},
	} {
		req, _ := http.NewRequest("GET", server.URL+"/v1.56/containers/json", nil)
		for k, v := range header {
			req.Header.Set(k, v)
		}

		res, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}

		body, _ := io.ReadAll(res.Body)
		_ = res.Body.Close()

		// Its connection is closed: a next request on it can't time the cause's logging
		if !res.Close {
			t.Errorf("%s: the connection stays open", cause)
		}

		// The answer: the same for every cause, but its request ID
		answer := res.Status + " " + res.Header.Get("Connection") + " " + string(body)
		if first == "" {
			first = answer
		} else if answer != first {
			t.Errorf("%s: answered %s, unlike %s", cause, answer, first)
		}

		var a struct{ Code string }
		_ = json.Unmarshal(body, &a)
		if res.StatusCode != http.StatusUnauthorized || a.Code != string(CodeAuthRejected) {
			t.Errorf("%s: %s", cause, answer)
		}

		// The log: this request's auth failed line, with its cause
		id := res.Header.Get(RequestIDHeader)
		var found map[string]any

		for _, l := range lines.Lines() {
			var line map[string]any
			if json.Unmarshal([]byte(l), &line) == nil && line["msg"] == "auth failed" && line["request_id"] == id {
				found = line
			}
		}

		switch {
		case found == nil:
			t.Errorf("%s: no auth failed line for request %s", cause, id)
		case found["auth_failure"] != cause:
			t.Errorf("%s: logged %v", cause, found["auth_failure"])
		case header["X-YorvoGate-Scope"] != "" && found["claimed_scope"] != header["X-YorvoGate-Scope"]:
			t.Errorf("%s: claimed_scope %v", cause, found["claimed_scope"])
		case !strings.HasPrefix(found["source"].(string), "127.0.0.1:"):
			t.Errorf("%s: source %v", cause, found["source"])
		}
	}
	// (checkedLog fails the test on any line holding a token)
}

func TestCutWritesLineBreaksOut(t *testing.T) {
	for in, want := range map[string]string{
		"a\r\nb":                 `a\r\nb`,
		strings.Repeat("x", 300): strings.Repeat("x", 256) + "…",
		"/v1.56/containers/json": "/v1.56/containers/json",
	} {
		if got := cut(in, 256); got != want {
			t.Errorf("cut(%q) = %q, want %q", in, got, want)
		}
	}
}

// A path and a claimed scope a client chose are cut short in the log, whatever they hold: one line,
// the schema's (checkedLog), never split.
func TestUntrustedValuesAreCutInTheLog(t *testing.T) {
	d := startDocker(t)
	log, lines := checkedLog(t)
	server := gateLogging(t, d, "sites", log)
	long := strings.Repeat("a\"\\é{}", 2000) // a client can't send control characters in a header

	req, _ := http.NewRequest("GET", server.URL+"/v1.56/containers/json", nil)
	req.Header.Set("X-YorvoGate-Scope", long)
	req.Header.Set("X-YorvoGate-Token", "x")
	req.Header.Set(RequestIDHeader, "not valid!")

	res, err := server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()

	for _, l := range lines.Lines() {
		if len(l) > 4096 {
			t.Errorf("a line of %d bytes", len(l))
		}

		if strings.Contains(l, "client_request_id") {
			t.Errorf("an invalid client request ID was logged: %s", l)
		}
	}
}
