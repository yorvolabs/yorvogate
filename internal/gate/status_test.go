package gate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/yorvolabs/yorvogate/internal/config"
)

const statusScope = `{"version": 1, "token_sha256": "%s", "owner": {"label": "com.docker.compose.project", "value": "jane"}, "prefixes": ["jane-", "jane_"]}`

// statusGate is a trusted listener and two scoped ones, with the registry served as serve does it:
// a reload asked for is done, then published. It returns the trusted listener, a scoped one, the
// scopes folder of "sites", and a function that reloads and publishes (a scan).
func statusGate(t *testing.T) (*httptest.Server, *httptest.Server, string, func()) {
	t.Helper()
	d := startDocker(t)
	sites, other := t.TempDir(), t.TempDir()

	c, err := config.Parse([]byte("version: 1\nupstream: unix://" + d.socket + "\nlisteners:\n" +
		"  - {name: server, address: 'tcp://127.0.0.1:2375', mode: trusted, allow: {system: read}}\n" +
		"  - {name: sites, address: 'tcp://127.0.0.1:2376', mode: scoped, scopes: " + sites + "}\n" +
		"  - {name: other, address: 'tcp://127.0.0.1:2377', mode: scoped, scopes: " + other + "}\n"))
	if err != nil {
		t.Fatal(err)
	}

	registry := Registry(c)
	scan := func() {
		if err := registry.Reload(); err != nil {
			t.Error(err)
		}

		registry.Publish()
	}
	scan()

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	go func() {
		for {
			select {
			case <-registry.Requests():
				_ = registry.Reload()
				registry.Publish()
			case <-ctx.Done():
				return
			}
		}
	}()

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	upstream := NewUpstream(c, log)
	trusted := httptest.NewServer(New(c, c.Listeners[0], upstream, registry, log))
	scoped := httptest.NewServer(New(c, c.Listeners[1], upstream, registry, log))
	t.Cleanup(trusted.Close)
	t.Cleanup(scoped.Close)

	return trusted, scoped, sites, scan
}

// writeAtomically writes a scope file as an orchestrator should (a new file renamed over it), and
// gives its SHA-256.
func writeAtomically(t *testing.T, dir, name, content string) string {
	t.Helper()
	tmp := filepath.Join(dir, name+".json.new")

	if err := os.WriteFile(tmp, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := os.Rename(tmp, filepath.Join(dir, name+".json")); err != nil {
		t.Fatal(err)
	}

	sum := sha256.Sum256([]byte(content))

	return hex.EncodeToString(sum[:])
}

func janeFile(token string) string {
	sum := sha256.Sum256([]byte(token))

	return strings.Replace(statusScope, "%s", hex.EncodeToString(sum[:]), 1)
}

type statusAnswer struct {
	Version    int
	Generation uint64
	Listener   string
	Scope      string
	FileSHA256 string `json:"file_sha256"`
	State      string
	Reason     string
	Matched    *bool
}

var statusSchema = func() *jsonschema.Schema {
	c := jsonschema.NewCompiler()

	s, err := c.Compile("../../schemas/yorvogate-scope-status.v1.schema.json")
	if err != nil {
		panic(err)
	}

	return s
}()

// status asks for a scope's status; every answer the schema accepts.
func status(t *testing.T, server *httptest.Server, path string) (int, statusAnswer) {
	t.Helper()
	code, body := send(t, server, "GET", path, "", nil)

	var a statusAnswer
	if code == http.StatusOK || code == http.StatusRequestTimeout {
		if err := json.Unmarshal([]byte(body), &a); err != nil {
			t.Fatalf("%s: %v %q", path, err, body)
		}

		doc, _ := jsonschema.UnmarshalJSON(bytes.NewReader([]byte(body)))
		if err := statusSchema.Validate(doc); err != nil {
			t.Errorf("%s: not the schema's: %v", path, err)
		}
	}

	return code, a
}

// An orchestrator waits on a fact: the scope file it wrote, by its SHA-256, is loaded or refused; a
// scope it removed is gone. Each a request that waits, with a scan done at once.
func TestScopeStatus(t *testing.T) {
	trusted, _, sites, _ := statusGate(t)
	const path = "/_yorvogate/v1/scopes/jane?listener=sites"

	if code, a := status(t, trusted, path); code != 200 || a.State != "unknown" || a.Matched != nil || a.FileSHA256 != "" {
		t.Errorf("no file yet: %d %+v", code, a)
	}

	first := writeAtomically(t, sites, "jane", janeFile("one"))
	if code, a := status(t, trusted, path+"&sha256="+first); code != 200 || a.State != "loaded" || a.FileSHA256 != first || a.Matched == nil || !*a.Matched || a.Version != 1 || a.Listener != "sites" {
		t.Errorf("written: %d %+v", code, a)
	}

	// A rewrite that isn't valid: this file is refused, and jane's claims are held
	bad := writeAtomically(t, sites, "jane", strings.Replace(janeFile("two"), `"jane-", `, `"jane", `, 1))
	if code, a := status(t, trusted, path+"&sha256="+bad); code != 200 || a.State != "reserved" || a.FileSHA256 != bad || a.Reason == "" || !*a.Matched {
		t.Errorf("an invalid rewrite: %d %+v", code, a)
	}

	// A new scope that was never valid is refused, holding nothing
	never := writeAtomically(t, sites, "blog", `{"version": 1}`)
	if code, a := status(t, trusted, "/_yorvogate/v1/scopes/blog?listener=sites&sha256="+never); code != 200 || a.State != "refused" || a.Reason == "" {
		t.Errorf("never valid: %d %+v", code, a)
	}

	_ = os.Remove(filepath.Join(sites, "jane.json"))
	if code, a := status(t, trusted, path+"&absent"); code != 200 || a.State != "unknown" || !*a.Matched {
		t.Errorf("removed: %d %+v", code, a)
	}
}

// A wait for a file that doesn't come says so: 408, matched false, and the state as it is.
func TestScopeStatusTimesOut(t *testing.T) {
	old := statusWait
	statusWait = 300 * time.Millisecond
	t.Cleanup(func() { statusWait = old })

	trusted, _, sites, _ := statusGate(t)
	current := writeAtomically(t, sites, "jane", janeFile("one"))

	code, a := status(t, trusted, "/_yorvogate/v1/scopes/jane?listener=sites&sha256="+strings.Repeat("0", 64))
	if code != http.StatusRequestTimeout || a.Matched == nil || *a.Matched || a.State != "loaded" || a.FileSHA256 != current {
		t.Errorf("%d %+v", code, a)
	}

	if code, a := status(t, trusted, "/_yorvogate/v1/scopes/jane?listener=sites&absent"); code != http.StatusRequestTimeout || *a.Matched {
		t.Errorf("absent: %d %+v", code, a)
	}
}

// The race a generation can't settle: a scan lands between the orchestrator's read and its write.
// Waiting on the SHA-256, the answer is never the old file's.
func TestScopeStatusIsAboutTheFileWritten(t *testing.T) {
	trusted, _, sites, scan := statusGate(t)
	old := writeAtomically(t, sites, "jane", janeFile("one"))
	scan()

	next := janeFile("two")
	sum := sha256.Sum256([]byte(next))
	want := hex.EncodeToString(sum[:])

	done := make(chan statusAnswer)
	go func() {
		_, a := status(t, trusted, "/_yorvogate/v1/scopes/jane?listener=sites&sha256="+want)
		done <- a
	}()

	// Scans before the write: newer generations, the old file
	for range 3 {
		time.Sleep(20 * time.Millisecond)
		_ = os.Chtimes(filepath.Join(sites, "jane.json"), time.Now(), time.Now())
		scan()
	}

	writeAtomically(t, sites, "jane", next)
	scan()

	a := <-done
	if a.FileSHA256 != want || a.FileSHA256 == old || a.State != "loaded" || !*a.Matched {
		t.Errorf("%+v", a)
	}
}

// Only a trusted listener answers, and only what it knows.
func TestScopeStatusIsATrustedListenersOnly(t *testing.T) {
	trusted, scoped, _, _ := statusGate(t)

	if code, answer := send(t, scoped, "GET", "/_yorvogate/v1/scopes/jane?listener=sites", "", asJane); code != http.StatusForbidden || !strings.Contains(message(t, answer), "a trusted listener's only") {
		t.Errorf("a scoped listener: %d %s", code, answer)
	}

	for path, want := range map[string]int{
		"/_yorvogate/v1/scopes/jane":                                                         http.StatusBadRequest, // two scoped listeners: which
		"/_yorvogate/v1/scopes/jane?listener=server":                                         http.StatusBadRequest,
		"/_yorvogate/v1/scopes/jane?listener=nope":                                           http.StatusBadRequest,
		"/_yorvogate/v1/scopes/jane?listener=sites&sha256=abc":                               http.StatusBadRequest,
		"/_yorvogate/v1/scopes/jane?listener=sites&absent&sha256=" + strings.Repeat("0", 64): http.StatusBadRequest,
		"/_yorvogate/v1/scopes/jane?listener=sites&absent=1":                                 http.StatusBadRequest,
		"/_yorvogate/v1/scopes/jane?listener=sites&listener=other":                           http.StatusBadRequest,
		"/_yorvogate/v1/scopes/jane?listener=sites&x=1":                                      http.StatusBadRequest,
		"/_yorvogate/v1/scopes/../etc":                                                       http.StatusNotFound,
		"/_yorvogate/v1/scopes/JANE?listener=sites":                                          http.StatusNotFound,
		"/_yorvogate/v2/scopes/jane?listener=sites":                                          http.StatusNotFound,
		"/_yorvogate/v1/scopes/jane?listener=other":                                          http.StatusOK,
	} {
		if code, _ := send(t, trusted, "GET", path, "", nil); code != want {
			t.Errorf("%s: %d, want %d", path, code, want)
		}
	}

	if code, _ := send(t, trusted, "POST", "/_yorvogate/v1/scopes/jane?listener=sites", "", nil); code != http.StatusMethodNotAllowed {
		t.Errorf("POST: %d", code)
	}
}
