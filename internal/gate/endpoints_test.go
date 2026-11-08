package gate

import (
	"bytes"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/yorvolabs/yorvogate/internal/route"
	"go.yaml.in/yaml/v3"
)

// The endpoints no scope may use, whatever its rules: each is a decision, so a new endpoint is in
// one list or the other.
var notForScopes = []string{
	"system.events", "system.df", "system.auth", "container.commit", "image.prune", "image.push",
	"build.build", "build.prune", "build.cancel", "volume.update",
	"plugin.list", "plugin.privileges", "plugin.pull", "plugin.create", "plugin.inspect", "plugin.delete",
	"plugin.enable", "plugin.disable", "plugin.upgrade", "plugin.push", "plugin.set",
	"swarm.inspect", "swarm.init", "swarm.join", "swarm.leave", "swarm.update", "swarm.unlockkey", "swarm.unlock",
	"node.list", "node.inspect", "node.delete", "node.update",
	"service.list", "service.create", "service.inspect", "service.delete", "service.update", "service.logs",
	"task.list", "task.inspect", "task.logs",
	"secret.list", "secret.create", "secret.inspect", "secret.delete", "secret.update",
	"config.list", "config.create", "config.inspect", "config.delete", "config.update",
	"session.session", "session.grpc",
}

func TestEveryEndpointIsDecidedOnForScopes(t *testing.T) {
	known := map[string]bool{}

	for _, e := range route.Endpoints() {
		known[e.Name] = true
		_, allowed := forScopes[e.Name]
		refused := slices.Contains(notForScopes, e.Name)

		if allowed == refused {
			t.Errorf("%s: in forScopes %v, in notForScopes %v: it has to be in exactly one", e.Name, allowed, refused)
		}
	}

	for name, d := range forScopes {
		if !known[name] {
			t.Errorf("forScopes has %s, which isn't an endpoint", name)
		}

		if d.rule == nil {
			t.Errorf("%s has no rule", name)
		}

		for key := range d.refused {
			if d.query[key] != 0 {
				t.Errorf("%s: %q is both forwarded and refused", name, key)
			}
		}
	}
}

// Every query parameter and header Docker's API description gives an endpoint a scope may use is
// decided on: forwarded (and how), refused, or (a header) forwarded where it's listed.
func TestEveryParameterDockerDescribesIsDecidedOn(t *testing.T) {
	dir, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "github.com/moby/moby/api").Output()
	if err != nil {
		t.Skipf("the moby api module isn't at hand: %v", err)
	}

	var spec struct {
		Paths map[string]map[string]struct {
			Parameters []struct{ Name, In string }
		}
	}

	raw, err := os.ReadFile(filepath.Join(strings.TrimSpace(string(dir)), "swagger.yaml"))
	if err != nil {
		t.Fatal(err)
	}

	if err := yaml.Unmarshal(raw, &spec); err != nil {
		t.Fatal(err)
	}

	checked := 0

	for _, e := range route.Endpoints() {
		d, ok := forScopes[e.Name]
		if !ok {
			continue
		}

		path := strings.ReplaceAll(e.Pattern, "{name*}", "{name}")

		op, ok := spec.Paths[path][strings.ToLower(e.Method)]
		if !ok {
			t.Errorf("%s: no %s %s in Docker's API description", e.Name, e.Method, path)

			continue
		}

		for _, p := range op.Parameters {
			switch p.In {
			case "query":
				if _, refused := d.refused[p.Name]; d.query[p.Name] == 0 && !refused {
					t.Errorf("%s: the parameter %q isn't decided on", e.Name, p.Name)
				}
			case "header":
				h, listed := forwardedHeaders[http.CanonicalHeaderKey(p.Name)]
				if !listed || (h.endpoints != nil && !slices.Contains(h.endpoints, e.Name)) {
					t.Errorf("%s: the header %q isn't decided on", e.Name, p.Name)
				}
			}

			checked++
		}
	}

	if checked < 80 {
		t.Errorf("only %d parameters checked: the description wasn't read as expected", checked)
	}
}

// pathOf is a request path for an endpoint, its objects named x.
func pathOf(e route.Endpoint) string {
	p := strings.NewReplacer("{id}", "x", "{name}", "x", "{name*}", "x").Replace(e.Pattern)
	if e.Pattern == "/_ping" {
		return p
	}

	return "/v1.56" + p
}

func TestAParameterNotListedIsRefusedOnEveryEndpoint(t *testing.T) {
	d := startDocker(t)
	server := gate(t, d, "sites")

	for _, e := range route.Endpoints() {
		if _, ok := forScopes[e.Name]; !ok {
			continue
		}

		status, answer := send(t, server, e.Method, pathOf(e)+"?yorvogate-unknown=1", "", asJane)
		if status != http.StatusForbidden || (e.Method != "HEAD" && !strings.Contains(answer, `the parameter \"yorvogate-unknown\" isn't one YorvoGate forwards`)) {
			t.Errorf("%s: %d %s", e.Name, status, answer)
		}

		for key := range forScopes[e.Name].refused {
			if status, _ := send(t, server, e.Method, pathOf(e)+"?"+key+"=1", "", asJane); status != http.StatusForbidden {
				t.Errorf("%s ?%s: %d", e.Name, key, status)
			}
		}
	}

	if d.count() != 0 {
		t.Errorf("%d requests reached Docker", d.count())
	}
}

// A scope that may delete one of its image names may not delete a platform's content: Docker deletes
// it from every image that has it, other scopes' too.
func TestAnImageDeleteCantDeleteAPlatformsContent(t *testing.T) {
	d := startDocker(t)
	server := gate(t, d, "sites")

	status, answer := send(t, server, "DELETE", "/v1.56/images/quire-sites/jane/php-prod:before-update?force=1&platforms=%7B%22os%22%3A%22linux%22%2C%22architecture%22%3A%22amd64%22%7D", "", asJane)
	if status != http.StatusForbidden || !strings.Contains(message(t, answer), "deleting a platform's content deletes it from every image that has it") {
		t.Errorf("%d %s", status, answer)
	}

	if status, answer := send(t, server, "DELETE", "/v1.56/images/quire-sites/jane/php-prod:before-update?force=1", "", asJane); status != http.StatusOK {
		t.Errorf("without platforms: %d %s", status, answer)
	}

	if q := d.last().query; q != "force=1" {
		t.Errorf("Docker got ?%s", q)
	}
}

// logs is a log that tests read.
type logs struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *logs) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	return l.buf.Write(p)
}

func (l *logs) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()

	return l.buf.String()
}

func TestDockerGetsOnlyTheHeadersListed(t *testing.T) {
	d := startDocker(t)
	var log logs
	server := gateLogging(t, d, "sites", slog.New(slog.NewTextHandler(&log, nil)))

	header := map[string]string{
		"User-Agent": "Docker-Client/29.9.2", "Accept": "application/json", "Traceparent": "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
		"X-Request-Id": "abc", "Via": "1.1 proxy", "X-Registry-Auth": "e30=", "Upgrade": "tcp", "Connection": "Upgrade",
		"X-Registry-Config": "e30=",
	}
	for k, v := range asJane {
		header[k] = v
	}

	for range 2 {
		if status, answer := send(t, server, "GET", "/v1.56/version", "", header); status != http.StatusOK {
			t.Fatalf("%d %s", status, answer)
		}
	}

	got := d.last().header
	for _, name := range []string{"User-Agent", "Accept", "Traceparent"} {
		if got.Get(name) != header[name] {
			t.Errorf("%s: Docker got %q", name, got.Get(name))
		}
	}

	for _, name := range []string{"X-Request-Id", "Via", "X-Registry-Auth", "Upgrade", "X-Registry-Config", "X-Yorvogate-Token", "X-Yorvogate-Scope"} {
		if got.Get(name) != "" {
			t.Errorf("%s: Docker got %q", name, got.Get(name))
		}
	}

	if strings.Count(log.String(), "header=X-Request-Id") != 1 {
		t.Errorf("a header not forwarded is warned of once:\n%s", log.String())
	}

	if !strings.Contains(log.String(), "headers_not_forwarded") || strings.Contains(log.String(), "e30=") {
		t.Errorf("the decision names what wasn't forwarded, never a value:\n%s", log.String())
	}

	// A pull's credentials go with a pull
	if status, answer := send(t, server, "POST", "/v1.56/images/create?fromImage=alpine&tag=3.22", "", header); status != http.StatusOK {
		t.Fatalf("%d %s", status, answer)
	}

	if got := d.last().header; got.Get("X-Registry-Auth") != "e30=" || got.Get("Upgrade") != "" {
		t.Errorf("a pull: Docker got %v", got)
	}
}

func TestAHeaderGivenTwiceOrTooLongIsRefused(t *testing.T) {
	d := startDocker(t)
	server := gate(t, d, "sites")

	for name, header := range map[string]http.Header{
		"twice":             {"Accept": {"application/json", "text/plain"}},
		"two spellings":     {"Accept": {"application/json"}, "accept": {"text/plain"}},
		"credentials twice": {"X-Registry-Auth": {"e30=", "e30="}},
		"too long":          {"Traceparent": {strings.Repeat("0", 257)}},
	} {
		req, _ := http.NewRequest("POST", server.URL+"/v1.56/images/create?fromImage=alpine&tag=3.22", nil)
		for k, v := range asJane {
			req.Header.Set(k, v)
		}

		for k, vs := range header {
			req.Header[k] = vs
		}

		res, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()

		if res.StatusCode != http.StatusBadRequest {
			t.Errorf("%s: %d", name, res.StatusCode)
		}
	}

	if d.count() != 0 {
		t.Errorf("%d requests reached Docker", d.count())
	}

	// Two spellings, read in this order, the first empty: given twice all the same
	if _, _, err := forwarded(http.Header{"Accept": {""}, "accept": {"application/json"}}, "system.version"); err == nil {
		t.Error("an empty header, then the same under another spelling: forwarded")
	}
}
