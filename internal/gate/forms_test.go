package gate

import (
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/yorvolabs/yorvogate/internal/route"
)

// The assessment's C-1: Docker's handlers read parameters with Go's Request.ParseForm, in which a
// form-encoded body's values win over the URL's query. A query YorvoGate checked must be all Docker
// reads.

// The attack as it ran against 0.1.0: the query a pull of jane's own, the body an import from a URL
// named postgres:18, and a pull into blog's namespace.
func TestAFormBodyNeverReachesDocker(t *testing.T) {
	d := startDocker(t)
	server := gate(t, d, "sites")
	query := "/v1.56/images/create?fromImage=quire-sites/jane/app&tag=1"

	for name, c := range map[string][2]string{
		"an import":                  {"application/x-www-form-urlencoded", "fromImage=&fromSrc=http://127.0.0.1:8000/rootfs.tar&repo=postgres&tag=18"},
		"a pull into blog's":         {"application/x-www-form-urlencoded", "fromImage=quire-sites/blog/php-prod&tag=1"},
		"in another case":            {"Application/X-WWW-Form-URLEncoded; charset=utf-8", "fromImage=quire-sites/blog/php-prod"},
		"multipart":                  {"multipart/form-data; boundary=x", "--x\r\nContent-Disposition: form-data; name=\"fromImage\"\r\n\r\nquire-sites/blog/php-prod\r\n--x--\r\n"},
		"another multipart":          {"multipart/mixed; boundary=x", "--x--\r\n"},
		"malformed parameters":       {"application/x-www-form-urlencoded; =", "fromImage=quire-sites/blog/php-prod"},
		"a type that doesn't parse":  {"application/", "fromImage=quire-sites/blog/php-prod"},
		"text, as the CLI labels it": {"text/plain", "fromImage=&fromSrc=http://127.0.0.1:8000/rootfs.tar&repo=postgres&tag=18"},
	} {
		status, answer := send(t, server, "POST", query, c[1], map[string]string{"X-YorvoGate-Scope": "jane", "X-YorvoGate-Token": token, "Content-Type": c[0]})
		if status/100 != 4 || !strings.HasPrefix(message(t, answer), "yorvogate: ") {
			t.Errorf("%s: %d %s", name, status, answer)
		}
	}

	// Two Content-Types: Docker's would be the first, a check's could be another.
	req, _ := http.NewRequest("POST", server.URL+query, strings.NewReader("fromImage=quire-sites/blog/php-prod"))
	req.Header.Set("X-YorvoGate-Scope", "jane")
	req.Header.Set("X-YorvoGate-Token", token)
	req.Header["Content-Type"] = []string{"text/plain", "application/x-www-form-urlencoded"}

	res, err := server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()

	if res.StatusCode != http.StatusBadRequest {
		t.Errorf("two Content-Types: %d", res.StatusCode)
	}

	if d.count() != 0 {
		t.Errorf("%d requests reached Docker", d.count())
	}
}

// Every endpoint in the table, allowed for a scope or not: a form body is refused before anything else.
func TestEveryEndpointRefusesAForm(t *testing.T) {
	d := startDocker(t)
	server := gate(t, d, "sites")
	header := map[string]string{"X-YorvoGate-Scope": "jane", "X-YorvoGate-Token": token, "Content-Type": "application/x-www-form-urlencoded"}
	params := strings.NewReplacer("{id}", "jane-php-1", "{name*}", "quire-sites/jane/php-prod", "{name}", "jane_data")

	for _, e := range route.Endpoints() {
		path := "/v1.56" + params.Replace(e.Pattern)

		status, answer := send(t, server, e.Method, path, "fromImage=quire-sites/blog/php-prod&container=blog-php-1", header)
		if status != http.StatusUnsupportedMediaType {
			t.Errorf("%s (%s %s): %d %s", e.Name, e.Method, path, status, answer)
		}
	}

	if d.count() != 0 {
		t.Errorf("%d requests reached Docker", d.count())
	}
}

// dockerReads is what Docker's handler reads from a forwarded request: Request.ParseForm, as
// httputils.ParseForm calls it.
func dockerReads(t *testing.T, s seen) url.Values {
	t.Helper()

	req, err := http.NewRequest(s.method, "http://docker"+s.path+"?"+s.query, strings.NewReader(s.body))
	if err != nil {
		t.Fatal(err)
	}

	req.Header = s.header
	if err := req.ParseForm(); err != nil {
		t.Fatalf("Docker couldn't read %s: %v", s.path, err)
	}

	return req.Form
}

// What a scope may do is forwarded with YorvoGate's Content-Type, whatever the client's: Docker
// reads the query that was checked, and nothing else.
func TestDockerReadsOnlyWhatWasChecked(t *testing.T) {
	d := startDocker(t)
	server := gate(t, d, "sites")
	tar := string(archive(t, entry{name: "manifest.json", content: `[{"RepoTags":["quire-sites/jane/php-prod:latest"]}]`}))

	for _, c := range []struct {
		name, method, path, contentType, body string
		want                                  string // the Content-Type Docker gets
	}{
		// The Docker CLI labels a POST without a body text/plain.
		{"a pull, as the CLI sends it", "POST", "/v1.56/images/create?fromImage=quire-sites/jane/app&tag=1", "text/plain", "", ""},
		{"a pull, unlabelled", "POST", "/v1.56/images/create?fromImage=quire-sites/jane/app&tag=1", "", "", ""},
		{"a start", "POST", "/v1.56/containers/jane-php-1/start", "text/plain", "", ""},
		{"a create, mislabelled", "POST", "/v1.56/containers/create?name=jane-php-1", "text/plain", encode(compose()), "application/json"},
		{"a load", "POST", "/v1.56/images/load?quiet=1", "application/octet-stream", tar, "application/x-tar"},
		{"an archive into its own container", "PUT", "/v1.56/containers/jane-php-1/archive?path=%2Ftmp", "application/octet-stream", "fromImage=not-a-form", "application/x-tar"},
	} {
		header := map[string]string{"X-YorvoGate-Scope": "jane", "X-YorvoGate-Token": token}
		if c.contentType != "" {
			header["Content-Type"] = c.contentType
		}

		before := d.count()
		if status, answer := send(t, server, c.method, c.path, c.body, header); status != 200 || d.count() != before+1 {
			t.Errorf("%s: %d %s", c.name, status, answer)

			continue
		}

		got := d.last()
		if ct := got.header.Get("Content-Type"); ct != c.want {
			t.Errorf("%s: Docker got Content-Type %q, want %q", c.name, ct, c.want)
		}

		query, _ := url.ParseQuery(got.query)
		if form := dockerReads(t, got); !reflect.DeepEqual(form, query) {
			t.Errorf("%s: Docker reads %v, YorvoGate checked %v", c.name, form, query)
		}
	}

	// A pull with a body: Docker would read an import's archive from it.
	before := d.count()
	for _, contentType := range []string{"text/plain", "application/x-tar", ""} {
		header := map[string]string{"X-YorvoGate-Scope": "jane", "X-YorvoGate-Token": token}
		if contentType != "" {
			header["Content-Type"] = contentType
		}

		status, answer := send(t, server, "POST", "/v1.56/images/create?fromImage=quire-sites/jane/app&tag=1", "an archive", header)
		if status != http.StatusBadRequest || !strings.Contains(message(t, answer), "image.create has no body") {
			t.Errorf("a pull with a body (%q): %d %s", contentType, status, answer)
		}
	}

	if d.count() != before {
		t.Errorf("%d pulls with a body reached Docker", d.count()-before)
	}
}
