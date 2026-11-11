package differential

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yorvolabs/yorvogate/internal/config"
	"github.com/yorvolabs/yorvogate/internal/gate"
	"github.com/yorvolabs/yorvogate/internal/scope"
)

const token = "a-long-random-token-0123456789abcdef"

// The scope the suite's requests are sent as, and its neighbour, whose objects are in the world.
const janeScope = `{
	"token_sha256": "%s",
	"owner": {"label": "com.docker.compose.project", "value": "jane"},
	"prefixes": ["jane-", "jane_"],
	"images": ["quire-sites/jane/"]
}`

const blogScope = `{
	"token_sha256": "` + "0000000000000000000000000000000000000000000000000000000000000000" + `",
	"owner": {"label": "com.docker.compose.project", "value": "blog"},
	"prefixes": ["blog-", "blog_"],
	"images": ["quire-sites/blog/"]
}`

// suite is a scoped gate in front of the recording daemon.
type suite struct {
	t        testing.TB
	d        *daemon
	registry *scope.Registry
	front    string // the gate's address
}

func newSuite(t testing.TB) *suite {
	t.Helper()

	d := startDaemon(t)
	front, registry := startGate(t, d.socket)
	d.take() // the gate's own reads so far

	return &suite{t: t, d: d, registry: registry, front: front}
}

// startGate is the suite's scoped gate in front of a Docker (the recorder, or a real one): its
// address, and its registry.
func startGate(t testing.TB, upstream string) (string, *scope.Registry) {
	t.Helper()

	dir := t.TempDir()
	scopes := filepath.Join(dir, "scopes")

	if err := os.Mkdir(scopes, 0o700); err != nil {
		t.Fatal(err)
	}

	sum := sha256.Sum256([]byte(token))
	write := func(name, content string) {
		if err := os.WriteFile(filepath.Join(scopes, name+".json"), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("jane", fmt.Sprintf(janeScope, hex.EncodeToString(sum[:])))
	write("blog", blogScope)

	// A Docker with neither AppArmor nor SELinux (Docker Desktop's VM) is accepted only when said:
	// a test's setting, never a host's (as the conformance suite's without_lsm)
	daemon := ""
	if os.Getenv("YGD_WITHOUT_LSM") == "1" {
		daemon = "daemon: {without_lsm: true}\n"
	}

	c, err := config.Parse([]byte(daemon + `
upstream: unix://` + upstream + `
listeners:
  - name: sites
    address: tcp://127.0.0.1:2376
    mode: scoped
    scopes: ` + scopes + `
    containers:
      drop_all_capabilities: true
      no_new_privileges: true
      protected_images: [quire-sites/]
`))
	if err != nil {
		t.Fatal(err)
	}

	registry := gate.Registry(c)
	if err := registry.Reload(); err != nil {
		t.Fatal(err)
	}

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	defaults := gate.NewDefaults(c)
	defaults.Read(context.Background())

	if unsafe, _ := defaults.Check(context.Background()); len(unsafe) > 0 {
		t.Fatalf("Docker's defaults, as the gate reads them: %v", unsafe)
	}

	g := gate.New(c, c.Listeners[0], gate.NewUpstream(c, log), registry, defaults, log)
	front := httptest.NewServer(gate.NewServer(g).Handler)
	t.Cleanup(front.Close)

	return strings.TrimPrefix(front.URL, "http://"), registry
}

// request is an HTTP request as it's written on the wire: the suite writes it byte for byte, so a
// variant can say what a client library wouldn't (two Content-Lengths, a raw path).
type request struct {
	method, target string // target: the request line's, path and query as written
	header         [][2]string
	body           []byte
	// framing: "" (Content-Length of body), "chunked", "both" (both headers), "short", "long"
	framing string
}

// asJane is a request with jane's scope and token.
func asJane(method, target, ctype string, body []byte) request {
	r := request{method: method, target: target, body: body, header: [][2]string{
		{"Host", "docker"}, {"X-YorvoGate-Scope", "jane"}, {"X-YorvoGate-Token", token},
	}}
	if ctype != "" {
		r.header = append(r.header, [2]string{"Content-Type", ctype})
	}

	return r
}

func (r request) clone() request {
	c := r
	c.header = append([][2]string{}, r.header...)
	c.body = append([]byte{}, r.body...)

	return c
}

// with is the request with a header set (replacing it) or added (add).
func (r request) with(name, value string, add bool) request {
	c := r.clone()
	if !add {
		kept := c.header[:0]
		for _, h := range c.header {
			if !strings.EqualFold(h[0], name) {
				kept = append(kept, h)
			}
		}
		c.header = kept
	}
	c.header = append(c.header, [2]string{name, value})

	return c
}

func (r request) wire() []byte {
	var b bytes.Buffer

	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\n", r.method, r.target)

	for _, h := range r.header {
		fmt.Fprintf(&b, "%s: %s\r\n", h[0], h[1])
	}

	body := r.body

	switch r.framing {
	case "":
		if len(body) > 0 || r.method == "POST" || r.method == "PUT" {
			fmt.Fprintf(&b, "Content-Length: %d\r\n", len(body))
		}
	case "chunked", "both":
		if r.framing == "both" {
			fmt.Fprintf(&b, "Content-Length: %d\r\n", len(body))
		}
		b.WriteString("Transfer-Encoding: chunked\r\n")
		var chunked bytes.Buffer
		if len(body) > 0 {
			fmt.Fprintf(&chunked, "%x\r\n%s\r\n", len(body), body)
		}
		chunked.WriteString("0\r\n\r\n")
		body = chunked.Bytes()
	case "short":
		fmt.Fprintf(&b, "Content-Length: %d\r\n", max(len(body)-1, 0))
	case "long":
		fmt.Fprintf(&b, "Content-Length: %d\r\n", len(body)+16)
	}

	b.WriteString("Connection: close\r\n\r\n")
	b.Write(body)

	return b.Bytes()
}

// What became of a request.
type kind int

const (
	refusedByGate     kind = iota // the gate answered it, nothing reached Docker
	read                          // forwarded, and a backend method was handed it
	refusedByDocker               // forwarded, and Docker answered before any backend method
	reachedUnrecorded             // forwarded, and Docker called a method the recorder hasn't
	answered                      // forwarded, and Docker answered it itself, calling no backend (2xx)
)

func (k kind) String() string {
	return [...]string{"refused by the gate", "read by Docker", "forwarded, refused by Docker", "reached an unrecorded method", "answered by Docker without a backend"}[k]
}

type outcome struct {
	kind     kind
	status   int
	message  string
	readings []reading
	reached  []string
}

func (o outcome) String() string {
	s := fmt.Sprintf("%s (%d)", o.kind, o.status)
	if o.message != "" {
		s += ": " + o.message
	}

	for _, r := range o.readings {
		s += "\n      " + r.String()
	}

	if len(o.reached) > 0 {
		s += "\n      reached " + strings.Join(o.reached, ", ")
	}

	return s
}

// send writes a request to the gate and says what became of it.
func (s *suite) send(r request) outcome {
	s.t.Helper()
	s.d.idle()
	s.d.take()

	network, address := "tcp", s.front
	if path, ok := strings.CutPrefix(s.front, "unix:"); ok {
		network, address = "unix", path
	}

	conn, err := net.DialTimeout(network, address, 5*time.Second)
	if err != nil {
		s.t.Fatal(err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	if _, err := conn.Write(r.wire()); err != nil {
		s.t.Fatal(err)
	}

	// Done writing, as a client that has sent all it has: a length that promised more ends here
	if c, ok := conn.(interface{ CloseWrite() error }); ok && r.framing == "long" {
		_ = c.CloseWrite()
	}

	o := outcome{status: 0}

	if res, err := http.ReadResponse(bufio.NewReader(conn), nil); err == nil {
		o.status = res.StatusCode
		body, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
		_ = res.Body.Close()

		var answer struct{ Message string }
		if json.Unmarshal(body, &answer) == nil {
			o.message = answer.Message
		}
	}

	// A stream's backend call can come after its answer: what this request made Docker read is in
	// once Docker serves nothing (the connection is closed: a stream ends with it)
	_ = conn.Close()
	s.d.idle()

	arrived := s.d.forwarded()
	o.readings, o.reached = s.d.take()

	switch {
	case len(o.reached) > 0:
		o.kind = reachedUnrecorded
	case len(o.readings) > 0:
		o.kind = read
	case arrived == 0:
		// Nothing reached Docker: the gate refused it (YorvoGate's rules, or its HTTP server's)
		o.kind = refusedByGate
	case o.status/100 == 2:
		o.kind = answered
	default:
		o.kind = refusedByDocker
	}

	return o
}
