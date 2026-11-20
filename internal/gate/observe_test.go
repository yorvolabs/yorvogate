package gate

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// A Docker that went away and came back (a restart, perhaps with other defaults) is never met with
// the defaults read before: once a request finds it down, scoped requests are refused (503) until
// its defaults are read again, and what's read then decides.
func TestADockerRestartIsNeverMetWithStaleDefaults(t *testing.T) {
	old := downRetry
	downRetry = 20 * time.Millisecond
	defer func() { downRetry = old }()

	d := startDocker(t)
	log, _ := checkedLog(t)
	server, defaults := gateAndDefaults(t, d, "sites", log)

	// Watch has returned before downRetry is restored (the defers run last first)
	ctx, stop := context.WithCancel(context.Background())
	watched := make(chan struct{})

	defer func() { stop(); <-watched }()

	go func() { defaults.Watch(ctx, log); close(watched) }()

	if status, answer := send(t, server, "GET", "/v1.56/containers/json", "", asJane); status != http.StatusOK {
		t.Fatalf("before: %d %s", status, answer)
	}

	// Docker restarts: one request finds it gone, and it comes back with defaults that would widen
	// what scopes may do
	d.mu.Lock()
	d.down = true
	d.mu.Unlock()

	if status, _ := send(t, server, "GET", "/v1.56/containers/json", "", asJane); status/100 != 5 {
		t.Fatalf("while it's down: %d", status)
	}

	d.mu.Lock()
	d.down = false
	unsafe := ubuntuInfo()
	unsafe["SecurityOptions"] = []string{"name=apparmor,profile=default", "name=seccomp,profile=unconfined", "name=cgroupns"}
	d.info = unsafe
	d.mu.Unlock()

	// At once: never forwarded under the old defaults
	if status, answer := send(t, server, "GET", "/v1.56/containers/json", "", asJane); status != http.StatusServiceUnavailable {
		t.Errorf("at once after it's back: %d %s", status, answer)
	}

	// Then refused for what's read now (Watch reads every downRetry while Docker is down), every
	// request until then refused too
	deadline := time.Now().Add(5 * time.Second)

	for {
		status, answer := send(t, server, "GET", "/v1.56/containers/json", "", asJane)
		if status != http.StatusServiceUnavailable {
			t.Fatalf("after it's back: %d %s", status, answer)
		}

		if strings.Contains(answer, "would widen") {
			break
		}

		if time.Now().After(deadline) {
			t.Fatalf("its defaults weren't read again in 5 s: %s", answer)
		}

		time.Sleep(downRetry)
	}
}

// checkExposition holds a /metrics answer to Prometheus's text format 0.0.4, strictly: every
// family's HELP and TYPE before its samples, once; each sample line name{labels} value, its labels
// escaped; a histogram's buckets cumulative, ending at +Inf, equal to its count.
func checkExposition(t *testing.T, text string) map[string]float64 {
	t.Helper()

	sample := regexp.MustCompile(`^([a-zA-Z_:][a-zA-Z0-9_:]*)(\{((?:[a-zA-Z_][a-zA-Z0-9_]*="(?:[^"\\\n]|\\["\\n])*",?)*)\})? (-?[0-9.e+-]+|\+Inf|NaN)$`)
	types, helps := map[string]string{}, map[string]bool{}
	values := map[string]float64{}
	lastBucket := map[string]float64{}

	for _, line := range strings.Split(strings.TrimSuffix(text, "\n"), "\n") {
		switch {
		case strings.HasPrefix(line, "# HELP "):
			name := strings.Fields(line)[2]
			if helps[name] {
				t.Errorf("HELP twice for %s", name)
			}

			helps[name] = true
		case strings.HasPrefix(line, "# TYPE "):
			f := strings.Fields(line)
			if len(f) != 4 || !slices.Contains([]string{"counter", "gauge", "histogram"}, f[3]) {
				t.Errorf("a TYPE line: %q", line)
			}

			if _, twice := types[f[2]]; twice || !helps[f[2]] {
				t.Errorf("TYPE of %s twice, or before its HELP", f[2])
			}

			types[f[2]] = f[3]
		default:
			m := sample.FindStringSubmatch(line)
			if m == nil {
				t.Errorf("not a sample line: %q", line)

				continue
			}

			family := strings.TrimSuffix(strings.TrimSuffix(strings.TrimSuffix(m[1], "_bucket"), "_sum"), "_count")
			if types[family] == "" {
				t.Errorf("%s before its TYPE", m[1])
			}

			v, _ := strconv.ParseFloat(strings.Replace(m[4], "+Inf", "Inf", 1), 64)
			values[m[1]+"{"+m[3]+"}"] = v

			if strings.HasSuffix(m[1], "_bucket") {
				series := m[1] + regexp.MustCompile(`,?le="[^"]*"`).ReplaceAllString(m[3], "")
				if v < lastBucket[series] {
					t.Errorf("%s: buckets not cumulative", line)
				}

				lastBucket[series] = v
			}
		}
	}

	return values
}

// /metrics counts decisions, refusals by code, and auth failures by cause, in the text format; by
// default no line names a scope; with scope_labels, refusals do.
func TestMetrics(t *testing.T) {
	for _, scopeLabels := range []bool{false, true} {
		d := startDocker(t)
		log, _ := checkedLog(t)
		server, defaults := gateAndDefaults(t, d, "sites", log)

		m := NewMetrics(scopeLabels)
		g := server.Config.Handler.(*Gate)
		g.UseMetrics(m)

		send(t, server, "GET", "/v1.56/containers/json", "", asJane)
		send(t, server, "POST", "/v1.56/containers/create?name=jane-x", encode(set(compose(), "HostConfig.Privileged", true)), asJane)
		send(t, server, "GET", "/v1.56/containers/json", "", map[string]string{"X-YorvoGate-Scope": "jane", "X-YorvoGate-Token": "wrong"})

		admin := httptest.NewServer(Admin(NewLive(g.config, ""), m, defaults, g.registry, g.spool))
		t.Cleanup(admin.Close)

		res, err := http.Get(admin.URL + "/metrics")
		if err != nil {
			t.Fatal(err)
		}

		body, _ := io.ReadAll(res.Body)
		_ = res.Body.Close()

		if ct := res.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/plain; version=0.0.4") {
			t.Errorf("Content-Type %q", ct)
		}

		text := string(body)
		values := checkExposition(t, text)

		for series, want := range map[string]float64{
			`yorvogate_requests_total{listener="sites",endpoint="container.list",outcome="allowed"}`:   1,
			`yorvogate_requests_total{listener="sites",endpoint="container.create",outcome="refused"}`: 1,
			`yorvogate_auth_failures_total{listener="sites",cause="wrong-token"}`:                      1,
			`yorvogate_docker_up{}`:            1,
			`yorvogate_docker_defaults_safe{}`: 1,
		} {
			if values[series] != want {
				t.Errorf("scope_labels %v: %s = %v, want %v", scopeLabels, series, values[series], want)
			}
		}

		// Go's runtime, as Prometheus's Go client names it
		for _, series := range []string{"go_goroutines{}", "go_memstats_heap_alloc_bytes{}", "go_memstats_sys_bytes{}", "go_gc_heap_goal_bytes{}", "go_gc_gomemlimit_bytes{}"} {
			if values[series] <= 0 {
				t.Errorf("%s = %v, want a value above 0", series, values[series])
			}
		}

		withScope := `yorvogate_refusals_total{listener="sites",code="body.field-not-allowed",scope="jane"}`
		without := `yorvogate_refusals_total{listener="sites",code="body.field-not-allowed"}`

		switch {
		case scopeLabels && values[withScope] != 1:
			t.Errorf("with scope_labels: no %s", withScope)
		case !scopeLabels && (values[without] != 1 || strings.Contains(text, `scope="`) || strings.Contains(text, "jane")):
			t.Errorf("by default: a scope is named, or no %s:\n%s", without, text)
		}
	}
}

// A label's value is escaped as the format reads it.
func TestMetricLabelsAreEscaped(t *testing.T) {
	m := NewMetrics(true)
	m.decided(`a"b\c`+"\n", "container.list", nil, "", time.Millisecond)

	var b strings.Builder
	_ = m.Write(&b)

	if !strings.Contains(b.String(), `listener="a\"b\\c\n"`) {
		t.Errorf("not escaped:\n%s", b.String())
	}

	checkExposition(t, b.String())
}

// /healthz is the process; /readyz whether scoped requests can be served now, saying why not: Docker
// gone, its defaults unsafe, its API versions not the gate's.
func TestReadiness(t *testing.T) {
	d := startDocker(t)
	log, _ := checkedLog(t)
	server, defaults := gateAndDefaults(t, d, "sites", log)
	g := server.Config.Handler.(*Gate)
	admin := httptest.NewServer(Admin(NewLive(g.config, ""), NewMetrics(false), defaults, g.registry, g.spool))
	t.Cleanup(admin.Close)

	ready := func() (int, Readiness) {
		res, err := http.Get(admin.URL + "/readyz")
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()

		var r Readiness
		body, _ := io.ReadAll(res.Body)
		_ = json.Unmarshal(body, &r)

		doc, _ := jsonschema.UnmarshalJSON(bytes.NewReader(body))
		if err := readinessSchema.Validate(doc); err != nil {
			t.Errorf("not the schema's: %v", err)
		}

		return res.StatusCode, r
	}

	if code, r := ready(); code != http.StatusOK || !r.Ready {
		t.Fatalf("ready: %d %+v", code, r)
	}

	if res, err := http.Get(admin.URL + "/healthz"); err != nil || res.StatusCode != http.StatusOK {
		t.Errorf("healthz: %v %v", res, err)
	}

	// Docker's API versions all above the gate's
	d.mu.Lock()
	d.api, d.apiMin = "1.61", "1.58"
	d.mu.Unlock()
	defaults.Read(context.Background())

	if code, r := ready(); code != http.StatusServiceUnavailable || !strings.Contains(r.Checks["api_versions"], "no version is both's") {
		t.Errorf("API versions not overlapping: %d %+v", code, r)
	}

	// Docker down: not ready, its ping cached at most a second
	d.mu.Lock()
	d.api, d.apiMin, d.down = "", "", true
	d.mu.Unlock()

	time.Sleep(1100 * time.Millisecond)

	if code, r := ready(); code != http.StatusServiceUnavailable || r.Checks["docker"] == "ok" {
		t.Errorf("Docker down: %d %+v", code, r)
	}

	// Anything but GET on its paths, and Docker's paths, aren't the admin listener's
	for method, path := range map[string]string{"POST": "/readyz", "GET": "/v1.56/containers/json"} {
		req, _ := http.NewRequest(method, admin.URL+path, nil)
		if res, err := http.DefaultClient.Do(req); err != nil || res.StatusCode/100 != 4 {
			t.Errorf("%s %s: %v %v", method, path, res, err)
		}
	}
}

var readinessSchema = func() *jsonschema.Schema {
	s, err := jsonschema.NewCompiler().Compile("../../schemas/yorvogate-readiness.v1.schema.json")
	if err != nil {
		panic(err)
	}

	return s
}()

// The auth failed line is limited: at most 10 a minute from one source (an IPv6 one by its /64), 600
// from all, the rest counted and said once. A flood from many sources doesn't grow the table.
func TestAuthFailedLinesAreLimited(t *testing.T) {
	a := newAuthLimiter()
	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	logged := 0

	for i := range 100 {
		if ok, _ := a.allow("203.0.113.9:"+strconv.Itoa(40000+i), now); ok {
			logged++
		}
	}

	if logged != authLinesPerSource {
		t.Errorf("one source: %d lines, want %d", logged, authLinesPerSource)
	}

	// An IPv6 source's /64 is one source
	logged = 0
	for i := range 50 {
		if ok, _ := a.allow(fmt.Sprintf("[2001:db8:1:2::%x]:443", i), now); ok {
			logged++
		}
	}

	if logged != authLinesPerSource {
		t.Errorf("one /64: %d lines, want %d", logged, authLinesPerSource)
	}

	// Many sources: the global limit, and a bounded table
	logged = 0
	for i := range 10000 {
		if ok, _ := a.allow(fmt.Sprintf("198.51.%d.%d:1", i/256, i%256), now); ok {
			logged++
		}
	}

	if total := logged + 2*authLinesPerSource; total != authLinesGlobal {
		t.Errorf("all sources: %d lines, want %d", total, authLinesGlobal)
	}

	if len(a.sources) > authSources {
		t.Errorf("%d sources kept", len(a.sources))
	}

	// The next minute: what was dropped is said once
	if _, dropped := a.allow("203.0.113.9:1", now.Add(time.Minute)); dropped != 100+50+10000-authLinesGlobal {
		t.Errorf("dropped: %d", dropped)
	}
}

// Docker hanging up on one request (while its _ping answers) isn't Docker down: no other scope's
// requests are made to wait, so no scope can stall the others by provoking it.
func TestOneRequestDockerDropsIsntDockerDown(t *testing.T) {
	d := startDocker(t)
	log, _ := checkedLog(t)
	_, defaults := gateAndDefaults(t, d, "sites", log)

	defaults.Suspect(io.ErrUnexpectedEOF) // Docker's _ping answers

	if _, err := defaults.current(defaults.config.Load()); err != nil {
		t.Errorf("a dropped request marked Docker down: %v", err)
	}

	// But a refused dial is Docker gone
	defaults.Suspect(&net.OpError{Op: "dial", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)})

	if _, err := defaults.current(defaults.config.Load()); err == nil {
		t.Error("a refused dial left Docker up")
	}
}

// However many requests Docker hangs up on, Suspect pings it at most once a second.
func TestSuspectingPingsAtMostOnceASecond(t *testing.T) {
	d := startDocker(t)
	log, _ := checkedLog(t)
	_, defaults := gateAndDefaults(t, d, "sites", log)

	d.mu.Lock()
	before := len(d.asked)
	d.mu.Unlock()

	for range 50 {
		defaults.Suspect(io.ErrUnexpectedEOF)
	}

	d.mu.Lock()
	pings := 0
	for _, p := range d.asked[before:] {
		if p == "/_ping" {
			pings++
		}
	}
	d.mu.Unlock()

	if pings > 1 {
		t.Errorf("%d pings for 50 failed requests in under a second", pings)
	}
}
