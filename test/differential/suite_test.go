package differential

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fetches is a server on loopback, on a port of its own, that counts the requests made to it: the
// fromSrc of every smuggled import points at it, so an import Docker would make is seen.
type fetches struct {
	server *httptest.Server
	count  atomic.Int64
}

func startFetches(t testing.TB) *fetches {
	t.Helper()

	f := &fetches{}
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		f.count.Add(1)
		_, _ = w.Write([]byte("rootfs"))
	}))
	t.Cleanup(f.server.Close)

	return f
}

func (f *fetches) url() string { return f.server.URL + "/rootfs.tar" }

// The detector works: an import sent to Docker straight, past the gate, is fetched from the server.
// (The gate never allows a scope an import, so this is the only way to see one made.)
func TestTheFetchDetectorSeesAnImport(t *testing.T) {
	s := newSuite(t)
	f := startFetches(t)

	direct := s.direct(asJane("POST", "/v1.56/images/create?fromSrc="+f.url()+"&repo=quire-sites/jane/x&tag=1", "", nil))
	if f.count.Load() == 0 {
		t.Fatalf("Docker didn't fetch the import's fromSrc: %s", direct)
	}
}

// state is what the gate holds of its scopes, as JSON: the same before and after every request.
func (s *suite) state() string {
	store := s.registry.Store("sites")

	var out []string

	for _, name := range []string{"jane", "blog"} {
		sc, err := store.Get(name)
		b, _ := json.Marshal(sc)
		out = append(out, fmt.Sprintf("%s %v %s", name, err, b))
	}

	out = append(out, fmt.Sprint(s.registry.Reserved(), s.registry.Missing()))

	return strings.Join(out, "\n")
}

// The differential property. For every base and every way of writing it: the gate refuses it, or
// Docker reads exactly what it reads of the base (or refuses it before any backend, counted). For
// every attack and every way of writing it: the gate refuses it, and nothing reaches Docker. No
// variant makes Docker fetch an import, and none changes what the gate holds of its scopes.
func TestWhatDockerReadsIsWhatTheGateDecided(t *testing.T) {
	s := newSuite(t)
	f := startFetches(t)
	before := s.state()

	type tally map[kind]int

	classes := map[string]tally{}
	count := func(class string, k kind) {
		if classes[class] == nil {
			classes[class] = tally{}
		}

		classes[class][k]++
	}

	// Each base at the newest and the oldest API version the gate serves: Docker's defaults differ
	for _, version := range []string{"1.56", "1.44"} {
		for _, b := range bases {
			base := atVersion(b.req(t), version)
			want := s.send(base)

			if want.kind != read && want.kind != answered {
				t.Errorf("%s: the base isn't read: %s", b.endpoint, want)

				continue
			}

			for _, v := range variants(base, f.url(), false) {
				started := time.Now()
				got := s.send(v.req)
				if took := time.Since(started); took > time.Second {
					t.Logf("slow: %s, %s (%s): %s", b.endpoint, v.class, v.name, took.Round(time.Millisecond))
				}
				count(v.class, got.kind)

				switch got.kind {
				case refusedByGate:
				case refusedByDocker:
					// What Docker refuses the gate should have refused itself: it forwarded what it read
					// differently, or didn't read at all (none does today; one that must is listed)
					if why, ok := forwardedJunk[v.class+": "+v.name]; !ok {
						t.Errorf("v%s %s, %s (%s): forwarded, and refused by Docker: %s", version, b.endpoint, v.class, v.name, got)
					} else if why == "" {
						t.Errorf("%s: listed in forwardedJunk without a reason", v.class+": "+v.name)
					}
				case read, answered:
					if got.kind != want.kind || !reflect.DeepEqual(got.readings, want.readings) {
						t.Errorf("v%s %s, %s (%s): Docker read what the gate didn't decide on\n   base:    %s\n   variant: %s", version, b.endpoint, v.class, v.name, want, got)
					}
				default:
					t.Errorf("%s, %s (%s): %s", b.endpoint, v.class, v.name, got)
				}
			}
		}
	}

	for _, a := range attacks {
		for _, v := range append([]variant{{"plain", "as written", a.req(t)}}, variants(a.req(t), f.url(), true)...) {
			if got := s.send(v.req); got.kind != refusedByGate {
				t.Errorf("attack %s, %s, %s (%s): not refused by the gate: %s", a.endpoint, a.name, v.class, v.name, got)
			}
		}
	}

	if n := f.count.Load(); n != 0 {
		t.Errorf("Docker fetched an import %d times", n)
	}

	if after := s.state(); after != before {
		t.Errorf("the gate's scopes changed:\nbefore %s\nafter  %s", before, after)
	}

	// What became of each class of variant (O2: one mostly forwarded and refused by Docker is one
	// the gate should refuse itself)
	names := make([]string, 0, len(classes))
	for c := range classes {
		names = append(names, c)
	}

	sort.Strings(names)

	for _, c := range names {
		total := 0
		for _, n := range classes[c] {
			total += n
		}

		t.Logf("%-14s %4d: %d refused by the gate, %d read as the base, %d forwarded and refused by Docker",
			c, total, classes[c][refusedByGate], classes[c][read]+classes[c][answered], classes[c][refusedByDocker])

		if byDocker := classes[c][refusedByDocker]; byDocker*2 > total {
			t.Errorf("%s: %d of %d forwarded and refused by Docker: the gate should refuse these itself", c, byDocker, total)
		}
	}
}

// forwardedJunk is the variants the gate may forward for Docker to refuse, each with why it's
// harmless: none today.
var forwardedJunk = map[string]string{}

// direct sends a request to the recorder straight, past the gate.
func (s *suite) direct(r request) outcome {
	s.t.Helper()

	front := s.front
	s.front = "unix:" + s.d.socket
	defer func() { s.front = front }()

	return s.send(r)
}
