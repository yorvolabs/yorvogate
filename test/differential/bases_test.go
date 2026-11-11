package differential

import (
	"testing"

	"github.com/yorvolabs/yorvogate/internal/gate"
)

// The endpoints whose moby handler answers without calling a backend: there's nothing to read.
var answersItself = map[string]string{
	"system.ping": "pingHandler, daemon/server/router/system/system_routes.go:36-54 at 0367cbe",
}

// Every base is allowed by the gate, forwarded, and read by Docker: a base the gate starts refusing
// fails here, by name, rather than make each of its variants pass for nothing.
func TestEveryBaseIsAllowedAndRead(t *testing.T) {
	s := newSuite(t)

	for _, b := range bases {
		o := s.send(b.req(t))
		if _, itself := answersItself[b.endpoint]; itself && o.kind == answered {
			continue
		}

		if o.kind != read || len(o.readings) == 0 {
			t.Errorf("%s: %s", b.endpoint, o)
		}
	}
}

// Every attack is refused by the gate, with nothing reaching Docker.
func TestEveryAttackIsRefused(t *testing.T) {
	s := newSuite(t)

	for _, a := range attacks {
		if o := s.send(a.req(t)); o.kind != refusedByGate {
			t.Errorf("%s, %s: %s", a.endpoint, a.name, o)
		}
	}
}

// Every endpoint a scope may send has a base, so a new one can't skip the suite; and every one has
// an attack, or says why it has none.
func TestEveryEndpointHasABaseAndAnAttack(t *testing.T) {
	has := map[string]bool{}
	for _, b := range bases {
		has[b.endpoint] = true
	}

	attacked := map[string]bool{}
	for _, a := range attacks {
		attacked[a.endpoint] = true
	}

	for _, e := range gate.ScopeEndpoints() {
		if !has[e] {
			t.Errorf("%s: no base in the corpus", e)
		}

		if _, why := noAttack[e]; attacked[e] == why {
			t.Errorf("%s: an attack, or a reason in noAttack why it has none (not both)", e)
		}
	}

	known := map[string]bool{}
	for _, e := range gate.ScopeEndpoints() {
		known[e] = true
	}

	for _, b := range bases {
		if !known[b.endpoint] {
			t.Errorf("a base for %s, which scopes may no longer send", b.endpoint)
		}
	}

	for e := range noAttack {
		if !known[e] {
			t.Errorf("noAttack names %s, which scopes may no longer send", e)
		}
	}
}

// What Docker makes of a base that creates or names an object is the scope's: its name under the
// scope's prefixes or image namespace, its owner label, as the gate booked it (O1).
func TestDockerMakesTheScopesOwn(t *testing.T) {
	s := newSuite(t)

	want := map[string][]string{
		"container.create": {`"jane-web-1"`, `"com.docker.compose.project":"jane"`},
		"container.rename": {`"jane-php-2"`},
		"network.create":   {`"Name":"jane_new"`, `"com.docker.compose.project":"jane"`},
		"volume.create":    {`"jane_new"`, `"com.docker.compose.project":"jane"`},
		"image.create":     {`"docker.io/quire-sites/jane/app:1"`},
		"image.tag":        {`"docker.io/quire-sites/jane/app:2"`},
		"image.load":       {`"index: docker.io/quire-sites/jane/app:2"`, `"manifest: quire-sites/jane/app:2"`},
		"container.list":   {`com.docker.compose.project=jane`},
		"container.prune":  {`com.docker.compose.project=jane`},
		"network.list":     {`["jane_default"]`},
		"network.prune":    {`com.docker.compose.project=jane`},
		"volume.list":      {`com.docker.compose.project=jane`},
		"volume.prune":     {`com.docker.compose.project=jane`},
	}

	for _, b := range bases {
		words, ok := want[b.endpoint]
		if !ok {
			continue
		}

		o := s.send(b.req(t))
		for _, w := range words {
			if len(o.readings) == 0 || !contains(o.readings[len(o.readings)-1], w) {
				t.Errorf("%s: Docker's reading doesn't have %s: %s", b.endpoint, w, o)
			}
		}

		delete(want, b.endpoint)
	}

	for e := range want {
		t.Errorf("%s: no base", e)
	}
}
