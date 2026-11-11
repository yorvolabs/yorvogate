package differential

import (
	"strings"
	"testing"
)

// Named cases: Docker 29.9.2's own reading of a request (recorded straight, past the gate) that a
// gate reading differently would let through, and the gate's refusal of it. A moby bump that
// changes one of these readings fails here by name.
func TestDockersReadingsTheGateMustNotMiss(t *testing.T) {
	s := newSuite(t)

	for _, c := range []struct {
		name string
		req  request
		// What Docker 29.9.2 does with it, as its code (mux, httputils, encoding/json) reads it
		docker kind
	}{
		// gorilla/mux matches the decoded path: Docker serves containers%2Fcreate as containers/create
		{"an encoded / in the path", asJane("POST", "/v1.56/containers%2Fcreate?name=jane-web-1", "application/json", []byte(janeContainer)), read},
		// The version middleware takes [0-9.]+ and compares versions numerically: v01.56 is 1.56
		{"a version written v01.56", asJane("POST", "/v01.56/containers/create?name=jane-web-1", "application/json", []byte(janeContainer)), read},
		// encoding/json matches keys case-insensitively, the last of two winning: privileged
		{"privileged, lower case and last", asJane("POST", "/v1.56/containers/create?name=jane-web-1", "application/json",
			[]byte(`{"Image":"alpine:3.22",`+own+`,"HostConfig":{"NetworkMode":"jane_default","CapDrop":["ALL"],"SecurityOpt":["no-new-privileges"],"Privileged":false,"privileged":true}}`)), read},
		// ParseForm puts a form body's values before the query's (C-1): Docker pulls blog's
		{"a form body's fromImage", asJane("POST", "/v1.56/images/create?fromImage=quire-sites/jane/app&tag=1", "application/x-www-form-urlencoded",
			[]byte("fromImage=quire-sites/blog/app&tag=1")), read},
	} {
		if got := s.direct(c.req); got.kind != c.docker {
			t.Errorf("%s: Docker no longer reads it so: %s", c.name, got)
		}

		if got := s.send(c.req); got.kind != refusedByGate {
			t.Errorf("%s: not refused by the gate: %s", c.name, got)
		}
	}

	// What Docker read of the last two is what the gate must never let through
	privileged := s.direct(asJane("POST", "/v1.56/containers/create?name=jane-web-1", "application/json",
		[]byte(`{"Image":"alpine:3.22","HostConfig":{"Privileged":false,"privileged":true}}`)))
	if len(privileged.readings) != 1 || !contains(privileged.readings[0], `"Privileged":true`) {
		t.Errorf("Docker's reading of a lower-case privileged last: %s", privileged)
	}
}

func contains(r reading, s string) bool {
	for _, a := range r.Args {
		if strings.Contains(string(a), s) {
			return true
		}
	}

	return false
}
