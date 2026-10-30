package route

import (
	"errors"
	"strings"
	"testing"
)

var lowest, highest = Version{1, 44}, Version{1, 56}

func TestEndpointsAreFound(t *testing.T) {
	cases := []struct {
		method, path, endpoint string
		params                 map[string]string
	}{
		{"GET", "/_ping", "system.ping", nil},
		{"HEAD", "/v1.56/_ping", "system.ping", nil},
		{"GET", "/v1.44/version", "system.version", nil},
		{"GET", "/v1.56/containers/json", "container.list", nil},
		{"POST", "/v1.56/containers/create", "container.create", nil},
		{"GET", "/v1.56/containers/jane-php-1/json", "container.inspect", map[string]string{"id": "jane-php-1"}},
		{"POST", "/v1.56/containers/abc/exec", "exec.create", map[string]string{"id": "abc"}},
		{"POST", "/v1.56/exec/abc/start", "exec.start", map[string]string{"id": "abc"}},
		{"GET", "/v1.56/images/json", "image.list", nil},
		{"GET", "/v1.56/images/get", "image.save-many", nil},
		{"GET", "/v1.56/images/quire-sites/jane/php-prod/json", "image.inspect", map[string]string{"name": "quire-sites/jane/php-prod"}},
		{"GET", "/v1.56/images/json/json", "image.inspect", map[string]string{"name": "json"}},
		{"POST", "/v1.56/images/ghcr.io/quirecms/server@sha256:4444/tag", "image.tag", map[string]string{"name": "ghcr.io/quirecms/server@sha256:4444"}},
		{"DELETE", "/v1.56/images/quire-sites/jane/php-prod:before-update", "image.delete", map[string]string{"name": "quire-sites/jane/php-prod:before-update"}},
		{"GET", "/v1.56/networks", "network.list", nil},
		{"POST", "/v1.56/networks/create", "network.create", nil},
		{"POST", "/v1.56/networks/jane_default/connect", "network.connect", map[string]string{"id": "jane_default"}},
		{"PUT", "/v1.56/containers/abc/archive", "container.archive-put", map[string]string{"id": "abc"}},
		{"POST", "/v1.56/grpc", "session.grpc", nil},
	}

	for _, c := range cases {
		req, err := Parse(c.method, c.path, lowest, highest)
		if err != nil {
			t.Errorf("%s %s: %v", c.method, c.path, err)

			continue
		}

		if req.Endpoint.Name != c.endpoint {
			t.Errorf("%s %s: %s, want %s", c.method, c.path, req.Endpoint.Name, c.endpoint)
		}

		for k, v := range c.params {
			if req.Params[k] != v {
				t.Errorf("%s %s: %s = %q, want %q", c.method, c.path, k, req.Params[k], v)
			}
		}
	}
}

// Paths two parsers could read differently, and versions YorvoGate doesn't know, are refused.
func TestPathsThatArentCanonicalAreRefused(t *testing.T) {
	for _, path := range []string{
		"/v1.56/containers/../images/json",
		"/v1.56/containers/./json",
		"/v1.56//containers/json",
		"/v1.56/containers/json/",
		"/v1.56/containers%2Fjson",
		"/v1.56/containers/a%2e%2e/json",
		"/v1.56/containers/a\\b/json",
		"/v1.56/containers/a b/json",
		"/v1.56/containers/a\x00b/json",
		"containers/json",
		"/",
		"",
	} {
		if _, err := Parse("GET", path, lowest, highest); err == nil {
			t.Errorf("%q: accepted", path)
		}
	}
}

func TestVersionsOutsideTheRangeAreRefused(t *testing.T) {
	for _, path := range []string{"/v1.57/containers/json", "/v1.43/containers/json", "/v2.0/containers/json", "/v1.056/containers/json", "/v01.56/containers/json"} {
		if _, err := Parse("GET", path, lowest, highest); err == nil {
			t.Errorf("%q: accepted", path)
		}
	}
}

func TestOnlyPingWorksWithoutAVersion(t *testing.T) {
	_, err := Parse("GET", "/containers/json", lowest, highest)
	if err == nil || !strings.Contains(err.Error(), "version is missing") {
		t.Fatalf("an unversioned path: %v", err)
	}
}

func TestUnknownEndpointsAreRefused(t *testing.T) {
	for _, c := range [][2]string{
		{"GET", "/v1.56/containers/abc/some-new-endpoint"},
		{"PATCH", "/v1.56/containers/abc/json"},
		{"POST", "/v1.56/containers/json"},
		{"GET", "/v1.56/images"},
		{"DELETE", "/v1.56/networks"},
	} {
		if _, err := Parse(c[0], c[1], lowest, highest); !errors.Is(err, ErrUnknown) {
			t.Errorf("%s %s: %v", c[0], c[1], err)
		}
	}
}

func TestEveryEndpointIsReachableAndInAGroup(t *testing.T) {
	groups := map[Group]bool{}
	for _, g := range Groups {
		groups[g] = true
	}

	for _, e := range Endpoints() {
		if !groups[e.Group] {
			t.Errorf("%s: group %q isn't listed", e.Name, e.Group)
		}

		path := "/v1.56" + strings.NewReplacer("{id}", "x", "{name}", "x", "{name*}", "x/y").Replace(e.Pattern)
		req, err := Parse(e.Method, path, lowest, highest)
		if err != nil || req.Endpoint.Name != e.Name {
			t.Errorf("%s %s: shadowed or unreachable (%v)", e.Method, e.Pattern, err)
		}
	}
}

func TestVersions(t *testing.T) {
	v, err := ParseVersion("1.56")
	if err != nil || v != (Version{1, 56}) || v.String() != "1.56" {
		t.Fatalf("1.56: %v %v", v, err)
	}

	if !(Version{1, 9}).Less(Version{1, 10}) || (Version{1, 10}).Less(Version{1, 9}) || (Version{2, 0}).Less(Version{1, 99}) {
		t.Fatal("ordering")
	}

	for _, s := range []string{"1", "1.", ".5", "a.b", "1.5.6", "-1.5", "1.-5", "+1.5"} {
		if _, err := ParseVersion(s); err == nil {
			t.Errorf("%q: accepted", s)
		}
	}
}
