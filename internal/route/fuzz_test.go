package route

import (
	"strings"
	"testing"
)

// FuzzParse: whatever path comes, an accepted one is canonical, has a known version (or is /_ping),
// and maps to the same endpoint when parsed again.
func FuzzParse(f *testing.F) {
	for _, seed := range [][2]string{
		{"GET", "/_ping"}, {"GET", "/v1.56/containers/json"}, {"POST", "/v1.56/containers/create"},
		{"GET", "/v1.56/images/quire-sites/jane/php-prod/json"}, {"DELETE", "/v1.56/images/a/b:c@sha256:x"},
		{"GET", "/v1.56/containers/../json"}, {"GET", "/v1.56//json"}, {"GET", "/v1.56/containers%2Fjson"},
		{"POST", "/v1.56/exec/x/start"}, {"GET", "/v1.57/version"}, {"GET", "/version"},
	} {
		f.Add(seed[0], seed[1])
	}

	f.Fuzz(func(t *testing.T, method, path string) {
		req, err := Parse(method, path, Version{1, 44}, Version{1, 56})
		if err != nil {
			return
		}

		if req.Endpoint == nil || req.Endpoint.Method != method {
			t.Fatalf("%s %s: endpoint %v", method, path, req.Endpoint)
		}

		if strings.ContainsAny(path, "%\\ ") || strings.Contains(path, "//") || strings.HasSuffix(path, "/") {
			t.Fatalf("%q accepted though not canonical", path)
		}

		for _, s := range strings.Split(path, "/")[1:] {
			if s == "." || s == ".." {
				t.Fatalf("%q accepted with a dot segment", path)
			}
		}

		if req.Version == nil {
			if req.Path != "/_ping" {
				t.Fatalf("%q accepted without a version", path)
			}

			return
		}

		if req.Version.Less(Version{1, 44}) || (Version{1, 56}).Less(*req.Version) {
			t.Fatalf("%q accepted with version %s", path, req.Version)
		}

		again, err := Parse(method, "/v"+req.Version.String()+req.Path, Version{1, 44}, Version{1, 56})
		if err != nil || again.Endpoint.Name != req.Endpoint.Name {
			t.Fatalf("%q: parsed again, %v %v", path, again.Endpoint, err)
		}
	})
}
