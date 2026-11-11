package main

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/yorvolabs/yorvogate/internal/gate"
)

var update = flag.Bool("update", false, "rewrite testdata from apidiff's output")

func versions(t *testing.T) (*spec, *spec) {
	t.Helper()

	older, err := load("v1.55.0")
	if err != nil {
		t.Skipf("the moby api module isn't at hand: %v", err)
	}

	newer, err := load("v1.56.1")
	if err != nil {
		t.Skipf("the moby api module isn't at hand: %v", err)
	}

	return older, newer
}

// 1.55 → 1.56 is what moby's api CHANGELOG says (HostConfig.Umask; an annotation filter for
// GET /containers/json), and the descriptions its swagger reworded.
func TestFrom155To156(t *testing.T) {
	older, newer := versions(t)

	var out bytes.Buffer
	write(&out, "v1.55.0", "v1.56.1", diff(older, newer), true)

	file := filepath.Join("testdata", "v1.55.0-v1.56.1.md")
	if *update {
		if err := os.WriteFile(file, out.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	want, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}

	if out.String() != string(want) {
		t.Errorf("got:\n%s\nwant:\n%s", out.String(), want)
	}

	for _, line := range []string{
		"| body | `POST /containers/create HostConfig.Umask` | added (integer (uint32)) | free [HostConfig] | |",
		"| query | `GET /containers/json filters` | description changed | checked | |",
	} {
		if !strings.Contains(out.String(), line) {
			t.Errorf("no %s", line)
		}
	}
}

// What a newer Docker could add, which the gate hasn't decided on: a field of a body a scope sends,
// a parameter of an endpoint it may use, an endpoint. Each is UNDECIDED.
func TestWhatIsntDecidedOnIsSaid(t *testing.T) {
	_, base := versions(t)

	newer, err := load("v1.56.1")
	if err != nil {
		t.Fatal(err)
	}

	newer.Definitions["HostConfig"].AllOf[1].Properties["Hypervisor"] = &schema{Type: "string"}
	newer.Definitions["Mount"].Properties["Remote"] = &schema{Type: "boolean"}

	op := newer.Paths["/containers/create"]["post"]
	op.Parameters = append(op.Parameters, parameter{Name: "privileged", In: "query", Type: "boolean"})
	newer.Paths["/containers/create"]["post"] = op
	newer.Paths["/containers/{id}/snapshot"] = map[string]operation{"post": {}}

	rows := diff(base, newer)

	for _, where := range []string{
		"POST /containers/create HostConfig.Hypervisor",
		"POST /containers/create HostConfig.Mounts[].Remote",
		"POST /containers/create privileged",
		"POST /containers/{id}/snapshot",
	} {
		i := slices.IndexFunc(rows, func(r row) bool { return r.where == where })
		if i < 0 || !strings.HasPrefix(rows[i].decision, undecided) {
			t.Errorf("%s: want it UNDECIDED, got %+v", where, rows)
		}
	}

	// -propose asks of each, for a maintainer to decide
	var out bytes.Buffer
	write(&out, "old", "new", rows, true)

	if s := out.String(); !strings.Contains(s, "## For a model to propose") || !strings.Contains(s, "- `POST /containers/create HostConfig.Mounts[].Remote` (body, added (boolean))") || !strings.Contains(s, "4 undecided") {
		t.Errorf("-propose:\n%s", s)
	}

	// A field added under one that's refused is refused with it
	newer.Definitions["HostConfig"].AllOf[1].Properties["Hypervisor"] = nil
	delete(newer.Definitions["HostConfig"].AllOf[1].Properties, "Hypervisor")
	newer.Definitions["ClusterVolumeSpec"].Properties["Encrypted"] = &schema{Type: "boolean"}

	rows = diff(base, newer)
	if i := slices.IndexFunc(rows, func(r row) bool { return r.where == "POST /volumes/create ClusterVolumeSpec.Encrypted" }); i < 0 || rows[i].decision != "refused, under ClusterVolumeSpec" {
		t.Errorf("a field under a refused one: %+v", rows)
	}
}

// apidiff reads bodies from swagger, the gate from moby's Go types (one walker each, C4): at the
// version the gate is built on, they name the same fields, but for those listed with why.
func TestTheToolReadsBodiesAsTheGateDoes(t *testing.T) {
	_, newer := versions(t)

	known := map[string]string{
		"container.update Init":                               "swagger's Resources has it, moby's UpdateConfig doesn't: the gate refuses it as an unknown field",
		"container.create HostConfig.Mounts[].ClusterOptions": "in moby's Mount, not in swagger's: refused",
	}

	gatePaths := map[string]bool{}
	endpoints := map[string]bool{}

	for _, f := range gate.Fields() {
		gatePaths[f.Endpoint+" "+f.Path] = true
		endpoints[f.Endpoint] = true
	}

	swagger := map[string]bool{}

	for path, ops := range newer.Paths {
		for method, op := range ops {
			e := endpointOf(method, path)
			if !endpoints[e] {
				continue
			}

			fields := map[string]string{}

			for _, p := range op.Parameters {
				if p.In == "body" {
					newer.bodyFields(p.Schema, "", nil, fields)
				}
			}

			for p := range fields {
				swagger[e+" "+p] = true

				if _, ok := known[e+" "+p]; !gatePaths[e+" "+p] && !ok && !strings.HasPrefix(fieldDecision(e, p, gate.Fields()), "refused, under") {
					t.Errorf("%s %s: in swagger, not among the gate's fields", e, p)
				}
			}
		}
	}

	for p := range gatePaths {
		if _, ok := known[p]; !swagger[p] && !ok {
			t.Errorf("%s: among the gate's fields, not in swagger", p)
		}
	}
}
