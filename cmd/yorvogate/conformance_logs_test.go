package main

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// The gate's log from a conformance run (YGC_LOGS: the folder run.sh fills) is the log schema's,
// line by line, and its refusals carry the codes the suites' attacks call for. Skipped outside the
// conformance job.
func TestConformanceLogs(t *testing.T) {
	dir := os.Getenv("YGC_LOGS")
	if dir == "" {
		t.Skip("YGC_LOGS isn't set: run after test/conformance/run.sh")
	}

	schema, err := jsonschema.NewCompiler().Compile("../../schemas/yorvogate-log.v1.schema.json")
	if err != nil {
		t.Fatal(err)
	}

	files, _ := filepath.Glob(filepath.Join(dir, "*.log"))
	if len(files) < 6 {
		t.Fatalf("%d logs in %s: the suites didn't keep theirs", len(files), dir)
	}

	codes := map[string]bool{}

	for _, file := range files {
		f, err := os.Open(file)
		if err != nil {
			t.Fatal(err)
		}

		lines := bufio.NewScanner(f)
		lines.Buffer(make([]byte, 1<<20), 1<<20)

		for n := 1; lines.Scan(); n++ {
			doc, err := jsonschema.UnmarshalJSON(strings.NewReader(lines.Text()))
			if err == nil {
				err = schema.Validate(doc)
			}

			if err != nil {
				t.Errorf("%s:%d: %v\n%s", filepath.Base(file), n, err, lines.Text())

				continue
			}

			var line struct{ Msg, Code string }
			_ = json.Unmarshal(lines.Bytes(), &line)

			if line.Msg == "refused" {
				codes[line.Code] = true
			}
		}

		_ = f.Close()
	}

	// One sample per area the suites attack: a host path, a capability, another scope's object, a
	// credential that isn't the scope's, a field a scope may not set
	for _, want := range []string{"policy.host-access", "policy.capability", "scope.not-found", "auth.rejected", "body.field-not-allowed"} {
		if !codes[want] {
			t.Errorf("no refusal with code %s in the conformance logs (codes seen: %v)", want, codes)
		}
	}
}
