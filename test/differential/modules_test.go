package differential

import (
	"os/exec"
	"strings"
	"testing"
)

// The gate under test is the gate that ships: every module that gives a package to YorvoGate's
// binary or its internal packages (the code this suite builds; their own tests don't build here) is
// the same version here as in YorvoGate's own module. (This module also needs moby's daemon, and Go takes the highest version
// any of its requirements asks for: a newer one here would build the gate on other code.) A
// difference is fixed by bumping YorvoGate's go.mod deliberately, in its own commit, or by pinning
// this module down; never by letting the two drift.
func TestTheGateIsBuiltAsItShips(t *testing.T) {
	list := func(dir string, args ...string) string {
		cmd := exec.Command("go", args...)
		cmd.Dir = dir

		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("go %s in %s: %v", strings.Join(args, " "), dir, err)
		}

		return string(out)
	}

	shipped := map[string]string{}
	// The code built: a module's version, or what a replace puts in its place
	effective := "{{with .Replace}}{{.Path}}@{{.Version}}{{else}}{{.Version}}{{end}}"
	format := "{{with .Module}}{{if not .Main}}{{.Path}} " + effective + "{{end}}{{end}}"

	for _, line := range strings.Split(list("../..", "list", "-deps", "-f", format, "./cmd/yorvogate", "./internal/..."), "\n") {
		if path, version, ok := strings.Cut(line, " "); ok {
			shipped[path] = version
		}
	}

	if len(shipped) == 0 {
		t.Fatal("no module found in YorvoGate's builds")
	}

	for path, version := range shipped {
		here := strings.TrimSpace(list(".", "list", "-m", "-f", effective, path))
		if here != version {
			t.Errorf("%s: %s in YorvoGate's module, %s here", path, version, here)
		}
	}
}
