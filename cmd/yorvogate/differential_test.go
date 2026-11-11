package main

import (
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The differential suite (test/differential) is a module of its own, with moby's daemon in it:
// nothing of YorvoGate's may import it, or the daemon would come into YorvoGate's build.
func TestNothingImportsTheDifferentialSuite(t *testing.T) {
	const suite = "github.com/yorvolabs/yorvogate/test/differential"

	err := filepath.WalkDir("../..", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() && (d.Name() == ".git" || filepath.ToSlash(path) == "../../test/differential") {
			return filepath.SkipDir
		}

		if d.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}

		f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}

		for _, imp := range f.Imports {
			if p, _ := strconv.Unquote(imp.Path.Value); p == suite || strings.HasPrefix(p, suite+"/") {
				t.Errorf("%s imports %s", path, p)
			}
		}

		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
