package gate

import (
	"go/ast"
	"go/parser"
	gotoken "go/token"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// codeConsts are the Code constants reasons.go declares, by name.
func codeConsts(t *testing.T) map[string]Code {
	t.Helper()
	f, err := parser.ParseFile(gotoken.NewFileSet(), "reasons.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}

	consts := map[string]Code{}
	for _, d := range f.Decls {
		g, ok := d.(*ast.GenDecl)
		if !ok || g.Tok != gotoken.CONST {
			continue
		}

		for _, spec := range g.Specs {
			v := spec.(*ast.ValueSpec)
			for i, n := range v.Names {
				if lit, ok := v.Values[i].(*ast.BasicLit); ok {
					consts[n.Name] = Code(strings.Trim(lit.Value, `"`))
				}
			}
		}
	}

	return consts
}

// Every refusal says a reason code from reasons.go's list, by its constant: refuse's code, each
// collected problem's (add), and a refusal or bound built by hand. No literal, no variable, so the
// list is every code there is. Every code is used. An authentication failure's only code is
// auth.rejected (its cause is logged, never answered: threat model point 5).
func TestEveryRefusalHasACodeOfTheList(t *testing.T) {
	consts := codeConsts(t)
	if len(consts) != len(Codes) {
		t.Errorf("%d codes declared, %d described in Codes", len(consts), len(Codes))
	}

	for name, code := range consts {
		if _, ok := Codes[code]; !ok {
			t.Errorf("%s (%s) has no meaning in Codes", name, code)
		}

		if strings.HasPrefix(string(code), "auth.") && code != CodeAuthRejected {
			t.Errorf("%s is %s: an authentication failure's only code is %s", name, code, CodeAuthRejected)
		}
	}

	files, _ := filepath.Glob("*.go")
	fset := gotoken.NewFileSet()
	used := map[string]bool{}
	sites := 0

	isCode := func(e ast.Expr) (string, bool) {
		switch e := e.(type) {
		case *ast.Ident:
			_, ok := consts[e.Name]

			return e.Name, ok
		case *ast.SelectorExpr: // bound.code, codeOf(...) aren't selectors; a field is a refusal's own
			return "", false
		}

		return "", false
	}

	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") || file == "reasons.go" {
			continue
		}

		f, err := parser.ParseFile(fset, file, nil, 0)
		if err != nil {
			t.Fatal(err)
		}

		ast.Inspect(f, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.Ident:
				if _, ok := consts[n.Name]; ok {
					used[n.Name] = true
				}
			case *ast.CallExpr:
				name := ""
				switch fn := n.Fun.(type) {
				case *ast.Ident:
					name = fn.Name
				case *ast.SelectorExpr:
					// A collected problem by its collector (found.add); another add is another
					// thing's (an archive's contents)
					if recv, ok := fn.X.(*ast.Ident); ok && (fn.Sel.Name != "add" || recv.Name == "found") {
						name = fn.Sel.Name
					}
				}

				var arg ast.Expr

				switch {
				case name == "refuse" && len(n.Args) >= 2:
					arg = n.Args[1]
				case (name == "add") && len(n.Args) >= 2:
					// A collected problem's code. Two adds take a string first: taken.go's own (kind,
					// name, labels), and a builder's problems (builders.go), which are all one code
					// (policy.builder), given where they're refused.
					if lit, ok := n.Args[0].(*ast.BasicLit); ok && lit.Kind == gotoken.STRING && (file == "taken.go" || file == "builders.go") {
						return true
					}

					arg = n.Args[0]
				default:
					return true
				}

				sites++

				if _, ok := isCode(arg); ok {
					return true
				}

				// The only other forms: the code a bound or refusal already has
				if sel, ok := arg.(*ast.SelectorExpr); ok && sel.Sel.Name == "code" {
					return true
				}

				if call, ok := arg.(*ast.CallExpr); ok {
					if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "codeOf" && len(call.Args) == 2 {
						if _, ok := isCode(call.Args[1]); ok {
							return true
						}
					}
				}

				t.Errorf("%s: %s(…) without a code of reasons.go's list", fset.Position(n.Pos()), name)
			case *ast.FuncDecl:
				// refuse builds the refusal from the code it's given (checked at its call)
				if n.Name.Name == "refuse" {
					return false
				}
			case *ast.CompositeLit:
				typ, ok := n.Type.(*ast.Ident)
				if !ok || (typ.Name != "refusal" && typ.Name != "boundError") {
					return true
				}

				sites++

				coded := false
				for i, e := range n.Elts {
					if kv, ok := e.(*ast.KeyValueExpr); ok {
						if k, ok := kv.Key.(*ast.Ident); ok && k.Name == "code" {
							_, coded = isCode(kv.Value)
						}
					} else if i == 0 && typ.Name == "boundError" {
						_, coded = isCode(e)
					}
				}

				if !coded {
					t.Errorf("%s: a %s without a code of reasons.go's list", fset.Position(n.Pos()), typ.Name)
				}
			}

			return true
		})
	}

	for name := range consts {
		if !used[name] {
			t.Errorf("%s is used by no refusal", name)
		}
	}

	if sites < 150 {
		t.Errorf("only %d refusal sites found: the test no longer sees them", sites)
	}

	t.Logf("%d refusal sites, %d codes", sites, len(consts))
}

// The configuration docs list every code with its meaning, as Codes has them.
func TestTheReasonCodesAreDocumented(t *testing.T) {
	doc, err := os.ReadFile("../../docs/configuration.md")
	if err != nil {
		t.Fatal(err)
	}

	row := regexp.MustCompile("(?m)^\\| `([a-z.-]+)` \\| (.+) \\|$")
	start := strings.Index(string(doc), "## Reason codes")
	if start < 0 {
		t.Fatal("no Reason codes section")
	}

	section := string(doc)[start:]
	if end := strings.Index(section[3:], "\n## "); end >= 0 {
		section = section[:end+3]
	}

	documented := map[Code]string{}
	for _, m := range row.FindAllStringSubmatch(section, -1) {
		documented[Code(m[1])] = m[2]
	}

	for code, meaning := range Codes {
		if documented[code] != meaning {
			t.Errorf("%s: documented %q, want %q", code, documented[code], meaning)
		}
	}

	for code := range documented {
		if _, ok := Codes[code]; !ok {
			t.Errorf("%s is documented but isn't a code", code)
		}
	}

	order := make([]string, 0, len(documented))
	for _, m := range row.FindAllStringSubmatch(section, -1) {
		order = append(order, m[1])
	}

	if !slices.IsSorted(order) {
		t.Error("the table isn't in the codes' order")
	}
}
