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

				// Where the code is: refuse(status, code, where, allowed, …), add(code, where, allowed, …)
				first := 0

				switch {
				case name == "refuse" && len(n.Args) >= 2:
					arg, first = n.Args[1], 1
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

				saysWhereAndWhat(t, fset, n, name, n.Args[first:])

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

				// A refusal is built by refuse or a collector only: so it has its problems
				if typ.Name == "refusal" {
					t.Errorf("%s: a refusal built by hand, without its problems: use refuse", fset.Position(n.Pos()))
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

// saysWhereAndWhat holds a refusal site (its code, where, allowed) to saying both, explicitly: where
// by at(…) or nowhere, what's allowed by an allow…(…) constructor or nothingAllowed, never a
// variable that could hold anything; an authentication failure and an object that isn't the
// scope's say neither (problems_test.go's neverSay). A where passed through a helper's parameter
// (field, named, modeField) is checked where the helper is called.
func saysWhereAndWhat(t *testing.T, fset *gotoken.FileSet, call *ast.CallExpr, name string, args []ast.Expr) {
	t.Helper()

	if len(args) < 3 {
		t.Errorf("%s: %s(…) without where and allowed", fset.Position(call.Pos()), name)

		return
	}

	code, where, allowed := args[0], args[1], args[2]

	called := func(e ast.Expr) string {
		if c, ok := e.(*ast.CallExpr); ok {
			switch f := c.Fun.(type) {
			case *ast.Ident:
				return f.Name
			case *ast.SelectorExpr:
				return f.Sel.Name
			case *ast.IndexExpr: // a generic's, instantiated
				if id, ok := f.X.(*ast.Ident); ok {
					return id.Name
				}
			}
		}

		return ""
	}

	ident := func(e ast.Expr) string {
		if id, ok := e.(*ast.Ident); ok {
			return id.Name
		}

		return ""
	}

	switch w := ident(where); {
	case w == "nowhere", w == "field", w == "named", w == "modeField", called(where) == "at", called(where) == "field":
	default:
		t.Errorf("%s: %s(…)'s where isn't at(…) or nowhere", fset.Position(call.Pos()), name)
	}

	switch a := called(allowed); {
	case ident(allowed) == "nothingAllowed", strings.HasPrefix(a, "allow"), a == "joinable":
	default:
		t.Errorf("%s: %s(…)'s allowed isn't an allow…(…) or nothingAllowed", fset.Position(call.Pos()), name)
	}

	if c := ident(code); c == "CodeAuthRejected" || c == "CodeNotFound" {
		if ident(where) != "nowhere" || ident(allowed) != "nothingAllowed" {
			t.Errorf("%s: %s says where or what's allowed: it may say neither", fset.Position(call.Pos()), c)
		}
	}
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
