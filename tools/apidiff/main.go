// apidiff lists what changed in Docker's API between two versions of moby's api module, for each
// change what YorvoGate decided on it, and what it hasn't decided on (UNDECIDED, exit status 1):
//
//	go run ./tools/apidiff v1.55.0 v1.56.1
//	go run ./tools/apidiff -propose v1.55.0 v1.56.1   (and what to ask a model of each undecided row)
//
// It reads each version's swagger.yaml from Go's module cache (go mod download): the endpoints, their
// query parameters and headers, and the fields of every request body, by the paths the gate's
// decisions use (internal/gate/testdata/fields.txt). Docker's handlers read some parameters its
// swagger doesn't list; those are decided on by hand (internal/gate/endpoints.go).
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"github.com/yorvolabs/yorvogate/internal/gate"
	"github.com/yorvolabs/yorvogate/internal/route"
	yaml "go.yaml.in/yaml/v3"
)

func main() {
	propose := flag.Bool("propose", false, "add, for each undecided row, what to ask a model to propose (a maintainer decides)")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: go run ./tools/apidiff [-propose] <old> <new>   (versions of github.com/moby/moby/api, e.g. v1.55.0 v1.56.1)")
	}
	flag.Parse()

	if flag.NArg() != 2 {
		flag.Usage()
		os.Exit(2)
	}

	older, err := load(flag.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, "apidiff:", err)
		os.Exit(2)
	}

	newer, err := load(flag.Arg(1))
	if err != nil {
		fmt.Fprintln(os.Stderr, "apidiff:", err)
		os.Exit(2)
	}

	rows := diff(older, newer)
	write(os.Stdout, flag.Arg(0), flag.Arg(1), rows, *propose)

	if slices.ContainsFunc(rows, func(r row) bool { return r.open() }) {
		os.Exit(1)
	}
}

const undecided = "UNDECIDED"

// load reads a version's swagger.yaml from the module cache, downloading the module if need be.
func load(version string) (*spec, error) {
	out, err := exec.Command("go", "mod", "download", "-json", "github.com/moby/moby/api@"+version).Output()
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			err = fmt.Errorf("%w: %s", err, bytes.TrimSpace(exit.Stderr))
		}

		return nil, fmt.Errorf("github.com/moby/moby/api@%s: %w", version, err)
	}

	var module struct{ Dir string }
	if err := json.Unmarshal(out, &module); err != nil || module.Dir == "" {
		return nil, fmt.Errorf("github.com/moby/moby/api@%s: no module directory in %s", version, out)
	}

	raw, err := os.ReadFile(filepath.Join(module.Dir, "swagger.yaml"))
	if err != nil {
		return nil, err
	}

	return parse(raw)
}

// spec is what apidiff reads of a swagger.yaml.
type spec struct {
	Paths       map[string]map[string]operation
	Definitions map[string]*schema
}

type operation struct {
	Parameters []parameter
}

type parameter struct {
	Name, In, Type, Description string
	Schema                      *schema
}

type schema struct {
	Ref                  string `yaml:"$ref"`
	Type                 string
	Format               string
	Description          string
	AllOf                []*schema `yaml:"allOf"`
	Properties           map[string]*schema
	Items                *schema
	AdditionalProperties any `yaml:"additionalProperties"`
}

func parse(raw []byte) (*spec, error) {
	var s spec
	if err := yaml.Unmarshal(raw, &s); err != nil {
		return nil, err
	}

	if len(s.Paths) == 0 || len(s.Definitions) == 0 {
		return nil, errors.New("swagger.yaml: no paths or definitions")
	}

	return &s, nil
}

// bodyFields are the fields of a schema, resolved through $ref and allOf, depth first, by path
// (Docker's names; [] an element of a list, {} a value of a map), each with its type as swagger
// gives it.
func (s *spec) bodyFields(sc *schema, prefix string, seen []string, out map[string]string) {
	if sc == nil {
		return
	}

	if sc.Ref != "" {
		name := strings.TrimPrefix(sc.Ref, "#/definitions/")
		if slices.Contains(seen, name) {
			return
		}

		s.bodyFields(s.Definitions[name], prefix, append(seen, name), out)

		return
	}

	for _, part := range sc.AllOf {
		s.bodyFields(part, prefix, seen, out)
	}

	for name, p := range sc.Properties {
		path := prefix + name
		out[path] = s.typeOf(p)
		s.within(p, path, seen, out)
	}
}

// within walks what a property holds: an object's fields, a list's element's, a map's value's.
func (s *spec) within(p *schema, path string, seen []string, out map[string]string) {
	switch r := s.resolve(p); {
	case r == nil:
	case r.Type == "array":
		s.within(r.Items, path+"[]", seen, out)
	case len(r.Properties) > 0 || len(r.AllOf) > 0:
		s.bodyFields(p, path+".", seen, out)
	default:
		if v, ok := r.AdditionalProperties.(map[string]any); ok {
			raw, _ := yaml.Marshal(v)

			var value schema
			if yaml.Unmarshal(raw, &value) == nil {
				s.within(&value, path+"{}", seen, out)
			}
		}
	}
}

// resolve follows a $ref.
func (s *spec) resolve(p *schema) *schema {
	for p != nil && p.Ref != "" {
		p = s.Definitions[strings.TrimPrefix(p.Ref, "#/definitions/")]
	}

	return p
}

// typeOf is a property's type as a reader of the diff wants it: a definition's name, or swagger's
// type and format, a list's of its element's.
func (s *spec) typeOf(p *schema) string {
	switch {
	case p == nil:
		return "?"
	case p.Ref != "":
		return strings.TrimPrefix(p.Ref, "#/definitions/")
	case p.Type == "array":
		return "[]" + s.typeOf(p.Items)
	case p.Format != "":
		return p.Type + " (" + p.Format + ")"
	case p.Type == "" && len(p.AllOf) > 0:
		return "object"
	}

	if v, ok := p.AdditionalProperties.(map[string]any); ok {
		t, _ := v["type"].(string)

		return "map of " + t
	}

	return p.Type
}

// row is one change, and what YorvoGate decided on what it changes.
type row struct {
	kind, endpoint, where, change, decision, description string
}

// open tells whether YorvoGate hasn't decided on it.
func (r row) open() bool { return strings.HasPrefix(r.decision, undecided) }

// endpointOf names an operation by the gate's route table: "" for one YorvoGate doesn't route.
func endpointOf(method, path string) string {
	for _, e := range route.Endpoints() {
		if e.Method == strings.ToUpper(method) && strings.ReplaceAll(e.Pattern, "{name*}", "{name}") == path {
			return e.Name
		}
	}

	return ""
}

func diff(older, newer *spec) []row {
	var rows []row

	scopes := gate.ScopeEndpoints()
	fields := gate.Fields()

	for _, path := range union(keys(older.Paths), keys(newer.Paths)) {
		for _, method := range union(keys(older.Paths[path]), keys(newer.Paths[path])) {
			was, had := older.Paths[path][method]
			is, has := newer.Paths[path][method]
			name := endpointOf(method, path)
			where := strings.ToUpper(method) + " " + path
			forScopes := slices.Contains(scopes, name)

			switch {
			case !had:
				d := undecided + ": a new endpoint, refused until it's routed (internal/route)"
				switch {
				case forScopes:
					d = "routed as " + name + ", allowed for scopes: review its rule"
				case name != "":
					d = "routed as " + name + ", refused for scopes"
				}

				rows = append(rows, row{"endpoint", name, where, "added", d, ""})

				continue
			case !has:
				rows = append(rows, row{"endpoint", name, where, "removed", "routed as " + orNone(name), ""})

				continue
			}

			rows = append(rows, parameters(name, where, forScopes, was, is)...)

			if forScopes {
				rows = append(rows, bodies(name, where, older, newer, was, is, fields)...)
			}
		}
	}

	return rows
}

func parameters(name, where string, forScopes bool, was, is operation) []row {
	var rows []row

	old := map[string]parameter{}
	for _, p := range was.Parameters {
		if p.In != "body" {
			old[p.In+" "+p.Name] = p
		}
	}

	for _, p := range is.Parameters {
		if p.In == "body" {
			continue
		}

		key := p.In + " " + p.Name
		o, existed := old[key]
		delete(old, key)

		decision := "not for scopes"
		if forScopes {
			decision = paramDecision(name, p)
		}

		switch {
		case !existed:
			rows = append(rows, row{p.In, name, where + " " + p.Name, "added", decision, p.Description})
		case o.Type != p.Type:
			rows = append(rows, row{p.In, name, where + " " + p.Name, "type " + o.Type + " → " + p.Type, decision, p.Description})
		case o.Description != p.Description:
			rows = append(rows, row{p.In, name, where + " " + p.Name, "description changed", decision, p.Description})
		}
	}

	for _, key := range keys(old) {
		p := old[key]
		rows = append(rows, row{p.In, name, where + " " + p.Name, "removed", "", ""})
	}

	return rows
}

func paramDecision(endpoint string, p parameter) string {
	switch p.In {
	case "query":
		if d := gate.ParameterDecision(endpoint, p.Name); d != "" {
			return d
		}

		return undecided
	case "header":
		if gate.HeaderForwarded(endpoint, p.Name) {
			return "forwarded"
		}

		return "not forwarded"
	}

	return "in the path"
}

func bodies(name, where string, older, newer *spec, was, is operation, fields []gate.Field) []row {
	before, after := map[string]string{}, map[string]string{}

	for _, p := range was.Parameters {
		if p.In == "body" {
			older.bodyFields(p.Schema, "", nil, before)
		}
	}

	for _, p := range is.Parameters {
		if p.In == "body" {
			newer.bodyFields(p.Schema, "", nil, after)
		}
	}

	var rows []row

	for _, path := range union(keys(before), keys(after)) {
		b, had := before[path]
		a, has := after[path]

		switch {
		case !had:
			rows = append(rows, row{"body", name, where + " " + path, "added (" + a + ")", fieldDecision(name, path, fields), ""})
		case !has:
			rows = append(rows, row{"body", name, where + " " + path, "removed", fieldDecision(name, path, fields), ""})
		case a != b:
			rows = append(rows, row{"body", name, where + " " + path, "type " + b + " → " + a, fieldDecision(name, path, fields), ""})
		}
	}

	return rows
}

// fieldDecision is the gate's decision on a body field, or on the refused field it's under.
func fieldDecision(endpoint, path string, fields []gate.Field) string {
	var found []string

	for _, f := range fields {
		if f.Endpoint != endpoint {
			continue
		}

		switch {
		case f.Path == path:
			found = append(found, f.Class+" ["+f.In+"]")
		case f.Class == "refused" && strings.HasPrefix(path, f.Path) && strings.ContainsAny(path[len(f.Path):len(f.Path)+1], ".[{"):
			return "refused, under " + f.Path
		}
	}

	if len(found) == 0 {
		return undecided
	}

	return strings.Join(found, ", ")
}

func write(w io.Writer, older, newer string, rows []row, propose bool) {
	fmt.Fprintf(w, "# Docker's API, %s → %s\n\n", older, newer)

	if len(rows) == 0 {
		fmt.Fprintln(w, "No change.")

		return
	}

	fmt.Fprintln(w, "| Kind | Where | Change | YorvoGate | Decision |")
	fmt.Fprintln(w, "|---|---|---|---|---|")

	for _, r := range rows {
		fmt.Fprintf(w, "| %s | `%s` | %s | %s | |\n", r.kind, r.where, r.change, r.decision)
	}

	var open []row

	for _, r := range rows {
		if r.open() {
			open = append(open, r)
		}
	}

	fmt.Fprintf(w, "\n%d changes, %d undecided.\n", len(rows), len(open))

	if !propose || len(open) == 0 {
		return
	}

	fmt.Fprintln(w, "\n## For a model to propose (a maintainer decides each, and writes the reason in the code)")
	fmt.Fprintln(w, "\nYorvoGate gates Docker's API for scopes: tenants who must not gain power over the host or each other. For each row, propose free (no power over the host or another scope: a setting of the scope's own object), checked (allowed only with a rule: name what it must refuse), or refused (with why), and your reasoning. Say when you aren't sure.")

	for _, r := range open {
		fmt.Fprintf(w, "\n- `%s` (%s, %s)", r.where, r.kind, r.change)

		if r.description != "" {
			fmt.Fprintf(w, ": %s", strings.Join(strings.Fields(r.description), " "))
		}
	}

	fmt.Fprintln(w)
}

func keys[M ~map[string]V, V any](m M) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}

	slices.Sort(ks)

	return ks
}

func union(a, b []string) []string {
	return slices.Compact(slices.Sorted(slices.Values(append(append([]string(nil), a...), b...))))
}

func orNone(name string) string {
	if name == "" {
		return "nothing"
	}

	return name
}
