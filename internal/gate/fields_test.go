package gate

import (
	"flag"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite testdata/fields.txt from the decisions (never in CI: a change to it is a change of decisions, reviewed as one)")

// undecided lists what's wrong with a classification and those its fields hold: a field without a
// decision, a decision on no field, a refused list or map that doesn't say what [] asks, a struct a
// field holds that isn't classified (nor a leaf), and an interface left free.
func undecided(c *classification) []string {
	var problems []string

	seen := map[*classification]bool{}

	var check func(*classification)
	check = func(c *classification) {
		if seen[c] {
			return
		}

		seen[c] = true
		names := map[string]bool{}

		for _, f := range exported(c.of) {
			names[f.Name] = true
			d, ok := c.fields[f.Name]
			where := c.name + "." + f.Name + " (" + f.Type.String() + ")"

			switch {
			case !ok:
				problems = append(problems, where+": no decision (free, checked or refused)")

				continue
			case d.why == "":
				problems = append(problems, where+": a decision without its reason or rule")
			}

			kind := f.Type.Kind()
			list := kind == reflect.Slice || kind == reflect.Map

			switch {
			case d.class == isRefused && list && d.empty == 0:
				problems = append(problems, where+": a refused list or map must say whether [] asks for something")
			case d.empty != 0 && (d.class != isRefused || !list):
				problems = append(problems, where+": only a refused list or map says what [] asks")
			}

			held := heldType(f.Type)

			switch {
			case d.class == isRefused:
				if len(d.nested) > 0 {
					problems = append(problems, where+": a refused field holds nothing to decide on")
				}
			case held.Kind() == reflect.Interface:
				problems = append(problems, where+": an interface can hold anything: refused, or a struct type of its own")
			case held.Kind() == reflect.Struct && !slices.Contains(leaves, held):
				if len(d.nested) == 0 {
					problems = append(problems, where+": holds "+held.String()+", which isn't classified")
				}

				for _, n := range d.nested {
					if n.of != held {
						problems = append(problems, where+": holds "+held.String()+", classified as "+n.of.String())
					}

					check(n)
				}
			case len(d.nested) > 0:
				problems = append(problems, where+": holds no struct, but names a classification")
			}

			if kind == reflect.Map {
				if k := heldType(f.Type.Key()); k.Kind() == reflect.Struct && !slices.Contains(leaves, k) {
					problems = append(problems, where+": a map keyed by "+k.String()+", which isn't a leaf")
				}
			}
		}

		for name := range c.fields {
			if !names[name] {
				problems = append(problems, c.name+"."+name+": a decision on a field the type doesn't have")
			}
		}
	}

	check(c)

	return problems
}

// heldType is what a field of this type holds: through pointers, lists' elements and maps' values.
func heldType(t reflect.Type) reflect.Type {
	for {
		switch t.Kind() {
		case reflect.Pointer, reflect.Slice, reflect.Array, reflect.Map:
			t = t.Elem()
		default:
			return t
		}
	}
}

func TestEveryFieldIsDecidedOn(t *testing.T) {
	for _, b := range bodies {
		for _, p := range undecided(b.of) {
			t.Errorf("%s: %s", b.endpoint, p)
		}
	}
}

// The check fails on what a newer moby could bring: a field added, a list whose [] asks for
// something not saying so, a struct of a new type, an interface.
func TestTheFieldCheckFailsOnWhatANewDockerBrings(t *testing.T) {
	type nested struct{ A string }

	cases := map[string]struct {
		c    *classification
		want string
	}{
		"a field added": {
			decided("added", reflect.TypeFor[struct {
				Known string
				Added bool
			}](), freeAs("x", "Known")),
			"added.Added (bool): no decision",
		},
		"[] not decided on (as MaskedPaths' would be)": {
			decided("masked", reflect.TypeFor[struct{ MaskedPaths []string }](), refusedAs("x", "MaskedPaths")),
			"must say whether [] asks",
		},
		"a struct not classified": {
			decided("struct", reflect.TypeFor[struct{ N *nested }](), freeAs("x", "N")),
			"which isn't classified",
		},
		"an interface free": {
			decided("interface", reflect.TypeFor[struct{ I any }](), freeAs("x", "I")),
			"an interface can hold anything",
		},
		"a decision on a field that's gone": {
			decided("gone", reflect.TypeFor[struct{ Known string }](), freeAs("x", "Known", "Gone")),
			"gone.Gone: a decision on a field the type doesn't have",
		},
	}

	for name, tc := range cases {
		problems := undecided(tc.c)
		if !slices.ContainsFunc(problems, func(p string) bool { return strings.Contains(p, tc.want) }) {
			t.Errorf("%s: want a problem with %q, got %q", name, tc.want, problems)
		}
	}

	// And MaskedPaths' decision, removed from the real one, is missed by name
	masked := *hostConfigFields
	masked.fields = maps.Clone(hostConfigFields.fields)
	d := masked.fields["MaskedPaths"]
	d.empty = 0
	masked.fields["MaskedPaths"] = d

	if !slices.ContainsFunc(undecided(&masked), func(p string) bool { return strings.Contains(p, "HostConfig.MaskedPaths") }) {
		t.Error("MaskedPaths without what [] asks wasn't missed")
	}
}

// A non-nil pointer asks for something whatever it points to, and a [] of a list whose empty asks
// does too; one whose empty asks nothing doesn't.
func TestWhatIsSet(t *testing.T) {
	zero, no := int64(0), false
	c := decided("set", reflect.TypeFor[struct {
		Swappiness *int64
		OomKill    *bool
		Masked     []string
		Links      []string
	}](), refusedAs("x", "Swappiness", "OomKill"), refusedEvenEmpty("x", "Masked"), refusedLists("x", "Links"))

	got := unset(struct {
		Swappiness *int64
		OomKill    *bool
		Masked     []string
		Links      []string
	}{&zero, &no, []string{}, []string{}}, c)

	if want := []string{"Swappiness", "OomKill", "Masked"}; !slices.Equal(got, want) {
		t.Errorf("set: %q, want %q", got, want)
	}
}

// A field refused inside what a free field holds is refused through it.
func TestARefusedFieldIsRefusedThroughAFreeOne(t *testing.T) {
	type inner struct{ Fine, Not string }

	type outer struct{ In []*inner }

	in := decided("inner", reflect.TypeFor[inner](), freeAs("x", "Fine"), refusedAs("x", "Not"))
	c := decided("outer", reflect.TypeFor[outer](), holding(freeAs("x", "In"), in))

	if got := unset(outer{In: []*inner{{Fine: "a"}, {Not: "b"}}}, c); !slices.Equal(got, []string{"In.Not"}) {
		t.Errorf("got %q, want In.Not", got)
	}
}

// testdata/fields.txt is every field of every body, with its Go type and decision: a field whose
// type changes under the same name, which the decisions alone wouldn't show, changes it too.
func TestTheFieldsAreTheListedOnes(t *testing.T) {
	var b strings.Builder

	b.WriteString("# Every field of every body the gate reads, and its decision. Written by\n")
	b.WriteString("# go test ./internal/gate -run TestTheFieldsAreTheListedOnes -update; a change here is a change of decisions.\n")

	for _, f := range Fields() {
		empty := ""
		if f.EmptyAsks {
			empty = " ([] asks)"
		}

		fmt.Fprintf(&b, "%s %s %s [%s] %s%s: %s\n", f.Endpoint, f.Path, f.GoType, f.In, f.Class, empty, f.Why)
	}

	file := filepath.Join("testdata", "fields.txt")
	if *update {
		if err := os.WriteFile(file, []byte(b.String()), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	want, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}

	if got := b.String(); got != string(want) {
		gl, wl := strings.Split(got, "\n"), strings.Split(string(want), "\n")
		for _, l := range gl {
			if !slices.Contains(wl, l) {
				t.Errorf("not listed: %s", l)
			}
		}

		for _, l := range wl {
			if !slices.Contains(gl, l) {
				t.Errorf("listed, but not a field: %s", l)
			}
		}
	}
}
