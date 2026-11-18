package gate

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/yorvolabs/yorvogate/internal/config"
)

// What another owner made under a scope's prefixes before its file was valid (a nested sibling's
// names, taken by the scope whose prefix is shorter) is listed for the operator in the scope's
// status, with whose it is.
func TestScopeStatusListsTakenNames(t *testing.T) {
	trusted, _, sites, _ := statusGate(t)

	sum := writeAtomically(t, sites, "jane", janeFile("one"))
	code, a := status(t, trusted, "/_yorvogate/v1/scopes/jane?listener=sites&sha256="+sum)
	if code != http.StatusOK || a.State != "loaded" {
		t.Fatalf("%d %+v", code, a)
	}

	// The fake Docker's volume jane_stolen, under jane's prefix jane_, carries blog's label
	want := Taken{Kind: "volume", Name: "jane_stolen", Owner: "com.docker.compose.project=blog"}
	if !slices.Contains(a.Taken, want) {
		t.Errorf("taken: %+v, want %+v among them", a.Taken, want)
	}

	// jane's own (jane-php-1, jane_data) and its builder aren't
	for _, tk := range a.Taken {
		if tk.Name == "jane-php-1" || tk.Name == "jane_data" || tk.Name == "buildx_buildkit_jane0" {
			t.Errorf("listed as taken: %+v", tk)
		}
	}
}

// A scope's create of a name another owner's object has is refused, saying it's taken, but not
// whose: another's objects are answered as ones that aren't there. Docker isn't asked to create it.
func TestCreatingATakenNameIsRefused(t *testing.T) {
	d := startDocker(t)
	d.extra = []fakeObject{{"cccc000000000000000000000000000000000000000000000000000000000009", "jane-shop-web-1", map[string]string{"com.docker.compose.project": "jane-shop"}}}
	server := gate(t, d, "sites")
	before := d.count()

	for what, c := range map[string][2]string{
		"a container": {"/v1.56/containers/create?name=jane-shop-web-1", encode(compose())},
		"a volume":    {"/v1.56/volumes/create", `{"Name":"jane_stolen","Labels":{"com.docker.compose.project":"jane"}}`},
	} {
		status, answer := send(t, server, "POST", c[0], c[1], asJane)
		if status != http.StatusConflict || !strings.Contains(message(t, answer), "is taken") || strings.Contains(answer, "blog") || strings.Contains(answer, "jane-shop\"") {
			t.Errorf("%s: %d %s", what, status, answer)
		}
	}

	if d.count() != before {
		t.Errorf("%d creates reached Docker", d.count()-before)
	}

	// Its own names still create
	if status, answer := send(t, server, "POST", "/v1.56/containers/create?name=jane-php-2", encode(compose()), asJane); status != http.StatusOK {
		t.Errorf("its own name: %d %s", status, answer)
	}
}

// check --docker names every loaded scope's taken names, with whose they are.
func TestCheckWarnsOfTakenNames(t *testing.T) {
	d := startDocker(t)
	scopes := t.TempDir()
	writeAtomically(t, scopes, "jane", janeFile("one"))

	c, err := config.Parse([]byte("version: 1\nupstream: unix://" + d.socket + "\nlisteners:\n  - {name: sites, address: 'tcp://127.0.0.1:2376', mode: scoped, scopes: " + scopes + "}\n"))
	if err != nil {
		t.Fatal(err)
	}

	registry := Registry(c)
	if err := registry.Reload(); err != nil {
		t.Fatal(err)
	}

	warnings := TakenWarnings(context.Background(), c, registry)
	if !slices.ContainsFunc(warnings, func(w string) bool {
		return strings.Contains(w, `scope jane's volume name "jane_stolen" is taken by com.docker.compose.project=blog`)
	}) {
		t.Errorf("warnings: %q", warnings)
	}
}
