package scope

import (
	"fmt"
	"maps"
	"math/rand/v2"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
)

// two folders, one per listener, read by one registry.
func twoListeners(t *testing.T, state string) (*Registry, string, string) {
	t.Helper()
	one, two := t.TempDir(), t.TempDir()

	return NewRegistry([]Folder{{Listener: "one", Dir: one}, {Listener: "two", Dir: two, Tokenless: true}}, state), one, two
}

func reload(t *testing.T, r *Registry) {
	t.Helper()

	if err := r.Reload(); err != nil {
		t.Fatal(err)
	}
}

func get(t *testing.T, r *Registry, listener, name string) *Scope {
	t.Helper()

	s, err := r.Store(listener).Get(name)
	if err != nil {
		t.Fatalf("%s on %s: %v", name, listener, err)
	}

	return s
}

// answers is what scope jane may do with jane-blog's names, images and label.
func answers(jane *Scope) string {
	return fmt.Sprint(jane.OwnsImage("quire-sites/jane/blog/php:1"), jane.NamesContainer("jane-blog-php-1"), jane.Names("jane-blog_data"), jane.OwnedByAnother(map[string]string{"com.docker.compose.project": "jane-blog"}))
}

// Nested scopes on two listeners of one Docker resolve as they do in one folder: jane-blog's names
// and images are its own, not jane's (ARC-0001).
func TestNestedScopesAcrossListeners(t *testing.T) {
	r, one, two := twoListeners(t, "")
	write(t, one, "jane", scopeFile("jane", "jane", "quire-sites/jane/"))
	write(t, two, "jane-blog", scopeFile("jane-blog", "jane-blog", "quire-sites/jane/blog/"))
	reload(t, r)

	if got := answers(get(t, r, "one", "jane")); got != "false false false true" {
		t.Errorf("jane, with jane-blog on another listener: %s", got)
	}

	blog := get(t, r, "two", "jane-blog")
	if !blog.Names("jane-blog-php-1") || !blog.OwnsImage("quire-sites/jane/blog/php:1") || blog.Names("jane-php-1") {
		t.Error("jane-blog's own")
	}

	// The same as in one folder
	dir := t.TempDir()
	write(t, dir, "jane", scopeFile("jane", "jane", "quire-sites/jane/"))
	write(t, dir, "jane-blog", scopeFile("jane-blog", "jane-blog", "quire-sites/jane/blog/"))

	jane, err := testStore(t, dir, false).Get("jane")
	if err != nil || answers(jane) != "false false false true" {
		t.Errorf("one folder: %v %v", answers(jane), err)
	}
}

// A claim on two listeners is refused as it is in one folder: at runtime, after a reload.
func TestACollisionAcrossListenersAtRuntime(t *testing.T) {
	r, one, two := twoListeners(t, "")
	write(t, one, "jane", scopeFile("jane", "jane", "quire-sites/jane/"))
	reload(t, r)

	write(t, two, "evil", scopeFile("evil", "jane", "quire-sites/evil/"))
	reload(t, r)

	get(t, r, "one", "jane")

	if _, err := r.Store("two").Get("evil"); err == nil || !strings.Contains(err.Error(), `prefixes: "jane-" is scope jane's already`) {
		t.Errorf("evil: %v", err)
	}
}

// The same scope on two listeners (one folder served by token and by socket) is one scope.
func TestTheSameScopeOnTwoListeners(t *testing.T) {
	dir := t.TempDir()
	r := NewRegistry([]Folder{{Listener: "tokens", Dir: dir}, {Listener: "sockets", Dir: dir, Tokenless: true}}, "")
	write(t, dir, "jane", scopeFile("jane", "jane", "quire-sites/jane/"))
	reload(t, r)

	for _, l := range []string{"tokens", "sockets"} {
		if s := get(t, r, l, "jane"); !s.Names("jane-php-1") || s.OwnedByAnother(map[string]string{"com.docker.compose.project": "jane"}) {
			t.Errorf("on %s", l)
		}
	}
}

// A scope file that turns invalid (caught half-written) keeps its last valid claims: its names and
// image namespace go to no one, its label stays another's; removing the file releases them (ARC-0002).
func TestAnInvalidScopeKeepsItsClaims(t *testing.T) {
	r, one, two := twoListeners(t, "")
	write(t, one, "jane", scopeFile("jane", "jane", "quire-sites/jane/"))
	blog := write(t, two, "jane-blog", scopeFile("jane-blog", "jane-blog", "quire-sites/jane/blog/"))
	reload(t, r)

	full := scopeFile("jane-blog", "jane-blog", "quire-sites/jane/blog/")
	write(t, two, "jane-blog", full[:len(full)/2])
	reload(t, r)

	if _, err := r.Store("two").Get("jane-blog"); err == nil {
		t.Fatal("a half-written file is valid")
	}

	if got := answers(get(t, r, "one", "jane")); got != "false false false true" {
		t.Errorf("jane, jane-blog half-written: %s", got)
	}

	// Nor can a new scope take them
	write(t, one, "squat", scopeFile("squat", "jane-blog", "quire-sites/jane/blog/"))
	reload(t, r)

	if _, err := r.Store("one").Get("squat"); err == nil || !strings.Contains(err.Error(), "scope jane-blog's already") {
		t.Errorf("squat: %v", err)
	}

	if strings.Join(r.Reserved(), ",") != "jane-blog" {
		t.Errorf("reserved: %v", r.Reserved())
	}

	_ = os.Remove(filepath.Join(one, "squat.json"))
	_ = os.Remove(blog)
	reload(t, r)

	if got := answers(get(t, r, "one", "jane")); got != "true true true false" {
		t.Errorf("jane, jane-blog removed: %s", got)
	}
}

// A scope refused for a collision doesn't lose what it held before the change that collides.
func TestARefusedRewriteKeepsTheOldClaims(t *testing.T) {
	dir := t.TempDir()
	store := testStore(t, dir, false)
	write(t, dir, "jane", scopeFile("jane", "jane", "quire-sites/jane/"))
	write(t, dir, "jane-blog", scopeFile("jane-blog", "jane-blog", "quire-sites/jane/blog/"))

	if _, err := store.Get("jane"); err != nil {
		t.Fatal(err)
	}

	// jane-blog now asks for jane's label: refused, and its old names stay its own
	write(t, dir, "jane-blog", scopeFile("jane", "jane-blog", "quire-sites/jane/blog/"))

	if _, err := store.Get("jane-blog"); err == nil {
		t.Fatal("a rewrite that takes jane's label")
	}

	if jane, _ := store.Get("jane"); answers(jane) != "false false false true" {
		t.Errorf("jane: %s", answers(jane))
	}
}

// With a state file, the claims held survive a restart: a nested file that is invalid when the gate
// starts keeps its names.
func TestHeldClaimsSurviveARestart(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state.json")
	r, one, two := twoListeners(t, state)
	write(t, one, "jane", scopeFile("jane", "jane", "quire-sites/jane/"))
	write(t, two, "jane-blog", scopeFile("jane-blog", "jane-blog", "quire-sites/jane/blog/"))
	reload(t, r)

	if info, err := os.Stat(state); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("the state file: %v", err)
	}

	full := scopeFile("jane-blog", "jane-blog", "quire-sites/jane/blog/")
	write(t, two, "jane-blog", full[:len(full)/2])

	// A new process
	again := NewRegistry([]Folder{{Listener: "one", Dir: one}, {Listener: "two", Dir: two, Tokenless: true}}, state)
	reload(t, again)

	if got := answers(get(t, again, "one", "jane")); got != "false false false true" || again.StateProblem() != nil {
		t.Errorf("after a restart: %s, %v", got, again.StateProblem())
	}

	// Without the state file, nothing is held: the names are open (the documented residual)
	bare := NewRegistry([]Folder{{Listener: "one", Dir: one}, {Listener: "two", Dir: two, Tokenless: true}}, "")
	reload(t, bare)

	if got := answers(get(t, bare, "one", "jane")); got != "true true true false" {
		t.Errorf("no state file: %s", got)
	}

	// A record whose file is gone is dropped
	_ = os.Remove(filepath.Join(two, "jane-blog.json"))
	reload(t, again)

	content, _ := os.ReadFile(state)
	if strings.Contains(string(content), "jane-blog") {
		t.Errorf("a removed scope's record stays: %s", content)
	}
}

// The state file only reserves: an edited one can refuse names (deny service) but never lets a scope
// act beyond its own file.
func TestTheStateFileNeverGrants(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(t.TempDir(), "state.json")
	write(t, dir, "jane", scopeFile("jane", "jane", "quire-sites/jane/"))
	write(t, dir, "x", "{")

	edited := `{"version": 1, "scopes": {
		"jane": {"owner": {"label": "com.docker.compose.project", "value": "jane"}, "prefixes": ["jane-", "other-"], "images": ["quire-sites/"]},
		"x": {"owner": {"label": "com.docker.compose.project", "value": "x"}, "prefixes": ["jane-x-"], "images": ["quire-sites/jane/x/"]}
	}}`
	if err := os.WriteFile(state, []byte(edited), 0o600); err != nil {
		t.Fatal(err)
	}

	r := NewRegistry([]Folder{{Listener: "sites", Dir: dir}}, state)
	reload(t, r)

	jane := get(t, r, "sites", "jane")

	// Never more than its own file
	if jane.Names("other-1") || jane.OwnsImage("quire-sites/other/php") {
		t.Error("the state file widened jane")
	}

	// It may block: x's reserved names
	if jane.Names("jane-x-1") || jane.OwnsImage("quire-sites/jane/x/php") || !jane.Names("jane-php-1") {
		t.Error("x's reservation")
	}

	// A state file anyone can write is not read
	if err := os.Chmod(state, 0o666); err != nil {
		t.Fatal(err)
	}

	loose := NewRegistry([]Folder{{Listener: "sites", Dir: dir}}, state)
	reload(t, loose)

	if loose.StateProblem() == nil || !get(t, loose, "sites", "jane").Names("jane-x-1") {
		t.Error("a state file anyone can write")
	}
}

// Scopes split over any number of listeners give the same answers as the same scopes in one folder.
func TestListenersAreOneFolder(t *testing.T) {
	scopes := map[string]string{
		"jane":          scopeFile("jane", "jane", "quire-sites/jane/"),
		"jane-blog":     scopeFile("jane-blog", "jane-blog", "quire-sites/jane/blog/"),
		"jane-blog-dev": scopeFile("jane-blog-dev", "jane-blog-dev", "quire-sites/jane/blog/dev/"),
		"janet":         scopeFile("janet", "janet", "quire-sites/janet/"),
		"bob":           scopeFile("bob", "bob", "quire-sites/bob/"),
	}
	probes := []string{"jane-php-1", "jane-blog-php-1", "jane-blog-dev-php-1", "janet-php-1", "jane_default", "jane-blog_data", "bob-x", "f5dba3e4fa27_jane-blog-php-1"}
	images := []string{"quire-sites/jane/php", "quire-sites/jane/blog/php", "quire-sites/jane/blog/dev/php", "quire-sites/janet/php", "quire-sites/bob/x"}

	names := slices.Sorted(maps.Keys(scopes))

	table := func(store func(name string) *Scope) string {
		var b strings.Builder

		for _, name := range names {
			s := store(name)
			for _, p := range probes {
				fmt.Fprint(&b, name, p, s.NamesContainer(p), s.Names(p), ";")
			}

			for _, i := range images {
				fmt.Fprint(&b, name, i, s.OwnsImage(i), ";")
			}

			for _, other := range names {
				fmt.Fprint(&b, name, other, s.OwnedByAnother(map[string]string{"com.docker.compose.project": other}), ";")
			}
		}

		return b.String()
	}

	dir := t.TempDir()
	for name, content := range scopes {
		write(t, dir, name, content)
	}

	single := NewRegistry([]Folder{{Listener: "sites", Dir: dir}}, "")
	reload(t, single)
	want := table(func(name string) *Scope { return get(t, single, "sites", name) })

	rng := rand.New(rand.NewPCG(1, 2))

	for round := range 50 {
		n := 1 + rng.IntN(4)
		folders := make([]Folder, n)

		for i := range folders {
			folders[i] = Folder{Listener: fmt.Sprint("l", i), Dir: t.TempDir()}
		}

		where := map[string]string{}

		for name, content := range scopes {
			f := folders[rng.IntN(n)]
			write(t, f.Dir, name, content)
			where[name] = f.Listener
		}

		r := NewRegistry(folders, "")
		reload(t, r)

		if got := table(func(name string) *Scope { return get(t, r, where[name], name) }); got != want {
			t.Fatalf("round %d, %d listeners: the answers differ from one folder's", round, n)
		}
	}
}

// No sequence of invalid writes, rewrites and restarts with a state file widens another scope: jane
// never gets jane-blog's names while jane-blog's file exists.
func TestInvalidWritesNeverWiden(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state.json")
	one, two := t.TempDir(), t.TempDir()
	folders := []Folder{{Listener: "one", Dir: one}, {Listener: "two", Dir: two}}
	full := scopeFile("jane-blog", "jane-blog", "quire-sites/jane/blog/")

	write(t, one, "jane", scopeFile("jane", "jane", "quire-sites/jane/"))
	write(t, two, "jane-blog", full)

	r := NewRegistry(folders, state)
	reload(t, r)

	rng := rand.New(rand.NewPCG(3, 4))

	for step := range 300 {
		switch rng.IntN(5) {
		case 0:
			write(t, two, "jane-blog", full[:rng.IntN(len(full))])
		case 1:
			write(t, two, "jane-blog", full+strings.Repeat(" ", rng.IntN(3)))
		case 2:
			write(t, two, "jane-blog", strings.Replace(full, "jane-blog_", "jane_", 1)) // collides
		case 3:
			write(t, two, "jane-blog", strings.Replace(full, digest(token), "x", 1)) // invalid
		case 4:
			r = NewRegistry(folders, state) // a restart
		}

		reload(t, r)

		if got := answers(get(t, r, "one", "jane")); got != "false false false true" {
			t.Fatalf("step %d: jane got jane-blog's: %s", step, got)
		}
	}
}

// A scopes folder that isn't there at the start has no scopes, and every claim the state file holds
// stays reserved; one that goes away later keeps the snapshot in use, rather than releasing its
// scopes' claims.
func TestAMissingFolder(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state.json")
	r, one, two := twoListeners(t, state)
	write(t, one, "jane", scopeFile("jane", "jane", "quire-sites/jane/"))
	write(t, two, "jane-blog", scopeFile("jane-blog", "jane-blog", "quire-sites/jane/blog/"))
	reload(t, r)

	moved := two + ".away"
	if err := os.Rename(two, moved); err != nil {
		t.Fatal(err)
	}

	if err := r.Reload(); err == nil {
		t.Error("a folder that went away")
	}

	if got := answers(get(t, r, "one", "jane")); got != "false false false true" {
		t.Errorf("the folder gone: %s", got)
	}

	// A restart while it's away: nothing on it, jane-blog's claims still held
	again := NewRegistry([]Folder{{Listener: "one", Dir: one}, {Listener: "two", Dir: two, Tokenless: true}}, state)
	reload(t, again)

	if len(again.Missing()) != 1 || again.Missing()[0] != two {
		t.Errorf("missing: %v", again.Missing())
	}

	if got := answers(get(t, again, "one", "jane")); got != "false false false true" {
		t.Errorf("a restart without the folder: %s", got)
	}

	if content, _ := os.ReadFile(state); !strings.Contains(string(content), "jane-blog") {
		t.Errorf("jane-blog's record was dropped: %s", content)
	}
}

// A refusal names the claim in a fixed order (builders, owner, prefixes, images), and the scopes it
// collides with.
func TestARefusalSaysWhy(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "jane", scopeFile("jane", "jane", "quire-sites/jane/"))
	write(t, dir, "zed", scopeFile("zed", "jane", "quire-sites/jane/"))

	for range 20 {
		store := testStore(t, dir, false)

		if _, err := store.Get("jane"); err == nil || !strings.Contains(err.Error(), `prefixes: "jane-" is also scope zed's`) {
			t.Fatalf("jane: %v", err)
		}

		if _, err := store.Get("zed"); err == nil || !strings.Contains(err.Error(), `prefixes: "jane-" is also scope jane's`) {
			t.Fatalf("zed: %v", err)
		}
	}
}

// A state file's record that isn't valid is dropped, and said; the others are kept.
func TestAStateRecordNotValid(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(t.TempDir(), "state.json")
	write(t, dir, "jane", scopeFile("jane", "jane", "quire-sites/jane/"))
	write(t, dir, "x", "{")
	write(t, dir, "y", "{")

	if err := os.WriteFile(state, []byte(`{"version": 1, "scopes": {
		"x": {"owner": {"label": "com.docker.compose.project", "value": "x"}, "prefixes": ["jane-x-"]},
		"y": {"owner": {"label": "com.docker.compose.project", "value": "y"}, "prefixes": ["jane-y"]}
	}}`), 0o600); err != nil {
		t.Fatal(err)
	}

	r := NewRegistry([]Folder{{Listener: "sites", Dir: dir}}, state).ReadOnly()
	reload(t, r)

	if err := r.StateProblem(); err == nil || !strings.Contains(err.Error(), `["y"]`) {
		t.Errorf("the bad record: %v", err)
	}

	if jane := get(t, r, "sites", "jane"); jane.Names("jane-x-1") || !jane.Names("jane-y1") {
		t.Error("x kept, y dropped")
	}

	for _, version := range []string{`{"version": 2, "scopes": {}}`, `{"scopes": {}}`, `[]`} {
		_ = os.WriteFile(state, []byte(version), 0o600)

		if bad := NewRegistry([]Folder{{Listener: "sites", Dir: dir}}, state).ReadOnly(); bad.Reload() != nil || bad.StateProblem() == nil {
			t.Errorf("%s: read", version)
		}
	}
}

// Requests read the snapshot while files change and reloads swap it in: with -race, no data race,
// and every answer is one snapshot's (jane never gets jane-blog's names).
func TestReloadUnderTraffic(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "jane", scopeFile("jane", "jane", "quire-sites/jane/"))
	write(t, dir, "jane-blog", scopeFile("jane-blog", "jane-blog", "quire-sites/jane/blog/"))
	r := NewRegistry([]Folder{{Listener: "sites", Dir: dir}}, filepath.Join(t.TempDir(), "state.json"))
	reload(t, r)

	done := make(chan struct{})
	failed := make(chan string, 1)

	var wg sync.WaitGroup

	for range 4 {
		wg.Go(func() {
			for {
				select {
				case <-done:
					return
				default:
				}

				jane, err := r.Store("sites").Authenticate("jane", token)
				if err != nil || jane.Names("jane-blog-php-1") || jane.OwnsImage("quire-sites/jane/blog/php:1") {
					select {
					case failed <- fmt.Sprint(err):
					default:
					}

					return
				}
			}
		})
	}

	full := scopeFile("jane-blog", "jane-blog", "quire-sites/jane/blog/")
	for i := range 200 {
		write(t, dir, "jane-blog", full[:i%len(full)])
		reload(t, r)
	}

	close(done)
	wg.Wait()

	select {
	case why := <-failed:
		t.Fatal("a request saw jane-blog's names as jane's:", why)
	default:
	}
}

// Status answers from the published snapshot only, and its channel closes when another is
// published: a scope is loaded, reserved, refused or unknown, with its file's SHA-256.
func TestStatusIsThePublishedSnapshots(t *testing.T) {
	r, one, _ := twoListeners(t, "")
	write(t, one, "jane", scopeFile("jane", "jane", "quire-sites/jane/"))
	reload(t, r)

	if s, _, ok := r.Status("one", "jane"); !ok || s.State != "unknown" || s.Generation != 0 {
		t.Errorf("before a publish: %+v", s)
	}

	r.Publish()

	s, next, _ := r.Status("one", "jane")
	if s.State != "loaded" || s.Generation != 1 || len(s.FileSHA256) != 64 || s.Reason != "" || s.Listener != "one" || s.Scope != "jane" {
		t.Errorf("published: %+v", s)
	}

	// Nothing new: the channel stays open
	r.Publish()
	select {
	case <-next:
		t.Fatal("closed with nothing new")
	default:
	}

	write(t, one, "jane", "{")
	write(t, one, "blog", "{")
	reload(t, r)
	r.Publish()

	select {
	case <-next:
	default:
		t.Fatal("not closed by a new snapshot")
	}

	if s, _, _ := r.Status("one", "jane"); s.State != "reserved" || s.Reason == "" || s.Generation != 2 {
		t.Errorf("jane: %+v", s)
	}

	if s, _, _ := r.Status("one", "blog"); s.State != "refused" || s.Reason == "" || len(s.FileSHA256) != 64 {
		t.Errorf("blog: %+v", s)
	}

	if s, _, _ := r.Status("two", "jane"); s.State != "unknown" || s.FileSHA256 != "" {
		t.Errorf("another listener: %+v", s)
	}

	if _, _, ok := r.Status("nope", "jane"); ok {
		t.Error("a listener it doesn't have")
	}

	if strings.Join(r.Listeners(), ",") != "one,two" {
		t.Errorf("listeners: %v", r.Listeners())
	}

	// Reload requests coalesce into one
	r.RequestReload()
	r.RequestReload()

	if len(r.Requests()) != 1 {
		t.Error("requests don't coalesce")
	}
}
