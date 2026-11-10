package scope

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

const token = "a-long-random-token-0123456789abcdef"

func digest(t string) string {
	sum := sha256.Sum256([]byte(t))

	return hex.EncodeToString(sum[:])
}

func write(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name+".json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	return path
}

// reloading is a listener's store that reloads before each lookup, as a test changes files between
// them (a running gate reloads on its scan, or SIGHUP).
type reloading struct {
	t *testing.T
	*Store
}

func (s reloading) Get(name string) (*Scope, error) {
	s.t.Helper()
	if err := s.registry.Reload(); err != nil {
		s.t.Fatal(err)
	}

	return s.Store.Get(name)
}

func (s reloading) Authenticate(name, token string) (*Scope, error) {
	s.t.Helper()
	if err := s.registry.Reload(); err != nil {
		s.t.Fatal(err)
	}

	return s.Store.Authenticate(name, token)
}

func (s reloading) Scopes() ([]string, map[string]error, error) {
	s.t.Helper()
	if err := s.registry.Reload(); err != nil {
		s.t.Fatal(err)
	}

	return s.Store.Scopes()
}

// testStore is one listener's store over a folder.
func testStore(t *testing.T, dir string, tokenless bool) reloading {
	t.Helper()

	return reloading{t, NewRegistry([]Folder{{Listener: "sites", Dir: dir, Tokenless: tokenless}}, "").Store("sites")}
}

func jane() string {
	return `{"token_sha256": "` + digest(token) + `", "owner": {"label": "com.docker.compose.project", "value": "jane"}, "prefixes": ["jane-", "jane_"]}`
}

func TestAScopeIsItsTokens(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "jane", jane())
	store := testStore(t, dir, false)

	s, err := store.Authenticate("jane", token)
	if err != nil {
		t.Fatal(err)
	}

	if s.Name != "jane" || !s.Owns(map[string]string{"com.docker.compose.project": "jane"}) || s.Owns(map[string]string{"com.docker.compose.project": "janet"}) || s.Owns(nil) {
		t.Error("owns only what carries its label")
	}

	if !s.Names("jane-php-1") || !s.Names("jane_default") || s.Names("janet-php-1") || s.Names("jane-") || s.Names("blog_default") {
		t.Error("names only with its prefixes")
	}

	for _, c := range [][2]string{{"jane", "wrong"}, {"jane", ""}, {"blog", token}, {"../jane", token}, {"", token}, {"JANE", token}} {
		if _, err := store.Authenticate(c[0], c[1]); !errors.Is(err, ErrUnknown) {
			t.Errorf("%q with %q: %v", c[0], c[1], err)
		}
	}
}

// A scope's file is read again when it changes, and its removal ends the scope.
func TestChangesNeedNoRestart(t *testing.T) {
	dir := t.TempDir()
	path := write(t, dir, "jane", jane())
	store := testStore(t, dir, false)

	if _, err := store.Authenticate("jane", token); err != nil {
		t.Fatal(err)
	}

	write(t, dir, "jane", strings.Replace(jane(), digest(token), digest("a-new-token"), 1))
	later := time.Now().Add(2 * time.Second)
	_ = os.Chtimes(path, later, later)

	if _, err := store.Authenticate("jane", token); !errors.Is(err, ErrUnknown) {
		t.Error("the old token still works")
	}

	if _, err := store.Authenticate("jane", "a-new-token"); err != nil {
		t.Errorf("the new token: %v", err)
	}

	// Changed without a new time (a copy that kept it): its size still tells
	info, _ := os.Stat(path)
	write(t, dir, "jane", strings.Replace(jane(), digest(token), digest("token-three"), 1)+"\n")
	_ = os.Chtimes(path, info.ModTime(), info.ModTime())

	if _, err := store.Authenticate("jane", "token-three"); err != nil {
		t.Errorf("changed, same time: %v", err)
	}

	_ = os.Remove(path)

	if _, err := store.Authenticate("jane", "token-three"); !errors.Is(err, ErrUnknown) {
		t.Error("a removed scope still works")
	}
}

func TestScopeFilesAreChecked(t *testing.T) {
	cases := map[string]string{
		"an unknown key":          strings.Replace(jane(), `"prefixes"`, `"privileged": true, "prefixes"`, 1),
		"two objects":             jane() + jane(),
		"a token in clear":        strings.Replace(jane(), digest(token), token, 1),
		"an uppercase digest":     strings.Replace(jane(), digest(token), strings.ToUpper(digest(token)), 1),
		"no owner label":          strings.Replace(jane(), `"com.docker.compose.project"`, `""`, 1),
		"an owner value of any":   strings.Replace(jane(), `"value": "jane"`, `"value": "*"`, 1),
		"no prefixes":             strings.Replace(jane(), `["jane-", "jane_"]`, `[]`, 1),
		"a prefix of any name":    strings.Replace(jane(), `"jane-"`, `"jane"`, 1),
		"an empty prefix":         strings.Replace(jane(), `"jane-"`, `""`, 1),
		"a recreated name prefix": strings.Replace(jane(), `"jane-"`, `"0123456789ab_"`, 1),
		"an image not a prefix":   strings.Replace(jane(), `"prefixes"`, `"images": ["quire-sites/jane"], "prefixes"`, 1),
		"a container pattern":     strings.Replace(jane(), `"prefixes"`, `"containers": ["*"], "prefixes"`, 1),
		"a network pattern":       strings.Replace(jane(), `"prefixes"`, `"networks": {"quire-*": {}}, "prefixes"`, 1),
		"an alias with a space":   strings.Replace(jane(), `"prefixes"`, `"networks": {"link": {"aliases": ["a b"]}}, "prefixes"`, 1),
		"an address of a range":   strings.Replace(jane(), `"prefixes"`, `"networks": {"link": {"addresses": ["10.0.0.0/8"]}}, "prefixes"`, 1),
		"an address unshortened":  strings.Replace(jane(), `"prefixes"`, `"networks": {"link": {"addresses": ["2001:db8:0:0::1"]}}, "prefixes"`, 1),
		"a network key unknown":   strings.Replace(jane(), `"prefixes"`, `"networks": {"link": {"mac": "x"}}, "prefixes"`, 1),
		"a subnet not a network":  strings.Replace(jane(), `"prefixes"`, `"subnets": ["10.213.0.33/27"], "prefixes"`, 1),
		"an address as a subnet":  strings.Replace(jane(), `"prefixes"`, `"subnets": ["10.213.0.32"], "prefixes"`, 1),
		"a newer format":          strings.Replace(jane(), `"prefixes"`, `"version": 2, "prefixes"`, 1),
		"format 0":                strings.Replace(jane(), `"prefixes"`, `"version": 0, "prefixes"`, 1),
		"an egress not none":      strings.Replace(jane(), `"prefixes"`, `"egress": "proxy", "prefixes"`, 1),
		"egress in uppercase":     strings.Replace(jane(), `"prefixes"`, `"egress": "NONE", "prefixes"`, 1),
		"a format as a string":    strings.Replace(jane(), `"prefixes"`, `"version": "1", "prefixes"`, 1),
	}

	for name, content := range cases {
		dir := t.TempDir()
		write(t, dir, "jane", content)

		// Refused as an unknown scope is, saying why only in what it wraps (for the log)
		if _, err := testStore(t, dir, false).Authenticate("jane", token); !errors.Is(err, ErrUnknown) || err.Error() == ErrUnknown.Error() {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// Every token is compared with a digest, once, whether its scope is there, valid, tokenless or not:
// which it is takes no other time to tell.
func TestEveryTokenIsComparedOnce(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "jane", jane())
	write(t, dir, "broken", "{")
	write(t, dir, "free", `{"owner": {"label": "com.docker.compose.project", "value": "free"}, "prefixes": ["free-"]}`)

	calls := 0
	compare := compareTokens
	compareTokens = func(x, y []byte) int {
		calls++
		if len(x) != len(y) {
			t.Errorf("compared %d bytes with %d", len(x), len(y))
		}

		return compare(x, y)
	}
	t.Cleanup(func() { compareTokens = compare })

	store := testStore(t, dir, false)
	tokenless := testStore(t, dir, true)

	for _, c := range []struct {
		store       reloading
		name, token string
	}{{store, "jane", token}, {store, "jane", "wrong"}, {store, "nobody", token}, {store, "broken", token}, {store, "free", token}, {tokenless, "free", token}} {
		calls = 0
		_, _ = c.store.Authenticate(c.name, c.token)

		if calls != 1 {
			t.Errorf("%s: compared %d times", c.name, calls)
		}
	}
}

// A pipe in a scope file's place is refused, not waited on: no reload is held up by one.
func TestAPipeIsntAScopeFile(t *testing.T) {
	dir := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(dir, "jane.json"), 0o600); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := testStore(t, dir, false).Authenticate("jane", token)
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "must be a plain file") {
			t.Errorf("a pipe: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the reload waited on a pipe")
	}
}

func TestOnlyPlainFilesOnlyItsOwnerWrites(t *testing.T) {
	dir := t.TempDir()
	path := write(t, dir, "jane", jane())

	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}

	if _, err := testStore(t, dir, false).Authenticate("jane", token); err == nil {
		t.Error("a file anyone can write")
	}

	other := t.TempDir()
	target := write(t, other, "real", jane())

	if err := os.Symlink(target, filepath.Join(dir, "linked.json")); err != nil {
		t.Fatal(err)
	}

	if _, err := testStore(t, dir, false).Authenticate("linked", token); err == nil {
		t.Error("a link")
	}
}

func TestWhatAScopeMayUse(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "jane", strings.Replace(jane(), `"prefixes"`, `"images": ["quire-sites/jane/"], "builders": ["buildx_buildkit_jane0", "tools-jane"], "networks": {"quire-link-jane": {"aliases": ["jane.example.quire.internal"], "addresses": ["10.213.0.4"]}}, "prefixes"`, 1))

	s, err := testStore(t, dir, false).Authenticate("jane", token)
	if err != nil {
		t.Fatal(err)
	}

	if !s.Builds("buildx_buildkit_jane0") || !s.Builds("tools-jane") || s.Builds("buildx_buildkit_jane") || s.Builds("tools-jane-2") || s.Builds("buildx_buildkit_blog0") {
		t.Error("uses only the containers its scope names")
	}

	if !s.OwnsImage("quire-sites/jane/php-prod") || s.OwnsImage("quire-sites/jane/") || s.OwnsImage("quire-sites/janet/php") || s.OwnsImage("quire-sites/blog/php") {
		t.Error("owns only images in its namespaces")
	}

	if s.Networks["quire-link-jane"].Addresses[0] != "10.213.0.4" {
		t.Error("its shared network")
	}
}

func TestSubnets(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "jane", strings.Replace(jane(), `"prefixes"`, `"subnets": ["10.213.0.32/27", "fd00:213::/64"], "prefixes"`, 1))

	s, err := testStore(t, dir, false).Authenticate("jane", token)
	if err != nil {
		t.Fatal(err)
	}

	for subnet, inside := range map[string]bool{"10.213.0.32/27": true, "10.213.0.48/28": true, "10.213.0.0/24": false, "10.213.0.64/27": false, "fd00:213::/80": true, "fd00:214::/64": false} {
		if s.Contains(netip.MustParsePrefix(subnet)) != inside || !s.HasSubnets() {
			t.Errorf("%s: inside %v", subnet, !inside)
		}
	}

	write(t, dir, "free", scopeFile("free", "free", "free/"))
	free, err := testStore(t, dir, false).Authenticate("free", token)
	if err != nil {
		t.Fatal(err)
	}

	if free.HasSubnets() || !free.Contains(netip.MustParsePrefix("172.20.0.0/16")) {
		t.Error("a scope without subnets takes Docker's")
	}
}

// A DNS name is at most 253 characters (labels of up to 63).
func TestAliasLengths(t *testing.T) {
	label := strings.Repeat("a", 63)
	longest := label + "." + label + "." + label + "." + strings.Repeat("b", 61)

	for alias, valid := range map[string]bool{longest: true, longest + "b": false} {
		dir := t.TempDir()
		write(t, dir, "jane", strings.Replace(jane(), `"prefixes"`, `"networks": {"link": {"aliases": ["`+alias+`"]}}, "prefixes"`, 1))

		if _, err := testStore(t, dir, false).Authenticate("jane", token); (err == nil) != valid {
			t.Errorf("%d characters: %v", len(alias), err)
		}
	}
}

// scopeFile is a scope with its own owner value, prefixes and image namespace.
func scopeFile(owner, prefix, images string) string {
	return `{"token_sha256": "` + digest(token) + `", "owner": {"label": "com.docker.compose.project", "value": "` + owner + `"}, "prefixes": ["` + prefix + `-", "` + prefix + `_"], "images": ["` + images + `"]}`
}

// Tenants' names nest (sites jane and jane-blog): both are valid, and a name is the scope's with the
// longest prefix it starts with, for as long as that scope exists.
func TestANameIsTheLongestPrefixs(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "jane", scopeFile("jane", "jane", "quire-sites/jane/"))
	write(t, dir, "jane-blog", scopeFile("jane-blog", "jane-blog", "quire-sites/jane/blog/"))
	store := testStore(t, dir, false)

	jane, err := store.Get("jane")
	if err != nil {
		t.Fatal(err)
	}

	blog, err := store.Get("jane-blog")
	if err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{"jane-blog-php-1", "jane-blog_default", "jane-blog_data"} {
		if jane.Names(name) || !blog.Names(name) {
			t.Errorf("%s: jane %v, jane-blog %v", name, jane.Names(name), blog.Names(name))
		}
	}

	if !jane.Names("jane-php-1") || !jane.Names("jane-blogger-1") || blog.Names("jane-php-1") {
		t.Error("jane's own names")
	}

	// The name Compose gives a container it recreates is the scope's whose name follows the 12 hex,
	// and only a container's.
	for name, want := range map[string][2]bool{
		"f5dba3e4fa27_jane-blog-php-1": {false, true},
		"f5dba3e4fa27_jane-php-1":      {true, false},
		"f5dba3e4fa27_other-php-1":     {false, false},
		"f5dba3e4fa2_jane-php-1":       {false, false},
		"F5DBA3E4FA27_jane-php-1":      {false, false},
		"f5dba3e4fa27-jane-php-1":      {false, false},
		"f5dba3e4fa27_":                {false, false},
	} {
		if jane.NamesContainer(name) != want[0] || blog.NamesContainer(name) != want[1] || jane.Names(name) || blog.Names(name) {
			t.Errorf("%s: jane %v, jane-blog %v", name, jane.NamesContainer(name), blog.NamesContainer(name))
		}
	}

	if jane.OwnsImage("quire-sites/jane/blog/php:1") || !blog.OwnsImage("quire-sites/jane/blog/php:1") || !jane.OwnsImage("quire-sites/jane/php:1") {
		t.Error("image namespaces")
	}

	// Without scope jane-blog, its names are jane's again.
	if err := os.Remove(filepath.Join(dir, "jane-blog.json")); err != nil {
		t.Fatal(err)
	}

	if jane, err = store.Get("jane"); err != nil || !jane.Names("jane-blog-php-1") || !jane.OwnsImage("quire-sites/jane/blog/php:1") {
		t.Errorf("jane-blog removed: %v", err)
	}
}

// Two scopes may not share an owner label, a prefix or an image namespace: the one that held it
// first stays valid, the later is refused naming both; rewriting the first (a new token) doesn't
// change which, and neither do the files' times.
func TestScopesThatShareAreRefused(t *testing.T) {
	for what, second := range map[string]string{
		"an owner label":      scopeFile("jane", "other", "quire-sites/other/"),
		"a prefix":            scopeFile("other", "jane", "quire-sites/other/"),
		"an image namespace":  scopeFile("other", "other", "quire-sites/jane/"),
		"one of two prefixes": strings.Replace(scopeFile("other", "other", "quire-sites/other/"), `"other_"`, `"jane_"`, 1),
	} {
		for _, order := range [][2]string{{"jane", "zed"}, {"zed", "jane"}} {
			dir := t.TempDir()
			store := testStore(t, dir, false)

			write(t, dir, order[0], scopeFile("jane", "jane", "quire-sites/jane/"))
			if _, err := store.Get(order[0]); err != nil {
				t.Fatalf("%s: %v", what, err)
			}

			later := write(t, dir, order[1], second)
			// An older time doesn't make it the first
			past := time.Now().Add(-time.Hour)
			_ = os.Chtimes(later, past, past)

			if _, err := store.Get(order[0]); err != nil {
				t.Errorf("%s, %s first: the first refused: %v", what, order[0], err)
			}

			_, err := store.Get(order[1])
			if err == nil || !strings.Contains(err.Error(), "scope "+order[0]+"'s already") || !strings.Contains(err.Error(), order[1]+".json") {
				t.Errorf("%s, %s first: the later: %v", what, order[0], err)
			}

			// The first file rewritten now: it's still the first.
			write(t, dir, order[0], scopeFile("jane", "jane", "quire-sites/jane/")+"\n")

			if _, err := store.Get(order[0]); err != nil {
				t.Errorf("%s, %s first: rewritten, it was refused: %v", what, order[0], err)
			}

			if _, err := store.Get(order[1]); err == nil {
				t.Errorf("%s, %s first: rewriting the first made the later valid", what, order[0])
			}
		}
	}
}

// Two scopes that collide when neither held the claim (both new, or a restart without a state file)
// are both refused, whatever their files' times: there is no first to keep.
func TestNewScopesThatShareAreBothRefused(t *testing.T) {
	for _, times := range [][2]time.Duration{{0, time.Hour}, {time.Hour, 0}} {
		dir := t.TempDir()
		a := write(t, dir, "jane", scopeFile("jane", "jane", "quire-sites/jane/"))
		b := write(t, dir, "zed", scopeFile("zed", "jane", "quire-sites/zed/"))
		_ = os.Chtimes(a, time.Now().Add(-times[0]), time.Now().Add(-times[0]))
		_ = os.Chtimes(b, time.Now().Add(-times[1]), time.Now().Add(-times[1]))
		store := testStore(t, dir, false)

		for _, name := range []string{"jane", "zed"} {
			if _, err := store.Get(name); err == nil || !strings.Contains(err.Error(), "no one held it before") {
				t.Errorf("%s: %v", name, err)
			}
		}
	}
}

// Scopes may use different owner labels: having its own label doesn't make an object only its own.
func TestLabelsOfAnotherScope(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "jane", scopeFile("jane", "jane", "quire-sites/jane/"))
	write(t, dir, "ci", strings.Replace(scopeFile("job-7", "ci", "ci/"), "com.docker.compose.project", "example.ci.job", 1))

	jane, err := testStore(t, dir, false).Get("jane")
	if err != nil {
		t.Fatal(err)
	}

	for labels, want := range map[*map[string]string]bool{
		{"com.docker.compose.project": "jane"}:                            false,
		{"com.docker.compose.project": "jane", "example.ci.job": "job-7"}: true,
		{"com.docker.compose.project": "jane", "example.ci.job": "job-8"}: false,
		{"example.ci.job": "job-7"}:                                       true,
	} {
		if got := jane.OwnedByAnother(*labels); got != want {
			t.Errorf("%v: %v", *labels, got)
		}
	}
}

// A scope with its own socket needs no token; one sent with each request does.
func TestATokenIsOptionalOnlyWithASocket(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "jane", `{"owner": {"label": "com.docker.compose.project", "value": "jane"}, "prefixes": ["jane-"]}`)
	write(t, dir, "blog", scopeFile("blog", "blog", "quire-sites/blog/"))
	write(t, dir, "bad", `{"token_sha256": "abc", "owner": {"label": "com.docker.compose.project", "value": "bad"}, "prefixes": ["bad-"]}`)

	if _, err := testStore(t, dir, false).Get("jane"); err == nil {
		t.Error("a scope without a token, where each request sends one")
	}

	store := testStore(t, dir, true)
	if s, err := store.Get("jane"); err != nil || s.TokenSHA256 != "" {
		t.Fatalf("a socket's scope without a token: %v", err)
	}

	if _, err := store.Authenticate("jane", "anything"); !errors.Is(err, ErrUnknown) {
		t.Errorf("a scope without a token is never authenticated by one: %v", err)
	}

	names, invalid, err := store.Scopes()
	if err != nil || strings.Join(names, ",") != "blog,jane" || len(invalid) != 1 || invalid["bad"] == nil {
		t.Errorf("valid %v, invalid %v, %v", names, invalid, err)
	}
}

// Builders are exact names, each one scope's; 0.1's "containers" is refused, saying why.
func TestBuilders(t *testing.T) {
	for content, want := range map[string]string{
		strings.Replace(jane(), `"prefixes"`, `"containers": ["buildx_buildkit_jane-*"], "prefixes"`, 1): "replaced by builders",
		strings.Replace(jane(), `"prefixes"`, `"builders": ["buildx_buildkit_jane-*"], "prefixes"`, 1):   "no wildcard",
		strings.Replace(jane(), `"prefixes"`, `"builders": ["../x"], "prefixes"`, 1):                     "no wildcard",
	} {
		dir := t.TempDir()
		write(t, dir, "jane", content)

		if _, err := testStore(t, dir, false).Get("jane"); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v", content, err)
		}
	}

	dir := t.TempDir()
	write(t, dir, "jane", strings.Replace(scopeFile("jane", "jane", "quire-sites/jane/"), `"prefixes"`, `"builders": ["bk-jane"], "prefixes"`, 1))

	store := testStore(t, dir, false)
	if _, err := store.Get("jane"); err != nil {
		t.Fatal(err)
	}

	write(t, dir, "blog", strings.Replace(scopeFile("blog", "blog", "quire-sites/blog/"), `"prefixes"`, `"builders": ["bk-jane"], "prefixes"`, 1))

	if _, err := store.Get("blog"); err == nil || !strings.Contains(err.Error(), `builders: "bk-jane" is scope jane's already`) {
		t.Errorf("a builder of two scopes: %v", err)
	}
}

// A scope file says its format; one without is valid, and named as one 0.4 refuses.
func TestScopeFormatVersions(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "jane", strings.Replace(jane(), `"prefixes"`, `"version": 1, "prefixes"`, 1))
	write(t, dir, "old", scopeFile("old", "old", "old/"))
	store := testStore(t, dir, false)

	if _, err := store.Get("jane"); err != nil {
		t.Fatal(err)
	}

	if _, err := store.Get("old"); err != nil {
		t.Fatal(err)
	}

	if got := store.Unversioned(); len(got) != 1 || got[0] != "old" {
		t.Errorf("unversioned: %v", got)
	}
}

// A missing scope, a wrong token and a file that isn't valid are refused with the same work: the
// same allocations, each error made at the reload. Timing measures this; this keeps it.
func TestEveryRefusalAllocatesAlike(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "jane", jane())
	write(t, dir, "broken", "{")

	reloaded := testStore(t, dir, false)
	if _, err := reloaded.Get("jane"); err != nil {
		t.Fatal(err)
	}

	store := reloaded.Store // as it is now: a reload is the scan's, not each request's

	wrong := strings.Repeat("x", len(token))
	counts := map[string]float64{}

	for name, ask := range map[string][2]string{
		"missing":     {"nobody", token},
		"wrong token": {"jane", wrong},
		"not valid":   {"broken", token},
	} {
		if _, err := store.Authenticate(ask[0], ask[1]); !errors.Is(err, ErrUnknown) {
			t.Fatalf("%s: %v", name, err)
		}

		counts[name] = testing.AllocsPerRun(1000, func() { _, _ = store.Authenticate(ask[0], ask[1]) })
	}

	if counts["missing"] != counts["wrong token"] || counts["not valid"] != counts["wrong token"] {
		t.Errorf("allocations: %v", counts)
	}

	// Why the file isn't valid is still there, for whoever logs it
	if _, err := store.Authenticate("broken", token); err == ErrUnknown || !strings.Contains(err.Error(), "broken.json") {
		t.Errorf("not valid: %v", err)
	}

	if _, err := store.Get("nobody"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("missing, as Get gives it: %v", err)
	}
}

// An alias is a name as Docker's DNS keeps it: lowercase, with Compose's "_" (a project demo_x
// gives demo_x-php-1).
func TestAnAliasAsDockerKeepsIt(t *testing.T) {
	label := strings.Repeat("a", 63)

	for alias, valid := range map[string]bool{
		"demo_x-php-1": true, "demo_x_web-1": true, "_x": true, "x_": true, "a_b.c_d": true, "web": true,
		label + "." + label + "." + label + "." + strings.Repeat("_", 61): true,
		"Demo_X-php-1": false, "web.": false, "a..b": false, ".a": false, "-x": false, "x-": false, "a b": false,
		"": false, label + "a": false, label + "." + label + "." + label + "." + strings.Repeat("_", 62): false,
		"wéb": false, "webK": false,
		// A container's short ID is one of its DNS names
		"0123456789ab": false, "abcdef012345.quire.internal": false, "0123456789abc": true, "0123456789ag": true, "x.0123456789a": true,
	} {
		dir := t.TempDir()
		write(t, dir, "jane", strings.Replace(jane(), `"prefixes"`, `"networks": {"link": {"aliases": [`+quoted(alias)+`]}}, "prefixes"`, 1))

		if _, err := testStore(t, dir, false).Authenticate("jane", token); (err == nil) != valid {
			t.Errorf("%q: %v", alias, err)
		}
	}
}

func quoted(s string) string {
	b, _ := json.Marshal(s)

	return string(b)
}

// What a request names is read as Docker's DNS keeps it: ASCII, lowercased; a trailing dot is
// another name to Docker (it keeps it), and a byte outside ASCII isn't lowercased by a DNS rule.
func TestNormaliseAlias(t *testing.T) {
	for in, want := range map[string]string{"web\x7f": "web\x7f", "web": "web", "WEB": "web", "Demo_X-Php-1": "demo_x-php-1", "Jane.Quire.Internal": "jane.quire.internal"} {
		if got, ok := NormaliseAlias(in); !ok || got != want {
			t.Errorf("%q: %q %v", in, got, ok)
		}
	}

	for _, in := range []string{"", "web.", "jane.quire.internal.", "K", "wéb", "0123456789AB", "x.ABCDEF012345", "web\x80", "web\x7f\x80"} {
		if got, ok := NormaliseAlias(in); ok {
			t.Errorf("%q: %q", in, got)
		}
	}
}

// A scope on an mTLS listener may pin its certificates' public keys: up to MaxCertificates, each
// once, as SHA-256 hex. Elsewhere a pin would never be read, so it's refused.
func TestCertificatePins(t *testing.T) {
	pins := func(digests ...string) string {
		var list []string
		for _, d := range digests {
			list = append(list, `{"sha256": "`+d+`"}`)
		}

		return strings.Replace(jane(), `"prefixes"`, `"certificates": [`+strings.Join(list, ", ")+`], "prefixes"`, 1)
	}
	a, b := digest("key a"), digest("key b")
	certified := func(dir string) *Store {
		r := NewRegistry([]Folder{{Listener: "sites", Dir: dir, Tokenless: true, Certificates: true}}, "")
		if err := r.Reload(); err != nil {
			t.Fatal(err)
		}

		return r.Store("sites")
	}

	nine := make([]string, MaxCertificates+1)
	for i := range nine {
		nine[i] = digest(strings.Repeat("k", i+1))
	}

	for name, content := range map[string]string{
		"an uppercase pin":  pins(strings.ToUpper(a)),
		"a short pin":       pins(a[:63]),
		"a pin twice":       pins(a, b, a),
		"too many":          pins(nine...),
		"a pin key unknown": strings.Replace(pins(a), `"sha256"`, `"spki"`, 1),
		"pins as strings":   strings.Replace(jane(), `"prefixes"`, `"certificates": ["`+a+`"], "prefixes"`, 1),
	} {
		dir := t.TempDir()
		write(t, dir, "jane", content)

		if _, err := certified(dir).Get("jane"); err == nil {
			t.Errorf("%s: allowed", name)
		}
	}

	// Not on a listener without mTLS
	dir := t.TempDir()
	write(t, dir, "jane", pins(a))

	if _, err := testStore(t, dir, true).Get("jane"); err == nil || !strings.Contains(err.Error(), "certificates: only a scope on an mTLS listener has them (listener sites has no tls.client_ca)") {
		t.Errorf("pins without mTLS: %v", err)
	}

	write(t, dir, "jane", pins(nine[:MaxCertificates]...))

	s, err := certified(dir).Get("jane")
	if err != nil {
		t.Fatal(err)
	}

	key := func(d string) (k [32]byte) {
		raw, _ := hex.DecodeString(d)
		copy(k[:], raw)

		return k
	}

	for _, d := range nine[:MaxCertificates] {
		if !s.Pinned(key(d)) {
			t.Errorf("%s isn't pinned", d)
		}
	}

	if s.Pinned(key(nine[MaxCertificates])) || s.Pinned(key(a)) {
		t.Error("an unpinned key is pinned")
	}

	// Without pins, any key is the scope's
	write(t, dir, "jane", strings.Replace(jane(), `"token_sha256": "`+digest(token)+`", `, "", 1))

	if s, err := certified(dir).Get("jane"); err != nil || !s.Pinned(key(a)) {
		t.Errorf("no pins, no token: %v", err)
	}

	if !ValidName("jane-blog") || ValidName("Jane") || ValidName("") {
		t.Error("ValidName")
	}
}
