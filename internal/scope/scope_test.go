package scope

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
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

func jane() string {
	return `{"token_sha256": "` + digest(token) + `", "owner": {"label": "com.docker.compose.project", "value": "jane"}, "prefixes": ["jane-", "jane_"]}`
}

func TestAScopeIsItsTokens(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "jane", jane())
	store := NewStore(dir)

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
	store := NewStore(dir)

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

	_ = os.Remove(path)

	if _, err := store.Authenticate("jane", "a-new-token"); !errors.Is(err, ErrUnknown) {
		t.Error("a removed scope still works")
	}
}

func TestScopeFilesAreChecked(t *testing.T) {
	cases := map[string]string{
		"an unknown key":         strings.Replace(jane(), `"prefixes"`, `"privileged": true, "prefixes"`, 1),
		"two objects":            jane() + jane(),
		"a token in clear":       strings.Replace(jane(), digest(token), token, 1),
		"an uppercase digest":    strings.Replace(jane(), digest(token), strings.ToUpper(digest(token)), 1),
		"no owner label":         strings.Replace(jane(), `"com.docker.compose.project"`, `""`, 1),
		"an owner value of any":  strings.Replace(jane(), `"value": "jane"`, `"value": "*"`, 1),
		"no prefixes":            strings.Replace(jane(), `["jane-", "jane_"]`, `[]`, 1),
		"a prefix of any name":   strings.Replace(jane(), `"jane-"`, `"jane"`, 1),
		"an empty prefix":        strings.Replace(jane(), `"jane-"`, `""`, 1),
		"an image not a prefix":  strings.Replace(jane(), `"prefixes"`, `"images": ["quire-sites/jane"], "prefixes"`, 1),
		"a container pattern":    strings.Replace(jane(), `"prefixes"`, `"containers": ["*"], "prefixes"`, 1),
		"a network pattern":      strings.Replace(jane(), `"prefixes"`, `"networks": {"quire-*": {}}, "prefixes"`, 1),
		"an alias with a space":  strings.Replace(jane(), `"prefixes"`, `"networks": {"link": {"aliases": ["a b"]}}, "prefixes"`, 1),
		"an address of a range":  strings.Replace(jane(), `"prefixes"`, `"networks": {"link": {"addresses": ["10.0.0.0/8"]}}, "prefixes"`, 1),
		"an address unshortened": strings.Replace(jane(), `"prefixes"`, `"networks": {"link": {"addresses": ["2001:db8:0:0::1"]}}, "prefixes"`, 1),
		"a network key unknown":  strings.Replace(jane(), `"prefixes"`, `"networks": {"link": {"mac": "x"}}, "prefixes"`, 1),
		"a subnet not a network": strings.Replace(jane(), `"prefixes"`, `"subnets": ["10.213.0.33/27"], "prefixes"`, 1),
		"an address as a subnet": strings.Replace(jane(), `"prefixes"`, `"subnets": ["10.213.0.32"], "prefixes"`, 1),
	}

	for name, content := range cases {
		dir := t.TempDir()
		write(t, dir, "jane", content)

		if _, err := NewStore(dir).Authenticate("jane", token); err == nil || errors.Is(err, ErrUnknown) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestOnlyPlainFilesOnlyItsOwnerWrites(t *testing.T) {
	dir := t.TempDir()
	path := write(t, dir, "jane", jane())

	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}

	if _, err := NewStore(dir).Authenticate("jane", token); err == nil {
		t.Error("a file anyone can write")
	}

	other := t.TempDir()
	target := write(t, other, "real", jane())

	if err := os.Symlink(target, filepath.Join(dir, "linked.json")); err != nil {
		t.Fatal(err)
	}

	if _, err := NewStore(dir).Authenticate("linked", token); err == nil {
		t.Error("a link")
	}
}

func TestWhatAScopeMayUse(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "jane", strings.Replace(jane(), `"prefixes"`, `"images": ["quire-sites/jane/"], "containers": ["buildx_buildkit_jane-*", "jane-tools"], "networks": {"quire-link-jane": {"aliases": ["jane.example.quire.internal"], "addresses": ["10.213.0.4"]}}, "prefixes"`, 1))

	s, err := NewStore(dir).Authenticate("jane", token)
	if err != nil {
		t.Fatal(err)
	}

	if !s.Uses("buildx_buildkit_jane-0") || !s.Uses("jane-tools") || s.Uses("buildx_buildkit_jane-") || s.Uses("jane-tools-2") || s.Uses("buildx_buildkit_blog-0") {
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

	s, err := NewStore(dir).Authenticate("jane", token)
	if err != nil {
		t.Fatal(err)
	}

	for subnet, inside := range map[string]bool{"10.213.0.32/27": true, "10.213.0.48/28": true, "10.213.0.0/24": false, "10.213.0.64/27": false, "fd00:213::/80": true, "fd00:214::/64": false} {
		if s.Contains(netip.MustParsePrefix(subnet)) != inside || !s.HasSubnets() {
			t.Errorf("%s: inside %v", subnet, !inside)
		}
	}

	write(t, dir, "free", jane())
	free, _ := NewStore(dir).Authenticate("free", token)
	if free.HasSubnets() || !free.Contains(netip.MustParsePrefix("172.20.0.0/16")) {
		t.Error("a scope without subnets takes Docker's")
	}
}
