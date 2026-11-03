// Package scope reads scopes: what one client of a scoped listener is, and owns. A scope is a JSON
// file, "<name>.json" in the listener's folder, written by whoever orchestrates the clients (the
// gate never writes one). It's read again whenever it changes, so adding, changing or removing a
// scope needs no restart.
package scope

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
)

// Scope is one client's identity and what it owns.
type Scope struct {
	// Name is the file's name, without ".json".
	Name string `json:"-"`
	// TokenSHA256 is the SHA-256 (hex) of the token the client sends. A scope with a socket of its
	// own needs none: whoever can open the socket is the scope.
	TokenSHA256 string `json:"token_sha256"`
	// Owner marks what the scope owns: every container, network and volume it creates carries this
	// label with this value, and only objects with it are its own.
	Owner Label `json:"owner"`
	// Prefixes are what the names of its containers, networks and volumes start with ("jane-",
	// "jane_"). Each ends with "-", "_" or ".", so "jane" never matches "janet".
	Prefixes []string `json:"prefixes"`
	// Images are the image name prefixes that are its own ("quire-sites/jane/"): it may name images
	// there even where the listener protects their namespace.
	Images []string `json:"images,omitempty"`
	// Networks are shared networks it may join, besides its own, with what it may have there.
	Networks map[string]Network `json:"networks,omitempty"`
	// Builders are its BuildKit builders, by exact name: containers the orchestrator created, which
	// it may only inspect and reach with "buildctl dial-stdio" (never its own, whatever their labels).
	Builders []string `json:"builders,omitempty"`
	// Containers was 0.1's key for containers a scope could use: refused, with why.
	Containers json.RawMessage `json:"containers,omitempty"`
	// Subnets, when set, are where its networks' addresses must be: each network it creates names
	// its subnet, inside one of these.
	Subnets []string `json:"subnets,omitempty"`

	subnets []netip.Prefix
	// The other scopes of its folder, as the store read them with it: the names and images that are
	// theirs rather than its own
	others []*Scope
}

// Network is what a scope may have on a shared network.
type Network struct {
	// Aliases it may take there (its DNS names); none if empty.
	Aliases []string `json:"aliases,omitempty"`
	// Addresses it may ask for there; none if empty (Docker assigns one).
	Addresses []string `json:"addresses,omitempty"`
}

// Label is a Docker label and its value.
type Label struct {
	Key   string `json:"label"`
	Value string `json:"value"`
}

var (
	validName   = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,62}$`)
	validLabel  = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)
	validValue  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
	validPrefix = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,62}[-_.]$`)
	validDigest = regexp.MustCompile(`^[0-9a-f]{64}$`)
	validImage  = regexp.MustCompile(`^[a-z0-9][a-z0-9._/-]{0,254}/$`)
	validObject = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$`)
	validAlias  = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)

	// recreated is the name Compose gives a container it recreates, until it removes the old one
	// and renames the new one to the old name: the first 12 hex of the old one's ID, _, its name.
	recreated = regexp.MustCompile(`^[0-9a-f]{12}_(.+)$`)
)

// ErrUnknown is a scope with no file, or a token that doesn't match it.
var ErrUnknown = errors.New("no such scope, or not its token")

// Store reads a folder of scope files. A scope is read together with the others: two may not share
// an owner label, a prefix or an image namespace (the one that came later is refused), and each
// knows the others' names, so a name belongs to the scope with the longest prefix it starts with.
type Store struct {
	dir string
	// Whether a scope may have no token (each has its own socket)
	tokenless bool

	mu     sync.Mutex
	loaded map[string]entry
	// What a request gets: each valid scope, knowing the others; or why a scope isn't valid
	views  map[string]*Scope
	errors map[string]error
}

type entry struct {
	modified time.Time
	size     int64
	// When this process first read the file: of two scopes that conflict, the earlier stays. Taken
	// from the file's modification time when it's first read, and kept when the file changes, so
	// rewriting an older scope (a new token) doesn't make it the later one.
	firstSeen time.Time
	scope     *Scope
	err       error
}

// NewStore reads scopes from a folder; each scope has a token.
func NewStore(dir string) *Store {
	return &Store{dir: dir, loaded: map[string]entry{}}
}

// NewSocketStore reads scopes from a folder for a listener where each scope has its own socket: a
// token is optional.
func NewSocketStore(dir string) *Store {
	return &Store{dir: dir, tokenless: true, loaded: map[string]entry{}}
}

// Authenticate returns the scope a request names, if its token is the scope's. Both a missing scope
// and a wrong token give ErrUnknown, so a client can't tell which scopes exist.
func (s *Store) Authenticate(name, token string) (*Scope, error) {
	if !validName.MatchString(name) || token == "" {
		return nil, ErrUnknown
	}

	scope, err := s.Get(name)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrUnknown
		}

		return nil, err
	}

	if scope.TokenSHA256 == "" {
		return nil, ErrUnknown
	}

	want, _ := hex.DecodeString(scope.TokenSHA256)
	got := sha256.Sum256([]byte(token))

	if subtle.ConstantTimeCompare(want, got[:]) != 1 {
		return nil, ErrUnknown
	}

	return scope, nil
}

// Get returns a scope as its folder has it now (each file read again only if it changed).
func (s *Store) Get(name string) (*Scope, error) {
	if !validName.MatchString(name) {
		return nil, fmt.Errorf("%q isn't a scope's name", name)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.scan(); err != nil {
		return nil, err
	}

	if err, ok := s.errors[name]; ok {
		return nil, err
	}

	if scope, ok := s.views[name]; ok {
		return scope, nil
	}

	return nil, fmt.Errorf("scope %s: %w", name, os.ErrNotExist)
}

// Scopes returns the names of the valid scopes as the folder has them now, and why each other scope
// file isn't valid.
func (s *Store) Scopes() ([]string, map[string]error, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.scan(); err != nil {
		return nil, nil, err
	}

	names := make([]string, 0, len(s.views))
	for name := range s.views {
		names = append(names, name)
	}

	sort.Strings(names)

	invalid := make(map[string]error, len(s.errors))
	for name, err := range s.errors {
		invalid[name] = err
	}

	return names, invalid, nil
}

// scan reads the folder's scope files that changed, and decides again which scopes are valid when
// any did.
func (s *Store) scan() error {
	files, err := os.ReadDir(s.dir)
	if err != nil {
		return err
	}

	changed := s.views == nil
	present := map[string]bool{}

	for _, f := range files {
		name, ok := strings.CutSuffix(f.Name(), ".json")
		if !ok || !validName.MatchString(name) {
			continue
		}

		path := filepath.Join(s.dir, f.Name())

		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return err
		}

		present[name] = true

		old, known := s.loaded[name]
		if known && old.modified.Equal(info.ModTime()) && old.size == info.Size() {
			continue
		}

		first := info.ModTime()
		if known {
			first = old.firstSeen
		}

		scope, err := read(path, info, s.tokenless)
		if scope != nil {
			scope.Name = name
		}

		s.loaded[name] = entry{modified: info.ModTime(), size: info.Size(), firstSeen: first, scope: scope, err: err}
		changed = true
	}

	for name := range s.loaded {
		if !present[name] {
			delete(s.loaded, name)

			changed = true
		}
	}

	if changed {
		s.resolve()
	}

	return nil
}

// resolve decides which scopes are valid: in the order they came, a scope that shares an owner
// label, a prefix or an image namespace with one before it is refused. Each valid scope is then
// given the others.
func (s *Store) resolve() {
	names := make([]string, 0, len(s.loaded))
	for name := range s.loaded {
		names = append(names, name)
	}

	sort.Slice(names, func(i, j int) bool {
		a, b := s.loaded[names[i]], s.loaded[names[j]]
		if !a.firstSeen.Equal(b.firstSeen) {
			return a.firstSeen.Before(b.firstSeen)
		}

		return names[i] < names[j]
	})

	s.errors = map[string]error{}
	owners, prefixes, images, builders := map[Label]string{}, map[string]string{}, map[string]string{}, map[string]string{}
	valid := []*Scope{}

	for _, name := range names {
		e := s.loaded[name]
		if e.err != nil {
			s.errors[name] = e.err

			continue
		}

		if err := conflict(e.scope, owners, prefixes, images, builders); err != nil {
			s.errors[name] = fmt.Errorf("scope file %s: %w", filepath.Join(s.dir, name+".json"), err)

			continue
		}

		owners[e.scope.Owner] = name
		for _, p := range e.scope.Prefixes {
			prefixes[p] = name
		}

		for _, i := range e.scope.Images {
			images[i] = name
		}

		for _, b := range e.scope.Builders {
			builders[b] = name
		}

		valid = append(valid, e.scope)
	}

	s.views = map[string]*Scope{}

	for _, scope := range valid {
		view := *scope
		view.others = make([]*Scope, 0, len(valid)-1)

		for _, other := range valid {
			if other != scope {
				view.others = append(view.others, other)
			}
		}

		s.views[scope.Name] = &view
	}
}

// conflict tells what a scope shares with the valid scopes before it.
func conflict(s *Scope, owners map[Label]string, prefixes, images, builders map[string]string) error {
	for _, b := range s.Builders {
		if other, ok := builders[b]; ok {
			return fmt.Errorf("builders: %q is scope %s's already", b, other)
		}
	}

	if other, ok := owners[s.Owner]; ok {
		return fmt.Errorf("owner: %s=%s is scope %s's already", s.Owner.Key, s.Owner.Value, other)
	}

	for _, p := range s.Prefixes {
		if other, ok := prefixes[p]; ok {
			return fmt.Errorf("prefixes: %q is scope %s's already", p, other)
		}
	}

	for _, i := range s.Images {
		if other, ok := images[i]; ok {
			return fmt.Errorf("images: %q is scope %s's already", i, other)
		}
	}

	return nil
}

func read(path string, info os.FileInfo, tokenless bool) (*Scope, error) {
	// Only a plain file that no one but its owner can change: a link could point anywhere.
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("scope file %s: must be a plain file, writable by its owner only", path)
	}

	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()

	var scope Scope
	if err := decoder.Decode(&scope); err != nil {
		return nil, fmt.Errorf("scope file %s: %w", path, err)
	}

	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("scope file %s: one JSON object only", path)
	}

	if err := scope.check(tokenless); err != nil {
		return nil, fmt.Errorf("scope file %s: %w", path, err)
	}

	return &scope, nil
}

func (s *Scope) check(tokenless bool) error {
	switch {
	case !validDigest.MatchString(s.TokenSHA256) && (s.TokenSHA256 != "" || !tokenless):
		return errors.New("token_sha256: the token's SHA-256, as 64 lowercase hex digits")
	case !validLabel.MatchString(s.Owner.Key):
		return errors.New("owner.label: a Docker label's name")
	case !validValue.MatchString(s.Owner.Value):
		return errors.New("owner.value: only letters, digits, _ . and - are allowed in it")
	case len(s.Prefixes) == 0:
		return errors.New("prefixes: at least one")
	}

	for _, i := range s.Images {
		if !validImage.MatchString(i) {
			return fmt.Errorf("images: %q must be an image name prefix ending with /", i)
		}
	}

	if s.Containers != nil {
		return errors.New("containers: replaced by builders (YorvoGate 0.2): exact names of BuildKit builders, which a scope may only inspect and reach with buildctl dial-stdio, never use as its own")
	}

	for _, b := range s.Builders {
		if !validObject.MatchString(b) {
			return fmt.Errorf("builders: %q must be a container's exact name (no wildcard)", b)
		}
	}

	for name, n := range s.Networks {
		if !validObject.MatchString(name) {
			return fmt.Errorf("networks: %q isn't a network's name", name)
		}

		for _, a := range n.Aliases {
			if !validAlias.MatchString(a) || len(a) > 253 {
				return fmt.Errorf("networks.%s.aliases: %q isn't a DNS name", name, a)
			}
		}

		for _, a := range n.Addresses {
			if ip, err := netip.ParseAddr(a); err != nil || ip.String() != a || ip.Zone() != "" {
				return fmt.Errorf("networks.%s.addresses: %q isn't an IP address (as Go writes it)", name, a)
			}
		}
	}

	for _, sn := range s.Subnets {
		prefix, err := netip.ParsePrefix(sn)
		if err != nil || prefix.Masked() != prefix || prefix.String() != sn {
			return fmt.Errorf("subnets: %q must be a network in CIDR form (e.g. 10.213.0.32/27)", sn)
		}

		s.subnets = append(s.subnets, prefix)
	}

	for _, p := range s.Prefixes {
		if !validPrefix.MatchString(p) {
			return fmt.Errorf("prefixes: %q must end with a separator (- _ or .) so no other name starts with it", p)
		}

		if recreated.MatchString(p + "x") {
			return fmt.Errorf("prefixes: %q starts like the name Compose gives a container it recreates (12 hex and _)", p)
		}
	}

	return nil
}

// Owns tells whether labels mark an object as this scope's.
func (s *Scope) Owns(labels map[string]string) bool {
	value, ok := labels[s.Owner.Key]

	return ok && value == s.Owner.Value
}

// OwnedByAnother tells whether labels mark an object as another scope's: a scope may label what it
// creates as its own only. (Scopes may use different owner labels, so having its own is no proof.)
func (s *Scope) OwnedByAnother(labels map[string]string) bool {
	for _, o := range s.others {
		if o.Owns(labels) {
			return true
		}
	}

	return false
}

// Contains tells whether a subnet is inside one of the scope's (true when it has none).
func (s *Scope) Contains(subnet netip.Prefix) bool {
	if len(s.subnets) == 0 {
		return true
	}

	for _, own := range s.subnets {
		if own.Contains(subnet.Addr()) && own.Bits() <= subnet.Bits() {
			return true
		}
	}

	return false
}

// HasSubnets tells whether its networks must name subnets of its own.
func (s *Scope) HasSubnets() bool {
	return len(s.subnets) > 0
}

// Builds tells whether a container is one of its builders, by exact name.
func (s *Scope) Builds(name string) bool {
	return slices.Contains(s.Builders, name)
}

// OwnsImage tells whether an image name is in one of its own namespaces: one it starts with, and no
// other scope's namespace it starts with is longer ("quire-sites/jane/blog/x" is scope jane-blog's
// while it exists, if its namespace is "quire-sites/jane/blog/").
func (s *Scope) OwnsImage(image string) bool {
	own := longest(s.Images, image)
	if own == 0 {
		return false
	}

	for _, o := range s.others {
		if longest(o.Images, image) > own {
			return false
		}
	}

	return true
}

// Names tells whether a name is the scope's: it starts with one of the scope's prefixes, and with no
// longer prefix of another scope's ("jane-blog-php-1" is scope jane-blog's while it exists, not
// jane's). Compose fixes the names (<project>-<service>-<n>), so tenants' names can nest.
func (s *Scope) Names(name string) bool {
	own := longest(s.Prefixes, name)
	if own == 0 {
		return false
	}

	for _, o := range s.others {
		if longest(o.Prefixes, name) > own {
			return false
		}
	}

	return true
}

// NamesContainer tells whether a new container's name is the scope's: one of its names, or the name
// Compose gives a container it recreates (<12 hex>_<name>) when <name> is one of them. No prefix
// starts like that, so the name is no other scope's.
func (s *Scope) NamesContainer(name string) bool {
	if s.Names(name) {
		return true
	}

	m := recreated.FindStringSubmatch(name)

	return m != nil && s.Names(m[1])
}

// longest is the length of the longest of the prefixes a name starts with (and goes beyond), or 0.
func longest(prefixes []string, name string) int {
	n := 0

	for _, p := range prefixes {
		if len(name) > len(p) && strings.HasPrefix(name, p) && len(p) > n {
			n = len(p)
		}
	}

	return n
}
