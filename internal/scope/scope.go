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
	"strings"
	"sync"
	"time"
)

// Scope is one client's identity and what it owns.
type Scope struct {
	// Name is the file's name, without ".json".
	Name string `json:"-"`
	// TokenSHA256 is the SHA-256 (hex) of the token the client sends.
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
	// Containers are containers it may use that aren't its own by label (e.g. its BuildKit
	// builder), by name; a trailing "*" matches any end ("buildx_buildkit_jane-*").
	Containers []string `json:"containers,omitempty"`
	// Subnets, when set, are where its networks' addresses must be: each network it creates names
	// its subnet, inside one of these.
	Subnets []string `json:"subnets,omitempty"`

	subnets []netip.Prefix
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
	validObject = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}\*?$`)
	validAlias  = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)
)

// ErrUnknown is a scope with no file, or a token that doesn't match it.
var ErrUnknown = errors.New("no such scope, or not its token")

// Store reads a folder of scope files.
type Store struct {
	dir string

	mu     sync.Mutex
	loaded map[string]entry
}

type entry struct {
	modified time.Time
	size     int64
	scope    *Scope
	err      error
}

// NewStore reads scopes from a folder.
func NewStore(dir string) *Store {
	return &Store{dir: dir, loaded: map[string]entry{}}
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

	want, _ := hex.DecodeString(scope.TokenSHA256)
	got := sha256.Sum256([]byte(token))

	if subtle.ConstantTimeCompare(want, got[:]) != 1 {
		return nil, ErrUnknown
	}

	return scope, nil
}

// Get reads a scope (again only if its file changed).
func (s *Store) Get(name string) (*Scope, error) {
	if !validName.MatchString(name) {
		return nil, fmt.Errorf("%q isn't a scope's name", name)
	}

	path := filepath.Join(s.dir, name+".json")
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if e, ok := s.loaded[name]; ok && e.modified.Equal(info.ModTime()) && e.size == info.Size() {
		return e.scope, e.err
	}

	scope, err := read(path, info)
	if scope != nil {
		scope.Name = name
	}

	s.loaded[name] = entry{modified: info.ModTime(), size: info.Size(), scope: scope, err: err}

	return scope, err
}

func read(path string, info os.FileInfo) (*Scope, error) {
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

	if err := scope.check(); err != nil {
		return nil, fmt.Errorf("scope file %s: %w", path, err)
	}

	return &scope, nil
}

func (s *Scope) check() error {
	switch {
	case !validDigest.MatchString(s.TokenSHA256):
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

	for _, c := range s.Containers {
		if !validObject.MatchString(c) {
			return fmt.Errorf("containers: %q must be a container's name, or its start followed by *", c)
		}
	}

	for name, n := range s.Networks {
		if !validObject.MatchString(name) || strings.HasSuffix(name, "*") {
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
	}

	return nil
}

// Owns tells whether labels mark an object as this scope's.
func (s *Scope) Owns(labels map[string]string) bool {
	value, ok := labels[s.Owner.Key]

	return ok && value == s.Owner.Value
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

// Uses tells whether a container that isn't its own by label is one it may use, by name.
func (s *Scope) Uses(name string) bool {
	for _, c := range s.Containers {
		if start, ok := strings.CutSuffix(c, "*"); ok {
			if strings.HasPrefix(name, start) && len(name) > len(start) {
				return true
			}
		} else if name == c {
			return true
		}
	}

	return false
}

// OwnsImage tells whether an image name is in one of its own namespaces.
func (s *Scope) OwnsImage(image string) bool {
	for _, i := range s.Images {
		if strings.HasPrefix(image, i) && len(image) > len(i) {
			return true
		}
	}

	return false
}

// Names tells whether a name starts with one of the scope's prefixes.
func (s *Scope) Names(name string) bool {
	for _, p := range s.Prefixes {
		if len(name) > len(p) && name[:len(p)] == p {
			return true
		}
	}

	return false
}
