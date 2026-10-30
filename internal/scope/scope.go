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
	"os"
	"path/filepath"
	"regexp"
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

// Names tells whether a name starts with one of the scope's prefixes.
func (s *Scope) Names(name string) bool {
	for _, p := range s.Prefixes {
		if len(name) > len(p) && name[:len(p)] == p {
			return true
		}
	}

	return false
}
