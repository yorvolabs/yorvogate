// Package scope reads scopes: what one client of a scoped listener is, and owns. A scope is a JSON
// file, "<name>.json" in the listener's folder, written by whoever orchestrates the clients (the
// gate never writes one). The Registry reads the folders again on reload, so adding, changing or
// removing a scope needs no restart.
package scope

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"regexp"
	"slices"
	"sort"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"
)

// Scope is one client's identity and what it owns.
type Scope struct {
	// Name is the file's name, without ".json".
	Name string `json:"-"`
	// Version is the format: 1. Without it, a scope file is read as 1 with a warning until 0.4,
	// which refuses it.
	Version *int `json:"version,omitempty"`
	// TokenSHA256 is the SHA-256 (hex) of the token the client sends. A scope with a socket of its
	// own needs none: whoever can open the socket is the scope.
	TokenSHA256 string `json:"token_sha256"`
	// Tokens are more tokens, besides token_sha256, each with an optional expiry: two are valid
	// during a rotation, and one past its expiry is refused like a wrong one.
	Tokens []Token `json:"tokens,omitempty"`
	// PeerUIDs (a listener on a unix address): when listed, a request is the scope only over a
	// connection from one of these users (the socket's peer, as the kernel says).
	PeerUIDs []uint32 `json:"peer_uids,omitempty"`
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
	// Certificates (on an mTLS listener) are its client certificates' public keys: when listed, only
	// a certificate with one of them is the scope, so one is revoked by removing it, and two are
	// valid during a rotation. Without them, any certificate the listener's CA issues with the scope's
	// name is the scope.
	Certificates []Pin `json:"certificates,omitempty"`
	// Egress "none" keeps its containers off every network with a way out: each network they join,
	// its own or shared, must be internal, and so must its builders'. Its listener may require it of
	// every scope (containers.egress).
	Egress string `json:"egress,omitempty"`

	subnets []netip.Prefix
	// Every scope's claims, on every listener, as the registry resolved them with it: the names,
	// images and labels that are another scope's rather than its own
	index *index
}

// Network is what a scope may have on a shared network.
type Network struct {
	// Aliases it may take there (its DNS names); none if empty.
	Aliases []string `json:"aliases,omitempty"`
	// Addresses it may ask for there; none if empty (Docker assigns one).
	Addresses []string `json:"addresses,omitempty"`
}

// NormaliseAlias is an alias as Docker's DNS keeps it: lowercased (Docker keys each name by its
// lowercase form, and lowercases a query). It isn't one (false) with a byte outside ASCII, where
// lowercasing is Unicode's and not a DNS rule, or with a trailing ".", which Docker keeps in the name
// it stores (only a query's is dropped, so "web." is another name than "web"), or with a label of a
// container ID's form (idLike). The gate's checks and
// the registry's claims both read an alias through this.
func NormaliseAlias(a string) (string, bool) {
	if a == "" || strings.HasSuffix(a, ".") {
		return "", false
	}

	for i := range len(a) {
		if a[i] >= utf8.RuneSelf {
			return "", false
		}
	}

	a = strings.ToLower(a)
	if idLike(a) {
		return "", false
	}

	return a, true
}

// idLike tells whether an alias has a label of a container ID's form, 12 or 64 hex digits: Docker
// gives each container its short ID as a DNS name too, so an alias of that form on a shared network
// would answer for another tenant's container by its ID. Compose never gives one.
func idLike(alias string) bool {
	for label := range strings.SplitSeq(alias, ".") {
		if (len(label) == 12 || len(label) == 64) && strings.Trim(label, "0123456789abcdef") == "" {
			return true
		}
	}

	return false
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
	// An alias as Docker's DNS keys it (lowercase), with what Compose puts in one: labels of letters,
	// digits, "-" and "_" (a project named demo_x gives demo_x-php-1)
	validAlias = regexp.MustCompile(`^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)*$`)

	// recreated is the name Compose gives a container it recreates, until it removes the old one
	// and renames the new one to the old name: the first 12 hex of the old one's ID, _, its name.
	recreated = regexp.MustCompile(`^[0-9a-f]{12}_(.+)$`)
)

// Token is a token's SHA-256 (hex), and when it stops being one (RFC 3339; never when unset).
type Token struct {
	SHA256  string `json:"sha256"`
	Expires string `json:"expires,omitempty"`

	expires time.Time // parsed; zero: never
}

// MaxTokens is how many tokens a scope may have, token_sha256 included.
const MaxTokens = 8

// tokens is every token of the scope, token_sha256 first.
func (s *Scope) tokens() []Token {
	all := make([]Token, 0, len(s.Tokens)+1)
	if s.TokenSHA256 != "" {
		all = append(all, Token{SHA256: s.TokenSHA256})
	}

	return append(all, s.Tokens...)
}

// expired tells whether a token has stopped being one at a time.
func (t Token) expired(now time.Time) bool {
	return !t.expires.IsZero() && !now.Before(t.expires)
}

// TokenCurrent tells whether a token's digest (hex) is still one of the scope's, and not expired.
// A stream allowed with a token goes on while it is.
func (s *Scope) TokenCurrent(digest string, now time.Time) bool {
	for _, t := range s.tokens() {
		if t.SHA256 == digest && !t.expired(now) {
			return true
		}
	}

	return false
}

// Expiring is the scope's tokens that have expired at a time, and those that will within a while:
// each named by the first 12 digits of its digest.
func (s *Scope) Expiring(now time.Time, within time.Duration) (expired, soon []string) {
	for _, t := range s.Tokens {
		switch {
		case t.expired(now):
			expired = append(expired, t.SHA256[:12])
		case t.expired(now.Add(within)):
			soon = append(soon, t.SHA256[:12])
		}
	}

	return expired, soon
}

// PeerAllowed tells whether a connection's peer user may be the scope: any when it lists none.
func (s *Scope) PeerAllowed(uid uint32, known bool) bool {
	return len(s.PeerUIDs) == 0 || known && slices.Contains(s.PeerUIDs, uid)
}

// Pin is a certificate's public key: the SHA-256 (hex) of its SubjectPublicKeyInfo.
type Pin struct {
	SHA256 string `json:"sha256"`
}

// MaxCertificates is how many certificates a scope may pin.
const MaxCertificates = 8

// Pinned tells whether a certificate's public key (its SubjectPublicKeyInfo's SHA-256) is the
// scope's: one it pins, or any when it pins none. Every pin is compared, in constant time.
func (s *Scope) Pinned(spki [sha256.Size]byte) bool {
	if len(s.Certificates) == 0 {
		return true
	}

	found := 0

	for _, p := range s.Certificates {
		want, _ := hex.DecodeString(p.SHA256)
		found |= subtle.ConstantTimeCompare(want, spki[:])
	}

	return found == 1
}

// ValidName tells whether a name is a scope's name, as a scope file's is.
func ValidName(name string) bool {
	return validName.MatchString(name)
}

// ErrUnknown is a scope with no file, or a token that doesn't match it.
var ErrUnknown = errors.New("no such scope, or not its token")

// compareTokens compares a token's digest with a scope's, in constant time (a test counts its calls).
var compareTokens = subtle.ConstantTimeCompare

// clock is the time tokens expire by (a test sets it).
var clock = time.Now

// Store is one scoped listener's scopes: its folder, as the registry's snapshot has it. It reads
// no file: Registry.Reload does.
type Store struct {
	registry *Registry
	folder   int
}

// Authenticate returns the scope a request names, if its token is one of the scope's and hasn't
// expired. A missing scope, one whose file isn't valid, a wrong token and an expired one all give
// ErrUnknown, in the same time: the token is compared with MaxTokens digests whatever the scope has
// (random ones in place of those it doesn't), so a client can tell neither which scopes exist, nor
// how many tokens one has, nor which matched. A file that isn't valid is said why in what's wrapped
// (for the log only).
func (s *Store) Authenticate(name, token string) (*Scope, error) {
	if !validName.MatchString(name) || token == "" {
		return nil, ErrUnknown
	}

	// The token is hashed and compared whether or not the scope has one: a scope that isn't there
	// takes as long to refuse as a wrong token.
	got := sha256.Sum256([]byte(token))

	var (
		scope   *Scope
		err     error
		unknown = errUnreadUnknown
	)

	if view := s.view(); view == nil {
		err = errUnread
	} else {
		scope, err = view.get(name)
		unknown = view.unknown[name] // nil when it's there or missing
		if unknown == nil {
			unknown = ErrUnknown
		}
	}

	// The scope's tokens in MaxTokens slots, the rest random: filled without allocating, so a scope
	// that's there allocates as one that isn't
	var slots [MaxTokens]Token

	n := 0
	if err == nil {
		if scope.TokenSHA256 != "" {
			slots[0], n = Token{SHA256: scope.TokenSHA256}, 1
		}

		n += copy(slots[n:], scope.Tokens)
	}

	// Every slot is compared, and which matched is kept without a branch on it
	now, matches := clock(), 0

	for i := range MaxTokens {
		digest, current := noToken, 0
		if i < n {
			digest = slots[i].SHA256
			if !slots[i].expired(now) {
				current = 1
			}
		}

		want, _ := hex.DecodeString(digest)
		matches |= compareTokens(want, got[:]) & current
	}

	switch {
	case err != nil:
		return nil, unknown
	case matches != 1:
		return nil, ErrUnknown
	}

	return scope, nil
}

// noToken is the digest a token is compared with when its scope has none: random, so no token
// matches it.
var noToken = func() string {
	var sum [sha256.Size]byte
	if _, err := rand.Read(sum[:]); err != nil {
		panic(err)
	}

	return hex.EncodeToString(sum[:])
}()

// Get returns a scope as the last reload found it.
func (s *Store) Get(name string) (*Scope, error) {
	if !validName.MatchString(name) {
		return nil, fmt.Errorf("%q isn't a scope's name", name)
	}

	view := s.view()
	if view == nil {
		return nil, errUnread
	}

	return view.get(name)
}

var (
	// errMissing is a scope that isn't there; errUnread, a lookup before the first reload. Each is
	// made once, as a file's error is made at its reload: a lookup that misses allocates nothing,
	// so it takes as long as one that finds.
	errMissing = fmt.Errorf("no such scope: %w", os.ErrNotExist)
	errUnread  = errors.New("the scope files haven't been read yet")
	// errUnreadUnknown is errUnread as Authenticate gives it
	errUnreadUnknown = fmt.Errorf("%w: %w", ErrUnknown, errUnread)
)

// view is the listener's folder as the last reload found it, or nil before the first.
func (s *Store) view() *folderView {
	snap := s.registry.snapshot.Load()
	if snap == nil {
		return nil
	}

	return &snap.folders[s.folder]
}

// get returns the scope a name is, or why it isn't one. Every error was made when the files were
// read.
func (v *folderView) get(name string) (*Scope, error) {
	if err, ok := v.errors[name]; ok {
		return nil, err
	}

	if scope, ok := v.views[name]; ok {
		return scope, nil
	}

	return nil, errMissing
}

// Unversioned names the valid scopes whose files have no version: read as version 1 until 0.4, which
// refuses them.
func (s *Store) Unversioned() []string {
	snap := s.registry.snapshot.Load()
	if snap == nil {
		return nil
	}

	return slices.Clone(snap.folders[s.folder].unversioned)
}

// Scopes returns the names of the valid scopes as the last reload found them, and why each other
// scope file isn't valid.
func (s *Store) Scopes() ([]string, map[string]error, error) {
	snap := s.registry.snapshot.Load()
	if snap == nil {
		return nil, nil, errors.New("the scope files haven't been read yet")
	}

	view := snap.folders[s.folder]

	names := make([]string, 0, len(view.views))
	for name := range view.views {
		names = append(names, name)
	}

	sort.Strings(names)

	invalid := make(map[string]error, len(view.errors))
	for name, err := range view.errors {
		invalid[name] = err
	}

	return names, invalid, nil
}

// read reads a scope file's content. The file is opened once, and what's checked (a plain file, its
// mode) is what's read: the descriptor's, not the path's, which can be swapped between a check and
// the read. It returns the file's information as the descriptor has it (nil if it couldn't be
// opened).
func read(path string) ([]byte, os.FileInfo, error) {
	notPlain := fmt.Errorf("scope file %s: must be a plain file, writable by its owner only", path)

	// Never through a link (it could point anywhere), and never waiting on a pipe put in its place
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, syscall.ELOOP) {
		return nil, nil, notPlain
	} else if err != nil {
		return nil, nil, err
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return nil, nil, err
	}

	if !info.Mode().IsRegular() {
		return nil, info, notPlain
	}

	// A scope file is a few hundred bytes; one larger than any scope needs isn't one.
	content, err := io.ReadAll(io.LimitReader(file, maxFile+1))
	if err == nil && len(content) > maxFile {
		return nil, info, fmt.Errorf("scope file %s: larger than %d bytes", path, maxFile)
	}

	return content, info, err
}

// maxFile is the largest scope file read: far more than any scope needs.
const maxFile = 1 << 20

func parse(path string, content []byte, info os.FileInfo, f Folder) (*Scope, error) {
	// Only a file that no one but its owner can change
	if info.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("scope file %s: must be a plain file, writable by its owner only", path)
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

	if err := scope.check(f); err != nil {
		return nil, fmt.Errorf("scope file %s: %w", path, err)
	}

	return &scope, nil
}

// checkTokens: at most MaxTokens, token_sha256 included, each a digest listed once. One that has
// expired is kept, and refused when sent: check names it.
func (s *Scope) checkTokens() error {
	if len(s.tokens()) > MaxTokens {
		return fmt.Errorf("tokens: at most %d, token_sha256 included", MaxTokens)
	}

	for i, t := range s.Tokens {
		if t.Expires == "" {
			continue
		}

		expires, err := time.Parse(time.RFC3339, t.Expires)
		if err != nil {
			return fmt.Errorf("tokens: expires %q must be a time in RFC 3339 (2026-12-01T00:00:00Z)", t.Expires)
		}

		s.Tokens[i].expires = expires
	}

	seen := map[string]bool{}

	for _, t := range s.tokens() {
		if !validDigest.MatchString(t.SHA256) {
			return fmt.Errorf("tokens: %q must be a token's SHA-256, as 64 lowercase hex digits", t.SHA256)
		}

		if seen[t.SHA256] {
			return fmt.Errorf("tokens: %s is listed twice (token_sha256 included)", t.SHA256)
		}

		seen[t.SHA256] = true
	}

	return nil
}

// MaxPeerUIDs is how many users a scope may list.
const MaxPeerUIDs = 32

// checkPeers: peer_uids only where every listener of the folder is on a unix address, each listed
// once; and on a listener that requires them, at least one.
func (s *Scope) checkPeers(f Folder) error {
	switch {
	case len(s.PeerUIDs) > 0 && !f.PeerUIDs:
		return fmt.Errorf("peer_uids: only a scope whose listeners are all on a unix address has them (listener %s, or another serving its folder, is on TCP or scope_sockets)", f.Listener)
	case len(s.PeerUIDs) == 0 && f.RequirePeerUIDs:
		return fmt.Errorf("peer_uids: listener %s requires them (require_peer_uids)", f.Listener)
	case len(s.PeerUIDs) > MaxPeerUIDs:
		return fmt.Errorf("peer_uids: at most %d", MaxPeerUIDs)
	}

	seen := map[uint32]bool{}

	for _, uid := range s.PeerUIDs {
		if seen[uid] {
			return fmt.Errorf("peer_uids: %d is listed twice", uid)
		}

		seen[uid] = true
	}

	return nil
}

// formatVersion is the scope files' format (config.FormatVersion: the two move together).
const formatVersion = 1

func (s *Scope) check(f Folder) error {
	tokenless := f.Tokenless

	if s.Version != nil && *s.Version != formatVersion {
		return fmt.Errorf("version: %d isn't a format this build reads (%d)", *s.Version, formatVersion)
	}

	switch {
	case s.TokenSHA256 != "" && !validDigest.MatchString(s.TokenSHA256),
		s.TokenSHA256 == "" && len(s.Tokens) == 0 && !tokenless:
		return errors.New("token_sha256: the token's SHA-256, as 64 lowercase hex digits (or tokens)")
	case !validLabel.MatchString(s.Owner.Key):
		return errors.New("owner.label: a Docker label's name")
	case !validValue.MatchString(s.Owner.Value):
		return errors.New("owner.value: only letters, digits, _ . and - are allowed in it")
	case len(s.Prefixes) == 0:
		return errors.New("prefixes: at least one")
	case s.Egress != "" && s.Egress != "none":
		return fmt.Errorf("egress: %q isn't one (only none, or leave it out)", s.Egress)
	}

	if err := s.checkTokens(); err != nil {
		return err
	}

	if err := s.checkPeers(f); err != nil {
		return err
	}

	if len(s.Certificates) > 0 && !f.Certificates {
		return fmt.Errorf("certificates: only a scope on an mTLS listener has them (listener %s has no tls.client_ca)", f.Listener)
	}

	if len(s.Certificates) > MaxCertificates {
		return fmt.Errorf("certificates: at most %d", MaxCertificates)
	}

	pins := map[string]bool{}
	for _, p := range s.Certificates {
		if !validDigest.MatchString(p.SHA256) {
			return fmt.Errorf("certificates: %q must be a public key's SHA-256, as 64 lowercase hex digits", p.SHA256)
		}

		if pins[p.SHA256] {
			return fmt.Errorf("certificates: %s is listed twice", p.SHA256)
		}

		pins[p.SHA256] = true
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
			if !validAlias.MatchString(a) || len(a) > 253 || idLike(a) {
				return fmt.Errorf("networks.%s.aliases: %q isn't a name as Docker's DNS keeps it (lowercase letters, digits, - and _; labels of 1 to 63, 253 in all; none of a container ID's form, 12 hex digits)", name, a)
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

// OwnedByAnother tells whether labels mark an object as another scope's, on any listener: a scope may
// label what it creates as its own only. (Scopes may use different owner labels, so having its own is
// no proof.) A scope whose file isn't valid now still owns its label here.
func (s *Scope) OwnedByAnother(labels map[string]string) bool {
	if s.index == nil {
		return false
	}

	for key, value := range labels {
		if owner, ok := s.index.owners[Label{key, value}]; ok && owner != s.Name {
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
// while it exists, if its namespace is "quire-sites/jane/blog/"), on any listener.
func (s *Scope) OwnsImage(image string) bool {
	own := longest(s.Images, image)
	if own == 0 {
		return false
	}

	return s.index == nil || !s.index.longer(s.index.images, s.Name, image, own, '/')
}

// Names tells whether a name is the scope's: it starts with one of the scope's prefixes, and with no
// longer prefix of another scope's, on any listener ("jane-blog-php-1" is scope jane-blog's while it
// exists, not jane's). Compose fixes the names (<project>-<service>-<n>), so tenants' names can nest.
func (s *Scope) Names(name string) bool {
	own := longest(s.Prefixes, name)
	if own == 0 {
		return false
	}

	return s.index == nil || !s.index.longer(s.index.prefixes, s.Name, name, own, '-', '_', '.')
}

// longer tells whether another scope claims a prefix of name longer than own. Prefixes end with a
// separator, so only those ends are looked up: the cost is the name's length, not the scopes' count.
func (x *index) longer(claimed map[string]string, self, name string, own int, separators ...byte) bool {
	for n := own + 1; n < len(name); n++ {
		if !slices.Contains(separators, name[n-1]) {
			continue
		}

		if owner, ok := claimed[name[:n]]; ok && owner != self {
			return true
		}
	}

	return false
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
