package scope

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

// Folder is one scoped listener's folder of scope files.
type Folder struct {
	// Listener is the listener's name, for messages.
	Listener string
	// Dir is the folder.
	Dir string
	// Tokenless: each scope has its own socket, so a token is optional.
	Tokenless bool
}

// Registry holds the scopes of every scoped listener in front of one Docker, as one immutable
// snapshot. The listeners share that Docker, so a scope's claims (its owner label, prefixes, image
// namespaces and builders) are decided across all of them: no two scopes share a claim, and a name
// belongs to the scope with the longest prefix it starts with, whichever listener that scope is on.
// A scope name is one scope: the same name in two folders (one folder served by token and by
// socket) is the same client either way.
//
// Reload reads the folders and swaps in a new snapshot; a request reads the snapshot and touches no
// file. A scope's claims are held for as long as its file exists: a file that becomes invalid, or
// is refused, keeps its last valid claims reserved (no other scope gets its names), so a half-written
// file never hands its names to a neighbour. With a state file the held claims survive a restart.
type Registry struct {
	folders []Folder
	state   string
	// Whether the state file is only read (yorvogate check), never written
	readOnly bool

	mu sync.Mutex
	// Per folder, what each file held when it was last read
	loaded []map[string]entry
	// Whether a file changed since the last snapshot
	dirty bool
	// Each scope's last accepted claims, by name; read from the state file once
	held     map[string]claims
	heldRead bool
	stateErr error
	writeErr error
	missing  []string
	snapshot atomic.Pointer[snapshot]
	// Snapshots swapped in so far
	generation uint64

	// What Status answers: the snapshot whose sockets are in line with it too (Publish), and a
	// channel closed when the next is published
	published struct {
		sync.Mutex
		snap *snapshot
		next chan struct{}
	}
	// Asks for a reload now (one pending at most)
	requests chan struct{}
}

type entry struct {
	// The SHA-256 of what was read ("" when nothing could be), and the mode it was read with: what a
	// scope file says and whether it may say it. Nothing of when it was written: a file rewritten
	// within one tick of the clock, or copied with its times kept, has the old time.
	digest string
	mode   os.FileMode
	scope  *Scope
	err    error
}

// claims are what a scope has that no other scope may have.
type claims struct {
	Owner    Label    `json:"owner"`
	Prefixes []string `json:"prefixes"`
	Images   []string `json:"images,omitempty"`
	Builders []string `json:"builders,omitempty"`
}

type snapshot struct {
	// How many snapshots were swapped in before this one, and it
	generation uint64
	folders    []folderView
	reserved   []string
}

type folderView struct {
	views  map[string]*Scope
	errors map[string]error
	// The SHA-256 of each scope file, as read
	digests map[string]string
	// The valid scopes whose files have no version
	unversioned []string
}

// index is every claim of the snapshot (accepted and reserved), by what is claimed: whose it is.
type index struct {
	owners   map[Label]string
	prefixes map[string]string
	images   map[string]string
	builders map[string]string
}

// NewRegistry holds the scopes of folders. A state file (optional, "" for none) keeps the claims
// held across restarts; it's YorvoGate's own, outside every scopes folder.
func NewRegistry(folders []Folder, state string) *Registry {
	loaded := make([]map[string]entry, len(folders))
	for i := range loaded {
		loaded[i] = map[string]entry{}
	}

	r := &Registry{folders: folders, state: state, loaded: loaded, dirty: true, requests: make(chan struct{}, 1)}
	r.published.next = make(chan struct{})

	return r
}

// ReadOnly makes the registry read its state file but never write it (for yorvogate check, which
// must not change what a running gate holds).
func (r *Registry) ReadOnly() *Registry {
	r.readOnly = true

	return r
}

// Store is one listener's view of the registry.
func (r *Registry) Store(listener string) *Store {
	for i, f := range r.folders {
		if f.Listener == listener {
			return &Store{registry: r, folder: i}
		}
	}

	return nil
}

// Reload reads the scope files that changed and, when any did, swaps in a new snapshot. When a
// folder can't be read, the snapshot in use stays, and the error says why. A state file that can't
// be written isn't an error here: StateProblem tells it.
func (r *Registry) Reload() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if !r.heldRead {
		r.held, r.stateErr = readState(r.state)
		r.heldRead = true
	}

	first := r.snapshot.Load() == nil
	r.missing = nil

	for i, f := range r.folders {
		changed, err := scanFolder(f, r.loaded[i])
		if first && errors.Is(err, os.ErrNotExist) {
			// At the start, a folder not there yet has no scopes. Later, a folder that goes away is
			// an error: the snapshot in use stays, rather than its scopes' claims being released.
			r.missing = append(r.missing, f.Dir)

			continue
		} else if err != nil {
			return fmt.Errorf("listener %s: %w", f.Listener, err)
		}

		r.dirty = r.dirty || changed
	}

	if !r.dirty {
		return nil
	}

	// While a folder is missing, which scopes it had is unknown: every claim held stays reserved.
	snap, held := resolve(r.folders, r.loaded, r.held, len(r.missing) > 0)
	r.generation++
	snap.generation = r.generation
	r.snapshot.Store(snap)
	r.dirty = false

	if !equalHeld(held, r.held) {
		r.held = held

		if r.state != "" && !r.readOnly {
			// The snapshot is in use either way; StateProblem tells the error until a write works.
			r.writeErr = writeState(r.state, held)
		}
	}

	return nil
}

// StateProblem tells why the state file couldn't be read or written, if it couldn't: held claims
// then last only as long as the process.
func (r *Registry) StateProblem() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	return errors.Join(r.stateErr, r.writeErr)
}

// Reserved names the scopes whose files exist but aren't valid now, whose last valid claims are
// held for them.
func (r *Registry) Reserved() []string {
	snap := r.snapshot.Load()
	if snap == nil {
		return nil
	}

	return slices.Clone(snap.reserved)
}

// Missing names the scopes folders that didn't exist at the start (read as empty).
func (r *Registry) Missing() []string {
	r.mu.Lock()
	defer r.mu.Unlock()

	return slices.Clone(r.missing)
}

// scanFolder reads a folder's scope files, every one, every scan: a file is parsed again when what
// it says (its SHA-256) or its mode changed since it was last read.
func scanFolder(f Folder, loaded map[string]entry) (bool, error) {
	files, err := os.ReadDir(f.Dir)
	if err != nil {
		return false, err
	}

	changed := false
	present := map[string]bool{}

	for _, file := range files {
		name, ok := strings.CutSuffix(file.Name(), ".json")
		if !ok || !validName.MatchString(name) {
			continue
		}

		path := filepath.Join(f.Dir, file.Name())

		content, info, err := read(path)
		if errors.Is(err, os.ErrNotExist) {
			// Removed since the folder was read
			continue
		}

		present[name] = true

		digest, mode := "", os.FileMode(0)
		if err == nil {
			sum := sha256.Sum256(content)
			digest, mode = hex.EncodeToString(sum[:]), info.Mode()
		}

		old, known := loaded[name]
		if known && digest != "" && old.digest == digest && old.mode == mode {
			continue
		}

		// A file that still can't be read, for the same reason, is no change either
		if known && err != nil && old.digest == "" && old.err != nil && old.err.Error() == err.Error() {
			continue
		}

		var scope *Scope
		if err == nil {
			scope, err = parse(path, content, info, f.Tokenless)
		}

		if scope != nil {
			scope.Name = name
		}

		loaded[name] = entry{digest: digest, mode: mode, scope: scope, err: err}
		changed = true
	}

	for name := range loaded {
		if !present[name] {
			delete(loaded, name)

			changed = true
		}
	}

	return changed, nil
}

// kinds are the kinds of claim, in the order a refusal looks at them.
var kinds = []string{"builders", "owner", "prefixes", "images"}

// claim is one thing a scope claims: its kind ("owner", "prefixes", "images", "builders") and key.
type claim struct{ kind, key string }

func (c claims) each(yield func(claim)) {
	yield(claim{"owner", c.Owner.Key + "=" + c.Owner.Value})

	for _, p := range c.Prefixes {
		yield(claim{"prefixes", p})
	}

	for _, i := range c.Images {
		yield(claim{"images", i})
	}

	for _, b := range c.Builders {
		yield(claim{"builders", b})
	}
}

func (c claims) has(want claim) bool {
	found := false

	c.each(func(x claim) { found = found || x == want })

	return found
}

// union adds a scope's claims to c (one name's files in two folders are one scope).
func (c claims) union(s *Scope) claims {
	if c.Owner == (Label{}) {
		c.Owner = s.Owner
	}

	add := func(to []string, from []string) []string {
		for _, x := range from {
			if !slices.Contains(to, x) {
				to = append(to, x)
			}
		}

		return to
	}

	c.Prefixes = add(slices.Clone(c.Prefixes), s.Prefixes)
	c.Images = add(slices.Clone(c.Images), s.Images)
	c.Builders = add(slices.Clone(c.Builders), s.Builders)

	return c
}

// resolve decides which scopes are valid, and the claims held from now on.
//
// Each name with a valid file claims what its files say; a name whose files exist but none is
// valid keeps the claims held for it (reserved: it can't act, but no one else gets them). Where
// names collide on a claim, the one that already held it keeps it and the others are refused; where
// none held it (two new scopes, or a restart without a state file), all of them are refused. A
// refused scope's held claims stay reserved. Nothing depends on files' times, so the same files and
// the same held claims always resolve the same way.
func resolve(folders []Folder, loaded []map[string]entry, held map[string]claims, keepHeld bool) (*snapshot, map[string]claims) {
	present := map[string]bool{}
	valid := map[string]claims{}

	if keepHeld {
		for name := range held {
			present[name] = true
		}
	}

	for _, files := range loaded {
		for name, e := range files {
			present[name] = true

			if e.err == nil {
				valid[name] = valid[name].union(e.scope)
			}
		}
	}

	names := make([]string, 0, len(present))
	for name := range present {
		names = append(names, name)
	}

	sort.Strings(names)

	refused := map[string]error{}

	var proposed map[string]claims

	for {
		proposed = map[string]claims{}

		for _, name := range names {
			if c, ok := valid[name]; ok && refused[name] == nil {
				proposed[name] = c
			} else if h, ok := held[name]; ok {
				proposed[name] = h
			}
		}

		claimants := map[claim][]string{}

		for _, name := range names {
			if c, ok := proposed[name]; ok {
				c.each(func(x claim) { claimants[x] = append(claimants[x], name) })
			}
		}

		more := false

		// In a fixed order, so a scope's refusal always names the same claim (its first in the file)
		keys := slices.SortedFunc(maps.Keys(claimants), func(a, b claim) int {
			if a.kind != b.kind {
				return slices.Index(kinds, a.kind) - slices.Index(kinds, b.kind)
			}

			return strings.Compare(a.key, b.key)
		})

		for _, x := range keys {
			who := claimants[x]
			if len(who) < 2 {
				continue
			}

			var incumbents []string

			for _, name := range who {
				if h, ok := held[name]; ok && h.has(x) {
					incumbents = append(incumbents, name)
				}
			}

			for _, name := range who {
				if _, ok := valid[name]; !ok || refused[name] != nil {
					continue // reserved, or refused already: it only keeps others out
				}

				if len(incumbents) == 1 && incumbents[0] == name {
					continue
				}

				refused[name] = collision(x, name, who, incumbents)
				more = true
			}
		}

		if !more {
			break
		}
	}

	idx := &index{owners: map[Label]string{}, prefixes: map[string]string{}, images: map[string]string{}, builders: map[string]string{}}
	next := map[string]claims{}
	snap := &snapshot{folders: make([]folderView, len(folders))}

	for _, name := range names {
		c, ok := proposed[name]
		if !ok {
			continue
		}

		next[name] = c

		if _, accepted := valid[name]; !accepted || refused[name] != nil {
			snap.reserved = append(snap.reserved, name)
		}

		first := func(m map[string]string, key string) {
			if _, taken := m[key]; !taken {
				m[key] = name
			}
		}

		if _, taken := idx.owners[c.Owner]; !taken {
			idx.owners[c.Owner] = name
		}

		for _, p := range c.Prefixes {
			first(idx.prefixes, p)
		}

		for _, i := range c.Images {
			first(idx.images, i)
		}

		for _, b := range c.Builders {
			first(idx.builders, b)
		}
	}

	for i, files := range loaded {
		view := folderView{views: map[string]*Scope{}, errors: map[string]error{}, digests: map[string]string{}}

		for name, e := range files {
			view.digests[name] = e.digest

			switch {
			case e.err != nil:
				view.errors[name] = e.err
			case refused[name] != nil:
				view.errors[name] = fmt.Errorf("scope file %s: %w", filepath.Join(folders[i].Dir, name+".json"), refused[name])
			default:
				s := *e.scope
				s.index = idx
				view.views[name] = &s

				if s.Version == nil {
					view.unversioned = append(view.unversioned, name)
				}
			}
		}

		sort.Strings(view.unversioned)

		snap.folders[i] = view
	}

	return snap, next
}

// collision says why a scope is refused: a claim another scope has, or that several want.
func collision(x claim, name string, who, incumbents []string) error {
	key := fmt.Sprintf("%q", x.key)
	if x.kind == "owner" {
		key = x.key
	}

	if len(incumbents) == 1 {
		return fmt.Errorf("%s: %s is scope %s's already", x.kind, key, incumbents[0])
	}

	others := slices.DeleteFunc(slices.Clone(who), func(n string) bool { return n == name })

	return fmt.Errorf("%s: %s is also scope %s's, and no one held it before: each is refused until only one claims it", x.kind, key, strings.Join(others, ", "))
}

func equalHeld(a, b map[string]claims) bool {
	if len(a) != len(b) {
		return false
	}

	for name, x := range a {
		y, ok := b[name]
		if !ok || x.Owner != y.Owner || !slices.Equal(x.Prefixes, y.Prefixes) || !slices.Equal(x.Images, y.Images) || !slices.Equal(x.Builders, y.Builders) {
			return false
		}
	}

	return true
}

// Publish makes the snapshot in use the one Status answers from. Serve calls it once the sockets are
// in line with the snapshot, so a scope Status says is loaded has its socket open.
func (r *Registry) Publish() {
	snap := r.snapshot.Load()

	r.published.Lock()
	defer r.published.Unlock()

	if snap == nil || snap == r.published.snap {
		return
	}

	r.published.snap = snap
	close(r.published.next)
	r.published.next = make(chan struct{})
}

// RequestReload asks for a reload and a Publish as soon as possible (Requests), rather than at the
// next scan.
func (r *Registry) RequestReload() {
	select {
	case r.requests <- struct{}{}:
	default:
	}
}

// Requests gives a value when a reload was asked for.
func (r *Registry) Requests() <-chan struct{} {
	return r.requests
}

// Status is what the last published snapshot has of one scope on one listener.
type Status struct {
	Generation uint64
	Listener   string
	Scope      string
	// The SHA-256 of the scope file the state is about ("" when there is none)
	FileSHA256 string
	// "loaded", "refused" (its file isn't valid, or collides, and it holds no claims), "reserved"
	// (refused, but its last valid claims are held for it) or "unknown" (no file)
	State  string
	Reason string
}

// Status tells a scope's state on a listener, from the last published snapshot, and gives a channel
// closed when another is published. ok is false for a listener the registry doesn't have.
func (r *Registry) Status(listener, name string) (status Status, next <-chan struct{}, ok bool) {
	folder := -1

	for i, f := range r.folders {
		if f.Listener == listener {
			folder = i
		}
	}

	if folder < 0 {
		return Status{}, nil, false
	}

	r.published.Lock()
	snap, next := r.published.snap, r.published.next
	r.published.Unlock()

	status = Status{Listener: listener, Scope: name, State: "unknown"}
	if snap == nil {
		return status, next, true
	}

	status.Generation = snap.generation
	view := snap.folders[folder]
	digest, present := view.digests[name]

	switch {
	case !present:
	case view.views[name] != nil:
		status.State, status.FileSHA256 = "loaded", digest
	case slices.Contains(snap.reserved, name):
		status.State, status.FileSHA256, status.Reason = "reserved", digest, view.errors[name].Error()
	default:
		status.State, status.FileSHA256, status.Reason = "refused", digest, view.errors[name].Error()
	}

	return status, next, true
}

// Listeners names the listeners whose scopes the registry holds.
func (r *Registry) Listeners() []string {
	names := make([]string, len(r.folders))
	for i, f := range r.folders {
		names[i] = f.Listener
	}

	return names
}
