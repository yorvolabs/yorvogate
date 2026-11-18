package gate

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"slices"
	"strings"
	"sync"
	"time"
)

// loadLimiter lets a scope load one image archive at a time. Reading an archive decompresses it,
// which is CPU-bound and uncapped by the on-disk limit (a small archive can decompress to a huge
// one): without this, a scope could run many loads at once and starve the others of CPU. One in
// flight per scope leaves the others' loads (one each) running as before.
type loadLimiter struct {
	mu  sync.Mutex
	sem map[string]*loadSlot
}

// loadSlot is one scope's: its one load at a time, and how many hold it or wait for it. The scope's
// entry goes when the last one releases, so the map holds only scopes loading now.
type loadSlot struct {
	ch      chan struct{}
	holders int
}

func newLoadLimiter() *loadLimiter {
	return &loadLimiter{sem: map[string]*loadSlot{}}
}

// acquire blocks until the scope has no other load in flight, and returns a function that releases
// the slot. A load is counted before it waits, so a waiting one keeps the entry.
func (l *loadLimiter) acquire(scope string) func() {
	release, _ := l.acquireBy(context.Background(), nil, scope)

	return release
}

// acquireBy is acquire, giving up when expired fires or ctx ends (then it holds nothing).
func (l *loadLimiter) acquireBy(ctx context.Context, expired <-chan time.Time, scope string) (func(), error) {
	l.mu.Lock()
	slot, ok := l.sem[scope]
	if !ok {
		slot = &loadSlot{ch: make(chan struct{}, 1)}
		l.sem[scope] = slot
	}
	slot.holders++
	l.mu.Unlock()

	leave := func() {
		l.mu.Lock()
		slot.holders--
		if slot.holders == 0 {
			delete(l.sem, scope)
		}
		l.mu.Unlock()
	}

	select {
	case slot.ch <- struct{}{}:
	case <-expired:
		leave()

		return nil, errors.New("the scope's other load didn't end in time")
	case <-ctx.Done():
		leave()

		return nil, ctx.Err()
	}

	return func() {
		<-slot.ch
		leave()
	}, nil
}

// loading is how many scopes have a load in flight or waiting.
func (l *loadLimiter) loading() int {
	l.mu.Lock()
	defer l.mu.Unlock()

	return len(l.sem)
}

// load checks an image archive before Docker loads it: the names it gives its images must be in the
// scope's own namespaces, or loading it would replace what another scope (or anything else) runs
// under that name. The archive is kept in the spool while it's read, then forwarded from there.
//
// What a load may hold is bounded before it holds it: its turn (spool.loads, one per scope), its
// bytes on disk (spool.limit, reserved as they come), what the archive decompresses to and how many
// entries it has (refused as soon as it passes them, before any name is checked), and time (an
// upload that goes silent, a check that runs long).
func (s *scoped) load() (err error) {
	// A refused load gives back its file, bytes and turn at once, not after its refusal is answered
	// (and held, see longestHold): another scope's load may need them now.
	defer func() {
		if err != nil && s.cleanup != nil {
			s.cleanup()
			s.cleanup = nil
		}
	}()

	if s.length > s.loadLimit {
		return refuse(http.StatusRequestEntityTooLarge, "image.load: the archive is larger than %d bytes", s.loadLimit)
	}

	if s.length > s.spool.limit {
		return refuse(http.StatusRequestEntityTooLarge, "image.load: the archive is larger than the image spool (spool.limit, %d bytes)", s.spool.limit)
	}

	held := &reservation{spool: s.spool, scope: s.scope.Name}

	release, err := s.spool.turn(s.ctx, s.scope.Name)
	if err != nil {
		return err
	}

	s.cleanup = func() {
		held.release()
		release()
	}

	// Its whole size at once when it says it, or as it comes
	if s.length > 0 {
		if err := held.reserve(s.length); err != nil {
			return err
		}
	}

	file, err := s.spool.spoolFile()
	if err != nil {
		return err
	}

	s.cleanup = func() {
		_ = file.Close()
		_ = os.Remove(file.Name())
		held.release()
		release()
		onUnspool(s.scope.Name)
	}

	onSpool(s.scope.Name)

	stream := newStalled(s.stream, s.stream.Close, readDeadline(s.ctx))
	defer stream.stop()

	n, err := s.spoolTo(file, stream, held)
	if err != nil {
		return err
	}

	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return err
	}

	names, contents, err := archiveNames(file, archiveBounds{unpacked: s.unpacked(n), deadline: time.Now().Add(loadCheck)})

	var bound *boundError

	switch {
	case errors.As(err, &bound):
		return refuse(http.StatusRequestEntityTooLarge, "image.load: %v", bound)
	case err != nil:
		return refuse(http.StatusBadRequest, "image.load: %v", err)
	}

	for _, name := range names {
		if err := s.ownsImageName(name, "image.load"); err != nil {
			return err
		}
	}

	// And it holds everything it refers to, each blob with its digest: else its names could be given
	// to content Docker already has, which may be another scope's.
	if err := contents.complete(); err != nil {
		return refuse(http.StatusBadRequest, "image.load: %v", err)
	}

	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return err
	}

	s.forwardBody, s.forwardLength = file, n

	return nil
}

// spoolTo copies the archive into its file, reserving each piece of the budget before it's written
// (unless the whole was reserved at once). It gives the archive's size.
func (s *scoped) spoolTo(file *os.File, stream io.Reader, held *reservation) (int64, error) {
	buf := make([]byte, 256<<10)
	reserved := s.length > 0

	var n int64

	for {
		got, err := stream.Read(buf)
		if got > 0 {
			if n+int64(got) > s.loadLimit {
				return n, refuse(http.StatusRequestEntityTooLarge, "image.load: the archive is larger than %d bytes", s.loadLimit)
			}

			if !reserved {
				if err := held.reserve(int64(got)); err != nil {
					return n, err
				}
			}

			if _, err := file.Write(buf[:got]); err != nil {
				return n, err
			}

			n += int64(got)
		}

		switch {
		case errors.Is(err, io.EOF):
			return n, nil
		case errors.Is(err, errStalled):
			return n, refuse(http.StatusBadRequest, "image.load: %v (nothing for %v)", err, loadStall)
		case err != nil:
			return n, refuse(http.StatusBadRequest, "image.load: the archive couldn't be read: %v", err)
		}
	}
}

// unpacked is what an archive of n bytes may decompress to.
func (s *scoped) unpacked(n int64) int64 {
	return s.spoolConfig.UnpackedLimit(n)
}

// The most entries an archive may have, as many as the blobs it may refer to: a docker save writes
// about one per blob, and a few more (four per layer on the classic store), so an image of 2,500
// layers still loads.
const maxEntries = maxDescriptors

// archiveBounds are what reading an archive may cost.
type archiveBounds struct {
	unpacked int64
	deadline time.Time
}

// boundError is an archive past one of its bounds.
type boundError struct{ reason string }

func (e *boundError) Error() string { return e.reason }

// bounded counts what the decompressed archive gives, and fails once it passes its bound, or the
// check its deadline.
type bounded struct {
	r      io.Reader
	bounds archiveBounds
	read   int64
}

func (b *bounded) Read(p []byte) (int, error) {
	n, err := b.r.Read(p)
	b.read += int64(n)

	switch {
	case b.read > b.bounds.unpacked:
		return n, &boundError{fmt.Sprintf("the archive decompresses to more than %d bytes (spool.unpacked, spool.ratio)", b.bounds.unpacked)}
	case !b.bounds.deadline.IsZero() && time.Now().After(b.bounds.deadline):
		return n, &boundError{fmt.Sprintf("the archive took longer than %v to check", loadCheck)}
	}

	return n, err
}

// archiveNames reads the names an image archive gives its images, wherever a Docker reads them,
// whichever its image store: a Docker archive's manifest.json (RepoTags) and repositories (the
// classic store's legacy format, until Docker 28), an OCI archive's index.json (the containerd
// store). Every name any of them would give is checked, so the store Docker has doesn't matter. Docker loads plain, gzip and bzip2 archives (and xz and zstd, which are refused
// here: YorvoGate can't read them).
//
// It also reads every plain file, hashing it (contents), so the caller can check the archive holds
// everything it refers to.
func archiveNames(r io.Reader, bounds archiveBounds) ([]string, *contents, error) {
	buffered := bufio.NewReader(r)
	magic, _ := buffered.Peek(6)

	var archive io.Reader = buffered

	switch {
	case bytes.HasPrefix(magic, []byte{0x1f, 0x8b}):
		gz, err := gzip.NewReader(buffered)
		if err != nil {
			return nil, nil, err
		}

		archive = gz
	case bytes.HasPrefix(magic, []byte("BZh")):
		archive = bzip2.NewReader(buffered)
	case bytes.HasPrefix(magic, []byte{0xfd, '7', 'z', 'X', 'Z', 0x00}), bytes.HasPrefix(magic, []byte{0x28, 0xb5, 0x2f, 0xfd}):
		return nil, nil, errors.New("xz and zstd archives aren't allowed (send it plain, or gzip)")
	}

	if bounds.unpacked > 0 {
		archive = &bounded{r: archive, bounds: bounds}
	}

	reader := tar.NewReader(archive)
	entries := 0
	held := newContents()
	paths := map[string]bool{}
	var names []string

	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}

		if err != nil {
			var bound *boundError
			if errors.As(err, &bound) {
				return nil, nil, bound
			}

			return nil, nil, fmt.Errorf("not an image archive: %w", err)
		}

		// Before its entry is kept: the maps of what the archive holds grow by one per entry.
		if entries++; entries > maxEntries {
			return nil, nil, &boundError{fmt.Sprintf("the archive has more than %d entries", maxEntries)}
		}

		// A name is relative and goes nowhere up: an extractor that joins "/manifest.json" or
		// "a/../manifest.json" onto its folder gets the manifest.json this check would read as
		// another file. Docker's own save writes neither.
		if strings.HasPrefix(header.Name, "/") || slices.Contains(strings.Split(header.Name, "/"), "..") {
			return nil, nil, fmt.Errorf("the archive's %q isn't a plain relative path", header.Name)
		}

		name := path.Clean(strings.TrimPrefix(header.Name, "./"))
		named := name == "manifest.json" || name == "index.json" || name == "repositories"

		// Every path once, whatever it is: where the last entry of a name wins, a second one would
		// put other content under a name than what was hashed.
		if paths[name] {
			return nil, nil, fmt.Errorf("the archive has %s twice", name)
		}

		paths[name] = true

		// One of each, a plain file: any other and Docker could read another than this check.
		if named && (held.digests[name] != "" || header.Typeflag != tar.TypeReg) {
			return nil, nil, fmt.Errorf("the archive's %s isn't one plain file", name)
		}

		// Only plain files hold content; a link or a folder holds none (one an index refers to
		// is then missing)
		if header.Typeflag != tar.TypeReg {
			continue
		}

		if err := held.add(name, header.Size, reader); err != nil {
			var bound *boundError
			if errors.As(err, &bound) {
				return nil, nil, bound
			}

			return nil, nil, err
		}

		if !named {
			continue
		}

		content, ok := held.json[name]
		if !ok {
			return nil, nil, fmt.Errorf("the archive's %s is larger than %d bytes, or not JSON", name, maxJSON)
		}

		found, err := namesIn(name, content)
		if err != nil {
			return nil, nil, fmt.Errorf("the archive's %s: %w", name, err)
		}

		names = append(names, found...)
	}

	return names, held, nil
}

func namesIn(file string, content []byte) ([]string, error) {
	var names []string

	switch file {
	case "manifest.json":
		var manifest []struct {
			RepoTags []string
		}
		if err := json.Unmarshal(content, &manifest); err != nil {
			return nil, err
		}

		for _, m := range manifest {
			names = append(names, m.RepoTags...)
		}
	case "repositories":
		var repositories map[string]map[string]string
		if err := json.Unmarshal(content, &repositories); err != nil {
			return nil, err
		}

		for repo, tags := range repositories {
			for tag := range tags {
				names = append(names, repo+":"+tag)
			}
		}
	case "index.json":
		var index struct {
			Manifests []struct {
				Annotations map[string]string
			}
		}
		if err := json.Unmarshal(content, &index); err != nil {
			return nil, err
		}

		// As containerd names what it imports (Docker 25 to 29 give it no name translator): each
		// image the index lists by its io.containerd.image.name, or else by its
		// org.opencontainers.image.ref.name as it is, a bare one ("latest", "postgres") too. Only the
		// index.json's own entries are named, never those of an index it lists.
		for _, m := range index.Manifests {
			name := m.Annotations["io.containerd.image.name"]
			if name == "" {
				name = m.Annotations["org.opencontainers.image.ref.name"]
			}

			if name != "" {
				names = append(names, name)
			}
		}
	}

	return names, nil
}
