package gate

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"strings"
	"sync"
)

// loadLimiter lets a scope load one image archive at a time. Reading an archive decompresses it,
// which is CPU-bound and uncapped by the on-disk limit (a small archive can decompress to a huge
// one): without this, a scope could run many loads at once and starve the others of CPU. One in
// flight per scope leaves the others' loads (one each) running as before.
type loadLimiter struct {
	mu  sync.Mutex
	sem map[string]chan struct{}
}

func newLoadLimiter() *loadLimiter {
	return &loadLimiter{sem: map[string]chan struct{}{}}
}

// acquire blocks until the scope has no other load in flight, and returns a function that releases
// the slot.
func (l *loadLimiter) acquire(scope string) func() {
	l.mu.Lock()
	ch, ok := l.sem[scope]
	if !ok {
		ch = make(chan struct{}, 1)
		l.sem[scope] = ch
	}
	l.mu.Unlock()

	ch <- struct{}{}

	return func() { <-ch }
}

// load checks an image archive before Docker loads it: the names it gives its images must be in the
// scope's own namespaces, or loading it would replace what another scope (or anything else) runs
// under that name. The archive is kept on disk while it's read, then forwarded from there.
func (s *scoped) load() error {
	release := s.loads.acquire(s.scope.Name)

	file, err := os.CreateTemp("", "yorvogate-load-*")
	if err != nil {
		release()

		return err
	}

	s.cleanup = func() {
		release()
		_ = file.Close()
		_ = os.Remove(file.Name())
	}

	n, err := io.Copy(file, io.LimitReader(s.stream, s.loadLimit+1))
	if err != nil {
		return refuse(http.StatusBadRequest, "image.load: the archive couldn't be read: %v", err)
	}

	if n > s.loadLimit {
		return refuse(http.StatusRequestEntityTooLarge, "image.load: the archive is larger than %d bytes", s.loadLimit)
	}

	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return err
	}

	names, held, err := archiveNames(file)
	if err != nil {
		return refuse(http.StatusBadRequest, "image.load: %v", err)
	}

	for _, name := range names {
		if err := s.ownsImageName(name, "image.load"); err != nil {
			return err
		}
	}

	// And it holds everything it refers to, each blob with its digest: else its names could be given
	// to content Docker already has, which may be another scope's.
	if err := held.complete(); err != nil {
		return refuse(http.StatusBadRequest, "image.load: %v", err)
	}

	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return err
	}

	s.forwardBody, s.forwardLength = file, n

	return nil
}

// archiveNames reads the names an image archive gives its images, wherever a Docker reads them,
// whichever its image store: a Docker archive's manifest.json (RepoTags) and repositories (the
// classic store's legacy format, until Docker 28), an OCI archive's index.json (the containerd
// store). Every name any of them would give is checked, so the store Docker has doesn't matter. Docker loads plain, gzip and bzip2 archives (and xz and zstd, which are refused
// here: YorvoGate can't read them).
//
// It also reads every plain file, hashing it (contents), so the caller can check the archive holds
// everything it refers to.
func archiveNames(r io.Reader) ([]string, *contents, error) {
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

	reader := tar.NewReader(archive)
	held := newContents()
	var names []string

	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}

		if err != nil {
			return nil, nil, fmt.Errorf("not an image archive: %w", err)
		}

		name := path.Clean(strings.TrimPrefix(header.Name, "./"))
		named := name == "manifest.json" || name == "index.json" || name == "repositories"

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
