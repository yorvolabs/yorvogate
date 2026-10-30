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
)

// load checks an image archive before Docker loads it: the names it gives its images must be in the
// scope's own namespaces, or loading it would replace what another scope (or anything else) runs
// under that name. The archive is kept on disk while it's read, then forwarded from there.
func (s *scoped) load() error {
	file, err := os.CreateTemp("", "yorvogate-load-*")
	if err != nil {
		return err
	}

	s.cleanup = func() {
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

	names, err := archiveNames(file)
	if err != nil {
		return refuse(http.StatusBadRequest, "image.load: %v", err)
	}

	for _, name := range names {
		if err := s.ownsImageName(name, "image.load"); err != nil {
			return err
		}
	}

	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return err
	}

	s.forwardBody, s.forwardLength = file, n

	return nil
}

// archiveNames reads the names an image archive gives its images, wherever Docker reads them: a
// Docker archive's manifest.json (RepoTags) and repositories, an OCI archive's index.json
// (annotations). Docker loads plain, gzip and bzip2 archives (and xz and zstd, which are refused
// here: YorvoGate can't read them).
func archiveNames(r io.Reader) ([]string, error) {
	buffered := bufio.NewReader(r)
	magic, _ := buffered.Peek(6)

	var archive io.Reader = buffered

	switch {
	case bytes.HasPrefix(magic, []byte{0x1f, 0x8b}):
		gz, err := gzip.NewReader(buffered)
		if err != nil {
			return nil, err
		}

		archive = gz
	case bytes.HasPrefix(magic, []byte("BZh")):
		archive = bzip2.NewReader(buffered)
	case bytes.HasPrefix(magic, []byte{0xfd, '7', 'z', 'X', 'Z', 0x00}), bytes.HasPrefix(magic, []byte{0x28, 0xb5, 0x2f, 0xfd}):
		return nil, errors.New("xz and zstd archives aren't allowed (send it plain, or gzip)")
	}

	reader := tar.NewReader(archive)
	seen := map[string]bool{}
	var names []string

	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			return names, nil
		}

		if err != nil {
			return nil, fmt.Errorf("not an image archive: %w", err)
		}

		name := path.Clean(strings.TrimPrefix(header.Name, "./"))
		if name != "manifest.json" && name != "index.json" && name != "repositories" {
			continue
		}

		// One of each, a plain file: any other and Docker could read another than this check.
		if seen[name] || header.Typeflag != tar.TypeReg {
			return nil, fmt.Errorf("the archive's %s isn't one plain file", name)
		}

		seen[name] = true

		content, err := io.ReadAll(io.LimitReader(reader, 16<<20))
		if err != nil {
			return nil, err
		}

		found, err := namesIn(name, content)
		if err != nil {
			return nil, fmt.Errorf("the archive's %s: %w", name, err)
		}

		names = append(names, found...)
	}
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

		for _, m := range index.Manifests {
			if name := m.Annotations["io.containerd.image.name"]; name != "" {
				names = append(names, name)
			}

			// A bare tag ("latest") names nothing; a full reference does.
			if ref := m.Annotations["org.opencontainers.image.ref.name"]; strings.ContainsAny(ref, "/:@") {
				names = append(names, ref)
			}
		}
	}

	return names, nil
}
