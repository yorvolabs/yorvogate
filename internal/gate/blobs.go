package gate

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"path"
	"regexp"
	"strings"
)

// An image archive is loaded only if it holds every blob it refers to, each with the digest it's
// referred to by. Docker's containerd store doesn't write a blob whose digest it already has, and
// doesn't read it either: an archive that refers to a digest without holding its bytes, or holds
// other bytes under that name, would have its names given to content already there, which may be
// another scope's. So every blob an index or manifest reaches is read and hashed here first.

const (
	// The largest JSON file (index, manifest, config) kept to be read, and all of them together
	maxJSON      = 4 << 20
	maxJSONTotal = 64 << 20
	// How deep indexes may nest, and how many descriptors an archive may have
	maxDepth       = 8
	maxDescriptors = 10000
)

var blobPath = regexp.MustCompile(`^blobs/sha256/([0-9a-f]{64})$`)

// contents are what an archive holds: each plain file's SHA-256 and size, and the small JSON ones.
type contents struct {
	digests map[string]string // path -> SHA-256 (hex)
	sizes   map[string]int64
	json    map[string][]byte
	kept    int
}

func newContents() *contents {
	return &contents{digests: map[string]string{}, sizes: map[string]int64{}, json: map[string][]byte{}}
}

// add reads one plain file of the archive, hashing it, and keeps it if it may be JSON one of the
// archive's indexes or manifests refers to.
func (c *contents) add(name string, size int64, r io.Reader) error {
	if _, dup := c.digests[name]; dup {
		return fmt.Errorf("the archive has %s twice", name)
	}

	hash := sha256.New()

	if size <= maxJSON {
		content, err := io.ReadAll(io.LimitReader(r, maxJSON+1))
		if err != nil {
			return err
		}

		hash.Write(content)

		if bytes.HasPrefix(bytes.TrimLeft(content, " \t\r\n"), []byte("{")) || bytes.HasPrefix(bytes.TrimLeft(content, " \t\r\n"), []byte("[")) {
			if c.kept+len(content) > maxJSONTotal {
				return fmt.Errorf("the archive's JSON files are larger than %d bytes together", maxJSONTotal)
			}

			c.kept += len(content)
			c.json[name] = content
		}

		size = int64(len(content))
	} else {
		n, err := io.Copy(hash, r)
		if err != nil {
			return err
		}

		size = n
	}

	c.digests[name] = hex.EncodeToString(hash.Sum(nil))
	c.sizes[name] = size

	return nil
}

// blobRef is an OCI descriptor, as an index or manifest refers to content.
type blobRef struct {
	MediaType string   `json:"mediaType"`
	Digest    string   `json:"digest"`
	Size      int64    `json:"size"`
	URLs      []string `json:"urls"`
}

// The media types walked: indexes list manifests, manifests a config and layers.
var (
	indexTypes = map[string]bool{
		"application/vnd.oci.image.index.v1+json":                   true,
		"application/vnd.docker.distribution.manifest.list.v2+json": true,
	}
	manifestTypes = map[string]bool{
		"application/vnd.oci.image.manifest.v1+json":           true,
		"application/vnd.docker.distribution.manifest.v2+json": true,
	}
)

// complete checks that the archive holds every blob its index.json and manifest.json reach, each
// with its digest and size. It names the first one that isn't.
func (c *contents) complete() error {
	w := &walk{c: c, seen: map[string]bool{}}

	if content, ok := c.json["index.json"]; ok {
		if err := w.index(content, "index.json", 0); err != nil {
			return err
		}
	} else if _, ok := c.digests["index.json"]; ok {
		return fmt.Errorf("the archive's index.json is larger than %d bytes, or not JSON", maxJSON)
	}

	if content, ok := c.json["manifest.json"]; ok {
		if err := c.legacy(content); err != nil {
			return err
		}
	} else if _, ok := c.digests["manifest.json"]; ok {
		return fmt.Errorf("the archive's manifest.json is larger than %d bytes, or not JSON", maxJSON)
	}

	return nil
}

type walk struct {
	c     *contents
	seen  map[string]bool
	count int
}

// blob checks that a descriptor's blob is in the archive, with its digest and size, and gives its
// content if it was kept.
func (w *walk) blob(d blobRef, from string) ([]byte, error) {
	w.count++
	if w.count > maxDescriptors {
		return nil, fmt.Errorf("the archive refers to more than %d blobs", maxDescriptors)
	}

	if len(d.URLs) > 0 {
		return nil, fmt.Errorf("%s refers to %s from elsewhere (urls): an archive must hold what it loads", from, d.Digest)
	}

	hexDigest, ok := strings.CutPrefix(d.Digest, "sha256:")
	if !ok || !blobPath.MatchString("blobs/sha256/"+hexDigest) {
		return nil, fmt.Errorf("%s refers to %q: only sha256 digests are read", from, d.Digest)
	}

	name := "blobs/sha256/" + hexDigest

	got, present := w.c.digests[name]
	if !present {
		return nil, fmt.Errorf("the archive lacks %s, which %s refers to", d.Digest, from)
	}

	if got != hexDigest {
		return nil, fmt.Errorf("the archive's %s isn't what its digest says (its SHA-256 is %s)", d.Digest, got)
	}

	if w.c.sizes[name] != d.Size {
		return nil, fmt.Errorf("the archive's %s is %d bytes, not the %d %s says", d.Digest, w.c.sizes[name], d.Size, from)
	}

	return w.c.json[name], nil
}

// index walks an index's manifests: every one must be in the archive, an index it lists too.
func (w *walk) index(content []byte, from string, depth int) error {
	if depth > maxDepth {
		return fmt.Errorf("the archive's indexes nest deeper than %d", maxDepth)
	}

	var index struct {
		MediaType string    `json:"mediaType"`
		Manifests []blobRef `json:"manifests"`
	}
	if err := json.Unmarshal(content, &index); err != nil {
		return fmt.Errorf("%s: %w", from, err)
	}

	for _, d := range index.Manifests {
		if err := w.descriptor(d, from, depth); err != nil {
			return err
		}
	}

	return nil
}

// descriptor walks what an index lists: an index or a manifest, nothing else.
func (w *walk) descriptor(d blobRef, from string, depth int) error {
	if w.seen[d.Digest] {
		return nil
	}

	content, err := w.blob(d, from)
	if err != nil {
		return err
	}

	w.seen[d.Digest] = true

	if !indexTypes[d.MediaType] && !manifestTypes[d.MediaType] {
		return fmt.Errorf("%s lists %s as %q, which YorvoGate can't read", from, d.Digest, d.MediaType)
	}

	if content == nil {
		return fmt.Errorf("the archive's %s (%s) is larger than %d bytes, or not JSON", d.Digest, d.MediaType, maxJSON)
	}

	// What the blob says it is must be what it's listed as
	var own struct {
		MediaType string `json:"mediaType"`
	}
	if err := json.Unmarshal(content, &own); err != nil {
		return fmt.Errorf("%s: %w", d.Digest, err)
	}

	if own.MediaType != "" && own.MediaType != d.MediaType {
		return fmt.Errorf("%s is listed as %q but says it's %q", d.Digest, d.MediaType, own.MediaType)
	}

	if indexTypes[d.MediaType] {
		return w.index(content, d.Digest, depth+1)
	}

	return w.manifest(content, d.Digest)
}

// manifest checks a manifest's config and layers are in the archive.
func (w *walk) manifest(content []byte, from string) error {
	var manifest struct {
		Config blobRef   `json:"config"`
		Layers []blobRef `json:"layers"`
	}
	if err := json.Unmarshal(content, &manifest); err != nil {
		return fmt.Errorf("%s: %w", from, err)
	}

	if manifest.Config.Digest == "" {
		return fmt.Errorf("%s has no config", from)
	}

	for _, d := range append([]blobRef{manifest.Config}, manifest.Layers...) {
		if _, err := w.blob(d, from); err != nil {
			return err
		}
	}

	return nil
}

// legacy checks a Docker archive's manifest.json: each image's config and layers are in the
// archive, and a file named by its digest has that digest.
func (c *contents) legacy(content []byte) error {
	var images []struct {
		Config       string
		Layers       []string
		LayerSources map[string]json.RawMessage
	}
	if err := json.Unmarshal(content, &images); err != nil {
		return fmt.Errorf("manifest.json: %w", err)
	}

	for _, image := range images {
		if len(image.LayerSources) > 0 {
			return fmt.Errorf("manifest.json refers to layers from elsewhere (LayerSources): an archive must hold what it loads")
		}

		if image.Config == "" {
			return fmt.Errorf("manifest.json lists an image with no config")
		}

		for _, file := range append([]string{image.Config}, image.Layers...) {
			name := path.Clean(strings.TrimPrefix(file, "./"))

			got, present := c.digests[name]
			if !present {
				return fmt.Errorf("the archive lacks %s, which manifest.json refers to", file)
			}

			// A blob ("blobs/sha256/<digest>") or an older archive's config ("<digest>.json") is
			// named by its digest
			want := ""
			if m := blobPath.FindStringSubmatch(name); m != nil {
				want = m[1]
			} else if hexName, ok := strings.CutSuffix(name, ".json"); ok && blobPath.MatchString("blobs/sha256/"+hexName) {
				want = hexName
			}

			if want != "" && got != want {
				return fmt.Errorf("the archive's %s isn't what its name says (its SHA-256 is %s)", file, got)
			}
		}
	}

	return nil
}
