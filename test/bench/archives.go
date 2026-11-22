package main

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

// An image archive as docker save writes it (manifest.json, each config, each layer.tar), generated:
// nothing is pulled.

// layer writes a layer: one file of size pseudo-random bytes (so no store can make it sparse), and
// returns its path and digest (its diff ID).
func layer(dir string, size int64) (string, string, error) {
	path := filepath.Join(dir, fmt.Sprintf("layer-%d.tar", size))

	f, err := os.Create(path)
	if err != nil {
		return "", "", err
	}

	defer f.Close()

	sum := sha256.New()
	w := tar.NewWriter(io.MultiWriter(f, sum))

	if err := w.WriteHeader(&tar.Header{Name: "data", Mode: 0o644, Size: size, ModTime: time.Unix(0, 0), Format: tar.FormatUSTAR}); err != nil {
		return "", "", err
	}

	random := rand.NewChaCha8([32]byte{})
	if _, err := io.CopyN(w, random, size); err != nil {
		return "", "", err
	}

	if err := w.Close(); err != nil {
		return "", "", err
	}

	return path, "sha256:" + hex.EncodeToString(sum.Sum(nil)), nil
}

// config is an image's config for one layer; label makes each one's ID its own.
func config(diffID, label string) []byte {
	b, _ := json.Marshal(map[string]any{
		"architecture": runtime.GOARCH,
		"os":           "linux",
		"config":       map[string]any{"Labels": map[string]string{"org.yorvolabs.bench.image": label, projectLabel: "yorvogate"}},
		"rootfs":       map[string]any{"type": "layers", "diff_ids": []string{diffID}},
		"created":      "1970-01-01T00:00:00Z",
	})

	return b
}

// image is one image of an archive: its config, and the names it's loaded as.
type image struct {
	config []byte
	tags   []string
}

// archiveSize is an archive's length, as writeArchive writes it (USTAR: a 512-byte header per file,
// its content to 512, two blocks of zeros at the end).
func archiveSize(layerSize int64, images []image) int64 {
	block := func(n int64) int64 { return 512 + (n+511)/512*512 }

	total := block(layerSize) + block(int64(len(manifest(images))))
	for _, i := range images {
		total += block(int64(len(i.config)))
	}

	return total + 1024
}

func manifest(images []image) []byte {
	type entry struct {
		Config   string
		RepoTags []string
		Layers   []string
	}

	entries := make([]entry, 0, len(images))
	for _, i := range images {
		entries = append(entries, entry{Config: configName(i.config), RepoTags: i.tags, Layers: []string{"layer/layer.tar"}})
	}

	b, _ := json.Marshal(entries)

	return b
}

func configName(c []byte) string {
	sum := sha256.Sum256(c)

	return hex.EncodeToString(sum[:]) + ".json"
}

// writeArchive writes the archive of images, every one of them the one layer at layerPath.
func writeArchive(w io.Writer, layerPath string, images []image) error {
	t := tar.NewWriter(w)
	header := func(name string, size int64) error {
		return t.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: size, ModTime: time.Unix(0, 0), Format: tar.FormatUSTAR})
	}

	l, err := os.Open(layerPath)
	if err != nil {
		return err
	}

	defer l.Close()

	info, err := l.Stat()
	if err != nil {
		return err
	}

	if err := header("layer/layer.tar", info.Size()); err != nil {
		return err
	}

	if _, err := io.Copy(t, l); err != nil {
		return err
	}

	for _, i := range images {
		if err := header(configName(i.config), int64(len(i.config))); err != nil {
			return err
		}

		if _, err := t.Write(i.config); err != nil {
			return err
		}
	}

	m := manifest(images)
	if err := header("manifest.json", int64(len(m))); err != nil {
		return err
	}

	if _, err := t.Write(m); err != nil {
		return err
	}

	return t.Close()
}
