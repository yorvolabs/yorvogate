package gate

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

const (
	ociIndex    = "application/vnd.oci.image.index.v1+json"
	ociManifest = "application/vnd.oci.image.manifest.v1+json"
)

func sha(content string) string {
	sum := sha256.Sum256([]byte(content))

	return hex.EncodeToString(sum[:])
}

func blob(content string) entry { return entry{name: "blobs/sha256/" + sha(content), content: content} }

func ref(mediaType, content string, annotations map[string]string) map[string]any {
	d := map[string]any{"mediaType": mediaType, "digest": "sha256:" + sha(content), "size": len(content)}
	if annotations != nil {
		d["annotations"] = annotations
	}

	return d
}

func asJSON(v any) string {
	b, _ := json.Marshal(v)

	return string(b)
}

// image is a manifest and its blobs, as Docker writes one: a config and a layer of its own.
type testImage struct {
	manifest string
	blobs    []entry
}

func anImage(tag string) testImage {
	layer := "layer of " + tag
	config := asJSON(map[string]any{"architecture": "amd64", "os": "linux", "rootfs": map[string]any{"type": "layers", "diff_ids": []string{"sha256:" + sha(layer)}}})
	manifest := asJSON(map[string]any{
		"schemaVersion": 2, "mediaType": ociManifest,
		"config": ref("application/vnd.oci.image.config.v1+json", config, nil),
		"layers": []any{ref("application/vnd.oci.image.layer.v1.tar", layer, nil)},
	})

	return testImage{manifest: manifest, blobs: []entry{blob(layer), blob(config), blob(manifest)}}
}

// ociArchive is an archive as docker save writes one on Docker 25 and later: an OCI layout whose
// index.json names each image, and a manifest.json with each one's config and layers.
func ociArchive(t testing.TB, names ...string) []byte {
	t.Helper()

	var entries []entry
	var index, legacy []any

	for _, name := range names {
		img := anImage(name)
		entries = append(entries, img.blobs...)
		index = append(index, ref(ociManifest, img.manifest, map[string]string{"io.containerd.image.name": "docker.io/" + name, "org.opencontainers.image.ref.name": name[strings.LastIndex(name, ":")+1:]}))

		var m struct {
			Config struct{ Digest string }
			Layers []map[string]any
		}
		_ = json.Unmarshal([]byte(img.manifest), &m)
		layer := m.Layers[0]["digest"].(string)
		// As Docker 29 writes it: each layer's descriptor in LayerSources, by its diff ID
		legacy = append(legacy, map[string]any{
			"Config":       "blobs/sha256/" + strings.TrimPrefix(m.Config.Digest, "sha256:"),
			"RepoTags":     []string{name},
			"Layers":       []string{"blobs/sha256/" + strings.TrimPrefix(layer, "sha256:")},
			"LayerSources": map[string]any{layer: m.Layers[0]},
		})
	}

	entries = append(entries,
		entry{name: "oci-layout", content: `{"imageLayoutVersion":"1.0.0"}`},
		entry{name: "index.json", content: asJSON(map[string]any{"schemaVersion": 2, "mediaType": ociIndex, "manifests": index})},
		entry{name: "manifest.json", content: asJSON(legacy)},
	)

	return archive(t, entries...)
}

// An archive is loaded only if it holds every blob it refers to, each with its digest and size:
// a manifest it lacks, a blob under another's digest, or one it says comes from elsewhere is
// refused before Docker sees it, naming what's wrong.
func TestAnArchiveHoldsWhatItRefersTo(t *testing.T) {
	d := startDocker(t)
	server := gate(t, d, "sites")

	img := anImage("quire-sites/jane/app:1")
	other := anImage("quire-sites/jane/other:1")
	name := map[string]string{"io.containerd.image.name": "quire-sites/jane/app:1"}

	// A multi-platform image with an attestation, as buildx --load gives one: an index of manifests
	attestation := anImage("attestation")
	multi := asJSON(map[string]any{"schemaVersion": 2, "mediaType": ociIndex, "manifests": []any{
		ref(ociManifest, img.manifest, map[string]string{}),
		ref(ociManifest, attestation.manifest, map[string]string{"vnd.docker.reference.type": "attestation-manifest"}),
	}})

	for what, entries := range map[string][]entry{
		"one image": append(append([]entry{}, img.blobs...), entry{name: "index.json", content: asJSON(map[string]any{"manifests": []any{ref(ociManifest, img.manifest, name)}})}),
		"an index, with an attestation": append(append(append([]entry{}, img.blobs...), attestation.blobs...), blob(multi),
			entry{name: "index.json", content: asJSON(map[string]any{"manifests": []any{ref(ociIndex, multi, name)}})}),
	} {
		if status, answer := send(t, server, "POST", "/v1.56/images/load", string(archive(t, entries...)), asJane); status != http.StatusOK {
			t.Errorf("%s: %d %s", what, status, answer)
		}
	}

	if status, answer := send(t, server, "POST", "/v1.56/images/load", string(ociArchive(t, "quire-sites/jane/app:1", "quire-sites/jane/app:2")), asJane); status != http.StatusOK {
		t.Errorf("docker save's archive of two images: %d %s", status, answer)
	}

	// The bytes of another image under the manifest's digest
	junk := entry{name: img.blobs[2].name, content: other.manifest}
	// An index naming a manifest it doesn't hold (another platform, say)
	missingChild := asJSON(map[string]any{"manifests": []any{ref(ociManifest, img.manifest, nil), ref(ociManifest, other.manifest, nil)}})
	withIndex := func(manifests ...any) entry {
		return entry{name: "index.json", content: asJSON(map[string]any{"manifests": manifests})}
	}
	deep := img.manifest
	var deepBlobs []entry
	for range maxDepth + 2 {
		deep = asJSON(map[string]any{"mediaType": ociIndex, "manifests": []any{ref(ociIndex, deep, nil)}})
		deepBlobs = append(deepBlobs, blob(deep))
	}

	before := d.count()

	for what, c := range map[string]struct {
		entries []entry
		words   string
	}{
		"a manifest it lacks":                            {[]entry{img.blobs[0], img.blobs[1], withIndex(ref(ociManifest, img.manifest, name))}, "lacks sha256:" + sha(img.manifest)},
		"a layer it lacks":                               {[]entry{img.blobs[1], img.blobs[2], withIndex(ref(ociManifest, img.manifest, name))}, "lacks sha256:" + sha("layer of quire-sites/jane/app:1")},
		"a config it lacks":                              {[]entry{img.blobs[0], img.blobs[2], withIndex(ref(ociManifest, img.manifest, name))}, "lacks sha256:"},
		"another's bytes":                                {[]entry{img.blobs[0], img.blobs[1], junk, withIndex(ref(ociManifest, img.manifest, name))}, "isn't what its digest says"},
		"a missing child":                                {append(append([]entry{}, img.blobs...), blob(missingChild), withIndex(ref(ociIndex, missingChild, name))), "lacks sha256:" + sha(other.manifest)},
		"another size":                                   {append(append([]entry{}, img.blobs...), withIndex(map[string]any{"mediaType": ociManifest, "digest": "sha256:" + sha(img.manifest), "size": 1})), "bytes, not the 1"},
		"a media type it can't read":                     {append(append([]entry{}, img.blobs...), withIndex(ref("application/vnd.example.thing", img.manifest, name))), "can't read"},
		"a manifest listed as an index":                  {append(append([]entry{}, img.blobs...), withIndex(ref(ociIndex, img.manifest, name))), ""},
		"a blob from elsewhere":                          {append(append([]entry{}, img.blobs...), withIndex(map[string]any{"mediaType": ociManifest, "digest": "sha256:" + sha(img.manifest), "size": len(img.manifest), "urls": []string{"https://example.com/x"}})), "from elsewhere"},
		"another digest algorithm":                       {append(append([]entry{}, img.blobs...), withIndex(map[string]any{"mediaType": ociManifest, "digest": "sha512:" + strings.Repeat("a", 128), "size": 1})), "only sha256"},
		"a blob, then a link by its name":                {[]entry{img.blobs[0], img.blobs[1], img.blobs[2], {name: "./" + img.blobs[2].name, link: true}, withIndex(ref(ociManifest, img.manifest, name))}, "twice"},
		"a blob that's a link":                           {[]entry{img.blobs[0], img.blobs[1], {name: img.blobs[2].name, link: true}, withIndex(ref(ociManifest, img.manifest, name))}, "lacks sha256:" + sha(img.manifest)},
		"indexes nested too deep":                        {append(append(append([]entry{}, img.blobs...), deepBlobs...), withIndex(ref(ociIndex, deep, name))), "deeper than"},
		"manifest.json, a layer it lacks":                {[]entry{img.blobs[1], {name: "manifest.json", content: `[{"Config":"` + img.blobs[1].name + `","RepoTags":["quire-sites/jane/app:1"],"Layers":["` + img.blobs[0].name + `"]}]`}}, "lacks " + img.blobs[0].name},
		"manifest.json, no config":                       {[]entry{{name: "manifest.json", content: `[{"RepoTags":["quire-sites/jane/app:1"]}]`}}, "no config"},
		"manifest.json, a config under another's digest": {[]entry{{name: sha("x") + ".json", content: "{}"}, {name: "manifest.json", content: `[{"Config":"` + sha("x") + `.json","RepoTags":["quire-sites/jane/app:1"]}]`}}, "isn't what its name says"},
		"manifest.json, a layer from elsewhere":          {append(append([]entry{}, img.blobs...), entry{name: "manifest.json", content: `[{"Config":"` + img.blobs[1].name + `","RepoTags":["quire-sites/jane/app:1"],"Layers":[],"LayerSources":{"sha256:` + sha("x") + `":{"mediaType":"application/vnd.oci.image.layer.v1.tar","digest":"sha256:` + sha("x") + `","size":1,"urls":["https://example.com/x"]}}}]`}), "from elsewhere"},
		"manifest.json, a layer source it lacks":         {append(append([]entry{}, img.blobs...), entry{name: "manifest.json", content: `[{"Config":"` + img.blobs[1].name + `","RepoTags":["quire-sites/jane/app:1"],"Layers":[],"LayerSources":{"sha256:` + sha("x") + `":{"mediaType":"application/vnd.oci.image.layer.v1.tar","digest":"sha256:` + sha("x") + `","size":1}}}]`}), "lacks sha256:" + sha("x")},
	} {
		status, answer := send(t, server, "POST", "/v1.56/images/load", string(archive(t, c.entries...)), asJane)
		if status != http.StatusBadRequest || !strings.Contains(message(t, answer), "image.load: ") || !strings.Contains(message(t, answer), c.words) {
			t.Errorf("%s: %d %s", what, status, answer)
		}
	}

	if d.count() != before {
		t.Errorf("%d incomplete archives reached Docker", d.count()-before)
	}
}

// What the walk keeps of an archive is bounded: an index or manifest larger than it reads is
// refused, as are JSON files larger than it keeps together.
func TestAnArchivesJSONIsBounded(t *testing.T) {
	img := anImage("quire-sites/jane/app:1")
	big := `{"manifests":[],"padding":"` + strings.Repeat("x", maxJSON) + `"}`

	if _, _, err := archiveNames(bytes.NewReader(archive(t, append(append([]entry{}, img.blobs...), entry{name: "index.json", content: big})...))); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Errorf("an oversize index.json: %v", err)
	}

	var many []entry
	for i := range maxJSONTotal/maxJSON + 1 {
		many = append(many, entry{name: fmt.Sprintf("blobs/sha256/%064x", i), content: "{" + strings.Repeat(" ", maxJSON-2) + "}"})
	}

	if _, _, err := archiveNames(bytes.NewReader(archive(t, many...))); err == nil || !strings.Contains(err.Error(), "together") {
		t.Errorf("too much JSON: %v", err)
	}

	// A manifest an index lists that's larger than what's kept: refused, not skipped
	huge := `{"mediaType":"` + ociManifest + `","padding":"` + strings.Repeat("x", maxJSON) + `"}`
	_, held, err := archiveNames(bytes.NewReader(archive(t, blob(huge), entry{name: "index.json", content: asJSON(map[string]any{"manifests": []any{ref(ociManifest, huge, nil)}})})))
	if err != nil {
		t.Fatal(err)
	}

	if err := held.complete(); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Errorf("an oversize manifest: %v", err)
	}
}

// An entry's name is relative, and goes nowhere up: "/manifest.json" is manifest.json to an
// extractor that joins names onto its folder, whatever this check would make of it.
func TestAnArchivesPathsAreRelative(t *testing.T) {
	d := startDocker(t)
	server := gate(t, d, "sites")
	own := `[{"RepoTags":["quire-sites/jane/app:1"]}]`
	before := d.count()

	for what, entries := range map[string][]entry{
		"manifest.json, then /manifest.json": {{name: "manifest.json", content: own}, {name: "/manifest.json", content: `[{"RepoTags":["postgres:18"]}]`}},
		"//manifest.json":                    {{name: "//manifest.json", content: `[{"RepoTags":["postgres:18"]}]`}},
		"an absolute blob":                   {{name: "/blobs/sha256/" + sha("x"), content: "x"}},
		"a/../manifest.json":                 {{name: "a/../manifest.json", content: `[{"RepoTags":["postgres:18"]}]`}},
		"../manifest.json":                   {{name: "../manifest.json", content: own}},
		"a folder up":                        {{name: "blobs/../../x", content: "x"}},
	} {
		status, answer := send(t, server, "POST", "/v1.56/images/load", string(archive(t, entries...)), asJane)
		if status != http.StatusBadRequest || !strings.Contains(message(t, answer), "isn't a plain relative path") {
			t.Errorf("%s: %d %s", what, status, answer)
		}
	}

	if d.count() != before {
		t.Errorf("%d archives reached Docker", d.count()-before)
	}

	// "./" and a dot segment that stays inside are still fine
	if _, _, err := archiveNames(bytes.NewReader(archive(t, entry{name: "./oci-layout", content: "{}"}, entry{name: "blobs/./sha256/" + sha("y"), content: "y"}))); err != nil {
		t.Errorf("./ and ./ inside: %v", err)
	}
}
