package gate

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// composeNetwork is a network as Compose creates one for jane's project, in its subnet.
func composeNetwork() map[string]any {
	return map[string]any{
		"Name":   "jane_default",
		"Driver": "bridge",
		"Labels": map[string]any{"com.docker.compose.project": "jane", "com.docker.compose.network": "default"},
		"IPAM":   map[string]any{"Config": []any{map[string]any{"Subnet": "10.213.0.32/27"}}},
	}
}

func TestNetworksOfItsOwn(t *testing.T) {
	d := startDocker(t)
	server := gate(t, d, "sites")

	if status, answer := send(t, server, "POST", "/v1.56/networks/create", encode(composeNetwork()), asJane); status != 200 {
		t.Fatalf("%d %s", status, answer)
	}

	cases := []struct {
		name, want string
		body       map[string]any
	}{
		{"another scope's name", `the name "blog_default" isn't one of scope jane's`, set(composeNetwork(), "Name", "blog_default")},
		{"no label", "it must carry the label", set(composeNetwork(), "Labels", map[string]any{})},
		{"another driver", `the driver "macvlan" isn't allowed`, set(composeNetwork(), "Driver", "macvlan")},
		{"the host's", `the driver "host" isn't allowed`, set(composeNetwork(), "Driver", "host")},
		{"the swarm's", `the scope "swarm" isn't allowed`, set(composeNetwork(), "Scope", "swarm")},
		{"the host's bridge", "Options isn't allowed", set(composeNetwork(), "Options", map[string]any{"com.docker.network.bridge.name": "docker0"})},
		{"another network's configuration", "ConfigFrom isn't allowed", set(composeNetwork(), "ConfigFrom", map[string]any{"Network": "quire-data-config"})},
		{"the routing mesh", "Ingress isn't allowed", set(composeNetwork(), "Ingress", true)},
		{"an IPAM plugin", `the IPAM driver "evil" isn't allowed`, set(composeNetwork(), "IPAM.Driver", "evil")},
		{"IPAM options", "IPAM.Options isn't allowed", set(composeNetwork(), "IPAM.Options", map[string]any{"x": "y"})},
		{"a subnet of another's", "the subnet 10.213.0.96/27 isn't inside the scope's", set(composeNetwork(), "IPAM.Config", []any{map[string]any{"Subnet": "10.213.0.96/27"}})},
		{"a subnet around its own", "the subnet 10.213.0.0/24 isn't inside the scope's", set(composeNetwork(), "IPAM.Config", []any{map[string]any{"Subnet": "10.213.0.0/24"}})},
		{"no subnet (Docker's pools)", "its subnet must be named", set(composeNetwork(), "IPAM", nil)},
	}

	for _, c := range cases {
		status, answer := send(t, server, "POST", "/v1.56/networks/create", encode(c.body), asJane)
		if status != http.StatusForbidden || !strings.Contains(message(t, answer), c.want) {
			t.Errorf("%s: %d %s", c.name, status, answer)
		}
	}

	if status, _ := send(t, server, "DELETE", "/v1.56/networks/jane_default", "", asJane); status != 200 || d.last().path != "/v1.56/networks/"+janeNet {
		t.Errorf("its own: %d %s", status, d.last().path)
	}

	for _, path := range []string{"/v1.56/networks/quire-link-jane", "/v1.56/networks/blog_default"} {
		if status, answer := send(t, server, "DELETE", path, "", asJane); status != http.StatusNotFound {
			t.Errorf("%s: %d %s", path, status, answer)
		}
	}

	if status, _ := send(t, server, "POST", "/v1.56/networks/prune", "", asJane); status != 200 || !strings.Contains(d.last().query, "jane") {
		t.Errorf("prune: %d %s", status, d.last().query)
	}
}

// A shared network's inspection lists only the scope's own containers on it.
func TestASharedNetworkShowsOnlyItsOwn(t *testing.T) {
	d := startDocker(t)
	server := gate(t, d, "sites")

	status, answer := send(t, server, "GET", "/v1.56/networks/quire-link-jane", "", asJane)
	if status != 200 {
		t.Fatalf("%d %s", status, answer)
	}

	var inspected struct {
		Name       string
		Containers map[string]struct{ Name string }
	}
	if err := json.Unmarshal([]byte(answer), &inspected); err != nil {
		t.Fatal(err)
	}

	if inspected.Name != "quire-link-jane" || len(inspected.Containers) != 1 || inspected.Containers[janePHP].Name != "jane-php-1" {
		t.Errorf("%s", answer)
	}
}

func TestVolumesOfItsOwn(t *testing.T) {
	d := startDocker(t)
	server := gate(t, d, "sites")
	own := `{"Name":"jane_data","Driver":"local","Labels":{"com.docker.compose.project":"jane"}}`

	if status, answer := send(t, server, "POST", "/v1.56/volumes/create", own, asJane); status != 200 {
		t.Fatalf("%d %s", status, answer)
	}

	for body, want := range map[string]string{
		`{"Name":"jane_root","Labels":{"com.docker.compose.project":"jane"},"DriverOpts":{"type":"none","o":"bind","device":"/"}}`: "DriverOpts isn't allowed",
		`{"Name":"jane_nfs","Driver":"rexray","Labels":{"com.docker.compose.project":"jane"}}`:                                     `the driver "rexray" isn't allowed`,
		`{"Name":"blog_data","Labels":{"com.docker.compose.project":"jane"}}`:                                                      `the name "blog_data" isn't one of scope jane's`,
		`{"Name":"jane_data"}`: "it must carry the label",
		`{"Name":"","Labels":{"com.docker.compose.project":"jane"}}`:                                         `the name "" isn't one`,
		`{"Name":"jane_c","Labels":{"com.docker.compose.project":"jane"},"ClusterVolumeSpec":{"Group":"x"}}`: "ClusterVolumeSpec isn't allowed",
	} {
		if status, answer := send(t, server, "POST", "/v1.56/volumes/create", body, asJane); status != http.StatusForbidden || !strings.Contains(message(t, answer), want) {
			t.Errorf("%s: %d %s", body, status, answer)
		}
	}

	if status, _ := send(t, server, "DELETE", "/v1.56/volumes/jane_data", "", asJane); status != 200 {
		t.Errorf("its own: %d", status)
	}

	if status, _ := send(t, server, "DELETE", "/v1.56/volumes/blog_data", "", asJane); status != http.StatusNotFound {
		t.Errorf("another's: %d", status)
	}

	if status, _ := send(t, server, "POST", "/v1.56/volumes/prune", "", asJane); status != 200 || !strings.Contains(d.last().query, "jane") {
		t.Errorf("prune: %d %s", status, d.last().query)
	}
}

func TestImages(t *testing.T) {
	d := startDocker(t)
	server := gate(t, d, "sites")
	blogID := "sha256:" + strings.Repeat("3", 64)
	leftover := strings.Repeat("4", 12)

	// The list: another scope's images and nameless leftovers aren't in it.
	status, answer := send(t, server, "GET", "/v1.56/images/json", "", asJane)
	if status != 200 || strings.Contains(answer, "blog") || strings.Contains(answer, strings.Repeat("4", 64)) || !strings.Contains(answer, "alpine:3.22") || !strings.Contains(answer, "quire-sites/jane/php-prod") {
		t.Errorf("list: %d %s", status, answer)
	}

	for _, c := range [][3]string{
		{"GET", "/v1.56/images/alpine:3.22/json", ""},
		{"GET", "/v1.56/images/quire-sites/jane/php-prod/history", ""},
		{"POST", "/v1.56/images/create?fromImage=alpine&tag=3.22", ""},
		{"POST", "/v1.56/images/create?fromImage=docker.io/quire-sites/jane/php-prod&tag=latest", ""},
		{"POST", "/v1.56/images/alpine:3.22/tag?repo=quire-sites/jane/php-prod&tag=before-update", ""},
		{"DELETE", "/v1.56/images/quire-sites/jane/php-prod:before-update", ""},
		{"GET", "/v1.56/images/quire-sites/jane/php-prod/get", ""},
		{"GET", "/v1.56/images/get?names=alpine:3.22&names=quire-sites/jane/php-prod", ""},
		{"GET", "/v1.56/images/search?term=alpine", ""},
		{"GET", "/v1.56/distribution/alpine:3.22/json", ""},
	} {
		if status, answer := send(t, server, c[0], c[1], c[2], asJane); status != 200 {
			t.Errorf("%s %s: %d %s", c[0], c[1], status, answer)
		}
	}

	for _, c := range [][3]string{
		{"GET", "/v1.56/images/quire-sites/blog/php-prod/json", "No such image"},
		{"GET", "/v1.56/images/" + blogID + "/json", "No such image"},
		{"GET", "/v1.56/images/" + leftover + "/json", "No such image"},
		{"GET", "/v1.56/images/docker.io/quire-sites/blog/php-prod/json", "No such image"},
		{"POST", "/v1.56/images/create?fromImage=quire-sites/blog/php-prod", "isn't its own"},
		{"POST", "/v1.56/images/create?fromSrc=http://evil.example/rootfs.tar&repo=quire-sites/jane/x", "importing (fromSrc) isn't allowed"},
		{"POST", "/v1.56/images/alpine:3.22/tag?repo=postgres&tag=18-alpine", "isn't in one of scope jane's image namespaces"},
		{"POST", "/v1.56/images/quire-sites/blog/php-prod/tag?repo=quire-sites/jane/stolen", "No such image"},
		{"DELETE", "/v1.56/images/alpine:3.22", "isn't in one of scope jane's image namespaces"},
		{"DELETE", "/v1.56/images/" + blogID, "isn't in one of scope jane's image namespaces"},
		{"GET", "/v1.56/images/quire-sites/blog/php-prod/get", "No such image"},
		{"GET", "/v1.56/images/get?names=alpine:3.22&names=quire-sites/blog/php-prod", "No such image"},
		{"GET", "/v1.56/distribution/quire-sites/blog/php-prod/json", "No such image"},
		{"POST", "/v1.56/images/quire-sites/jane/php-prod/push", "isn't allowed for scope jane"},
	} {
		if status, answer := send(t, server, c[0], c[1], "", asJane); status/100 != 4 || !strings.Contains(message(t, answer), c[2]) {
			t.Errorf("%s %s: %d %s", c[0], c[1], status, answer)
		}
	}
}

type entry struct {
	name, content string
	link          bool
}

func archive(t *testing.T, entries ...entry) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := tar.NewWriter(&buf)

	for _, e := range entries {
		h := &tar.Header{Name: e.name, Mode: 0o644, Size: int64(len(e.content)), Typeflag: tar.TypeReg}
		if e.link {
			h = &tar.Header{Name: e.name, Linkname: "blobs/x", Typeflag: tar.TypeSymlink}
		}

		if err := w.WriteHeader(h); err != nil {
			t.Fatal(err)
		}

		if !e.link {
			_, _ = w.Write([]byte(e.content))
		}
	}

	_ = w.Close()

	return buf.Bytes()
}

func gzipped(b []byte) []byte {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	_, _ = w.Write(b)
	_ = w.Close()

	return buf.Bytes()
}

// An image archive is loaded only when every name it gives is in the scope's own namespaces.
func TestLoadingAnArchiveChecksItsNames(t *testing.T) {
	d := startDocker(t)
	server := gate(t, d, "sites")

	own := archive(t,
		entry{name: "blobs/sha256/aa", content: "layer"},
		entry{name: "index.json", content: `{"manifests":[{"annotations":{"io.containerd.image.name":"docker.io/quire-sites/jane/php-prod:latest","org.opencontainers.image.ref.name":"latest"}}]}`},
		entry{name: "manifest.json", content: `[{"RepoTags":["quire-sites/jane/php-prod:latest"]}]`},
	)

	if status, answer := send(t, server, "POST", "/v1.56/images/load?quiet=1", string(own), asJane); status != 200 {
		t.Fatalf("its own: %d %s", status, answer)
	}

	if got := d.last(); got.body != string(own) || got.path != "/v1.56/images/load" {
		t.Errorf("forwarded %d bytes to %s, want the archive (%d)", len(got.body), got.path, len(own))
	}

	if status, _ := send(t, server, "POST", "/v1.56/images/load", string(archive(t, entry{name: "blobs/sha256/aa", content: "layer"})), asJane); status != 200 {
		t.Errorf("an archive without names: %d", status)
	}

	if status, answer := send(t, server, "POST", "/v1.56/images/load", string(gzipped(own)), asJane); status != 200 {
		t.Errorf("its own, compressed: %d %s", status, answer)
	}

	before := d.count()

	for name, body := range map[string][]byte{
		"another scope's name":         archive(t, entry{name: "manifest.json", content: `[{"RepoTags":["quire-sites/blog/php-prod:latest"]}]`}),
		"a shared name":                archive(t, entry{name: "manifest.json", content: `[{"RepoTags":["postgres:18-alpine"]}]`}),
		"compressed":                   gzipped(archive(t, entry{name: "manifest.json", content: `[{"RepoTags":["alpine:3.22"]}]`})),
		"in the OCI index":             archive(t, entry{name: "index.json", content: `{"manifests":[{"annotations":{"io.containerd.image.name":"docker.io/library/postgres:18"}}]}`}),
		"a full reference as ref.name": archive(t, entry{name: "index.json", content: `{"manifests":[{"annotations":{"org.opencontainers.image.ref.name":"quire-sites/blog/php-prod:latest"}}]}`}),
		"in the legacy repositories":   archive(t, entry{name: "repositories", content: `{"quire-sites/blog/php-prod":{"latest":"abc"}}`}),
		"a second manifest":            archive(t, entry{name: "manifest.json", content: `[{"RepoTags":["quire-sites/jane/x:1"]}]`}, entry{name: "./manifest.json", content: `[{"RepoTags":["alpine:3.22"]}]`}),
		"a manifest that's a link":     archive(t, entry{name: "manifest.json", link: true}),
		"xz":                           append([]byte{0xfd, '7', 'z', 'X', 'Z', 0x00}, make([]byte, 600)...),
		"zstd":                         append([]byte{0x28, 0xb5, 0x2f, 0xfd}, make([]byte, 600)...),
		"too large":                    bytes.Repeat([]byte{0}, 1<<20+1),
	} {
		if status, answer := send(t, server, "POST", "/v1.56/images/load", string(body), asJane); status/100 != 4 {
			t.Errorf("%s: %d %s", name, status, answer)
		}
	}

	if d.count() != before {
		t.Errorf("%d archives reached Docker", d.count()-before)
	}
}
