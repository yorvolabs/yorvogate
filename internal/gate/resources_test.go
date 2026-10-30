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

	// The list: another scope's images and nameless leftovers aren't in it; a shared image another
	// scope also tagged is, without that scope's name.
	status, answer := send(t, server, "GET", "/v1.56/images/json", "", asJane)
	if status != 200 || strings.Contains(answer, "blog") || strings.Contains(answer, strings.Repeat("4", 64)) || !strings.Contains(answer, "alpine:3.22") || !strings.Contains(answer, "quire-sites/jane/php-prod") || !strings.Contains(answer, "busybox:1") {
		t.Errorf("list: %d %s", status, answer)
	}

	// Tagging a shared image into a namespace doesn't take it from anyone else.
	for _, path := range []string{"/v1.56/images/busybox:1/json", "/v1.56/images/sha256:" + strings.Repeat("5", 64) + "/json"} {
		if status, answer := send(t, server, "GET", path, "", asJane); status != 200 {
			t.Errorf("%s: %d %s", path, status, answer)
		}
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

func archive(t testing.TB, entries ...entry) []byte {
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

// The edges of each limit, and what a listener without limits allows.
func TestLimitsAtTheirEdges(t *testing.T) {
	d := startDocker(t)
	server := gate(t, d, "sites")
	create := func(body map[string]any) (int, string) {
		return send(t, server, "POST", "/v1.56/containers/create?name=jane-edge-1", encode(body), asJane)
	}

	for name, body := range map[string]map[string]any{
		"memory at the limit":         set(compose(), "HostConfig.Memory", 1<<30),
		"processes at the limit":      set(compose(), "HostConfig.PidsLimit", 512),
		"its own volume, bound":       set(compose(), "HostConfig.Binds", []any{"jane_data:/data:ro"}),
		"the local driver, named":     set(compose(), "HostConfig.Mounts", []any{map[string]any{"Type": "volume", "Source": "jane_data", "Target": "/x", "VolumeOptions": map[string]any{"DriverConfig": map[string]any{"Name": "local"}}}}),
		"a subpath inside the volume": set(compose(), "HostConfig.Mounts", []any{map[string]any{"Type": "volume", "Source": "jane_data", "Target": "/x", "VolumeOptions": map[string]any{"Subpath": "uploads/2026"}}}),
		"an anonymous volume":         set(compose(), "HostConfig.Mounts", []any{map[string]any{"Type": "volume", "Target": "/cache"}}),
		"its own cgroup namespace":    set(compose(), "HostConfig.CgroupnsMode", "private"),
	} {
		if status, answer := create(body); status != 200 {
			t.Errorf("%s: %d %s", name, status, answer)
		}
	}

	for name, body := range map[string]map[string]any{
		"memory a byte over":           set(compose(), "HostConfig.Memory", 1<<30+1),
		"processes one over":           set(compose(), "HostConfig.PidsLimit", 513),
		"another volume driver":        set(compose(), "HostConfig.Mounts", []any{map[string]any{"Type": "volume", "Source": "jane_data", "Target": "/x", "VolumeOptions": map[string]any{"DriverConfig": map[string]any{"Name": "nfs"}}}}),
		"an absolute subpath":          set(compose(), "HostConfig.Mounts", []any{map[string]any{"Type": "volume", "Source": "jane_data", "Target": "/x", "VolumeOptions": map[string]any{"Subpath": "/etc"}}}),
		"a subpath that isn't clean":   set(compose(), "HostConfig.Mounts", []any{map[string]any{"Type": "volume", "Source": "jane_data", "Target": "/x", "VolumeOptions": map[string]any{"Subpath": "a/../../b"}}}),
		"a target that isn't absolute": set(compose(), "HostConfig.Mounts", []any{map[string]any{"Type": "tmpfs", "Target": "tmp"}}),
		"a tmpfs with a source":        set(compose(), "HostConfig.Mounts", []any{map[string]any{"Type": "tmpfs", "Source": "/etc", "Target": "/x"}}),
		"unlimited processes (0)":      set(compose(), "HostConfig.PidsLimit", 0),
		"its prefix, another's volume": set(compose(), "HostConfig.Mounts", []any{map[string]any{"Type": "volume", "Source": "jane_stolen", "Target": "/x"}}),
		"the same, bound":              set(compose(), "HostConfig.Binds", []any{"jane_stolen:/x"}),
	} {
		if status, answer := create(body); status != http.StatusForbidden {
			t.Errorf("%s: %d %s", name, status, answer)
		}
	}

	for body, want := range map[string]int{
		`{"Memory":1073741824}`: 200,
		`{"PidsLimit":512}`:     200,
		`{"Memory":1073741825}`: 403,
		`{"PidsLimit":513}`:     403,
		`{"PidsLimit":0}`:       403, // 0 is unlimited, to Docker
		`{"Memory":-1}`:         403,
	} {
		if status, answer := send(t, server, "POST", "/v1.56/containers/jane-php-1/update", body, asJane); status != want {
			t.Errorf("update %s: %d %s", body, status, answer)
		}
	}

	// A listener with no limits set: Docker's defaults, but never the host's.
	loose := gate(t, d, "loose")
	free := set(set(set(set(compose(), "HostConfig.Memory", nil), "HostConfig.PidsLimit", nil), "HostConfig.CapDrop", nil), "HostConfig.SecurityOpt", nil)
	free = set(free, "HostConfig.CapAdd", nil)
	free = set(free, "HostConfig.Ulimits", nil)

	if status, answer := send(t, loose, "POST", "/v1.56/containers/create?name=jane-free-1", encode(free), asJane); status != 200 {
		t.Errorf("no limits where none are asked: %d %s", status, answer)
	}

	if status, answer := send(t, loose, "POST", "/v1.56/containers/jane-php-1/update", `{"PidsLimit":-1,"Memory":8589934592}`, asJane); status != 200 {
		t.Errorf("no limits where none are asked, updated: %d %s", status, answer)
	}

	for name, body := range map[string]map[string]any{
		"a capability":      set(free, "HostConfig.CapAdd", []any{"NET_BIND_SERVICE"}),
		"privileged":        set(free, "HostConfig.Privileged", true),
		"a ulimit":          set(free, "HostConfig.Ulimits", []any{map[string]any{"Name": "nofile", "Soft": 1, "Hard": 1}}),
		"a log driver":      set(free, "HostConfig.LogConfig", map[string]any{"Type": "syslog"}),
		"a security option": set(free, "HostConfig.SecurityOpt", []any{"label=disable"}),
	} {
		if status, answer := send(t, loose, "POST", "/v1.56/containers/create?name=jane-free-1", encode(body), asJane); status != http.StatusForbidden {
			t.Errorf("%s, with no list: %d %s", name, status, answer)
		}
	}
}

func TestEdgesOfImagesAndArchives(t *testing.T) {
	d := startDocker(t)
	server := gate(t, d, "sites")

	// Another scope's image, by a name that isn't in its namespace (a digest reference)
	ref := "mirror.example/anything@sha256:" + strings.Repeat("3", 64)
	if status, answer := send(t, server, "GET", "/v1.56/images/"+ref+"/json", "", asJane); status != http.StatusNotFound {
		t.Errorf("another's image by digest: %d %s", status, answer)
	}

	// A build's leftover, by a digest reference: anyone's, so no one's to read
	leftover := "anything@sha256:" + strings.Repeat("4", 64)
	if status, answer := send(t, server, "GET", "/v1.56/images/"+leftover+"/json", "", asJane); status != http.StatusNotFound {
		t.Errorf("a leftover by digest: %d %s", status, answer)
	}

	// An archive exactly at the limit is read; a byte over isn't.
	exact := bytes.Repeat([]byte{0}, 1<<20)
	if status, answer := send(t, server, "POST", "/v1.56/images/load", string(exact), asJane); status != 200 {
		t.Errorf("at the limit: %d %s", status, answer)
	}
}

func TestStreamsOnAScopedListener(t *testing.T) {
	d := startDocker(t)
	server := gate(t, d, "sites")

	if status, answer := send(t, server, "POST", "/v1.56/exec/exec-jane/start", `{"Detach":false}`, asJane); status != http.StatusBadRequest || !strings.Contains(message(t, answer), "only as an HTTP upgrade") {
		t.Errorf("attached, without an upgrade: %d %s", status, answer)
	}

	if status, _ := send(t, server, "POST", "/v1.56/exec/exec-jane/start", `{"Detach":true,"Tty":true}`, asJane); status != 200 || !strings.Contains(d.last().body, `"Detach":true`) || !strings.Contains(d.last().body, `"Tty":true`) {
		t.Errorf("detached: %d, forwarded %s", status, d.last().body)
	}

	// "Connection: Upgrade" without an Upgrade header isn't an upgrade.
	if status, answer := send(t, server, "POST", "/v1.56/containers/jane-php-1/attach?stream=1", "", map[string]string{"X-YorvoGate-Scope": "jane", "X-YorvoGate-Token": token, "Connection": "Upgrade"}); status != http.StatusBadRequest {
		t.Errorf("half an upgrade: %d %s", status, answer)
	}
}
