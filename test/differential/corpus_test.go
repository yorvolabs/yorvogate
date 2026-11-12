package differential

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
)

// base is a request a scope sends that the gate allows plainly, for one endpoint: every variant of
// it must reach Docker as it does, or not at all.
type base struct {
	endpoint string
	req      func(t testing.TB) request
}

// attack is a request the gate refuses plainly, for an endpoint's rule: every variant of it must be
// refused, with nothing reaching Docker.
type attack struct {
	endpoint, name string
	req            func(t testing.TB) request
}

func get(target string) func(testing.TB) request {
	return func(testing.TB) request { return asJane("GET", target, "", nil) }
}

func head(target string) func(testing.TB) request {
	return func(testing.TB) request { return asJane("HEAD", target, "", nil) }
}

func post(target string) func(testing.TB) request {
	return func(testing.TB) request { return asJane("POST", target, "", nil) }
}

func del(target string) func(testing.TB) request {
	return func(testing.TB) request { return asJane("DELETE", target, "", nil) }
}

func postJSON(target, body string) func(testing.TB) request {
	return func(testing.TB) request { return asJane("POST", target, "application/json", []byte(body)) }
}

// upgrade is a stream's request: Docker hijacks the connection.
func upgrade(r func(testing.TB) request) func(testing.TB) request {
	return func(t testing.TB) request {
		return r(t).with("Connection", "Upgrade", false).with("Upgrade", "tcp", false)
	}
}

const own = `"Labels":{"com.docker.compose.project":"jane"}`

// janeContainer is a container.create body the gate allows on the suite's listener.
const janeContainer = `{"Image":"alpine:3.22",` + own + `,"HostConfig":{"NetworkMode":"jane_default","CapDrop":["ALL"],"SecurityOpt":["no-new-privileges"]}}`

// The bases: one or more per endpoint scopes may send (TestEveryEndpointHasABase holds it to that).
var bases = []base{
	{"system.ping", get("/v1.56/_ping")},
	{"system.version", get("/v1.56/version")},
	{"system.info", get("/v1.56/info")},

	{"container.list", get("/v1.56/containers/json?all=1")},
	{"container.prune", post("/v1.56/containers/prune")},
	{"container.create", postJSON("/v1.56/containers/create?name=jane-web-1", janeContainer)},
	{"container.update", postJSON("/v1.56/containers/jane-php-1/update", `{"RestartPolicy":{"Name":"unless-stopped"}}`)},
	{"container.rename", post("/v1.56/containers/jane-php-1/rename?name=jane-php-2")},
	{"container.inspect", get("/v1.56/containers/jane-php-1/json")},
	{"container.top", get("/v1.56/containers/jane-php-1/top?ps_args=aux")},
	{"container.logs", get("/v1.56/containers/jane-php-1/logs?stdout=1&stderr=1")},
	{"container.changes", get("/v1.56/containers/jane-php-1/changes")},
	{"container.export", get("/v1.56/containers/jane-php-1/export")},
	{"container.stats", get("/v1.56/containers/jane-php-1/stats?stream=0")},
	{"container.resize", post("/v1.56/containers/jane-php-1/resize?h=24&w=80")},
	{"container.start", post("/v1.56/containers/jane-php-1/start")},
	{"container.stop", post("/v1.56/containers/jane-php-1/stop?t=1")},
	{"container.restart", post("/v1.56/containers/jane-php-1/restart?t=1")},
	{"container.kill", post("/v1.56/containers/jane-php-1/kill?signal=TERM")},
	{"container.pause", post("/v1.56/containers/jane-php-1/pause")},
	{"container.unpause", post("/v1.56/containers/jane-php-1/unpause")},
	{"container.attach", upgrade(post("/v1.56/containers/jane-php-1/attach?stream=1&stdout=1"))},
	{"container.attach-websocket", func(t testing.TB) request {
		return asJane("GET", "/v1.56/containers/jane-php-1/attach/ws?stream=1&stdout=1", "", nil).
			with("Connection", "Upgrade", false).with("Upgrade", "websocket", false).
			with("Sec-WebSocket-Version", "13", false).with("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==", false)
	}},
	{"container.wait", post("/v1.56/containers/jane-php-1/wait?condition=not-running")},
	{"container.delete", del("/v1.56/containers/jane-php-1?force=1")},
	{"container.archive-info", head("/v1.56/containers/jane-php-1/archive?path=/etc")},
	{"container.archive-get", get("/v1.56/containers/jane-php-1/archive?path=/etc")},
	{"container.archive-put", func(t testing.TB) request {
		return asJane("PUT", "/v1.56/containers/jane-php-1/archive?path=/tmp", "application/x-tar", tarOf(t, map[string]string{"x": "y"}))
	}},

	{"exec.create", postJSON("/v1.56/containers/jane-php-1/exec", `{"Cmd":["true"]}`)},
	{"exec.start", postJSON("/v1.56/exec/exec-jane/start", `{"Detach":true}`)},
	{"exec.resize", post("/v1.56/exec/exec-jane/resize?h=24&w=80")},
	{"exec.inspect", get("/v1.56/exec/exec-jane/json")},

	{"image.list", get("/v1.56/images/json")},
	{"image.create", post("/v1.56/images/create?fromImage=quire-sites/jane/app&tag=1")},
	{"image.search", get("/v1.56/images/search?term=alpine&limit=5")},
	{"image.save-many", get("/v1.56/images/get?names=quire-sites/jane/app:1")},
	{"image.load", func(t testing.TB) request {
		return asJane("POST", "/v1.56/images/load", "application/x-tar", imageArchive(t, "quire-sites/jane/app:2"))
	}},
	{"image.inspect", get("/v1.56/images/quire-sites/jane/app:1/json")},
	{"image.history", get("/v1.56/images/quire-sites/jane/app:1/history")},
	{"image.tag", post("/v1.56/images/quire-sites/jane/app:1/tag?repo=quire-sites/jane/app&tag=2")},
	{"image.save", get("/v1.56/images/quire-sites/jane/app:1/get")},
	{"image.delete", del("/v1.56/images/quire-sites/jane/app:1")},

	{"network.list", get("/v1.56/networks")},
	{"network.create", postJSON("/v1.56/networks/create", `{"Name":"jane_new",`+own+`}`)},
	{"network.prune", post("/v1.56/networks/prune")},
	{"network.inspect", get("/v1.56/networks/jane_default")},
	{"network.delete", del("/v1.56/networks/jane_default")},
	{"network.connect", postJSON("/v1.56/networks/jane_default/connect", `{"Container":"jane-php-1"}`)},
	{"network.disconnect", postJSON("/v1.56/networks/jane_default/disconnect", `{"Container":"jane-php-1"}`)},

	{"volume.list", get("/v1.56/volumes")},
	{"volume.create", postJSON("/v1.56/volumes/create", `{"Name":"jane_new",`+own+`}`)},
	{"volume.prune", post("/v1.56/volumes/prune")},
	{"volume.inspect", get("/v1.56/volumes/jane_data")},
	{"volume.delete", del("/v1.56/volumes/jane_data")},

	{"distribution.inspect", get("/v1.56/distribution/quire-sites/jane/app:1/json")},
}

// The attacks: requests each rule refuses (TestEveryRuleHasAnAttack holds the corpus to that).
var attacks = []attack{
	{"container.create", "privileged", postJSON("/v1.56/containers/create?name=jane-x", `{"Image":"alpine:3.22",`+own+`,"HostConfig":{"NetworkMode":"jane_default","CapDrop":["ALL"],"SecurityOpt":["no-new-privileges"],"Privileged":true}}`)},
	{"container.create", "the host's /", postJSON("/v1.56/containers/create?name=jane-x", `{"Image":"alpine:3.22",`+own+`,"HostConfig":{"NetworkMode":"jane_default","CapDrop":["ALL"],"SecurityOpt":["no-new-privileges"],"Binds":["/:/host"]}}`)},
	{"container.create", "another scope's name", postJSON("/v1.56/containers/create?name=blog-x", janeContainer)},
	{"container.create", "another scope's label", postJSON("/v1.56/containers/create?name=jane-x", `{"Image":"alpine:3.22","Labels":{"com.docker.compose.project":"blog"},"HostConfig":{"NetworkMode":"jane_default","CapDrop":["ALL"],"SecurityOpt":["no-new-privileges"]}}`)},
	{"container.create", "the host's network", postJSON("/v1.56/containers/create?name=jane-x", `{"Image":"alpine:3.22",`+own+`,"HostConfig":{"NetworkMode":"host","CapDrop":["ALL"],"SecurityOpt":["no-new-privileges"]}}`)},
	{"container.create", "a protected image", postJSON("/v1.56/containers/create?name=jane-x", `{"Image":"quire-sites/blog/app:1",`+own+`,"HostConfig":{"NetworkMode":"jane_default","CapDrop":["ALL"],"SecurityOpt":["no-new-privileges"]}}`)},
	{"container.update", "another scope's", postJSON("/v1.56/containers/blog-php-1/update", `{"RestartPolicy":{"Name":"unless-stopped"}}`)},
	{"container.rename", "into another scope's name", post("/v1.56/containers/jane-php-1/rename?name=blog-php-2")},
	{"container.start", "another scope's", post("/v1.56/containers/blog-php-1/start")},
	{"container.delete", "another scope's", del("/v1.56/containers/blog-php-1?force=1")},
	{"container.archive-put", "into another scope's", func(t testing.TB) request {
		return asJane("PUT", "/v1.56/containers/blog-php-1/archive?path=/tmp", "application/x-tar", tarOf(t, map[string]string{"x": "y"}))
	}},
	{"exec.create", "in another scope's", postJSON("/v1.56/containers/blog-php-1/exec", `{"Cmd":["true"]}`)},
	{"exec.create", "privileged", postJSON("/v1.56/containers/jane-php-1/exec", `{"Cmd":["true"],"Privileged":true}`)},
	{"exec.start", "another scope's", postJSON("/v1.56/exec/exec-blog/start", `{"Detach":true}`)},
	{"exec.resize", "another scope's", post("/v1.56/exec/exec-blog/resize?h=24&w=80")},
	{"image.create", "into another scope's namespace", post("/v1.56/images/create?fromImage=quire-sites/blog/app&tag=1")},
	{"image.create", "an import", func(t testing.TB) request {
		return asJane("POST", "/v1.56/images/create?fromSrc=-&repo=quire-sites/jane/x&tag=1", "", []byte("rootfs"))
	}},
	{"image.save-many", "another scope's", get("/v1.56/images/get?names=quire-sites/blog/app:1")},
	{"image.load", "into another scope's namespace", func(t testing.TB) request {
		return asJane("POST", "/v1.56/images/load", "application/x-tar", imageArchive(t, "quire-sites/blog/app:2"))
	}},
	{"image.inspect", "another scope's", get("/v1.56/images/quire-sites/blog/app:1/json")},
	{"image.history", "another scope's", get("/v1.56/images/quire-sites/blog/app:1/history")},
	{"image.tag", "into another scope's namespace", post("/v1.56/images/quire-sites/jane/app:1/tag?repo=quire-sites/blog/app&tag=2")},
	{"image.save", "another scope's", get("/v1.56/images/quire-sites/blog/app:1/get")},
	{"image.delete", "another scope's", del("/v1.56/images/quire-sites/blog/app:1")},
	{"network.create", "another scope's name", postJSON("/v1.56/networks/create", `{"Name":"blog_new",`+own+`}`)},
	{"network.inspect", "another scope's", get("/v1.56/networks/blog_default")},
	{"network.delete", "another scope's", del("/v1.56/networks/blog_default")},
	{"network.connect", "another scope's container", postJSON("/v1.56/networks/jane_default/connect", `{"Container":"blog-php-1"}`)},
	{"network.disconnect", "from another scope's network", postJSON("/v1.56/networks/blog_default/disconnect", `{"Container":"blog-php-1"}`)},
	{"volume.create", "another scope's name", postJSON("/v1.56/volumes/create", `{"Name":"blog_new",`+own+`}`)},
	{"volume.inspect", "another scope's", get("/v1.56/volumes/blog_data")},
	{"volume.delete", "another scope's", del("/v1.56/volumes/blog_data")},
	{"distribution.inspect", "another scope's", get("/v1.56/distribution/quire-sites/blog/app:1/json")},

	// A refused value of each checked field (fields_test.go), on the suite's listener
	{"container.create", "another scope's network", postJSON("/v1.56/containers/create?name=jane-x", `{"Image":"alpine:3.22",`+own+`,"HostConfig":{"NetworkMode":"jane_default","CapDrop":["ALL"],"SecurityOpt":["no-new-privileges"]},"NetworkingConfig":{"EndpointsConfig":{"blog_default":{}}}}`)},
	{"container.create", "a capability added", janeHost(`"CapAdd":["SYS_ADMIN"]`)},
	{"container.create", "not every capability dropped", postJSON("/v1.56/containers/create?name=jane-x", `{"Image":"alpine:3.22",`+own+`,"HostConfig":{"NetworkMode":"jane_default","CapDrop":["NET_RAW"],"SecurityOpt":["no-new-privileges"]}}`)},
	{"container.create", "the host's cgroup namespace", janeHost(`"CgroupnsMode":"host"`)},
	{"container.create", "the host's IPC namespace", janeHost(`"IpcMode":"host"`)},
	{"container.create", "the host's PID namespace", janeHost(`"PidMode":"host"`)},
	{"container.create", "the host's UTS namespace", janeHost(`"UTSMode":"host"`)},
	{"container.create", "the host's user namespace", janeHost(`"UsernsMode":"host"`)},
	{"container.create", "another isolation", janeHost(`"Isolation":"hyperv"`)},
	{"container.create", "a log driver not allowed", janeHost(`"LogConfig":{"Type":"syslog"}`)},
	{"container.create", "a log option not the driver's", janeHost(`"LogConfig":{"Type":"json-file","Config":{"syslog-address":"tcp://192.0.2.1:514"}}`)},
	{"container.create", "a bind mount", janeHost(`"Mounts":[{"Type":"bind","Source":"/","Target":"/host"}]`)},
	{"container.create", "another scope's volume mounted", janeHost(`"Mounts":[{"Type":"volume","Source":"blog_data","Target":"/data"}]`)},
	{"container.create", "a mount's relative target", janeHost(`"Mounts":[{"Type":"volume","Source":"jane_x","Target":"data"}]`)},
	{"container.create", "a mount's volume labelled another's", janeHost(`"Mounts":[{"Type":"volume","Source":"jane_x","Target":"/data","VolumeOptions":{"Labels":{"com.docker.compose.project":"blog"}}}]`)},
	{"container.create", "a mount's subpath out of the volume", janeHost(`"Mounts":[{"Type":"volume","Source":"jane_x","Target":"/data","VolumeOptions":{"Subpath":"../etc"}}]`)},
	{"container.create", "a mount's volume driver", janeHost(`"Mounts":[{"Type":"volume","Source":"jane_x","Target":"/data","VolumeOptions":{"DriverConfig":{"Name":"nfs"}}}]`)},
	{"container.create", "a mount's volume driver options", janeHost(`"Mounts":[{"Type":"volume","Source":"jane_x","Target":"/data","VolumeOptions":{"DriverConfig":{"Name":"local","Options":{"type":"none","o":"bind","device":"/"}}}}]`)},
	{"container.create", "the OOM killer disabled", janeHost(`"OomKillDisable":true`)},
	{"container.create", "an OOM score below 0", janeHost(`"OomScoreAdj":-1000`)},
	{"container.create", "a runtime not allowed", janeHost(`"Runtime":"runsc"`)},
	{"container.create", "a security option not allowed", postJSON("/v1.56/containers/create?name=jane-x", `{"Image":"alpine:3.22",`+own+`,"HostConfig":{"NetworkMode":"jane_default","CapDrop":["ALL"],"SecurityOpt":["no-new-privileges","apparmor=unconfined"]}}`)},
	{"container.create", "a ulimit not allowed", janeHost(`"Ulimits":[{"Name":"nofile","Soft":1048576,"Hard":1048576}]`)},
	{"container.create", "a volume driver", janeHost(`"VolumeDriver":"nfs"`)},
	{"container.create", "another scope's volumes", janeHost(`"VolumesFrom":["blog-php-1"]`)},
	{"container.create", "every capability added", janeHost(`"CapAdd":["ALL"]`)},
	{"container.create", "the SYS_MODULE capability", janeHost(`"CapAdd":["SYS_MODULE"]`)},
	{"container.create", "the DAC_READ_SEARCH capability", janeHost(`"CapAdd":["DAC_READ_SEARCH"]`)},
	{"container.create", "the SYS_PTRACE capability", janeHost(`"CapAdd":["SYS_PTRACE"]`)},
	{"container.create", "the host's devices", janeHost(`"Devices":[{"PathOnHost":"/dev/sda1","PathInContainer":"/dev/sda1","CgroupPermissions":"rwm"}]`)},
	{"container.create", "seccomp unconfined", postJSON("/v1.56/containers/create?name=jane-x", `{"Image":"alpine:3.22",`+own+`,"HostConfig":{"NetworkMode":"jane_default","CapDrop":["ALL"],"SecurityOpt":["no-new-privileges","seccomp=unconfined"]}}`)},
	{"container.update", "the OOM killer disabled", postJSON("/v1.56/containers/jane-php-1/update", `{"OomKillDisable":true}`)},
	{"container.update", "a ulimit not allowed", postJSON("/v1.56/containers/jane-php-1/update", `{"Ulimits":[{"Name":"nofile","Soft":1048576,"Hard":1048576}]}`)},
	{"network.connect", "an endpoint's legacy links", postJSON("/v1.56/networks/jane_default/connect", `{"Container":"jane-php-1","EndpointConfig":{"Links":["blog-php-1:db"]}}`)},
	{"network.create", "a driver not allowed", postJSON("/v1.56/networks/create", `{"Name":"jane_new","Driver":"macvlan",`+own+`}`)},
	{"network.create", "the swarm's scope", postJSON("/v1.56/networks/create", `{"Name":"jane_new","Scope":"swarm",`+own+`}`)},
	{"network.create", "another scope's label", postJSON("/v1.56/networks/create", `{"Name":"jane_new","Labels":{"com.docker.compose.project":"blog"}}`)},
	{"network.create", "an IPAM plugin", postJSON("/v1.56/networks/create", `{"Name":"jane_new",`+own+`,"IPAM":{"Driver":"weave"}}`)},
	{"volume.create", "a driver not allowed", postJSON("/v1.56/volumes/create", `{"Name":"jane_new","Driver":"nfs",`+own+`}`)},
	{"volume.create", "a local driver binding a host path", postJSON("/v1.56/volumes/create", `{"Name":"jane_new","Driver":"local","DriverOpts":{"type":"none","o":"bind","device":"/"},`+own+`}`)},
	{"volume.create", "another scope's label", postJSON("/v1.56/volumes/create", `{"Name":"jane_new","Labels":{"com.docker.compose.project":"blog"}}`)},
}

// janeHost is a container.create of jane's, its host configuration the suite's base with more.
func janeHost(more string) func(testing.TB) request {
	return postJSON("/v1.56/containers/create?name=jane-x", `{"Image":"alpine:3.22",`+own+`,"HostConfig":{"NetworkMode":"jane_default","CapDrop":["ALL"],"SecurityOpt":["no-new-privileges"],`+more+`}}`)
}

// The endpoints whose rule refuses nothing for a request's target: they filter or rewrite what
// they answer (a list limited to the scope's own, info and version of its own), so no request of
// theirs is an attack to vary. Each says how it's covered instead.
var noAttack = map[string]string{
	"system.ping":                "always allowed: nothing to refuse",
	"system.version":             "answered from the scope's own view: covered by its base",
	"system.info":                "answered from the scope's own view: covered by its base",
	"container.list":             "the scope's label is added to the filters: Docker's reading of the base shows it",
	"container.prune":            "the scope's label is added to the filters: Docker's reading of the base shows it",
	"network.list":               "the scope's label is added to the filters: Docker's reading of the base shows it",
	"network.prune":              "the scope's label is added to the filters: Docker's reading of the base shows it",
	"volume.list":                "the scope's label is added to the filters: Docker's reading of the base shows it",
	"volume.prune":               "the scope's label is added to the filters: Docker's reading of the base shows it",
	"image.list":                 "the answer is filtered to the scope's images: no request to refuse",
	"image.search":               "a registry search, of no scope's objects",
	"container.inspect":          "onOwnContainer, attacked through container.start and container.delete",
	"container.top":              "onOwnContainer, attacked through container.start and container.delete",
	"container.logs":             "onOwnContainer, attacked through container.start and container.delete",
	"container.changes":          "onOwnContainer, attacked through container.start and container.delete",
	"container.export":           "onOwnContainer, attacked through container.start and container.delete",
	"container.stats":            "onOwnContainer, attacked through container.start and container.delete",
	"container.resize":           "onOwnContainer, attacked through container.start and container.delete",
	"container.stop":             "onOwnContainer, attacked through container.start and container.delete",
	"container.restart":          "onOwnContainer, attacked through container.start and container.delete",
	"container.kill":             "onOwnContainer, attacked through container.start and container.delete",
	"container.pause":            "onOwnContainer, attacked through container.start and container.delete",
	"container.unpause":          "onOwnContainer, attacked through container.start and container.delete",
	"container.attach":           "onOwnContainer, attacked through container.start and container.delete",
	"container.attach-websocket": "onOwnContainer, attacked through container.start and container.delete",
	"container.wait":             "onOwnContainer, attacked through container.start and container.delete",
	"container.archive-info":     "onOwnContainer, attacked through container.start and container.delete",
	"container.archive-get":      "onOwnContainer, attacked through container.start and container.delete",
	"exec.inspect":               "exec, attacked through exec.resize",
}

// tarOf is a tar of these files.
func tarOf(t testing.TB, files map[string]string) []byte {
	t.Helper()

	var buf bytes.Buffer

	w := tar.NewWriter(&buf)

	for name, content := range files {
		if err := w.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(content)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}

		_, _ = w.Write([]byte(content))
	}

	_ = w.Close()

	return buf.Bytes()
}

// imageArchive is a docker save archive of one image, as Docker 25 and later write one: an OCI
// layout whose index.json names the image, its blobs, and a manifest.json.
func imageArchive(t testing.TB, name string) []byte {
	t.Helper()

	layer := tarOf(t, map[string]string{"app": name})
	layerSum := sha256.Sum256(layer)
	layerDigest := "sha256:" + hex.EncodeToString(layerSum[:])

	config, _ := json.Marshal(map[string]any{
		"architecture": "amd64", "os": "linux",
		"rootfs": map[string]any{"type": "layers", "diff_ids": []string{layerDigest}},
	})
	configSum := sha256.Sum256(config)
	configDigest := "sha256:" + hex.EncodeToString(configSum[:])

	manifest, _ := json.Marshal(map[string]any{
		"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
		"config": map[string]any{"mediaType": "application/vnd.oci.image.config.v1+json", "digest": configDigest, "size": len(config)},
		"layers": []any{map[string]any{"mediaType": "application/vnd.oci.image.layer.v1.tar", "digest": layerDigest, "size": len(layer)}},
	})
	manifestSum := sha256.Sum256(manifest)
	manifestDigest := "sha256:" + hex.EncodeToString(manifestSum[:])

	tagAt := len(name)
	for i := len(name) - 1; i >= 0 && name[i] != '/'; i-- {
		if name[i] == ':' {
			tagAt = i

			break
		}
	}

	index, _ := json.Marshal(map[string]any{
		"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json",
		"manifests": []any{map[string]any{
			"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": manifestDigest, "size": len(manifest),
			"annotations": map[string]string{"io.containerd.image.name": "docker.io/" + name, "org.opencontainers.image.ref.name": name[min(tagAt+1, len(name)):]},
		}},
	})
	legacy, _ := json.Marshal([]any{map[string]any{
		"Config": "blobs/sha256/" + configDigest[7:], "RepoTags": []string{name}, "Layers": []string{"blobs/sha256/" + layerDigest[7:]},
	}})

	blobs := map[string]string{
		"blobs/sha256/" + layerDigest[7:]:    string(layer),
		"blobs/sha256/" + configDigest[7:]:   string(config),
		"blobs/sha256/" + manifestDigest[7:]: string(manifest),
		"oci-layout":                         `{"imageLayoutVersion":"1.0.0"}`,
		"index.json":                         string(index),
		"manifest.json":                      string(legacy),
	}

	return tarOf(t, blobs)
}
