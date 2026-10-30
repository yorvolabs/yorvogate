package gate

import (
	"bytes"
	"encoding/json"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
)

// FuzzCreateContainer: whatever body comes, what YorvoGate forwards, read as Docker reads it, asks
// nothing of the host. The check below is written apart from the rules (not with their code), so a
// rule that lets something through fails it.
func FuzzCreateContainer(f *testing.F) {
	d := startDocker(f)
	server := gate(f, d, "sites")

	f.Add(encode(compose()))
	f.Add(encode(set(compose(), "HostConfig.Privileged", true)))
	f.Add(strings.Replace(encode(compose()), `"HostConfig":{`, `"HostConfig":{"privileged":true,`, 1))
	f.Add(strings.Replace(encode(compose()), `"HostConfig":{`, `"HostConfig":{"Privileged":false,"Privileged":true,`, 1))
	f.Add(encode(set(compose(), "HostConfig.Binds", []any{"/:/host"})))
	f.Add(encode(set(compose(), "HostConfig.MaskedPaths", []any{})))
	f.Add(encode(set(set(compose(), "HostConfig.NetworkMode", "host"), "NetworkingConfig", nil)))
	f.Add(encode(set(compose(), "HostConfig.CapAdd", []any{"cap_sys_admin"})))
	f.Add(`{"Image":"x","Labels":{"com.docker.compose.project":"jane"},"HostConfig":{"Mounts":[{"Type":"bind","Source":"/","Target":"/h"}]}}`)

	f.Fuzz(func(t *testing.T, body string) {
		status, _ := send(t, server, "POST", "/v1.56/containers/create?name=jane-fuzz-1", body, asJane)
		if status != 200 {
			return
		}

		var forwarded container.CreateRequest
		if err := json.NewDecoder(bytes.NewReader([]byte(d.last().body))).Decode(&forwarded); err != nil {
			t.Fatalf("forwarded a body Docker can't read: %v", err)
		}

		if problem := hostReach(&forwarded); problem != "" {
			t.Fatalf("forwarded %s: %s", d.last().body, problem)
		}
	})
}

// hostReach is what a container's configuration asks of the host that the test listener never
// allows ("" for nothing).
func hostReach(r *container.CreateRequest) string {
	if r.Config == nil || r.Config.Labels["com.docker.compose.project"] != "jane" || strings.HasPrefix(imageName(r.Config.Image), "quire-sites/blog/") {
		return "not jane's, or another's image"
	}

	h := r.HostConfig
	if h == nil {
		return "no host configuration (Docker's defaults: no limits, all default capabilities)"
	}

	switch {
	case h.Privileged, h.PublishAllPorts, len(h.PortBindings) > 0:
		return "privileged or published"
	case len(h.Devices) > 0, len(h.DeviceRequests) > 0, len(h.DeviceCgroupRules) > 0:
		return "devices"
	case len(h.Sysctls) > 0, len(h.Annotations) > 0, len(h.StorageOpt) > 0, h.CgroupParent != "", h.Cgroup != "":
		return "kernel, runtime or cgroup settings"
	case h.MaskedPaths != nil, h.ReadonlyPaths != nil:
		return "/proc paths changed"
	case string(h.PidMode) == "host", string(h.IpcMode) == "host", string(h.UTSMode) == "host", string(h.UsernsMode) == "host", string(h.CgroupnsMode) == "host":
		return "a host namespace"
	case slices.Contains([]string{"", "host", "bridge", "default"}, string(h.NetworkMode)):
		return "the host's or the default network"
	case h.OomKillDisable != nil && *h.OomKillDisable, h.OomScoreAdj < 0, h.CPURealtimeRuntime != 0, h.CPURealtimePeriod != 0:
		return "the OOM killer or the real-time scheduler"
	case h.Memory <= 0 || h.Memory > 1<<30, h.PidsLimit == nil || *h.PidsLimit <= 0 || *h.PidsLimit > 512:
		return "no limits"
	case h.Runtime != "" || (h.Isolation != "" && h.Isolation != "default"):
		return "another runtime"
	case !slices.ContainsFunc(h.CapDrop, func(c string) bool { return strings.EqualFold(c, "all") }):
		return "default capabilities kept"
	}

	for _, c := range h.CapAdd {
		if name := strings.TrimPrefix(strings.ToUpper(c), "CAP_"); name != "NET_BIND_SERVICE" && name != "CHOWN" {
			return "capability " + c
		}
	}

	for _, o := range h.SecurityOpt {
		if !slices.Contains([]string{"no-new-privileges", "no-new-privileges:true", "no-new-privileges=true"}, o) {
			return "security option " + o
		}
	}

	for _, b := range h.Binds {
		if source, _, _ := strings.Cut(b, ":"); strings.ContainsAny(source, "/.\\~") || !strings.HasPrefix(source, "jane") {
			return "bind " + b
		}
	}

	for _, m := range h.Mounts {
		if (m.Type != mount.TypeVolume && m.Type != mount.TypeTmpfs) || m.BindOptions != nil || m.ImageOptions != nil || m.ClusterOptions != nil ||
			(m.VolumeOptions != nil && m.VolumeOptions.DriverConfig != nil && len(m.VolumeOptions.DriverConfig.Options) > 0) ||
			(m.Type == mount.TypeVolume && m.Source != "" && !strings.HasPrefix(m.Source, "jane")) {
			return "mount of " + m.Source
		}
	}

	return ""
}

// FuzzListFilters: whatever filters come, a list Docker gets is limited to the scope's own.
func FuzzListFilters(f *testing.F) {
	d := startDocker(f)
	server := gate(f, d, "sites")

	for _, seed := range []string{"", `{"label":["a=b"]}`, `{"label":{"a=b":true}}`, `{"LABEL":["com.docker.compose.project=blog"]}`, `{"label":null}`, `[]`, `{"label":"x"}`} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, filters string) {
		status, _ := send(t, server, "GET", "/v1.56/containers/json?filters="+url.QueryEscape(filters), "", asJane)
		if status != 200 {
			return
		}

		query, _ := url.ParseQuery(d.last().query)
		var forwarded map[string][]string
		if err := json.Unmarshal([]byte(query.Get("filters")), &forwarded); err != nil {
			t.Fatalf("forwarded filters Docker can't read: %q", query.Get("filters"))
		}

		if !slices.Contains(forwarded["label"], "com.docker.compose.project=jane") || len(query["filters"]) != 1 {
			t.Fatalf("%q forwarded as %q", filters, query["filters"])
		}
	})
}

// FuzzArchiveNames: whatever an archive holds, reading its names never fails but with an error.
func FuzzArchiveNames(f *testing.F) {
	f.Add([]byte{})
	f.Add(archive(f, entry{name: "manifest.json", content: `[{"RepoTags":["quire-sites/jane/x:1"]}]`}))
	f.Add(gzipped(archive(f, entry{name: "index.json", content: `{"manifests":[{"annotations":{"io.containerd.image.name":"x"}}]}`})))
	f.Add([]byte("BZh91AY&SY"))

	f.Fuzz(func(t *testing.T, data []byte) {
		names, err := archiveNames(bytes.NewReader(data))
		if err == nil {
			for _, n := range names {
				if n == "" {
					t.Fatal("an empty name")
				}
			}
		}
	})
}
