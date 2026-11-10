package gate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/moby/moby/api/types/container"

	"github.com/yorvolabs/yorvogate/internal/config"
)

// Docker's defaults, as Docker 29 reports them (daemon/info.go:198-229): what's unsafe, what's noted.
func TestJudgeDockersDefaults(t *testing.T) {
	ubuntu := []string{"name=apparmor,profile=default", "name=seccomp,profile=builtin", "name=cgroupns"}
	listed := func(r string) bool { return r == "runc" || r == "runsc" }

	for name, c := range map[string]struct {
		options []string
		runtime string
		noLSM   bool
		unsafe  string
		note    string
	}{
		"Ubuntu's":                     {ubuntu, "runc", false, "", ""},
		"SELinux instead of AppArmor":  {[]string{"name=selinux", "name=seccomp,profile=builtin", "name=cgroupns"}, "runc", false, "", ""},
		"a default runtime listed":     {ubuntu, "runsc", false, "", ""},
		"seccomp unconfined":           {[]string{"name=apparmor,profile=default", "name=seccomp,profile=unconfined", "name=cgroupns"}, "runc", false, "Docker's own seccomp profile is unconfined, which a container created without seccomp=builtin gets each time it starts", ""},
		"a seccomp profile's path":     {[]string{"name=apparmor,profile=default", "name=seccomp,profile=/etc/docker/seccomp.json", "name=cgroupns"}, "runc", false, "", "Docker's own seccomp profile is /etc/docker/seccomp.json"},
		"an AppArmor profile's path":   {[]string{"name=apparmor,profile=/etc/x", "name=seccomp,profile=builtin", "name=cgroupns"}, "runc", false, "", "Docker's AppArmor profile is /etc/x"},
		"a host cgroup namespace":      {[]string{"name=apparmor,profile=default", "name=seccomp,profile=builtin"}, "runc", false, "", "Docker's default cgroup namespace is the host's"},
		"userns-remap":                 {append(slices.Clone(ubuntu), "name=userns"), "runc", false, "", "userns-remap"},
		"rootless":                     {append(slices.Clone(ubuntu), "name=rootless"), "runc", false, "", "Docker is rootless"},
		"no-new-privileges":            {append(slices.Clone(ubuntu), "name=no-new-privileges"), "runc", false, "", "no-new-privileges"},
		"no LSM, accepted":             {[]string{"name=seccomp,profile=builtin", "name=cgroupns"}, "runc", true, "", "as daemon.without_lsm accepts"},
		"no seccomp in the kernel":     {[]string{"name=apparmor,profile=default", "name=cgroupns"}, "runc", false, "the kernel has no seccomp", ""},
		"no seccomp, without_lsm":      {[]string{"name=cgroupns"}, "runc", true, "the kernel has no seccomp", ""},
		"no LSM":                       {[]string{"name=seccomp,profile=builtin", "name=cgroupns"}, "runc", false, "Docker has neither AppArmor nor SELinux (set daemon.without_lsm: true to accept that)", ""},
		"another default runtime":      {ubuntu, "sysbox-runc", false, "Docker's default runtime sysbox-runc isn't runc, nor one every scoped listener allows", ""},
		"no default runtime":           {ubuntu, "", false, "names no default runtime", ""},
		"a runtime that contains runc": {ubuntu, "runc-x", false, "runc-x isn't runc", ""},
	} {
		state := judge(dockerInfo{SecurityOptions: c.options, DefaultRuntime: c.runtime}, listed, c.noLSM)
		unsafe, notes := strings.Join(state.unsafe, "; "), strings.Join(state.notes, "; ")

		if c.unsafe == "" && unsafe != "" || !strings.Contains(unsafe, c.unsafe) {
			t.Errorf("%s: unsafe %q, want %q", name, unsafe, c.unsafe)
		}

		if !strings.Contains(notes, c.note) || c.note == "" && name == "Ubuntu's" && notes != "" {
			t.Errorf("%s: notes %q, want %q", name, notes, c.note)
		}

		if c.unsafe == "" && state.runtime != c.runtime {
			t.Errorf("%s: the runtime %q", name, state.runtime)
		}
	}
}

// A default runtime is allowed when it's runc or every scoped listener lists it.
func TestADefaultRuntimeEveryScopedListenerAllows(t *testing.T) {
	c, err := config.Parse([]byte(`
upstream: unix:///var/run/docker.sock
listeners:
  - {name: a, address: 'tcp://127.0.0.1:2381', mode: scoped, scopes: /etc/a, containers: {runtimes: [runsc, kata]}}
  - {name: b, address: 'tcp://127.0.0.1:2382', mode: scoped, scopes: /etc/b, containers: {runtimes: [runsc]}}
  - {name: t, address: 'tcp://127.0.0.1:2383', mode: trusted, allow: {system: read}}
`))
	if err != nil {
		t.Fatal(err)
	}

	defaults := NewDefaults(c)

	for runtime, allowed := range map[string]bool{"runc": true, "runsc": true, "kata": false, "crun": false, "": false} {
		if defaults.runtime(runtime) != allowed {
			t.Errorf("%q: allowed %v", runtime, !allowed)
		}
	}
}

// What a container leaves unset, the forwarded body states: a private cgroup namespace, Docker's
// built-in seccomp profile, the default runtime YorvoGate read. What it asks stays.
func TestTheBodyStatesSafeDefaults(t *testing.T) {
	for name, c := range map[string]struct {
		given, want container.HostConfig
	}{
		"nothing set": {
			container.HostConfig{},
			container.HostConfig{CgroupnsMode: "private", SecurityOpt: []string{"seccomp=builtin"}, Runtime: "runc"},
		},
		"each as asked": {
			container.HostConfig{CgroupnsMode: "private", SecurityOpt: []string{"seccomp=/etc/p.json"}, Runtime: "runsc", IpcMode: "shareable"},
			container.HostConfig{CgroupnsMode: "private", SecurityOpt: []string{"seccomp=/etc/p.json"}, Runtime: "runsc", IpcMode: "shareable"},
		},
		"seccomp the old way": {
			container.HostConfig{SecurityOpt: []string{"no-new-privileges", "seccomp:/etc/p.json"}},
			container.HostConfig{CgroupnsMode: "private", SecurityOpt: []string{"no-new-privileges", "seccomp:/etc/p.json"}, Runtime: "runc"},
		},
		"other options": {
			container.HostConfig{SecurityOpt: []string{"no-new-privileges:true", "apparmor=docker-default"}},
			container.HostConfig{CgroupnsMode: "private", SecurityOpt: []string{"no-new-privileges:true", "apparmor=docker-default", "seccomp=builtin"}, Runtime: "runc"},
		},
		"an IPC mode left as Docker sets it": {
			container.HostConfig{IpcMode: ""},
			container.HostConfig{CgroupnsMode: "private", SecurityOpt: []string{"seccomp=builtin"}, Runtime: "runc"},
		},
	} {
		h := c.given
		safeDefaults(&h, "runc")

		got, _ := json.Marshal(h)
		want, _ := json.Marshal(c.want)

		if string(got) != string(want) {
			t.Errorf("%s:\n got %s\nwant %s", name, got, want)
		}
	}
}

func hostConfig(t *testing.T, body string) map[string]any {
	t.Helper()

	var forwarded map[string]any
	if err := json.Unmarshal([]byte(body), &forwarded); err != nil {
		t.Fatal(err)
	}

	return forwarded["HostConfig"].(map[string]any)
}

// A scope's container is created with the runtime YorvoGate last read as Docker's default and found
// safe: a default runtime reloaded live doesn't reach it, and the next read refuses an unlisted one.
func TestACreateCarriesTheRuntimeChecked(t *testing.T) {
	d := startDocker(t)
	server, defaults := gateAndDefaults(t, d, "sites", slog.New(slog.NewTextHandler(io.Discard, nil)))

	create := func() (int, string) {
		return send(t, server, "POST", "/v1.56/containers/create?name=jane-php-1", encode(compose()), asJane)
	}

	if status, answer := create(); status != http.StatusOK {
		t.Fatalf("%d %s", status, answer)
	}

	h := hostConfig(t, d.last().body)
	if h["Runtime"] != "runc" || h["CgroupnsMode"] != "private" || !slices.Contains(h["SecurityOpt"].([]any), any("seccomp=builtin")) || h["IpcMode"] != "" {
		t.Errorf("forwarded %v", h)
	}

	// Docker's default runtime is reloaded as another; until it's read, what's created runs runc.
	info := ubuntuInfo()
	info["DefaultRuntime"] = "sysbox-runc"
	d.mu.Lock()
	d.info = info
	d.mu.Unlock()

	if status, answer := create(); status != http.StatusOK || hostConfig(t, d.last().body)["Runtime"] != "runc" {
		t.Errorf("before the read: %d %s, %v", status, answer, hostConfig(t, d.last().body)["Runtime"])
	}

	defaults.Read(context.Background())

	forwarded := d.count()
	if status, answer := create(); status != http.StatusServiceUnavailable || !strings.Contains(message(t, answer), "Docker's default runtime sysbox-runc isn't runc, nor one every scoped listener allows") || d.count() != forwarded {
		t.Errorf("after the read: %d %s", status, answer)
	}
}

// While Docker's defaults are unsafe, or haven't been read, every scoped request is refused, saying
// why; a trusted listener's aren't. Once they're safe again, scopes are answered.
func TestUnsafeDefaultsRefuseEveryScopedRequest(t *testing.T) {
	d := startDocker(t)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	info := ubuntuInfo()
	info["SecurityOptions"] = []string{"name=apparmor,profile=default", "name=cgroupns"}
	d.mu.Lock()
	d.info = info
	d.mu.Unlock()

	sites, defaults := gateAndDefaults(t, d, "sites", log)
	trusted := gate(t, d, "server")

	for _, path := range []string{"/_ping", "/v1.56/version", "/v1.56/containers/json", "/v1.56/images/json"} {
		forwarded := d.count()
		status, answer := send(t, sites, "GET", path, "", asJane)

		if status != http.StatusServiceUnavailable || message(t, answer) != "yorvogate: Docker's defaults would widen what scopes may do: the kernel has no seccomp (Docker's info lists none), so no container has a seccomp profile" || d.count() != forwarded {
			t.Errorf("%s: %d %s", path, status, answer)
		}
	}

	if status, answer := send(t, trusted, "GET", "/v1.56/containers/json", "", nil); status != http.StatusOK {
		t.Errorf("a trusted listener: %d %s", status, answer)
	}

	d.mu.Lock()
	d.info = nil
	d.mu.Unlock()
	defaults.Read(context.Background())

	if status, answer := send(t, sites, "GET", "/v1.56/containers/json", "", asJane); status != http.StatusOK {
		t.Errorf("once safe: %d %s", status, answer)
	}

	// Unread: no answer yet
	scopes := t.TempDir()
	sum := sha256.Sum256([]byte(token))
	if err := os.WriteFile(filepath.Join(scopes, "jane.json"), []byte(strings.Replace(scopeFile, "%s", hex.EncodeToString(sum[:]), 1)), 0o600); err != nil {
		t.Fatal(err)
	}

	c, err := config.Parse([]byte("upstream: unix://" + d.socket + "\nlisteners:\n  - {name: sites, address: 'tcp://127.0.0.1:2376', mode: scoped, scopes: " + scopes + "}\n"))
	if err != nil {
		t.Fatal(err)
	}

	registry := Registry(c)
	if err := registry.Reload(); err != nil {
		t.Fatal(err)
	}

	unread := httptest.NewServer(New(c, c.Listeners[0], NewUpstream(c, log), registry, NewDefaults(c), log))
	t.Cleanup(unread.Close)

	if status, answer := send(t, unread, "GET", "/_ping", "", asJane); status != http.StatusServiceUnavailable || !strings.Contains(message(t, answer), "haven't been read yet") {
		t.Errorf("unread: %d %s", status, answer)
	}

	// A read that fails is unsafe.
	d.mu.Lock()
	d.info = map[string]any{"SecurityOptions": "not a list"}
	d.mu.Unlock()
	defaults.Read(context.Background())

	if status, answer := send(t, sites, "GET", "/_ping", "", asJane); status != http.StatusServiceUnavailable || !strings.Contains(message(t, answer), "they couldn't be read") {
		t.Errorf("a failed read: %d %s", status, answer)
	}
}

// A trusted listener's create goes to Docker as it came: YorvoGate writes nothing into it.
func TestATrustedCreateIsForwardedAsItCame(t *testing.T) {
	d := startDocker(t)
	server := gate(t, d, "server")
	body := `{"Image":"alpine","HostConfig":{"Privileged":true}}`

	if status, answer := send(t, server, "POST", "/v1.56/containers/create?name=buildkit", body, nil); status != http.StatusOK {
		t.Fatalf("%d %s", status, answer)
	}

	if got := d.last().body; got != body {
		t.Errorf("forwarded %s", got)
	}
}
