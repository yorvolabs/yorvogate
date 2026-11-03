package gate

import (
	"net/http"
	"strings"
	"testing"
)

const dialStdioExec = `{"AttachStdin":true,"AttachStdout":true,"AttachStderr":true,"Cmd":["buildctl","dial-stdio"]}`

// What buildx's remote driver sends (measured): an inspect of the builder, an exec of buildctl
// dial-stdio, and its start. That's all a scope may do with its builder.
func TestABuilderIsReachedOnlyByDialStdio(t *testing.T) {
	d := startDocker(t)
	server := gate(t, d, "sites")

	for _, c := range [][3]string{
		{"GET", "/v1.56/containers/buildx_buildkit_jane0/json", ""},
		{"POST", "/v1.56/containers/buildx_buildkit_jane0/exec", dialStdioExec},
		{"POST", "/v1.56/exec/exec-dial-as-docker-says/start", `{"Detach":true}`},
		{"POST", "/v1.56/exec/exec-dial/start", `{"Detach":true}`},
	} {
		if status, answer := send(t, server, c[0], c[1], c[2], asJane); status != http.StatusOK {
			t.Errorf("%s %s: %d %s", c[0], c[1], status, answer)
		}
	}

	if got := d.last(); got.path != "/v1.56/exec/exec-dial/start" {
		t.Errorf("forwarded %s", got.path)
	}

	before := d.count()

	for name, c := range map[string]struct{ method, path, body, words string }{
		"a shell":                 {"POST", "/v1.56/containers/buildx_buildkit_jane0/exec", `{"Cmd":["sh"]}`, "only buildctl dial-stdio"},
		"dial-stdio and more":     {"POST", "/v1.56/containers/buildx_buildkit_jane0/exec", `{"Cmd":["buildctl","dial-stdio","--x"]}`, "only buildctl dial-stdio"},
		"dial-stdio as root":      {"POST", "/v1.56/containers/buildx_buildkit_jane0/exec", `{"Cmd":["buildctl","dial-stdio"],"User":"0"}`, "User"},
		"dial-stdio, privileged":  {"POST", "/v1.56/containers/buildx_buildkit_jane0/exec", `{"Cmd":["buildctl","dial-stdio"],"Privileged":true}`, "Privileged"},
		"dial-stdio with an env":  {"POST", "/v1.56/containers/buildx_buildkit_jane0/exec", `{"Cmd":["buildctl","dial-stdio"],"Env":["LD_PRELOAD=/x"]}`, "Env"},
		"dial-stdio elsewhere":    {"POST", "/v1.56/containers/buildx_buildkit_jane0/exec", `{"Cmd":["buildctl","dial-stdio"],"WorkingDir":"/tmp"}`, "WorkingDir"},
		"dial-stdio with a tty":   {"POST", "/v1.56/containers/buildx_buildkit_jane0/exec", `{"Cmd":["buildctl","dial-stdio"],"Tty":true}`, "Tty"},
		"starting another's exec": {"POST", "/v1.56/exec/exec-shell/start", `{"Detach":true}`, "only buildctl dial-stdio is started"},
		"starting a root exec":    {"POST", "/v1.56/exec/exec-dial-root/start", `{"Detach":true}`, "only buildctl dial-stdio is started"},
		"resizing dial-stdio":     {"POST", "/v1.56/exec/exec-dial/resize?h=1&w=1", "", "exec.resize isn't allowed in builder"},
		"inspecting dial-stdio":   {"GET", "/v1.56/exec/exec-dial/json", "", "exec.inspect isn't allowed in builder"},
		"an archive out":          {"GET", "/v1.56/containers/buildx_buildkit_jane0/archive?path=/etc", "", "isn't allowed on builder"},
		"an archive in":           {"PUT", "/v1.56/containers/buildx_buildkit_jane0/archive?path=/tmp", "x", "isn't allowed on builder"},
		"its stat":                {"HEAD", "/v1.56/containers/buildx_buildkit_jane0/archive?path=/etc", "", "isn't allowed on builder"},
		"its logs":                {"GET", "/v1.56/containers/buildx_buildkit_jane0/logs?stdout=1", "", "isn't allowed on builder"},
		"its export":              {"GET", "/v1.56/containers/buildx_buildkit_jane0/export", "", "isn't allowed on builder"},
		"stopping it":             {"POST", "/v1.56/containers/buildx_buildkit_jane0/stop", "", "isn't allowed on builder"},
		"killing it":              {"POST", "/v1.56/containers/buildx_buildkit_jane0/kill", "", "isn't allowed on builder"},
		"removing it":             {"DELETE", "/v1.56/containers/buildx_buildkit_jane0", "", "isn't allowed on builder"},
		"updating it":             {"POST", "/v1.56/containers/buildx_buildkit_jane0/update", `{"Memory":0}`, "isn't allowed on builder"},
		"renaming it":             {"POST", "/v1.56/containers/buildx_buildkit_jane0/rename?name=jane-x", "", "isn't allowed on builder"},
	} {
		status, answer := send(t, server, c.method, c.path, c.body, asJane)
		if c.method == "HEAD" {
			if status != http.StatusForbidden {
				t.Errorf("%s: %d", name, status)
			}

			continue
		}

		if status != http.StatusForbidden || !strings.Contains(message(t, answer), c.words) {
			t.Errorf("%s: %d %s", name, status, answer)
		}
	}

	// An attach is an upgrade: refused before one is asked for, and on a builder in any case.
	if status, _ := send(t, server, "POST", "/v1.56/containers/buildx_buildkit_jane0/attach?stream=1", "", map[string]string{"X-YorvoGate-Scope": "jane", "X-YorvoGate-Token": token, "Connection": "Upgrade", "Upgrade": "tcp"}); status != http.StatusForbidden {
		t.Errorf("attach: %d", status)
	}

	if d.count() != before {
		t.Errorf("%d refused requests reached Docker", d.count()-before)
	}
}

// A builder isn't one of its containers: nothing may join its namespaces or take its volumes, nor
// connect it to a network, even when it carries the scope's owner label.
func TestABuilderIsNotItsOwn(t *testing.T) {
	d := startDocker(t)
	server := gate(t, d, "sites")
	d.setBuilder("Config.Labels", map[string]string{"com.docker.compose.project": "jane"})

	for name, body := range map[string]map[string]any{
		"its PIDs":    set(compose(), "HostConfig.PidMode", "container:buildx_buildkit_jane0"),
		"its IPC":     set(compose(), "HostConfig.IpcMode", "container:buildx_buildkit_jane0"),
		"its network": set(set(compose(), "HostConfig.NetworkMode", "container:buildx_buildkit_jane0"), "NetworkingConfig", nil),
		"its volumes": set(compose(), "HostConfig.VolumesFrom", []string{"buildx_buildkit_jane0"}),
	} {
		if status, answer := send(t, server, "POST", "/v1.56/containers/create?name=jane-worker-1", encode(body), asJane); status != http.StatusForbidden || !strings.Contains(message(t, answer), "buildx_buildkit_jane0") {
			t.Errorf("%s: %d %s", name, status, answer)
		}
	}

	for _, path := range []string{"/v1.56/networks/jane_default/connect", "/v1.56/networks/jane_default/disconnect"} {
		if status, answer := send(t, server, "POST", path, `{"Container":"buildx_buildkit_jane0"}`, asJane); status != http.StatusNotFound {
			t.Errorf("%s: %d %s", path, status, answer)
		}
	}

	if status, answer := send(t, server, "POST", "/v1.56/containers/buildx_buildkit_jane0/exec", `{"Cmd":["sh"]}`, asJane); status != http.StatusForbidden {
		t.Errorf("a shell in a builder labelled its own: %d %s", status, answer)
	}

	if status, answer := send(t, server, "POST", "/v1.56/containers/buildx_buildkit_jane0/stop", "", asJane); status != http.StatusForbidden {
		t.Errorf("stopping a builder labelled its own: %d %s", status, answer)
	}

	if status, answer := send(t, server, "GET", "/v1.56/containers/buildx_buildkit_jane0/json", "", map[string]string{"X-YorvoGate-Scope": "jane-blog", "X-YorvoGate-Token": "x"}); status != http.StatusUnauthorized {
		t.Errorf("%d %s", status, answer)
	}

	if d.count() != 0 {
		t.Errorf("%d refused requests reached Docker", d.count())
	}
}

// A builder is used only while it's configured as a builder must be: each property that fails is
// named, and nothing reaches Docker.
func TestABuildersConfiguration(t *testing.T) {
	for name, c := range map[string]struct {
		path  string
		value any
		words string
	}{
		"privileged":                   {"HostConfig.Privileged", true, "it's privileged"},
		"a capability":                 {"HostConfig.CapAdd", []string{"SYS_ADMIN"}, "SYS_ADMIN"},
		"a device":                     {"HostConfig.Devices", []map[string]any{{"PathOnHost": "/dev/sda", "PathInContainer": "/dev/sda"}}, "devices"},
		"a GPU":                        {"HostConfig.DeviceRequests", []map[string]any{{"Count": -1}}, "devices"},
		"device rules":                 {"HostConfig.DeviceCgroupRules", []string{"b 8:* rmw"}, "devices"},
		"a bind":                       {"HostConfig.Binds", []string{"/:/host"}, `binds the host path "/"`},
		"a relative bind":              {"HostConfig.Binds", []string{"state:/s", "./x:/host"}, `binds the host path "./x"`},
		"a bind mount":                 {"HostConfig.Mounts", []map[string]any{{"Type": "bind", "Source": "/", "Target": "/host"}}, `mounts "/" as bind`},
		"a bind it has":                {"Mounts", []map[string]any{{"Type": "bind", "Source": "/", "Destination": "/host"}}, "a bind mount at /host"},
		"the host's PIDs":              {"HostConfig.PidMode", "host", "the host's namespaces"},
		"the host's IPC":               {"HostConfig.IpcMode", "host", "the host's namespaces"},
		"the host's UTS":               {"HostConfig.UTSMode", "host", "the host's namespaces"},
		"the host's users":             {"HostConfig.UsernsMode", "host", "the host's namespaces"},
		"the host's cgroups":           {"HostConfig.CgroupnsMode", "host", "the host's namespaces"},
		"the host's network":           {"HostConfig.NetworkMode", "host", "the host's namespaces"},
		"another's PIDs":               {"HostConfig.PidMode", "container:blog-php-1", "joins another container"},
		"another's volumes":            {"HostConfig.VolumesFrom", []string{"blog-php-1"}, "joins another container"},
		"a port":                       {"HostConfig.PortBindings", map[string]any{"1234/tcp": []map[string]any{{"HostPort": "1234"}}}, "publishes ports"},
		"every port":                   {"HostConfig.PublishAllPorts", true, "publishes ports"},
		"a kernel parameter":           {"HostConfig.Sysctls", map[string]string{"kernel.x": "1"}, "Sysctls"},
		"root":                         {"Config.User", "0", "runs as root"},
		"root by name":                 {"Config.User", "root:root", "runs as root"},
		"no user":                      {"Config.User", "", "runs as root"},
		"a profile not listed":         {"HostConfig.SecurityOpt", []string{"apparmor=docker-default-loose"}, "apparmor=docker-default-loose"},
		"no AppArmor, not listed":      {"HostConfig.SecurityOpt", []string{"apparmor=unconfined"}, "apparmor=unconfined"},
		"an SELinux label":             {"HostConfig.SecurityOpt", []string{"label=disable"}, "label=disable"},
		"a seccomp profile of its own": {"HostConfig.SecurityOpt", []string{"seccomp=/x.json"}, "seccomp=/x.json"},
		"no-new-privileges, bare":      {"HostConfig.SecurityOpt", []string{"no-new-privileges"}, `"no-new-privileges" isn't allowed`},
		"no-new-privileges true":       {"HostConfig.SecurityOpt", []string{"no-new-privileges=true"}, `"no-new-privileges=true" isn't allowed`},
	} {
		d := startDocker(t)
		server := gate(t, d, "sites")
		d.setBuilder(c.path, c.value)

		for _, r := range [][3]string{
			{"GET", "/v1.56/containers/buildx_buildkit_jane0/json", ""},
			{"POST", "/v1.56/containers/buildx_buildkit_jane0/exec", dialStdioExec},
			{"POST", "/v1.56/exec/exec-dial/start", `{"Detach":true}`},
		} {
			status, answer := send(t, server, r[0], r[1], r[2], asJane)
			if status != http.StatusForbidden || !strings.Contains(message(t, answer), "isn't configured as a builder must be") || !strings.Contains(message(t, answer), c.words) {
				t.Errorf("%s, %s: %d %s", name, r[1], status, answer)
			}
		}

		if d.count() != 0 {
			t.Errorf("%s: %d requests reached Docker", name, d.count())
		}

		// Where the listener accepts any builder, it's accepted (the scope is then root on the host).
		if status, answer := send(t, gate(t, d, "any-builder"), "POST", "/v1.56/containers/buildx_buildkit_jane0/exec", dialStdioExec, asJane); status != http.StatusOK {
			t.Errorf("%s, with allow_privileged_builders: %d %s", name, status, answer)
		}
	}

	// What a rootless builder may have: no-new-privileges=false (the opt-out it needs on a daemon
	// that defaults no-new-privileges on), in either of Docker's forms, and the unconfined/apparmor
	// options.
	// Its state in a named volume, as "docker run -v <name>:<path>" gives it (among the binds)
	d := startDocker(t)
	d.setBuilder("HostConfig.Binds", []string{"buildkit-jane-state:/home/user/.local/share/buildkit", "cache:/cache:ro"})

	if status, answer := send(t, gate(t, d, "sites"), "POST", "/v1.56/containers/buildx_buildkit_jane0/exec", dialStdioExec, asJane); status != http.StatusOK {
		t.Errorf("a named volume, as a bind: %d %s", status, answer)
	}

	for _, options := range [][]string{
		{"no-new-privileges=false"}, {"no-new-privileges:false"}, {"seccomp:unconfined", "apparmor:yorvogate-buildkit-rootless"}, nil,
	} {
		d := startDocker(t)
		d.setBuilder("HostConfig.SecurityOpt", options)

		if status, answer := send(t, gate(t, d, "sites"), "POST", "/v1.56/containers/buildx_buildkit_jane0/exec", dialStdioExec, asJane); status != http.StatusOK {
			t.Errorf("%v: %d %s", options, status, answer)
		}
	}
}
