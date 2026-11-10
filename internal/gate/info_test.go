package gate

import (
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

func decoded(t *testing.T, s string) any {
	t.Helper()

	var v any
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		t.Fatalf("%v: %s", err, s)
	}

	return v
}

// A scope's /info: of Docker's (testdata/info.json, a hardened host's), what clients read and what
// tells nothing of the host or of other scopes, with the scope's own counts.
func TestAScopesInfo(t *testing.T) {
	d := startDocker(t)

	for listener, want := range map[string]string{
		"sites": `{
			"Architecture": "x86_64", "CPUSet": true, "CPUShares": true, "CgroupDriver": "systemd", "CgroupVersion": "2",
			"CpuCfsPeriod": true, "CpuCfsQuota": true, "Debug": false, "DefaultRuntime": "runc", "Driver": "overlayfs",
			"DriverStatus": [["driver-type", "io.containerd.snapshotter.v1"]], "ExperimentalBuild": false,
			"IPv4Forwarding": true, "IndexServerAddress": "https://index.docker.io/v1/", "Isolation": "",
			"LiveRestoreEnabled": true, "LoggingDriver": "json-file", "MemoryLimit": true, "OSType": "linux",
			"OomKillDisable": false, "PidsLimit": true, "ServerVersion": "29.9.2", "SwapLimit": true,
			"SystemTime": "2026-11-10T20:00:00.000000000Z",
			"SecurityOptions": ["name=apparmor", "name=seccomp", "name=cgroupns", "name=userns"],
			"Swarm": {"LocalNodeState": "inactive"},
			"Plugins": {"Volume": ["local"], "Network": ["bridge"], "Log": ["json-file", "local", "none"]},
			"Runtimes": {"runc": {}},
			"Containers": 2, "ContainersRunning": 1, "ContainersPaused": 0, "ContainersStopped": 1, "Images": 3
		}`,
	} {
		server := gate(t, d, listener)

		status, answer := send(t, server, "GET", "/v1.56/info", "", asJane)
		if status != http.StatusOK {
			t.Fatalf("%s: %d %s", listener, status, answer)
		}

		if got := decoded(t, answer); !reflect.DeepEqual(got, decoded(t, want)) {
			t.Errorf("%s: %s", listener, answer)
		}

		for _, secret := range []string{"host-07", "secret", "mirror.internal", "/var/lib/docker", "7.1.0", "135019876352", "region=fra1", "sysbox", "1.5.2", "10.200.0.0", "/etc/", "AFieldANewerDockerAdds", "Root Dir"} {
			if strings.Contains(answer, secret) {
				t.Errorf("%s: %q is in it", listener, secret)
			}
		}
	}

	// A listener's own log drivers and runtimes are what it lists.
	_, answer := send(t, gate(t, d, "logs"), "GET", "/v1.56/info", "", asJane)
	got := decoded(t, answer).(map[string]any)

	if !reflect.DeepEqual(got["Plugins"], decoded(t, `{"Volume": ["local"], "Network": ["bridge"], "Log": ["json-file", "local", "none", "syslog"]}`)) || !reflect.DeepEqual(got["Runtimes"], decoded(t, `{"runc": {}, "runsc": {}}`)) {
		t.Errorf("logs: %v %v", got["Plugins"], got["Runtimes"])
	}

	// A trusted listener's is Docker's.
	if _, answer := send(t, gate(t, d, "server"), "GET", "/v1.56/info", "", nil); !strings.Contains(answer, "host-07") {
		t.Errorf("trusted: %s", answer)
	}
}

// Each of /info's security options keeps its name, and its profile only when it's Docker's own or
// unconfined.
func TestSecurityOptionsWithoutPaths(t *testing.T) {
	got := securityOptions(json.RawMessage(`["name=apparmor,profile=default", "name=apparmor,profile=/etc/apparmor.d/x", "name=seccomp,profile=builtin", "name=seccomp,profile=unconfined", "name=seccomp,profile=/etc/docker/s.json", "name=selinux", "name=rootless"]`))
	want := []string{"name=apparmor,profile=default", "name=apparmor", "name=seccomp,profile=builtin", "name=seccomp,profile=unconfined", "name=seccomp", "name=selinux", "name=rootless"}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("%q", got)
	}

	if got := securityOptions(nil); got == nil || len(got) != 0 {
		t.Errorf("none: %q", got)
	}
}

// A scope's /version: Docker's own version, API and platform, and its Engine's, with the API versions
// both serve; not the kernel's, build details, or the other components'.
func TestAScopesVersion(t *testing.T) {
	d := startDocker(t)

	status, answer := send(t, gate(t, d, "sites"), "GET", "/v1.56/version", "", asJane)
	if status != http.StatusOK {
		t.Fatalf("%d %s", status, answer)
	}

	want := `{
		"Version": "30.0.0", "ApiVersion": "1.56", "MinAPIVersion": "1.44", "Os": "linux", "Arch": "amd64",
		"Platform": {"Name": "Docker Engine - Community"},
		"Components": [{"Name": "Engine", "Version": "30.0.0", "Details": {"ApiVersion": "1.56", "MinAPIVersion": "1.44", "Os": "linux", "Arch": "amd64", "Experimental": "false"}}]
	}`

	if !reflect.DeepEqual(decoded(t, answer), decoded(t, want)) {
		t.Errorf("%s", answer)
	}

	// A trusted listener's keeps them (with the API versions both serve).
	if _, answer := send(t, gate(t, d, "server"), "GET", "/v1.56/version", "", nil); !strings.Contains(answer, "runc") || !strings.Contains(answer, "KernelVersion") {
		t.Errorf("trusted: %s", answer)
	}
}

// A container's log options, for the driver its logs go to.
func TestLogOptions(t *testing.T) {
	d := startDocker(t)
	sites, logs := gate(t, d, "sites"), gate(t, d, "logs")

	logging := func(driver string, options map[string]any) string {
		return encode(set(compose(), "HostConfig.LogConfig", map[string]any{"Type": driver, "Config": options}))
	}

	for name, c := range map[string]struct {
		server, driver string
		options        map[string]any
		refusal        string
	}{
		"json-file's own":               {"sites", "json-file", map[string]any{"max-size": "10m", "max-file": "3", "compress": "true", "tag": "{{.Name}}", "labels": "a", "labels-regex": "^a", "env": "A", "env-regex": "^A", "mode": "non-blocking", "max-buffer-size": "4m"}, ""},
		"local's own":                   {"sites", "local", map[string]any{"max-size": "10m", "max-file": "3", "compress": "false"}, ""},
		"the default driver's own":      {"sites", "", map[string]any{"max-size": "10m"}, ""},
		"json-file, another's option":   {"sites", "json-file", map[string]any{"syslog-address": "udp://1.2.3.4:514"}, "the log option syslog-address isn't one of the json-file driver's"},
		"the default, another's option": {"sites", "", map[string]any{"gelf-address": "udp://1.2.3.4:12201"}, "the log option gelf-address isn't one of the json-file driver's"},
		"none, with an option":          {"sites", "none", map[string]any{"tag": "x"}, "the log driver none takes no option (tag)"},
		"a buffer too large":            {"sites", "json-file", map[string]any{"mode": "non-blocking", "max-buffer-size": "64g"}, `the log option max-buffer-size "64g" isn't allowed (at most 4194304 bytes`},
		"a buffer just too large":       {"sites", "json-file", map[string]any{"mode": "non-blocking", "max-buffer-size": "4194305"}, "at most 4194304 bytes"},
		"a buffer at the limit":         {"sites", "json-file", map[string]any{"mode": "non-blocking", "max-buffer-size": "4194304"}, ""},
		"a buffer that isn't a size":    {"sites", "json-file", map[string]any{"mode": "non-blocking", "max-buffer-size": "lots"}, `max-buffer-size "lots" isn't allowed`},
		"a listener's buffer limit":     {"logs", "json-file", map[string]any{"mode": "non-blocking", "max-buffer-size": "3m"}, "at most 2097152 bytes"},
		"syslog, its listed address":    {"logs", "syslog", map[string]any{"syslog-address": "udp://10.0.0.9:514", "syslog-facility": "local0", "tag": "x"}, ""},
		"syslog, another address":       {"logs", "syslog", map[string]any{"syslog-address": "udp://169.254.169.254:514"}, `the log option syslog-address="udp://169.254.169.254:514" isn't one the listener allows for the syslog driver`},
		"syslog, an option not listed":  {"logs", "syslog", map[string]any{"syslog-tls-ca-cert": "/etc/ssl/x"}, "the log option syslog-tls-ca-cert"},
		"syslog where it isn't allowed": {"sites", "syslog", map[string]any{}, `the log driver "syslog" isn't allowed`},
	} {
		server := sites
		if c.server == "logs" {
			server = logs
		}

		status, answer := send(t, server, "POST", "/v1.56/containers/create?name=jane-php-1", logging(c.driver, c.options), asJane)

		switch {
		case c.refusal == "" && status != http.StatusOK:
			t.Errorf("%s: %d %s", name, status, answer)
		case c.refusal != "" && (status != http.StatusForbidden || !strings.Contains(message(t, answer), c.refusal)):
			t.Errorf("%s: %d %s", name, status, answer)
		}
	}
}
