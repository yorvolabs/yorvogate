package gate

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// The volume drivers and options every site is tried with: a plain local volume, and each way one
// can reach the host.
var volumeCases = []struct {
	name    string
	driver  string
	options map[string]string
	plain   bool
}{
	{"no driver", "", nil, true},
	{"local", "local", nil, true},
	{"a plugin", "rexray/ebs", nil, false},
	{"local, a bind", "local", map[string]string{"o": "bind"}, false},
	{"local, a device", "local", map[string]string{"device": "/"}, false},
	{"local, type none", "local", map[string]string{"type": "none"}, false},
	{"local, all three", "local", map[string]string{"type": "none", "o": "bind", "device": "/"}, false},
	{"a plugin, options", "rexray/ebs", map[string]string{"size": "1"}, false},
}

// volumeDrivers is how fake Docker has each volume: jane's own volumes, one for each case.
var volumeDrivers = map[string]struct {
	driver  string
	options map[string]string
}{
	"jane_hostbind": {"local", map[string]string{"type": "none", "o": "bind", "device": "/"}},
}

func caseVolume(i int) string { return "jane_case" + string(rune('a'+i)) }

func init() {
	for i, c := range volumeCases {
		volumes = append(volumes, fakeObject{caseVolume(i), caseVolume(i), jane})
		volumeDrivers[caseVolume(i)] = struct {
			driver  string
			options map[string]string
		}{c.driver, c.options}
	}
}

func TestPlainLocal(t *testing.T) {
	for _, c := range volumeCases {
		if plainLocal(c.driver, c.options) != c.plain {
			t.Errorf("%s: %v", c.name, !c.plain)
		}
	}
}

func TestHostPath(t *testing.T) {
	for source, want := range map[string]bool{
		"": true, "/": true, "/srv": true, `C:\x`: true, "a/b": true, ".": true, "./x": true, "..": true, "~": true, "~/x": true,
		"jane_data": false, "jane-data.1": false,
	} {
		if hostPath(source) != want {
			t.Errorf("%q: %v", source, !want)
		}
	}
}

// Each volume case, through every site a volume is mounted, created or found: a plain local one
// passes everywhere, and any other is refused everywhere.
func TestAVolumesDriverIsCheckedEverywhere(t *testing.T) {
	for i, c := range volumeCases {
		d := startDocker(t)
		server := gate(t, d, "sites")

		marshal := func(v any) string {
			b, _ := json.Marshal(v)

			return string(b)
		}

		sites := map[string][2]string{
			// A mount's driver configuration, the volume created with it
			"a mount's DriverConfig": {"/v1.56/containers/create?name=jane-php-9", marshal(set(compose(), "HostConfig.Mounts", []any{map[string]any{
				"Type": "volume", "Source": "jane_new", "Target": "/x",
				"VolumeOptions": map[string]any{"DriverConfig": map[string]any{"Name": c.driver, "Options": c.options}},
			}}))},
			// An existing volume of its own, mounted (a bind's name, and a mount's source)
			"a named volume it binds":  {"/v1.56/containers/create?name=jane-php-9", marshal(set(compose(), "HostConfig.Binds", []any{caseVolume(i) + ":/x"}))},
			"a named volume it mounts": {"/v1.56/containers/create?name=jane-php-9", marshal(set(compose(), "HostConfig.Mounts", []any{map[string]any{"Type": "volume", "Source": caseVolume(i), "Target": "/x"}}))},
			"volume.create":            {"/v1.56/volumes/create", marshal(map[string]any{"Name": "jane_new", "Driver": c.driver, "DriverOpts": c.options, "Labels": jane})},
		}

		// HostConfig.VolumeDriver has a driver and no options
		if c.options == nil {
			sites["HostConfig.VolumeDriver"] = [2]string{"/v1.56/containers/create?name=jane-php-9", marshal(set(compose(), "HostConfig.VolumeDriver", c.driver))}
		}

		for site, r := range sites {
			status, answer := send(t, server, "POST", r[0], r[1], asJane)
			if c.plain && status >= 400 {
				t.Errorf("%s, %s: %d %s", c.name, site, status, answer)
			}

			if !c.plain && status != http.StatusForbidden {
				t.Errorf("%s, %s: %d %s", c.name, site, status, answer)
			}
		}

		// A builder with the volume
		d.setBuilder("Mounts", []map[string]any{{"Type": "volume", "Name": caseVolume(i), "Destination": "/home/user/.local/share/buildkit"}})

		status, answer := send(t, server, "GET", "/v1.56/containers/buildx_buildkit_jane0/json", "", asJane)
		if c.plain && status != http.StatusOK {
			t.Errorf("%s, a builder: %d %s", c.name, status, answer)
		}

		if !c.plain && (status != http.StatusForbidden || !strings.Contains(message(t, answer), "could bind a host path")) {
			t.Errorf("%s, a builder: %d %s", c.name, status, answer)
		}
	}
}

// A builder's volume Docker can't say anything of is refused.
func TestABuildersVolumeMustBeRead(t *testing.T) {
	d := startDocker(t)
	server := gate(t, d, "sites")
	d.setBuilder("Mounts", []map[string]any{{"Type": "volume", "Name": "gone", "Destination": "/state"}})

	if status, answer := send(t, server, "GET", "/v1.56/containers/buildx_buildkit_jane0/json", "", asJane); status != http.StatusForbidden || !strings.Contains(message(t, answer), "couldn't be read") {
		t.Errorf("%d %s", status, answer)
	}

	if d.count() != 0 {
		t.Errorf("%d requests reached Docker", d.count())
	}
}
