package differential

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yorvolabs/yorvogate/internal/gate"
)

// The checked fields each attack sets to a refused value, by endpoint and attack name: a field the
// gate says it checks has a request that shows the check refusing (0.3-e, C1).
var attackFields = map[string][]string{
	"container.create/privileged":                          {"HostConfig"},
	"container.create/the host's /":                        {"HostConfig.Binds"},
	"container.create/another scope's label":               {"Labels"},
	"container.create/the host's network":                  {"HostConfig.NetworkMode"},
	"container.create/a protected image":                   {"Image"},
	"container.create/another scope's network":             {"NetworkingConfig", "NetworkingConfig.EndpointsConfig"},
	"container.create/a capability added":                  {"HostConfig.CapAdd"},
	"container.create/not every capability dropped":        {"HostConfig.CapDrop"},
	"container.create/the host's cgroup namespace":         {"HostConfig.CgroupnsMode"},
	"container.create/the host's IPC namespace":            {"HostConfig.IpcMode"},
	"container.create/the host's PID namespace":            {"HostConfig.PidMode"},
	"container.create/the host's UTS namespace":            {"HostConfig.UTSMode"},
	"container.create/the host's user namespace":           {"HostConfig.UsernsMode"},
	"container.create/another isolation":                   {"HostConfig.Isolation"},
	"container.create/a log driver not allowed":            {"HostConfig.LogConfig", "HostConfig.LogConfig.Type"},
	"container.create/a log option not the driver's":       {"HostConfig.LogConfig.Config"},
	"container.create/a bind mount":                        {"HostConfig.Mounts", "HostConfig.Mounts[].Type"},
	"container.create/another scope's volume mounted":      {"HostConfig.Mounts[].Source"},
	"container.create/a mount's relative target":           {"HostConfig.Mounts[].Target"},
	"container.create/a mount's volume labelled another's": {"HostConfig.Mounts[].VolumeOptions", "HostConfig.Mounts[].VolumeOptions.Labels"},
	"container.create/a mount's subpath out of the volume": {"HostConfig.Mounts[].VolumeOptions.Subpath"},
	"container.create/a mount's volume driver":             {"HostConfig.Mounts[].VolumeOptions.DriverConfig", "HostConfig.Mounts[].VolumeOptions.DriverConfig.Name"},
	"container.create/a mount's volume driver options":     {"HostConfig.Mounts[].VolumeOptions.DriverConfig.Options"},
	"container.create/the OOM killer disabled":             {"HostConfig.OomKillDisable"},
	"container.create/an OOM score below 0":                {"HostConfig.OomScoreAdj"},
	"container.create/a runtime not allowed":               {"HostConfig.Runtime"},
	"container.create/a security option not allowed":       {"HostConfig.SecurityOpt"},
	"container.create/a ulimit not allowed":                {"HostConfig.Ulimits", "HostConfig.Ulimits[].Name"},
	"container.create/a volume driver":                     {"HostConfig.VolumeDriver"},
	"container.create/another scope's volumes":             {"HostConfig.VolumesFrom"},
	"container.update/the OOM killer disabled":             {"OomKillDisable"},
	"container.update/a ulimit not allowed":                {"Ulimits", "Ulimits[].Name"},
	"network.connect/another scope's container":            {"Container"},
	"network.connect/an endpoint's legacy links":           {"EndpointConfig"},
	"network.disconnect/from another scope's network":      {"Container"},
	"network.create/another scope's name":                  {"Name"},
	"network.create/a driver not allowed":                  {"Driver"},
	"network.create/the swarm's scope":                     {"Scope"},
	"network.create/another scope's label":                 {"Labels"},
	"network.create/an IPAM plugin":                        {"IPAM", "IPAM.Driver"},
	"volume.create/another scope's name":                   {"Name"},
	"volume.create/a driver not allowed":                   {"Driver"},
	"volume.create/another scope's label":                  {"Labels"},
}

// The checked fields whose refusal needs what the suite's listener and scopes don't have (limits,
// a shared network, egress: none, subnets, a builder), by endpoint and path: the test in
// internal/gate that refuses each.
var refusedElsewhere = map[string]string{
	"container.create HostConfig.Memory":                                          "TestWhatReachesTheHostOrAnotherScopeIsRefused",
	"container.create HostConfig.PidsLimit":                                       "TestWhatReachesTheHostOrAnotherScopeIsRefused",
	"container.create NetworkingConfig.EndpointsConfig{}.Aliases":                 "TestWhatReachesTheHostOrAnotherScopeIsRefused",
	"container.create NetworkingConfig.EndpointsConfig{}.IPAMConfig":              "TestWhatReachesTheHostOrAnotherScopeIsRefused",
	"container.create NetworkingConfig.EndpointsConfig{}.IPAMConfig.IPv4Address":  "TestWhatReachesTheHostOrAnotherScopeIsRefused",
	"container.create NetworkingConfig.EndpointsConfig{}.IPAMConfig.IPv6Address":  "TestWhatReachesTheHostOrAnotherScopeIsRefused",
	"container.create NetworkingConfig.EndpointsConfig{}.IPAMConfig.LinkLocalIPs": "TestWhatReachesTheHostOrAnotherScopeIsRefused",
	"container.update Memory":                                                     "TestNewLimitsAreChecked",
	"container.update PidsLimit":                                                  "TestNewLimitsAreChecked",
	"exec.create Cmd":                                                             "TestABuilderIsReachedOnlyByDialStdio",
	"exec.start Detach":                                                           "TestExecsAreInItsOwnContainersAndNeverPrivileged",
	"network.connect EndpointConfig.Aliases":                                      "TestJoiningANetwork",
	"network.connect EndpointConfig.IPAMConfig":                                   "TestJoiningANetwork",
	"network.connect EndpointConfig.IPAMConfig.IPv4Address":                       "TestJoiningANetwork",
	"network.connect EndpointConfig.IPAMConfig.IPv6Address":                       "TestJoiningANetwork",
	"network.connect EndpointConfig.IPAMConfig.LinkLocalIPs":                      "TestJoiningANetwork",
	"network.create Internal":                                                     "TestAnEgressFreeScopeCreatesInternalNetworks",
	"network.create IPAM.Config":                                                  "TestNetworksOfItsOwn",
	"network.create IPAM.Config[].Subnet":                                         "TestNetworksOfItsOwn",
}

// Every field the gate checks is refused somewhere: by an attack here that sets it (and so by every
// variant of that attack, TestEveryAttackVariantIsRefused), or by the internal/gate test named.
func TestEveryCheckedFieldIsRefused(t *testing.T) {
	checkedFields := map[string]bool{}

	for _, f := range gate.Fields() {
		if f.Class == "checked" {
			checkedFields[f.Endpoint+" "+f.Path] = true
		}
	}

	if len(checkedFields) < 60 {
		t.Fatalf("only %d checked fields: gate.Fields wasn't read as expected", len(checkedFields))
	}

	byAttack := map[string]bool{}
	known := map[string]bool{}

	for _, a := range attacks {
		key := a.endpoint + "/" + a.name
		known[key] = true

		for _, path := range attackFields[key] {
			field := a.endpoint + " " + path
			if !checkedFields[field] {
				t.Errorf("%s: %s isn't a field the gate checks", key, field)
			}

			var body any
			if err := json.Unmarshal(a.req(t).body, &body); err != nil {
				t.Errorf("%s: its body isn't JSON: %v", key, err)

				continue
			}

			if !present(body, strings.Split(path, ".")) {
				t.Errorf("%s: its body doesn't set %s", key, path)
			}

			byAttack[field] = true
		}
	}

	for key := range attackFields {
		if !known[key] {
			t.Errorf("attackFields names %s, which isn't an attack", key)
		}
	}

	tests := gateTests(t)

	for field, test := range refusedElsewhere {
		switch {
		case !checkedFields[field]:
			t.Errorf("refusedElsewhere names %s, which isn't a field the gate checks", field)
		case byAttack[field]:
			t.Errorf("%s: an attack here sets it, so it needs no refusedElsewhere", field)
		case !tests[test]:
			t.Errorf("%s: internal/gate has no %s", field, test)
		}
	}

	for field := range checkedFields {
		if _, elsewhere := refusedElsewhere[field]; !byAttack[field] && !elsewhere {
			t.Errorf("%s: the gate checks it, but no attack sets it to a refused value (attackFields), nor is a test named that refuses it (refusedElsewhere)", field)
		}
	}
}

// present tells whether a JSON value sets a field by its path: keys matched regardless of case, as
// Docker and the gate read them; [] steps into any element of a list, {} into any value of a map.
func present(v any, path []string) bool {
	if len(path) == 0 {
		return v != nil
	}

	key, steps := path[0], ""
	if i := strings.IndexAny(key, "[{"); i >= 0 {
		key, steps = key[:i], key[i:]
	}

	object, ok := v.(map[string]any)
	if !ok {
		return false
	}

	for k, value := range object {
		if strings.EqualFold(k, key) && into(value, steps, path[1:]) {
			return true
		}
	}

	return false
}

// into follows a field's steps ([] and {}) into what it holds, then the rest of the path.
func into(v any, steps string, rest []string) bool {
	switch {
	case steps == "":
		return present(v, rest)
	case strings.HasPrefix(steps, "[]"):
		list, _ := v.([]any)
		for _, e := range list {
			if into(e, steps[2:], rest) {
				return true
			}
		}
	case strings.HasPrefix(steps, "{}"):
		object, _ := v.(map[string]any)
		for _, e := range object {
			if into(e, steps[2:], rest) {
				return true
			}
		}
	}

	return false
}

// gateTests are the names of internal/gate's tests.
func gateTests(t *testing.T) map[string]bool {
	files, err := filepath.Glob(filepath.Join("..", "..", "internal", "gate", "*_test.go"))
	if err != nil || len(files) == 0 {
		t.Fatalf("internal/gate's tests: %v", err)
	}

	names := map[string]bool{}

	for _, file := range files {
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}

		for _, line := range strings.Split(string(raw), "\n") {
			if name, ok := strings.CutPrefix(line, "func Test"); ok {
				if n, _, ok := strings.Cut(name, "(t *testing.T)"); ok {
					names["Test"+n] = true
				}
			}
		}
	}

	return names
}
