package config

import (
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

// Every key of the configuration is classified for a reload (reloadable, moved, restart): a key
// added to a type fails here until it is.
func TestEveryKeyIsClassifiedForAReload(t *testing.T) {
	for _, tc := range []struct {
		of   any
		keys map[string]keyClass
	}{
		{Config{}, configKeys},
		{Listener{}, listenerKeys},
		{Spool{}, spoolKeys},
		{Admin{}, adminKeys},
	} {
		rt := reflect.TypeOf(tc.of)

		var tags []string

		for i := range rt.NumField() {
			tag, _, _ := strings.Cut(rt.Field(i).Tag.Get("yaml"), ",")
			if tag == "" || tag == "-" {
				continue
			}

			tags = append(tags, tag)

			if _, ok := tc.keys[tag]; !ok {
				t.Errorf("%s's %q isn't classified for a reload", rt.Name(), tag)
			}
		}

		for key := range tc.keys {
			if !slices.Contains(tags, key) {
				t.Errorf("%s has no key %q, which is classified", rt.Name(), key)
			}
		}
	}
}

const reloadBase = `version: 1
upstream: unix:///var/run/docker.sock
state_file: /var/lib/yorvogate/state.json
admin: {address: 'unix:///run/yorvogate/admin.sock'}
listeners:
  - {name: orchestrator, address: 'unix:///run/yorvogate/o.sock', mode: trusted, allow: {system: read}}
  - {name: ops, address: 'tcp://127.0.0.1:2375', mode: trusted, allow: {system: read}}
  - {name: sites, scope_sockets: /run/yorvogate/sites, mode: scoped, scopes: /etc/yorvogate/sites}
  - {name: tenants, address: 'unix:///run/yorvogate/tenants.sock', mode: scoped, scopes: /etc/yorvogate/tenants}
`

func parsed(t *testing.T, content string) *Config {
	t.Helper()

	c, err := Parse([]byte(content))
	if err != nil {
		t.Fatalf("%v\n%s", err, content)
	}

	return c
}

// What a reload changes: policies and limits anywhere, and trusted listeners added, removed and moved;
// what only a restart changes is refused, by its name.
func TestAReloadChangesPoliciesAndTrustedListeners(t *testing.T) {
	base := parsed(t, reloadBase)

	for _, tc := range []struct {
		name, from, to string
		want           Reload
		refused        string
	}{
		{"nothing", "", "", Reload{}, ""},
		{"a trusted listener's policy", "allow: {system: read}}\n  - {name: ops", "allow: {system: read, containers: write}}\n  - {name: ops", Reload{Changed: []string{"orchestrator"}}, ""},
		{"a scoped listener's policy", "scopes: /etc/yorvogate/sites}", "scopes: /etc/yorvogate/sites, pulls: {registries: [ghcr.io]}}", Reload{Changed: []string{"sites"}}, ""},
		{"limits", "state_file:", "load_limit: 1048576\nbody_limit: 8192\nspool: {limit: 1048576, loads: 1}\nshutdown_grace: 1s\nstate_file:", Reload{}, ""},
		{"a trusted listener added", "  - {name: sites", "  - {name: more, address: 'unix:///run/yorvogate/m.sock', mode: trusted, allow: {system: read}}\n  - {name: sites", Reload{Added: []string{"more"}}, ""},
		{"a trusted listener removed", "  - {name: ops, address: 'tcp://127.0.0.1:2375', mode: trusted, allow: {system: read}}\n", "", Reload{Removed: []string{"ops"}}, ""},
		{"a trusted listener renamed", "name: ops,", "name: operations,", Reload{Added: []string{"operations"}, Removed: []string{"ops"}}, ""},
		{"a trusted listener's address", "tcp://127.0.0.1:2375", "tcp://127.0.0.1:2385", Reload{Moved: []string{"ops"}}, ""},
		{"a trusted listener's socket group", "o.sock', mode", "o.sock', socket_group: '2001', mode", Reload{Moved: []string{"orchestrator"}}, ""},
		{"admin's scope labels", "admin.sock'}", "admin.sock', scope_labels: true}", Reload{}, ""},

		{"upstream", "unix:///var/run/docker.sock", "unix:///run/docker.sock", Reload{}, "upstream can't change"},
		{"the state file", "/var/lib/yorvogate/state.json", "/var/lib/yorvogate/other.json", Reload{}, "state_file can't change"},
		{"the spool's folder", "state_file:", "spool: {dir: /var/tmp/spool}\nstate_file:", Reload{}, "spool.dir can't change"},
		{"admin's address", "admin.sock'}", "other.sock'}", Reload{}, "admin.address can't change"},
		{"admin removed", "admin: {address: 'unix:///run/yorvogate/admin.sock'}\n", "", Reload{}, "admin can't change"},
		{"a scoped listener added", "  - {name: sites", "  - {name: more, scope_sockets: /run/yorvogate/more, mode: scoped, scopes: /etc/yorvogate/more}\n  - {name: sites", Reload{}, "listener more (a scoped listener added or removed) can't change"},
		{"a scoped listener removed", "  - {name: sites, scope_sockets: /run/yorvogate/sites, mode: scoped, scopes: /etc/yorvogate/sites}\n", "", Reload{}, "listener sites (a scoped listener added or removed) can't change"},
		{"a scoped listener's scopes", "scopes: /etc/yorvogate/sites", "scopes: /etc/yorvogate/others", Reload{}, "listener sites's scopes can't change"},
		{"a scoped listener's sockets", "scope_sockets: /run/yorvogate/sites", "scope_sockets: /run/yorvogate/elsewhere", Reload{}, "listener sites's scope_sockets can't change"},
		{"a scoped listener's peer users", "scopes: /etc/yorvogate/tenants}", "scopes: /etc/yorvogate/tenants, require_peer_uids: true}", Reload{}, "listener tenants's require_peer_uids can't change"},
		{"a trusted listener made scoped", "  - {name: ops, address: 'tcp://127.0.0.1:2375', mode: trusted, allow: {system: read}}", "  - {name: ops, address: 'tcp://127.0.0.1:2375', mode: scoped, scopes: /etc/yorvogate/ops}", Reload{}, "listener ops's mode can't change"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			next := parsed(t, strings.Replace(reloadBase, tc.from, tc.to, 1))

			got, err := Compare(base, next)

			if tc.refused != "" {
				if err == nil || !strings.Contains(err.Error(), tc.refused) || !strings.Contains(err.Error(), "restart it") {
					t.Errorf("refused with %v, want %q", err, tc.refused)
				}

				return
			}

			if err != nil {
				t.Fatal(err)
			}

			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

// shutdown_grace is a duration from 0s to 10m, 8s by default.
func TestShutdownGrace(t *testing.T) {
	if got := parsed(t, reloadBase).Grace(); got != 8*time.Second {
		t.Errorf("the default: %v", got)
	}

	for value, want := range map[string]time.Duration{"0s": 0, "500ms": 500 * time.Millisecond, "10m": 10 * time.Minute} {
		if got := parsed(t, reloadBase+"shutdown_grace: "+value+"\n").Grace(); got != want {
			t.Errorf("%s: %v", value, got)
		}
	}

	for _, value := range []string{"11m", "-1s", "8", "soon"} {
		if _, err := Parse([]byte(reloadBase + "shutdown_grace: " + value + "\n")); err == nil || !strings.Contains(err.Error(), "shutdown_grace") {
			t.Errorf("%s: %v", value, err)
		}
	}
}
