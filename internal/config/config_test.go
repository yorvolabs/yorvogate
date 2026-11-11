package config

import (
	"fmt"
	"strings"
	"testing"

	"github.com/yorvolabs/yorvogate/internal/route"
)

const valid = `
upstream: unix:///var/run/docker.sock
listeners:
  - name: server
    address: tcp://127.0.0.1:2375
    mode: trusted
    allow: {system: read, containers: write, exec: write}
  - name: sites
    address: unix:///run/yorvogate/sites.sock
    mode: scoped
    scopes: /etc/yorvogate/scopes
`

func TestAValidConfiguration(t *testing.T) {
	c, err := Parse([]byte(valid))
	if err != nil {
		t.Fatal(err)
	}

	if lo, hi := c.Versions(); lo != Lowest || hi != Highest {
		t.Errorf("versions %s–%s", lo, hi)
	}

	if c.BodyLimit != DefaultBodyLimit || c.LoadLimit != DefaultLoadLimit || c.UpstreamSocket() != "/var/run/docker.sock" {
		t.Errorf("defaults: %d %s", c.BodyLimit, c.UpstreamSocket())
	}

	trusted := c.Listeners[0]
	containers := &route.Endpoint{Group: route.Containers, Write: true}
	info := &route.Endpoint{Group: route.System}
	auth := &route.Endpoint{Group: route.System, Write: true}
	images := &route.Endpoint{Group: route.Images}

	if !trusted.Allows(containers) || !trusted.Allows(info) || trusted.Allows(auth) || trusted.Allows(images) {
		t.Error("allow: write allows writes, read only reads, nothing else")
	}

	for _, edge := range []string{"api: {min: '1.45', max: '1.50'}", "body_limit: 4096", "body_limit: 67108864", "load_limit: 1048576", "load_limit: 274877906944"} {
		c, err := Parse([]byte(valid + edge + "\n"))
		if err != nil {
			t.Errorf("%s: %v", edge, err)

			continue
		}

		if strings.HasPrefix(edge, "api") {
			if lo, hi := c.Versions(); lo != (route.Version{Major: 1, Minor: 45}) || hi != (route.Version{Major: 1, Minor: 50}) {
				t.Errorf("api: %s–%s", lo, hi)
			}
		}
	}

	if _, err := Parse([]byte(strings.Replace(valid, "mode: scoped", "mode: scoped\n    containers: {max_memory: 6291456}", 1))); err != nil {
		t.Errorf("Docker's least memory: %v", err)
	}

	withContainers := strings.Replace(valid, "mode: scoped", "mode: scoped\n    containers: {capabilities: [NET_BIND_SERVICE], drop_all_capabilities: true, no_new_privileges: true, max_memory: 1073741824, max_pids: 512, protected_images: [quire-sites/]}", 1)
	if _, err := Parse([]byte(withContainers)); err != nil {
		t.Errorf("a scoped listener's containers: %v", err)
	}

	withBuilders := strings.Replace(valid, "mode: scoped", "mode: scoped\n    builder_apparmor_profiles: [yorvogate-buildkit-rootless, unconfined]\n    allow_privileged_builders: false", 1)
	if c, err := Parse([]byte(withBuilders)); err != nil || len(c.Listeners[1].BuilderAppArmorProfiles) != 2 {
		t.Errorf("a scoped listener's builder profiles: %v", err)
	}

	if n, _ := c.Listeners[1].Network(); n != [2]string{"unix", "/run/yorvogate/sites.sock"} {
		t.Errorf("network %v", n)
	}
}

// A scoped listener whose scopes each have their own socket
var socketBound = strings.Replace(valid, "address: unix:///run/yorvogate/sites.sock", "scope_sockets: /run/yorvogate/scopes\n    socket_group: docker-sites", 1)

func TestScopeSockets(t *testing.T) {
	c, err := Parse([]byte(socketBound))
	if err != nil {
		t.Fatal(err)
	}

	sites := c.Listeners[1]
	if !sites.SocketBound() || !sites.Unix() || sites.SocketGroup != "docker-sites" || c.Listeners[0].SocketBound() || c.Listeners[0].Unix() {
		t.Errorf("%+v", sites)
	}

	for _, g := range []string{"0", "1001", "_sites"} {
		if _, err := Parse([]byte(strings.Replace(socketBound, "docker-sites", g, 1))); err != nil {
			t.Errorf("group %q: %v", g, err)
		}
	}

	if _, err := Parse([]byte(strings.Replace(valid, "mode: scoped", "mode: scoped\n    socket_group: docker", 1))); err != nil {
		t.Errorf("a group on a unix address: %v", err)
	}
}

func TestMistakesAreErrorsNotDefaults(t *testing.T) {
	cases := map[string]string{
		"an unknown key":                 strings.Replace(valid, "upstream:", "upstreem: x\nupstream:", 1),
		"an unknown listener key":        strings.Replace(valid, "mode: scoped", "mode: scoped\n    tls: true", 1),
		"two documents":                  valid + "\n---\nupstream: unix:///x\n",
		"an egress not none":             strings.Replace(valid, "mode: scoped", "mode: scoped\n    containers: {egress: all}", 1),
		"a log option without values":    strings.Replace(valid, "mode: scoped", "mode: scoped\n    containers: {log_options: {syslog-address: []}}", 1),
		"a log option's empty value":     strings.Replace(valid, "mode: scoped", "mode: scoped\n    containers: {log_options: {syslog-address: [\"\"]}}", 1),
		"a log option not a name":        strings.Replace(valid, "mode: scoped", "mode: scoped\n    containers: {log_options: {\"Syslog Address\": [x]}}", 1),
		"a negative log buffer":          strings.Replace(valid, "mode: scoped", "mode: scoped\n    containers: {max_log_buffer: -1}", 1),
		"upstream over TCP":              strings.Replace(valid, "unix:///var/run/docker.sock", "tcp://127.0.0.1:2375", 1),
		"upstream not absolute":          strings.Replace(valid, "unix:///var/run/docker.sock", "unix://docker.sock", 1),
		"an unknown mode":                strings.Replace(valid, "mode: scoped", "mode: open", 1),
		"an unknown group":               strings.Replace(valid, "exec: write", "everything: write", 1),
		"an unknown access":              strings.Replace(valid, "exec: write", "exec: all", 1),
		"scopes on a trusted one":        strings.Replace(valid, "mode: trusted", "mode: trusted\n    scopes: /x", 1),
		"allow on a scoped one":          strings.Replace(valid, "mode: scoped", "mode: scoped\n    allow: {system: read}", 1),
		"relative scopes":                strings.Replace(valid, "/etc/yorvogate/scopes", "scopes", 1),
		"scopes not clean":               strings.Replace(valid, "/etc/yorvogate/scopes", "/etc/../scopes", 1),
		"the same address twice":         strings.Replace(valid, "unix:///run/yorvogate/sites.sock", "tcp://127.0.0.1:2375", 1),
		"the same name twice":            strings.Replace(valid, "name: sites", "name: server", 1),
		"a name with spaces":             strings.Replace(valid, "name: sites", "name: my sites", 1),
		"an address without a port":      strings.Replace(valid, "tcp://127.0.0.1:2375", "tcp://127.0.0.1", 1),
		"an http address":                strings.Replace(valid, "tcp://127.0.0.1:2375", "http://127.0.0.1:2375", 1),
		"a version newer than known":     valid + "api: {max: '1.57'}\n",
		"a version older than known":     valid + "api: {min: '1.40'}\n",
		"min above max":                  valid + "api: {min: '1.50', max: '1.45'}\n",
		"a version that isn't one":       valid + "api: {min: 'latest'}\n",
		"a tiny body limit":              valid + "body_limit: 10\n",
		"a newer format":                 valid + "version: 2\n",
		"format 0":                       valid + "version: 0\n",
		"a format that isn't a number":   valid + "version: one\n",
		"a relative state file":          valid + "state_file: state.json\n",
		"a state file not clean":         valid + "state_file: /var/lib/../state.json\n",
		"a state file in scopes":         valid + "state_file: /etc/yorvogate/scopes/state.json\n",
		"the scopes folder as state":     valid + "state_file: /etc/yorvogate/scopes\n",
		"no listeners":                   "upstream: unix:///var/run/docker.sock\n",
		"containers on a trusted one":    strings.Replace(valid, "mode: trusted", "mode: trusted\n    containers: {max_pids: 10}", 1),
		"lists on a trusted one":         strings.Replace(valid, "mode: trusted", "mode: trusted\n    containers: {capabilities: [CHOWN], security_options: [x]}", 1),
		"a body limit just too large":    valid + "body_limit: 67108865\n",
		"memory just too little":         strings.Replace(valid, "mode: scoped", "mode: scoped\n    containers: {max_memory: 6291455}", 1),
		"a capability with CAP_":         strings.Replace(valid, "mode: scoped", "mode: scoped\n    containers: {capabilities: [CAP_CHOWN]}", 1),
		"all capabilities":               strings.Replace(valid, "mode: scoped", "mode: scoped\n    containers: {capabilities: [ALL]}", 1),
		"a lowercase capability":         strings.Replace(valid, "mode: scoped", "mode: scoped\n    containers: {capabilities: [chown]}", 1),
		"too little memory":              strings.Replace(valid, "mode: scoped", "mode: scoped\n    containers: {max_memory: 1024}", 1),
		"negative pids":                  strings.Replace(valid, "mode: scoped", "mode: scoped\n    containers: {max_pids: -1}", 1),
		"a protected image not a prefix": strings.Replace(valid, "mode: scoped", "mode: scoped\n    containers: {protected_images: [quire-sites]}", 1),
		"an unknown container key":       strings.Replace(valid, "mode: scoped", "mode: scoped\n    containers: {privileged: true}", 1),
		"a tiny load limit":              valid + "load_limit: 1024\n",
		"a huge load limit":              valid + "load_limit: 300000000000\n",
		"builders on a trusted one":      strings.Replace(valid, "mode: trusted", "mode: trusted\n    allow_privileged_builders: true", 1),
		"a profile that isn't a name":    strings.Replace(valid, "mode: scoped", "mode: scoped\n    builder_apparmor_profiles: [\"a b\"]", 1),
		"scope sockets and an address":   strings.Replace(valid, "mode: scoped", "mode: scoped\n    scope_sockets: /run/yorvogate/scopes", 1),
		"scope sockets on a trusted one": strings.Replace(valid, "mode: trusted", "mode: trusted\n    scope_sockets: /run/yorvogate/scopes", 1),
		"relative scope sockets":         strings.Replace(socketBound, "/run/yorvogate/scopes", "run/scopes", 1),
		"scope sockets not clean":        strings.Replace(socketBound, "/run/yorvogate/scopes", "/run/yorvogate/../scopes", 1),
		"a group on a TCP listener":      strings.Replace(valid, "mode: trusted", "mode: trusted\n    socket_group: docker", 1),
		"a group that isn't one":         strings.Replace(socketBound, "docker-sites", "my group", 1),
		"the same folder twice":          strings.Replace(socketBound, "name: server", "name: other\n    mode: scoped\n    scope_sockets: /run/yorvogate/scopes\n    scopes: /etc/yorvogate/scopes\n  - name: server", 1),
	}

	for name, content := range cases {
		if _, err := Parse([]byte(content)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// A configuration says its format; without one it's read as 1, with a warning (0.4 refuses it).
func TestTheFormatVersion(t *testing.T) {
	c, err := Parse([]byte(valid + "version: 1\n"))
	if err != nil || len(c.Deprecations()) != 0 {
		t.Errorf("version 1: %v %v", err, c.Deprecations())
	}

	c, err = Parse([]byte(valid))
	if err != nil || len(c.Deprecations()) != 1 || !strings.Contains(c.Deprecations()[0], "0.4 refuses it") {
		t.Errorf("no version: %v %v", err, c.Deprecations())
	}
}

func TestTheLogBuffer(t *testing.T) {
	if (&Containers{}).LogBuffer() != 4<<20 || (&Containers{MaxLogBuffer: 1 << 20}).LogBuffer() != 1<<20 {
		t.Error("the log buffer's limit")
	}
}

// Off loopback, a TCP listener needs mTLS, or plaintext to say it accepts cleartext; on loopback it
// needs neither. A host name isn't loopback, whatever it resolves to.
func TestOffLoopbackNeedsMTLS(t *testing.T) {
	listener := func(address, extra string) string {
		return "upstream: unix:///var/run/docker.sock\nlisteners:\n  - name: server\n    address: " + address + "\n    mode: trusted\n    allow: {system: read}\n" + extra
	}
	mtls := "    tls: {certificate: /etc/yorvogate/server.pem, key: /etc/yorvogate/server.key, client_ca: /etc/yorvogate/clients.pem}\n"
	tlsOnly := "    tls: {certificate: /etc/yorvogate/server.pem, key: /etc/yorvogate/server.key}\n"
	plaintext := "    plaintext: i-understand\n"

	for _, address := range []string{"tcp://0.0.0.0:2375", "tcp://:2375", "tcp://[::]:2375", "tcp://10.0.0.2:2375", "tcp://localhost:2375", "tcp://gate.example:2375", "tcp://[fe80::1%25eth0]:2375"} {
		_, err := Parse([]byte(listener(address, "")))
		if err == nil || !strings.Contains(err.Error(), "isn't loopback: a listener off loopback needs tls with client_ca (mTLS), or plaintext: i-understand") {
			t.Errorf("%s: %v", address, err)
		}

		if _, err := Parse([]byte(listener(address, tlsOnly))); err == nil {
			t.Errorf("%s with TLS but no client_ca was allowed", address)
		}

		for _, extra := range []string{mtls, plaintext, tlsOnly + plaintext} {
			if _, err := Parse([]byte(listener(address, extra))); err != nil {
				t.Errorf("%s with %q: %v", address, extra, err)
			}
		}
	}

	for _, address := range []string{"tcp://127.0.0.1:2375", "tcp://127.5.6.7:2375", "tcp://[::1]:2375", "tcp://[::ffff:127.0.0.1]:2375"} {
		c, err := Parse([]byte(listener(address, "")))
		if err != nil || !c.Listeners[0].Loopback() || c.Listeners[0].MutualTLS() {
			t.Errorf("%s: %v", address, err)
		}
	}

	c, err := Parse([]byte(listener("tcp://0.0.0.0:2375", mtls)))
	if err != nil || !c.Listeners[0].MutualTLS() || c.Listeners[0].Loopback() {
		t.Errorf("mTLS: %v", err)
	}

	if c, err := Parse([]byte(listener("unix:///run/yorvogate/server.sock", ""))); err != nil || c.Listeners[0].Loopback() {
		t.Errorf("a unix socket: %v", err)
	}
}

func TestTLSIsChecked(t *testing.T) {
	base := "upstream: unix:///var/run/docker.sock\nlisteners:\n  - name: server\n    address: %s\n    mode: %s\n    %s\n"
	trusted := "trusted\n    allow: {system: read}"
	scoped := "scoped\n    scopes: /etc/yorvogate/scopes"
	pin := strings.Repeat("a", 64)
	mtls := "tls: {certificate: /etc/yorvogate/server.pem, key: /etc/yorvogate/server.key, client_ca: /etc/yorvogate/clients.pem}"

	cases := map[string][3]string{
		"tls on a unix socket":       {"unix:///run/yorvogate/server.sock", trusted, mtls},
		"a relative certificate":     {"tcp://127.0.0.1:2375", trusted, "tls: {certificate: server.pem, key: /etc/yorvogate/server.key}"},
		"no key":                     {"tcp://127.0.0.1:2375", trusted, "tls: {certificate: /etc/yorvogate/server.pem}"},
		"an unclean key":             {"tcp://127.0.0.1:2375", trusted, "tls: {certificate: /etc/yorvogate/server.pem, key: /etc/yorvogate/../server.key}"},
		"a relative client CA":       {"tcp://127.0.0.1:2375", trusted, "tls: {certificate: /etc/yorvogate/server.pem, key: /etc/yorvogate/server.key, client_ca: clients.pem}"},
		"clients without client_ca":  {"tcp://127.0.0.1:2375", trusted, "tls: {certificate: /etc/yorvogate/server.pem, key: /etc/yorvogate/server.key}\n    clients: [{sha256: " + pin + "}]"},
		"clients on a scoped one":    {"tcp://127.0.0.1:2375", scoped, mtls + "\n    clients: [{sha256: " + pin + "}]"},
		"a client that isn't a pin":  {"tcp://127.0.0.1:2375", trusted, mtls + "\n    clients: [{sha256: " + strings.ToUpper(pin) + "}]"},
		"a client twice":             {"tcp://127.0.0.1:2375", trusted, mtls + "\n    clients: [{sha256: " + pin + "}, {sha256: " + pin + "}]"},
		"plaintext, misspelt":        {"tcp://0.0.0.0:2375", trusted, "plaintext: yes"},
		"plaintext on a unix socket": {"unix:///run/yorvogate/server.sock", trusted, "plaintext: i-understand"},
		"plaintext with mTLS":        {"tcp://0.0.0.0:2375", trusted, mtls + "\n    plaintext: i-understand"},
		"plaintext on loopback":      {"tcp://127.0.0.1:2375", trusted, "plaintext: i-understand"},
	}

	for name, c := range cases {
		if _, err := Parse([]byte(fmt.Sprintf(base, c[0], c[1], c[2]))); err == nil {
			t.Errorf("%s: allowed", name)
		}
	}

	c, err := Parse([]byte(fmt.Sprintf(base, "tcp://0.0.0.0:2375", trusted, mtls+"\n    clients: [{sha256: "+pin+"}]")))
	if err != nil || len(c.Listeners[0].Clients) != 1 || c.Listeners[0].TLS.ClientCA != "/etc/yorvogate/clients.pem" {
		t.Errorf("a trusted mTLS listener with a client: %v", err)
	}

	if _, err := Parse([]byte(fmt.Sprintf(base, "unix:///run/yorvogate/server.sock", trusted, "socket_group: docker"))); err != nil {
		t.Errorf("a unix socket: %v", err)
	}
}

// require_peer_uids is for a scoped listener on a unix address only: a TCP connection has no peer
// user, and on scope sockets the socket's permissions decide who connects.
func TestRequirePeerUIDsIsForAUnixAddress(t *testing.T) {
	for _, c := range []struct {
		name, listener, want string
	}{
		{"a unix address", "{name: a, address: 'unix:///run/a.sock', mode: scoped, scopes: /etc/a, require_peer_uids: true}", ""},
		{"TCP", "{name: a, address: 'tcp://127.0.0.1:2376', mode: scoped, scopes: /etc/a, require_peer_uids: true}", "require_peer_uids: only a scoped listener on a unix address has it"},
		{"scope sockets", "{name: a, scope_sockets: /run/a, mode: scoped, scopes: /etc/a, require_peer_uids: true}", "require_peer_uids: only a scoped listener on a unix address has it"},
		{"trusted", "{name: a, address: 'unix:///run/a.sock', mode: trusted, allow: {system: read}, require_peer_uids: true}", "require_peer_uids: only a scoped listener on a unix address has it"},
	} {
		c2, err := Parse([]byte("upstream: unix:///var/run/docker.sock\nlisteners:\n  - " + c.listener + "\n"))
		if c.want == "" && (err != nil || !c2.Listeners[0].RequirePeerUIDs || !c2.Listeners[0].PeerCredentials()) || c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}
