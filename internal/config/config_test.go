package config

import (
	"strings"
	"testing"

	"github.com/yorvolabs/yorvogate/internal/route"
)

const valid = `
upstream: unix:///var/run/docker.sock
listeners:
  - name: server
    address: tcp://0.0.0.0:2375
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

	if c.BodyLimit != DefaultBodyLimit || c.UpstreamSocket() != "/var/run/docker.sock" {
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

	if n, _ := c.Listeners[1].Network(); n != [2]string{"unix", "/run/yorvogate/sites.sock"} {
		t.Errorf("network %v", n)
	}
}

func TestMistakesAreErrorsNotDefaults(t *testing.T) {
	cases := map[string]string{
		"an unknown key":             strings.Replace(valid, "upstream:", "upstreem: x\nupstream:", 1),
		"an unknown listener key":    strings.Replace(valid, "mode: scoped", "mode: scoped\n    tls: true", 1),
		"two documents":              valid + "\n---\nupstream: unix:///x\n",
		"upstream over TCP":          strings.Replace(valid, "unix:///var/run/docker.sock", "tcp://127.0.0.1:2375", 1),
		"upstream not absolute":      strings.Replace(valid, "unix:///var/run/docker.sock", "unix://docker.sock", 1),
		"an unknown mode":            strings.Replace(valid, "mode: scoped", "mode: open", 1),
		"an unknown group":           strings.Replace(valid, "exec: write", "everything: write", 1),
		"an unknown access":          strings.Replace(valid, "exec: write", "exec: all", 1),
		"scopes on a trusted one":    strings.Replace(valid, "mode: trusted", "mode: trusted\n    scopes: /x", 1),
		"allow on a scoped one":      strings.Replace(valid, "mode: scoped", "mode: scoped\n    allow: {system: read}", 1),
		"relative scopes":            strings.Replace(valid, "/etc/yorvogate/scopes", "scopes", 1),
		"scopes not clean":           strings.Replace(valid, "/etc/yorvogate/scopes", "/etc/../scopes", 1),
		"the same address twice":     strings.Replace(valid, "unix:///run/yorvogate/sites.sock", "tcp://0.0.0.0:2375", 1),
		"the same name twice":        strings.Replace(valid, "name: sites", "name: server", 1),
		"a name with spaces":         strings.Replace(valid, "name: sites", "name: my sites", 1),
		"an address without a port":  strings.Replace(valid, "tcp://0.0.0.0:2375", "tcp://0.0.0.0", 1),
		"an http address":            strings.Replace(valid, "tcp://0.0.0.0:2375", "http://0.0.0.0:2375", 1),
		"a version newer than known": valid + "api: {max: '1.57'}\n",
		"a version older than known": valid + "api: {min: '1.40'}\n",
		"min above max":              valid + "api: {min: '1.50', max: '1.45'}\n",
		"a version that isn't one":   valid + "api: {min: 'latest'}\n",
		"a tiny body limit":          valid + "body_limit: 10\n",
		"no listeners":               "upstream: unix:///var/run/docker.sock\n",
	}

	for name, content := range cases {
		if _, err := Parse([]byte(content)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
