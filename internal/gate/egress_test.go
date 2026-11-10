package gate

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/yorvolabs/yorvogate/internal/config"
	"github.com/yorvolabs/yorvogate/internal/scope"
)

// agent is a container of jane's on its internal network and the shared one with the egress proxy.
func agent() map[string]any {
	body := set(compose(), "HostConfig.NetworkMode", "jane_internal")

	return set(body, "NetworkingConfig.EndpointsConfig", map[string]any{
		"jane_internal": map[string]any{"Aliases": []any{"agent"}},
		"quire-egress":  map[string]any{},
	})
}

// An egress-free scope creates only internal networks; another scope, any.
func TestAnEgressFreeScopeCreatesInternalNetworks(t *testing.T) {
	d := startDocker(t)
	egress, sites := gate(t, d, "egress"), gate(t, d, "sites")

	status, answer := send(t, egress, "POST", "/v1.56/networks/create", encode(composeNetwork()), asJane)
	if status != http.StatusForbidden || !strings.Contains(message(t, answer), "scope jane may create only internal networks (egress: none): set Internal (Compose: networks.<name>.internal: true)") {
		t.Errorf("not internal: %d %s", status, answer)
	}

	if status, answer := send(t, egress, "POST", "/v1.56/networks/create", encode(set(composeNetwork(), "Internal", true)), asJane); status != http.StatusOK {
		t.Errorf("internal: %d %s", status, answer)
	}

	if status, answer := send(t, sites, "POST", "/v1.56/networks/create", encode(composeNetwork()), asJane); status != http.StatusOK {
		t.Errorf("a scope that isn't egress-free: %d %s", status, answer)
	}
}

// Every network an egress-free scope's container joins is internal: its own, a shared one, and the
// networks of a container whose namespace it joins.
func TestAnEgressFreeScopesContainerJoinsInternalNetworks(t *testing.T) {
	d := startDocker(t)
	egress, sites := gate(t, d, "egress"), gate(t, d, "sites")
	create := "/v1.56/containers/create?name=jane-agent-2"

	for name, c := range map[string]struct {
		body    map[string]any
		refusal string
	}{
		"internal ones":               {agent(), ""},
		"no network":                  {set(set(agent(), "HostConfig.NetworkMode", "none"), "NetworkingConfig.EndpointsConfig", map[string]any{}), ""},
		"an internal one's namespace": {set(set(agent(), "HostConfig.NetworkMode", "container:jane-agent-1"), "NetworkingConfig.EndpointsConfig", map[string]any{}), ""},
		"its own that isn't":          {set(agent(), "NetworkingConfig.EndpointsConfig.jane_default", map[string]any{}), "the network jane_default isn't internal (egress: none)"},
		"its own by NetworkMode only": {set(set(agent(), "HostConfig.NetworkMode", "jane_default"), "NetworkingConfig.EndpointsConfig", map[string]any{}), "the network jane_default isn't internal"},
		"a shared one that isn't":     {set(agent(), "NetworkingConfig.EndpointsConfig.quire-link-jane", map[string]any{}), "the network quire-link-jane isn't internal"},
		"a namespace that isn't":      {set(set(agent(), "HostConfig.NetworkMode", "container:jane-php-1"), "NetworkingConfig.EndpointsConfig", map[string]any{}), "the container jane-php-1 whose network it joins is on a network that isn't internal (jane_default; egress: none)"},
		"another's namespace, still":  {set(set(agent(), "HostConfig.NetworkMode", "container:blog-php-1"), "NetworkingConfig.EndpointsConfig", map[string]any{}), "isn't one of its own containers"},
		"Docker's bridge, still":      {set(agent(), "HostConfig.NetworkMode", "bridge"), `NetworkMode "bridge" isn't allowed`},
	} {
		status, answer := send(t, egress, "POST", create, encode(c.body), asJane)

		switch {
		case c.refusal == "" && status != http.StatusOK:
			t.Errorf("%s: %d %s", name, status, answer)
		case c.refusal != "" && (status != http.StatusForbidden || !strings.Contains(message(t, answer), c.refusal)):
			t.Errorf("%s: %d %s", name, status, answer)
		}
	}

	// A scope that isn't egress-free joins its networks as before.
	if status, answer := send(t, sites, "POST", "/v1.56/containers/create?name=jane-php-2", encode(compose()), asJane); status != http.StatusOK {
		t.Errorf("not egress-free: %d %s", status, answer)
	}
}

func TestAnEgressFreeScopeConnectsToInternalNetworks(t *testing.T) {
	d := startDocker(t)
	egress, sites := gate(t, d, "egress"), gate(t, d, "sites")

	for network, refusal := range map[string]string{
		"jane_internal":   "",
		"quire-egress":    "",
		"jane_default":    "the network jane_default isn't internal (egress: none)",
		"quire-link-jane": "the network quire-link-jane isn't internal (egress: none)",
	} {
		status, answer := send(t, egress, "POST", "/v1.56/networks/"+network+"/connect", `{"Container":"jane-agent-1"}`, asJane)

		switch {
		case refusal == "" && status != http.StatusOK:
			t.Errorf("%s: %d %s", network, status, answer)
		case refusal != "" && (status != http.StatusForbidden || !strings.Contains(message(t, answer), refusal)):
			t.Errorf("%s: %d %s", network, status, answer)
		}
	}

	if status, answer := send(t, sites, "POST", "/v1.56/networks/jane_default/connect", `{"Container":"jane-php-1"}`, asJane); status != http.StatusOK {
		t.Errorf("not egress-free: %d %s", status, answer)
	}
}

// A container made before its scope was egress-free, on a network with a way out, doesn't run code
// again until it's disconnected or recreated; what doesn't run code in it still works.
func TestAnEgressFreeScopesContainerOnAWayOut(t *testing.T) {
	d := startDocker(t)
	egress, sites := gate(t, d, "egress"), gate(t, d, "sites")

	for _, c := range []struct{ method, path, body string }{
		{"POST", "/v1.56/containers/jane-php-1/start", ""},
		{"POST", "/v1.56/containers/jane-php-1/restart", ""},
		{"POST", "/v1.56/containers/jane-php-1/unpause", ""},
		{"POST", "/v1.56/containers/jane-php-1/attach?stream=1&stdout=1", ""},
		{"GET", "/v1.56/containers/jane-php-1/attach/ws?stream=1", ""},
		{"POST", "/v1.56/containers/jane-php-1/exec", `{"Cmd":["sh"]}`},
	} {
		forwarded := d.count()
		status, answer := send(t, egress, c.method, c.path, c.body, asJane)

		if status != http.StatusForbidden || !strings.Contains(message(t, answer), "the container jane-php-1 is on a network that isn't internal (jane_default; egress: none): disconnect it, or recreate the container") || d.count() != forwarded {
			t.Errorf("%s %s: %d %s", c.method, c.path, status, answer)
		}

		// On internal networks only, it runs (an attach without an upgrade is refused for that alone,
		// after this check), and so does it for a scope that isn't egress-free.
		passes := func(status int, answer string) bool {
			return status/100 == 2 || strings.Contains(answer, "allowed only as an HTTP upgrade")
		}

		if status, answer := send(t, egress, c.method, strings.Replace(c.path, "jane-php-1", "jane-agent-1", 1), c.body, asJane); !passes(status, answer) {
			t.Errorf("%s %s, internal: %d %s", c.method, c.path, status, answer)
		}

		if status, answer := send(t, sites, c.method, c.path, c.body, asJane); !passes(status, answer) {
			t.Errorf("%s %s, not egress-free: %d %s", c.method, c.path, status, answer)
		}
	}

	for _, c := range []struct{ method, path, body string }{
		{"GET", "/v1.56/containers/jane-php-1/json", ""},
		{"GET", "/v1.56/containers/jane-php-1/logs?stdout=1", ""},
		{"POST", "/v1.56/containers/jane-php-1/stop", ""},
		{"POST", "/v1.56/containers/jane-php-1/kill", ""},
		{"DELETE", "/v1.56/containers/jane-php-1", ""},
		{"POST", "/v1.56/networks/jane_default/disconnect", `{"Container":"jane-php-1"}`},
	} {
		if status, answer := send(t, egress, c.method, c.path, c.body, asJane); status/100 != 2 {
			t.Errorf("%s %s: %d %s", c.method, c.path, status, answer)
		}
	}
}

// An egress-free scope's builder is on internal networks only, or none: its RUN steps are no way out.
func TestAnEgressFreeScopesBuilder(t *testing.T) {
	d := startDocker(t)
	egress, sites := gate(t, d, "egress"), gate(t, d, "sites")
	dial := func(server string) (int, string) {
		s := egress
		if server == "sites" {
			s = sites
		}

		return send(t, s, "POST", "/v1.56/containers/buildx_buildkit_jane0/exec", dialStdioExec, asJane)
	}

	// On Docker's bridge (the fake builder's)
	if status, answer := dial("egress"); status != http.StatusForbidden || !strings.Contains(message(t, answer), "it's on a network that isn't internal (bridge; egress: none)") {
		t.Errorf("on the bridge: %d %s", status, answer)
	}

	if status, answer := dial("sites"); status != http.StatusCreated && status != http.StatusOK {
		t.Errorf("on the bridge, not egress-free: %d %s", status, answer)
	}

	d.setBuilder("HostConfig.NetworkMode", "quire-egress")
	if status, answer := dial("egress"); status/100 != 2 {
		t.Errorf("on the shared internal network: %d %s", status, answer)
	}

	d.setBuilder("HostConfig.NetworkMode", "none")
	if status, answer := dial("egress"); status/100 != 2 {
		t.Errorf("on none: %d %s", status, answer)
	}

	d.setBuilder("HostConfig.NetworkMode", "quire-egress")
	d.setBuilder("NetworkSettings", map[string]any{"Networks": map[string]any{"quire-egress": map[string]any{"NetworkID": egressNet}, "quire-link-jane": map[string]any{"NetworkID": linkNet}}})
	if status, answer := dial("egress"); status != http.StatusForbidden || !strings.Contains(message(t, answer), "(quire-link-jane; egress: none)") {
		t.Errorf("also on a network with a way out: %d %s", status, answer)
	}
}

// A scope is egress-free by its own file's egress: none, or its listener's.
func TestAScopeIsEgressFreeByEitherSetting(t *testing.T) {
	for _, c := range []struct {
		scope, listener string
		free            bool
	}{{"", "", false}, {"none", "", true}, {"", "none", true}, {"none", "none", true}} {
		s := &scoped{scope: &scope.Scope{Egress: c.scope}, policy: config.Containers{Egress: c.listener}}
		if s.egressFree() != c.free {
			t.Errorf("scope %q, listener %q: %v", c.scope, c.listener, !c.free)
		}
	}
}

// The running containers an egress-free scope has on a network with a way out, named with those
// networks: what's logged when a scope becomes egress-free, and what check --docker lists.
func TestEgressLeaks(t *testing.T) {
	d := startDocker(t)
	docker := NewDocker(d.socket)

	leaks, err := EgressLeaks(context.Background(), docker, "1.56", "com.docker.compose.project", "jane")
	if err != nil {
		t.Fatal(err)
	}

	if strings.Join(leaks, "; ") != "jane-php-1 (jane_default)" {
		t.Errorf("leaks: %v", leaks)
	}
}

// An exec made before the scope was egress-free, in a container with a way out, isn't started; one in
// a container on internal networks only is, and so is any for a scope that isn't egress-free. What
// doesn't run code (its inspection) still works.
func TestAnEgressFreeScopesExecStarts(t *testing.T) {
	d := startDocker(t)
	egress, sites := gate(t, d, "egress"), gate(t, d, "sites")
	start := `{"Detach":true}`

	forwarded := d.count()
	if status, answer := send(t, egress, "POST", "/v1.56/exec/exec-jane/start", start, asJane); status != http.StatusForbidden || !strings.Contains(message(t, answer), "exec.start: the container jane-php-1 is on a network that isn't internal (jane_default; egress: none)") || d.count() != forwarded {
		t.Errorf("a way out: %d %s", status, answer)
	}

	for _, c := range []struct {
		server       string
		method, path string
	}{
		{"egress", "POST", "/v1.56/exec/exec-agent/start"},
		{"sites", "POST", "/v1.56/exec/exec-jane/start"},
		{"egress", "GET", "/v1.56/exec/exec-jane/json"},
	} {
		server := egress
		if c.server == "sites" {
			server = sites
		}

		body := start
		if c.method == "GET" {
			body = ""
		}

		if status, answer := send(t, server, c.method, c.path, body, asJane); status/100 != 2 {
			t.Errorf("%s %s %s: %d %s", c.server, c.method, c.path, status, answer)
		}
	}
}

// A running container that can't be inspected is named as one that couldn't be checked, not left out.
func TestEgressLeaksNameWhatCouldntBeChecked(t *testing.T) {
	d := startDocker(t)

	// jane-agent-1's network namespace is another container that isn't there
	containerNetworks[janeAgent] = []string{"container:gone"}
	t.Cleanup(func() { containerNetworks[janeAgent] = []string{"jane_internal", "quire-egress"} })

	leaks, err := EgressLeaks(context.Background(), NewDocker(d.socket), "1.56", "com.docker.compose.project", "jane")
	if err != nil {
		t.Fatal(err)
	}

	if got := strings.Join(leaks, "; "); !strings.Contains(got, "jane-agent-1 (its networks couldn't be checked: the container gone whose network it joins isn't there)") || !strings.Contains(got, "jane-php-1 (jane_default)") {
		t.Errorf("leaks: %s", got)
	}
}
