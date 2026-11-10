package gate

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/moby/moby/api/types/container"
)

// A scope with "egress": "none" (its own, or its listener's containers.egress) keeps its containers off
// every network with a way out. A container reaches outside as soon as one of its networks has a
// gateway, and the resolver forwards outside names only then (moby 29.9.2,
// daemon/libnetwork/sandbox_dns_unix.go:60-66, resolver.go:518-525). So every network its containers
// and builders join, its own or shared, must be internal. The way out, when there's one, is a proxy
// the orchestrator puts on a shared internal network. Internal is set when a network is created and
// never changes, so a network is checked when it's joined; and what was made before the setting is
// checked each time a container runs code (start, restart, unpause, attach, exec).

// egressFree tells whether the scope's containers may join only internal networks.
func (s *scoped) egressFree() bool {
	return s.scope.Egress == "none" || s.policy.Egress == "none"
}

// runsCode are the endpoints that run code in a container, or let it run again.
var runsCode = []string{"container.start", "container.restart", "container.unpause", "container.attach", "container.attach-websocket", "exec.create"}

// internal checks a network an egress-free scope's container joins, by name or ID.
func (s *scoped) internal(network string, add func(string, ...any)) {
	n, err := s.docker.Network(s.ctx, s.version, network)

	switch {
	case err != nil:
		add("the network %s couldn't be checked: %v", network, err)
	case n == nil || !n.Internal:
		add("the network %s isn't internal (egress: none)", network)
	}
}

// external names the networks of a container that aren't internal: its own, or, in another
// container's network namespace, that one's (as many deep as Docker lets them go).
func external(ctx context.Context, d *Docker, version string, c *container.InspectResponse) ([]string, error) {
	for range 8 {
		if c == nil || c.HostConfig == nil {
			return nil, fmt.Errorf("its configuration couldn't be read")
		}

		other, ok := strings.CutPrefix(string(c.HostConfig.NetworkMode), "container:")
		if !ok {
			break
		}

		o, err := d.Container(ctx, version, other)
		if err != nil {
			return nil, err
		}

		if o == nil {
			return nil, fmt.Errorf("the container %s whose network it joins isn't there", other)
		}

		c = o.inspection
	}

	mode := string(c.HostConfig.NetworkMode)
	if mode == "none" {
		return nil, nil
	}

	// Its networks: each it has an endpoint on, and the one its NetworkMode names (Docker's default
	// bridge when it names none), so a container's settings that don't list it still have it checked.
	if mode == "" || mode == "default" {
		mode = "bridge"
	}

	ids := map[string]string{mode: mode}

	if c.NetworkSettings != nil {
		for name, e := range c.NetworkSettings.Networks {
			ids[name] = name
			if e != nil && e.NetworkID != "" {
				ids[name] = e.NetworkID
			}
		}
	}

	var outside []string

	for name, id := range ids {
		n, err := d.Network(ctx, version, id)
		if err != nil {
			return nil, err
		}

		if n == nil || !n.Internal {
			outside = append(outside, name)
		}
	}

	slices.Sort(outside)

	return outside, nil
}

// runsInside checks a container an egress-free scope runs code in: all its networks are internal.
// Disconnecting it from the others, or recreating it, is the way to run it again.
func (s *scoped) runsInside(c *object, builder bool) error {
	if !s.egressFree() || builder || !slices.Contains(runsCode, s.req.Endpoint.Name) {
		return nil
	}

	outside, err := external(s.ctx, s.docker, s.version, c.inspection)
	if err != nil {
		return err
	}

	if len(outside) > 0 {
		return refuse(http.StatusForbidden, "%s: the container %s is on a network that isn't internal (%s; egress: none): disconnect it, or recreate the container", s.req.Endpoint.Name, c.Name, strings.Join(outside, ", "))
	}

	return nil
}

// EgressLeaks names a scope's running containers that are on a network that isn't internal, each
// with those networks: what turning "egress": "none" on doesn't stop, until they're disconnected or
// recreated.
func EgressLeaks(ctx context.Context, d *Docker, version, label, value string) ([]string, error) {
	filters, _ := json.Marshal(map[string][]string{"label": {label + "=" + value}, "status": {"running"}})

	var running []struct {
		ID string `json:"Id"`
	}
	if _, err := d.fetch(ctx, version, "/containers/json?filters="+url.QueryEscape(string(filters)), &running); err != nil {
		return nil, err
	}

	var leaks []string

	for _, r := range running {
		c, err := d.Container(ctx, version, r.ID)
		if err != nil || c == nil {
			continue
		}

		outside, err := external(ctx, d, version, c.inspection)
		if err != nil {
			return nil, err
		}

		if len(outside) > 0 {
			leaks = append(leaks, fmt.Sprintf("%s (%s)", c.Name, strings.Join(outside, ", ")))
		}
	}

	slices.Sort(leaks)

	return leaks, nil
}
