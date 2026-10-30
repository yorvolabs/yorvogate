package gate

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/api/types/volume"
)

// The fields of a network a scope may set: its own bridge, with its name and labels, IPv4 and IPv6,
// internal or not, and its subnets (checked). The rest asks for a driver's powers, the swarm's, or
// another network's configuration.
var (
	networkFields = fields("Name", "Driver", "Scope", "EnableIPv4", "EnableIPv6", "IPAM", "Internal", "Labels")
	ipamFields    = fields("Driver", "Config")
	volumeFields  = fields("Name", "Driver", "Labels")
)

// createNetwork checks a network a scope creates: a bridge of its own, with its name and label, and
// within its subnets when it has some.
func (s *scoped) createNetwork(body []byte) ([]byte, error) {
	var req network.CreateRequest
	if err := decode(body, &req); err != nil {
		return nil, err
	}

	var problems []string
	add := func(format string, args ...any) { problems = append(problems, fmt.Sprintf(format, args...)) }

	for _, f := range unset(req, networkFields) {
		add("%s isn't allowed", f)
	}

	if !s.scope.Names(req.Name) {
		add("the name %q isn't one of scope %s's (%s)", req.Name, s.scope.Name, strings.Join(s.scope.Prefixes, ", "))
	}

	if !s.scope.Owns(req.Labels) {
		add("it must carry the label %s=%s", s.scope.Owner.Key, s.scope.Owner.Value)
	}

	if req.Driver != "" && req.Driver != "bridge" {
		add("the driver %q isn't allowed (only bridge)", req.Driver)
	}

	if req.Scope != "" && req.Scope != "local" {
		add("the scope %q isn't allowed (only local)", req.Scope)
	}

	var configs []network.IPAMConfig
	if req.IPAM != nil {
		for _, f := range unset(req.IPAM, ipamFields) {
			add("IPAM.%s isn't allowed", f)
		}

		if req.IPAM.Driver != "" && req.IPAM.Driver != "default" {
			add("the IPAM driver %q isn't allowed (a plugin runs on the host)", req.IPAM.Driver)
		}

		configs = req.IPAM.Config
	}

	if s.scope.HasSubnets() && len(configs) == 0 {
		add("its subnet must be named, inside the scope's")
	}

	for _, c := range configs {
		if !c.Subnet.IsValid() && s.scope.HasSubnets() {
			add("each IPAM config names its subnet")

			continue
		}

		if c.Subnet.IsValid() && !s.scope.Contains(c.Subnet) {
			add("the subnet %s isn't inside the scope's", c.Subnet)
		}
	}

	if len(problems) > 0 {
		return nil, refuse(http.StatusForbidden, "network.create: %s", strings.Join(problems, "; "))
	}

	return json.Marshal(req)
}

// ownNetwork checks that the network the path names is the scope's own (not a shared one it joins).
func (s *scoped) ownNetwork() error {
	id := s.req.Params["id"]

	n, err := s.docker.Network(s.ctx, s.version, id)
	if err != nil {
		return err
	}

	if n == nil || !s.scope.Owns(n.Labels) {
		return refuse(http.StatusNotFound, "network %s not found", id)
	}

	s.with("id", n.ID)

	return nil
}

// createVolume checks a volume a scope creates: the local driver, with its name and label, without
// driver options (with them, a local volume can mount any host path).
func (s *scoped) createVolume(body []byte) ([]byte, error) {
	var req volume.CreateRequest
	if err := decode(body, &req); err != nil {
		return nil, err
	}

	var problems []string
	add := func(format string, args ...any) { problems = append(problems, fmt.Sprintf(format, args...)) }

	for _, f := range unset(req, volumeFields) {
		add("%s isn't allowed", f)
	}

	if !s.scope.Names(req.Name) {
		add("the name %q isn't one of scope %s's (%s)", req.Name, s.scope.Name, strings.Join(s.scope.Prefixes, ", "))
	}

	if !s.scope.Owns(req.Labels) {
		add("it must carry the label %s=%s", s.scope.Owner.Key, s.scope.Owner.Value)
	}

	if req.Driver != "" && req.Driver != "local" {
		add("the driver %q isn't allowed (only local)", req.Driver)
	}

	if len(problems) > 0 {
		return nil, refuse(http.StatusForbidden, "volume.create: %s", strings.Join(problems, "; "))
	}

	return json.Marshal(req)
}

// sharedContainers filters the answer of a network's inspection: only the scope's own containers are
// listed (a shared network's others are other scopes').
func (s *scoped) sharedContainers(body []byte) ([]byte, error) {
	var answer map[string]json.RawMessage
	if err := json.Unmarshal(body, &answer); err != nil {
		return nil, err
	}

	var containers map[string]struct {
		Name string
	}
	if raw, ok := answer["Containers"]; ok && string(raw) != "null" {
		if err := json.Unmarshal(raw, &containers); err != nil {
			return nil, err
		}

		var all map[string]json.RawMessage
		_ = json.Unmarshal(raw, &all)

		for id, c := range containers {
			if !s.scope.Names(c.Name) && !s.scope.Uses(c.Name) {
				delete(all, id)
			}
		}

		filtered, err := json.Marshal(all)
		if err != nil {
			return nil, err
		}

		answer["Containers"] = filtered
	}

	return json.Marshal(answer)
}
