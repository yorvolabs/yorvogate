package gate

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/api/types/volume"
)

// createNetwork checks a network a scope creates: a bridge of its own, with its name and label, and
// within its subnets when it has some.
func (s *scoped) createNetwork(body []byte) ([]byte, error) {
	var req network.CreateRequest
	if err := decode(body, &req); err != nil {
		return nil, err
	}

	var found problems
	add := found.add

	for _, f := range unset(req, networkCreate) {
		add(CodeFieldNotAllowed, at(inBody, f), allowUnset(), "%s isn't allowed", f)
	}

	if !s.scope.Names(req.Name) {
		add(CodeNameNotOwn, at(inBody, "Name"), allowPrefixed(s.scope.Prefixes), "the name %q isn't one of scope %s's (%s)", req.Name, s.scope.Name, strings.Join(s.scope.Prefixes, ", "))
	} else if err := s.notTaken("network", req.Name, at(inBody, "Name"), s.docker.Network); err != nil {
		return nil, err
	}

	s.ownLabels(req.Labels, "Labels", add)

	if req.Driver != "" && req.Driver != "bridge" {
		add(CodeNetwork, at(inBody, "Driver"), allowOneOf([]string{"bridge"}), "the driver %q isn't allowed (only bridge)", req.Driver)
	}

	if req.Scope != "" && req.Scope != "local" {
		add(CodeNetwork, at(inBody, "Scope"), allowOneOf([]string{"local"}), "the scope %q isn't allowed (only local)", req.Scope)
	}

	if s.egressFree() && !req.Internal {
		add(CodeEgress, at(inBody, "Internal"), allowRequired(true), "scope %s may create only internal networks (egress: none): set Internal (Compose: networks.<name>.internal: true)", s.scope.Name)
	}

	var configs []network.IPAMConfig
	if req.IPAM != nil {
		for _, f := range unset(req.IPAM, ipam) {
			add(CodeFieldNotAllowed, at(inBody, "IPAM."+f), allowUnset(), "IPAM.%s isn't allowed", f)
		}

		if req.IPAM.Driver != "" && req.IPAM.Driver != "default" {
			add(CodeNetwork, at(inBody, "IPAM.Driver"), allowOneOf([]string{"default"}), "the IPAM driver %q isn't allowed (a plugin runs on the host)", req.IPAM.Driver)
		}

		configs = req.IPAM.Config
	}

	if s.scope.HasSubnets() && len(configs) == 0 {
		add(CodeNetwork, at(inBody, index("IPAM.Config", 0)+".Subnet"), allowUnder(s.scope.Subnets), "its subnet must be named, inside the scope's")
	}

	for i, c := range configs {
		base := index("IPAM.Config", i) + "."

		for _, f := range unset(c, ipamConfig) {
			add(CodeFieldNotAllowed, at(inBody, base+f), allowUnset(), "IPAM.Config.%s isn't allowed", f)
		}

		if !c.Subnet.IsValid() && s.scope.HasSubnets() {
			add(CodeNetwork, at(inBody, base+"Subnet"), allowUnder(s.scope.Subnets), "each IPAM config names its subnet")

			continue
		}

		if c.Subnet.IsValid() && !s.scope.Contains(c.Subnet) {
			add(CodeNetwork, at(inBody, base+"Subnet"), allowUnder(s.scope.Subnets), "the subnet %s isn't inside the scope's", c.Subnet)
		}
	}

	if len(found) > 0 {
		return nil, found.refusal(http.StatusForbidden, "network.create")
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
		return refuse(http.StatusNotFound, CodeNotFound, nowhere, nothingAllowed, "network %s not found", id)
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

	var found problems
	add := found.add

	for _, f := range unset(req, volumeCreate) {
		add(CodeFieldNotAllowed, at(inBody, f), allowUnset(), "%s isn't allowed", f)
	}

	if !s.scope.Names(req.Name) {
		add(CodeNameNotOwn, at(inBody, "Name"), allowPrefixed(s.scope.Prefixes), "the name %q isn't one of scope %s's (%s)", req.Name, s.scope.Name, strings.Join(s.scope.Prefixes, ", "))
	} else if err := s.notTaken("volume", req.Name, at(inBody, "Name"), s.docker.Volume); err != nil {
		return nil, err
	}

	s.ownLabels(req.Labels, "Labels", add)

	if !plainLocal(req.Driver, req.DriverOpts) {
		add(CodeMount, at(inBody, "Driver"), allowOneOf([]string{"local"}), "the driver %q isn't allowed (only local, without options)", req.Driver)
	}

	if len(found) > 0 {
		return nil, found.refusal(http.StatusForbidden, "volume.create")
	}

	return json.Marshal(req)
}

// sharedContainers filters the answer of a network's inspection: only the scope's own containers are
// listed (a shared network's others are other scopes'). A container is its own by its owner label,
// looked up, never by its name: scopes' names can nest ("jane-blog-php-1" starts with "jane-").
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

		for id := range containers {
			found, err := s.docker.Container(s.ctx, s.version, id)
			if err != nil {
				return nil, err
			}

			// One gone since Docker answered isn't listed.
			if !s.owned(found) {
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
