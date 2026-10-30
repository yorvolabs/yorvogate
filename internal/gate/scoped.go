package gate

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/moby/moby/api/types/network"
	"github.com/yorvolabs/yorvogate/internal/config"
	"github.com/yorvolabs/yorvogate/internal/route"
	"github.com/yorvolabs/yorvogate/internal/scope"
)

// scoped decides on one request of a scope: whether it may, and what Docker gets. Objects the request
// names are looked up first; the request then names the object by the full ID that was checked, so
// what Docker acts on is what was checked, whatever the name meant by then.
type scoped struct {
	ctx     context.Context
	req     route.Request
	scope   *scope.Scope
	policy  config.Containers
	docker  *Docker
	version string

	// What's forwarded: the path (with its version) and the query, as the rules leave them
	path  string
	query url.Values

	// Whether the request asks for an HTTP upgrade
	upgrading bool

	// A stream's body (an image archive), the most read of it, and what's forwarded in its place
	stream        io.Reader
	loadLimit     int64
	forwardBody   io.ReadCloser
	forwardLength int64
	// Done once the request is forwarded (e.g. an archive's copy removed)
	cleanup func()
	// Changes Docker's answer before the client sees it (e.g. other scopes' objects left out)
	answer func([]byte) ([]byte, error)
}

// container endpoints that act on one container and take no body: allowed on the scope's own
var onOwnContainer = map[string]bool{
	"container.inspect": true, "container.top": true, "container.logs": true, "container.changes": true,
	"container.export": true, "container.stats": true, "container.resize": true, "container.start": true,
	"container.stop": true, "container.restart": true, "container.kill": true, "container.pause": true,
	"container.unpause": true, "container.attach": true, "container.attach-websocket": true,
	"container.wait": true, "container.delete": true, "container.archive-info": true, "container.archive-get": true,
}

// decide returns the body to forward (nil for none, or a stream forwarded as it comes).
func (s *scoped) decide(body []byte) ([]byte, error) {
	name := s.req.Endpoint.Name

	if !s.req.Endpoint.Stream && !takesBody[name] && len(body) > 0 {
		return nil, refuse(http.StatusBadRequest, "%s has no body", name)
	}

	// Docker reads the first of a repeated parameter; a check could read another.
	for key, values := range s.query {
		if len(values) > 1 && !(name == "image.save-many" && key == "names") {
			return nil, refuse(http.StatusBadRequest, "the parameter %q is given more than once", key)
		}
	}

	switch {
	case name == "system.ping" || name == "system.version" || name == "system.info":
		return nil, nil
	case name == "container.list" || name == "container.prune" || name == "network.list" || name == "volume.list":
		return nil, s.ownOnly()
	case name == "network.inspect":
		_, err := s.network()
		s.answer = s.sharedContainers

		return nil, err
	case name == "network.create":
		return s.createNetwork(body)
	case name == "network.delete":
		return nil, s.ownNetwork()
	case name == "network.prune" || name == "volume.prune":
		return nil, s.ownOnly()
	case name == "volume.inspect" || name == "volume.delete":
		return nil, s.volume()
	case name == "volume.create":
		return s.createVolume(body)
	case name == "image.create":
		return nil, s.pull()
	case name == "image.tag":
		return nil, s.tag()
	case name == "image.delete":
		return nil, s.ownsImageName(s.req.Params["name"], "image.delete")
	case name == "image.save":
		return nil, s.readsImage(s.req.Params["name"])
	case name == "image.save-many":
		for _, n := range s.query["names"] {
			if err := s.readsImage(n); err != nil {
				return nil, err
			}
		}

		return nil, nil
	case name == "image.search":
		return nil, nil
	case name == "image.load":
		return nil, s.load()
	case name == "distribution.inspect":
		if err := s.image(s.req.Params["name"]); err != nil {
			return nil, refuse(http.StatusNotFound, "No such image: %s", s.req.Params["name"])
		}

		return nil, nil
	case name == "container.create":
		return s.createContainer(body)
	case onOwnContainer[name] || name == "container.archive-put":
		return nil, s.container()
	case name == "container.update":
		if err := s.container(); err != nil {
			return nil, err
		}

		return s.updateContainer(body)
	case name == "container.rename":
		if err := s.container(); err != nil {
			return nil, err
		}

		if to := s.single("name"); !s.scope.Names(to) {
			return nil, refuse(http.StatusForbidden, "container.rename: the name %q isn't one of scope %s's", to, s.scope.Name)
		}

		return nil, nil
	case name == "exec.create":
		if err := s.container(); err != nil {
			return nil, err
		}

		return s.createExec(body)
	case name == "exec.start":
		if err := s.exec(); err != nil {
			return nil, err
		}

		return s.startExec(body)
	case name == "exec.resize" || name == "exec.inspect":
		return nil, s.exec()
	case name == "image.list":
		s.answer = s.images

		return nil, nil
	case name == "image.inspect" || name == "image.history":
		// Another scope's image holds its code, and its configuration its environment.
		return nil, s.readsImage(s.req.Params["name"])
	case name == "network.connect":
		return s.connect(body)
	case name == "network.disconnect":
		return s.disconnect(body)
	}

	return nil, refuse(http.StatusForbidden, "%s isn't allowed for scope %s", name, s.scope.Name)
}

// The endpoints whose body YorvoGate reads (a JSON value); any other has none.
var takesBody = map[string]bool{
	"container.create": true, "container.update": true, "exec.create": true, "exec.start": true,
	"network.connect": true, "network.disconnect": true, "network.create": true, "volume.create": true,
}

// container checks that the container the path names is the scope's (by its label, or one its scope
// lets it use), and names it by its full ID. Another scope's container is answered as Docker answers
// one that doesn't exist.
func (s *scoped) container() error {
	id := s.req.Params["id"]

	c, err := s.docker.Container(s.ctx, s.version, id)
	if err != nil {
		return err
	}

	if c == nil || !(s.scope.Owns(c.Labels) || s.scope.Uses(c.Name)) {
		return refuse(http.StatusNotFound, "No such container: %s", id)
	}

	s.with("id", c.ID)

	return nil
}

// ownsContainer tells whether a container (by ID or name) is the scope's.
func (s *scoped) ownsContainer(id string) bool {
	c, err := s.docker.Container(s.ctx, s.version, id)

	return err == nil && c != nil && (s.scope.Owns(c.Labels) || s.scope.Uses(c.Name))
}

// exec checks that an exec runs in one of the scope's containers.
func (s *scoped) exec() error {
	id := s.req.Params["id"]

	containerID, err := s.docker.ExecContainer(s.ctx, s.version, id)
	if err != nil {
		return err
	}

	if containerID == "" || !s.ownsContainer(containerID) {
		return refuse(http.StatusNotFound, "No such exec instance: %s", id)
	}

	return nil
}

// connect checks a container joining a network: one of the scope's containers, its own network or a
// shared one its scope names, with what it may have there.
func (s *scoped) connect(body []byte) ([]byte, error) {
	var req network.ConnectRequest
	if err := decode(body, &req); err != nil {
		return nil, err
	}

	name, err := s.network()
	if err != nil {
		return nil, err
	}

	c, err := s.docker.Container(s.ctx, s.version, req.Container)
	if err != nil {
		return nil, err
	}

	if c == nil || !(s.scope.Owns(c.Labels) || s.scope.Uses(c.Name)) {
		return nil, refuse(http.StatusNotFound, "No such container: %s", req.Container)
	}

	req.Container = c.ID

	var problems []string
	s.endpoint(name, req.EndpointConfig, func(format string, args ...any) { problems = append(problems, fmt.Sprintf(format, args...)) })

	if len(problems) > 0 {
		return nil, refuse(http.StatusForbidden, "network.connect: %s", strings.Join(problems, "; "))
	}

	return json.Marshal(req)
}

func (s *scoped) disconnect(body []byte) ([]byte, error) {
	var req network.DisconnectRequest
	if err := decode(body, &req); err != nil {
		return nil, err
	}

	if _, err := s.network(); err != nil {
		return nil, err
	}

	c, err := s.docker.Container(s.ctx, s.version, req.Container)
	if err != nil {
		return nil, err
	}

	if c == nil || !(s.scope.Owns(c.Labels) || s.scope.Uses(c.Name)) {
		return nil, refuse(http.StatusNotFound, "No such container: %s", req.Container)
	}

	req.Container = c.ID

	return json.Marshal(req)
}

// network checks that the network the path names is the scope's or a shared one it may join, names
// it by its full ID, and returns its name.
func (s *scoped) network() (string, error) {
	id := s.req.Params["id"]

	n, err := s.docker.Network(s.ctx, s.version, id)
	if err != nil {
		return "", err
	}

	if n == nil {
		return "", refuse(http.StatusNotFound, "network %s not found", id)
	}

	if _, shared := s.scope.Networks[n.Name]; !shared && !s.scope.Owns(n.Labels) {
		return "", refuse(http.StatusNotFound, "network %s not found", id)
	}

	s.with("id", n.ID)

	return n.Name, nil
}

// volume checks that the volume the path names is the scope's.
func (s *scoped) volume() error {
	name := s.req.Params["name"]

	v, err := s.docker.Volume(s.ctx, s.version, name)
	if err != nil {
		return err
	}

	if v == nil || !s.scope.Owns(v.Labels) {
		return refuse(http.StatusNotFound, "get %s: no such volume", name)
	}

	s.with("name", v.Name)

	return nil
}

// ownOnly limits a list (or a prune) to the scope's objects: its label is added to the filters.
func (s *scoped) ownOnly() error {
	filters := map[string][]string{}

	if given := s.query["filters"]; len(given) > 0 {
		var raw map[string]json.RawMessage
		if err := json.Unmarshal([]byte(given[0]), &raw); err != nil {
			return refuse(http.StatusBadRequest, "filters isn't JSON: %v", err)
		}

		for key, value := range raw {
			// Docker takes both {"label": ["a=b"]} and the older {"label": {"a=b": true}}.
			var values []string
			if err := json.Unmarshal(value, &values); err != nil {
				var set map[string]bool
				if err := json.Unmarshal(value, &set); err != nil {
					return refuse(http.StatusBadRequest, "filters.%s isn't a list", key)
				}

				for v, on := range set {
					if on {
						values = append(values, v)
					}
				}
			}

			filters[strings.ToLower(key)] = append(filters[strings.ToLower(key)], values...)
		}
	}

	filters["label"] = append(filters["label"], s.scope.Owner.Key+"="+s.scope.Owner.Value)

	encoded, err := json.Marshal(filters)
	if err != nil {
		return err
	}

	s.query.Set("filters", string(encoded))

	return nil
}

// single is a query parameter (decide refused it given more than once).
func (s *scoped) single(name string) string {
	return s.query.Get(name)
}

// with names the object of the path by what was checked.
func (s *scoped) with(param, value string) {
	s.req.Params[param] = value
	s.path = "/v" + s.version + strings.NewReplacer("{"+param+"}", url.PathEscape(value)).Replace(s.req.Endpoint.Pattern)
}
