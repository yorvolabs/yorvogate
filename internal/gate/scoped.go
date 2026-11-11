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
	ctx   context.Context
	req   route.Request
	scope *scope.Scope
	// The digest of the token it was allowed with (a token listener's)
	token  string
	policy config.Containers
	// The registries and platforms its pulls may reach
	pulls config.Pulls
	// Docker's defaults, as last read (safe: an unsafe read refuses the request first)
	daemon *daemonState
	// The listener's AppArmor profiles for builders, and whether any builder is accepted
	builderProfiles []string
	anyBuilder      bool
	// The builder the request names, if it names one
	builderName string
	docker      *Docker
	version     string

	// What's forwarded: the path (with its version) and the query, as the rules leave them
	path  string
	query url.Values

	// Whether the request asks for an HTTP upgrade
	upgrading bool

	// A stream's body (an image archive), the most read of it, and what's forwarded in its place
	stream io.Reader
	// Whether the request came with a body (one of unknown length included)
	hasBody       bool
	loadLimit     int64
	loads         *loadLimiter
	forwardBody   io.ReadCloser
	forwardLength int64
	// Done once the request is forwarded (e.g. an archive's copy removed)
	cleanup func()
	// Changes Docker's answer before the client sees it (e.g. other scopes' objects left out)
	answer func([]byte) ([]byte, error)
}

// decide returns the body to forward (nil for none, or a stream forwarded as it comes).
func (s *scoped) decide(body []byte) ([]byte, error) {
	name := s.req.Endpoint.Name

	d, ok := forScopes[name]
	if !ok {
		return nil, refuse(http.StatusForbidden, "%s isn't allowed for scope %s", name, s.scope.Name)
	}

	if !s.req.Endpoint.Stream && !d.body && len(body) > 0 {
		return nil, refuse(http.StatusBadRequest, "%s has no body", name)
	}

	if err := d.parameters(name, s.query); err != nil {
		return nil, err
	}

	return d.rule(s, body)
}

// onOwnContainer allows what acts on one of the scope's containers and takes no body; on a builder,
// only its inspection.
func (s *scoped) onOwnContainer() error {
	builder, err := s.container()
	if err == nil && builder && s.req.Endpoint.Name != "container.inspect" {
		return s.notOnBuilder()
	}

	return err
}

func (s *scoped) updateOwnContainer(body []byte) ([]byte, error) {
	if err := s.ownContainer(); err != nil {
		return nil, err
	}

	return s.updateContainer(body)
}

func (s *scoped) rename() error {
	if err := s.ownContainer(); err != nil {
		return err
	}

	if to := s.single("name"); !s.scope.Names(to) {
		return refuse(http.StatusForbidden, "container.rename: the name %q isn't one of scope %s's", to, s.scope.Name)
	}

	return nil
}

// createExecIn checks an exec: in a builder, only its dial-stdio.
func (s *scoped) createExecIn(body []byte) ([]byte, error) {
	builder, err := s.container()
	if err != nil {
		return nil, err
	}

	if builder {
		return s.createDialStdio(body)
	}

	return s.createExec(body)
}

func (s *scoped) startOwnExec(body []byte) ([]byte, error) {
	if err := s.exec(); err != nil {
		return nil, err
	}

	return s.startExec(body)
}

func (s *scoped) inspectNetwork() error {
	_, err := s.network()
	s.answer = s.sharedContainers

	return err
}

func (s *scoped) listImages() error {
	s.answer = s.images

	return nil
}

// inspectImage and imageHistory: another scope's image holds its code, and its configuration its
// environment.
// inspectImage, imageHistory: of an image the scope may read, the one checked (by its ID).
func (s *scoped) inspectImage() error {
	s.answer = s.imageNames

	return s.pinImage()
}

func (s *scoped) imageHistory() error {
	s.answer = s.history

	return s.pinImage()
}

func (s *scoped) pinImage() error {
	img, err := s.readsImage(s.req.Params["name"])
	if err != nil {
		return err
	}

	s.with("name", img.ID)

	return nil
}

// saveImage, saveMany: by the names asked, not the ID, which would leave the archive without them
// (Docker names what it saves by what it was asked). A name may move between the check and the
// save. A scope can't move one through image.tag (it tags only from what it may read, and only into
// its own namespaces). Whether image.load or a pull can give a name to content the scope doesn't
// hold is open until the archive completeness check and 0.3-d's registry allowlist ship: see the
// roadmap (0.3-o, 0.3-w).
func (s *scoped) saveImage() error {
	_, err := s.readsImage(s.req.Params["name"])

	return err
}

func (s *scoped) saveMany() error {
	for _, n := range s.query["names"] {
		if _, err := s.readsImage(n); err != nil {
			return err
		}
	}

	return nil
}

// deleteImage: by name, not ID. By name, Docker removes that name; by ID, the image.
func (s *scoped) deleteImage() error {
	return s.ownsImageName(s.req.Params["name"], "image.delete")
}

// distribution: Docker answers it from the registry, never from the images it has, and the answer
// has no names to filter. A name in another scope's protected namespace is refused before any request.
// It reaches only a registry of the listener's (pulls.go).
func (s *scoped) distribution() error {
	if err := s.image(s.req.Params["name"]); err != nil {
		return refuse(http.StatusNotFound, "No such image: %s", s.req.Params["name"])
	}

	return s.registry(ReferenceRegistry(s.req.Params["name"]), "distribution.inspect")
}

// The streams whose body is an archive: one YorvoGate reads (image.load), or one that goes into the
// scope's own container as it comes (container.archive-put). Docker gets them as application/x-tar.
var sendsArchive = map[string]bool{"image.load": true, "container.archive-put": true}

// container checks that the container the path names is the scope's (by its label) or one of its
// builders, and names it by its full ID. Another scope's container is answered as Docker answers one
// that doesn't exist. It tells whether the container is a builder: what may be done with one is
// checked by the caller.
func (s *scoped) container() (bool, error) {
	id := s.req.Params["id"]

	c, err := s.docker.Container(s.ctx, s.version, id)
	if err != nil {
		return false, err
	}

	if c == nil || !(s.owned(c) || s.scope.Builds(c.Name)) {
		return false, refuse(http.StatusNotFound, "No such container: %s", id)
	}

	s.with("id", c.ID)

	if s.scope.Builds(c.Name) {
		return true, s.builder(c)
	}

	return false, s.runsInside(c, false)
}

// owned tells whether a container is the scope's own: by its label, and never one of its builders
// (whatever their labels, they're the orchestrator's).
func (s *scoped) owned(c *object) bool {
	return c != nil && s.scope.Owns(c.Labels) && !s.scope.Builds(c.Name)
}

// ownsContainer tells whether a container (by ID or name) is the scope's own.
func (s *scoped) ownsContainer(id string) bool {
	c, err := s.docker.Container(s.ctx, s.version, id)

	return err == nil && s.owned(c)
}

// exec checks that an exec runs in one of the scope's containers, or is a builder's dial-stdio (only
// started, never resized or inspected).
func (s *scoped) exec() error {
	id := s.req.Params["id"]

	e, err := s.docker.Exec(s.ctx, s.version, id)
	if err != nil {
		return err
	}

	if e == nil {
		return refuse(http.StatusNotFound, "No such exec instance: %s", id)
	}

	c, err := s.docker.Container(s.ctx, s.version, e.ContainerID)
	if err != nil {
		return err
	}

	switch {
	case s.owned(c):
		// An exec made before the scope was egress-free runs code in a container with a way out.
		return s.runsInside(c, false)
	case c != nil && s.scope.Builds(c.Name):
		if s.req.Endpoint.Name != "exec.start" {
			return refuse(http.StatusForbidden, "%s isn't allowed in builder %s: only buildctl dial-stdio, created and started", s.req.Endpoint.Name, c.Name)
		}

		// Docker reports an exec created without a user as the container's (the builder's own,
		// which isn't root).
		if p := e.ProcessConfig; p == nil || !dialStdio(append([]string{p.Entrypoint}, p.Arguments...)) || (p.Privileged != nil && *p.Privileged) || !builderUser(c, p.User) || p.Tty {
			return refuse(http.StatusForbidden, "exec.start: in builder %s, only buildctl dial-stdio is started", c.Name)
		}

		return s.builder(c)
	}

	return refuse(http.StatusNotFound, "No such exec instance: %s", id)
}

// connect checks a container joining a network: one of the scope's containers, its own network or a
// shared one its scope names, with what it may have there.
func (s *scoped) connect(body []byte) ([]byte, error) {
	var req network.ConnectRequest
	if err := decode(body, &req); err != nil {
		return nil, err
	}

	if f := unset(req, networkConnect); len(f) > 0 {
		return nil, refuse(http.StatusForbidden, "network.connect: %s isn't allowed", strings.Join(f, ", "))
	}

	name, err := s.network()
	if err != nil {
		return nil, err
	}

	c, err := s.docker.Container(s.ctx, s.version, req.Container)
	if err != nil {
		return nil, err
	}

	if !s.owned(c) {
		return nil, refuse(http.StatusNotFound, "No such container: %s", req.Container)
	}

	req.Container = string(c.ID)

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

	if f := unset(req, networkDisconnect); len(f) > 0 {
		return nil, refuse(http.StatusForbidden, "network.disconnect: %s isn't allowed", strings.Join(f, ", "))
	}

	if _, err := s.network(); err != nil {
		return nil, err
	}

	c, err := s.docker.Container(s.ctx, s.version, req.Container)
	if err != nil {
		return nil, err
	}

	if !s.owned(c) {
		return nil, refuse(http.StatusNotFound, "No such container: %s", req.Container)
	}

	req.Container = string(c.ID)

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

	s.with("name", v.ID)

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
func (s *scoped) with(param string, id resolvedID) {
	s.req.Params[param] = string(id)
	escaped := url.PathEscape(string(id))
	// "{name*}" (an image's name, which may span segments) is replaced as "{id}" is
	s.path = "/v" + s.version + strings.NewReplacer("{"+param+"}", escaped, "{"+param+"*}", escaped).Replace(s.req.Endpoint.Pattern)
}
