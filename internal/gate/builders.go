package gate

import (
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
)

// A scope's builder is a BuildKit container the orchestrator created. A scope may only inspect it and
// reach BuildKit through it with "buildctl dial-stdio" (what buildx's remote driver runs), and only
// while the builder has the configuration below: rootless, unprivileged, nothing of the host's.

// dialStdio tells whether a command is BuildKit's dial-stdio, exactly.
func dialStdio(cmd []string) bool {
	return slices.Equal(cmd, []string{"buildctl", "dial-stdio"})
}

// createDialStdio checks an exec created in a builder: buildctl dial-stdio and nothing else.
func (s *scoped) createDialStdio(body []byte) ([]byte, error) {
	var req container.ExecCreateRequest
	if err := decode(body, &req); err != nil {
		return nil, err
	}

	if !dialStdio(req.Cmd) {
		return nil, refuse(http.StatusForbidden, "exec.create: in builder %s, only buildctl dial-stdio is allowed", s.builderName)
	}

	if f := unset(req, dialStdioCreate); len(f) > 0 {
		return nil, refuse(http.StatusForbidden, "exec.create: in builder %s, %s isn't allowed", s.builderName, strings.Join(f, ", "))
	}

	return json.Marshal(req)
}

// builderUser tells whether an exec's user, as Docker reports it, is the builder's own.
func builderUser(c *object, user string) bool {
	return user == "" || (c.inspection != nil && c.inspection.Config != nil && user == c.inspection.Config.User)
}

// notOnBuilder refuses anything else on a builder.
func (s *scoped) notOnBuilder() error {
	return refuse(http.StatusForbidden, "%s isn't allowed on builder %s: a builder may only be inspected, and reached with buildctl dial-stdio", s.req.Endpoint.Name, s.builderName)
}

// ownContainer checks that the container the path names is the scope's own (a builder isn't).
func (s *scoped) ownContainer() error {
	builder, err := s.container()
	if err == nil && builder {
		return s.notOnBuilder()
	}

	return err
}

// builder checks a builder's configuration, as Docker has it now: anything that would give the
// scope more than BuildKit's own unprivileged process is refused, naming what.
func (s *scoped) builder(c *object) error {
	s.builderName = c.Name

	if s.anyBuilder {
		return nil
	}

	volume := func(name string) (*object, error) { return s.docker.Volume(s.ctx, s.version, name) }

	problems := builderProblems(c.inspection, s.builderProfiles, volume)

	// An egress-free scope's builder fetches through the orchestrator's proxy, if at all: its RUN
	// steps would otherwise be the way out.
	if s.egressFree() {
		outside, err := external(s.ctx, s.docker, s.version, c.inspection)
		if err != nil {
			problems = append(problems, fmt.Sprintf("its networks couldn't be checked: %v", err))
		} else if len(outside) > 0 {
			problems = append(problems, fmt.Sprintf("it's on a network that isn't internal (%s; egress: none)", strings.Join(outside, ", ")))
		}
	}

	if len(problems) > 0 {
		return refuse(http.StatusForbidden, "builder %s isn't configured as a builder must be: %s", c.Name, strings.Join(problems, "; "))
	}

	return nil
}

// builderProblems lists what's wrong with a builder's configuration. volume reads a volume it
// mounts, as Docker has it now.
func builderProblems(c *container.InspectResponse, profiles []string, volume func(string) (*object, error)) []string {
	if c == nil || c.HostConfig == nil || c.Config == nil {
		return []string{"its configuration couldn't be read"}
	}

	h := c.HostConfig

	var problems []string

	add := func(format string, args ...any) { problems = append(problems, fmt.Sprintf(format, args...)) }

	if h.Privileged {
		add("it's privileged")
	}

	if len(h.CapAdd) > 0 {
		add("it adds capabilities (%s)", strings.Join(h.CapAdd, ", "))
	}

	if len(h.Devices) > 0 || len(h.DeviceRequests) > 0 || len(h.DeviceCgroupRules) > 0 {
		add("it has devices")
	}

	// "-v name:/path" is a named volume, which Docker keeps among the binds; "-v /x:/path" a host path.
	for _, b := range h.Binds {
		if source, _, _ := strings.Cut(b, ":"); hostPath(source) {
			add("it binds the host path %q", source)
		}
	}

	for _, m := range h.Mounts {
		if m.Type != mount.TypeVolume && m.Type != mount.TypeTmpfs {
			add("it mounts %q as %s (only volumes and tmpfs)", m.Source, m.Type)
		}
	}

	for _, m := range c.Mounts {
		if m.Type != mount.TypeVolume && m.Type != mount.TypeTmpfs {
			add("it has a %s mount at %s (only volumes and tmpfs)", m.Type, m.Destination)
		}

		// A volume's labels say nothing of where it is: one with driver options binds a host path
		// as a bind would. Each is read (an anonymous one too); one that can't be is refused.
		if m.Type == mount.TypeVolume {
			v, err := volume(m.Name)
			switch {
			case err != nil || v == nil:
				add("its volume at %s couldn't be read", m.Destination)
			case !plainLocal(v.Driver, v.Options):
				add("its volume %q at %s has driver options that could bind a host path (only a plain local volume)", m.Name, m.Destination)
			}
		}
	}

	if h.PidMode.IsHost() || h.IpcMode.IsHost() || h.UTSMode.IsHost() || h.UsernsMode.IsHost() || h.CgroupnsMode.IsHost() || h.NetworkMode.IsHost() {
		add("it shares the host's namespaces")
	}

	if h.PidMode.IsContainer() || h.IpcMode.IsContainer() || h.NetworkMode.IsContainer() || len(h.VolumesFrom) > 0 {
		add("it joins another container (PidMode, IpcMode, NetworkMode or VolumesFrom)")
	}

	if len(h.PortBindings) > 0 || h.PublishAllPorts {
		add("it publishes ports")
	}

	if len(h.Sysctls) > 0 {
		add("it sets kernel parameters (Sysctls)")
	}

	if user, _, _ := strings.Cut(strings.TrimSpace(c.Config.User), ":"); user == "" || user == "0" || user == "root" {
		add("it runs as root (User %q): a builder runs as an unprivileged user, as BuildKit's rootless image does", c.Config.User)
	}

	for _, o := range h.SecurityOpt {
		if !builderOption(o, profiles) {
			add("the security option %q isn't allowed (seccomp=unconfined, systempaths=unconfined, no-new-privileges=false, apparmor=<one of the listener's builder_apparmor_profiles>)", o)
		}
	}

	return problems
}

// builderOption tells whether a builder may have a security option, as Docker takes it ("key=value"
// or "key:value"). A bare option (no value) is refused: the only one Docker reads bare is
// "no-new-privileges" (= true), which a rootless builder can't run under.
func builderOption(o string, profiles []string) bool {
	i := strings.IndexAny(o, "=:")
	if i < 0 {
		return false
	}

	key, value := o[:i], o[i+1:]

	switch key {
	case "seccomp", "systempaths":
		return value == "unconfined"
	case "no-new-privileges":
		// Rootless BuildKit can't map its users under no-new-privileges, so a hardened daemon
		// (no-new-privileges true by default) needs the builder to opt out. Only "false" is
		// allowed: "true" (or a bare option) is a builder that can't start.
		return value == "false"
	case "apparmor":
		return slices.Contains(profiles, value)
	}

	return false
}
