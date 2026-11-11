package gate

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"path"
	"slices"
	"strings"

	"github.com/docker/go-units"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
	"github.com/moby/moby/api/types/network"
	"github.com/yorvolabs/yorvogate/internal/scope"
)

var noNewPrivileges = []string{"no-new-privileges", "no-new-privileges:true", "no-new-privileges=true"}

// decode reads a body into Docker's own type the way Docker does (Go's decoder: keys matched
// regardless of case, the last of duplicates wins), refusing a field the type doesn't have.
func decode(body []byte, into any) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(into); err != nil {
		return refuse(http.StatusBadRequest, "the body isn't one this endpoint takes: %v", err)
	}

	if decoder.More() {
		return refuse(http.StatusBadRequest, "the body has more than one value")
	}

	return nil
}

// createContainer checks a container's configuration, and returns the body Docker gets: the
// configuration that was checked, encoded anew.
func (s *scoped) createContainer(body []byte) ([]byte, error) {
	name := s.single("name")
	if !s.scope.NamesContainer(name) {
		return nil, refuse(http.StatusForbidden, "container.create: the name %q isn't one of scope %s's (%s)", name, s.scope.Name, strings.Join(s.scope.Prefixes, ", "))
	}

	var req container.CreateRequest
	if err := decode(body, &req); err != nil {
		return nil, err
	}

	if f := unset(req, createRequest); len(f) > 0 {
		return nil, refuse(http.StatusForbidden, "container.create %s: %s isn't allowed", name, strings.Join(f, ", "))
	}

	if req.Config == nil || req.Config.Image == "" {
		return nil, refuse(http.StatusBadRequest, "container.create: no image")
	}

	if req.HostConfig == nil {
		req.HostConfig = &container.HostConfig{}
	}

	var problems []string
	add := func(format string, args ...any) { problems = append(problems, fmt.Sprintf(format, args...)) }

	for _, f := range unset(req.Config, containerConfig) {
		add("%s isn't allowed", f)
	}

	for _, f := range unset(req.HostConfig, hostConfigFields) {
		add("HostConfig.%s isn't allowed", f)
	}

	s.ownLabels(req.Config.Labels, add)

	if err := s.image(req.Config.Image); err != nil {
		add("%v", err)
	}

	s.host(req.HostConfig, add)
	s.resources(&req.HostConfig.Resources, add)
	for _, f := range unset(req.NetworkingConfig, networkingConfig) {
		add("NetworkingConfig.%s isn't allowed", f)
	}

	s.networking(req.HostConfig.NetworkMode, req.NetworkingConfig, add)

	if len(problems) > 0 {
		return nil, refuse(http.StatusForbidden, "container.create %s: %s", name, strings.Join(problems, "; "))
	}

	// What it runs is an image it may read, however it's named: Docker takes an ID by as few as 4 of
	// its digits, so a name checked alone would let it run an image all of whose names are another's.
	img, err := s.readsImage(req.Config.Image)
	if err != nil {
		return nil, err
	}

	// And it runs that image: a name moved after the check doesn't change what it runs.
	req.Config.Image = pinned(req.Config.Image, img)

	// What it leaves unset isn't left to Docker's configuration: a private cgroup namespace,
	// Docker's built-in seccomp profile, and the default runtime YorvoGate last read and checked.
	safeDefaults(req.HostConfig, s.daemon.runtime)

	// A volume a mount creates is the scope's: it carries its owner label. (Docker sets a mount's
	// labels only on a volume it creates; one that exists is left as it is.)
	for i := range req.HostConfig.Mounts {
		m := &req.HostConfig.Mounts[i]
		if m.Type != mount.TypeVolume {
			continue
		}

		if m.VolumeOptions == nil {
			m.VolumeOptions = &mount.VolumeOptions{}
		}

		if m.VolumeOptions.Labels == nil {
			m.VolumeOptions.Labels = map[string]string{}
		}

		m.VolumeOptions.Labels[s.scope.Owner.Key] = s.scope.Owner.Value
	}

	return json.Marshal(req)
}

// The log options every driver takes (moby 29.9.2, daemon/logger/factory.go:127-130 and the common
// attributes), and those of the drivers every scope has (jsonfilelog.go:146-160, local/local.go:38-49).
var (
	commonLogOptions = []string{"mode", "max-buffer-size", "tag", "labels", "labels-regex", "env", "env-regex"}
	ownLogOptions    = map[string][]string{"json-file": {"max-size", "max-file", "compress"}, "local": {"max-size", "max-file", "compress"}}
)

// logOptions checks a container's log options for the driver its logs go to: the one it names, or
// Docker's default. json-file and local take their own; another driver the listener allows takes
// only the values its log_options list, so a scope can't point Docker at an address of its choosing.
// A non-blocking log's buffer is in Docker's own memory: it's bounded.
func (s *scoped) logOptions(c container.LogConfig, add func(string, ...any)) {
	driver := c.Type
	if driver == "" && s.daemon != nil {
		driver = s.daemon.logDriver
	}

	for option, value := range c.Config {
		switch {
		case driver == "none":
			add("the log driver none takes no option (%s)", option)
		case option == "max-buffer-size":
			size, err := units.RAMInBytes(value)
			if err != nil || size > s.policy.LogBuffer() {
				add("the log option max-buffer-size %q isn't allowed (at most %d bytes: the buffer is in Docker's own memory)", value, s.policy.LogBuffer())
			}
		case slices.Contains(commonLogOptions, option), slices.Contains(ownLogOptions[driver], option):
		case driver == "json-file" || driver == "local":
			add("the log option %s isn't one of the %s driver's", option, driver)
		case !slices.Contains(s.policy.LogOptions[option], value):
			add("the log option %s=%q isn't one the listener allows for the %s driver", option, value, driver)
		}
	}
}

// safeDefaults writes into a container's host configuration what Docker would otherwise take from its
// own: "default-cgroupns-mode" may be host, "seccomp-profile" unconfined, and "default-runtime" is
// reloaded live. A container's "seccomp=builtin" is Docker's built-in profile whatever the daemon's
// (moby 29.9.2, daemon/seccomp_linux.go:46-47). The IPC mode is left as asked: Docker's default is a
// private or shareable namespace, never the host's, and a container can't join one that's private.
func safeDefaults(h *container.HostConfig, runtime string) {
	if h.CgroupnsMode == "" {
		h.CgroupnsMode = container.CgroupnsModePrivate
	}

	// Docker reads "seccomp=…" and, deprecated, "seccomp:…" (daemon_unix.go:225-241).
	if !slices.ContainsFunc(h.SecurityOpt, func(o string) bool {
		return strings.HasPrefix(o, "seccomp=") || strings.HasPrefix(o, "seccomp:")
	}) {
		h.SecurityOpt = append(h.SecurityOpt, "seccomp=builtin")
	}

	if h.Runtime == "" {
		h.Runtime = runtime
	}
}

// ownLabels checks the labels of an object a scope creates: they carry its owner label, and none of
// another scope's.
func (s *scoped) ownLabels(labels map[string]string, add func(string, ...any)) {
	if !s.scope.Owns(labels) {
		add("it must carry the label %s=%s", s.scope.Owner.Key, s.scope.Owner.Value)
	}

	if s.scope.OwnedByAnother(labels) {
		add("its labels mark it as another scope's")
	}
}

// host checks what a container asks of the host: namespaces, capabilities, security options, the
// runtime, logs, and what it mounts.
func (s *scoped) host(h *container.HostConfig, add func(string, ...any)) {
	p := s.policy

	if h.Privileged || h.PublishAllPorts || len(h.PortBindings) > 0 || len(h.Devices) > 0 {
		add("privileged containers, published ports and devices aren't allowed")
	}

	if h.PidMode.IsHost() || h.IpcMode.IsHost() || h.UTSMode.IsHost() || h.UsernsMode.IsHost() || h.CgroupnsMode.IsHost() {
		add("the host's namespaces aren't allowed")
	}

	for mode, other := range map[string]string{"PidMode": h.PidMode.Container(), "IpcMode": h.IpcMode.Container()} {
		if other != "" && !s.ownsContainer(other) {
			add("%s: container:%s isn't one of its own", mode, other)
		}
	}

	// Each namespace: its own (Docker's default), or another of the scope's containers'. Only the
	// values listed; Docker reads any other as an error, or as the host's.
	if h.PidMode != "" && !h.PidMode.IsContainer() {
		add("PidMode %q isn't allowed", h.PidMode)
	}

	if !slices.Contains([]container.IpcMode{"", "private", "shareable", "none"}, h.IpcMode) && !h.IpcMode.IsContainer() {
		add("IpcMode %q isn't allowed", h.IpcMode)
	}

	if h.UTSMode != "" || h.UsernsMode != "" {
		add("UTSMode and UsernsMode must be left as Docker sets them")
	}

	if h.CgroupnsMode != "" && h.CgroupnsMode != "private" {
		add("CgroupnsMode %q isn't allowed", h.CgroupnsMode)
	}

	for _, c := range h.CapAdd {
		name := strings.TrimPrefix(strings.ToUpper(c), "CAP_")
		if !slices.Contains(p.Capabilities, name) {
			add("adding the capability %s isn't allowed (allowed: %s)", c, list(p.Capabilities))
		}
	}

	if p.DropAllCapabilities && !slices.ContainsFunc(h.CapDrop, func(c string) bool { return strings.EqualFold(c, "ALL") }) {
		add("it must drop all capabilities (CapDrop: ALL)")
	}

	for _, o := range h.SecurityOpt {
		if !slices.Contains(noNewPrivileges, o) && !slices.Contains(p.SecurityOptions, o) {
			add("the security option %q isn't allowed", o)
		}
	}

	if p.NoNewPrivileges && !slices.ContainsFunc(h.SecurityOpt, func(o string) bool { return slices.Contains(noNewPrivileges, o) }) {
		add("it must run with no-new-privileges")
	}

	if h.Runtime != "" && !slices.Contains(p.Runtimes, h.Runtime) {
		add("the runtime %q isn't allowed", h.Runtime)
	}

	if h.Isolation != "" && h.Isolation != "default" {
		add("the isolation %q isn't allowed", h.Isolation)
	}

	if h.LogConfig.Type != "" && !slices.Contains(append([]string{"json-file", "local", "none"}, p.LogDrivers...), h.LogConfig.Type) {
		add("the log driver %q isn't allowed", h.LogConfig.Type)
	} else {
		s.logOptions(h.LogConfig, add)
	}

	for _, f := range unset(h.LogConfig, logConfig) {
		add("LogConfig.%s isn't allowed", f)
	}

	if h.OomScoreAdj < 0 {
		add("OomScoreAdj below 0 isn't allowed")
	}

	if !plainLocal(h.VolumeDriver, nil) {
		add("the volume driver %q isn't allowed", h.VolumeDriver)
	}

	for _, from := range h.VolumesFrom {
		other, _, _ := strings.Cut(from, ":")
		if !s.ownsContainer(other) {
			add("VolumesFrom: %s isn't one of its own containers", other)
		}
	}

	for _, b := range h.Binds {
		source, _, _ := strings.Cut(b, ":")
		if err := s.volumeSource(source); err != nil {
			add("Binds %q: %v", b, err)
		}
	}

	for _, m := range h.Mounts {
		s.mount(m, add)
	}
}

// resources checks limits: what the listener requires, and what reaches the host's devices or its
// real-time scheduler.
func (s *scoped) resources(r *container.Resources, add func(string, ...any)) {
	p := s.policy

	if p.MaxMemory > 0 && (r.Memory <= 0 || r.Memory > p.MaxMemory) {
		add("a memory limit up to %d bytes is required", p.MaxMemory)
	}

	if p.MaxPids > 0 && (r.PidsLimit == nil || *r.PidsLimit <= 0 || *r.PidsLimit > p.MaxPids) {
		add("a process limit up to %d is required", p.MaxPids)
	}

	if r.OomKillDisable != nil && *r.OomKillDisable {
		add("disabling the OOM killer isn't allowed")
	}

	for _, u := range r.Ulimits {
		if u != nil && !slices.Contains(p.Ulimits, u.Name) {
			add("the ulimit %s isn't allowed", u.Name)
		}
	}

	for _, u := range r.Ulimits {
		for _, f := range unset(u, ulimit) {
			add("a ulimit's %s isn't allowed", f)
		}
	}
}

func (s *scoped) mount(m mount.Mount, add func(string, ...any)) {
	for _, f := range unset(m, mountSpec) {
		add("a mount's %s isn't allowed", f)
	}

	if !path.IsAbs(m.Target) || path.Clean(m.Target) != m.Target {
		add("a mount's target %q must be an absolute, clean path", m.Target)
	}

	switch m.Type {
	case mount.TypeVolume:
		if m.Source != "" {
			if err := s.volumeSource(m.Source); err != nil {
				add("mount of %q: %v", m.Source, err)
			}
		}

		if o := m.VolumeOptions; o != nil {
			for _, f := range unset(o, volumeOptions) {
				add("a mount's VolumeOptions.%s isn't allowed", f)
			}

			for _, f := range unset(o.DriverConfig, mountDriver) {
				add("a mount's VolumeOptions.DriverConfig.%s isn't allowed", f)
			}

			if o.DriverConfig != nil && !plainLocal(o.DriverConfig.Name, o.DriverConfig.Options) {
				add("mount of %q: volume driver options aren't allowed", m.Source)
			}

			if s.scope.OwnedByAnother(o.Labels) {
				add("mount of %q: its labels mark the volume as another scope's", m.Source)
			}

			if o.Subpath != "" && (path.IsAbs(o.Subpath) || path.Clean(o.Subpath) != o.Subpath || strings.HasPrefix(o.Subpath, "..")) {
				add("mount of %q: the subpath %q must stay inside the volume", m.Source, o.Subpath)
			}
		}
	case mount.TypeTmpfs:
		if m.Source != "" {
			add("a tmpfs mount has no source")
		}
	default:
		add("a %q mount of %q isn't allowed (only volumes and tmpfs)", m.Type, m.Source)
	}
}

// volumeSource checks a named volume a container mounts: a name of the scope's, never a host path,
// and if it exists, its own.
func (s *scoped) volumeSource(source string) error {
	if hostPath(source) {
		return errors.New("only named volumes of its own, never a host path")
	}

	if !s.scope.Names(source) {
		return fmt.Errorf("the volume %q isn't one of its own names", source)
	}

	v, err := s.docker.Volume(s.ctx, s.version, source)
	if err != nil {
		return err
	}

	if v != nil && !s.scope.Owns(v.Labels) {
		return fmt.Errorf("the volume %q isn't its own", source)
	}

	// Its labels can say it's the scope's while its driver binds a host path (a local volume with
	// o=bind,device=/,type=none, or any non-local driver). Checked at use, not only at create,
	// because the scope may not have created it: an orchestrator provisions labelled volumes.
	if v != nil && !plainLocal(v.Driver, v.Options) {
		return fmt.Errorf("the volume %q has driver options that could bind a host path; only a plain local volume may be mounted", source)
	}

	return nil
}

// networking checks the networks a container joins: its own, or the shared ones its scope names
// (with only its own aliases and addresses there).
func (s *scoped) networking(mode container.NetworkMode, nc *network.NetworkingConfig, add func(string, ...any)) {
	var endpoints map[string]*network.EndpointSettings
	if nc != nil {
		endpoints = nc.EndpointsConfig
	}

	switch {
	case mode == "none":
		if len(endpoints) > 0 {
			add("a container without a network joins none")
		}

		return
	case strings.HasPrefix(string(mode), "container:"):
		other := strings.TrimPrefix(string(mode), "container:")
		c, err := s.docker.Container(s.ctx, s.version, other)

		switch {
		case err != nil || !s.owned(c):
			add("NetworkMode container:%s isn't one of its own containers", other)
		case s.egressFree():
			// The one it joins may have been made before the scope was egress-free.
			if outside, err := external(s.ctx, s.docker, s.version, c.inspection); err != nil {
				add("the networks of container %s couldn't be checked: %v", other, err)
			} else if len(outside) > 0 {
				add("the container %s whose network it joins is on a network that isn't internal (%s; egress: none)", other, strings.Join(outside, ", "))
			}
		}

		if len(endpoints) > 0 {
			add("a container in another's network joins none of its own")
		}

		return
	case mode == "" || mode == "default" || mode == "bridge" || mode == "host" || strings.Contains(string(mode), ":"):
		// Docker's default bridge (shared by every container on the machine), the host's, or a mode
		// YorvoGate doesn't know
		add("NetworkMode %q isn't allowed: a container joins its scope's networks", mode)

		return
	}

	if _, ok := endpoints[string(mode)]; !ok {
		s.endpoint(string(mode), nil, add)
	}

	for name, e := range endpoints {
		s.endpoint(name, e, add)
	}
}

func (s *scoped) endpoint(name string, e *network.EndpointSettings, add func(string, ...any)) {
	if shared, ok := s.scope.Networks[name]; ok {
		if s.egressFree() {
			s.internal(name, add)
		}

		if e == nil {
			return
		}

		for _, f := range unset(e, endpointShared) {
			add("on the shared network %s, %s isn't allowed", name, f)
		}

		// As Docker's DNS keeps it: "WEB" is the scope's "web", "web." another name
		for _, a := range e.Aliases {
			alias, ok := scope.NormaliseAlias(a)
			if !ok {
				add("the alias %q on the shared network %s isn't a name as Docker's DNS keeps it (ASCII, no trailing dot)", a, name)

				continue
			}

			if !slices.Contains(shared.Aliases, alias) {
				add("the alias %q on the shared network %s isn't one of its own", a, name)
			}
		}

		for _, f := range unset(e.IPAMConfig, endpointIPAMShared) {
			add("on the shared network %s, IPAMConfig.%s isn't allowed", name, f)
		}

		if c := e.IPAMConfig; c != nil {
			for _, ip := range append([]netip.Addr{c.IPv4Address, c.IPv6Address}, c.LinkLocalIPs...) {
				if ip.IsValid() && !slices.Contains(shared.Addresses, ip.String()) {
					add("the address %s on the shared network %s isn't one of its own", ip, name)
				}
			}
		}

		return
	}

	n, err := s.docker.Network(s.ctx, s.version, name)
	if err != nil {
		add("the network %s couldn't be checked: %v", name, err)

		return
	}

	if n == nil || !s.scope.Owns(n.Labels) {
		add("the network %s isn't one of its own, nor a shared one it may join", name)

		return
	}

	if s.egressFree() && !n.Internal {
		add("the network %s isn't internal (egress: none)", name)
	}

	if e != nil {
		for _, f := range unset(e, endpointOwn) {
			add("on the network %s, %s isn't allowed", name, f)
		}
	}
}

// updateContainer checks new limits for a running container, as create does.
func (s *scoped) updateContainer(body []byte) ([]byte, error) {
	var req container.UpdateConfig
	if err := decode(body, &req); err != nil {
		return nil, err
	}

	var problems []string
	add := func(format string, args ...any) { problems = append(problems, fmt.Sprintf(format, args...)) }

	for _, f := range unset(req, updateConfig) {
		add("%s isn't allowed", f)
	}

	r := req.Resources
	if s.policy.MaxMemory > 0 && r.Memory != 0 && (r.Memory < 0 || r.Memory > s.policy.MaxMemory) {
		add("a memory limit up to %d bytes is required", s.policy.MaxMemory)
	}

	if s.policy.MaxPids > 0 && r.PidsLimit != nil && (*r.PidsLimit <= 0 || *r.PidsLimit > s.policy.MaxPids) {
		add("a process limit up to %d is required", s.policy.MaxPids)
	}

	if r.OomKillDisable != nil && *r.OomKillDisable {
		add("disabling the OOM killer isn't allowed")
	}

	for _, u := range r.Ulimits {
		if u != nil && !slices.Contains(s.policy.Ulimits, u.Name) {
			add("the ulimit %s isn't allowed", u.Name)
		}
	}

	for _, u := range r.Ulimits {
		for _, f := range unset(u, ulimit) {
			add("a ulimit's %s isn't allowed", f)
		}
	}

	if len(problems) > 0 {
		return nil, refuse(http.StatusForbidden, "container.update: %s", strings.Join(problems, "; "))
	}

	return json.Marshal(req)
}

// createExec checks a command run in one of its containers: never privileged.
func (s *scoped) createExec(body []byte) ([]byte, error) {
	var req container.ExecCreateRequest
	if err := decode(body, &req); err != nil {
		return nil, err
	}

	if req.Privileged {
		return nil, refuse(http.StatusForbidden, "exec.create: a privileged exec isn't allowed")
	}

	if f := unset(req, execCreate); len(f) > 0 {
		return nil, refuse(http.StatusForbidden, "exec.create: %s isn't allowed", strings.Join(f, ", "))
	}

	return json.Marshal(req)
}

func (s *scoped) startExec(body []byte) ([]byte, error) {
	var req container.ExecStartRequest
	if err := decode(body, &req); err != nil {
		return nil, err
	}

	if f := unset(req, execStart); len(f) > 0 {
		return nil, refuse(http.StatusForbidden, "exec.start: %s isn't allowed", strings.Join(f, ", "))
	}

	// Attached, it's a stream both ways: only as an upgrade.
	if !req.Detach && !s.upgrading {
		return nil, refuse(http.StatusBadRequest, "exec.start: an attached exec is allowed only as an HTTP upgrade")
	}

	return json.Marshal(req)
}

func list(values []string) string {
	if len(values) == 0 {
		return "none"
	}

	return strings.Join(values, ", ")
}
