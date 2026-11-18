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
		return refuse(http.StatusBadRequest, CodeBodyInvalid, "the body isn't one this endpoint takes: %v", err)
	}

	if decoder.More() {
		return refuse(http.StatusBadRequest, CodeBodyInvalid, "the body has more than one value")
	}

	return nil
}

// createContainer checks a container's configuration, and returns the body Docker gets: the
// configuration that was checked, encoded anew.
func (s *scoped) createContainer(body []byte) ([]byte, error) {
	name := s.single("name")
	if !s.scope.NamesContainer(name) {
		return nil, refuse(http.StatusForbidden, CodeNameNotOwn, "container.create: the name %q isn't one of scope %s's (%s)", name, s.scope.Name, strings.Join(s.scope.Prefixes, ", "))
	}

	if err := s.notTaken("container", name, s.docker.Container); err != nil {
		return nil, err
	}

	var req container.CreateRequest
	if err := decode(body, &req); err != nil {
		return nil, err
	}

	if f := unset(req, createRequest); len(f) > 0 {
		return nil, refuse(http.StatusForbidden, CodeFieldNotAllowed, "container.create %s: %s isn't allowed", name, strings.Join(f, ", "))
	}

	if req.Config == nil || req.Config.Image == "" {
		return nil, refuse(http.StatusBadRequest, CodeImage, "container.create: no image")
	}

	if req.HostConfig == nil {
		req.HostConfig = &container.HostConfig{}
	}

	var found problems
	add := found.add

	for _, f := range unset(req.Config, containerConfig) {
		add(CodeFieldNotAllowed, "%s isn't allowed", f)
	}

	for _, f := range unset(req.HostConfig, hostConfigFields) {
		add(CodeFieldNotAllowed, "HostConfig.%s isn't allowed", f)
	}

	s.ownLabels(req.Config.Labels, add)

	if err := s.image(req.Config.Image); err != nil {
		add(codeOf(err, CodeImage), "%v", err)
	}

	s.host(req.HostConfig, add)
	s.resources(&req.HostConfig.Resources, add)
	for _, f := range unset(req.NetworkingConfig, networkingConfig) {
		add(CodeFieldNotAllowed, "NetworkingConfig.%s isn't allowed", f)
	}

	s.networking(&req.HostConfig.NetworkMode, req.NetworkingConfig, add)

	if len(found) > 0 {
		return nil, found.refusal(http.StatusForbidden, "container.create "+name)
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
func (s *scoped) logOptions(c container.LogConfig, add func(Code, string, ...any)) {
	driver := c.Type
	if driver == "" && s.daemon != nil {
		driver = s.daemon.logDriver
	}

	for option, value := range c.Config {
		switch {
		case driver == "none":
			add(CodeLogging, "the log driver none takes no option (%s)", option)
		case option == "max-buffer-size":
			size, err := units.RAMInBytes(value)
			if err != nil || size > s.policy.LogBuffer() {
				add(CodeLogging, "the log option max-buffer-size %q isn't allowed (at most %d bytes: the buffer is in Docker's own memory)", value, s.policy.LogBuffer())
			}
		case slices.Contains(commonLogOptions, option), slices.Contains(ownLogOptions[driver], option):
		case driver == "json-file" || driver == "local":
			add(CodeLogging, "the log option %s isn't one of the %s driver's", option, driver)
		case !slices.Contains(s.policy.LogOptions[option], value):
			add(CodeLogging, "the log option %s=%q isn't one the listener allows for the %s driver", option, value, driver)
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
func (s *scoped) ownLabels(labels map[string]string, add func(Code, string, ...any)) {
	if !s.scope.Owns(labels) {
		add(CodeLabelNotOwn, "it must carry the label %s=%s", s.scope.Owner.Key, s.scope.Owner.Value)
	}

	if s.scope.OwnedByAnother(labels) {
		add(CodeLabelNotOwn, "its labels mark it as another scope's")
	}
}

// host checks what a container asks of the host: namespaces, capabilities, security options, the
// runtime, logs, and what it mounts.
func (s *scoped) host(h *container.HostConfig, add func(Code, string, ...any)) {
	p := s.policy

	if h.Privileged || h.PublishAllPorts || len(h.PortBindings) > 0 || len(h.Devices) > 0 {
		add(CodeHostAccess, "privileged containers, published ports and devices aren't allowed")
	}

	if h.PidMode.IsHost() || h.IpcMode.IsHost() || h.UTSMode.IsHost() || h.UsernsMode.IsHost() || h.CgroupnsMode.IsHost() {
		add(CodeNamespace, "the host's namespaces aren't allowed")
	}

	// Another of its own containers' namespace, by the ID the check found: by its name, Docker would
	// look it up again, and the name may be another container's by then.
	if other := h.PidMode.Container(); other != "" {
		if id, ok := s.ownContainerID(other); ok {
			h.PidMode = container.PidMode("container:" + id)
		} else {
			add(CodeObjectNotOwn, "PidMode: container:%s isn't one of its own", other)
		}
	}

	if other := h.IpcMode.Container(); other != "" {
		if id, ok := s.ownContainerID(other); ok {
			h.IpcMode = container.IpcMode("container:" + id)
		} else {
			add(CodeObjectNotOwn, "IpcMode: container:%s isn't one of its own", other)
		}
	}

	// Each namespace: its own (Docker's default), or another of the scope's containers'. Only the
	// values listed; Docker reads any other as an error, or as the host's.
	if h.PidMode != "" && !h.PidMode.IsContainer() {
		add(CodeNamespace, "PidMode %q isn't allowed", h.PidMode)
	}

	if !slices.Contains([]container.IpcMode{"", "private", "shareable", "none"}, h.IpcMode) && !h.IpcMode.IsContainer() {
		add(CodeNamespace, "IpcMode %q isn't allowed", h.IpcMode)
	}

	if h.UTSMode != "" || h.UsernsMode != "" {
		add(CodeNamespace, "UTSMode and UsernsMode must be left as Docker sets them")
	}

	if h.CgroupnsMode != "" && h.CgroupnsMode != "private" {
		add(CodeNamespace, "CgroupnsMode %q isn't allowed", h.CgroupnsMode)
	}

	for _, c := range h.CapAdd {
		name := strings.TrimPrefix(strings.ToUpper(c), "CAP_")
		if !slices.Contains(p.Capabilities, name) {
			add(CodeCapability, "adding the capability %s isn't allowed (allowed: %s)", c, list(p.Capabilities))
		}
	}

	if p.DropAllCapabilities && !slices.ContainsFunc(h.CapDrop, func(c string) bool { return strings.EqualFold(c, "ALL") }) {
		add(CodeCapability, "it must drop all capabilities (CapDrop: ALL)")
	}

	for _, o := range h.SecurityOpt {
		if !slices.Contains(noNewPrivileges, o) && !slices.Contains(p.SecurityOptions, o) {
			add(CodeSecurity, "the security option %q isn't allowed", o)
		}
	}

	if p.NoNewPrivileges && !slices.ContainsFunc(h.SecurityOpt, func(o string) bool { return slices.Contains(noNewPrivileges, o) }) {
		add(CodeSecurity, "it must run with no-new-privileges")
	}

	if h.Runtime != "" && !slices.Contains(p.Runtimes, h.Runtime) {
		add(CodeRuntime, "the runtime %q isn't allowed", h.Runtime)
	}

	if h.Isolation != "" && h.Isolation != "default" {
		add(CodeRuntime, "the isolation %q isn't allowed", h.Isolation)
	}

	if h.LogConfig.Type != "" && !slices.Contains(append([]string{"json-file", "local", "none"}, p.LogDrivers...), h.LogConfig.Type) {
		add(CodeLogging, "the log driver %q isn't allowed", h.LogConfig.Type)
	} else {
		s.logOptions(h.LogConfig, add)
	}

	for _, f := range unset(h.LogConfig, logConfig) {
		add(CodeFieldNotAllowed, "LogConfig.%s isn't allowed", f)
	}

	if h.OomScoreAdj < 0 {
		add(CodeLimit, "OomScoreAdj below 0 isn't allowed")
	}

	if !plainLocal(h.VolumeDriver, nil) {
		add(CodeMount, "the volume driver %q isn't allowed", h.VolumeDriver)
	}

	// By the ID the check found, as namespaces are (its :ro or :rw kept)
	for i, from := range h.VolumesFrom {
		other, mode, moded := strings.Cut(from, ":")
		id, ok := s.ownContainerID(other)

		switch {
		case !ok:
			add(CodeObjectNotOwn, "VolumesFrom: %s isn't one of its own containers", other)
		case moded:
			h.VolumesFrom[i] = id + ":" + mode
		default:
			h.VolumesFrom[i] = id
		}
	}

	for _, b := range h.Binds {
		source, _, _ := strings.Cut(b, ":")
		if err := s.volumeSource(source); err != nil {
			add(CodeHostAccess, "Binds %q: %v", b, err)
		}
	}

	for _, m := range h.Mounts {
		s.mount(m, add)
	}
}

// resources checks a new container's limits: what the listener requires, and what reaches the host's
// devices or its real-time scheduler.
func (s *scoped) resources(r *container.Resources, add func(Code, string, ...any)) {
	s.limits(*r, true, 0, add)
}

// limits checks a container's limits against the listener's, the same way on create and on update.
// On create, a required limit must be given. On an update, one left out (Memory 0, PidsLimit nil)
// is the container's own, which Docker keeps, and only one given is checked. Swap (MemorySwap, which
// is memory and swap together) is bounded by the memory limit as Docker bounds it by default: at
// most twice it, never unlimited. An update that gives swap without memory is checked against the
// container's memory now (current).
func (s *scoped) limits(r container.Resources, creating bool, current int64, add func(Code, string, ...any)) {
	p := s.policy

	if p.MaxMemory > 0 {
		if (creating || r.Memory != 0) && (r.Memory <= 0 || r.Memory > p.MaxMemory) {
			add(CodeLimit, "a memory limit up to %d bytes is required", p.MaxMemory)
		}

		memory := r.Memory
		if memory == 0 {
			memory = current
		}

		switch {
		case r.MemorySwap < 0:
			add(CodeLimit, "unlimited swap (MemorySwap -1) isn't allowed: memory and swap together are at most twice the memory limit")
		case r.MemorySwap > 0 && memory > 0 && (r.MemorySwap < memory || r.MemorySwap > 2*memory):
			add(CodeLimit, "MemorySwap (memory and swap together) must be between the memory limit and twice it (%d to %d bytes), or left unset", memory, 2*memory)
		}
	}

	if p.MaxPids > 0 && (creating || r.PidsLimit != nil) && (r.PidsLimit == nil || *r.PidsLimit <= 0 || *r.PidsLimit > p.MaxPids) {
		add(CodeLimit, "a process limit up to %d is required", p.MaxPids)
	}

	if r.OomKillDisable != nil && *r.OomKillDisable {
		add(CodeLimit, "disabling the OOM killer isn't allowed")
	}

	for _, u := range r.Ulimits {
		if u != nil && !slices.Contains(p.Ulimits, u.Name) {
			add(CodeLimit, "the ulimit %s isn't allowed", u.Name)
		}
	}

	for _, u := range r.Ulimits {
		for _, f := range unset(u, ulimit) {
			add(CodeFieldNotAllowed, "a ulimit's %s isn't allowed", f)
		}
	}
}

func (s *scoped) mount(m mount.Mount, add func(Code, string, ...any)) {
	for _, f := range unset(m, mountSpec) {
		add(CodeFieldNotAllowed, "a mount's %s isn't allowed", f)
	}

	if !path.IsAbs(m.Target) || path.Clean(m.Target) != m.Target {
		add(CodeMount, "a mount's target %q must be an absolute, clean path", m.Target)
	}

	switch m.Type {
	case mount.TypeVolume:
		if m.Source != "" {
			if err := s.volumeSource(m.Source); err != nil {
				add(CodeMount, "mount of %q: %v", m.Source, err)
			}
		}

		if o := m.VolumeOptions; o != nil {
			for _, f := range unset(o, volumeOptions) {
				add(CodeFieldNotAllowed, "a mount's VolumeOptions.%s isn't allowed", f)
			}

			for _, f := range unset(o.DriverConfig, mountDriver) {
				add(CodeFieldNotAllowed, "a mount's VolumeOptions.DriverConfig.%s isn't allowed", f)
			}

			if o.DriverConfig != nil && !plainLocal(o.DriverConfig.Name, o.DriverConfig.Options) {
				add(CodeMount, "mount of %q: volume driver options aren't allowed", m.Source)
			}

			if s.scope.OwnedByAnother(o.Labels) {
				add(CodeObjectNotOwn, "mount of %q: its labels mark the volume as another scope's", m.Source)
			}

			if o.Subpath != "" && (path.IsAbs(o.Subpath) || path.Clean(o.Subpath) != o.Subpath || strings.HasPrefix(o.Subpath, "..")) {
				add(CodeMount, "mount of %q: the subpath %q must stay inside the volume", m.Source, o.Subpath)
			}
		}
	case mount.TypeTmpfs:
		if m.Source != "" {
			add(CodeMount, "a tmpfs mount has no source")
		}
	default:
		add(CodeMount, "a %q mount of %q isn't allowed (only volumes and tmpfs)", m.Type, m.Source)
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
func (s *scoped) networking(pinned *container.NetworkMode, nc *network.NetworkingConfig, add func(Code, string, ...any)) {
	mode := *pinned

	var endpoints map[string]*network.EndpointSettings
	if nc != nil {
		endpoints = nc.EndpointsConfig
	}

	switch {
	case mode == "none":
		if len(endpoints) > 0 {
			add(CodeNetwork, "a container without a network joins none")
		}

		return
	case strings.HasPrefix(string(mode), "container:"):
		other := strings.TrimPrefix(string(mode), "container:")
		c, err := s.docker.Container(s.ctx, s.version, other)

		if err == nil && s.owned(c) {
			// By the ID the check found, not the name Docker would look up again
			*pinned = container.NetworkMode("container:" + string(c.ID))
		}

		switch {
		case err != nil || !s.owned(c):
			add(CodeObjectNotOwn, "NetworkMode container:%s isn't one of its own containers", other)
		case s.egressFree():
			// The one it joins may have been made before the scope was egress-free.
			if outside, err := external(s.ctx, s.docker, s.version, c.inspection); err != nil {
				add(CodeNetwork, "the networks of container %s couldn't be checked: %v", other, err)
			} else if len(outside) > 0 {
				add(CodeEgress, "the container %s whose network it joins is on a network that isn't internal (%s; egress: none)", other, strings.Join(outside, ", "))
			}
		}

		if len(endpoints) > 0 {
			add(CodeNetwork, "a container in another's network joins none of its own")
		}

		return
	case mode == "" || mode == "default" || mode == "bridge" || mode == "host" || strings.Contains(string(mode), ":"):
		// Docker's default bridge (shared by every container on the machine), the host's, or a mode
		// YorvoGate doesn't know
		add(CodeNetwork, "NetworkMode %q isn't allowed: a container joins its scope's networks", mode)

		return
	}

	if _, ok := endpoints[string(mode)]; !ok {
		s.endpoint(string(mode), nil, add)
	}

	for name, e := range endpoints {
		s.endpoint(name, e, add)
	}
}

func (s *scoped) endpoint(name string, e *network.EndpointSettings, add func(Code, string, ...any)) {
	if shared, ok := s.scope.Networks[name]; ok {
		if s.egressFree() {
			s.internal(name, add)
		}

		if e == nil {
			return
		}

		for _, f := range unset(e, endpointShared) {
			add(CodeFieldNotAllowed, "on the shared network %s, %s isn't allowed", name, f)
		}

		// As Docker's DNS keeps it: "WEB" is the scope's "web", "web." another name
		for _, a := range e.Aliases {
			alias, ok := scope.NormaliseAlias(a)
			if !ok {
				add(CodeNetwork, "the alias %q on the shared network %s isn't a name as Docker's DNS keeps it (ASCII, no trailing dot)", a, name)

				continue
			}

			if !slices.Contains(shared.Aliases, alias) {
				add(CodeNetwork, "the alias %q on the shared network %s isn't one of its own", a, name)
			}
		}

		for _, f := range unset(e.IPAMConfig, endpointIPAMShared) {
			add(CodeFieldNotAllowed, "on the shared network %s, IPAMConfig.%s isn't allowed", name, f)
		}

		if c := e.IPAMConfig; c != nil {
			for _, ip := range append([]netip.Addr{c.IPv4Address, c.IPv6Address}, c.LinkLocalIPs...) {
				if ip.IsValid() && !slices.Contains(shared.Addresses, ip.String()) {
					add(CodeNetwork, "the address %s on the shared network %s isn't one of its own", ip, name)
				}
			}
		}

		return
	}

	n, err := s.docker.Network(s.ctx, s.version, name)
	if err != nil {
		add(CodeNetwork, "the network %s couldn't be checked: %v", name, err)

		return
	}

	if n == nil || !s.scope.Owns(n.Labels) {
		add(CodeObjectNotOwn, "the network %s isn't one of its own, nor a shared one it may join", name)

		return
	}

	if s.egressFree() && !n.Internal {
		add(CodeEgress, "the network %s isn't internal (egress: none)", name)
	}

	if e != nil {
		for _, f := range unset(e, endpointOwn) {
			add(CodeFieldNotAllowed, "on the network %s, %s isn't allowed", name, f)
		}
	}
}

// updateContainer checks new limits for a running container, as create does.
// currentMemory is the memory limit of the container an update is for, as Docker has it (0 when
// there's none, or it wasn't inspected).
func (s *scoped) currentMemory() int64 {
	if c := s.target; c != nil && c.inspection != nil && c.inspection.HostConfig != nil {
		return c.inspection.HostConfig.Memory
	}

	return 0
}

func (s *scoped) updateContainer(body []byte) ([]byte, error) {
	var req container.UpdateConfig
	if err := decode(body, &req); err != nil {
		return nil, err
	}

	var found problems
	add := found.add

	for _, f := range unset(req, updateConfig) {
		add(CodeFieldNotAllowed, "%s isn't allowed", f)
	}

	s.limits(req.Resources, false, s.currentMemory(), add)

	if len(found) > 0 {
		return nil, found.refusal(http.StatusForbidden, "container.update")
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
		return nil, refuse(http.StatusForbidden, CodeExec, "exec.create: a privileged exec isn't allowed")
	}

	if f := unset(req, execCreate); len(f) > 0 {
		return nil, refuse(http.StatusForbidden, CodeFieldNotAllowed, "exec.create: %s isn't allowed", strings.Join(f, ", "))
	}

	return json.Marshal(req)
}

func (s *scoped) startExec(body []byte) ([]byte, error) {
	var req container.ExecStartRequest
	if err := decode(body, &req); err != nil {
		return nil, err
	}

	if f := unset(req, execStart); len(f) > 0 {
		return nil, refuse(http.StatusForbidden, CodeFieldNotAllowed, "exec.start: %s isn't allowed", strings.Join(f, ", "))
	}

	// Attached, it's a stream both ways: only as an upgrade.
	if !req.Detach && !s.upgrading {
		return nil, refuse(http.StatusBadRequest, CodeUpgradeOnly, "exec.start: an attached exec is allowed only as an HTTP upgrade")
	}

	return json.Marshal(req)
}

func list(values []string) string {
	if len(values) == 0 {
		return "none"
	}

	return strings.Join(values, ", ")
}
