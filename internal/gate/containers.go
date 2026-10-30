package gate

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"path"
	"reflect"
	"slices"
	"strings"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
	"github.com/moby/moby/api/types/network"
)

// The fields of Docker's container types a scope may set, each either free (no power over the host
// or other scopes) or checked by a rule below. Every other field must be left unset: a field a
// newer Docker adds is refused until it's reviewed and listed here.
var (
	configFields = fields("Hostname", "Domainname", "User", "AttachStdin", "AttachStdout", "AttachStderr", "ExposedPorts",
		"Tty", "OpenStdin", "StdinOnce", "Env", "Cmd", "Healthcheck", "ArgsEscaped", "Image", "Volumes", "WorkingDir",
		"Entrypoint", "NetworkDisabled", "OnBuild", "Labels", "StopSignal", "StopTimeout", "Shell")

	hostFields = fields(
		// Free
		"ContainerIDFile", "RestartPolicy", "AutoRemove", "ConsoleSize", "DNS", "DNSOptions", "DNSSearch", "ExtraHosts",
		"GroupAdd", "ReadonlyRootfs", "Tmpfs", "ShmSize", "Umask", "Init",
		"CPUShares", "Memory", "NanoCPUs", "BlkioWeight", "CPUPeriod", "CPUQuota", "CpusetCpus", "CpusetMems",
		"MemoryReservation", "MemorySwap", "MemorySwappiness", "CPUCount", "CPUPercent", "IOMaximumIOps", "IOMaximumBandwidth",
		// Checked below
		"Binds", "LogConfig", "NetworkMode", "VolumeDriver", "VolumesFrom", "CapAdd", "CapDrop", "CgroupnsMode", "IpcMode",
		"OomScoreAdj", "PidMode", "SecurityOpt", "UTSMode", "UsernsMode", "Runtime", "Isolation", "Mounts",
		"OomKillDisable", "PidsLimit", "Ulimits")

	updateFields = fields("CPUShares", "Memory", "NanoCPUs", "BlkioWeight", "CPUPeriod", "CPUQuota", "CpusetCpus", "CpusetMems",
		"MemoryReservation", "MemorySwap", "MemorySwappiness", "CPUCount", "CPUPercent", "IOMaximumIOps", "IOMaximumBandwidth",
		"RestartPolicy", "PidsLimit", "Ulimits", "OomKillDisable")

	mountFields = fields("Type", "Source", "Target", "ReadOnly", "Consistency", "VolumeOptions", "TmpfsOptions")

	// On a network of its own, an endpoint is the scope's to set up; on a shared one, only its aliases
	// and addresses from its scope file.
	ownEndpointFields    = fields("IPAMConfig", "Aliases", "GwPriority", "MacAddress")
	sharedEndpointFields = fields("IPAMConfig", "Aliases", "GwPriority")

	execFields = fields("User", "Tty", "ConsoleSize", "AttachStdin", "AttachStderr", "AttachStdout", "DetachKeys", "Env", "WorkingDir", "Cmd")

	noNewPrivileges = []string{"no-new-privileges", "no-new-privileges:true", "no-new-privileges=true"}
)

func fields(names ...string) map[string]bool {
	set := make(map[string]bool, len(names))
	for _, n := range names {
		set[n] = true
	}

	return set
}

// unset lists the fields of a struct (embedded ones included) that are set although they aren't
// allowed, by the names Docker's API uses for them.
func unset(v any, allowed map[string]bool) []string {
	var set []string

	value := reflect.ValueOf(v)
	for value.Kind() == reflect.Pointer {
		if value.IsNil() {
			return nil
		}

		value = value.Elem()
	}

	for i := range value.NumField() {
		field := value.Type().Field(i)
		if field.Anonymous && field.Type.Kind() == reflect.Struct {
			set = append(set, unset(value.Field(i).Interface(), allowed)...)

			continue
		}

		if !allowed[field.Name] && isSet(field.Name, value.Field(i)) {
			set = append(set, apiName(field))
		}
	}

	return set
}

// isSet tells whether a field asks for something. An empty map or list asks for nothing, as Docker
// reads it, but for the paths Docker masks or makes read-only in /proc: there, an empty list means
// none, i.e. /proc unmasked.
func isSet(name string, v reflect.Value) bool {
	if name == "MaskedPaths" || name == "ReadonlyPaths" {
		return !v.IsNil()
	}

	if (v.Kind() == reflect.Map || v.Kind() == reflect.Slice) && v.Len() == 0 {
		return false
	}

	return !v.IsZero()
}

func apiName(f reflect.StructField) string {
	if name, _, _ := strings.Cut(f.Tag.Get("json"), ","); name != "" && name != "-" {
		return name
	}

	return f.Name
}

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
	if !s.scope.Names(name) {
		return nil, refuse(http.StatusForbidden, "container.create: the name %q isn't one of scope %s's (%s)", name, s.scope.Name, strings.Join(s.scope.Prefixes, ", "))
	}

	var req container.CreateRequest
	if err := decode(body, &req); err != nil {
		return nil, err
	}

	if req.Config == nil || req.Config.Image == "" {
		return nil, refuse(http.StatusBadRequest, "container.create: no image")
	}

	if req.HostConfig == nil {
		req.HostConfig = &container.HostConfig{}
	}

	var problems []string
	add := func(format string, args ...any) { problems = append(problems, fmt.Sprintf(format, args...)) }

	for _, f := range unset(req.Config, configFields) {
		add("%s isn't allowed", f)
	}

	for _, f := range unset(req.HostConfig, hostFields) {
		add("HostConfig.%s isn't allowed", f)
	}

	if !s.scope.Owns(req.Config.Labels) {
		add("it must carry the label %s=%s", s.scope.Owner.Key, s.scope.Owner.Value)
	}

	if err := s.image(req.Config.Image); err != nil {
		add("%v", err)
	}

	s.host(req.HostConfig, add)
	s.resources(&req.HostConfig.Resources, add)
	s.networking(req.HostConfig.NetworkMode, req.NetworkingConfig, add)

	if len(problems) > 0 {
		return nil, refuse(http.StatusForbidden, "container.create %s: %s", name, strings.Join(problems, "; "))
	}

	return json.Marshal(req)
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
	}

	if h.OomScoreAdj < 0 {
		add("OomScoreAdj below 0 isn't allowed")
	}

	if h.VolumeDriver != "" && h.VolumeDriver != "local" {
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
}

func (s *scoped) mount(m mount.Mount, add func(string, ...any)) {
	for _, f := range unset(m, mountFields) {
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
			if o.DriverConfig != nil && (o.DriverConfig.Name != "" && o.DriverConfig.Name != "local" || len(o.DriverConfig.Options) > 0) {
				add("mount of %q: volume driver options aren't allowed", m.Source)
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
	if source == "" || strings.ContainsAny(source, "/\\") || strings.HasPrefix(source, ".") || strings.HasPrefix(source, "~") {
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
		if !s.ownsContainer(other) {
			add("NetworkMode container:%s isn't one of its own containers", other)
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
		if e == nil {
			return
		}

		for _, f := range unset(e, sharedEndpointFields) {
			add("on the shared network %s, %s isn't allowed", name, f)
		}

		for _, a := range e.Aliases {
			if !slices.Contains(shared.Aliases, a) {
				add("the alias %q on the shared network %s isn't one of its own", a, name)
			}
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

	if e != nil {
		for _, f := range unset(e, ownEndpointFields) {
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

	for _, f := range unset(req, updateFields) {
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

	if f := unset(req, execFields); len(f) > 0 {
		return nil, refuse(http.StatusForbidden, "exec.create: %s isn't allowed", strings.Join(f, ", "))
	}

	return json.Marshal(req)
}

func (s *scoped) startExec(body []byte) ([]byte, error) {
	var req container.ExecStartRequest
	if err := decode(body, &req); err != nil {
		return nil, err
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
