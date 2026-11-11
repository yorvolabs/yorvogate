package gate

import (
	"net/netip"
	"reflect"
	"slices"
	"strings"

	units "github.com/docker/go-units"
	imagespec "github.com/moby/docker-image-spec/specs-go/v1"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/api/types/volume"
)

// What the gate decided on every field of the bodies it reads (moby's api types): each is free (no
// power over the host or another scope), checked (a rule reads it and refuses what it may not ask),
// or refused (it must be left unset). TestEveryFieldIsDecidedOn holds every field of every struct
// type a body reaches, embedded ones included, to exactly one decision, so a field a newer Docker
// adds fails the tests until it's decided on (go run ./tools/apidiff lists them).

type class int

const (
	isFree class = iota + 1
	isChecked
	isRefused
)

func (c class) String() string {
	return [...]string{"", "free", "checked", "refused"}[c]
}

// emptiness is what an empty list or map asks of a refused one, as Docker reads it.
type emptiness int

const (
	// emptyIsUnset: [] or {} asks for nothing, as null does
	emptyIsUnset emptiness = iota + 1
	// emptyAsks: [] asks for something (MaskedPaths: [] is /proc unmasked); only null is unset
	emptyAsks
)

type decision struct {
	class class
	// checked: the rule that reads it; free or refused: why
	why   string
	empty emptiness
	// The classification of what a struct-typed field holds (its element, for a list or map). A
	// free field's is walked with it; a checked field's rule walks it, and may choose among several
	// (an endpoint's, on its own network or a shared one).
	nested []*classification
}

type classification struct {
	name   string
	of     reflect.Type
	fields map[string]decision
}

// decided builds a classification from groups of fields, each group one decision.
func decided(name string, of reflect.Type, groups ...map[string]decision) *classification {
	c := &classification{name: name, of: of, fields: map[string]decision{}}

	for _, g := range groups {
		for f, d := range g {
			if _, twice := c.fields[f]; twice {
				panic("fields: " + name + "." + f + " is decided on twice")
			}

			c.fields[f] = d
		}
	}

	return c
}

func group(d decision, names ...string) map[string]decision {
	g := make(map[string]decision, len(names))
	for _, n := range names {
		g[n] = d
	}

	return g
}

func freeAs(why string, names ...string) map[string]decision {
	return group(decision{class: isFree, why: why}, names...)
}

func checkedBy(rule string, names ...string) map[string]decision {
	return group(decision{class: isChecked, why: rule}, names...)
}

func refusedAs(why string, names ...string) map[string]decision {
	return group(decision{class: isRefused, why: why}, names...)
}

// refusedLists are refused lists and maps whose empty value asks for nothing.
func refusedLists(why string, names ...string) map[string]decision {
	return group(decision{class: isRefused, why: why, empty: emptyIsUnset}, names...)
}

// refusedEvenEmpty are refused lists whose empty value asks for something: only null is unset.
func refusedEvenEmpty(why string, names ...string) map[string]decision {
	return group(decision{class: isRefused, why: why, empty: emptyAsks}, names...)
}

// holding is a struct-typed field's decision with what it holds.
func holding(d map[string]decision, nested ...*classification) map[string]decision {
	for f, x := range d {
		x.nested = nested
		d[f] = x
	}

	return d
}

// The value types read as scalars: their fields are unexported, and Docker parses them from text.
var leaves = []reflect.Type{
	reflect.TypeFor[netip.Addr](),
	reflect.TypeFor[netip.Prefix](),
	reflect.TypeFor[network.Port](),
	reflect.TypeFor[struct{}](),
}

const (
	ownContainer = "the scope's own container's setting, on its own namespaces and files"
	ownLimit     = "a limit on the scope's own container (cgroup shares, quotas, sets, weights)"
	hostDevices  = "reaches the host's devices or block devices"
	realtime     = "the host's real-time scheduler"
	outputs      = "what Docker reports, never what a client asks"
)

var (
	healthcheck = decided("HealthcheckConfig", reflect.TypeFor[imagespec.HealthcheckConfig](),
		freeAs("a command in the container's own namespaces, and its timing", "Test", "Interval", "Timeout", "StartPeriod", "StartInterval", "Retries"))

	containerConfig = decided("Config", reflect.TypeFor[container.Config](),
		freeAs(ownContainer, "Hostname", "Domainname", "User", "AttachStdin", "AttachStdout", "AttachStderr", "ExposedPorts",
			"Tty", "OpenStdin", "StdinOnce", "Env", "Cmd", "ArgsEscaped", "Volumes", "WorkingDir", "Entrypoint", "NetworkDisabled",
			"OnBuild", "StopSignal", "StopTimeout", "Shell"),
		holding(freeAs(ownContainer, "Healthcheck"), healthcheck),
		checkedBy("image, readsImage", "Image"),
		checkedBy("ownLabels", "Labels"))

	restartPolicy = decided("RestartPolicy", reflect.TypeFor[container.RestartPolicy](),
		freeAs("when Docker restarts the scope's own container", "Name", "MaximumRetryCount"))

	logConfig = decided("LogConfig", reflect.TypeFor[container.LogConfig](),
		checkedBy("host, logOptions", "Type", "Config"))

	ulimit = decided("Ulimit", reflect.TypeFor[units.Ulimit](),
		checkedBy("resources (the listener's ulimits)", "Name"),
		freeAs("a limit on the scope's own processes, of a kind the listener allows", "Hard", "Soft"))

	mountDriver = decided("Driver", reflect.TypeFor[mount.Driver](),
		checkedBy("mount, plainLocal", "Name", "Options"))

	volumeOptions = decided("VolumeOptions", reflect.TypeFor[mount.VolumeOptions](),
		freeAs("whether Docker copies the image's files into a new volume of the scope's", "NoCopy"),
		checkedBy("mount (another scope's owner label)", "Labels"),
		checkedBy("mount (inside the volume)", "Subpath"),
		holding(checkedBy("mount, plainLocal", "DriverConfig"), mountDriver))

	tmpfsOptions = decided("TmpfsOptions", reflect.TypeFor[mount.TmpfsOptions](),
		freeAs("a memory-backed mount of the container's own, counted in its memory limit", "SizeBytes", "Mode", "Options"))

	mountSpec = decided("Mount", reflect.TypeFor[mount.Mount](),
		checkedBy("mount (volumes and tmpfs only)", "Type"),
		checkedBy("mount, volumeSource", "Source"),
		checkedBy("mount (an absolute, clean path)", "Target"),
		freeAs(ownContainer, "ReadOnly", "Consistency"),
		holding(checkedBy("mount", "VolumeOptions"), volumeOptions),
		holding(freeAs("a memory-backed mount of the container's own, counted in its memory limit", "TmpfsOptions"), tmpfsOptions),
		refusedAs("a bind mount reaches the host's files", "BindOptions"),
		refusedAs("an image mount reads an image the scope's rules don't check", "ImageOptions"),
		refusedAs("the swarm's", "ClusterOptions"))

	// The limits Resources holds, in a container's host configuration and in an update
	resourcesFree = freeAs(ownLimit, "CPUShares", "NanoCPUs", "BlkioWeight", "CPUPeriod", "CPUQuota", "CpusetCpus", "CpusetMems",
		"MemoryReservation", "MemorySwap", "MemorySwappiness", "CPUCount", "CPUPercent", "IOMaximumIOps", "IOMaximumBandwidth")
	resourcesRefused = []map[string]decision{
		refusedAs("its cgroup's place is the daemon's to choose", "CgroupParent"),
		refusedLists(hostDevices, "BlkioWeightDevice", "BlkioDeviceReadBps", "BlkioDeviceWriteBps", "BlkioDeviceReadIOps",
			"BlkioDeviceWriteIOps", "Devices", "DeviceCgroupRules", "DeviceRequests"),
		refusedAs(realtime, "CPURealtimePeriod", "CPURealtimeRuntime"),
	}

	hostConfigFields = decided("HostConfig", reflect.TypeFor[container.HostConfig](), append([]map[string]decision{
		freeAs(ownContainer, "ContainerIDFile", "AutoRemove", "ConsoleSize", "DNS", "DNSOptions", "DNSSearch", "ExtraHosts",
			"GroupAdd", "ReadonlyRootfs", "Tmpfs", "ShmSize", "Umask", "Init"),
		holding(freeAs(ownContainer, "RestartPolicy"), restartPolicy),
		resourcesFree,
		checkedBy("host", "Binds", "VolumeDriver", "VolumesFrom", "CapAdd", "CapDrop", "CgroupnsMode", "IpcMode", "OomScoreAdj",
			"PidMode", "SecurityOpt", "UTSMode", "UsernsMode", "Runtime", "Isolation"),
		holding(checkedBy("host, logOptions", "LogConfig"), logConfig),
		holding(checkedBy("host, mount", "Mounts"), mountSpec),
		checkedBy("networking", "NetworkMode"),
		checkedBy("resources (the listener's limits)", "Memory", "OomKillDisable", "PidsLimit"),
		holding(checkedBy("resources (the listener's ulimits)", "Ulimits"), ulimit),
		refusedLists("publishes the host's ports", "PortBindings"),
		refusedAs("publishes the host's ports", "PublishAllPorts"),
		refusedAs("every power over the host", "Privileged"),
		refusedLists("read by runtimes, which may act on them", "Annotations"),
		refusedAs("the cgroup of another container", "Cgroup"),
		refusedLists("legacy links reach other containers' addresses and environments", "Links"),
		refusedLists("the storage driver's options, on the host's disk", "StorageOpt"),
		refusedLists("kernel parameters", "Sysctls"),
		refusedEvenEmpty("what Docker masks or makes read-only in /proc: [] is none, /proc unmasked", "MaskedPaths", "ReadonlyPaths"),
	}, resourcesRefused...)...)

	endpointIPAMOwn = decided("EndpointIPAMConfig (its own network)", reflect.TypeFor[network.EndpointIPAMConfig](),
		freeAs("an address on the scope's own network", "IPv4Address", "IPv6Address", "LinkLocalIPs"))

	endpointIPAMShared = decided("EndpointIPAMConfig (a shared network)", reflect.TypeFor[network.EndpointIPAMConfig](),
		checkedBy("endpoint (the scope's addresses there)", "IPv4Address", "IPv6Address", "LinkLocalIPs"))

	endpointRefused = []map[string]decision{
		refusedLists("legacy links reach other containers' addresses and environments", "Links"),
		refusedLists("the network driver's options", "DriverOpts"),
		refusedLists("names in Docker's DNS beyond its aliases", "DNSNames"),
		refusedAs(outputs, "NetworkID", "EndpointID", "Gateway", "IPAddress", "IPPrefixLen", "IPv6Gateway", "GlobalIPv6Address",
			"GlobalIPv6PrefixLen"),
	}

	endpointOwn = decided("EndpointSettings (its own network)", reflect.TypeFor[network.EndpointSettings](), append([]map[string]decision{
		freeAs("on the scope's own network", "Aliases", "GwPriority", "MacAddress"),
		holding(freeAs("on the scope's own network", "IPAMConfig"), endpointIPAMOwn),
	}, endpointRefused...)...)

	endpointShared = decided("EndpointSettings (a shared network)", reflect.TypeFor[network.EndpointSettings](), append([]map[string]decision{
		freeAs("which of its networks routes by default: its own container's", "GwPriority"),
		checkedBy("endpoint (the scope's aliases there)", "Aliases"),
		holding(checkedBy("endpoint", "IPAMConfig"), endpointIPAMShared),
		refusedLists("another container's address on a network others share", "MacAddress"),
	}, endpointRefused...)...)

	networkingConfig = decided("NetworkingConfig", reflect.TypeFor[network.NetworkingConfig](),
		holding(checkedBy("networking, endpoint", "EndpointsConfig"), endpointOwn, endpointShared))

	createRequest = decided("container.CreateRequest", reflect.TypeFor[container.CreateRequest](),
		holding(checkedBy("createContainer", "Config"), containerConfig),
		holding(checkedBy("createContainer", "HostConfig"), hostConfigFields),
		holding(checkedBy("createContainer, networking", "NetworkingConfig"), networkingConfig))

	updateConfig = decided("container.UpdateConfig", reflect.TypeFor[container.UpdateConfig](), append([]map[string]decision{
		resourcesFree,
		holding(freeAs(ownContainer, "RestartPolicy"), restartPolicy),
		checkedBy("updateContainer (the listener's limits)", "Memory", "OomKillDisable", "PidsLimit"),
		holding(checkedBy("updateContainer (the listener's ulimits)", "Ulimits"), ulimit),
	}, resourcesRefused...)...)

	execCreate = decided("container.ExecCreateRequest (its own container)", reflect.TypeFor[container.ExecCreateRequest](),
		freeAs("a command in the scope's own container, as its own user", "User", "Tty", "ConsoleSize", "AttachStdin", "AttachStderr",
			"AttachStdout", "DetachKeys", "Env", "WorkingDir", "Cmd"),
		refusedAs("every power over the host", "Privileged"))

	dialStdioCreate = decided("container.ExecCreateRequest (a builder)", reflect.TypeFor[container.ExecCreateRequest](),
		checkedBy("createDialStdio (buildctl dial-stdio exactly)", "Cmd"),
		freeAs("what docker exec -i sends: the stream's ends", "AttachStdin", "AttachStdout", "AttachStderr", "ConsoleSize", "DetachKeys"),
		refusedAs("a builder runs only dial-stdio, as its own user", "User", "Privileged", "Tty", "WorkingDir"),
		refusedLists("a builder runs only dial-stdio, as its own user", "Env"))

	execStart = decided("container.ExecStartRequest", reflect.TypeFor[container.ExecStartRequest](),
		checkedBy("startExec (attached only as an upgrade)", "Detach"),
		freeAs("the terminal of an exec of its own", "Tty", "ConsoleSize"))

	ipamConfig = decided("IPAMConfig", reflect.TypeFor[network.IPAMConfig](),
		checkedBy("createNetwork (inside the scope's subnets)", "Subnet"),
		freeAs("addresses within the subnet, which is checked: Docker refuses one outside it (\"parent subnet … doesn't contain\"; the nightly leg checks it)", "IPRange", "Gateway", "AuxAddress"))

	ipam = decided("IPAM", reflect.TypeFor[network.IPAM](),
		checkedBy("createNetwork (the default driver)", "Driver"),
		holding(checkedBy("createNetwork", "Config"), ipamConfig),
		refusedLists("an IPAM driver's options", "Options"))

	networkCreate = decided("network.CreateRequest", reflect.TypeFor[network.CreateRequest](),
		checkedBy("createNetwork (its names)", "Name"),
		checkedBy("createNetwork, ownLabels", "Labels"),
		checkedBy("createNetwork (bridge only)", "Driver"),
		checkedBy("createNetwork (local only)", "Scope"),
		checkedBy("createNetwork (egress: none)", "Internal"),
		holding(checkedBy("createNetwork", "IPAM"), ipam),
		freeAs("which addresses the scope's own bridge has", "EnableIPv4", "EnableIPv6"),
		refusedAs("the swarm's", "Attachable", "Ingress", "ConfigOnly", "ConfigFrom"),
		refusedLists("the network driver's options", "Options"))

	networkConnect = decided("network.ConnectRequest", reflect.TypeFor[network.ConnectRequest](),
		checkedBy("connect (one of its containers)", "Container"),
		holding(checkedBy("connect, endpoint", "EndpointConfig"), endpointOwn, endpointShared))

	networkDisconnect = decided("network.DisconnectRequest", reflect.TypeFor[network.DisconnectRequest](),
		checkedBy("disconnect (one of its containers)", "Container"),
		freeAs("whether Docker disconnects a container of its own that's running", "Force"))

	volumeCreate = decided("volume.CreateRequest", reflect.TypeFor[volume.CreateRequest](),
		checkedBy("createVolume (its names)", "Name"),
		checkedBy("createVolume, ownLabels", "Labels"),
		checkedBy("createVolume, plainLocal", "Driver"),
		refusedLists("with them, a local volume mounts any host path", "DriverOpts"),
		refusedAs("the swarm's", "ClusterVolumeSpec"))
)

// bodies are the bodies each endpoint's rule decodes, by the classification of what it decodes into.
var bodies = []struct {
	endpoint string
	of       *classification
}{
	{"container.create", createRequest},
	{"container.update", updateConfig},
	{"exec.create", execCreate},
	{"exec.create", dialStdioCreate},
	{"exec.start", execStart},
	{"network.create", networkCreate},
	{"network.connect", networkConnect},
	{"network.disconnect", networkDisconnect},
	{"volume.create", volumeCreate},
}

// unset lists the fields of a struct (embedded ones included) that are set although they're
// refused, by the names Docker's API uses for them, and those of what a free field holds, by their
// path. A field without a decision is refused (TestEveryFieldIsDecidedOn keeps there being none).
func unset(v any, c *classification) []string {
	return unsetIn(reflect.ValueOf(v), c, "")
}

// applying, set by a test, is told of each classification unset applies to a body's struct.
var applying func(*classification)

func unsetIn(value reflect.Value, c *classification, prefix string) []string {
	for value.Kind() == reflect.Pointer {
		if value.IsNil() {
			return nil
		}

		value = value.Elem()
	}

	if applying != nil {
		applying(c)
	}

	var set []string

	for _, f := range exported(value.Type()) {
		v := value.FieldByIndex(f.Index)
		d := c.fields[f.Name]

		switch {
		case d.class == isFree || d.class == isChecked:
			if d.class == isFree && len(d.nested) == 1 {
				each(v, func(e reflect.Value) {
					set = append(set, unsetIn(e, d.nested[0], prefix+apiName(f)+".")...)
				})
			}
		case isSet(d, v):
			set = append(set, prefix+apiName(f))
		}
	}

	return set
}

// exported are a struct type's exported fields, those of an embedded struct in its place. An
// embedded pointer to a struct (CreateRequest's *Config) is a field of its own, holding what it
// points to, whose fields are at the body's top level.
func exported(t reflect.Type) []reflect.StructField {
	var fs []reflect.StructField

	for _, f := range reflect.VisibleFields(t) {
		if !f.IsExported() || f.Anonymous && f.Type.Kind() == reflect.Struct || throughPointer(t, f.Index) {
			continue
		}

		fs = append(fs, f)
	}

	return fs
}

// throughPointer tells whether a promoted field is reached through an embedded pointer.
func throughPointer(t reflect.Type, index []int) bool {
	for _, i := range index[:len(index)-1] {
		f := t.Field(i)
		if f.Type.Kind() == reflect.Pointer {
			return true
		}

		t = f.Type
	}

	return false
}

// each calls fn with every struct a field's value holds: itself, or the elements of a list or map.
func each(v reflect.Value, fn func(reflect.Value)) {
	switch v.Kind() {
	case reflect.Pointer:
		if !v.IsNil() {
			each(v.Elem(), fn)
		}
	case reflect.Struct:
		fn(v)
	case reflect.Slice, reflect.Array:
		for i := range v.Len() {
			each(v.Index(i), fn)
		}
	case reflect.Map:
		for it := v.MapRange(); it.Next(); {
			each(it.Value(), fn)
		}
	}
}

// isSet tells whether a field asks for something. A non-nil pointer does, whatever it points to
// (MemorySwappiness: 0). An empty list or map asks for nothing, unless its decision says that empty
// asks too.
func isSet(d decision, v reflect.Value) bool {
	if v.Kind() == reflect.Map || v.Kind() == reflect.Slice {
		if d.empty == emptyAsks {
			return !v.IsNil()
		}

		return v.Len() > 0
	}

	return !v.IsZero()
}

func apiName(f reflect.StructField) string {
	if name, _, _ := strings.Cut(f.Tag.Get("json"), ","); name != "" && name != "-" {
		return name
	}

	return f.Name
}

// Field is one field of a body the gate reads, and its decision (for apidiff, and the
// differential suite's check that every checked field is refused somewhere).
type Field struct {
	// The endpoint whose body it's in, and the classification it's decided in
	Endpoint, In string
	// Its path in the body, by Docker's API names: [] an element of a list, {} a value of a map
	Path, GoType, Class, Why string
	// For a refused list or map: whether [] asks for something
	EmptyAsks bool
}

// Fields lists the decision on every field of every body the gate reads, sorted.
func Fields() []Field {
	var out []Field

	for _, b := range bodies {
		walkFields(b.of, "", func(c *classification, path string, f reflect.StructField, d decision) {
			out = append(out, Field{Endpoint: b.endpoint, In: c.name, Path: path, GoType: f.Type.String(),
				Class: d.class.String(), Why: d.why, EmptyAsks: d.empty == emptyAsks})
		})
	}

	slices.SortFunc(out, func(a, b Field) int {
		return strings.Compare(a.Endpoint+" "+a.Path+" "+a.In, b.Endpoint+" "+b.Path+" "+b.In)
	})

	return out
}

// walkFields calls fn for each field of a classification, and of what its free and checked fields
// hold, depth first.
func walkFields(c *classification, prefix string, fn func(*classification, string, reflect.StructField, decision)) {
	for _, f := range exported(c.of) {
		d := c.fields[f.Name]

		// An embedded pointer's fields are at this level
		if f.Anonymous {
			for _, n := range d.nested {
				walkFields(n, prefix, fn)
			}

			continue
		}

		path := prefix + apiName(f)
		fn(c, path, f, d)

		if d.class == isRefused {
			continue
		}

		for _, n := range d.nested {
			walkFields(n, path+holds(f.Type)+".", fn)
		}
	}
}

// holds is how a path steps into what a field of this type holds: [] into a list's element, {} into
// a map's value.
func holds(t reflect.Type) string {
	s := ""

	for {
		switch t.Kind() {
		case reflect.Pointer:
			t = t.Elem()
		case reflect.Slice, reflect.Array:
			s += "[]"
			t = t.Elem()
		case reflect.Map:
			s += "{}"
			t = t.Elem()
		default:
			return s
		}
	}
}
