package differential

import (
	"archive/tar"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/distribution/reference"
	dist "github.com/docker/distribution"
	"github.com/moby/go-archive"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/image"
	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/api/types/registry"
	"github.com/moby/moby/api/types/swarm"
	"github.com/moby/moby/api/types/system"
	"github.com/moby/moby/api/types/volume"
	containerpkg "github.com/moby/moby/v2/daemon/container"
	dnetwork "github.com/moby/moby/v2/daemon/network"
	"github.com/moby/moby/v2/daemon/server"
	"github.com/moby/moby/v2/daemon/server/backend"
	"github.com/moby/moby/v2/daemon/server/imagebackend"
	"github.com/moby/moby/v2/daemon/server/middleware"
	containerrouter "github.com/moby/moby/v2/daemon/server/router/container"
	distributionrouter "github.com/moby/moby/v2/daemon/server/router/distribution"
	imagerouter "github.com/moby/moby/v2/daemon/server/router/image"
	networkrouter "github.com/moby/moby/v2/daemon/server/router/network"
	systemrouter "github.com/moby/moby/v2/daemon/server/router/system"
	volumerouter "github.com/moby/moby/v2/daemon/server/router/volume"
	"github.com/moby/moby/v2/daemon/volume/service/opts"
	"github.com/moby/moby/v2/pkg/sysinfo"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// The Engine version the recorder's code is (go.mod pins moby at its commit), and the API versions
// it serves, as Docker Engine 29.9.2 does.
const (
	engineVersion = "29.9.2"
	apiMax        = "1.56"
	apiMin        = "1.44"
)

// reading is what Docker's server code handed one backend method for a request: what Docker would
// act on. Args are the method's arguments as JSON, so two readings compare field by field.
type reading struct {
	Method string
	Args   []json.RawMessage
}

func (r reading) String() string {
	parts := make([]string, len(r.Args))
	for i, a := range r.Args {
		parts[i] = string(a)
	}

	return r.Method + "(" + strings.Join(parts, ", ") + ")"
}

// lookupKey marks, in a request's context, one of the gate's own lookups (User-Agent "yorvogate"):
// answered from the world, never recorded.
type lookupKey struct{}

// daemon is Docker's API server, as moby's code has it, with backends that record: the readings of
// the requests forwarded to it, and the method a request reached that has no recorder (its name,
// from the panic of the nil interface it's embedded in).
type daemon struct {
	t      testing.TB
	socket string

	// Lookups being served: a backend method that takes no context is one of theirs while there is
	// one (the suite sends one request at a time, and the gate looks up before it forwards)
	lookups atomic.Int32
	// Requests being served: a stream's backend call can come after its answer's headers, so a
	// request's readings are all in only once none is
	inFlight atomic.Int32

	mu       sync.Mutex
	arrived  int // requests the gate forwarded (its own lookups aside)
	readings []reading
	reached  []string // methods without a recorder that a request made Docker call
}

func (d *daemon) record(ctx context.Context, method string, args ...any) {
	if ctx != nil && ctx.Value(lookupKey{}) != nil || ctx == nil && d.lookups.Load() > 0 {
		return
	}

	r := reading{Method: method}

	for _, a := range args {
		b, err := json.Marshal(a)
		if err != nil {
			b, _ = json.Marshal(err.Error())
		}

		r.Args = append(r.Args, b)
	}

	d.mu.Lock()
	d.readings = append(d.readings, r)
	d.mu.Unlock()
}

// take is what was read and reached since the last take.
func (d *daemon) take() ([]reading, []string) {
	d.mu.Lock()
	defer d.mu.Unlock()

	readings, reached := d.readings, d.reached
	d.readings, d.reached, d.arrived = nil, nil, 0

	return readings, reached
}

// idle waits until no request is being served (a second at most: then it says so).
func (d *daemon) idle() {
	for deadline := time.Now().Add(time.Second); d.inFlight.Load() > 0; {
		if time.Now().After(deadline) {
			d.t.Errorf("the recorder is still serving %d requests", d.inFlight.Load())

			return
		}

		time.Sleep(time.Millisecond)
	}
}

// forwarded is how many requests reached it since the last take.
func (d *daemon) forwarded() int {
	d.mu.Lock()
	defer d.mu.Unlock()

	return d.arrived
}

var reachedMethod = regexp.MustCompile(`differential\.\(\*[a-z]+\)\.([A-Z][A-Za-z]+)`)

// startDaemon serves Docker's routers for the endpoints scopes may use, on a unix socket.
func startDaemon(t testing.TB) *daemon {
	t.Helper()

	d := &daemon{t: t, socket: filepath.Join(t.TempDir(), "docker.sock")}

	s := &server.Server{}

	vm, err := middleware.NewVersionMiddleware(engineVersion, apiMax, apiMin)
	if err != nil {
		t.Fatal(err)
	}

	s.UseMiddleware(*vm)

	// The stand-ins first: mux takes the first route that matches (standin_test.go)
	mux := s.CreateMux(context.Background(),
		standInRouter{d: d},
		containerrouter.NewRouter(&containers{d: d}),
		imagerouter.NewRouter(&images{d: d}, nil),
		networkrouter.NewRouter(&networks{d: d}, networkCluster{}),
		volumerouter.NewRouter(&volumes{d: d}, volumeCluster{}),
		systemrouter.NewRouter(&systems{d: d}, systemCluster{}, nil, func() map[string]bool { return nil }),
		distributionrouter.NewRouter(&distribution{d: d}),
	)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d.inFlight.Add(1)
		defer d.inFlight.Add(-1)

		if r.Header.Get("User-Agent") == "yorvogate" {
			r = r.WithContext(context.WithValue(r.Context(), lookupKey{}, true))
			d.lookups.Add(1)
			defer d.lookups.Add(-1)
		} else {
			d.mu.Lock()
			d.arrived++
			d.mu.Unlock()
		}

		defer func() {
			if recover() == nil {
				return
			}

			stack := string(debug.Stack())
			method := "?"

			if m := reachedMethod.FindStringSubmatch(stack); m != nil {
				method = m[1]
			} else {
				// Not a method the recorder lacks: moby's own code failed on what the recorder answered
				d.t.Errorf("Docker's handler failed on the recorder's answer:\n%s", stack)
			}

			if r.Context().Value(lookupKey{}) == nil {
				d.mu.Lock()
				d.reached = append(d.reached, method)
				d.mu.Unlock()
			}

			http.Error(w, `{"message":"the recorder has no `+method+`"}`, http.StatusNotImplemented)
		}()

		mux.ServeHTTP(w, r)
	})

	l, err := net.Listen("unix", d.socket)
	if err != nil {
		t.Fatal(err)
	}

	srv := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })

	return d
}

// The world the gate's lookups are answered from: scope jane's objects and blog's.
const (
	janePHP = "aaaa000000000000000000000000000000000000000000000000000000000001"
	blogPHP = "bbbb000000000000000000000000000000000000000000000000000000000002"
	janeNet = "dddd000000000000000000000000000000000000000000000000000000000004"
	blogNet = "eeee000000000000000000000000000000000000000000000000000000000005"
	janeImg = "sha256:1111000000000000000000000000000000000000000000000000000000000001"
	blogImg = "sha256:2222000000000000000000000000000000000000000000000000000000000002"
	alpine  = "sha256:3333000000000000000000000000000000000000000000000000000000000003"
)

var owner = "com.docker.compose.project"

type object struct {
	id, name string
	labels   map[string]string
}

var (
	worldContainers = []object{
		{janePHP, "jane-php-1", map[string]string{owner: "jane"}},
		{blogPHP, "blog-php-1", map[string]string{owner: "blog"}},
	}
	worldNetworks = []object{
		{janeNet, "jane_default", map[string]string{owner: "jane"}},
		{blogNet, "blog_default", map[string]string{owner: "blog"}},
	}
	worldVolumes = []object{
		{"jane_data", "jane_data", map[string]string{owner: "jane"}},
		{"blog_data", "blog_data", map[string]string{owner: "blog"}},
	}
	worldImages = []struct{ id, tag string }{
		{janeImg, "quire-sites/jane/app:1"},
		{blogImg, "quire-sites/blog/app:1"},
		{alpine, "alpine:3.22"},
	}
	worldExecs = map[string]string{"exec-jane": janePHP, "exec-blog": blogPHP}
)

func find(list []object, idOrName string) *object {
	idOrName = strings.TrimPrefix(idOrName, "/")
	for i, o := range list {
		if o.id == idOrName || o.name == idOrName || len(idOrName) >= 12 && strings.HasPrefix(o.id, idOrName) {
			return &list[i]
		}
	}

	return nil
}

func findImage(ref string) (string, string, bool) {
	for _, img := range worldImages {
		if img.id == ref || img.tag == ref || strings.TrimPrefix(img.id, "sha256:") == ref || !strings.Contains(ref, ":") && img.tag == ref+":latest" {
			return img.id, img.tag, true
		}
	}

	return "", "", false
}

// notFound is Docker's error for an object that isn't there (a 404).
type notFound struct{ what string }

func (e notFound) Error() string { return "No such " + e.what }
func (notFound) NotFound()       {}

// containers is the container router's backend: it records what each call is handed, and answers
// inspections from the world.
type containers struct {
	containerrouter.Backend
	d *daemon
}

func (c *containers) RawSysInfo() (*sysinfo.SysInfo, error) { return &sysinfo.SysInfo{}, nil }

func (c *containers) ContainerInspect(ctx context.Context, name string, options backend.ContainerInspectOptions) (*container.InspectResponse, network.HardwareAddr, error) {
	c.d.record(ctx, "ContainerInspect", name, options)

	o := find(worldContainers, name)
	if o == nil {
		return nil, nil, notFound{"container: " + name}
	}

	// As a daemon answers it: NetworkSettings always there (moby's handler reads it below API 1.45)
	net := strings.TrimSuffix(o.name, "-php-1") + "_default"

	return &container.InspectResponse{
		ID: o.id, Name: "/" + o.name,
		Config:          &container.Config{Labels: o.labels, Image: "alpine:3.22"},
		HostConfig:      &container.HostConfig{NetworkMode: container.NetworkMode(net)},
		State:           &container.State{Status: container.StateRunning, Running: true},
		NetworkSettings: &container.NetworkSettings{Networks: map[string]*network.EndpointSettings{net: {}}},
	}, nil, nil
}

func (c *containers) Containers(ctx context.Context, config *backend.ContainerListOptions) ([]container.Summary, error) {
	c.d.record(ctx, "Containers", config)

	return []container.Summary{}, nil
}

func (c *containers) ContainerCreate(ctx context.Context, config backend.ContainerCreateConfig) (container.CreateResponse, error) {
	c.d.record(ctx, "ContainerCreate", config.Name, config.Config, config.HostConfig, config.NetworkingConfig, config.Platform, config.DefaultReadOnlyNonRecursive)

	return container.CreateResponse{ID: strings.Repeat("c", 64)}, nil
}

func (c *containers) ContainerUpdate(name string, hostConfig *container.HostConfig) (container.UpdateResponse, error) {
	c.d.record(nil, "ContainerUpdate", name, hostConfig)

	return container.UpdateResponse{}, nil
}

func (c *containers) ContainerRename(oldName, newName string) error {
	c.d.record(nil, "ContainerRename", oldName, newName)

	return nil
}

func (c *containers) ContainerTop(name string, psArgs string) (*container.TopResponse, error) {
	c.d.record(nil, "ContainerTop", name, psArgs)

	return &container.TopResponse{}, nil
}

func (c *containers) ContainerLogs(ctx context.Context, name string, config *backend.ContainerLogsOptions) (<-chan *backend.LogMessage, bool, error) {
	c.d.record(ctx, "ContainerLogs", name, config)

	ch := make(chan *backend.LogMessage)
	close(ch)

	return ch, false, nil
}

func (c *containers) ContainerChanges(ctx context.Context, name string) ([]archive.Change, error) {
	c.d.record(ctx, "ContainerChanges", name)

	return nil, nil
}

func (c *containers) ContainerExport(ctx context.Context, name string, _ io.Writer) error {
	c.d.record(ctx, "ContainerExport", name)

	return nil
}

func (c *containers) ContainerStats(ctx context.Context, name string, config *backend.ContainerStatsConfig) error {
	c.d.record(ctx, "ContainerStats", name, config.Stream, config.OneShot)

	return nil
}

func (c *containers) ContainerResize(ctx context.Context, name string, height, width uint32) error {
	c.d.record(ctx, "ContainerResize", name, height, width)

	return nil
}

func (c *containers) ContainerStart(ctx context.Context, name string, checkpoint string, checkpointDir string) error {
	c.d.record(ctx, "ContainerStart", name, checkpoint, checkpointDir)

	return nil
}

func (c *containers) ContainerStop(ctx context.Context, name string, options backend.ContainerStopOptions) error {
	c.d.record(ctx, "ContainerStop", name, options)

	return nil
}

func (c *containers) ContainerRestart(ctx context.Context, name string, options backend.ContainerStopOptions) error {
	c.d.record(ctx, "ContainerRestart", name, options)

	return nil
}

func (c *containers) ContainerKill(ctx context.Context, name string, signal string) error {
	c.d.record(ctx, "ContainerKill", name, signal)

	return nil
}

func (c *containers) ContainerPause(name string) error {
	c.d.record(nil, "ContainerPause", name)

	return nil
}

func (c *containers) ContainerUnpause(name string) error {
	c.d.record(nil, "ContainerUnpause", name)

	return nil
}

func (c *containers) ContainerAttach(name string, config *backend.ContainerAttachConfig) error {
	c.d.record(nil, "ContainerAttach", name, config.UseStdin, config.UseStdout, config.UseStderr, config.Logs, config.Stream, config.DetachKeys)

	return nil
}

func (c *containers) ContainerWait(ctx context.Context, name string, condition container.WaitCondition) (<-chan containerpkg.StateStatus, error) {
	c.d.record(ctx, "ContainerWait", name, condition)

	ch := make(chan containerpkg.StateStatus, 1)
	ch <- containerpkg.StateStatus{}

	return ch, nil
}

func (c *containers) ContainerRm(name string, config *backend.ContainerRmConfig) error {
	c.d.record(nil, "ContainerRm", name, config)

	return nil
}

func (c *containers) ContainerStatPath(name string, path string) (*container.PathStat, error) {
	c.d.record(nil, "ContainerStatPath", name, path)

	return &container.PathStat{Name: filepath.Base(path)}, nil
}

func (c *containers) ContainerArchivePath(name string, path string) (io.ReadCloser, *container.PathStat, error) {
	c.d.record(nil, "ContainerArchivePath", name, path)

	return io.NopCloser(strings.NewReader("")), &container.PathStat{Name: filepath.Base(path)}, nil
}

func (c *containers) ContainerExtractToDir(name, path string, copyUIDGID, allowOverwriteDirWithFile bool, content io.Reader) error {
	n, _ := io.Copy(io.Discard, content)
	c.d.record(nil, "ContainerExtractToDir", name, path, copyUIDGID, allowOverwriteDirWithFile, n)

	return nil
}

func (c *containers) ContainerExecCreate(name string, options *container.ExecCreateRequest) (string, error) {
	c.d.record(nil, "ContainerExecCreate", name, options)

	return "exec-new", nil
}

func (c *containers) ExecExists(name string) (bool, error) {
	_, ok := worldExecs[name]

	return ok, nil
}

func (c *containers) ContainerExecInspect(id string) (*container.ExecInspectResponse, error) {
	c.d.record(nil, "ContainerExecInspect", id)

	cid, ok := worldExecs[id]
	if !ok {
		return nil, notFound{"exec instance: " + id}
	}

	return &container.ExecInspectResponse{ID: id, ContainerID: cid}, nil
}

func (c *containers) ContainerExecStart(ctx context.Context, name string, options backend.ExecStartConfig) error {
	c.d.record(ctx, "ContainerExecStart", name, options.ConsoleSize)

	return nil
}

func (c *containers) ContainerExecResize(ctx context.Context, name string, height, width uint32) error {
	c.d.record(ctx, "ContainerExecResize", name, height, width)

	return nil
}

// images is the image router's backend. GetImage, TagImage, ImportImage, ImagePrune and Search
// have moby internal types in their signatures and can't be written here: a request that reaches
// one is seen by its name (startDaemon's recover), and image.tag is a stand-in's (standin_test.go).
type images struct {
	imagerouter.Backend
	d *daemon
}

func (i *images) ImageInspect(ctx context.Context, refOrID string, options imagebackend.ImageInspectOpts) (*imagebackend.InspectData, error) {
	i.d.record(ctx, "ImageInspect", refOrID, options.Manifests, options.Platform)

	id, tag, ok := findImage(refOrID)
	if !ok {
		return nil, notFound{"image: " + refOrID}
	}

	return &imagebackend.InspectData{InspectResponse: image.InspectResponse{ID: id, RepoTags: []string{tag}}}, nil
}

func (i *images) Images(ctx context.Context, opts imagebackend.ListOptions) ([]image.Summary, error) {
	i.d.record(ctx, "Images", opts)

	return []image.Summary{}, nil
}

func (i *images) ImageHistory(ctx context.Context, imageName string, platform *ocispec.Platform) ([]*image.HistoryResponseItem, error) {
	i.d.record(ctx, "ImageHistory", imageName, platform)

	return nil, nil
}

func (i *images) ImageDelete(ctx context.Context, imageRef string, options imagebackend.RemoveOptions) ([]image.DeleteResponse, error) {
	i.d.record(ctx, "ImageDelete", imageRef, options)

	return nil, nil
}

func (i *images) PullImage(ctx context.Context, ref reference.Named, options imagebackend.PullOptions) error {
	i.d.record(ctx, "PullImage", ref.String(), options.Platforms)

	return nil
}

func (i *images) LoadImage(ctx context.Context, inTar io.ReadCloser, platformList []ocispec.Platform, _ io.Writer, quiet bool) error {
	i.d.record(ctx, "LoadImage", archiveNames(inTar), platformList, quiet)

	return nil
}

// archiveNames is what a docker save archive names: index.json's image names (containerd's
// annotation, as Docker 25 and later load them) and manifest.json's RepoTags.
func archiveNames(r io.Reader) []string {
	var names []string

	tr := tar.NewReader(r)

	for {
		h, err := tr.Next()
		if err != nil {
			break
		}

		switch h.Name {
		case "index.json":
			var index struct {
				Manifests []struct{ Annotations map[string]string }
			}
			if json.NewDecoder(tr).Decode(&index) == nil {
				for _, m := range index.Manifests {
					names = append(names, "index: "+m.Annotations["io.containerd.image.name"])
				}
			}
		case "manifest.json":
			var manifest []struct{ RepoTags []string }
			if json.NewDecoder(tr).Decode(&manifest) == nil {
				for _, m := range manifest {
					for _, tag := range m.RepoTags {
						names = append(names, "manifest: "+tag)
					}
				}
			}
		}
	}

	_, _ = io.Copy(io.Discard, r)
	sort.Strings(names)

	return names
}

func (i *images) ExportImage(ctx context.Context, names []string, platformList []ocispec.Platform, _ io.Writer) error {
	i.d.record(ctx, "ExportImage", names, platformList)

	return nil
}

// filterable is a world network as moby's network filter reads one.
type filterable struct{ object }

func (n filterable) Driver() string                { return "bridge" }
func (n filterable) Name() string                  { return n.name }
func (n filterable) ID() string                    { return n.id }
func (n filterable) Labels() map[string]string     { return n.labels }
func (n filterable) Scope() string                 { return "local" }
func (n filterable) Created() time.Time            { return time.Time{} }
func (n filterable) HasContainerAttachments() bool { return false }
func (n filterable) HasServiceAttachments() bool   { return false }

// networks is the network router's backend.
type networks struct {
	networkrouter.Backend
	d *daemon
}

// admitted is the world's networks a filter admits: what Docker's reading of a list's filters is
// (moby's Filter keeps its arguments to itself; what it matches says what they are).
func admitted(filter dnetwork.Filter) []string {
	var names []string

	for _, o := range worldNetworks {
		if filter.Matches(filterable{o}) {
			names = append(names, o.name)
		}
	}

	return names
}

func (n *networks) GetNetworks(filter dnetwork.Filter, config backend.NetworkListConfig) ([]network.Inspect, error) {
	n.d.record(nil, "GetNetworks", admitted(filter), config)

	var answer []network.Inspect

	for _, o := range worldNetworks {
		if filter.Matches(filterable{o}) {
			answer = append(answer, network.Inspect{Network: network.Network{ID: o.id, Name: o.name, Labels: o.labels}})
		}
	}

	return answer, nil
}

func (n *networks) GetNetworkSummaries(filter dnetwork.Filter) ([]network.Summary, error) {
	n.d.record(nil, "GetNetworkSummaries", admitted(filter))

	return []network.Summary{}, nil
}

func (n *networks) CreateNetwork(ctx context.Context, nc network.CreateRequest) (*network.CreateResponse, error) {
	n.d.record(ctx, "CreateNetwork", nc)

	return &network.CreateResponse{ID: strings.Repeat("n", 64)}, nil
}

func (n *networks) ConnectContainerToNetwork(ctx context.Context, containerName, networkName string, endpointConfig *network.EndpointSettings) error {
	n.d.record(ctx, "ConnectContainerToNetwork", containerName, networkName, endpointConfig)

	return nil
}

func (n *networks) DisconnectContainerFromNetwork(containerName string, networkName string, force bool) error {
	n.d.record(nil, "DisconnectContainerFromNetwork", containerName, networkName, force)

	return nil
}

func (n *networks) DeleteNetwork(networkID string) error {
	n.d.record(nil, "DeleteNetwork", networkID)

	return nil
}

// volumes is the volume router's backend. List and Prune can't be written here (stand-ins).
type volumes struct {
	volumerouter.Backend
	d *daemon
}

func (v *volumes) Get(ctx context.Context, name string, _ ...opts.GetOption) (*volume.Volume, error) {
	v.d.record(ctx, "VolumeGet", name)

	o := find(worldVolumes, name)
	if o == nil {
		return nil, notFound{"volume: " + name}
	}

	return &volume.Volume{Name: o.name, Driver: "local", Labels: o.labels}, nil
}

func (v *volumes) Create(ctx context.Context, name, driverName string, options ...opts.CreateOption) (*volume.Volume, error) {
	var cfg opts.CreateConfig
	for _, o := range options {
		o(&cfg)
	}

	v.d.record(ctx, "VolumeCreate", name, driverName, cfg.Options, cfg.Labels)

	return &volume.Volume{Name: name, Driver: driverName, Labels: cfg.Labels}, nil
}

func (v *volumes) Remove(ctx context.Context, name string, options ...opts.RemoveOption) error {
	var cfg opts.RemoveConfig
	for _, o := range options {
		o(&cfg)
	}

	v.d.record(ctx, "VolumeRemove", name, cfg.PurgeOnError)

	return nil
}

// systems is the system router's backend: Docker's info and version, as Docker 29.9.2 on Ubuntu
// 26.04 says them.
type systems struct {
	systemrouter.Backend
	d *daemon
}

func (s *systems) SystemInfo(ctx context.Context) (*system.Info, error) {
	s.d.record(ctx, "SystemInfo")

	return &system.Info{
		SecurityOptions: []string{"name=apparmor,profile=default", "name=seccomp,profile=builtin", "name=cgroupns"},
		DefaultRuntime:  "runc", LoggingDriver: "json-file", OSType: "linux", Architecture: "x86_64",
	}, nil
}

func (s *systems) SystemVersion(ctx context.Context) (system.VersionResponse, error) {
	s.d.record(ctx, "SystemVersion")

	return system.VersionResponse{Version: engineVersion, APIVersion: apiMax, MinAPIVersion: apiMin, Os: "linux", Arch: "amd64"}, nil
}

// distribution is the distribution router's backend.
type distribution struct {
	distributionrouter.Backend
	d *daemon
}

func (b *distribution) GetRepositories(ctx context.Context, ref reference.Named, _ *registry.AuthConfig) ([]dist.Repository, error) {
	b.d.record(ctx, "GetRepositories", ref.String())

	return nil, notFound{"repository: " + ref.String()}
}

// A node outside any swarm, as each router asks: it has no swarm networks.
type networkCluster struct{ networkrouter.ClusterBackend }

func (networkCluster) GetNetworks(dnetwork.Filter, bool) ([]network.Inspect, error) { return nil, nil }
func (networkCluster) GetNetworkSummaries(dnetwork.Filter) ([]network.Summary, error) {
	return nil, nil
}
func (networkCluster) GetNetwork(name string, _ bool) (network.Inspect, error) {
	return network.Inspect{}, notFound{"network: " + name}
}
func (networkCluster) GetNetworksByName(string) ([]network.Network, error) { return nil, nil }

type volumeCluster struct{ volumerouter.ClusterBackend }

func (volumeCluster) IsManager() bool { return false }

type systemCluster struct{ systemrouter.ClusterBackend }

func (systemCluster) Info(context.Context) swarm.Info { return swarm.Info{} }
