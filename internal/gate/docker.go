package gate

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/moby/moby/api/types/container"
)

// Docker is what YorvoGate asks Docker itself, to decide: who owns an object a request names. It
// only reads, and only what the decision needs.
type Docker struct {
	client *http.Client
}

// NewDocker asks Docker through its unix socket.
func NewDocker(socket string) *Docker {
	dialer := &net.Dialer{Timeout: 10 * time.Second}

	return &Docker{client: &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return dialer.DialContext(ctx, "unix", socket)
			},
			MaxIdleConns: 8,
		},
	}}
}

// resolvedID is an object's full ID (a volume's name), as Docker answered it to YorvoGate's own
// lookup: what a checked request names its object by, never a name or prefix the client gave.
type resolvedID string

// object is what YorvoGate needs to know of a container, network or volume: its full ID or name,
// and its labels. A container's whole inspection comes with it (a builder's configuration is
// checked on each use).
type object struct {
	ID     resolvedID
	Name   string
	Labels map[string]string

	// Volumes only: the driver and its options, so a mount can refuse a volume that binds a host
	// path (a local volume with o=bind/device/type) even when its labels mark it as the scope's.
	Driver  string
	Options map[string]string

	inspection *container.InspectResponse
}

// Container looks a container up by ID or name; nil when there's none.
func (d *Docker) Container(ctx context.Context, version, id string) (*object, error) {
	var answer container.InspectResponse

	found, err := d.get(ctx, version, "/containers/"+url.PathEscape(id)+"/json", &answer)
	if !found || err != nil {
		return nil, err
	}

	var labels map[string]string
	if answer.Config != nil {
		labels = answer.Config.Labels
	}

	return &object{ID: resolvedID(answer.ID), Name: strings.TrimPrefix(answer.Name, "/"), Labels: labels, inspection: &answer}, nil
}

// Network looks a network up by ID or name; nil when there's none.
func (d *Docker) Network(ctx context.Context, version, id string) (*object, error) {
	var answer struct {
		ID     string `json:"Id"`
		Name   string
		Labels map[string]string
	}

	found, err := d.get(ctx, version, "/networks/"+url.PathEscape(id), &answer)
	if !found || err != nil {
		return nil, err
	}

	return &object{ID: resolvedID(answer.ID), Name: answer.Name, Labels: answer.Labels}, nil
}

// Volume looks a volume up by name; nil when there's none.
func (d *Docker) Volume(ctx context.Context, version, name string) (*object, error) {
	var answer struct {
		Name    string
		Labels  map[string]string
		Driver  string
		Options map[string]string
	}

	found, err := d.get(ctx, version, "/volumes/"+url.PathEscape(name), &answer)
	if !found || err != nil {
		return nil, err
	}

	return &object{ID: resolvedID(answer.Name), Name: answer.Name, Labels: answer.Labels, Driver: answer.Driver, Options: answer.Options}, nil
}

// image is what YorvoGate needs to know of an image: its ID, its names, and whether the containerd
// store keeps it (there, the ID is the digest a name points to, so "name@ID" names it too).
type image struct {
	ID         resolvedID
	Tags       []string
	Containerd bool
}

// Image looks an image up by name or ID; nil when there's none.
func (d *Docker) Image(ctx context.Context, version, ref string) (*image, error) {
	var answer struct {
		ID       string `json:"Id"`
		RepoTags []string
		// Only the containerd store gives it (and only from API 1.48): the descriptor of what the ID
		// names, whose digest is then the ID.
		Descriptor *struct {
			Digest string `json:"digest"`
		}
	}

	found, err := d.get(ctx, version, "/images/"+url.PathEscape(ref)+"/json", &answer)
	if !found || err != nil {
		return nil, err
	}

	return &image{
		ID:         resolvedID(answer.ID),
		Tags:       answer.RepoTags,
		Containerd: answer.Descriptor != nil && answer.Descriptor.Digest == answer.ID,
	}, nil
}

// execInfo is what YorvoGate needs to know of an exec: its container, and what it runs.
type execInfo struct {
	ContainerID   string
	ProcessConfig *container.ExecProcessConfig
}

// Exec looks an exec up; nil when there's none.
func (d *Docker) Exec(ctx context.Context, version, id string) (*execInfo, error) {
	var answer execInfo

	found, err := d.get(ctx, version, "/exec/"+url.PathEscape(id)+"/json", &answer)
	if !found || err != nil {
		return nil, err
	}

	return &answer, nil
}

func (d *Docker) get(ctx context.Context, version, path string, into any) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker/v"+version+path, nil)
	if err != nil {
		return false, err
	}

	// Docker's logs (and tests) tell YorvoGate's own lookups from what it forwards.
	req.Header.Set("User-Agent", "yorvogate")

	res, err := d.client.Do(req)
	if err != nil {
		return false, fmt.Errorf("asking Docker: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode == http.StatusNotFound {
		return false, nil
	}

	if res.StatusCode != http.StatusOK {
		return false, fmt.Errorf("asking Docker %s: %s", path, res.Status)
	}

	// The decision found an object: its time is remembered (refusals.go)
	foundObject(ctx)

	if err := json.NewDecoder(io.LimitReader(res.Body, 16<<20)).Decode(into); err != nil {
		return false, fmt.Errorf("the answer of Docker to %s: %w", path, err)
	}

	return true, nil
}
