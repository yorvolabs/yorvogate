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

// object is what YorvoGate needs to know of a container, network or volume: its full ID or name,
// and its labels.
type object struct {
	ID     string
	Name   string
	Labels map[string]string
}

// Container looks a container up by ID or name; nil when there's none.
func (d *Docker) Container(ctx context.Context, version, id string) (*object, error) {
	var answer struct {
		ID     string `json:"Id"`
		Name   string
		Config struct {
			Labels map[string]string
		}
	}

	found, err := d.get(ctx, version, "/containers/"+url.PathEscape(id)+"/json", &answer)
	if !found || err != nil {
		return nil, err
	}

	return &object{ID: answer.ID, Name: strings.TrimPrefix(answer.Name, "/"), Labels: answer.Config.Labels}, nil
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

	return &object{ID: answer.ID, Name: answer.Name, Labels: answer.Labels}, nil
}

// Volume looks a volume up by name; nil when there's none.
func (d *Docker) Volume(ctx context.Context, version, name string) (*object, error) {
	var answer struct {
		Name   string
		Labels map[string]string
	}

	found, err := d.get(ctx, version, "/volumes/"+url.PathEscape(name), &answer)
	if !found || err != nil {
		return nil, err
	}

	return &object{ID: answer.Name, Name: answer.Name, Labels: answer.Labels}, nil
}

// ExecContainer is the ID of the container an exec runs in; "" when there's no such exec.
func (d *Docker) ExecContainer(ctx context.Context, version, id string) (string, error) {
	var answer struct {
		ContainerID string
	}

	found, err := d.get(ctx, version, "/exec/"+url.PathEscape(id)+"/json", &answer)
	if !found || err != nil {
		return "", err
	}

	return answer.ContainerID, nil
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

	if err := json.NewDecoder(io.LimitReader(res.Body, 16<<20)).Decode(into); err != nil {
		return false, fmt.Errorf("the answer of Docker to %s: %w", path, err)
	}

	return true, nil
}
