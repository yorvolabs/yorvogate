// Package config reads YorvoGate's configuration: strict YAML, where an unknown key, a second
// document or an invalid value is an error, never ignored.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/yorvolabs/yorvogate/internal/route"
	"go.yaml.in/yaml/v3"
)

// Highest is the newest Docker API version this build understands (github.com/moby/moby/api's).
var Highest = route.Version{Major: 1, Minor: 56}

// Lowest is the oldest it accepts: what Docker Engine 29 still serves.
var Lowest = route.Version{Major: 1, Minor: 44}

const (
	// Trusted listeners allow endpoint groups by path, as docker-socket-proxy does.
	Trusted = "trusted"
	// Scoped listeners act for one scope per request, and read every body.
	Scoped = "scoped"

	// DefaultBodyLimit is the largest body read whole (a container's configuration is a few KiB).
	DefaultBodyLimit = 1 << 20
)

// Config is the whole configuration.
type Config struct {
	// Upstream is Docker's socket: "unix:///var/run/docker.sock".
	Upstream string `yaml:"upstream"`
	// API is the range of Docker API versions accepted.
	API APIRange `yaml:"api"`
	// BodyLimit is the largest request body read whole, in bytes.
	BodyLimit int64 `yaml:"body_limit"`
	// Listeners are where clients connect.
	Listeners []Listener `yaml:"listeners"`

	lowest, highest route.Version
}

// APIRange is a range of Docker API versions.
type APIRange struct {
	Min string `yaml:"min"`
	Max string `yaml:"max"`
}

// Listener is an address clients connect to, and how it treats them.
type Listener struct {
	Name    string `yaml:"name"`
	Address string `yaml:"address"` // "tcp://10.0.0.2:2375" or "unix:///run/yorvogate/sites.sock"
	Mode    string `yaml:"mode"`    // trusted or scoped
	// Allow (trusted): endpoint group => "read" or "write".
	Allow map[string]string `yaml:"allow"`
	// Scopes (scoped): the folder of scope files, one "<name>.json" per scope.
	Scopes string `yaml:"scopes"`
}

var name = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// Load reads and checks a configuration file.
func Load(path string) (*Config, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return Parse(content)
}

// Parse reads and checks a configuration.
func Parse(content []byte) (*Config, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(content))
	decoder.KnownFields(true)

	var c Config
	if err := decoder.Decode(&c); err != nil {
		return nil, fmt.Errorf("the configuration isn't valid: %w", err)
	}

	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("the configuration must be one YAML document")
	}

	if err := c.check(); err != nil {
		return nil, err
	}

	return &c, nil
}

// Versions is the range of API versions accepted.
func (c *Config) Versions() (route.Version, route.Version) {
	return c.lowest, c.highest
}

// UpstreamSocket is the path of Docker's socket.
func (c *Config) UpstreamSocket() string {
	return strings.TrimPrefix(c.Upstream, "unix://")
}

func (c *Config) check() error {
	socket, ok := strings.CutPrefix(c.Upstream, "unix://")
	if !ok || !filepath.IsAbs(socket) || filepath.Clean(socket) != socket {
		return fmt.Errorf("upstream: %q must be Docker's socket, as unix:///absolute/path", c.Upstream)
	}

	c.lowest, c.highest = Lowest, Highest

	if c.API.Min != "" {
		v, err := route.ParseVersion(c.API.Min)
		if err != nil {
			return fmt.Errorf("api.min: %w", err)
		}

		c.lowest = v
	}

	if c.API.Max != "" {
		v, err := route.ParseVersion(c.API.Max)
		if err != nil {
			return fmt.Errorf("api.max: %w", err)
		}

		c.highest = v
	}

	switch {
	case c.lowest.Less(Lowest):
		return fmt.Errorf("api.min: %s is older than the oldest this build accepts (%s)", c.lowest, Lowest)
	case Highest.Less(c.highest):
		return fmt.Errorf("api.max: %s is newer than this build understands (%s)", c.highest, Highest)
	case c.highest.Less(c.lowest):
		return errors.New("api: min is newer than max")
	}

	if c.BodyLimit == 0 {
		c.BodyLimit = DefaultBodyLimit
	}

	if c.BodyLimit < 4096 || c.BodyLimit > 64<<20 {
		return errors.New("body_limit: between 4096 bytes and 64 MiB")
	}

	if len(c.Listeners) == 0 {
		return errors.New("listeners: at least one")
	}

	names := map[string]bool{}
	addresses := map[string]bool{}

	for i := range c.Listeners {
		l := &c.Listeners[i]
		if err := l.check(); err != nil {
			return fmt.Errorf("listeners[%d]: %w", i, err)
		}

		if names[l.Name] || addresses[l.Address] {
			return fmt.Errorf("listeners[%d]: its name and address must be its own", i)
		}

		names[l.Name], addresses[l.Address] = true, true
	}

	return nil
}

func (l *Listener) check() error {
	if !name.MatchString(l.Name) {
		return fmt.Errorf("name: %q must be lowercase letters, digits and dashes", l.Name)
	}

	if _, err := l.Network(); err != nil {
		return err
	}

	switch l.Mode {
	case Trusted:
		if len(l.Allow) == 0 || l.Scopes != "" {
			return errors.New("a trusted listener has allow (and no scopes)")
		}

		for group, access := range l.Allow {
			if !known(group) {
				return fmt.Errorf("allow: %q isn't an endpoint group (%s)", group, groupList())
			}

			if access != "read" && access != "write" {
				return fmt.Errorf("allow.%s: %q must be read or write", group, access)
			}
		}
	case Scoped:
		if len(l.Allow) != 0 || !filepath.IsAbs(l.Scopes) || filepath.Clean(l.Scopes) != l.Scopes {
			return errors.New("a scoped listener has scopes, an absolute folder (and no allow)")
		}
	default:
		return fmt.Errorf("mode: %q must be trusted or scoped", l.Mode)
	}

	return nil
}

// Network splits the address into Go's network and address ("tcp", "10.0.0.2:2375").
func (l *Listener) Network() ([2]string, error) {
	if path, ok := strings.CutPrefix(l.Address, "unix://"); ok {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return [2]string{}, fmt.Errorf("address: %q must be unix:///absolute/path", l.Address)
		}

		return [2]string{"unix", path}, nil
	}

	if hostPort, ok := strings.CutPrefix(l.Address, "tcp://"); ok {
		if _, _, err := net.SplitHostPort(hostPort); err != nil {
			return [2]string{}, fmt.Errorf("address: %q must be tcp://host:port", l.Address)
		}

		return [2]string{"tcp", hostPort}, nil
	}

	return [2]string{}, fmt.Errorf("address: %q must be tcp://host:port or unix:///path", l.Address)
}

// Allows tells whether a trusted listener allows an endpoint.
func (l *Listener) Allows(e *route.Endpoint) bool {
	access := l.Allow[string(e.Group)]

	return access == "write" || (access == "read" && !e.Write)
}

func known(group string) bool {
	for _, g := range route.Groups {
		if string(g) == group {
			return true
		}
	}

	return false
}

func groupList() string {
	names := make([]string, len(route.Groups))
	for i, g := range route.Groups {
		names[i] = string(g)
	}

	return strings.Join(names, ", ")
}
