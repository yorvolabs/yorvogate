// Package route maps a Docker API request to one endpoint of YorvoGate's table, after checking that
// its path is canonical and its API version is one YorvoGate understands. A request that maps to no
// endpoint is refused: a new endpoint of a newer Docker is unknown until it's added here.
package route

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Version is a Docker Engine API version, e.g. 1.56.
type Version struct {
	Major, Minor int
}

// ParseVersion reads "1.56".
func ParseVersion(s string) (Version, error) {
	major, minor, ok := strings.Cut(s, ".")
	if !ok {
		return Version{}, fmt.Errorf("%q isn't an API version (e.g. 1.56)", s)
	}

	ma, err1 := strconv.Atoi(major)
	mi, err2 := strconv.Atoi(minor)
	if err1 != nil || err2 != nil || ma < 1 || mi < 0 || major != strconv.Itoa(ma) || minor != strconv.Itoa(mi) {
		return Version{}, fmt.Errorf("%q isn't an API version (e.g. 1.56)", s)
	}

	return Version{ma, mi}, nil
}

// Less tells whether v is older than o.
func (v Version) Less(o Version) bool {
	return v.Major < o.Major || (v.Major == o.Major && v.Minor < o.Minor)
}

func (v Version) String() string {
	return fmt.Sprintf("%d.%d", v.Major, v.Minor)
}

// Group names a set of endpoints, as a trusted listener allows them.
type Group string

const (
	System       Group = "system"
	Containers   Group = "containers"
	Exec         Group = "exec"
	Images       Group = "images"
	Build        Group = "build"
	Networks     Group = "networks"
	Volumes      Group = "volumes"
	Distribution Group = "distribution"
	Plugins      Group = "plugins"
	Swarm        Group = "swarm"
	Session      Group = "session"
)

// Groups lists every group, for configuration checks.
var Groups = []Group{System, Containers, Exec, Images, Build, Networks, Volumes, Distribution, Plugins, Swarm, Session}

// Endpoint is one operation of the Docker API.
type Endpoint struct {
	Name    string // e.g. "container.create"
	Method  string
	Pattern string // e.g. "/containers/{id}/json"; "{name*}" spans one or more segments (image names)
	Group   Group
	Write   bool // changes something (a trusted listener's "read" doesn't allow it)
	Upgrade bool // a hijacked stream: allowed only as an HTTP upgrade
	Stream  bool // its body is a stream (an archive, an image), never read whole

	segments []string
}

// Request is a request mapped to its endpoint.
type Request struct {
	Version  *Version // nil for an unversioned /_ping
	Path     string   // without the version
	Endpoint *Endpoint
	Params   map[string]string
}

// ErrUnknown is a request no endpoint matches.
var ErrUnknown = errors.New("not an endpoint YorvoGate knows")

// Parse maps a method and an escaped path ("/v1.56/containers/json") to its endpoint, refusing a
// path that isn't canonical or a version outside [lowest, highest].
func Parse(method, escapedPath string, lowest, highest Version) (Request, error) {
	if err := canonical(escapedPath); err != nil {
		return Request{}, err
	}

	path := escapedPath
	var version *Version

	if rest, ok := strings.CutPrefix(path, "/v"); ok {
		number, tail, _ := strings.Cut(rest, "/")
		if v, err := ParseVersion(number); err == nil {
			if v.Less(lowest) || highest.Less(v) {
				return Request{}, fmt.Errorf("API version %s isn't supported (%s to %s)", v, lowest, highest)
			}

			version = &v
			path = "/" + tail
		}
	}

	if version == nil && path != "/_ping" {
		return Request{}, errors.New("the API version is missing from the path (e.g. /v1.56/…)")
	}

	segments := strings.Split(strings.TrimPrefix(path, "/"), "/")

	for i := range table {
		e := &table[i]
		if e.Method != method {
			continue
		}

		if params, ok := match(e.segments, segments); ok {
			return Request{Version: version, Path: path, Endpoint: e, Params: params}, nil
		}
	}

	return Request{}, fmt.Errorf("%s %s: %w", method, path, ErrUnknown)
}

// canonical refuses what different parsers could read differently: dot segments, empty segments, a
// trailing slash, and any percent-encoding (no Docker object name needs it).
func canonical(p string) error {
	switch {
	case !strings.HasPrefix(p, "/") || p == "/":
		return errors.New("the path must start with / and name an endpoint")
	case strings.ContainsAny(p, "%\\"):
		return errors.New("the path may not be percent-encoded or contain a backslash")
	case strings.HasSuffix(p, "/"):
		return errors.New("the path may not end with /")
	}

	for _, s := range strings.Split(p[1:], "/") {
		if s == "" || s == "." || s == ".." {
			return errors.New("the path may not have empty, . or .. segments")
		}

		for _, c := range s {
			if c < 0x21 || c == 0x7f {
				return errors.New("the path may not contain spaces or control characters")
			}
		}
	}

	return nil
}

// match fits path segments to a pattern's; "{x}" takes one segment, "{x*}" one or more (followed only
// by fixed segments).
func match(pattern, path []string) (map[string]string, bool) {
	params := map[string]string{}

	for i, p := range pattern {
		if strings.HasPrefix(p, "{") && strings.HasSuffix(p, "*}") {
			tail := pattern[i+1:]
			n := len(path) - i - len(tail)
			if n < 1 {
				return nil, false
			}

			for j, t := range tail {
				if path[i+n+j] != t {
					return nil, false
				}
			}

			params[p[1:len(p)-2]] = strings.Join(path[i:i+n], "/")

			return params, true
		}

		if i >= len(path) {
			return nil, false
		}

		if strings.HasPrefix(p, "{") {
			params[p[1:len(p)-1]] = path[i]
		} else if p != path[i] {
			return nil, false
		}
	}

	return params, len(pattern) == len(path)
}
