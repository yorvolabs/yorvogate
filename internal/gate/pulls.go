package gate

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/yorvolabs/yorvogate/internal/config"
)

// The registries a scope's requests make the daemon reach, read as the daemon reads them: a pull's
// and a distribution inspection's by a reference's rule, a search's by its own. What isn't one of
// the listener's registries is refused before Docker is asked. Names aren't resolved: the daemon's
// resolver is the one that counts, and a listed host is trusted whatever it resolves to.

// ReferenceRegistry is the registry a reference names, by Docker's reference rule (moby 29.9.2,
// vendor/github.com/distribution/reference/normalize.go, splitDockerDomain): the first part of a
// name with a "/" is a registry when it's "localhost", has a "." or a ":", or isn't all lowercase;
// anything else is on Docker Hub.
func ReferenceRegistry(ref string) string {
	first, _, ok := strings.Cut(ref, "/")
	if !ok {
		return config.DockerHub
	}

	if first == "localhost" || strings.ContainsAny(first, ".:") || strings.ToLower(first) != first {
		return first
	}

	return config.DockerHub
}

// searchRegistry is the registry a search term names, by the search's own rule (moby 29.9.2,
// daemon/pkg/registry/search.go, splitReposSearchTerm): only "localhost", a "." or a ":" make one.
func searchRegistry(term string) string {
	first, _, ok := strings.Cut(term, "/")
	if !ok || (first != "localhost" && !strings.ContainsAny(first, ".:")) {
		return config.DockerHub
	}

	return first
}

// registry checks that a request reaches only a registry of the listener's.
func (s *scoped) registry(registry, what string) error {
	if !s.pulls.Allows(registry) {
		return refuse(http.StatusForbidden, "%s: the registry %s isn't one this listener's scopes may pull from (%s)", what, registry, s.pulls.RegistryList())
	}

	return nil
}

// platform checks a pull's platform: the host's own, or one the listener lists. Without Docker's own
// platform, a pull that names one is refused.
func (s *scoped) platform(asked string) error {
	if asked == "" {
		return nil
	}

	platform, err := config.Platform(asked)
	if err != nil {
		return refuse(http.StatusBadRequest, "image.create: %v", err)
	}

	host, err := s.docker.Platform(s.ctx, s.version)
	if err != nil {
		return refuse(http.StatusServiceUnavailable, "image.create: the platform %s can't be checked: Docker's own platform couldn't be read (%v)", asked, err)
	}

	if platform != host && !s.pulls.AllowsPlatform(platform) {
		return refuse(http.StatusForbidden, "image.create: the platform %s isn't the host's (%s), nor one this listener's scopes may pull", asked, host)
	}

	return nil
}

// search checks a search: on a registry of the listener's.
func (s *scoped) search() error {
	return s.registry(searchRegistry(s.query.Get("term")), "image.search")
}

// hostPlatform is Docker's own platform, read once it's read well.
type hostPlatform struct {
	mu       sync.Mutex
	platform string
}

// Platform is Docker's own platform, as config.Platform writes it, from its version's Os and Arch.
func (d *Docker) Platform(ctx context.Context, version string) (string, error) {
	d.host.mu.Lock()
	defer d.host.mu.Unlock()

	if d.host.platform != "" {
		return d.host.platform, nil
	}

	var answer struct{ Os, Arch string }
	found, err := d.fetch(ctx, version, "/version", &answer)
	if err != nil {
		return "", err
	}

	if !found {
		return "", errors.New("no /version from Docker")
	}

	platform, err := config.Platform(answer.Os + "/" + answer.Arch)
	if err != nil {
		return "", fmt.Errorf("the version answer of Docker: %w", err)
	}

	d.host.platform = platform

	return platform, nil
}
