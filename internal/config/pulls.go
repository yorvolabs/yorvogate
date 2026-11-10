package config

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// DockerHub is the registry a scoped listener's scopes may pull from when its pulls list none.
const DockerHub = "docker.io"

// Pulls (scoped) is what a scope's pulls may reach: the registries the daemon may fetch from for it,
// and the platforms beyond the host's own. A registry listed is trusted with every scope's content:
// on Docker's containerd store, an image pulled is made of the blobs its manifest names, and blobs
// Docker already has aren't fetched again.
type Pulls struct {
	// Registries, each a host with an optional port, exactly ("ghcr.io", "registry.local:5000");
	// Docker Hub alone when none are listed.
	Registries []string `yaml:"registries"`
	// Platforms a pull may name besides the host's own, as containerd writes them ("linux/arm64").
	Platforms []string `yaml:"platforms"`
}

// A registry's host: a name, an IPv4 address or a bracketed IPv6 one, and an optional port.
var registryHost = regexp.MustCompile(`^(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*)(:[0-9]{1,5})?$`)

func (p *Pulls) check() error {
	for _, r := range p.Registries {
		if !registryHost.MatchString(r) {
			return fmt.Errorf("registries: %q must be a registry's host, with a port if it has one (no scheme, path or *)", r)
		}
	}

	for _, pl := range p.Platforms {
		canonical, err := Platform(pl)
		if err != nil {
			return fmt.Errorf("platforms: %w", err)
		}

		if canonical != pl {
			return fmt.Errorf("platforms: %q is written %q", pl, canonical)
		}
	}

	return nil
}

func (p *Pulls) empty() bool {
	return len(p.Registries) == 0 && len(p.Platforms) == 0
}

// Allows tells whether a registry is one the listener's scopes may pull from. Hosts compare in any
// case; Docker Hub is "docker.io" under any of its names.
func (p *Pulls) Allows(registry string) bool {
	listed := p.Registries
	if len(listed) == 0 {
		listed = []string{DockerHub}
	}

	return slices.ContainsFunc(listed, func(r string) bool { return Registry(r) == Registry(registry) })
}

// AllowsPlatform tells whether a platform (as Platform writes it) is listed.
func (p *Pulls) AllowsPlatform(platform string) bool {
	return slices.Contains(p.Platforms, platform)
}

// RegistryList is the registries allowed, for a refusal to name.
func (p *Pulls) RegistryList() string {
	if len(p.Registries) == 0 {
		return DockerHub
	}

	return strings.Join(p.Registries, ", ")
}

// Registry is a registry's host as compared: lowercase, and Docker Hub's other names ("index.docker.io",
// the legacy one Docker rewrites, and "registry-1.docker.io", its API's host) as "docker.io".
func Registry(host string) string {
	host = strings.ToLower(host)

	switch host {
	case "index.docker.io", "registry-1.docker.io":
		return DockerHub
	}

	return host
}

var platformPart = regexp.MustCompile(`^[a-z0-9_.-]+$`)

// Platform writes a platform ("os/arch" or "os/arch/variant") as containerd normalises it, by its
// own table (github.com/containerd/platforms, database.go: normalizeOS, normalizeArch), so each of the
// ways Docker reads as one platform is one string. Uppercase isn't read (no client sends it), nor an
// OS alone, an architecture alone or a Windows OS version.
func Platform(p string) (string, error) {
	parts := strings.Split(p, "/")
	if len(parts) < 2 || len(parts) > 3 {
		return "", fmt.Errorf("%q isn't a platform (os/arch or os/arch/variant)", p)
	}

	for _, part := range parts {
		if !platformPart.MatchString(part) {
			return "", fmt.Errorf("%q isn't a platform (lowercase os/arch or os/arch/variant)", p)
		}
	}

	os := parts[0]
	if os == "macos" {
		os = "darwin"
	}

	variant := ""
	if len(parts) == 3 {
		variant = parts[2]
	}

	arch, variant := normaliseArch(parts[1], variant)
	if variant == "" {
		return os + "/" + arch, nil
	}

	return os + "/" + arch + "/" + variant, nil
}

// normaliseArch is containerd's normalizeArch (moby 29.9.2's vendored containerd/platforms), for
// lowercase input.
func normaliseArch(arch, variant string) (string, string) {
	switch arch {
	case "i386":
		arch = "386"
		variant = ""
	case "x86_64", "x86-64", "amd64":
		arch = "amd64"
		if variant == "v1" {
			variant = ""
		}
	case "aarch64", "arm64":
		arch = "arm64"
		switch variant {
		case "8", "v8", "v8.0":
			variant = ""
		case "9", "9.0", "v9.0":
			variant = "v9"
		}
	case "armhf":
		arch = "arm"
		variant = "v7"
	case "armel":
		arch = "arm"
		variant = "v6"
	case "arm":
		switch variant {
		case "", "7":
			variant = "v7"
		case "5", "6", "8":
			variant = "v" + variant
		}
	}

	return arch, variant
}
