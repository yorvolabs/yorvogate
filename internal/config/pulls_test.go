package config

import (
	"strings"
	"testing"
)

// Every case of containerd's own table (normalizeOS, normalizeArch), and what isn't a platform.
func TestAPlatformAsContainerdWritesIt(t *testing.T) {
	for given, want := range map[string]string{
		"linux/amd64":      "linux/amd64",
		"linux/x86_64":     "linux/amd64",
		"linux/x86-64":     "linux/amd64",
		"linux/amd64/v1":   "linux/amd64",
		"linux/x86_64/v1":  "linux/amd64",
		"linux/amd64/v2":   "linux/amd64/v2",
		"linux/amd64/v3":   "linux/amd64/v3",
		"linux/i386":       "linux/386",
		"linux/i386/x":     "linux/386",
		"linux/386":        "linux/386",
		"linux/arm64":      "linux/arm64",
		"linux/aarch64":    "linux/arm64",
		"linux/arm64/8":    "linux/arm64",
		"linux/arm64/v8":   "linux/arm64",
		"linux/arm64/v8.0": "linux/arm64",
		"linux/aarch64/v8": "linux/arm64",
		"linux/arm64/9":    "linux/arm64/v9",
		"linux/arm64/9.0":  "linux/arm64/v9",
		"linux/arm64/v9.0": "linux/arm64/v9",
		"linux/arm64/v9":   "linux/arm64/v9",
		"linux/arm64/v8.2": "linux/arm64/v8.2",
		"linux/armhf":      "linux/arm/v7",
		"linux/armhf/v6":   "linux/arm/v7",
		"linux/armel":      "linux/arm/v6",
		"linux/armel/v7":   "linux/arm/v6",
		"linux/arm":        "linux/arm/v7",
		"linux/arm/7":      "linux/arm/v7",
		"linux/arm/v7":     "linux/arm/v7",
		"linux/arm/5":      "linux/arm/v5",
		"linux/arm/6":      "linux/arm/v6",
		"linux/arm/8":      "linux/arm/v8",
		"linux/arm/v6":     "linux/arm/v6",
		"linux/riscv64":    "linux/riscv64",
		"linux/s390x":      "linux/s390x",
		"macos/arm64":      "darwin/arm64",
		"windows/amd64":    "windows/amd64",
	} {
		got, err := Platform(given)
		if err != nil || got != want {
			t.Errorf("%s: %q %v, want %s", given, got, err, want)
		}
	}

	for _, wrong := range []string{"", "linux", "amd64", "LINUX/AMD64", "Linux/amd64", "linux/AMD64", "linux/amd64/V1", "linux//amd64", "/amd64", "linux/", "linux/amd64/", "linux/amd64/v1/x", "windows(10.0.17763)/amd64", "linux/amd 64", "linux\\amd64"} {
		if got, err := Platform(wrong); err == nil {
			t.Errorf("%q: %q, want an error", wrong, got)
		}
	}
}

func TestPulls(t *testing.T) {
	scoped := strings.Replace(valid, "mode: scoped", "mode: scoped\n    pulls: {registries: [docker.io, GHCR.io, \"registry.local:5000\", \"10.0.0.5:5000\", \"[::1]:5000\", localhost], platforms: [linux/arm64, linux/arm/v7]}", 1)

	c, err := Parse([]byte(scoped))
	if err != nil {
		t.Fatal(err)
	}

	var p Pulls
	for _, l := range c.Listeners {
		if l.Mode == Scoped {
			p = l.Pulls
		}
	}

	for registry, allowed := range map[string]bool{
		"docker.io": true, "index.docker.io": true, "registry-1.docker.io": true, "DOCKER.IO": true,
		"ghcr.io": true, "registry.local:5000": true, "10.0.0.5:5000": true, "[::1]:5000": true, "localhost": true,
		"registry.local": false, "ghcr.io:443": false, "localhost:5000": false, "10.0.0.5": false, "quay.io": false,
	} {
		if p.Allows(registry) != allowed {
			t.Errorf("%s: allowed %v", registry, !allowed)
		}
	}

	if !p.AllowsPlatform("linux/arm64") || !p.AllowsPlatform("linux/arm/v7") || p.AllowsPlatform("linux/amd64") {
		t.Error("platforms")
	}

	// Docker Hub alone when none are listed, under any of its names
	var none Pulls
	if !none.Allows("docker.io") || !none.Allows("index.docker.io") || !none.Allows("registry-1.docker.io") || none.Allows("ghcr.io") || none.RegistryList() != "docker.io" {
		t.Error("the default")
	}

	if p.RegistryList() != "docker.io, GHCR.io, registry.local:5000, 10.0.0.5:5000, [::1]:5000, localhost" {
		t.Errorf("the list: %s", p.RegistryList())
	}
}

func TestPullsMistakes(t *testing.T) {
	for what, c := range map[string]struct{ pulls, err string }{
		"a scheme":        {"{registries: [\"https://ghcr.io\"]}", `pulls: registries: "https://ghcr.io" must be a registry's host`},
		"a path":          {"{registries: [ghcr.io/x]}", "must be a registry's host"},
		"a wildcard":      {"{registries: [\"*.example.com\"]}", "must be a registry's host"},
		"an empty one":    {"{registries: [\"\"]}", "must be a registry's host"},
		"a port too long": {"{registries: [\"ghcr.io:123456\"]}", "must be a registry's host"},
		"a trailing dot":  {"{registries: [ghcr.io.]}", "must be a registry's host"},
		"not a platform":  {"{platforms: [linux]}", `pulls: platforms: "linux" isn't a platform`},
		"not as written":  {"{platforms: [linux/aarch64]}", `pulls: platforms: "linux/aarch64" is written "linux/arm64"`},
		"in uppercase":    {"{platforms: [Linux/arm64]}", "isn't a platform"},
		"an unknown key":  {"{registry: [ghcr.io]}", "registry"},
	} {
		_, err := Parse([]byte(strings.Replace(valid, "mode: scoped", "mode: scoped\n    pulls: "+c.pulls, 1)))
		if err == nil || !strings.Contains(err.Error(), c.err) {
			t.Errorf("%s: %v", what, err)
		}
	}

	if _, err := Parse([]byte(strings.Replace(valid, "mode: trusted", "mode: trusted\n    pulls: {registries: [ghcr.io]}", 1))); err == nil || !strings.Contains(err.Error(), "pulls: only a scoped listener has them") {
		t.Errorf("pulls on a trusted listener: %v", err)
	}
}
