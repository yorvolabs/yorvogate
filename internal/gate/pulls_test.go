package gate

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// Each of Docker's ways of naming a registry, by the rule of the endpoint that reads it.
func TestTheRegistryARequestReaches(t *testing.T) {
	for ref, want := range map[string]string{
		"alpine":                      "docker.io",
		"alpine:3.22":                 "docker.io",
		"library/alpine":              "docker.io",
		"quire-sites/jane/web":        "docker.io",
		"docker.io/library/alpine":    "docker.io",
		"index.docker.io/x/y":         "index.docker.io",
		"registry-1.docker.io/x/y":    "registry-1.docker.io",
		"ghcr.io/x":                   "ghcr.io",
		"localhost/x":                 "localhost",
		"localhost:5000/x":            "localhost:5000",
		"Upper/x":                     "Upper",
		"10.0.0.5:5000/x":             "10.0.0.5:5000",
		"127.0.0.1/x":                 "127.0.0.1",
		"[::1]:5000/x":                "[::1]:5000",
		"host:5000/x":                 "host:5000",
		"localhost:5000":              "docker.io",
		"alpine@sha256:" + hex64("1"): "docker.io",
	} {
		if got := ReferenceRegistry(ref); got != want {
			t.Errorf("a reference %s: %s, want %s", ref, got, want)
		}
	}

	for term, want := range map[string]string{
		"alpine":           "docker.io",
		"Upper/x":          "docker.io",
		"jane/web":         "docker.io",
		"ghcr.io/x":        "ghcr.io",
		"localhost/x":      "localhost",
		"host:5000/x":      "host:5000",
		"10.0.0.5:5000/x":  "10.0.0.5:5000",
		"":                 "docker.io",
		"localhost":        "docker.io",
		"Localhost/x":      "docker.io",
		"registry.local/x": "registry.local",
	} {
		if got := searchRegistry(term); got != want {
			t.Errorf("a search %q: %s, want %s", term, got, want)
		}
	}
}

func hex64(digit string) string { return strings.Repeat(digit, 64) }

func TestARegistryOfTheListenersOnly(t *testing.T) {
	d := startDocker(t)
	sites, registries := gate(t, d, "sites"), gate(t, d, "registries")

	pull := func(ref string) string { return "/v1.56/images/create?fromImage=" + url.QueryEscape(ref) + "&tag=1" }
	search := func(term string) string { return "/v1.56/images/search?term=" + url.QueryEscape(term) }

	for _, c := range []struct {
		server  string
		path    string
		allowed bool
	}{
		// Docker Hub, by default, under each of its names
		{"sites", pull("alpine"), true},
		{"sites", pull("docker.io/library/alpine"), true},
		{"sites", pull("index.docker.io/library/alpine"), true},
		{"sites", pull("registry-1.docker.io/library/alpine"), true},
		{"sites", search("alpine"), true},
		// By the search's rule, a first part in uppercase is a name on Docker Hub
		{"sites", search("Upper/x"), true},
		{"sites", "/v1.56/distribution/alpine:3.22/json", true},
		// Anything else, private addresses and the metadata address included
		{"sites", pull("ghcr.io/x/y"), false},
		{"sites", pull("10.0.0.5:5000/x"), false},
		{"sites", pull("localhost/x"), false},
		{"sites", pull("localhost:5000/x"), false},
		{"sites", pull("127.0.0.1/x"), false},
		{"sites", pull("[::1]:5000/x"), false},
		{"sites", pull("169.254.169.254/x"), false},
		{"sites", pull("Upper/x"), false},
		{"sites", search("ghcr.io/x"), false},
		{"sites", search("localhost:5000/x"), false},
		{"sites", "/v1.56/distribution/ghcr.io/x/y/json", false},
		{"sites", "/v1.56/distribution/localhost:5000/x/json", false},
		// A listener's own list: hosts in any case, exactly, with their ports; Docker Hub under
		// any of its names
		{"registries", pull("alpine"), true},
		{"registries", pull("ghcr.io/x/y"), true},
		{"registries", pull("GHCR.IO/x/y"), true},
		{"registries", pull("registry.local:5000/x"), true},
		{"registries", pull("10.0.0.5:5000/x"), true},
		{"registries", pull("[::1]:5000/x"), true},
		{"registries", pull("localhost/x"), true},
		{"registries", search("ghcr.io/x"), true},
		{"registries", "/v1.56/distribution/ghcr.io/x/y/json", true},
		{"registries", pull("registry.local/x"), false},
		{"registries", pull("ghcr.io:443/x"), false},
		{"registries", pull("localhost:5000/x"), false},
		{"registries", pull("10.0.0.5/x"), false},
		{"registries", pull("Upper/x"), false},
		{"registries", search("registry.local/x"), false},
	} {
		server := sites
		if c.server == "registries" {
			server = registries
		}

		lookups, forwarded := d.lookupCount(), d.count()
		method := "POST"
		if !strings.Contains(c.path, "/create?") {
			method = "GET"
		}

		status, answer := send(t, server, method, c.path, "", asJane)

		switch {
		case c.allowed && status != http.StatusOK:
			t.Errorf("%s %s: %d %s", c.server, c.path, status, answer)
		case !c.allowed && (status != http.StatusForbidden || !strings.Contains(message(t, answer), "isn't one this listener's scopes may pull from")):
			t.Errorf("%s %s: %d %s", c.server, c.path, status, answer)
		case !c.allowed && (d.lookupCount() != lookups || d.count() != forwarded):
			t.Errorf("%s %s: Docker was asked", c.server, c.path)
		}
	}

	// A refusal names the registry and the listener's list.
	_, answer := send(t, registries, "POST", pull("registry.local/x"), "", asJane)
	if want := "yorvogate: image.create: the registry registry.local isn't one this listener's scopes may pull from (index.docker.io, GHCR.io, registry.local:5000, 10.0.0.5:5000, [::1]:5000, localhost)"; message(t, answer) != want {
		t.Errorf("the refusal: %s", answer)
	}

	_, answer = send(t, sites, "GET", search("ghcr.io/x"), "", asJane)
	if want := "yorvogate: image.search: the registry ghcr.io isn't one this listener's scopes may pull from (docker.io)"; message(t, answer) != want {
		t.Errorf("the refusal: %s", answer)
	}
}

func TestAPullsPlatform(t *testing.T) {
	d := startDocker(t)
	sites, registries := gate(t, d, "sites"), gate(t, d, "registries")
	pull := func(platform string) string {
		return "/v1.56/images/create?fromImage=alpine&tag=3.22&platform=" + url.QueryEscape(platform)
	}

	for _, c := range []struct {
		server, platform string
		status           int
		refusal          string
	}{
		// The host's own (Docker's version says linux/amd64), however containerd writes it
		{"sites", "", http.StatusOK, ""},
		{"sites", "linux/amd64", http.StatusOK, ""},
		{"sites", "linux/x86_64", http.StatusOK, ""},
		{"sites", "linux/x86-64", http.StatusOK, ""},
		{"sites", "linux/amd64/v1", http.StatusOK, ""},
		// Another, unless it's listed
		{"sites", "linux/arm64", http.StatusForbidden, "image.create: the platform linux/arm64 isn't the host's (linux/amd64), nor one this listener's scopes may pull"},
		{"sites", "linux/amd64/v3", http.StatusForbidden, "isn't the host's (linux/amd64)"},
		{"sites", "linux/386", http.StatusForbidden, "isn't the host's"},
		{"sites", "windows/amd64", http.StatusForbidden, "isn't the host's"},
		{"registries", "linux/arm64", http.StatusOK, ""},
		{"registries", "linux/aarch64", http.StatusOK, ""},
		{"registries", "linux/arm64/v8", http.StatusOK, ""},
		{"registries", "linux/armhf", http.StatusOK, ""},
		{"registries", "linux/arm", http.StatusOK, ""},
		{"registries", "linux/arm/7", http.StatusOK, ""},
		{"registries", "linux/arm/v6", http.StatusForbidden, "isn't the host's"},
		{"registries", "linux/armel", http.StatusForbidden, "isn't the host's"},
		{"registries", "linux/arm64/v9", http.StatusForbidden, "isn't the host's"},
		// What isn't a platform as containerd writes one
		{"sites", "LINUX/AMD64", http.StatusBadRequest, `image.create: "LINUX/AMD64" isn't a platform (lowercase os/arch or os/arch/variant)`},
		{"sites", "Linux/amd64", http.StatusBadRequest, "isn't a platform"},
		{"sites", "linux", http.StatusBadRequest, "isn't a platform (os/arch or os/arch/variant)"},
		{"sites", "amd64", http.StatusBadRequest, "isn't a platform"},
		{"sites", "linux/amd64/v1/x", http.StatusBadRequest, "isn't a platform"},
		{"sites", "linux//amd64", http.StatusBadRequest, "isn't a platform"},
		{"sites", "windows(10.0.17763)/amd64", http.StatusBadRequest, "isn't a platform"},
	} {
		server := sites
		if c.server == "registries" {
			server = registries
		}

		forwarded := d.count()
		status, answer := send(t, server, "POST", pull(c.platform), "", asJane)

		if status != c.status || (c.refusal != "" && !strings.Contains(message(t, answer), c.refusal)) {
			t.Errorf("%s %q: %d %s", c.server, c.platform, status, answer)
		}

		if c.status != http.StatusOK && d.count() != forwarded {
			t.Errorf("%s %q: forwarded", c.server, c.platform)
		}
	}
}

// On an arm64 host, its own platform is arm64's, in each of the ways containerd writes it.
func TestAPullsPlatformOnAnotherHost(t *testing.T) {
	d := startDocker(t)
	d.mu.Lock()
	d.arch = "arm64"
	d.mu.Unlock()
	server := gate(t, d, "sites")

	for platform, status := range map[string]int{
		"linux/arm64":    http.StatusOK,
		"linux/arm64/v8": http.StatusOK,
		"linux/aarch64":  http.StatusOK,
		"linux/amd64":    http.StatusForbidden,
	} {
		if got, answer := send(t, server, "POST", "/v1.56/images/create?fromImage=alpine&platform="+url.QueryEscape(platform), "", asJane); got != status {
			t.Errorf("%s: %d %s", platform, got, answer)
		}
	}
}

// Without Docker's own platform, a pull that names one is refused, saying why; one that names none
// isn't. The platform is read again when it couldn't be.
func TestAPullsPlatformWithoutDockers(t *testing.T) {
	d := startDocker(t)
	d.mu.Lock()
	d.noVersion = true
	d.mu.Unlock()
	server := gate(t, d, "sites")

	status, answer := send(t, server, "POST", "/v1.56/images/create?fromImage=alpine&platform=linux/amd64", "", asJane)
	if status != http.StatusServiceUnavailable || !strings.Contains(message(t, answer), "image.create: the platform linux/amd64 can't be checked: Docker's own platform couldn't be read") {
		t.Errorf("without Docker's platform: %d %s", status, answer)
	}

	if status, answer := send(t, server, "POST", "/v1.56/images/create?fromImage=alpine", "", asJane); status != http.StatusOK {
		t.Errorf("without a platform: %d %s", status, answer)
	}

	d.mu.Lock()
	d.noVersion = false
	d.mu.Unlock()

	if status, answer := send(t, server, "POST", "/v1.56/images/create?fromImage=alpine&platform=linux/amd64", "", asJane); status != http.StatusOK {
		t.Errorf("once Docker answers: %d %s", status, answer)
	}

	// Read once it's read well: Docker isn't asked again.
	lookups := d.lookupCount()
	if status, _ := send(t, server, "POST", "/v1.56/images/create?fromImage=alpine&platform=linux/amd64", "", asJane); status != http.StatusOK || d.lookupCount() != lookups {
		t.Errorf("Docker's platform was read again (%d lookups more)", d.lookupCount()-lookups)
	}
}

// A trusted listener's pull is Docker's to decide: any registry, any platform, as it was asked.
func TestATrustedPullReachesDockerAsAsked(t *testing.T) {
	d := startDocker(t)
	server := gate(t, d, "images")
	lookups := d.lookupCount()

	status, answer := send(t, server, "POST", "/v1.56/images/create?fromImage=localhost:5000/x&tag=1&platform=linux/arm64", "", nil)
	if status != http.StatusOK {
		t.Fatalf("%d %s", status, answer)
	}

	if got := d.last(); got.path != "/v1.56/images/create" || got.query != "fromImage=localhost:5000/x&tag=1&platform=linux/arm64" {
		t.Errorf("Docker got %s ?%s", got.path, got.query)
	}

	if d.lookupCount() != lookups {
		t.Errorf("Docker was asked %d times by the gate", d.lookupCount()-lookups)
	}
}
