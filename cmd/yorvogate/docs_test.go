package main

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/yorvolabs/yorvogate/internal/config"
	"github.com/yorvolabs/yorvogate/internal/scope"
)

// The documents whose examples must be what YorvoGate accepts
var documents = []string{"../../README.md", "../../docs/configuration.md", "../../docs/threat-model.md", "../../docs/agents.md"}

var fence = regexp.MustCompile("(?ms)^```(yaml|json)\n(.*?)^```")

// examples are the YorvoGate configurations (YAML with listeners) and scope files (JSON with an
// owner) in the documents, and the files in examples/; other blocks (Compose, a client's
// config.json) aren't YorvoGate's.
func examples(t *testing.T) (configs, scopes map[string]string) {
	t.Helper()
	configs, scopes = map[string]string{}, map[string]string{}

	for _, doc := range documents {
		content, err := os.ReadFile(doc)
		if err != nil {
			t.Fatal(err)
		}

		for i, m := range fence.FindAllStringSubmatch(string(content), -1) {
			name := filepath.Base(doc) + "#" + string(rune('a'+i))

			switch {
			case m[1] == "yaml" && regexp.MustCompile(`(?m)^listeners:`).MatchString(m[2]):
				configs[name] = m[2]
			case m[1] == "json" && strings.Contains(m[2], `"owner"`):
				scopes[name] = m[2]
			}
		}
	}

	files, _ := filepath.Glob("../../examples/*.yaml")
	for _, f := range files {
		content, _ := os.ReadFile(f)
		configs[f] = string(content)
	}

	return configs, scopes
}

// A scopes folder the example names that this host doesn't have: about the host, not the example
var missingFolder = regexp.MustCompile(`^warning: the scopes folder \S+ doesn't exist: `)

// Every example configuration and scope file in the docs is one "yorvogate check" passes, and an
// example configuration gets no warning: what's copied from the docs is what YorvoGate recommends.
func TestEveryExampleIsValid(t *testing.T) {
	configs, scopes := examples(t)
	if len(configs) < 3 || len(scopes) < 2 {
		t.Fatalf("found %d configurations and %d scope files: the documents changed shape", len(configs), len(scopes))
	}

	for name, content := range configs {
		path := filepath.Join(t.TempDir(), "yorvogate.yaml")
		_ = os.WriteFile(path, []byte(content), 0o600)

		var out, errs bytes.Buffer
		if code := run([]string{"check", "--config", path}, &out, &errs); code != 0 {
			t.Errorf("%s: %s", name, errs.String())
		}

		for _, line := range strings.Split(out.String(), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "warning:") && !missingFolder.MatchString(line) {
				t.Errorf("%s: %s", name, line)
			}
		}
	}

	// A placeholder for the token's hash ("<the SHA-256 …>") stands for one.
	placeholder := regexp.MustCompile(`"<[^">]*>"`)

	for name, content := range scopes {
		// A scope file without a token serves only scope sockets.
		listeners := []bool{false, true}
		if !strings.Contains(content, `"token_sha256"`) {
			listeners = []bool{true}
		}

		for _, socketBound := range listeners {
			dir := t.TempDir()
			scopesDir := filepath.Join(dir, "scopes")
			_ = os.Mkdir(scopesDir, 0o700)
			_ = os.WriteFile(filepath.Join(scopesDir, "jane.json"), []byte(placeholder.ReplaceAllString(content, `"`+strings.Repeat("a", 64)+`"`)), 0o600)

			listener := "address: unix://" + dir + "/sites.sock"
			if socketBound {
				listener = "scope_sockets: " + dir
			}

			path := filepath.Join(dir, "yorvogate.yaml")
			_ = os.WriteFile(path, []byte("upstream: unix:///var/run/docker.sock\nlisteners:\n  - {name: sites, "+listener+", mode: scoped, scopes: "+scopesDir+"}\n"), 0o600)

			var out, errs bytes.Buffer
			if code := run([]string{"check", "--config", path}, &out, &errs); code != 0 || !strings.Contains(out.String(), "ok, 1 scopes") {
				t.Errorf("%s (socket-bound %v): %s %s", name, socketBound, out.String(), errs.String())
			}
		}
	}
}

// Every key of the configuration and of a scope file is documented in docs/configuration.md.
func TestEveryKeyIsDocumented(t *testing.T) {
	content, err := os.ReadFile("../../docs/configuration.md")
	if err != nil {
		t.Fatal(err)
	}

	doc := string(content)

	for _, k := range keys(reflect.TypeFor[config.Config](), "yaml") {
		if !strings.Contains(doc, k+":") && !strings.Contains(doc, "`"+k+"`") {
			t.Errorf("the configuration's %q isn't in docs/configuration.md", k)
		}
	}

	for _, k := range keys(reflect.TypeFor[scope.Scope](), "json") {
		if !strings.Contains(doc, `"`+k+`"`) && !strings.Contains(doc, "`"+k+"`") {
			t.Errorf("a scope file's %q isn't in docs/configuration.md", k)
		}
	}
}

// keys lists a type's keys in a format (by its struct tags), the keys of its structs included.
func keys(t reflect.Type, format string) []string {
	var all []string

	for t.Kind() == reflect.Pointer || t.Kind() == reflect.Slice || t.Kind() == reflect.Map {
		t = t.Elem()
	}

	if t.Kind() != reflect.Struct {
		return nil
	}

	for i := range t.NumField() {
		f := t.Field(i)
		name, _, _ := strings.Cut(f.Tag.Get(format), ",")

		if !f.IsExported() || name == "-" || name == "" {
			continue
		}

		all = append(all, name)
		all = append(all, keys(f.Type, format)...)
	}

	return all
}

// The AppArmor profile the docs show is the one the release ships (examples/apparmor), its
// comments aside.
func TestTheDocsShowTheShippedAppArmorProfile(t *testing.T) {
	doc, err := os.ReadFile("../../docs/configuration.md")
	if err != nil {
		t.Fatal(err)
	}

	shipped, err := os.ReadFile("../../examples/apparmor/yorvogate-buildkit-rootless")
	if err != nil {
		t.Fatal(err)
	}

	var profile []string

	for _, line := range strings.Split(string(shipped), "\n") {
		if !strings.HasPrefix(line, "#") {
			profile = append(profile, line)
		}
	}

	want := strings.TrimSpace(strings.Join(profile, "\n"))
	shown := regexp.MustCompile("(?ms)^```\n(abi .*?)^```").FindStringSubmatch(string(doc))

	if shown == nil || strings.TrimSpace(shown[1]) != want {
		t.Errorf("docs/configuration.md shows a profile other than examples/apparmor/yorvogate-buildkit-rootless:\n%v\nwant:\n%s", shown, want)
	}
}
