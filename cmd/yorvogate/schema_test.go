package main

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/yorvolabs/yorvogate/internal/config"
	"github.com/yorvolabs/yorvogate/internal/route"
	"github.com/yorvolabs/yorvogate/internal/scope"
	"go.yaml.in/yaml/v3"
)

const (
	configSchema = "../../schemas/yorvogate-config.v1.schema.json"
	scopeSchema  = "../../schemas/yorvogate-scope.v1.schema.json"
	quireConfig  = "../../test/conformance/quire/yorvogate.yaml"
)

func compile(t *testing.T, path string) *jsonschema.Schema {
	t.Helper()
	c := jsonschema.NewCompiler()
	c.AssertFormat()

	s, err := c.Compile(path)
	if err != nil {
		t.Fatal(err)
	}

	return s
}

// asJSON reads YAML or JSON as JSON Schema validates it.
func asJSON(t *testing.T, content string) any {
	t.Helper()

	var v any
	if err := yaml.Unmarshal([]byte(content), &v); err != nil {
		t.Fatal(err)
	}

	encoded, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}

	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}

	return doc
}

// The schemas accept every example in the docs and examples/, and Quire Server's real configuration.
func TestTheSchemasAcceptTheExamples(t *testing.T) {
	configs, scopes := examples(t)
	quire, err := os.ReadFile(quireConfig)
	if err != nil {
		t.Fatal(err)
	}

	configs["Quire Server's"] = string(quire)

	cs, ss := compile(t, configSchema), compile(t, scopeSchema)
	placeholder := regexp.MustCompile(`"<[^">]*>"`)

	for name, content := range configs {
		if err := cs.Validate(asJSON(t, content)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}

	for name, content := range scopes {
		if err := ss.Validate(asJSON(t, placeholder.ReplaceAllString(content, `"`+strings.Repeat("a", 64)+`"`))); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// What YorvoGate refuses, the schemas refuse too (for what a schema can say).
func TestTheSchemasRefuseMistakes(t *testing.T) {
	cs, ss := compile(t, configSchema), compile(t, scopeSchema)
	base := "upstream: unix:///var/run/docker.sock\nlisteners:\n  - {name: sites, address: 'unix:///run/s.sock', mode: scoped, scopes: /etc/s}\n"

	for name, content := range map[string]string{
		"a newer format":              "version: 2\n" + base,
		"an unknown key":              "tls: true\n" + base,
		"upstream over TCP":           strings.Replace(base, "unix:///var/run/docker.sock", "tcp://127.0.0.1:2375", 1),
		"no listeners":                "upstream: unix:///var/run/docker.sock\nlisteners: []\n",
		"an unknown mode":             strings.Replace(base, "mode: scoped", "mode: open", 1),
		"scoped with allow":           strings.Replace(base, "scopes: /etc/s", "scopes: /etc/s, allow: {system: read}", 1),
		"trusted with scopes":         strings.Replace(base, "mode: scoped", "mode: trusted, allow: {system: read}", 1),
		"an unknown group":            strings.Replace(base, "mode: scoped, scopes: /etc/s", "mode: trusted, allow: {everything: read}", 1),
		"an address and socket":       strings.Replace(base, "mode: scoped", "scope_sockets: /run/x, mode: scoped", 1),
		"CAP_ in a capability":        strings.Replace(base, "scopes: /etc/s", "scopes: /etc/s, containers: {capabilities: [CAP_CHOWN]}", 1),
		"all capabilities":            strings.Replace(base, "scopes: /etc/s", "scopes: /etc/s, containers: {capabilities: [ALL]}", 1),
		"too little memory":           strings.Replace(base, "scopes: /etc/s", "scopes: /etc/s, containers: {max_memory: 1024}", 1),
		"a tiny body limit":           "body_limit: 10\n" + base,
		"a version not one":           "api: {max: latest}\n" + base,
		"a registry's scheme":         strings.Replace(base, "scopes: /etc/s", "scopes: /etc/s, pulls: {registries: ['https://ghcr.io']}", 1),
		"a registry's path":           strings.Replace(base, "scopes: /etc/s", "scopes: /etc/s, pulls: {registries: [ghcr.io/x]}", 1),
		"a registry wildcard":         strings.Replace(base, "scopes: /etc/s", "scopes: /etc/s, pulls: {registries: ['*.example.com']}", 1),
		"an OS alone":                 strings.Replace(base, "scopes: /etc/s", "scopes: /etc/s, pulls: {platforms: [linux]}", 1),
		"a platform's case":           strings.Replace(base, "scopes: /etc/s", "scopes: /etc/s, pulls: {platforms: [Linux/arm64]}", 1),
		"an unknown pulls key":        strings.Replace(base, "scopes: /etc/s", "scopes: /etc/s, pulls: {mirrors: [x]}", 1),
		"pulls on trusted":            strings.Replace(base, "mode: scoped, scopes: /etc/s", "mode: trusted, allow: {system: read}, pulls: {registries: [ghcr.io]}", 1),
		"an unknown daemon key":       "daemon: {seccomp: off}\n" + base,
		"a listener's egress":         strings.Replace(base, "scopes: /etc/s", "scopes: /etc/s, containers: {egress: all}", 1),
		"a log option without values": strings.Replace(base, "scopes: /etc/s", "scopes: /etc/s, containers: {log_options: {syslog-address: []}}", 1),
		"a negative log buffer":       strings.Replace(base, "scopes: /etc/s", "scopes: /etc/s, containers: {max_log_buffer: -1}", 1),
		"without_lsm not a bool":      "daemon: {without_lsm: yes please}\n" + base,
	} {
		if cs.Validate(asJSON(t, content)) == nil {
			t.Errorf("config, %s: accepted", name)
		}

		if _, err := config.Parse([]byte(content)); err == nil {
			t.Errorf("config, %s: YorvoGate accepts it", name)
		}
	}

	jane := `{"version": 1, "token_sha256": "` + strings.Repeat("a", 64) + `", "owner": {"label": "com.docker.compose.project", "value": "jane"}, "prefixes": ["jane-"]}`

	for name, content := range map[string]string{
		"a newer format":          strings.Replace(jane, `"version": 1`, `"version": 2`, 1),
		"an unknown key":          strings.Replace(jane, `"prefixes"`, `"privileged": true, "prefixes"`, 1),
		"no prefixes":             strings.Replace(jane, `["jane-"]`, `[]`, 1),
		"a prefix of any name":    strings.Replace(jane, `"jane-"`, `"jane"`, 1),
		"a recreated name prefix": strings.Replace(jane, `"jane-"`, `"0123456789ab_"`, 1),
		"a token in clear":        strings.Replace(jane, strings.Repeat("a", 64), "secret", 1),
		"0.1's containers":        strings.Replace(jane, `"prefixes"`, `"containers": ["x"], "prefixes"`, 1),
		"an image not a prefix":   strings.Replace(jane, `"prefixes"`, `"images": ["quire-sites/jane"], "prefixes"`, 1),
		"an address not one":      strings.Replace(jane, `"prefixes"`, `"networks": {"link": {"addresses": ["10.0.0.0/8"]}}, "prefixes"`, 1),
		"a network key unknown":   strings.Replace(jane, `"prefixes"`, `"networks": {"link": {"mac": "x"}}, "prefixes"`, 1),
		"an egress not none":      strings.Replace(jane, `"prefixes"`, `"egress": "proxy", "prefixes"`, 1),
	} {
		if ss.Validate(asJSON(t, content)) == nil {
			t.Errorf("scope, %s: accepted", name)
		}
	}
}

// properties lists every property name a schema defines, its definitions' included.
func properties(t *testing.T, path string) []string {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	var doc any
	if err := json.Unmarshal(content, &doc); err != nil {
		t.Fatal(err)
	}

	var all []string

	var walk func(any)
	walk = func(v any) {
		switch v := v.(type) {
		case map[string]any:
			if p, ok := v["properties"].(map[string]any); ok {
				for k := range p {
					all = append(all, k)
				}
			}

			for _, x := range v {
				walk(x)
			}
		case []any:
			for _, x := range v {
				walk(x)
			}
		}
	}
	walk(doc)

	return all
}

// Every key YorvoGate reads is in its schema, and the endpoint groups are YorvoGate's: a key added to
// the code without its schema fails here.
func TestTheSchemasHaveEveryKey(t *testing.T) {
	cp, sp := properties(t, configSchema), properties(t, scopeSchema)

	for _, k := range keys(reflect.TypeFor[config.Config](), "yaml") {
		if !slices.Contains(cp, k) {
			t.Errorf("the configuration's %q isn't in its schema", k)
		}
	}

	for _, k := range keys(reflect.TypeFor[scope.Scope](), "json") {
		if !slices.Contains(sp, k) && k != "containers" {
			t.Errorf("a scope file's %q isn't in its schema", k)
		}
	}

	content, _ := os.ReadFile(configSchema)
	for _, g := range route.Groups {
		if !strings.Contains(string(content), `"`+string(g)+`"`) {
			t.Errorf("endpoint group %q isn't in the schema's allow", g)
		}
	}
}

// The schema's alias pattern is YorvoGate's: Compose's "_" accepted, uppercase and a trailing dot not.
func TestTheSchemaReadsAliasesAsYorvoGateDoes(t *testing.T) {
	ss := compile(t, scopeSchema)
	jane := `{"version": 1, "token_sha256": "` + strings.Repeat("a", 64) + `", "owner": {"label": "com.docker.compose.project", "value": "jane"}, "prefixes": ["jane-"], "networks": {"link": {"aliases": [ALIAS]}}}`

	for alias, valid := range map[string]bool{"demo_x-php-1": true, "_x.y_": true, "jane.quire.internal": true, "Demo_x-php-1": false, "web.": false, "-x": false, "a..b": false, "0123456789ab": false, "x.abcdef012345.y": false, "0123456789abc": true} {
		quoted, _ := json.Marshal(alias)
		if (ss.Validate(asJSON(t, strings.Replace(jane, "ALIAS", string(quoted), 1))) == nil) != valid {
			t.Errorf("%q: the schema says %v", alias, !valid)
		}
	}
}
