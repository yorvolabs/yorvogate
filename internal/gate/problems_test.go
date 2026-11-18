package gate

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/yorvolabs/yorvogate/internal/config"
)

var refusalSchema = func() *jsonschema.Schema {
	s, err := jsonschema.NewCompiler().Compile("../../schemas/yorvogate-refusal.v1.schema.json")
	if err != nil {
		panic(err)
	}

	return s
}()

// What every refusal the package's tests produce is held to, checked as it's answered: it validates;
// the codes that never say where or what's allowed don't; those about a part of the request say
// where; a message's "(allowed: …)" is what allowed says; and nothing of scope zulu (the fixture's,
// which no request names) is in it.
var (
	refusalsMu    sync.Mutex
	refusalFaults []string
	refusalsSeen  int
)

// Codes whose problems never say where, nor what's allowed: an authentication failure says nothing
// of why (threat model point 5), and an object that isn't the scope's is answered as one that
// doesn't exist.
var neverSay = []Code{CodeAuthRejected, CodeNotFound}

// mustSayWhere tells whether a code's problems are about a part of the request, so say which.
func mustSayWhere(c Code) bool {
	s := string(c)

	return c != CodeBuilder && (strings.HasPrefix(s, "policy.") || strings.HasPrefix(s, "body.") || strings.HasPrefix(s, "query.") || strings.HasPrefix(s, "header.") ||
		c == CodeNameNotOwn || c == CodeNameTaken || c == CodeImageNotOwn || c == CodeLabelNotOwn)
}

// mustSayField tells whether a code's problems name the field too (not only the part).
func mustSayField(c Code) bool {
	return c == CodeFieldNotAllowed || strings.HasPrefix(string(c), "query.") || strings.HasPrefix(string(c), "header.")
}

var allowedText = regexp.MustCompile(`\(allowed: ([^)]*)\)`)

func checkRefusal(r *refusal, body []byte) []string {
	var faults []string

	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(body))
	if err == nil {
		err = refusalSchema.Validate(doc)
	}

	if err != nil {
		faults = append(faults, fmt.Sprintf("doesn't validate: %v", err))
	}

	var answer refusalBody
	_ = json.Unmarshal(body, &answer)

	if bytes.Contains(body, []byte("zulu")) {
		faults = append(faults, "names scope zulu's")
	}

	for _, p := range answer.Problems {
		switch {
		case slices.Contains(neverSay, p.Code) && (p.In != "" || p.Field != "" || p.Allowed != nil):
			faults = append(faults, fmt.Sprintf("%s says where or what's allowed", p.Code))
		case mustSayWhere(p.Code) && p.In == "":
			faults = append(faults, fmt.Sprintf("%s (%s) doesn't say where", p.Code, p.Message))
		case mustSayField(p.Code) && p.Field == "":
			faults = append(faults, fmt.Sprintf("%s (%s) doesn't say the field", p.Code, p.Message))
		}

		if m := allowedText.FindStringSubmatch(p.Message); m != nil {
			said := m[1]
			if said == "none" && p.Allowed != nil && p.Allowed.Kind == "unset" {
				continue
			}

			if p.Allowed == nil || p.Allowed.text() != said {
				faults = append(faults, fmt.Sprintf("%s: the message says allowed: %s, allowed is %+v", p.Code, said, p.Allowed))
			}
		}
	}

	if len(r.problems) != len(answer.Problems) {
		faults = append(faults, "its problems aren't all answered")
	}

	return faults
}

func TestMain(m *testing.M) {
	answering = func(r *refusal, body []byte) {
		faults := checkRefusal(r, body)

		refusalsMu.Lock()
		defer refusalsMu.Unlock()

		refusalsSeen++
		for _, f := range faults {
			refusalFaults = append(refusalFaults, fmt.Sprintf("%s: %s", f, body))
		}
	}

	code := m.Run()

	if len(refusalFaults) > 0 {
		fmt.Fprintf(os.Stderr, "%d of the %d refusals answered break the refusal format's rules:\n", len(refusalFaults), refusalsSeen)

		for _, f := range refusalFaults[:min(len(refusalFaults), 40)] {
			fmt.Fprintln(os.Stderr, "  "+f)
		}

		code = 1
	} else if refusalsSeen < 300 && code == 0 && !testing.Short() && runsAll() {
		fmt.Fprintf(os.Stderr, "only %d refusals answered: TestMain's check no longer sees them\n", refusalsSeen)

		code = 1
	}

	os.Exit(code)
}

// runsAll tells whether the whole package's tests ran (no -run).
func runsAll() bool {
	for _, a := range os.Args {
		if strings.HasPrefix(a, "-test.run") {
			return false
		}
	}

	return true
}

// problemsOf reads a refusal's body.
func problemsOf(t *testing.T, answer string) refusalBody {
	t.Helper()

	var r refusalBody
	if err := json.Unmarshal([]byte(answer), &r); err != nil || r.Version != RefusalVersion {
		t.Fatalf("not a refusal: %s", answer)
	}

	return r
}

// The problem of a refusal at a field, or nil.
func (r refusalBody) at(in place, field string) *problemBody {
	for i, p := range r.Problems {
		if p.In == in && p.Field == field {
			return &r.Problems[i]
		}
	}

	return nil
}

// Each refusal points at the element of the request it's about (list indexes, map keys), with what
// the policy would accept there.
func TestRefusalsSayWhereAndWhatIsAllowed(t *testing.T) {
	d := startDocker(t)
	sites := gate(t, d, "sites")
	egress := gate(t, d, "egress")
	registries := gate(t, d, "registries")
	logs := gate(t, d, "logs")

	create := "/v1.56/containers/create?name=jane-php-1"
	mounts := []any{map[string]any{"Type": "volume", "Source": "jane_data", "Target": "/a"}, map[string]any{"Type": "bind", "Source": "/etc", "Target": "/b"}}

	cases := []struct {
		name         string
		server       *httptest.Server
		method, path string
		body         any
		code         Code
		in           place
		field        string
		kind         string
		values       []any
	}{
		{"a capability, the second", sites, "POST", create, set(compose(), "HostConfig.CapAdd", []any{"CHOWN", "SYS_ADMIN"}), CodeCapability, inBody, "HostConfig.CapAdd[1]", "one-of", []any{"NET_BIND_SERVICE", "CHOWN"}},
		{"a refused field", sites, "POST", create, set(compose(), "HostConfig.Sysctls", map[string]any{"net.ipv4.ip_forward": "1"}), CodeFieldNotAllowed, inBody, "HostConfig.Sysctls", "unset", nil},
		{"privileged", sites, "POST", create, set(compose(), "HostConfig.Privileged", true), CodeFieldNotAllowed, inBody, "HostConfig.Privileged", "unset", nil},
		{"a device", sites, "POST", create, set(compose(), "HostConfig.Devices", []any{map[string]any{"PathOnHost": "/dev/kmsg"}}), CodeFieldNotAllowed, inBody, "HostConfig.Devices", "unset", nil},
		{"published ports", sites, "POST", create, set(compose(), "HostConfig.PublishAllPorts", true), CodeFieldNotAllowed, inBody, "HostConfig.PublishAllPorts", "unset", nil},
		{"the host's PIDs", sites, "POST", create, set(compose(), "HostConfig.PidMode", "host"), CodeNamespace, inBody, "HostConfig.PidMode", "unset", nil},
		{"the host's users", sites, "POST", create, set(compose(), "HostConfig.UsernsMode", "host"), CodeNamespace, inBody, "HostConfig.UsernsMode", "unset", nil},
		{"another's IPC", sites, "POST", create, set(compose(), "HostConfig.IpcMode", "container:blog-php-1"), CodeObjectNotOwn, inBody, "HostConfig.IpcMode", "own", nil},
		{"cgroups", sites, "POST", create, set(compose(), "HostConfig.CgroupnsMode", "weird"), CodeNamespace, inBody, "HostConfig.CgroupnsMode", "one-of", []any{"private"}},
		{"no CapDrop", sites, "POST", create, set(compose(), "HostConfig.CapDrop", nil), CodeCapability, inBody, "HostConfig.CapDrop", "required", []any{[]any{"ALL"}}},
		{"a security option, the second", sites, "POST", create, set(compose(), "HostConfig.SecurityOpt", []any{"no-new-privileges:true", "seccomp=unconfined"}), CodeSecurity, inBody, "HostConfig.SecurityOpt[1]", "one-of", []any{"no-new-privileges"}},
		{"no no-new-privileges", sites, "POST", create, set(compose(), "HostConfig.SecurityOpt", []any{}), CodeSecurity, inBody, "HostConfig.SecurityOpt", "required", []any{[]any{"no-new-privileges"}}},
		{"a runtime", logs, "POST", create, set(compose(), "HostConfig.Runtime", "kata"), CodeRuntime, inBody, "HostConfig.Runtime", "one-of", []any{"runsc"}},
		{"no runtime allowed", sites, "POST", create, set(compose(), "HostConfig.Runtime", "kata"), CodeRuntime, inBody, "HostConfig.Runtime", "unset", nil},
		{"a log driver", sites, "POST", create, set(compose(), "HostConfig.LogConfig.Type", "syslog"), CodeLogging, inBody, "HostConfig.LogConfig.Type", "one-of", []any{"json-file", "local", "none"}},
		{"a log option, by its key", logs, "POST", create, set(set(compose(), "HostConfig.LogConfig.Type", "syslog"), "HostConfig.LogConfig.Config", map[string]any{"syslog-address": "udp://1.2.3.4:514"}), CodeLogging, inBody, `HostConfig.LogConfig.Config["syslog-address"]`, "one-of", []any{"udp://10.0.0.9:514"}},
		{"the log buffer", logs, "POST", create, set(compose(), "HostConfig.LogConfig.Config", map[string]any{"mode": "non-blocking", "max-buffer-size": "1g"}), CodeLogging, inBody, `HostConfig.LogConfig.Config["max-buffer-size"]`, "at-most", nil},
		{"memory above", sites, "POST", create, set(compose(), "HostConfig.Memory", 4294967296), CodeLimit, inBody, "HostConfig.Memory", "required", nil},
		{"unlimited swap", sites, "POST", create, set(compose(), "HostConfig.MemorySwap", -1), CodeLimit, inBody, "HostConfig.MemorySwap", "unset", nil},
		{"swap out of range", sites, "POST", create, set(compose(), "HostConfig.MemorySwap", 1), CodeLimit, inBody, "HostConfig.MemorySwap", "between", nil},
		{"no process limit", sites, "POST", create, set(compose(), "HostConfig.PidsLimit", nil), CodeLimit, inBody, "HostConfig.PidsLimit", "required", nil},
		{"a ulimit, the second", sites, "POST", create, set(compose(), "HostConfig.Ulimits", []any{map[string]any{"Name": "nofile", "Soft": 1, "Hard": 1}, map[string]any{"Name": "memlock", "Soft": 1, "Hard": 1}}), CodeLimit, inBody, "HostConfig.Ulimits[1].Name", "one-of", []any{"nofile"}},
		{"OomScoreAdj", sites, "POST", create, set(compose(), "HostConfig.OomScoreAdj", -500), CodeLimit, inBody, "HostConfig.OomScoreAdj", "between", nil},
		{"a bind mount, the second", sites, "POST", create, set(compose(), "HostConfig.Mounts", mounts), CodeMount, inBody, "HostConfig.Mounts[1].Type", "one-of", []any{"volume", "tmpfs"}},
		{"a mount's refused field", sites, "POST", create, set(compose(), "HostConfig.Mounts", []any{map[string]any{"Type": "volume", "Source": "jane_data", "Target": "/x", "BindOptions": map[string]any{"Propagation": "rshared"}}}), CodeFieldNotAllowed, inBody, "HostConfig.Mounts[0].BindOptions", "unset", nil},
		{"a subpath out", sites, "POST", create, set(compose(), "HostConfig.Mounts", []any{map[string]any{"Type": "volume", "Source": "jane_data", "Target": "/x", "VolumeOptions": map[string]any{"Subpath": "../x"}}}), CodeMount, inBody, "HostConfig.Mounts[0].VolumeOptions.Subpath", "under", []any{"."}},
		{"another's volume", sites, "POST", create, set(compose(), "HostConfig.Mounts", []any{map[string]any{"Type": "volume", "Source": "jane_stolen", "Target": "/x"}}), CodeMount, inBody, "HostConfig.Mounts[0].Source", "own", nil},
		{"a host bind", sites, "POST", create, set(compose(), "HostConfig.Binds", []any{"jane_data:/a", "/etc:/b"}), CodeHostAccess, inBody, "HostConfig.Binds[1]", "own", nil},
		{"another's volumes", sites, "POST", create, set(compose(), "HostConfig.VolumesFrom", []any{"jane-php-1", "blog-php-1:ro"}), CodeObjectNotOwn, inBody, "HostConfig.VolumesFrom[1]", "own", nil},
		{"the default bridge", sites, "POST", create, set(compose(), "HostConfig.NetworkMode", "bridge"), CodeNetwork, inBody, "HostConfig.NetworkMode", "own", []any{"quire-egress", "quire-link-jane"}},
		{"another's network", sites, "POST", create, set(compose(), "NetworkingConfig.EndpointsConfig.blog_default", map[string]any{}), CodeObjectNotOwn, inBody, `NetworkingConfig.EndpointsConfig["blog_default"]`, "own", []any{"quire-egress", "quire-link-jane"}},
		{"an alias not its own", sites, "POST", create, set(compose(), "NetworkingConfig.EndpointsConfig.quire-link-jane", map[string]any{"Aliases": []any{"jane.example.quire.internal", "blog.example"}}), CodeNetwork, inBody, `NetworkingConfig.EndpointsConfig["quire-link-jane"].Aliases[1]`, "one-of", []any{"jane.example.quire.internal"}},
		{"an address not its own", sites, "POST", create, set(compose(), "NetworkingConfig.EndpointsConfig.quire-link-jane", map[string]any{"IPAMConfig": map[string]any{"IPv4Address": "10.213.0.9"}}), CodeNetwork, inBody, `NetworkingConfig.EndpointsConfig["quire-link-jane"].IPAMConfig.IPv4Address`, "one-of", []any{"10.213.0.4"}},
		{"a network with a way out", egress, "POST", create, set(compose(), "NetworkingConfig.EndpointsConfig", map[string]any{"jane_internal": map[string]any{}, "quire-link-jane": map[string]any{}}), CodeEgress, inBody, `NetworkingConfig.EndpointsConfig["quire-link-jane"]`, "", nil},
		{"no owner label", sites, "POST", create, set(compose(), "Labels", map[string]any{}), CodeLabelNotOwn, inBody, `Labels["com.docker.compose.project"]`, "required", []any{"jane"}},
		{"a name not its own", sites, "POST", "/v1.56/containers/create?name=web", compose(), CodeNameNotOwn, inQuery, "name", "prefixed", []any{"jane-", "jane_"}},
		{"a parameter not forwarded", sites, "GET", "/v1.56/containers/json?all=1&nope=1", nil, CodeQueryNotAllowed, inQuery, "nope", "unset", nil},
		{"a registry", registries, "POST", "/v1.56/images/create?fromImage=evil.example/x&tag=1", nil, CodeRegistry, inQuery, "fromImage", "under", []any{"index.docker.io", "GHCR.io", "registry.local:5000", "10.0.0.5:5000", "[::1]:5000", "localhost"}},
		{"a platform", registries, "POST", "/v1.56/images/create?fromImage=alpine&tag=3.22&platform=linux/s390x", nil, CodePlatform, inQuery, "platform", "one-of", []any{"linux/amd64", "linux/arm64", "linux/arm/v7"}},
		{"a tag into another's namespace", sites, "POST", "/v1.56/images/alpine:3.22/tag?repo=quire-sites/blog/x&tag=1", nil, CodeImageNotOwn, inQuery, "repo", "under", []any{"quire-sites/jane/"}},
		{"a network's driver", sites, "POST", "/v1.56/networks/create", map[string]any{"Name": "jane_x", "Driver": "macvlan", "Labels": jane, "IPAM": map[string]any{"Config": []any{map[string]any{"Subnet": "10.213.0.32/28"}}}}, CodeNetwork, inBody, "Driver", "one-of", []any{"bridge"}},
		{"a subnet, the second", sites, "POST", "/v1.56/networks/create", map[string]any{"Name": "jane_x", "Labels": jane, "IPAM": map[string]any{"Config": []any{map[string]any{"Subnet": "10.213.0.32/28"}, map[string]any{"Subnet": "10.0.0.0/8"}}}}, CodeNetwork, inBody, "IPAM.Config[1].Subnet", "under", []any{"10.213.0.32/27", "10.213.0.64/27"}},
		{"no subnet", sites, "POST", "/v1.56/networks/create", map[string]any{"Name": "jane_x", "Labels": jane}, CodeNetwork, inBody, "IPAM.Config[0].Subnet", "under", []any{"10.213.0.32/27", "10.213.0.64/27"}},
		{"a network that isn't internal", egress, "POST", "/v1.56/networks/create", map[string]any{"Name": "jane_x", "Labels": jane, "IPAM": map[string]any{"Config": []any{map[string]any{"Subnet": "10.213.0.32/28"}}}}, CodeEgress, inBody, "Internal", "required", []any{true}},
		{"a volume's driver", sites, "POST", "/v1.56/volumes/create", map[string]any{"Name": "jane_x", "Driver": "nfs", "Labels": jane}, CodeMount, inBody, "Driver", "one-of", []any{"local"}},
		{"a privileged exec", sites, "POST", "/v1.56/containers/jane-php-1/exec", map[string]any{"Cmd": []any{"sh"}, "Privileged": true}, CodeExec, inBody, "Privileged", "unset", nil},
		{"an endpoint a scope may not use", sites, "POST", "/v1.56/images/quire-sites/jane/php-prod/push", nil, CodeScopeDenies, inPath, "", "none", nil},
		{"an update's memory", sites, "POST", "/v1.56/containers/jane-php-1/update", map[string]any{"Memory": 4294967296}, CodeLimit, inBody, "Memory", "required", nil},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			body := ""
			if c.body != nil {
				b, _ := json.Marshal(c.body)
				body = string(b)
			}

			status, answer := send(t, c.server, c.method, c.path, body, asJane)
			if status/100 == 2 {
				t.Fatalf("allowed: %s", answer)
			}

			r := problemsOf(t, answer)

			p := r.at(c.in, c.field)
			if p == nil {
				t.Fatalf("no problem at %s %s: %s", c.in, c.field, answer)
			}

			if p.Code != c.code {
				t.Errorf("code %s, want %s", p.Code, c.code)
			}

			switch {
			case c.kind == "" && p.Allowed != nil:
				t.Errorf("allowed %+v, want none", p.Allowed)
			case c.kind != "" && (p.Allowed == nil || p.Allowed.Kind != c.kind):
				t.Errorf("allowed %+v, want kind %s", p.Allowed, c.kind)
			case c.values != nil:
				got, _ := json.Marshal(p.Allowed.Values)
				want, _ := json.Marshal(c.values)

				if !bytes.Equal(got, want) {
					t.Errorf("allowed values %s, want %s", got, want)
				}
			}
		})
	}
}

// A field's path reads back: a map key is a JSON string inside brackets, whatever it holds.
func FuzzAFieldPathReadsBack(f *testing.F) {
	for _, k := range []string{"max-size", `"]`, `a"]["b`, "\\", "", "\x00\n", "ü", "]["} {
		f.Add(k, 3)
	}

	f.Fuzz(func(t *testing.T, k string, i int) {
		if i < 0 {
			i = -i
		}

		path := index(key("HostConfig.LogConfig.Config", k), i) + ".Name"

		got, err := parseField(path)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}

		want := []any{"HostConfig", "LogConfig", "Config", k, i, "Name"}
		if fmt.Sprint(got) != fmt.Sprint(want) || got[3] != k {
			t.Fatalf("%s reads back as %q, want %q", path, got, want)
		}
	})
}

// parseField reads a field's path: names (string), [i] (int), and ["key"] (string).
func parseField(path string) ([]any, error) {
	var out []any

	for path != "" {
		switch path[0] {
		case '.':
			path = path[1:]
		case '[':
			if strings.HasPrefix(path, `["`) {
				dec := json.NewDecoder(strings.NewReader(path[1:]))

				var k string
				if err := dec.Decode(&k); err != nil {
					return nil, err
				}

				rest := path[1+dec.InputOffset():]
				if !strings.HasPrefix(rest, "]") {
					return nil, errors.New("a key without its ]")
				}

				out = append(out, k)
				path = rest[1:]

				continue
			}

			end := strings.IndexByte(path, ']')
			if end < 0 {
				return nil, errors.New("an index without its ]")
			}

			i, err := strconv.Atoi(path[1:end])
			if err != nil {
				return nil, err
			}

			out = append(out, i)
			path = path[end+1:]
		default:
			end := strings.IndexAny(path, ".[")
			if end < 0 {
				end = len(path)
			}

			out = append(out, path[:end])
			path = path[end:]
		}
	}

	return out, nil
}

// A body of thousands of refused mounts is answered, and logged, with its first maxProblems only:
// an answer of bounded size that still validates.
func TestAThousandProblemsAreTruncated(t *testing.T) {
	limit := fixtureBodyLimit
	fixtureBodyLimit = 1 << 20

	defer func() { fixtureBodyLimit = limit }()

	d := startDocker(t)
	log, lines := checkedLog(t)
	server := gateLogging(t, d, "sites", log)

	var mounts []any
	for i := range 10000 {
		mounts = append(mounts, map[string]any{"Type": "bind", "Source": fmt.Sprintf("/h%d", i), "Target": fmt.Sprintf("/m%d", i)})
	}

	status, answer := send(t, server, "POST", "/v1.56/containers/create?name=jane-php-1", encode(set(compose(), "HostConfig.Mounts", mounts)), asJane)
	if status != http.StatusForbidden {
		t.Fatalf("%d %s", status, answer)
	}

	r := problemsOf(t, answer)
	if len(r.Problems) != maxProblems || !r.Truncated || !strings.HasSuffix(r.Message, "; and 9968 more") {
		t.Errorf("%d problems, truncated %v, message ending %q", len(r.Problems), r.Truncated, r.Message[max(0, len(r.Message)-40):])
	}

	if len(answer) > 16<<10 {
		t.Errorf("an answer of %d bytes", len(answer))
	}

	line := lines.waitFor(t, func(l map[string]any) bool { return l["msg"] == "refused" })
	if codes, _ := line["codes"].([]any); len(codes) != maxProblems || line["codes_total"] != float64(10000) {
		t.Errorf("logged %d codes of %v", len(codes), line["codes_total"])
	}
}

// What's allowed is the policy's, never the state's: the same, code by code, whatever another
// scope holds of the shared spool, and Retry-After a constant.
func TestAllowedIsThePolicyNotTheState(t *testing.T) {
	c, err := config.Parse([]byte("version: 1\nupstream: unix:///nowhere\nspool: {dir: " + t.TempDir() + ", limit: 1048576}\nlisteners:\n  - {name: server, address: \"tcp://127.0.0.1:2375\", mode: trusted, allow: {system: read}}\n"))
	if err != nil {
		t.Fatal(err)
	}

	byCode := map[Code]string{}

	for _, held := range []int64{0, 1, 400 << 10, 1<<20 - 1, 1 << 20} {
		spool := NewSpool(c)

		other := &reservation{spool: spool, scope: "zulu"}
		if held > 0 {
			if err := other.reserve(held); err != nil {
				t.Fatal(err)
			}
		}

		for _, asked := range []int64{1, 600 << 10, 1 << 20, 1<<20 + 1} {
			own := &reservation{spool: spool, scope: "jane"}

			var r *refusal
			if !errors.As(own.reserve(asked), &r) {
				own.release()

				continue
			}

			w := httptest.NewRecorder()
			answerRefusal(w, r)

			var body refusalBody
			_ = json.Unmarshal(w.Body.Bytes(), &body)

			problems, _ := json.Marshal(body.Problems)
			if seen, ok := byCode[r.code]; ok && seen != string(problems) {
				t.Errorf("%s with %d of the spool held by another: %s, before %s", r.code, held, problems, seen)
			}

			byCode[r.code] = string(problems)
		}

		other.release()
	}

	if len(byCode) != 2 {
		t.Errorf("codes seen: %v, want load.spool-full and load.too-large", byCode)
	}
}

// A refusal tells scope A nothing of scope B (zulu, the fixture's, or blog's objects): requests about
// B's objects, by name or ID, alone and mixed with A's in one long list, never get B's name, owner,
// IDs, image namespaces or subnets back; and B's object is refused as nothing at all is.
func TestRefusalsTellNothingOfAnotherScope(t *testing.T) {
	d := startDocker(t)
	zuluWeb := "5151000000000000000000000000000000000000000000000000000000000051"
	d.extra = []fakeObject{{zuluWeb, "zulu-web-1", map[string]string{"com.docker.compose.project": "zulu-owner-7f3a"}}}

	server := gate(t, d, "sites")
	create := "/v1.56/containers/create?name=jane-php-1"

	var mixed []any
	for i := range 40 {
		source := [...]string{"jane_data", "blog_data", "jane_stolen", "jane_hostbind"}[i%4]
		mixed = append(mixed, map[string]any{"Type": "volume", "Source": source, "Target": fmt.Sprintf("/m%d", i)})
	}

	requests := []struct{ method, path, body string }{
		{"POST", create, encode(set(compose(), "HostConfig.Mounts", mixed))},
		{"POST", create, encode(set(set(compose(), "HostConfig.VolumesFrom", []any{"jane-php-1", "blog-php-1", zuluWeb[:12], "jane-php-1:ro"}), "HostConfig.PidMode", "container:"+zuluWeb))},
		{"POST", create, encode(set(compose(), "HostConfig.NetworkMode", "container:"+zuluWeb[:8]))},
		{"POST", create, encode(set(compose(), "NetworkingConfig.EndpointsConfig", map[string]any{"jane_default": map[string]any{}, "blog_default": map[string]any{}, blogNet[:12]: map[string]any{}}))},
		{"POST", create, encode(set(compose(), "Labels", map[string]any{"com.docker.compose.project": "blog"}))},
		{"POST", create, encode(set(compose(), "Image", "quire-sites/blog/php-prod"))},
		{"POST", "/v1.56/containers/create?name=blog-php-2", encode(compose())},
		{"POST", "/v1.56/networks/" + blogNet[:12] + "/connect", `{"Container": "jane-php-1"}`},
		{"POST", "/v1.56/networks/jane_default/connect", `{"Container": "` + zuluWeb + `"}`},
		{"POST", "/v1.56/images/" + strings.Repeat("3", 12) + "/tag?repo=quire-sites/jane/x&tag=1", ""},
		{"GET", "/v1.56/containers/" + zuluWeb + "/json", ""},
		{"GET", "/v1.56/containers/" + blogPHP[:10] + "/json", ""},
		{"DELETE", "/v1.56/volumes/blog_data", ""},
	}

	markers := []string{"zulu", zuluWeb, blogPHP, blogNet, "10.99.7", "quire-sites/blog/\"", "blog-, blog_"}

	for _, r := range requests {
		status, answer := send(t, server, r.method, r.path, r.body, asJane)
		if status/100 == 2 {
			t.Errorf("%s %s: allowed", r.method, r.path)

			continue
		}

		for _, m := range markers {
			if strings.Contains(answer, m) && !strings.Contains(r.path+r.body, m) {
				t.Errorf("%s %s tells %q: %s", r.method, r.path, m, answer)
			}
		}

		for _, p := range problemsOf(t, answer).Problems {
			allowed, _ := json.Marshal(p.Allowed)
			if bytes.Contains(allowed, []byte("blog")) || bytes.Contains(allowed, []byte("zulu")) {
				t.Errorf("%s %s: allowed %s names another scope's", r.method, r.path, allowed)
			}
		}
	}

	// Another's object, and nothing: the same answer, problems and all
	_, another := send(t, server, "GET", "/v1.56/containers/"+zuluWeb+"/json", "", asJane)
	nothing := strings.Repeat("7", 64)
	_, none := send(t, server, "GET", "/v1.56/containers/"+nothing+"/json", "", asJane)

	if strings.ReplaceAll(another, zuluWeb, "X") != strings.ReplaceAll(none, nothing, "X") {
		t.Errorf("another's: %s\nnothing: %s", another, none)
	}
}

// fix is the scripted fixer: it reads only a refusal's problems (never its message) and changes the
// request by what each says is allowed. It's what an agent or SDK can do with the fields alone.
func fix(t *testing.T, r refusalBody, query url.Values, body map[string]any) {
	t.Helper()

	var drops [][]any

	for _, p := range r.Problems {
		value, ok := fixed(p, func() any {
			if p.In == inQuery {
				return query.Get(p.Field)
			}

			v, _ := get(body, mustParse(t, p.Field))

			return v
		})

		switch {
		case !ok:
			t.Fatalf("can't fix %s at %s %s by %+v", p.Code, p.In, p.Field, p.Allowed)
		case p.In == inQuery && value == nil:
			query.Del(p.Field)
		case p.In == inQuery:
			query.Set(p.Field, value.(string))
		case p.In == inBody && value == nil:
			drops = append(drops, mustParse(t, p.Field))
		case p.In == inBody:
			put(body, mustParse(t, p.Field), value)
		default:
			t.Fatalf("can't fix %s in %s", p.Code, p.In)
		}
	}

	// Drops last, the later elements of a list first, so the indexes still hold
	slices.SortFunc(drops, func(a, b []any) int { return strings.Compare(fmt.Sprint(b), fmt.Sprint(a)) })

	for _, path := range drops {
		drop(body, path)
	}
}

// fixed is the value a problem's allowed asks for (nil: none, leave it out), given the current one.
func fixed(p problemBody, current func() any) (any, bool) {
	a := p.Allowed
	if a == nil {
		return nil, false
	}

	first := func() any {
		if len(a.Values) > 0 {
			return a.Values[0]
		}

		return nil
	}

	switch a.Kind {
	case "unset":
		return nil, true
	case "one-of":
		return first(), len(a.Values) > 0
	case "required":
		switch {
		case len(a.Values) > 0:
			return first(), true
		case a.Max != nil:
			return *a.Max, true
		}
	case "at-most":
		return *a.Max, a.Max != nil
	case "between":
		return *a.Min, a.Min != nil
	case "own":
		if len(a.Values) > 0 {
			return first(), true
		}

		return nil, true
	case "prefixed":
		s, _ := current().(string)

		return first().(string) + s, len(a.Values) > 0
	case "under":
		s, _ := current().(string)
		under := first().(string)

		// A subnet is inside itself; a name goes under the namespace or registry
		if strings.Contains(under, "/") && !strings.HasSuffix(under, "/") {
			return under, true
		}

		return strings.TrimSuffix(under, "/") + "/" + s[strings.LastIndex(s, "/")+1:], true
	}

	return nil, false
}

func mustParse(t *testing.T, field string) []any {
	t.Helper()

	path, err := parseField(field)
	if err != nil {
		t.Fatalf("%s: %v", field, err)
	}

	return path
}

func get(v any, path []any) (any, bool) {
	for _, step := range path {
		switch s := step.(type) {
		case string:
			m, ok := v.(map[string]any)
			if !ok {
				return nil, false
			}

			v, ok = m[s]
			if !ok {
				return nil, false
			}
		case int:
			l, ok := v.([]any)
			if !ok || s >= len(l) {
				return nil, false
			}

			v = l[s]
		}
	}

	return v, true
}

// put sets a value at a path, making what's missing on the way.
func put(body map[string]any, path []any, value any) {
	var walk func(v any, path []any) any
	walk = func(v any, path []any) any {
		if len(path) == 0 {
			return value
		}

		switch s := path[0].(type) {
		case string:
			m, _ := v.(map[string]any)
			if m == nil {
				m = map[string]any{}
			}

			m[s] = walk(m[s], path[1:])

			return m
		case int:
			l, _ := v.([]any)
			for len(l) <= s {
				l = append(l, nil)
			}

			l[s] = walk(l[s], path[1:])

			return l
		}

		return v
	}

	walk(body, path)
}

// drop removes what's at a path: a map's key, or a list's element.
func drop(body map[string]any, path []any) {
	parent, ok := get(body, path[:len(path)-1])
	if !ok {
		return
	}

	switch s := path[len(path)-1].(type) {
	case string:
		delete(parent.(map[string]any), s)
	case int:
		put(body, path[:len(path)-1], slices.Delete(parent.([]any), s, s+1))
	}
}

// Twelve requests, each wrong at first: the fixer, reading only the problems, makes each one that's
// allowed on its one retry. (That the fields are enough to act on; not that they help a model, which
// paper 2 measures, outside this repo.)
func TestTheFixerFixesEachRequestFromItsProblemsAlone(t *testing.T) {
	d := startDocker(t)
	servers := map[string]*httptest.Server{"sites": gate(t, d, "sites"), "egress": gate(t, d, "egress"), "registries": gate(t, d, "registries")}

	tasks := []struct {
		name, listener, method, path string
		body                         map[string]any
	}{
		{"a capability", "sites", "POST", "/v1.56/containers/create?name=jane-php-1", set(compose(), "HostConfig.CapAdd", []any{"NET_BIND_SERVICE", "SYS_ADMIN"})},
		{"a refused field", "sites", "POST", "/v1.56/containers/create?name=jane-php-1", set(compose(), "HostConfig.Sysctls", map[string]any{"net.ipv4.ip_forward": "1"})},
		{"memory above the bound", "sites", "POST", "/v1.56/containers/create?name=jane-php-1", set(compose(), "HostConfig.Memory", 8589934592)},
		{"a host mount", "sites", "POST", "/v1.56/containers/create?name=jane-php-1", set(compose(), "HostConfig.Binds", []any{"/etc:/host-etc:ro"})},
		{"a name outside the prefixes", "sites", "POST", "/v1.56/containers/create?name=web", compose()},
		{"Docker's default capabilities", "sites", "POST", "/v1.56/containers/create?name=jane-php-1", set(compose(), "HostConfig.CapDrop", nil)},
		{"no no-new-privileges", "sites", "POST", "/v1.56/containers/create?name=jane-php-1", set(compose(), "HostConfig.SecurityOpt", nil)},
		{"a log driver", "sites", "POST", "/v1.56/containers/create?name=jane-php-1", set(compose(), "HostConfig.LogConfig.Type", "syslog")},
		{"no owner label", "sites", "POST", "/v1.56/containers/create?name=jane-php-1", set(compose(), "Labels", map[string]any{"com.docker.compose.service": "php"})},
		{"the default bridge", "sites", "POST", "/v1.56/containers/create?name=jane-php-1", set(compose(), "HostConfig.NetworkMode", "bridge")},
		{"a network with a way out, no subnet", "egress", "POST", "/v1.56/networks/create", map[string]any{"Name": "jane_new", "Labels": map[string]any{"com.docker.compose.project": "jane"}}},
		{"a registry", "registries", "POST", "/v1.56/images/create?fromImage=evil.example%2Ftools%2Falpine&tag=3.22", nil},
	}

	for _, task := range tasks {
		t.Run(task.name, func(t *testing.T) {
			path, raw, _ := strings.Cut(task.path, "?")
			query, _ := url.ParseQuery(raw)
			body := task.body

			sendTask := func() (int, string) {
				encoded := ""
				if body != nil {
					encoded = encode(body)
				}

				return send(t, servers[task.listener], task.method, path+"?"+query.Encode(), encoded, asJane)
			}

			status, answer := sendTask()
			if status/100 == 2 {
				t.Fatalf("the wrong first request is allowed: %s", answer)
			}

			fix(t, problemsOf(t, answer), query, body)

			if status, answer := sendTask(); status/100 != 2 {
				t.Errorf("after the fix: %d %s", status, answer)
			}
		})
	}
}
