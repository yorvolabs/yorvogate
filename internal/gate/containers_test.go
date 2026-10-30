package gate

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// compose is a container as Compose creates one for jane's project: hardened, on its own network and
// the shared one its scope may join, with its own volume.
func compose() map[string]any {
	return map[string]any{
		"Image":  "quire-sites/jane/php-prod",
		"Labels": map[string]any{"com.docker.compose.project": "jane", "com.docker.compose.service": "php"},
		"Env":    []any{"SERVER_NAME=jane.example"},
		"HostConfig": map[string]any{
			"NetworkMode":   "jane_default",
			"CapDrop":       []any{"ALL"},
			"CapAdd":        []any{"NET_BIND_SERVICE"},
			"SecurityOpt":   []any{"no-new-privileges:true"},
			"Memory":        536870912,
			"PidsLimit":     256,
			"RestartPolicy": map[string]any{"Name": "unless-stopped"},
			"LogConfig":     map[string]any{"Type": "json-file", "Config": map[string]any{}},
			"Mounts":        []any{map[string]any{"Type": "volume", "Source": "jane_data", "Target": "/app/storage", "VolumeOptions": map[string]any{}}},
			"Tmpfs":         map[string]any{"/tmp": ""},
			"Ulimits":       []any{map[string]any{"Name": "nofile", "Soft": 1024, "Hard": 2048}},
		},
		"NetworkingConfig": map[string]any{"EndpointsConfig": map[string]any{
			"jane_default":    map[string]any{"Aliases": []any{"php"}},
			"quire-link-jane": map[string]any{"Aliases": []any{"jane.example.quire.internal"}},
		}},
	}
}

// set changes one value of a body, by a path of keys ("HostConfig.Privileged").
func set(body map[string]any, path string, value any) map[string]any {
	keys := strings.Split(path, ".")
	m := body

	for _, k := range keys[:len(keys)-1] {
		next, ok := m[k].(map[string]any)
		if !ok {
			next = map[string]any{}
			m[k] = next
		}

		m = next
	}

	if value == nil {
		delete(m, keys[len(keys)-1])
	} else {
		m[keys[len(keys)-1]] = value
	}

	return body
}

func encode(body map[string]any) string {
	b, _ := json.Marshal(body)

	return string(b)
}

func TestAContainerAsComposeCreatesItIsAllowed(t *testing.T) {
	d := startDocker(t)
	server := gate(t, d, "sites")

	status, answer := send(t, server, "POST", "/v1.56/containers/create?name=jane-php-1", encode(compose()), asJane)
	if status != 200 {
		t.Fatalf("%d %s", status, answer)
	}

	got := d.last()
	if got.path != "/v1.56/containers/create" || got.query != "name=jane-php-1" {
		t.Errorf("forwarded %s?%s", got.path, got.query)
	}

	// What Docker gets is the configuration that was checked, encoded anew.
	var forwarded map[string]any
	if err := json.Unmarshal([]byte(got.body), &forwarded); err != nil {
		t.Fatal(err)
	}

	if forwarded["Image"] != "quire-sites/jane/php-prod" || forwarded["HostConfig"].(map[string]any)["Memory"] != float64(536870912) {
		t.Errorf("forwarded %s", got.body)
	}

	// Empty maps and lists ask for nothing, as Docker reads them.
	empty := set(set(set(compose(), "HostConfig.Sysctls", map[string]any{}), "HostConfig.Devices", []any{}), "NetworkingConfig.EndpointsConfig.quire-link-jane", map[string]any{"Aliases": []any{"jane.example.quire.internal"}, "DriverOpts": map[string]any{}, "Links": []any{}})
	if status, answer := send(t, server, "POST", "/v1.56/containers/create?name=jane-php-1", encode(empty), asJane); status != 200 {
		t.Errorf("empty values: %d %s", status, answer)
	}

	// Its builder, which its scope names, and a network-less container are fine too.
	for _, body := range []map[string]any{
		set(set(compose(), "HostConfig.NetworkMode", "none"), "NetworkingConfig", nil),
		set(set(compose(), "HostConfig.NetworkMode", "container:jane-php-1"), "NetworkingConfig", nil),
		set(compose(), "HostConfig.IpcMode", "container:buildx_buildkit_jane-0"),
	} {
		if status, answer := send(t, server, "POST", "/v1.56/containers/create?name=jane-worker-1", encode(body), asJane); status != 200 {
			t.Errorf("%d %s", status, answer)
		}
	}
}

// Every way a container could reach the host or another scope, each refused with the reason.
func TestWhatReachesTheHostOrAnotherScopeIsRefused(t *testing.T) {
	d := startDocker(t)
	server := gate(t, d, "sites")

	cases := []struct {
		name, want string
		body       map[string]any
	}{
		{"privileged", "HostConfig.Privileged isn't allowed", set(compose(), "HostConfig.Privileged", true)},
		{"the host's root, bound", "only named volumes of its own, never a host path", set(compose(), "HostConfig.Binds", []any{"/:/host"})},
		{"another scope's volume, bound", `the volume "blog_data" isn't one of its own names`, set(compose(), "HostConfig.Binds", []any{"blog_data:/x"})},
		{"a bind mount", `a "bind" mount of "/etc" isn't allowed`, set(compose(), "HostConfig.Mounts", []any{map[string]any{"Type": "bind", "Source": "/etc", "Target": "/x"}})},
		{"a volume bound to the host", "volume driver options aren't allowed", set(compose(), "HostConfig.Mounts", []any{map[string]any{"Type": "volume", "Source": "jane_root", "Target": "/x", "VolumeOptions": map[string]any{"DriverConfig": map[string]any{"Name": "local", "Options": map[string]any{"type": "none", "o": "bind", "device": "/"}}}}})},
		{"a volume's subpath out of it", "must stay inside the volume", set(compose(), "HostConfig.Mounts", []any{map[string]any{"Type": "volume", "Source": "jane_data", "Target": "/x", "VolumeOptions": map[string]any{"Subpath": "../../.."}}})},
		{"an image mount", `a "image" mount`, set(compose(), "HostConfig.Mounts", []any{map[string]any{"Type": "image", "Source": "quire-sites/blog/php-prod", "Target": "/x"}})},
		{"bind options on a volume", "a mount's BindOptions isn't allowed", set(compose(), "HostConfig.Mounts", []any{map[string]any{"Type": "volume", "Source": "jane_data", "Target": "/x", "BindOptions": map[string]any{"Propagation": "rshared"}}})},
		{"the host's network", `NetworkMode "host" isn't allowed`, set(set(compose(), "HostConfig.NetworkMode", "host"), "NetworkingConfig", nil)},
		{"Docker's default bridge", `NetworkMode "bridge" isn't allowed`, set(set(compose(), "HostConfig.NetworkMode", "bridge"), "NetworkingConfig", nil)},
		{"no network mode (the bridge)", `NetworkMode "" isn't allowed`, set(set(compose(), "HostConfig.NetworkMode", nil), "NetworkingConfig", nil)},
		{"another scope's network", "the network blog_default isn't one of its own", set(set(compose(), "HostConfig.NetworkMode", "blog_default"), "NetworkingConfig", nil)},
		{"another network, joined beside", "the network blog_default isn't one of its own", set(compose(), "NetworkingConfig.EndpointsConfig.blog_default", map[string]any{})},
		{"another container's network", "NetworkMode container:blog-php-1 isn't one of its own", set(set(compose(), "HostConfig.NetworkMode", "container:blog-php-1"), "NetworkingConfig", nil)},
		{"another's alias on a shared network", `the alias "blog.example.quire.internal"`, set(compose(), "NetworkingConfig.EndpointsConfig.quire-link-jane", map[string]any{"Aliases": []any{"blog.example.quire.internal"}})},
		{"another's address on a shared network", "the address 10.213.0.9 on the shared network", set(compose(), "NetworkingConfig.EndpointsConfig.quire-link-jane", map[string]any{"IPAMConfig": map[string]any{"IPv4Address": "10.213.0.9"}})},
		{"driver options on a shared network", "on the shared network quire-link-jane, DriverOpts isn't allowed", set(compose(), "NetworkingConfig.EndpointsConfig.quire-link-jane", map[string]any{"DriverOpts": map[string]any{"com.docker.network.endpoint.sysctls": "net.ipv4.conf.IFNAME.proxy_arp=1"}})},
		{"a MAC address on a shared network", "MacAddress isn't allowed", set(compose(), "NetworkingConfig.EndpointsConfig.quire-link-jane", map[string]any{"MacAddress": "02:42:ac:11:00:02"})},
		{"the host's PIDs", "the host's namespaces aren't allowed", set(compose(), "HostConfig.PidMode", "host")},
		{"another's PIDs", "PidMode: container:blog-php-1 isn't one of its own", set(compose(), "HostConfig.PidMode", "container:blog-php-1")},
		{"the host's IPC", "the host's namespaces aren't allowed", set(compose(), "HostConfig.IpcMode", "host")},
		{"the host's UTS", "the host's namespaces aren't allowed", set(compose(), "HostConfig.UTSMode", "host")},
		{"the host's users", "the host's namespaces aren't allowed", set(compose(), "HostConfig.UsernsMode", "host")},
		{"the host's cgroups", "the host's namespaces aren't allowed", set(compose(), "HostConfig.CgroupnsMode", "host")},
		{"a capability", "adding the capability SYS_ADMIN isn't allowed", set(compose(), "HostConfig.CapAdd", []any{"SYS_ADMIN"})},
		{"a capability, spelled otherwise", "adding the capability cap_sys_ptrace isn't allowed", set(compose(), "HostConfig.CapAdd", []any{"cap_sys_ptrace"})},
		{"all capabilities", "adding the capability ALL isn't allowed", set(compose(), "HostConfig.CapAdd", []any{"ALL"})},
		{"Docker's default capabilities", "it must drop all capabilities", set(compose(), "HostConfig.CapDrop", nil)},
		{"no seccomp", `the security option "seccomp=unconfined" isn't allowed`, set(compose(), "HostConfig.SecurityOpt", []any{"no-new-privileges", "seccomp=unconfined"})},
		{"no AppArmor", `the security option "apparmor=unconfined" isn't allowed`, set(compose(), "HostConfig.SecurityOpt", []any{"no-new-privileges", "apparmor=unconfined"})},
		{"gaining privileges", "it must run with no-new-privileges", set(compose(), "HostConfig.SecurityOpt", nil)},
		{"/proc unmasked", "HostConfig.MaskedPaths isn't allowed", set(compose(), "HostConfig.MaskedPaths", []any{})},
		{"/proc writable", "HostConfig.ReadonlyPaths isn't allowed", set(compose(), "HostConfig.ReadonlyPaths", []any{})},
		{"a device", "HostConfig.Devices isn't allowed", set(compose(), "HostConfig.Devices", []any{map[string]any{"PathOnHost": "/dev/sda", "PathInContainer": "/dev/sda", "CgroupPermissions": "rwm"}})},
		{"GPUs", "HostConfig.DeviceRequests isn't allowed", set(compose(), "HostConfig.DeviceRequests", []any{map[string]any{"Count": -1, "Capabilities": [][]any{{"gpu"}}}})},
		{"device rules", "HostConfig.DeviceCgroupRules isn't allowed", set(compose(), "HostConfig.DeviceCgroupRules", []any{"a *:* rwm"})},
		{"kernel parameters", "HostConfig.Sysctls isn't allowed", set(compose(), "HostConfig.Sysctls", map[string]any{"net.ipv4.ip_forward": "1"})},
		{"another cgroup", "HostConfig.CgroupParent isn't allowed", set(compose(), "HostConfig.CgroupParent", "/system.slice")},
		{"runtime annotations", "HostConfig.Annotations isn't allowed", set(compose(), "HostConfig.Annotations", map[string]any{"dev.gvisor.flag.debug": "true"})},
		{"storage options", "HostConfig.StorageOpt isn't allowed", set(compose(), "HostConfig.StorageOpt", map[string]any{"size": "1T"})},
		{"links", "HostConfig.Links isn't allowed", set(compose(), "HostConfig.Links", []any{"blog-php-1:php"})},
		{"published ports", "published ports", set(compose(), "HostConfig.PortBindings", map[string]any{"80/tcp": []any{map[string]any{"HostPort": "80"}}})},
		{"every port published", "published ports", set(compose(), "HostConfig.PublishAllPorts", true)},
		{"another runtime", `the runtime "runsc" isn't allowed`, set(compose(), "HostConfig.Runtime", "runsc")},
		{"another isolation", `the isolation "hyperv" isn't allowed`, set(compose(), "HostConfig.Isolation", "hyperv")},
		{"a log driver that reaches elsewhere", `the log driver "syslog" isn't allowed`, set(compose(), "HostConfig.LogConfig", map[string]any{"Type": "syslog", "Config": map[string]any{"syslog-address": "udp://10.0.0.1:514"}})},
		{"no OOM killer", "disabling the OOM killer isn't allowed", set(compose(), "HostConfig.OomKillDisable", true)},
		{"spared by the OOM killer", "OomScoreAdj below 0 isn't allowed", set(compose(), "HostConfig.OomScoreAdj", -1000)},
		{"real-time priority", "the ulimit rtprio isn't allowed", set(compose(), "HostConfig.Ulimits", []any{map[string]any{"Name": "rtprio", "Soft": 99, "Hard": 99}})},
		{"the real-time scheduler", "HostConfig.CpuRealtimeRuntime isn't allowed", set(compose(), "HostConfig.CpuRealtimeRuntime", 950000)},
		{"no memory limit", "a memory limit up to 1073741824 bytes is required", set(compose(), "HostConfig.Memory", nil)},
		{"too much memory", "a memory limit up to", set(compose(), "HostConfig.Memory", 1<<31)},
		{"no process limit", "a process limit up to 512 is required", set(compose(), "HostConfig.PidsLimit", nil)},
		{"unlimited processes", "a process limit up to 512 is required", set(compose(), "HostConfig.PidsLimit", -1)},
		{"a volume plugin", `the volume driver "rexray" isn't allowed`, set(compose(), "HostConfig.VolumeDriver", "rexray")},
		{"another's volumes", "VolumesFrom: blog-php-1 isn't one of its own containers", set(compose(), "HostConfig.VolumesFrom", []any{"blog-php-1:ro"})},
		{"not its label", "it must carry the label com.docker.compose.project=jane", set(compose(), "Labels", map[string]any{"com.docker.compose.service": "php"})},
		{"another's label", "it must carry the label com.docker.compose.project=jane", set(compose(), "Labels", map[string]any{"com.docker.compose.project": "blog"})},
		{"another scope's image", "the image quire-sites/blog/php-prod is in a protected namespace", set(compose(), "Image", "quire-sites/blog/php-prod")},
		{"an output field as input", "NetworkID isn't allowed", set(compose(), "NetworkingConfig.EndpointsConfig.jane_default", map[string]any{"NetworkID": blogNet})},
	}

	for _, c := range cases {
		status, answer := send(t, server, "POST", "/v1.56/containers/create?name=jane-evil-1", encode(c.body), asJane)
		if status != http.StatusForbidden || !strings.Contains(message(t, answer), c.want) {
			t.Errorf("%s: %d %s", c.name, status, answer)
		}
	}

	if d.count() != 0 {
		t.Errorf("%d requests reached Docker", d.count())
	}
}

// What a body says is read as Docker reads it: whatever the keys' case, the last of duplicates, and
// nothing the type doesn't have.
func TestABodyIsReadTheWayDockerReadsIt(t *testing.T) {
	d := startDocker(t)
	server := gate(t, d, "sites")
	valid := encode(compose())

	cases := map[string]struct {
		body   string
		status int
		want   string
	}{
		"a lowercase key":     {strings.Replace(valid, `"HostConfig":{`, `"HostConfig":{"privileged":true,`, 1), 403, "HostConfig.Privileged isn't allowed"},
		"a key in odd case":   {strings.Replace(valid, `"HostConfig":{`, `"HostConfig":{"pRiViLeGeD":true,`, 1), 403, "HostConfig.Privileged isn't allowed"},
		"duplicates, last on": {strings.Replace(valid, `"HostConfig":{`, `"HostConfig":{"Privileged":false,"Privileged":true,`, 1), 403, "HostConfig.Privileged isn't allowed"},
		"an unknown field":    {strings.Replace(valid, `"HostConfig":{`, `"HostConfig":{"SomeFutureField":true,`, 1), 400, "unknown field"},
		"two values":          {valid + valid, 400, "more than one value"},
		"not JSON":            {"{", 400, "isn't one this endpoint takes"},
		"no image":            {`{"Labels":{"com.docker.compose.project":"jane"}}`, 400, "no image"},
	}

	for name, c := range cases {
		status, answer := send(t, server, "POST", "/v1.56/containers/create?name=jane-evil-1", c.body, asJane)
		if status != c.status || !strings.Contains(message(t, answer), c.want) {
			t.Errorf("%s: %d %s", name, status, answer)
		}
	}

	// Duplicates the other way: the checked value is what's forwarded, never the bytes that came.
	twice := strings.Replace(valid, `"HostConfig":{`, `"HostConfig":{"Privileged":true,"Privileged":false,`, 1)
	if status, answer := send(t, server, "POST", "/v1.56/containers/create?name=jane-php-1", twice, asJane); status != 200 {
		t.Fatalf("%d %s", status, answer)
	}

	if strings.Contains(strings.ToLower(d.last().body), "privileged\":true") {
		t.Errorf("forwarded %s", d.last().body)
	}
}

func TestNamesAreItsOwn(t *testing.T) {
	d := startDocker(t)
	server := gate(t, d, "sites")

	for _, query := range []string{"", "?name=blog-php-1", "?name=janet-php-1", "?name=jane-", "?name=jane-a&name=blog-b"} {
		if status, answer := send(t, server, "POST", "/v1.56/containers/create"+query, encode(compose()), asJane); status/100 != 4 {
			t.Errorf("%q: %d %s", query, status, answer)
		}
	}

	if d.count() != 0 {
		t.Errorf("%d requests reached Docker", d.count())
	}
}

// A scope acts on its own containers (and those its scope names), by the ID that was checked; another
// scope's are answered as if they didn't exist.
func TestOnlyItsOwnContainers(t *testing.T) {
	d := startDocker(t)
	server := gate(t, d, "sites")

	for _, c := range [][2]string{
		{"GET", "/v1.56/containers/jane-php-1/json"},
		{"POST", "/v1.56/containers/jane-php-1/stop"},
		{"DELETE", "/v1.56/containers/jane-php-1?v=1&force=1"},
		{"GET", "/v1.56/containers/buildx_buildkit_jane-0/json"},
	} {
		if status, answer := send(t, server, c[0], c[1], "", asJane); status != 200 {
			t.Errorf("%s %s: %d %s", c[0], c[1], status, answer)
		}
	}

	if got := d.last(); got.path != "/v1.56/containers/"+janeBuilder+"/json" {
		t.Errorf("named by its name, forwarded as %s", got.path)
	}

	before := d.count()

	for _, c := range [][2]string{
		{"GET", "/v1.56/containers/blog-php-1/json"},
		{"GET", "/v1.56/containers/" + blogPHP + "/logs"},
		{"POST", "/v1.56/containers/bbbb/kill"},
		{"DELETE", "/v1.56/containers/blog-php-1"},
		{"GET", "/v1.56/containers/nothing-here/json"},
		{"PUT", "/v1.56/containers/blog-php-1/archive?path=/app"},
	} {
		if status, answer := send(t, server, c[0], c[1], "", asJane); status != http.StatusNotFound || !strings.Contains(message(t, answer), "No such container") {
			t.Errorf("%s %s: %d %s", c[0], c[1], status, answer)
		}
	}

	if status, answer := send(t, server, "POST", "/v1.56/containers/jane-php-1/rename?name=blog-php-2", "", asJane); status != http.StatusForbidden {
		t.Errorf("renamed out of its names: %d %s", status, answer)
	}

	if d.count() != before {
		t.Errorf("%d requests reached Docker", d.count()-before)
	}
}

// Lists and prunes see only its own: its label is added to whatever filters came.
func TestListsAreItsOwn(t *testing.T) {
	d := startDocker(t)
	server := gate(t, d, "sites")

	for _, given := range []string{"", `{"name":["php"]}`, `{"label":{"com.docker.compose.oneoff=False":true}}`} {
		path := "/v1.56/containers/json?all=1"
		if given != "" {
			path += "&filters=" + url.QueryEscape(given)
		}

		if status, answer := send(t, server, "GET", path, "", asJane); status != 200 {
			t.Fatalf("%s: %d %s", given, status, answer)
		}

		query, _ := url.ParseQuery(d.last().query)
		var filters map[string][]string
		if err := json.Unmarshal([]byte(query.Get("filters")), &filters); err != nil {
			t.Fatal(err)
		}

		if !contains(filters["label"], "com.docker.compose.project=jane") || query.Get("all") != "1" {
			t.Errorf("%s: forwarded %s", given, query.Get("filters"))
		}

		if strings.Contains(given, "oneoff") && !contains(filters["label"], "com.docker.compose.oneoff=False") {
			t.Errorf("the filters that came are kept: %v", filters)
		}
	}

	if status, _ := send(t, server, "POST", "/v1.56/containers/prune", "", asJane); status != 200 || !strings.Contains(d.last().query, "jane") {
		t.Errorf("prune: %d %s", status, d.last().query)
	}

	if status, _ := send(t, server, "GET", "/v1.56/containers/json?filters=%7B%7D&filters=%7B%7D", "", asJane); status != http.StatusBadRequest {
		t.Errorf("filters twice: %d", status)
	}
}

func contains(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}

	return false
}

func TestExecsAreInItsOwnContainersAndNeverPrivileged(t *testing.T) {
	d := startDocker(t)
	server := gate(t, d, "sites")

	if status, answer := send(t, server, "POST", "/v1.56/containers/jane-php-1/exec", `{"Cmd":["bin/console","quire:backup"],"AttachStdout":true}`, asJane); status != 200 {
		t.Fatalf("its own: %d %s", status, answer)
	}

	if d.last().path != "/v1.56/containers/"+janePHP+"/exec" {
		t.Errorf("forwarded %s", d.last().path)
	}

	before := d.count()

	for _, c := range [][4]string{
		{"POST", "/v1.56/containers/jane-php-1/exec", `{"Cmd":["sh"],"Privileged":true}`, "a privileged exec isn't allowed"},
		{"POST", "/v1.56/containers/blog-php-1/exec", `{"Cmd":["cat","/app/prod.env"]}`, "No such container"},
		{"POST", "/v1.56/exec/exec-blog/start", `{"Detach":true}`, "No such exec instance"},
		{"GET", "/v1.56/exec/exec-blog/json", "", "No such exec instance"},
		{"POST", "/v1.56/exec/nothing/start", `{"Detach":true}`, "No such exec instance"},
	} {
		if status, answer := send(t, server, c[0], c[1], c[2], asJane); status/100 != 4 || !strings.Contains(message(t, answer), c[3]) {
			t.Errorf("%s %s: %d %s", c[0], c[1], status, answer)
		}
	}

	if d.count() != before {
		t.Errorf("%d requests reached Docker", d.count()-before)
	}

	if status, answer := send(t, server, "POST", "/v1.56/exec/exec-jane/start", `{"Detach":true}`, asJane); status != 200 {
		t.Errorf("its own exec: %d %s", status, answer)
	}
}

func TestJoiningANetwork(t *testing.T) {
	d := startDocker(t)
	server := gate(t, d, "sites")

	ok := `{"Container":"jane-php-1","EndpointConfig":{"Aliases":["jane.example.quire.internal"],"IPAMConfig":{"IPv4Address":"10.213.0.4"}}}`
	if status, answer := send(t, server, "POST", "/v1.56/networks/quire-link-jane/connect", ok, asJane); status != 200 {
		t.Fatalf("%d %s", status, answer)
	}

	got := d.last()
	if got.path != "/v1.56/networks/"+linkNet+"/connect" || !strings.Contains(got.body, janePHP) {
		t.Errorf("forwarded %s %s", got.path, got.body)
	}

	for _, c := range [][3]string{
		{"/v1.56/networks/quire-link-jane/connect", `{"Container":"jane-php-1","EndpointConfig":{"Aliases":["blog.example.quire.internal"]}}`, "isn't one of its own"},
		{"/v1.56/networks/blog_default/connect", `{"Container":"jane-php-1"}`, "not found"},
		{"/v1.56/networks/jane_default/connect", `{"Container":"blog-php-1"}`, "No such container"},
		{"/v1.56/networks/blog_default/disconnect", `{"Container":"blog-php-1","Force":true}`, "not found"},
	} {
		if status, answer := send(t, server, "POST", c[0], c[1], asJane); status/100 != 4 || !strings.Contains(message(t, answer), c[2]) {
			t.Errorf("%s %s: %d %s", c[0], c[1], status, answer)
		}
	}
}

func TestNewLimitsAreChecked(t *testing.T) {
	d := startDocker(t)
	server := gate(t, d, "sites")

	if status, answer := send(t, server, "POST", "/v1.56/containers/jane-php-1/update", `{"Memory":268435456,"RestartPolicy":{"Name":"always"}}`, asJane); status != 200 {
		t.Fatalf("%d %s", status, answer)
	}

	for body, want := range map[string]string{
		`{"Memory":4294967296}`:                                "a memory limit up to",
		`{"PidsLimit":-1}`:                                     "a process limit up to",
		`{"Devices":[{"PathOnHost":"/dev/sda"}]}`:              "Devices isn't allowed",
		`{"CpuRealtimeRuntime":950000}`:                        "CpuRealtimeRuntime isn't allowed",
		`{"OomKillDisable":true}`:                              "disabling the OOM killer",
		`{"Ulimits":[{"Name":"memlock","Soft":-1,"Hard":-1}]}`: "the ulimit memlock isn't allowed",
	} {
		if status, answer := send(t, server, "POST", "/v1.56/containers/jane-php-1/update", body, asJane); status != http.StatusForbidden || !strings.Contains(message(t, answer), want) {
			t.Errorf("%s: %d %s", body, status, answer)
		}
	}
}

func TestItReadsImagesButNotAnotherScopes(t *testing.T) {
	d := startDocker(t)
	server := gate(t, d, "sites")

	for _, path := range []string{"/v1.56/images/json", "/v1.56/images/alpine:3.22/json", "/v1.56/images/quire-sites/jane/php-prod/json", "/v1.56/images/quire-sites/jane/php-prod/history"} {
		if status, answer := send(t, server, "GET", path, "", asJane); status != 200 {
			t.Errorf("%s: %d %s", path, status, answer)
		}
	}

	for _, path := range []string{"/v1.56/images/quire-sites/blog/php-prod/json", "/v1.56/images/quire-sites/blog/php-prod/history"} {
		if status, answer := send(t, server, "GET", path, "", asJane); status != http.StatusNotFound || !strings.Contains(message(t, answer), "No such image") {
			t.Errorf("%s: %d %s", path, status, answer)
		}
	}
}

func TestItSeesItsOwnNetworksAndVolumes(t *testing.T) {
	d := startDocker(t)
	server := gate(t, d, "sites")

	for _, path := range []string{"/v1.56/networks", "/v1.56/volumes"} {
		if status, _ := send(t, server, "GET", path, "", asJane); status != 200 || !strings.Contains(d.last().query, "jane") {
			t.Errorf("%s: %d %s", path, status, d.last().query)
		}
	}

	for _, path := range []string{"/v1.56/networks/jane_default", "/v1.56/networks/quire-link-jane", "/v1.56/volumes/jane_data"} {
		if status, answer := send(t, server, "GET", path, "", asJane); status != 200 {
			t.Errorf("%s: %d %s", path, status, answer)
		}
	}

	for _, path := range []string{"/v1.56/networks/blog_default", "/v1.56/networks/" + blogNet, "/v1.56/volumes/blog_data", "/v1.56/volumes/nothing"} {
		if status, answer := send(t, server, "GET", path, "", asJane); status != http.StatusNotFound {
			t.Errorf("%s: %d %s", path, status, answer)
		}
	}
}
