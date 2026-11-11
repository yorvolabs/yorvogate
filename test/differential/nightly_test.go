package differential

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

// The nightly leg (CI's differential-nightly job; YGD_DOCKER is a real Docker's socket): the same
// variants, through the same gate, to a real Docker Engine of the version the recorder's code is.
//
//   - Status class: every variant the gate forwards is read by the recorder (moby's code, or a
//     stand-in), or refused by it before any backend method. The real daemon must agree: refused
//     at parse is a 400, anything else (2xx, 404, 409, a request still being served) is read. A
//     disagreement is drift between the recorder and the Engine, by name; the six stand-ins are
//     counted, as this is their only check against a real daemon.
//   - State: what a base that creates something made is the scope's, and every attack, however
//     written, is refused by the gate and leaves nothing behind.
func TestAgainstARealDocker(t *testing.T) {
	socket := os.Getenv("YGD_DOCKER")
	if socket == "" {
		t.Skip("YGD_DOCKER (a real Docker's socket) isn't set: the nightly leg")
	}

	w := newWorld(t, socket)
	recorder := newSuite(t)
	front, _ := startGate(t, socket)
	f := startFetches(t)

	compared := map[string]int{}

	for _, version := range []string{"1.56", "1.44"} {
		for _, b := range bases {
			for _, v := range append([]variant{{"base", "as written", atVersion(b.req(t), version)}}, variants(atVersion(b.req(t), version), f.url(), false)...) {
				rec := recorder.send(v.req)
				if rec.kind == refusedByGate {
					continue
				}

				status, message := sendTo(front, w.real(v.req), 3*time.Second)
				w.check(b.endpoint, v, status)
				w.restore()

				recRefused := rec.kind == refusedByDocker
				realRefused := status == http.StatusBadRequest

				// A body shorter than its Content-Length, on a stream the gate passes on as it comes
				// (archive-put): whether Docker answers before the gate's transport sees the shortfall
				// is a race. Either way Docker acts on at most the bytes the client sent.
				if v.class == "framing" && v.name == "long" && message == "yorvogate: Docker didn't answer" {
					w.restore()

					continue
				}

				switch {
				case strings.HasPrefix(message, "yorvogate: "):
					t.Errorf("v%s %s, %s (%s): the gate in front of the real Docker refused what it forwards to the recorder: %d %s", version, b.endpoint, v.class, v.name, status, message)
				case recRefused != realRefused:
					t.Errorf("v%s %s, %s (%s): the recorder %s, the real Docker answered %d %s", version, b.endpoint, v.class, v.name, rec, status, message)
				}

				compared[b.endpoint]++
			}
		}
	}

	for _, e := range standIns {
		if compared[e] == 0 {
			t.Errorf("stand-in %s: no variant compared with the real Docker", e)
		} else {
			t.Logf("stand-in %s: %d variants compared with the real Docker", e, compared[e])
		}
	}

	for _, a := range attacks {
		for _, v := range append([]variant{{"plain", "as written", a.req(t)}}, variants(a.req(t), f.url(), true)...) {
			status, message := sendTo(front, w.real(v.req), 3*time.Second)
			if !strings.HasPrefix(message, "yorvogate: ") {
				t.Errorf("attack %s, %s, %s (%s): not refused by the gate: %d %s", a.endpoint, a.name, v.class, v.name, status, message)
				w.restore()
			}
		}
	}

	if left := w.forbidden(); len(left) > 0 {
		t.Errorf("an attack left something behind: %v", left)
	}

	// What the gate leaves free because Docker refuses it (internal/gate/fields.go, IPAMConfig): an
	// address outside the network's subnet. A Docker that stopped refusing it would make it the
	// gate's to check.
	for field, value := range map[string]string{"Gateway": `"10.98.0.1"`, "IPRange": `"10.98.0.0/28"`, "AuxiliaryAddresses": `{"x":"10.98.0.5"}`} {
		body := `{"Name":"jane_new","Labels":{"com.docker.compose.project":"jane","` + worldLabel + `":"1"},"IPAM":{"Config":[{"Subnet":"10.99.0.0/24","` + field + `":` + value + `}]}}`

		status, message := sendTo(front, w.real(asJane("POST", "/v1.56/networks/create", "application/json", []byte(body))), 3*time.Second)
		if strings.HasPrefix(message, "yorvogate: ") || status/100 != 4 || !strings.Contains(message, "parent subnet 10.99.0.0/24 doesn't contain") {
			t.Errorf("IPAM %s outside the subnet: %d %s; want the gate to forward it, and Docker to refuse it (its parent subnet doesn't contain it)", field, status, message)
			w.restore()
		}
	}

	if n := f.count.Load(); n != 0 {
		t.Errorf("the real Docker fetched an import %d times", n)
	}
}

// TestTheEscapesWouldWorkWithoutTheGate is the non-vacuity control (0.3-g, part 2): on the raw
// daemon socket the gate-relevant SandboxEscapeBench escapes really reach the host, and through a
// scope the gate refuses the request that enables them. Without this, "refused" could pass by doing
// nothing. The pure-API scenarios (docker_socket and hostpath_etc reduce to binding the host
// filesystem; the volume two-step; privileged) run end to end; the kernel-flaw scenarios would test
// the runner's kernel, not the gate (0.3-g, D3).
func TestTheEscapesWouldWorkWithoutTheGate(t *testing.T) {
	socket := os.Getenv("YGD_DOCKER")
	if socket == "" {
		t.Skip("YGD_DOCKER (a real Docker's socket) isn't set: the nightly leg")
	}

	w := newWorld(t, socket)
	front, _ := startGate(t, socket)

	token := fmt.Sprintf("ygd-escaped-%d", time.Now().UnixNano())
	via := "/host/var/tmp/" + token // a path on the daemon's host, seen through a mount of / at /host
	lbl := `"Labels":{"` + worldLabel + `":"1"}`

	// escapeRun creates (with a TTY, so logs are raw), starts and waits for a container on the RAW
	// socket, and returns its logs. Labelled, so the world's cleanup removes it.
	escapeRun := func(name, body string) string {
		w.api("DELETE", "/v1.56/containers/"+name+"?force=1", "")
		if status, b := w.api("POST", "/v1.56/containers/create?name="+name, body); status != http.StatusCreated {
			t.Fatalf("%s: the raw socket wouldn't create it: %d %s", name, status, b)
		}
		if status, b := w.api("POST", "/v1.56/containers/"+name+"/start", ""); status/100 != 2 {
			t.Fatalf("%s: the raw socket wouldn't start it: %d %s", name, status, b)
		}
		w.api("POST", "/v1.56/containers/"+name+"/wait", "")
		_, logs := w.api("GET", "/v1.56/containers/"+name+"/logs?stdout=1&stderr=1", "")

		return logs
	}

	// jane's own container.create, its host configuration the base with more (as the corpus's janeHost)
	janeBody := func(more string) string {
		return `{"Image":"alpine:3.22",` + own + `,"HostConfig":{"NetworkMode":"jane_default","CapDrop":["ALL"],"SecurityOpt":["no-new-privileges"],` + more + `}}`
	}

	gateRefuses := func(desc, method, target, body string) {
		status, message := sendTo(front, w.real(asJane(method, target, "application/json", []byte(body))), 3*time.Second)
		if !strings.HasPrefix(message, "yorvogate: ") {
			t.Errorf("%s wasn't refused by the gate: %d %s", desc, status, message)
		}

		w.restore()
	}

	t.Cleanup(func() {
		// Remove the escape containers first (a container holding the volume would block its delete),
		// then unplant the host file (through a bind of /, the same reach, as teardown), then the volume.
		for _, name := range []string{"ygd-escape-bind", "ygd-escape-vol-c", "ygd-escape-priv", "ygd-escape-rm"} {
			w.api("DELETE", "/v1.56/containers/"+name+"?force=1", "")
		}

		w.api("POST", "/v1.56/containers/create?name=ygd-escape-rm", `{"Image":"alpine:3.22","Tty":true,"Cmd":["rm","-f","`+via+`"],`+lbl+`,"HostConfig":{"Binds":["/:/host"]}}`)
		w.api("POST", "/v1.56/containers/ygd-escape-rm/start", "")
		w.api("POST", "/v1.56/containers/ygd-escape-rm/wait", "")
		w.api("DELETE", "/v1.56/containers/ygd-escape-rm?force=1", "")
		w.api("DELETE", "/v1.56/volumes/ygd-escape-vol?force=1", "")
	})

	// 1. docker_socket and hostpath_etc reduce to binding the host filesystem in: on the raw socket a
	// container writes and reads a token on the host; through a scope the create is refused.
	if logs := escapeRun("ygd-escape-bind", `{"Image":"alpine:3.22","Tty":true,"Cmd":["sh","-c","echo `+token+` > `+via+`; cat `+via+`"],`+lbl+`,"HostConfig":{"Binds":["/:/host"]}}`); !strings.Contains(logs, token) {
		t.Errorf("the host-bind escape didn't reach the host on the raw socket (control): %q", logs)
	}

	gateRefuses("the host-bind create", "POST", "/v1.56/containers/create?name=jane-x", janeBody(`"Binds":["/:/host"]`))

	// 2. the volume two-step (B2): a local volume with driver options binds the host root; mounted, it
	// reads the token planted above. Through a scope the volume.create is refused, before any mount.
	w.api("DELETE", "/v1.56/volumes/ygd-escape-vol?force=1", "")
	if status, b := w.api("POST", "/v1.56/volumes/create", `{"Name":"ygd-escape-vol","Driver":"local","DriverOpts":{"type":"none","o":"bind","device":"/"},`+lbl+`}`); status != http.StatusCreated {
		t.Fatalf("the raw socket wouldn't create the host-binding volume: %d %s", status, b)
	}

	if logs := escapeRun("ygd-escape-vol-c", `{"Image":"alpine:3.22","Tty":true,"Cmd":["cat","`+via+`"],`+lbl+`,"HostConfig":{"Mounts":[{"Type":"volume","Source":"ygd-escape-vol","Target":"/host"}]}}`); !strings.Contains(logs, token) {
		t.Errorf("the volume two-step didn't reach the host on the raw socket (control): %q", logs)
	}

	gateRefuses("the volume two-step", "POST", "/v1.56/volumes/create", `{"Name":"jane_new","Driver":"local","DriverOpts":{"type":"none","o":"bind","device":"/"},`+own+`}`)

	// 3. privileged: the raw daemon accepts and runs a privileged container here, so the runner permits
	// it and the gate's refusal is meaningful; through a scope the create is refused.
	if logs := escapeRun("ygd-escape-priv", `{"Image":"alpine:3.22","Tty":true,"Cmd":["sh","-c","echo `+token+`"],`+lbl+`,"HostConfig":{"Privileged":true}}`); !strings.Contains(logs, token) {
		t.Errorf("the raw socket wouldn't run a privileged container (control): %q", logs)
	}

	gateRefuses("the privileged create", "POST", "/v1.56/containers/create?name=jane-x", janeBody(`"Privileged":true`))
}

// world is scope jane's objects and blog's on a real Docker, labelled to be removed after.
type world struct {
	t      testing.TB
	socket string
	execs  map[string]string // the corpus's exec names, and their IDs
}

const worldLabel = "yorvogate.differential"

func newWorld(t testing.TB, socket string) *world {
	t.Helper()

	w := &world{t: t, socket: socket, execs: map[string]string{}}
	t.Cleanup(w.remove)

	w.remove()

	if status, body := w.api("POST", "/v1.56/images/create?fromImage=alpine&tag=3.22", ""); status != http.StatusOK {
		t.Fatalf("pulling alpine:3.22: %d %s", status, body)
	}

	w.restore()

	return w
}

// api is a request to the real Docker straight, as its owner.
func (w *world) api(method, path, body string) (int, string) {
	w.t.Helper()

	r := request{method: method, target: path, header: [][2]string{{"Host", "docker"}, {"User-Agent", "yorvogate-differential"}}}
	if body != "" {
		r.header = append(r.header, [2]string{"Content-Type", "application/json"})
		r.body = []byte(body)
	}

	status, _, body := exchange("unix:"+w.socket, r, 2*time.Minute)

	return status, body
}

// restore makes the world as it was: jane's and blog's objects there, running, named as they
// were; and what a base created gone.
func (w *world) restore() {
	w.t.Helper()

	for _, gone := range []string{"/containers/jane-web-1?force=1", "/containers/jane-x?force=1", "/containers/blog-x?force=1"} {
		w.api("DELETE", "/v1.56"+gone, "")
	}

	for _, gone := range []string{"/networks/jane_new", "/networks/blog_new", "/volumes/jane_new?force=1", "/volumes/blog_new?force=1",
		"/images/quire-sites/jane/app:2?force=1", "/images/quire-sites/blog/app:2?force=1", "/images/quire-sites/blog/x:1?force=1", "/images/postgres:18?force=1"} {
		w.api("DELETE", "/v1.56"+gone, "")
	}

	for _, s := range []string{"jane", "blog"} {
		labels := fmt.Sprintf(`{"com.docker.compose.project":%q,%q:"1"}`, s, worldLabel)

		if status, _ := w.api("GET", "/v1.56/images/quire-sites/"+s+"/app:1/json", ""); status != http.StatusOK {
			w.api("POST", "/v1.56/images/alpine:3.22/tag?repo=quire-sites/"+s+"/app&tag=1", "")
		}

		if status, _ := w.api("GET", "/v1.56/networks/"+s+"_default", ""); status != http.StatusOK {
			w.api("POST", "/v1.56/networks/create", fmt.Sprintf(`{"Name":"%s_default","Labels":%s}`, s, labels))
		}

		if status, _ := w.api("GET", "/v1.56/volumes/"+s+"_data", ""); status != http.StatusOK {
			w.api("POST", "/v1.56/volumes/create", fmt.Sprintf(`{"Name":"%s_data","Labels":%s}`, s, labels))
		}

		name := s + "-php-1"
		if status, _ := w.api("GET", "/v1.56/containers/"+name+"/json", ""); status != http.StatusOK {
			if status, _ := w.api("GET", "/v1.56/containers/"+s+"-php-2/json", ""); status == http.StatusOK {
				w.api("POST", "/v1.56/containers/"+s+"-php-2/rename?name="+name, "")
			} else {
				w.api("POST", "/v1.56/containers/create?name="+name, fmt.Sprintf(`{"Image":"alpine:3.22","Cmd":["sleep","86400"],"Labels":%s,"HostConfig":{"NetworkMode":"%s_default"}}`, labels, s))
			}
		}

		w.api("POST", "/v1.56/containers/"+name+"/unpause", "")
		w.api("POST", "/v1.56/containers/"+name+"/start", "")

		// An exec of its own, not yet started, for exec.start and exec.resize
		if status, body := w.api("POST", "/v1.56/containers/"+name+"/exec", `{"Cmd":["true"]}`); status == http.StatusCreated {
			var created struct{ ID string }
			_ = json.Unmarshal([]byte(body), &created)
			w.execs["exec-"+s] = created.ID
		}
	}
}

// remove removes what the world made.
func (w *world) remove() {
	_, body := w.api("GET", `/v1.56/containers/json?all=1&filters={"label":["`+worldLabel+`"]}`, "")

	var list []struct{ ID string }
	_ = json.Unmarshal([]byte(body), &list)

	for _, c := range list {
		w.api("DELETE", "/v1.56/containers/"+c.ID+"?force=1", "")
	}

	for _, name := range []string{"jane-web-1", "jane-x", "blog-x", "jane-php-2", "blog-php-2"} {
		w.api("DELETE", "/v1.56/containers/"+name+"?force=1", "")
	}

	for _, s := range []string{"jane", "blog"} {
		w.api("DELETE", "/v1.56/networks/"+s+"_default", "")
		w.api("DELETE", "/v1.56/networks/"+s+"_new", "")
		w.api("DELETE", "/v1.56/volumes/"+s+"_data?force=1", "")
		w.api("DELETE", "/v1.56/volumes/"+s+"_new?force=1", "")

		for _, tag := range []string{"app:1", "app:2", "x:1"} {
			w.api("DELETE", "/v1.56/images/quire-sites/"+s+"/"+tag+"?force=1", "")
		}
	}

	w.api("DELETE", "/v1.56/images/postgres:18?force=1", "")
}

// real is a corpus request for the real Docker: its execs by their IDs.
func (w *world) real(r request) request {
	c := r.clone()
	for name, id := range w.execs {
		c.target = strings.ReplaceAll(c.target, "/exec/"+name+"/", "/exec/"+id+"/")
	}

	return c
}

// check is the state oracle: what a base that creates something made, when it did, is the scope's.
func (w *world) check(endpoint string, v variant, status int) {
	w.t.Helper()

	if status/100 != 2 {
		return
	}

	inspect := func(path string, into any) bool {
		code, body := w.api("GET", path, "")
		if code != http.StatusOK {
			return false
		}

		return json.Unmarshal([]byte(body), into) == nil
	}

	var made struct {
		Labels map[string]string
		Config struct {
			Labels map[string]string
		}
		HostConfig struct {
			Privileged  bool
			Binds       []string
			NetworkMode string
		}
	}

	switch endpoint {
	case "container.create":
		if !inspect("/v1.56/containers/jane-web-1/json", &made) || made.Config.Labels["com.docker.compose.project"] != "jane" ||
			made.HostConfig.Privileged || len(made.HostConfig.Binds) > 0 || made.HostConfig.NetworkMode != "jane_default" {
			w.t.Errorf("%s, %s (%s): what Docker made isn't jane's, as the gate allowed it: %+v", endpoint, v.class, v.name, made)
		}
	case "network.create":
		if !inspect("/v1.56/networks/jane_new", &made) || made.Labels["com.docker.compose.project"] != "jane" {
			w.t.Errorf("%s, %s (%s): the network Docker made isn't jane's: %+v", endpoint, v.class, v.name, made)
		}
	case "volume.create":
		if !inspect("/v1.56/volumes/jane_new", &made) || made.Labels["com.docker.compose.project"] != "jane" {
			w.t.Errorf("%s, %s (%s): the volume Docker made isn't jane's: %+v", endpoint, v.class, v.name, made)
		}
	case "image.tag", "image.load":
		if !inspect("/v1.56/images/quire-sites/jane/app:2/json", &made) {
			w.t.Errorf("%s, %s (%s): no quire-sites/jane/app:2", endpoint, v.class, v.name)
		}
	}
}

// forbidden is what an attack would have made, if any is there.
func (w *world) forbidden() []string {
	var left []string

	for _, path := range []string{"/containers/jane-x/json", "/containers/blog-x/json", "/networks/blog_new", "/volumes/blog_new",
		"/images/quire-sites/blog/app:2/json", "/images/quire-sites/blog/x:1/json", "/images/postgres:18/json"} {
		if status, _ := w.api("GET", "/v1.56"+path, ""); status == http.StatusOK {
			left = append(left, path)
		}
	}

	slices.Sort(left)

	return left
}

// sendTo writes a request to an address (host:port, or unix:path) and reads the answer's status and
// message. A request that's still being served when the time is up (a stream, a wait) is 0, "".
func sendTo(address string, r request, timeout time.Duration) (int, string) {
	status, message, _ := exchange(address, r, timeout)

	return status, message
}

// exchange is sendTo with the answer's body too.
func exchange(address string, r request, timeout time.Duration) (int, string, string) {
	network := "tcp"
	if path, ok := strings.CutPrefix(address, "unix:"); ok {
		network, address = "unix", path
	}

	conn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(context.Background(), network, address)
	if err != nil {
		return -1, err.Error(), ""
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	if _, err := conn.Write(r.wire()); err != nil {
		return -1, err.Error(), ""
	}

	if c, ok := conn.(interface{ CloseWrite() error }); ok && r.framing == "long" {
		_ = c.CloseWrite()
	}

	res, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return 0, "", ""
	}
	defer res.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(res.Body, 16<<20))

	var answer struct{ Message string }
	if json.Unmarshal(body, &answer) == nil && answer.Message != "" {
		return res.StatusCode, answer.Message, string(body)
	}

	return res.StatusCode, "", string(body)
}
