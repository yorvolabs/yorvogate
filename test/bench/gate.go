package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// The API version every request names: the newest YorvoGate serves.
const api = "/v1.56"

// The owner label of every scope's objects, and of the host's that are no scope's.
const ownerLabel = "org.yorvolabs.bench"

// Scopes are named site00000, site00001, …: on the token listener a scope's objects are owned by
// t<name>, on the scope sockets' by s<name>, so the two never share a name.
func scopeName(i int) string { return fmt.Sprintf("site%05d", i) }

func tokenOf(name string) string { return "token-" + name + "-0123456789abcdef" }

// gate is a running YorvoGate: a token listener (tokens, on loopback TCP), a scope-sockets listener
// (sockets), a trusted listener for scope status and the admin listener, every one on a folder of
// its own.
type gate struct {
	cmd     *exec.Cmd
	dir     string
	tcp     string
	trusted string
	admin   string
	log     *os.File
	scopes  int
	took    time.Duration
}

// The policy a scope's containers are held to: Quire Server's (test/conformance/quire), so a create
// is checked as a site's is. Its sites' images are protected as Quire's are: a scope sees its own
// and the host's alpine, not the 10,000 others under bench/.
const containers = `    containers:
      capabilities: [NET_BIND_SERVICE, CHOWN, DAC_OVERRIDE, FOWNER, SETGID, SETUID]
      drop_all_capabilities: true
      no_new_privileges: true
      ulimits: [nofile, nproc, core, stack]
      max_memory: 68719476736
      max_pids: 4096
      protected_images: [bench/]
`

// writeGate writes a configuration with n scopes on each scoped listener, and returns where.
func writeGate(o options, n int) (*gate, string, error) {
	dir, err := os.MkdirTemp(o.tmp, "gate")
	if err != nil {
		return nil, "", err
	}

	for _, d := range []string{"tokens", "socket-scopes", "sockets", "spool"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o700); err != nil {
			return nil, "", err
		}
	}

	for i := range n {
		name := scopeName(i)
		if err := writeScope(dir, "tokens", name, "t"+name, tokenOf(name)); err != nil {
			return nil, "", err
		}

		if err := writeScope(dir, "socket-scopes", name, "s"+name, ""); err != nil {
			return nil, "", err
		}
	}

	address, err := freeAddress()
	if err != nil {
		return nil, "", err
	}

	daemon := ""
	if o.withoutLSM {
		daemon = "daemon: {without_lsm: true}\n"
	}

	config := fmt.Sprintf(`version: 1
upstream: unix://%[1]s
state_file: %[2]s/state.json
spool: {dir: %[2]s/spool}
%[3]sadmin: {address: 'unix://%[2]s/admin.sock'}
listeners:
  - name: trusted
    address: unix://%[2]s/trusted.sock
    mode: trusted
    allow: {system: read}
  - name: tokens
    address: tcp://%[4]s
    mode: scoped
    scopes: %[2]s/tokens
%[5]s  - name: sockets
    scope_sockets: %[2]s/sockets
    mode: scoped
    scopes: %[2]s/socket-scopes
%[5]s`, o.docker, dir, daemon, address, containers)

	path := filepath.Join(dir, "yorvogate.yaml")
	if err := os.WriteFile(path, []byte(config), 0o600); err != nil {
		return nil, "", err
	}

	return &gate{dir: dir, tcp: address, trusted: filepath.Join(dir, "trusted.sock"), admin: filepath.Join(dir, "admin.sock"), scopes: n}, path, nil
}

// writeScope writes a scope file.
func writeScope(dir, folder, name, owner, tok string) error {
	_, err := writeScopeFile(dir, folder, name, owner, tok, "")

	return err
}

// writeScopeFile writes a scope file, extra fields added, by renaming a complete one over it, and
// returns its SHA-256.
func writeScopeFile(dir, folder, name, owner, tok, extra string) (string, error) {
	file := `{"version": 1, "owner": {"label": "` + ownerLabel + `", "value": "` + owner + `"}, "prefixes": ["` + owner + `-", "` + owner + `_"], "images": ["bench/` + owner + `/"]`
	if tok != "" {
		sum := sha256.Sum256([]byte(tok))
		file += `, "token_sha256": "` + hex.EncodeToString(sum[:]) + `"`
	}

	file += extra + "}"

	path := filepath.Join(dir, folder, name+".json")
	if err := os.WriteFile(path+".new", []byte(file), 0o600); err != nil {
		return "", err
	}

	sum := sha256.Sum256([]byte(file))

	return hex.EncodeToString(sum[:]), os.Rename(path+".new", path)
}

// check runs yorvogate check on the configuration, timed.
func check(o options, path string) (time.Duration, error) {
	started := time.Now()

	out, err := exec.Command(o.binary, "check", "--config", path).CombinedOutput()
	if err != nil {
		return 0, fmt.Errorf("yorvogate check: %v: %s", err, out)
	}

	return time.Since(started), nil
}

// startGate starts serve on the configuration, and returns once every listener is open, the last
// scope's socket included, and a scope's request is decided (Docker's defaults are read). took is
// how long until the sockets and listeners were open.
func startGate(o options, g *gate, path string) error {
	log, err := os.Create(filepath.Join(g.dir, "gate.log"))
	if err != nil {
		return err
	}

	g.log = log
	g.cmd = exec.Command(o.binary, "serve", "--config", path)
	g.cmd.Stdout, g.cmd.Stderr = log, log
	g.cmd.Env = append(os.Environ(), o.gateEnv...)

	started := time.Now()
	if err := g.cmd.Start(); err != nil {
		return err
	}

	last := filepath.Join(g.dir, "sockets", scopeName(g.scopes-1)+".sock")

	for {
		_, err := os.Stat(last)
		if err == nil {
			if c, err := net.Dial("tcp", g.tcp); err == nil {
				_ = c.Close()

				break
			}
		}

		if time.Since(started) > 10*time.Minute {
			g.stop()

			return fmt.Errorf("the gate with %d scopes isn't up after 10 minutes:\n%s", g.scopes, g.lastLog())
		}

		time.Sleep(10 * time.Millisecond)
	}

	g.took = time.Since(started)

	// Decided means Docker's defaults are read: a refusal for the endpoint, not for the defaults
	for deadline := time.Now().Add(time.Minute); ; time.Sleep(50 * time.Millisecond) {
		if status, _, _ := refusedByToken(g, scopeName(0)); status == http.StatusForbidden {
			return nil
		}

		if time.Now().After(deadline) {
			g.stop()

			return fmt.Errorf("the gate doesn't decide a scope's request after a minute:\n%s", g.lastLog())
		}
	}
}

func (g *gate) stop() {
	if g.cmd != nil && g.cmd.Process != nil {
		_ = g.cmd.Process.Signal(os.Interrupt)
		_ = g.cmd.Wait()
	}

	if g.log != nil {
		_ = g.log.Close()
	}

	_ = os.RemoveAll(g.dir)
}

func (g *gate) lastLog() string {
	content, err := os.ReadFile(filepath.Join(g.dir, "gate.log"))
	if err != nil {
		return ""
	}

	lines := strings.Split(string(content), "\n")

	return strings.Join(lines[max(0, len(lines)-30):], "\n")
}

// memory is the gate's resident memory now and at its peak (VmRSS, VmHWM), in bytes.
func (g *gate) memory() (rss, peak int64) {
	status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", g.cmd.Process.Pid))
	if err != nil {
		return 0, 0
	}

	for _, line := range strings.Split(string(status), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}

		kb, _ := strconv.ParseInt(f[1], 10, 64)

		switch f[0] {
		case "VmRSS:":
			rss = kb * 1024
		case "VmHWM:":
			peak = kb * 1024
		}
	}

	return rss, peak
}

// heap is the gate's Go heap (go_memstats_heap_alloc_bytes), from its admin listener.
func (g *gate) heap() int64 {
	res, err := unixClient(g.admin).Get("http://admin/metrics")
	if err != nil {
		return 0
	}

	defer res.Body.Close()

	scanner := bufio.NewScanner(res.Body)
	for scanner.Scan() {
		if v, ok := strings.CutPrefix(scanner.Text(), "go_memstats_heap_alloc_bytes "); ok {
			f, _ := strconv.ParseFloat(v, 64)

			return int64(f)
		}
	}

	return 0
}

// refusedByToken sends a request the scope may not make (GET /swarm: scope.endpoint-not-allowed),
// decided without Docker, on a connection of its own.
func refusedByToken(g *gate, name string) (int, time.Duration, error) {
	c, err := net.Dial("tcp", g.tcp)
	if err != nil {
		return 0, 0, err
	}

	defer c.Close()

	started := time.Now()

	if _, err := fmt.Fprintf(c, "GET %s/swarm HTTP/1.1\r\nHost: docker\r\nConnection: close\r\nX-YorvoGate-Scope: %s\r\nX-YorvoGate-Token: %s\r\n\r\n", api, name, tokenOf(name)); err != nil {
		return 0, 0, err
	}

	res, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		return 0, 0, err
	}

	_, _ = io.Copy(io.Discard, res.Body)

	return res.StatusCode, time.Since(started), nil
}

// unixClient is a client of one unix socket, its connections kept.
func unixClient(socket string) *http.Client {
	return &http.Client{Timeout: 10 * time.Minute, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socket)
		},
		MaxIdleConnsPerHost: 200,
	}}
}

// tokenClient is a scope's client of the token listener, its connections kept.
func tokenClient(address, name string) *http.Client {
	return &http.Client{Timeout: 10 * time.Minute, Transport: headers{&http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", address)
		},
		MaxIdleConnsPerHost: 200,
	}, name}}
}

type headers struct {
	http.RoundTripper
	scope string
}

func (h headers) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("X-YorvoGate-Scope", h.scope)
	r.Header.Set("X-YorvoGate-Token", tokenOf(h.scope))

	return h.RoundTripper.RoundTrip(r)
}

func freeAddress() (string, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}

	defer l.Close()

	return l.Addr().String(), nil
}
