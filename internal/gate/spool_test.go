package gate

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/yorvolabs/yorvogate/internal/config"
)

// The image load path's bounds (0.4-d1): a load spools to the configured folder only, within a
// budget shared by every scope, a few at a time, and its archive is read within bounds on what it
// decompresses to and how many entries it has. Each test goes through the HTTP handler.

// spoolGate serves one scoped listener with two scopes, jane and blog, and the spool settings given
// (YAML under `spool:`, its folder added). It gives the server and the spool's folder.
func spoolGate(t *testing.T, d *docker, spool string) (*httptest.Server, string) {
	t.Helper()
	scopes, dir := t.TempDir(), t.TempDir()

	for name, secret := range map[string]string{"jane": token, "blog": blogToken} {
		sum := sha256.Sum256([]byte(secret))
		file := `{"token_sha256": "` + hex.EncodeToString(sum[:]) + `", "owner": {"label": "com.docker.compose.project", "value": "` + name + `"}, "prefixes": ["` + name + `-", "` + name + `_"], "images": ["quire-sites/` + name + `/"]}`

		if err := os.WriteFile(filepath.Join(scopes, name+".json"), []byte(file), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	c, err := config.Parse([]byte(`
version: 1
upstream: unix://` + d.socket + `
load_limit: 2097152
spool:
  dir: ` + dir + `
` + spool + `
listeners:
  - name: sites
    address: tcp://127.0.0.1:2376
    mode: scoped
    scopes: ` + scopes + `
`))
	if err != nil {
		t.Fatal(err)
	}

	registry := Registry(c)
	if err := registry.Reload(); err != nil {
		t.Fatal(err)
	}

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := httptest.NewServer(New(c, c.Listeners[0], NewUpstream(c, log), registry, readDefaults(c), NewSpool(c), log))
	t.Cleanup(server.Close)

	return server, dir
}

// loadFrom sends an image load whose body is r (chunked, no Content-Length, when it's a pipe), and
// gives the answer on a channel.
type answered struct {
	status int
	header http.Header
	body   string
}

func loadFrom(t *testing.T, server *httptest.Server, header map[string]string, r io.Reader) <-chan answered {
	t.Helper()
	done := make(chan answered, 1)

	go func() {
		req, _ := http.NewRequest("POST", server.URL+"/v1.56/images/load", r)
		for k, v := range header {
			req.Header.Set(k, v)
		}

		client := &http.Client{Timeout: 20 * time.Second}

		res, err := client.Do(req)
		if err != nil {
			done <- answered{status: -1, body: err.Error()}

			return
		}
		defer res.Body.Close()

		body, _ := io.ReadAll(res.Body)
		done <- answered{status: res.StatusCode, header: res.Header, body: string(body)}
	}()

	return done
}

func wait(t *testing.T, c <-chan answered) answered {
	t.Helper()

	select {
	case a := <-c:
		return a
	case <-time.After(30 * time.Second):
		t.Fatal("no answer in 30 s")
	}

	return answered{}
}

// started is the scope of the next load that starts spooling.
func started(t *testing.T, spooling <-chan string) string {
	t.Helper()

	select {
	case scope := <-spooling:
		return scope
	case <-time.After(5 * time.Second):
		t.Fatal("no load started spooling in 5 s")
	}

	return ""
}

// emptied waits until the spool's folder is empty, each time a load is cleaned up (onUnspool), or
// fails after 5 s: a load's answer reaches the client before its file is removed.
func emptied(t *testing.T, dir string, unspooled <-chan string) {
	t.Helper()
	timeout := time.After(5 * time.Second)

	for len(files(t, dir)) > 0 {
		select {
		case <-unspooled:
		case <-timeout:
			t.Errorf("the spool kept %v", files(t, dir))

			return
		}
	}
}

// files lists what's in a folder.
func files(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}

	return names
}

// padded is a valid archive of about n bytes: one file no index refers to, so it's loaded.
func padded(t *testing.T, n int) []byte {
	t.Helper()

	return archive(t, entry{name: "padding", content: strings.Repeat("x", n)})
}

// allocated is how many bytes the process allocated while f ran.
func allocated(f func()) uint64 {
	var before, after runtime.MemStats

	runtime.GC()
	runtime.ReadMemStats(&before)
	f()
	runtime.ReadMemStats(&after)

	return after.TotalAlloc - before.TotalAlloc
}

// A small gzip that decompresses to far more than any image would is refused once it has
// decompressed to its bound, not read to its end; nothing reaches Docker.
func TestLoadByteBomb(t *testing.T) {
	d := startDocker(t)
	server, dir := spoolGate(t, d, "")

	var raw bytes.Buffer
	gz := gzip.NewWriter(&raw)
	tw := tar.NewWriter(gz)
	size := int64(256 << 20)
	_ = tw.WriteHeader(&tar.Header{Name: "padding", Mode: 0o644, Size: size, Typeflag: tar.TypeReg})
	zeros := make([]byte, 1<<20)
	for written := int64(0); written < size; written += int64(len(zeros)) {
		_, _ = tw.Write(zeros)
	}
	_ = tw.Close()
	_ = gz.Close()

	before := d.count()
	start := time.Now()

	var status int
	var answer string
	bytes := allocated(func() {
		status, answer = send(t, server, "POST", "/v1.56/images/load", raw.String(), asJane)
	})

	if status != http.StatusRequestEntityTooLarge || !strings.Contains(answer, "decompresses to more than") {
		t.Fatalf("a %d-byte gzip of %d MiB: %d %s", raw.Len(), size>>20, status, answer)
	}

	if d.count() != before {
		t.Error("the bomb reached Docker")
	}

	if bytes > 32<<20 && !raceBuild {
		t.Errorf("reading the bomb allocated %d MiB", bytes>>20)
	}

	t.Logf("refused after %v, %d KiB allocated", time.Since(start), bytes>>10)

	if left := files(t, dir); len(left) != 0 {
		t.Errorf("the spool kept %v", left)
	}
}

// An archive of a great many empty entries is refused at the entry bound: the maps that hold each
// entry's digest don't grow past it.
func TestLoadEntryBomb(t *testing.T) {
	d := startDocker(t)
	server, _ := spoolGate(t, d, "")

	var raw bytes.Buffer
	gz := gzip.NewWriter(&raw)
	tw := tar.NewWriter(gz)
	for i := range maxEntries + 10 {
		_ = tw.WriteHeader(&tar.Header{Name: "e/" + hex.EncodeToString([]byte{byte(i >> 16), byte(i >> 8), byte(i)}), Mode: 0o644, Typeflag: tar.TypeReg})
	}
	_ = tw.Close()
	_ = gz.Close()

	before := d.count()

	var status int
	var answer string
	bytes := allocated(func() {
		status, answer = send(t, server, "POST", "/v1.56/images/load", raw.String(), asJane)
	})

	if status != http.StatusRequestEntityTooLarge || !strings.Contains(answer, fmt.Sprintf("more than %d entries", maxEntries)) {
		t.Fatalf("%d entries: %d %s", maxEntries+10, status, answer)
	}

	if d.count() != before {
		t.Error("the archive reached Docker")
	}

	// About 1.5 KiB per entry read (its tar header, hash and map keys), most of it garbage at once
	if bytes > 32<<20 && !raceBuild {
		t.Errorf("reading %d entries allocated %d MiB", maxEntries, bytes>>20)
	}

	t.Logf("%d KiB allocated", bytes>>10)
}

// Loads run a few at a time across every scope, not one per scope: past spool.loads, a load waits
// a bounded time, then is told to retry. A waiting load has read nothing. The archive spools to the
// configured folder, never to TMPDIR.
func TestLoadsAtOnce(t *testing.T) {
	d := startDocker(t)
	server, dir := spoolGate(t, d, "  loads: 1")
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)

	spooling, unspooled := make(chan string, 4), make(chan string, 16)
	spoolingHook.Store(ptr(func(scope string) { spooling <- scope }))
	unspooledHook.Store(ptr(func(scope string) { unspooled <- scope }))
	defer func() { spoolingHook.Store(nil); unspooledHook.Store(nil) }()

	old := loadWait
	loadWait = 200 * time.Millisecond
	defer func() { loadWait = old }()

	archive := padded(t, 64<<10)
	pr, pw := io.Pipe()
	janes := loadFrom(t, server, asJane, pr)

	if _, err := pw.Write(archive[:1024]); err != nil {
		t.Fatal(err)
	}

	if scope := started(t, spooling); scope != "jane" {
		t.Fatalf("%s spooling, want jane", scope)
	}

	if got := files(t, dir); len(got) != 1 {
		t.Errorf("the spool holds %v while jane loads, want one file", got)
	}

	if got := files(t, tmp); len(got) != 0 {
		t.Errorf("TMPDIR holds %v", got)
	}

	blogs := wait(t, loadFrom(t, server, asBlog, bytes.NewReader(padded(t, 1024))))
	if blogs.status != http.StatusServiceUnavailable || !strings.Contains(blogs.body, "too many image loads at once") || blogs.header.Get("Retry-After") == "" {
		t.Errorf("blog's load while jane's runs: %d %v %s", blogs.status, blogs.header, blogs.body)
	}

	if _, err := pw.Write(archive[1024:]); err != nil {
		t.Fatal(err)
	}
	_ = pw.Close()

	if a := wait(t, janes); a.status != http.StatusOK {
		t.Errorf("jane's load: %d %s", a.status, a.body)
	}

	emptied(t, dir, unspooled)

	// And with the slot free, blog's loads
	if a := wait(t, loadFrom(t, server, asBlog, bytes.NewReader(padded(t, 1024)))); a.status != http.StatusOK {
		t.Errorf("blog's load after jane's: %d %s", a.status, a.body)
	}
}

// Every load's bytes come out of one budget, reserved as they arrive: two chunked loads that
// together pass it can't both spool. The one that can't reserve is told to retry; the other
// completes. A load that could never fit is refused for good (413), whether it says its size or
// not.
func TestLoadSpoolBudget(t *testing.T) {
	d := startDocker(t)
	server, dir := spoolGate(t, d, "  limit: 1572864\n  loads: 2")

	spooling, unspooled := make(chan string, 4), make(chan string, 16)
	spoolingHook.Store(ptr(func(scope string) { spooling <- scope }))
	unspooledHook.Store(ptr(func(scope string) { unspooled <- scope }))
	reserved := make(chan int64, 64)
	reservedHook.Store(ptr(func(scope string, held int64) {
		if scope == "jane" {
			select {
			case reserved <- held:
			default:
			}
		}
	}))
	defer func() { spoolingHook.Store(nil); unspooledHook.Store(nil); reservedHook.Store(nil) }()

	big := padded(t, 1000<<10)
	pr, pw := io.Pipe()
	janes := loadFrom(t, server, asJane, pr)

	// Jane's first 900 KiB, chunked, until the gate holds them all of the budget (onReserve: the
	// bytes may still be on their way when the pipe's write returns)
	go func() { _, _ = pw.Write(big[:900<<10]) }()
	started(t, spooling)

	for held := int64(0); held < 900<<10; {
		select {
		case held = <-reserved:
		case <-time.After(5 * time.Second):
			t.Fatalf("jane holds %d bytes of the budget, want 900 KiB", held)
		}
	}

	// Blog's, chunked too: it can't reserve past the budget while jane's holds 900 KiB.
	bpr, bpw := io.Pipe()
	blogs := loadFrom(t, server, asBlog, bpr)
	go func() { _, _ = bpw.Write(big); _ = bpw.Close() }()

	b := wait(t, blogs)
	_ = bpr.Close()
	if b.status != http.StatusServiceUnavailable || !strings.Contains(b.body, "the image spool is full") || b.header.Get("Retry-After") == "" {
		t.Errorf("blog's load past the budget: %d %v %s", b.status, b.header, b.body)
	}

	if _, err := pw.Write(big[900<<10:]); err != nil {
		t.Fatal(err)
	}
	_ = pw.Close()

	if a := wait(t, janes); a.status != http.StatusOK {
		t.Errorf("jane's load: %d %s", a.status, a.body)
	}

	// Never fits: a Content-Length above the budget, before anything is read
	huge := padded(t, 1600<<10)
	if status, answer := send(t, server, "POST", "/v1.56/images/load", string(huge), asJane); status != http.StatusRequestEntityTooLarge || !strings.Contains(answer, "larger than the image spool") {
		t.Errorf("an archive larger than the spool: %d %s", status, answer)
	}

	// ...and chunked, past the budget with nothing else reserved
	cpr, cpw := io.Pipe()
	chunked := loadFrom(t, server, asJane, cpr)
	go func() { _, _ = cpw.Write(huge); _ = cpw.Close() }()
	if a := wait(t, chunked); a.status != http.StatusRequestEntityTooLarge || !strings.Contains(a.body, "larger than the image spool") {
		t.Errorf("a chunked archive larger than the spool: %d %s", a.status, a.body)
	}
	_ = cpr.Close()

	emptied(t, dir, unspooled)
}

// An upload that stops arriving is given up after the stall timeout: its slot and its reservation
// are freed for the next.
func TestLoadStall(t *testing.T) {
	d := startDocker(t)
	server, dir := spoolGate(t, d, "  loads: 1")

	old := loadStall
	loadStall = 150 * time.Millisecond
	defer func() { loadStall = old }()

	unspooled := make(chan string, 16)
	unspooledHook.Store(ptr(func(scope string) { unspooled <- scope }))
	defer unspooledHook.Store(nil)

	pr, pw := io.Pipe()
	defer pw.Close()

	stalled := loadFrom(t, server, asJane, pr)
	if _, err := pw.Write(padded(t, 4096)[:1024]); err != nil {
		t.Fatal(err)
	}

	if a := wait(t, stalled); a.status != http.StatusBadRequest || !strings.Contains(a.body, "stopped arriving") {
		t.Errorf("a stalled upload: %d %s", a.status, a.body)
	}

	if a := wait(t, loadFrom(t, server, asBlog, bytes.NewReader(padded(t, 1024)))); a.status != http.StatusOK {
		t.Errorf("the next load: %d %s", a.status, a.body)
	}

	emptied(t, dir, unspooled)
}

// check and serve refuse a spool folder they can't write, the same way; check changes nothing.
func TestTheSpoolsFolder(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes any folder")
	}

	parse := func(dir string) *config.Config {
		c, err := config.Parse([]byte("version: 1\nupstream: unix:///var/run/docker.sock\nspool: {dir: " + dir + "}\nlisteners:\n  - {name: sites, address: 'tcp://127.0.0.1:2376', mode: scoped, scopes: /etc/s}\n"))
		if err != nil {
			t.Fatal(err)
		}

		return c
	}

	base := t.TempDir()
	fresh := filepath.Join(base, "a", "spool")

	if err := CheckSpool(parse(fresh)); err != nil {
		t.Errorf("check, a folder serve can make: %v", err)
	}

	if _, err := os.Stat(fresh); !os.IsNotExist(err) {
		t.Error("check made the folder")
	}

	if err := PrepareSpool(parse(fresh)); err != nil {
		t.Fatalf("serve: %v", err)
	}

	if info, err := os.Stat(fresh); err != nil || info.Mode().Perm() != 0o700 {
		t.Errorf("serve made %v (%v), want 0700", info, err)
	}

	// What a previous run left is removed
	left := filepath.Join(fresh, spoolPrefix+"123")
	_ = os.WriteFile(left, []byte("x"), 0o600)
	if err := PrepareSpool(parse(fresh)); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(left); !os.IsNotExist(err) {
		t.Error("a previous run's archive was kept")
	}

	locked := filepath.Join(base, "locked")
	_ = os.Mkdir(locked, 0o500)

	for _, dir := range []string{locked, filepath.Join(locked, "spool")} {
		if err := CheckSpool(parse(dir)); err == nil || !strings.Contains(err.Error(), "can't be written") {
			t.Errorf("check, %s: %v", dir, err)
		}

		if err := PrepareSpool(parse(dir)); err == nil || !strings.Contains(err.Error(), "spool.dir "+dir) {
			t.Errorf("serve, %s: %v", dir, err)
		}
	}

	// A trusted listener alone loads nothing through the spool: no folder needed
	c, err := config.Parse([]byte("version: 1\nupstream: unix:///var/run/docker.sock\nspool: {dir: " + locked + "}\nlisteners:\n  - {name: server, address: 'tcp://127.0.0.1:2375', mode: trusted, allow: {images: write}}\n"))
	if err != nil {
		t.Fatal(err)
	}

	if CheckSpool(c) != nil || PrepareSpool(c) != nil {
		t.Error("a trusted listener alone needs a spool")
	}
}

// The stall timeout is for silence, not the whole upload: one that keeps sending, slower than the
// timeout in all, is loaded.
func TestLoadSlowButSteady(t *testing.T) {
	d := startDocker(t)
	server, _ := spoolGate(t, d, "")

	old := loadStall
	loadStall = 400 * time.Millisecond
	defer func() { loadStall = old }()

	body := padded(t, 8<<10)
	pr, pw := io.Pipe()
	steady := loadFrom(t, server, asJane, pr)

	go func() {
		for i := 0; i < len(body); i += len(body) / 8 {
			_, _ = pw.Write(body[i:min(i+len(body)/8, len(body))])
			time.Sleep(100 * time.Millisecond) // a slow client: 2 stall timeouts in all, a quarter of one at a time
		}
		_ = pw.Close()
	}()

	if a := wait(t, steady); a.status != http.StatusOK {
		t.Errorf("a slow, steady upload: %d %s", a.status, a.body)
	}
}
