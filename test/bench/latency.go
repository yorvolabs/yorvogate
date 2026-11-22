package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// A, latency: each request through YorvoGate (on a scope's socket, and on the token listener) and
// straight to Docker, the same Docker and client code in one run, interleaved (the three in turn, in
// a rotating order), so the machine's noise falls on each alike.

// path is one way to Docker: direct, or a listener of the gate as one scope.
type path struct {
	name   string
	client *http.Client
	// A connection of its own (an exec's stream), and the headers it sends
	dial   func() (net.Conn, error)
	header string
	// Whose objects it acts on, and its running container
	owner   string
	running string
}

// request is one row of table A: a sample of it on a path, timed (what isn't timed, before and
// after, is the sample's own).
type request struct {
	name    string
	samples int
	sample  func(p path, i int) (time.Duration, error)
}

// latency measures A. Docker holds only the bench's containers until every other request is
// measured: a host's 10,000 images slow every request of Docker's, with the gate or without. Then,
// where loadImages is given, it loads them, and measures the image list.
func latency(o options, d *http.Client, tmp string, loadImages func() error) ([]Latency, error) {
	g, configPath, err := writeGate(o, 10)
	if err != nil {
		return nil, err
	}

	if err := startGate(o, g, configPath); err != nil {
		return nil, err
	}

	defer g.stop()

	name := scopeName(0)
	paths := []path{
		{name: "direct", client: d, dial: func() (net.Conn, error) { return net.Dial("unix", o.docker) }, owner: "s" + name},
		{name: "socket", client: unixClient(filepath.Join(g.dir, "sockets", name+".sock")), dial: func() (net.Conn, error) { return net.Dial("unix", filepath.Join(g.dir, "sockets", name+".sock")) }, owner: "s" + name},
		{name: "token", client: tokenClient(g.tcp, name), dial: func() (net.Conn, error) { return net.Dial("tcp", g.tcp) }, header: "X-YorvoGate-Scope: " + name + "\r\nX-YorvoGate-Token: " + tokenOf(name) + "\r\n", owner: "t" + name},
	}

	// The direct path acts on the socket scope's objects, under names of its own
	for _, owner := range []string{"s" + name, "t" + name} {
		running, err := prepareOwner(d, owner)
		if err != nil {
			return nil, err
		}

		for i := range paths {
			if paths[i].owner == owner {
				paths[i].running = running
			}
		}
	}

	// The host's other containers, no scope's: 200 in all
	for i := range 160 {
		if _, err := createContainer(d, "host", fmt.Sprintf("bench-host-l%03d", i)); err != nil {
			return nil, err
		}
	}

	requests := []request{
		{"GET /_ping", o.samples(2000, 300), get("/_ping")},
		{"GET /containers/json", o.samples(2000, 300), listContainers},
		{"GET /containers/{id}/json", o.samples(2000, 300), inspectContainer},
		{"POST /containers/create", o.samples(500, 50), createSample(d)},
		{"POST /containers/{id}/start", o.samples(500, 50), startSample(d)},
		{"exec: create, start, read", o.samples(300, 50), execSample},
	}

	if o.full {
		started := time.Now()

		big, diffID, err := layer(tmp, 1<<30)
		if err != nil {
			return nil, err
		}

		progress("the 1 GiB layer written in %v", time.Since(started).Round(time.Millisecond))
		requests = append(requests, request{"POST /images/load (1 GiB)", 5, loadSample(d, big, diffID)})
	}

	var rows []Latency

	for _, r := range requests {
		row, err := measureRequest(r, paths)
		if err != nil {
			return nil, fmt.Errorf("%s: %w\n%s", r.name, err, g.lastLog())
		}

		rows = append(rows, row...)
		progress("A %-28s %s", r.name, summary(row))
	}

	if loadImages == nil {
		return rows, nil
	}

	if err := loadImages(); err != nil {
		return nil, err
	}

	row, err := measureRequest(request{"GET /images/json", 20, listImages}, paths)
	if err != nil {
		return nil, fmt.Errorf("GET /images/json: %w\n%s", err, g.lastLog())
	}

	progress("A %-28s %s", "GET /images/json", summary(row))

	return append(rows, row...), nil
}

// measureRequest takes r's samples on every path in turn, and gives a row per gate path.
func measureRequest(r request, paths []path) ([]Latency, error) {
	took := make([][]time.Duration, len(paths))

	for i := range r.samples {
		for k := range paths {
			p := (i + k) % len(paths)

			d, err := r.sample(paths[p], i)
			if err != nil {
				return nil, fmt.Errorf("%s, sample %d: %w", paths[p].name, i, err)
			}

			took[p] = append(took[p], d)
		}
	}

	direct := stats(took[0])

	rows := make([]Latency, 0, len(paths)-1)
	for p := 1; p < len(paths); p++ {
		row := Latency{Request: r.name, Listener: paths[p].name, Samples: r.samples, Direct: direct, Gate: stats(took[p])}
		row.OverheadP50 = row.Gate.P50 - row.Direct.P50
		row.Ratio = row.Gate.P50 / row.Direct.P50
		rows = append(rows, row)
	}

	return rows, nil
}

func get(endpoint string) func(path, int) (time.Duration, error) {
	return func(p path, _ int) (time.Duration, error) {
		return timed(func() error { _, err := must(p.client, "GET", api+endpoint, nil); return err })
	}
}

// listContainers: through the gate, the scope's list (the gate adds the owner filter); direct, the
// same filter given, so Docker does the same work either way.
func listContainers(p path, _ int) (time.Duration, error) {
	query := "?all=1"
	if p.name == "direct" {
		query += "&filters=" + url.QueryEscape(`{"label":["`+ownerLabel+`=`+p.owner+`"]}`)
	}

	var n int

	took, err := timed(func() error {
		answer, err := must(p.client, "GET", api+"/containers/json"+query, nil)
		if err == nil {
			var listed []json.RawMessage
			err = json.Unmarshal(answer, &listed)
			n = len(listed)
		}

		return err
	})

	// The scope's 20 and its running one
	if err == nil && n != 21 {
		err = fmt.Errorf("listed %d containers, want the scope's 21", n)
	}

	return took, err
}

func inspectContainer(p path, _ int) (time.Duration, error) {
	return timed(func() error { _, err := must(p.client, "GET", api+"/containers/"+p.running+"/json", nil); return err })
}

// createSample: the create timed, the container removed after.
func createSample(d *http.Client) func(path, int) (time.Duration, error) {
	return func(p path, i int) (time.Duration, error) {
		name := fmt.Sprintf("%s-%sc%d", p.owner, p.name, i)

		took, err := timed(func() error {
			_, err := must(p.client, "POST", api+"/containers/create?name="+name, composeBody(p.owner))
			return err
		})
		if err != nil {
			return 0, err
		}

		_, err = must(d, "DELETE", api+"/containers/"+name+"?force=1", nil)

		return took, err
	}
}

// startSample: a container created (straight with Docker), its start timed, removed after.
func startSample(d *http.Client) func(path, int) (time.Duration, error) {
	return func(p path, i int) (time.Duration, error) {
		name := fmt.Sprintf("%s-%ss%d", p.owner, p.name, i)

		id, err := createContainer(d, p.owner, name)
		if err != nil {
			return 0, err
		}

		took, err := timed(func() error {
			_, err := must(p.client, "POST", api+"/containers/"+id+"/start", nil)
			return err
		})
		if err != nil {
			return 0, err
		}

		_, err = must(d, "DELETE", api+"/containers/"+id+"?force=1", nil)

		return took, err
	}
}

// execSample is an exec's round trip: created, started on a connection of its own (upgraded to a
// stream), its output read to its end.
func execSample(p path, _ int) (time.Duration, error) {
	return timed(func() error {
		answer, err := must(p.client, "POST", api+"/containers/"+p.running+"/exec", map[string]any{"AttachStdout": true, "AttachStderr": true, "Cmd": []string{"echo", "ok"}})
		if err != nil {
			return err
		}

		var created struct {
			ID string `json:"Id"`
		}
		if err := json.Unmarshal(answer, &created); err != nil {
			return err
		}

		c, err := p.dial()
		if err != nil {
			return err
		}

		defer c.Close()

		_ = c.SetDeadline(time.Now().Add(time.Minute))

		body := `{"Detach":false,"Tty":false}`
		if _, err := fmt.Fprintf(c, "POST %s/exec/%s/start HTTP/1.1\r\nHost: docker\r\nContent-Type: application/json\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n%sContent-Length: %d\r\n\r\n%s", api, created.ID, p.header, len(body), body); err != nil {
			return err
		}

		r := bufio.NewReader(c)

		res, err := http.ReadResponse(r, nil)
		if err != nil {
			return err
		}

		if res.StatusCode != http.StatusSwitchingProtocols && res.StatusCode != http.StatusOK {
			return fmt.Errorf("exec start: %d", res.StatusCode)
		}

		out, err := io.ReadAll(r)
		if err != nil && !errors.Is(err, net.ErrClosed) {
			return err
		}

		if !bytes.Contains(out, []byte("ok")) {
			return fmt.Errorf("exec's output %q", out)
		}

		return nil
	})
}

// listImages: through the gate, the scope's list of a host's 10,000 images (the gate filters it as
// it reads Docker's); direct, the same request unfiltered. The gate can't hand Docker a filter (a
// scope also sees the images in no protected namespace, such as alpine), so Docker builds its whole
// list either way, and the difference is the gate's reading and filtering of it.
func listImages(p path, _ int) (time.Duration, error) {
	var listed []listedImage

	took, err := timed(func() error {
		answer, err := must(p.client, "GET", api+"/images/json", nil)
		if err == nil {
			err = json.Unmarshal(answer, &listed)
		}

		return err
	})

	if err == nil && p.name == "direct" && len(listed) < hostImages {
		err = fmt.Errorf("listed %d images, want the host's %d", len(listed), hostImages)
	} else if err == nil && p.name != "direct" {
		err = scopesImages(listed, p.owner)
	}

	return took, err
}

type listedImage struct{ RepoTags []string }

// scopesImages checks a scope's image list: of the images under bench/, its own 10 (and its alpine,
// where it has one), none of another's. The host's other images, in no protected namespace, are
// listed too: on CI's runner the conformance suites leave some before the benchmark.
func scopesImages(listed []listedImage, owner string) error {
	own := 0

	for _, image := range listed {
		for _, tag := range image.RepoTags {
			switch {
			case !strings.HasPrefix(tag, "bench/"):
			case !strings.HasPrefix(tag, "bench/"+owner+"/"):
				return fmt.Errorf("listed %s, not the scope's", tag)
			case strings.HasPrefix(tag, "bench/"+owner+"/image"):
				own++
			}
		}
	}

	if own != imagesPerScope {
		return fmt.Errorf("listed %d of the scope's images, want its %d", own, imagesPerScope)
	}

	return nil
}

// loadSample loads a 1 GiB image under the path's owner's name, and removes it after.
func loadSample(d *http.Client, layerPath, diffID string) func(path, int) (time.Duration, error) {
	info, _ := os.Stat(layerPath)

	return func(p path, _ int) (time.Duration, error) {
		images := []image{{config: config(diffID, "big"), tags: []string{"bench/" + p.owner + "/big:latest"}}}

		r, w := io.Pipe()
		go func() { w.CloseWithError(writeArchive(w, layerPath, images)) }()

		req, err := http.NewRequest("POST", "http://docker"+api+"/images/load?quiet=1", r)
		if err != nil {
			return 0, err
		}

		req.ContentLength = archiveSize(info.Size(), images)
		req.Header.Set("Content-Type", "application/x-tar")

		var answer []byte

		took, err := timed(func() error {
			res, err := p.client.Do(req)
			if err != nil {
				return err
			}

			defer res.Body.Close()

			answer, err = io.ReadAll(res.Body)
			if err == nil && (res.StatusCode != http.StatusOK || bytes.Contains(answer, []byte(`"errorDetail"`))) {
				err = fmt.Errorf("image load: %d %s", res.StatusCode, answer)
			}

			return err
		})
		if err != nil {
			return 0, err
		}

		return took, removeImages(d, "bench/"+p.owner+"/big")
	}
}

func timed(do func() error) (time.Duration, error) {
	started := time.Now()
	err := do()

	return time.Since(started), err
}

// stats are a sample's p50, p99 and max, in microseconds.
func stats(took []time.Duration) Stats {
	sorted := slices.Clone(took)
	slices.Sort(sorted)

	us := func(d time.Duration) float64 { return float64(d.Nanoseconds()) / 1000 }

	return Stats{P50: us(sorted[len(sorted)/2]), P99: us(sorted[min(len(sorted)-1, len(sorted)*99/100)]), Max: us(sorted[len(sorted)-1])}
}

func summary(rows []Latency) string {
	parts := make([]string, 0, len(rows))
	for _, r := range rows {
		parts = append(parts, fmt.Sprintf("%s %s → %s (×%.2f)", r.Listener, us(r.Direct.P50), us(r.Gate.P50), r.Ratio))
	}

	return strings.Join(parts, "; ")
}
