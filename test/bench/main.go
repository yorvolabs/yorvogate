// Command bench measures YorvoGate's overhead and how it scales with scopes, through the built gate
// and a real Docker (README.md): A, the latency of the common requests through the gate and straight
// to Docker; B, the gate's memory under 10 concurrent image lists of a 10,000-image host; C, a
// request's cost, check's and serve's, at 1 to 10,000 scopes. It writes results.json and results.md,
// and with -baseline says which figures regressed past their thresholds (with -fail, it fails on one).
//
//	make build && cd test/bench && go run . -gate ../../bin/yorvogate -docker /var/run/docker.sock
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type options struct {
	binary, docker, out, tmp string
	withoutLSM               bool
	full                     bool
	gateEnv                  []string
}

// samples is a request's sample count: the full run's, or a pull request's quick one.
func (o options) samples(full, quick int) int {
	if o.full {
		return full
	}

	return quick
}

func main() {
	if err := bench(); err != nil {
		fmt.Fprintln(os.Stderr, "bench:", err)
		os.Exit(1)
	}
}

func bench() error {
	var o options

	baselinePath := flag.String("baseline", "", "compare with this baseline (baseline.json), and mark the gated figures")
	fail := flag.Bool("fail", false, "exit 1 when a figure regressed past its threshold, measured twice")
	baselineOf := flag.String("baseline-of", "", "write a baseline to standard output: the medians of these results.json, comma-separated")

	flag.StringVar(&o.binary, "gate", "", "the built gate (bin/yorvogate)")
	flag.StringVar(&o.docker, "docker", "/var/run/docker.sock", "Docker's socket")
	flag.StringVar(&o.out, "out", "out", "where results.json and results.md go")
	flag.BoolVar(&o.full, "full", false, "the full run: more samples, every count of scopes, the 1 GiB load and B's 10,000 images")
	flag.BoolVar(&o.withoutLSM, "without-lsm", false, "accept a Docker without AppArmor or SELinux (Docker Desktop)")
	flag.Parse()

	if *baselineOf != "" {
		b, err := medians(strings.Split(*baselineOf, ","))
		if err != nil {
			return err
		}

		encoded, err := json.MarshalIndent(b, "", "  ")
		fmt.Println(string(encoded))

		return err
	}

	if o.binary == "" {
		return fmt.Errorf("-gate is the built gate to measure")
	}

	var baseline *Baseline

	if *baselinePath != "" {
		baseline = &Baseline{}

		// Before the first baseline (it's made from CI's runs), no ratio is gated; scaling's bounds,
		// fixed, still are
		switch err := readJSON(*baselinePath, baseline); {
		case errors.Is(err, fs.ErrNotExist):
			progress("no baseline at %s yet: the ratios are reported, not gated", *baselinePath)

			baseline = nil
		case err != nil:
			return err
		}
	}

	if err := os.MkdirAll(o.out, 0o755); err != nil {
		return err
	}

	tmp, err := os.MkdirTemp("", "yorvogate-bench")
	if err != nil {
		return err
	}

	defer os.RemoveAll(tmp)

	o.tmp = tmp
	// What a release's image sets (docs/configuration.md): the gate collects sooner rather than grow
	o.gateEnv = []string{"GOMEMLIMIT=200MiB"}

	r, err := run(o)
	if err != nil {
		return err
	}

	return report(o, r, baseline, *fail)
}

func run(o options) (*Results, error) {
	d := unixClient(o.docker)

	r := &Results{Version: 1, Run: "quick", Started: time.Now().UTC()}
	if o.full {
		r.Run = "full"
	}

	var err error
	if r.Machine, err = machine(o, d); err != nil {
		return nil, err
	}

	progress("on %s, %d CPUs; Docker %s (%s)", r.Machine.CPU, r.Machine.CPUs, r.Machine.Docker, r.Machine.ImageStore)

	if err := clean(d); err != nil {
		return nil, err
	}

	defer func() {
		if err := clean(d); err != nil {
			progress("cleaning up: %v", err)
		}
	}()

	if err := pullBase(d); err != nil {
		return nil, err
	}

	var (
		loaded time.Duration
		load   func() error
	)

	// B's images are loaded once A's other requests are measured: its image list is the one that
	// needs them
	if o.full {
		load = func() error {
			var err error
			if loaded, err = loadImages(d, o.tmp); err != nil {
				return err
			}

			progress("B: %d images loaded in %v", hostImages, loaded.Round(time.Millisecond))

			return nil
		}
	}

	if r.Latency, err = latency(o, d, o.tmp, load); err != nil {
		return nil, err
	}

	if o.full {
		if r.Memory, err = memory(o, d, loaded); err != nil {
			return nil, err
		}

		progress("B: RSS %.0f → %.0f MiB, heap %.1f → %.1f MiB", r.Memory.IdleRSS, r.Memory.PeakRSS, r.Memory.IdleHeap, r.Memory.PeakHeap)
	}

	if r.Scaling, r.Rescan, err = scaling(o, scopeCounts(o), o.samples(2000, 1000)); err != nil {
		return nil, err
	}

	return r, nil
}

func scopeCounts(o options) []int {
	if o.full {
		return []int{1, 100, 1000, 4000, 10000}
	}

	return []int{1, 1000, 10000}
}

// report writes the results, and compares them with the baseline: a figure past its threshold is
// measured once more (its section again), and is a regression only when it's past it both times.
func report(o options, r *Results, b *Baseline, fail bool) error {
	found := regressions(r, b)

	if len(found) > 0 {
		for _, f := range found {
			progress("past its threshold, measuring again: %s", f.text)
		}

		again, err := remeasure(o, r, found)
		if err != nil {
			return err
		}

		r, found = again, regressions(again, b)
	}

	if err := writeJSON(filepath.Join(o.out, "results.json"), r); err != nil {
		return err
	}

	if err := os.WriteFile(filepath.Join(o.out, "results.md"), []byte(markdown(r, b)), 0o644); err != nil {
		return err
	}

	fmt.Print(markdown(r, b))

	for _, f := range found {
		fmt.Printf("::error::regression, measured twice: %s\n", f.text)
	}

	if fail && len(found) > 0 {
		return fmt.Errorf("%d figures regressed past their thresholds", len(found))
	}

	return nil
}

// remeasure runs again the sections of the figures found: A, or C.
func remeasure(o options, r *Results, found []regression) (*Results, error) {
	d := unixClient(o.docker)
	again := *r

	sections := map[string]bool{}
	for _, f := range found {
		sections[f.section] = true
	}

	if sections["latency"] {
		if err := clean(d); err != nil {
			return nil, err
		}

		if err := pullBase(d); err != nil {
			return nil, err
		}

		var err error
		if again.Latency, err = latency(o, d, o.tmp, nil); err != nil {
			return nil, err
		}

		if err := clean(d); err != nil {
			return nil, err
		}
	}

	if sections["scaling"] {
		var err error
		if again.Scaling, again.Rescan, err = scaling(o, scopeCounts(o), o.samples(2000, 1000)); err != nil {
			return nil, err
		}
	}

	return &again, nil
}

// machine is what this run measures on.
func machine(o options, d *http.Client) (Machine, error) {
	m := Machine{CPUs: runtime.NumCPU(), Go: runtime.Version()}

	if cpuinfo, err := os.ReadFile("/proc/cpuinfo"); err == nil {
		for _, line := range strings.Split(string(cpuinfo), "\n") {
			if name, ok := strings.CutPrefix(line, "model name"); ok {
				m.CPU = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(name), ":"))

				break
			}
		}
	}

	if meminfo, err := os.ReadFile("/proc/meminfo"); err == nil {
		for _, line := range strings.Split(string(meminfo), "\n") {
			if f := strings.Fields(line); len(f) >= 2 && f[0] == "MemTotal:" {
				kb, _ := strconv.ParseInt(f[1], 10, 64)
				m.MemoryMiB = kb / 1024
			}
		}
	}

	if kernel, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		m.Kernel = strings.TrimSpace(string(kernel))
	}

	answer, err := must(d, "GET", "/info", nil)
	if err != nil {
		return m, fmt.Errorf("docker at %s: %w", o.docker, err)
	}

	var info struct {
		ServerVersion string
		Driver        string
		DriverStatus  [][2]string
	}
	if err := json.Unmarshal(answer, &info); err != nil {
		return m, err
	}

	m.Docker, m.StorageDriver, m.ImageStore = info.ServerVersion, info.Driver, "classic"

	for _, s := range info.DriverStatus {
		if s[0] == "driver-type" && strings.Contains(s[1], "snapshotter") {
			m.ImageStore = "containerd"
		}
	}

	if version, err := must(d, "GET", "/version", nil); err == nil {
		var v struct{ APIVersion string }
		_ = json.Unmarshal(version, &v)
		m.DockerAPI = v.APIVersion
	}

	if out, err := exec.Command(o.binary, "version").Output(); err == nil {
		m.YorvoGate = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(string(out)), "yorvogate"))
	}

	if out, err := exec.Command("git", "rev-parse", "--short=12", "HEAD").Output(); err == nil {
		m.Commit = strings.TrimSpace(string(out))
	}

	return m, nil
}

func progress(format string, args ...any) {
	fmt.Fprintf(os.Stderr, time.Now().Format("15:04:05 ")+format+"\n", args...)
}
