package main

import (
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"
)

// Results are a run's: results.json, and results.md (the tables of docs/performance.md).
type Results struct {
	Version int       `json:"version"`
	Run     string    `json:"run"` // quick (a pull request's) or full (nightly, and a release's)
	Started time.Time `json:"started"`
	Machine Machine   `json:"machine"`
	Latency []Latency `json:"latency"`
	Memory  *Memory   `json:"memory,omitempty"`
	Scaling []Scaling `json:"scaling"`
	Rescan  *Rescan   `json:"rescan,omitempty"`
}

// Machine is what the numbers were measured on.
type Machine struct {
	CPU           string `json:"cpu"`
	CPUs          int    `json:"cpus"`
	MemoryMiB     int64  `json:"memory_mib"`
	Kernel        string `json:"kernel"`
	Docker        string `json:"docker"`
	DockerAPI     string `json:"docker_api"`
	StorageDriver string `json:"storage_driver"`
	ImageStore    string `json:"image_store"`
	Go            string `json:"go"`
	YorvoGate     string `json:"yorvogate"`
	Commit        string `json:"commit,omitempty"`
}

// Stats are microseconds.
type Stats struct {
	P50 float64 `json:"p50_us"`
	P99 float64 `json:"p99_us"`
	Max float64 `json:"max_us"`
}

// Latency is a row of table A: a request through one listener, and straight to Docker.
type Latency struct {
	Request     string  `json:"request"`
	Listener    string  `json:"listener"`
	Samples     int     `json:"samples"`
	Direct      Stats   `json:"direct"`
	Gate        Stats   `json:"gate"`
	OverheadP50 float64 `json:"overhead_p50_us"`
	// Gate p50 over direct p50
	Ratio float64 `json:"ratio"`
}

// Memory is table B.
type Memory struct {
	HostImages  int     `json:"host_images"`
	Scopes      int     `json:"scopes"`
	PerScope    int     `json:"images_per_scope"`
	Concurrent  int     `json:"concurrent"`
	Rounds      int     `json:"rounds"`
	LoadSeconds float64 `json:"load_seconds"`
	IdleRSS     float64 `json:"idle_rss_mib"`
	PeakRSS     float64 `json:"peak_rss_mib"`
	IdleHeap    float64 `json:"idle_heap_mib"`
	PeakHeap    float64 `json:"peak_heap_mib"`
	List        Stats   `json:"list"`
}

// Scaling is a row of table C.
type Scaling struct {
	Scopes  int     `json:"scopes"`
	Samples int     `json:"samples"`
	CheckMS float64 `json:"check_ms"`
	ServeMS float64 `json:"serve_ms"`
	Tokens  Stats   `json:"tokens"`
	Sockets Stats   `json:"sockets"`
	RSS     float64 `json:"rss_mib"`
}

// Rescan is how long a changed scope file took to be in effect.
type Rescan struct {
	Scopes int     `json:"scopes"`
	MS     float64 `json:"ms"`
}

// Baseline is what a pull request's run is compared with: each latency row's medians over the
// runs it was made from (test/bench/baseline.json, changed only in a pull request that says why).
type Baseline struct {
	Version int               `json:"version"`
	From    []string          `json:"from"`
	Latency []BaselineLatency `json:"latency"`
}

type BaselineLatency struct {
	Request   string  `json:"request"`
	Listener  string  `json:"listener"`
	DirectP50 float64 `json:"direct_p50_us"`
	GateP50   float64 `json:"gate_p50_us"`
	Ratio     float64 `json:"ratio"`
}

// The thresholds a pull request's run is held to.
const (
	// A gated ratio may grow to this times its baseline's
	ratioBound = 1.5
	// A ratio is gated where the gate is at least this share of the request's time (direct p50)
	gatedShare = 0.2
	// The most scopes' per-request p50 may be this times one scope's: absolute, never a baseline's
	scalingBound = 1.5
	// check at 10,000 scopes, at most (0.2's took minutes)
	checkBound = 30 * time.Second
	// From 1,000 scopes to 10,000, check and serve may take at most this times 10 × longer
	growthBound = 1.5
)

// gated says whether a baseline row's ratio is held: the gate is a visible share of its time.
func (b BaselineLatency) gated() bool {
	return b.GateP50-b.DirectP50 >= gatedShare*b.DirectP50
}

func (b *Baseline) row(request, listener string) (BaselineLatency, bool) {
	if b == nil {
		return BaselineLatency{}, false
	}

	for _, r := range b.Latency {
		if r.Request == request && r.Listener == listener {
			return r, true
		}
	}

	return BaselineLatency{}, false
}

// regression is a figure past its threshold.
type regression struct {
	section string // latency or scaling
	request string // a latency row's
	text    string
}

// regressions are r's figures past their thresholds.
func regressions(r *Results, b *Baseline) []regression {
	var out []regression

	for _, l := range r.Latency {
		base, ok := b.row(l.Request, l.Listener)
		if !ok || !base.gated() {
			continue
		}

		if l.Ratio > ratioBound*base.Ratio {
			out = append(out, regression{"latency", l.Request, fmt.Sprintf("%s on %s: ×%.2f of Docker's time, more than %.1f × the baseline's ×%.2f", l.Request, l.Listener, l.Ratio, ratioBound, base.Ratio)})
		}
	}

	if len(r.Scaling) >= 2 {
		first, last := r.Scaling[0], r.Scaling[len(r.Scaling)-1]

		for _, c := range []struct {
			name        string
			first, last Stats
		}{{"tokens", first.Tokens, last.Tokens}, {"sockets", first.Sockets, last.Sockets}} {
			if c.last.P50 > scalingBound*c.first.P50 {
				out = append(out, regression{"scaling", "", fmt.Sprintf("a refused request on %s: p50 %s at %d scopes, more than %.1f × %s at %d", c.name, us(c.last.P50), last.Scopes, scalingBound, us(c.first.P50), first.Scopes)})
			}
		}

		if last.Scopes >= 10000 && last.CheckMS > float64(checkBound.Milliseconds()) {
			out = append(out, regression{"scaling", "", fmt.Sprintf("check at %d scopes: %s, more than %v", last.Scopes, ms(last.CheckMS), checkBound)})
		}

		// From a tenth of the most scopes to the most, check and serve grow at most growthBound ×
		// linearly
		for _, from := range r.Scaling {
			if from.Scopes*10 != last.Scopes {
				continue
			}

			for _, c := range []struct {
				name     string
				from, to float64
			}{{"check", from.CheckMS, last.CheckMS}, {"serve", from.ServeMS, last.ServeMS}} {
				if c.to > growthBound*10*c.from {
					out = append(out, regression{"scaling", "", fmt.Sprintf("%s: %s at %d scopes, more than %.0f × its %s at %d (%.1f × linear)", c.name, ms(c.to), last.Scopes, growthBound*10, ms(c.from), from.Scopes, growthBound)})
				}
			}
		}
	}

	return out
}

// medians makes a baseline of runs' results: each latency row's median.
func medians(paths []string) (*Baseline, error) {
	b := &Baseline{Version: 1}
	values := map[[2]string][][2]float64{}

	var order [][2]string

	for _, p := range paths {
		var r Results
		if err := readJSON(p, &r); err != nil {
			return nil, err
		}

		b.From = append(b.From, fmt.Sprintf("%s run %s on %s (%d CPUs), Docker %s", r.Run, r.Started.Format(time.RFC3339), r.Machine.CPU, r.Machine.CPUs, r.Machine.Docker))

		for _, l := range r.Latency {
			key := [2]string{l.Request, l.Listener}
			if _, seen := values[key]; !seen {
				order = append(order, key)
			}

			values[key] = append(values[key], [2]float64{l.Direct.P50, l.Gate.P50})
		}
	}

	median := func(v []float64) float64 {
		slices.Sort(v)

		return v[len(v)/2]
	}

	for _, key := range order {
		var direct, gate, ratio []float64
		for _, v := range values[key] {
			direct, gate, ratio = append(direct, v[0]), append(gate, v[1]), append(ratio, v[1]/v[0])
		}

		b.Latency = append(b.Latency, BaselineLatency{Request: key[0], Listener: key[1], DirectP50: median(direct), GateP50: median(gate), Ratio: median(ratio)})
	}

	return b, nil
}

func readJSON(path string, v any) error {
	content, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	return json.Unmarshal(content, v)
}

func writeJSON(path string, v any) error {
	content, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, append(content, '\n'), 0o644)
}

func us(v float64) string {
	if v < 0 {
		return "−" + us(-v)
	}

	switch {
	case v >= 1e6:
		return fmt.Sprintf("%.2f s", v/1e6)
	case v >= 1000:
		return fmt.Sprintf("%.2f ms", v/1000)
	}

	return fmt.Sprintf("%.0f µs", v)
}

func ms(v float64) string { return us(v * 1000) }

// markdown is results.md: the machine and the three tables, as docs/performance.md has them.
func markdown(r *Results, b *Baseline) string {
	var s strings.Builder

	m := r.Machine
	fmt.Fprintf(&s, "Measured %s (%s run) on %s, %d CPUs, %d MiB; Linux %s; Docker %s (API %s, %s, %s); %s; YorvoGate %s",
		r.Started.Format("2006-01-02"), r.Run, m.CPU, m.CPUs, m.MemoryMiB, m.Kernel, m.Docker, m.DockerAPI, m.StorageDriver, m.ImageStore, m.Go, m.YorvoGate)

	if m.Commit != "" {
		fmt.Fprintf(&s, " (%s)", m.Commit)
	}

	s.WriteString(".\n\n### A. Latency, through YorvoGate and straight to Docker\n\n")
	s.WriteString("| Request | Listener | Samples | Docker p50 / p99 | Through YorvoGate p50 / p99 | Added (p50) | × Docker's | Gated |\n|---|---|---|---|---|---|---|---|\n")

	for _, l := range r.Latency {
		gated := "no"
		if base, ok := b.row(l.Request, l.Listener); ok && base.gated() {
			gated = "yes"
		} else if !ok {
			gated = "—"
		}

		fmt.Fprintf(&s, "| `%s` | %s | %d | %s / %s | %s / %s | %s | %.2f | %s |\n", l.Request, l.Listener, l.Samples, us(l.Direct.P50), us(l.Direct.P99), us(l.Gate.P50), us(l.Gate.P99), us(l.OverheadP50), l.Ratio, gated)
	}

	if mem := r.Memory; mem != nil {
		fmt.Fprintf(&s, "\n### B. Memory, %d concurrent image lists on a host of %d images\n\n", mem.Concurrent, mem.HostImages)
		fmt.Fprintf(&s, "%d scopes of %d images each, %d lists at once (%d per scope), %d times. Docker loaded the %d images in %.0f s.\n\n", mem.Scopes, mem.PerScope, mem.Concurrent, mem.Concurrent/mem.Scopes, mem.Rounds, mem.HostImages, mem.LoadSeconds)
		s.WriteString("| | Idle | Peak |\n|---|---|---|\n")
		fmt.Fprintf(&s, "| Resident memory (VmRSS, VmHWM) | %.0f MiB | %.0f MiB |\n", mem.IdleRSS, mem.PeakRSS)
		fmt.Fprintf(&s, "| Go heap (`go_memstats_heap_alloc_bytes`) | %.1f MiB | %.1f MiB |\n", mem.IdleHeap, mem.PeakHeap)
		fmt.Fprintf(&s, "\nA list under that load: p50 %s, p99 %s.\n", us(mem.List.P50), us(mem.List.P99))
	}

	s.WriteString("\n### C. Scaling with scopes\n\n")
	s.WriteString("| Scopes per listener | `check` | `serve`, every listener open | Refused request, token listener p50 / p99 | Refused request, scope socket p50 / p99 | Memory once up |\n|---|---|---|---|---|---|\n")

	for _, c := range r.Scaling {
		fmt.Fprintf(&s, "| %d | %s | %s | %s / %s | %s / %s | %.0f MiB |\n", c.Scopes, ms(c.CheckMS), ms(c.ServeMS), us(c.Tokens.P50), us(c.Tokens.P99), us(c.Sockets.P50), us(c.Sockets.P99), c.RSS)
	}

	if r.Rescan != nil {
		fmt.Fprintf(&s, "\nAt %d scopes, a changed scope file was in effect %s after it was written (scope status, asked with its SHA-256).\n", r.Rescan.Scopes, ms(r.Rescan.MS))
	}

	return s.String()
}
