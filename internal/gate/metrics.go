package gate

import (
	"fmt"
	"io"
	"log/slog"
	"maps"
	"math"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Metrics are the process's, written as Prometheus's text format (0.0.4) by hand: counters, gauges
// and fixed-bucket histograms, every label bounded (endpoint names, reason codes, auth causes, the
// configuration's listeners). A scope is a label only where an operator asked for it (scopeLabels),
// and then on refusals alone. Nil-safe: a gate without metrics (a test's) counts nothing.
type Metrics struct {
	mu sync.Mutex

	scopeLabels bool
	// Whether the last reload was taken (1 until one is refused)
	reloaded   bool
	counters   map[string]map[labels]float64
	histograms map[string]map[labels]*histogram
	streams    map[string]int64
	// Scoped requests in flight, by listener (and scope, with scopeLabels)
	inflight map[labels]int64
	gauges   []gauge

	authLog *authLimiter
}

// labels are a sample's, as name=value pairs in a fixed order (a map key).
type labels string

func labelsOf(pairs ...string) labels {
	var b strings.Builder

	for i := 0; i+1 < len(pairs); i += 2 {
		if b.Len() > 0 {
			b.WriteByte(',')
		}

		b.WriteString(pairs[i])
		b.WriteString(`="`)
		b.WriteString(escapeLabel(pairs[i+1]))
		b.WriteByte('"')
	}

	return labels(b.String())
}

// escapeLabel escapes a label value as the text format reads it: backslash, quote and newline.
func escapeLabel(v string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(v)
}

// The buckets of every histogram, in seconds: a decision is a few milliseconds, Docker's answer up to
// a pull's minutes.
var buckets = []float64{0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 300}

type histogram struct {
	counts []uint64 // per bucket, not cumulative
	sum    float64
	count  uint64
}

// gauge is a value read when the metrics are written.
type gauge struct {
	name, help string
	read       func() []sample
}

type sample struct {
	labels labels
	value  float64
}

// The metrics' names and what each counts (HELP), in the order they're written.
var metricHelp = map[string]string{
	"yorvogate_requests_total":             "Decisions on Docker requests, by listener, endpoint and outcome.",
	"yorvogate_refusals_total":             "Refusals, by listener and reason code (and scope, with admin.scope_labels).",
	"yorvogate_auth_failures_total":        "Authentication failures, by listener and cause.",
	"yorvogate_docker_errors_total":        "Requests Docker didn't answer, by listener.",
	"yorvogate_decision_seconds":           "How long YorvoGate took to decide, a refusal's hold included, by listener.",
	"yorvogate_docker_seconds":             "How long Docker took to answer a forwarded request (its headers; streams excluded), by listener.",
	"yorvogate_streams_open":               "Streams open (requests upgraded to a connection), by listener.",
	"yorvogate_requests_in_flight":         "Scoped requests in flight (streams included), by listener; by scope too with admin.scope_labels. What limits.requests bounds, per scope.",
	"yorvogate_auth_log_dropped_total":     "auth failed log lines dropped by the per-source and global limits.",
	"yorvogate_config_reloads_total":       "Reloads of the configuration (SIGHUP), by result: reloaded or refused.",
	"yorvogate_config_last_reload_success": "Whether the last reload of the configuration was taken (1 before any).",
}

// NewMetrics are a process's metrics.
func NewMetrics(scopeLabels bool) *Metrics {
	return &Metrics{
		scopeLabels: scopeLabels,
		reloaded:    true,
		counters:    map[string]map[labels]float64{},
		histograms:  map[string]map[labels]*histogram{},
		streams:     map[string]int64{},
		inflight:    map[labels]int64{},
		authLog:     newAuthLimiter(),
	}
}

// Reloaded counts a reload of the configuration, taken or refused; a taken one may change
// admin.scope_labels.
func (m *Metrics) Reloaded(taken, scopeLabels bool) {
	if m == nil {
		return
	}

	result := "refused"
	if taken {
		result = "reloaded"
	}

	m.add("yorvogate_config_reloads_total", labelsOf("result", result), 1)

	m.mu.Lock()
	defer m.mu.Unlock()

	m.reloaded = taken
	if taken {
		m.scopeLabels = scopeLabels
	}
}

func (m *Metrics) add(name string, l labels, n float64) {
	if m == nil {
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.counters[name] == nil {
		m.counters[name] = map[labels]float64{}
	}

	m.counters[name][l] += n
}

func (m *Metrics) observe(name string, l labels, seconds float64) {
	if m == nil {
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.histograms[name] == nil {
		m.histograms[name] = map[labels]*histogram{}
	}

	h := m.histograms[name][l]
	if h == nil {
		h = &histogram{counts: make([]uint64, len(buckets))}
		m.histograms[name][l] = h
	}

	for i, b := range buckets {
		if seconds <= b {
			h.counts[i]++

			break
		}
	}

	h.sum += seconds
	h.count++
}

// Gauge adds a value read when the metrics are written.
func (m *Metrics) Gauge(name, help string, read func() []sample) {
	if m == nil {
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.gauges = append(m.gauges, gauge{name: name, help: help, read: read})
}

// decided counts a decision.
func (m *Metrics) decided(listener, endpoint string, refused *refusal, scope string, took time.Duration) {
	if m == nil {
		return
	}

	outcome := "allowed"
	if refused != nil {
		outcome = "refused"
	}

	m.add("yorvogate_requests_total", labelsOf("listener", listener, "endpoint", endpoint, "outcome", outcome), 1)
	m.observe("yorvogate_decision_seconds", labelsOf("listener", listener), took.Seconds())

	if refused == nil {
		return
	}

	l := labelsOf("listener", listener, "code", string(refused.code))
	if m.scopeLabels && scope != "" {
		l = labelsOf("listener", listener, "code", string(refused.code), "scope", scope)
	}

	m.add("yorvogate_refusals_total", l, 1)
}

func (m *Metrics) authFailed(listener, cause string) {
	m.add("yorvogate_auth_failures_total", labelsOf("listener", listener, "cause", cause), 1)
}

// authLimit tells whether an auth failed line may be logged (and what was dropped before), counting
// a dropped one.
func (m *Metrics) authLimit(source string, now time.Time) (bool, int) {
	if m == nil {
		return true, 0
	}

	ok, dropped := m.authLog.allow(source, now)
	if !ok {
		m.add("yorvogate_auth_log_dropped_total", "", 1)
	}

	return ok, dropped
}

func (m *Metrics) dockerAnswered(listener string, took time.Duration) {
	m.observe("yorvogate_docker_seconds", labelsOf("listener", listener), took.Seconds())
}

func (m *Metrics) dockerFailed(listener string) {
	m.add("yorvogate_docker_errors_total", labelsOf("listener", listener), 1)
}

// requestInFlight counts a scoped request in flight (delta 1), or ended (-1).
func (m *Metrics) requestInFlight(listener, scope string, delta int64) {
	if m == nil {
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	l := labelsOf("listener", listener)
	if m.scopeLabels {
		l = labelsOf("listener", listener, "scope", scope)
	}

	if m.inflight[l] += delta; m.inflight[l] <= 0 {
		delete(m.inflight, l)
	}
}

func (m *Metrics) stream(listener string, delta int64) {
	if m == nil {
		return
	}

	m.mu.Lock()
	m.streams[listener] += delta
	m.mu.Unlock()
}

// Write writes the metrics in Prometheus's text format, each family once, in a fixed order.
func (m *Metrics) Write(w io.Writer) error {
	m.mu.Lock()
	counters := map[string]map[labels]float64{}
	for name, s := range m.counters {
		counters[name] = maps.Clone(s)
	}

	histograms := map[string]map[labels]histogram{}
	for name, s := range m.histograms {
		histograms[name] = map[labels]histogram{}
		for l, h := range s {
			histograms[name][l] = histogram{counts: slices.Clone(h.counts), sum: h.sum, count: h.count}
		}
	}

	streams := maps.Clone(m.streams)
	inflight := maps.Clone(m.inflight)
	reloaded := m.reloaded
	gauges := slices.Clone(m.gauges)
	m.mu.Unlock()

	var b strings.Builder

	family := func(name, kind, help string) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, kind)
	}

	value := func(v float64) string {
		switch {
		case math.IsInf(v, 1):
			return "+Inf"
		case v == math.Trunc(v) && math.Abs(v) < 1e15:
			return strconv.FormatInt(int64(v), 10)
		}

		return strconv.FormatFloat(v, 'g', -1, 64)
	}

	line := func(name string, l labels, v float64) {
		if l == "" {
			fmt.Fprintf(&b, "%s %s\n", name, value(v))
		} else {
			fmt.Fprintf(&b, "%s{%s} %s\n", name, l, value(v))
		}
	}

	for _, name := range []string{"yorvogate_requests_total", "yorvogate_refusals_total", "yorvogate_auth_failures_total", "yorvogate_docker_errors_total", "yorvogate_auth_log_dropped_total", "yorvogate_config_reloads_total"} {
		family(name, "counter", metricHelp[name])

		for _, l := range slices.Sorted(maps.Keys(counters[name])) {
			line(name, l, counters[name][l])
		}
	}

	for _, name := range []string{"yorvogate_decision_seconds", "yorvogate_docker_seconds"} {
		family(name, "histogram", metricHelp[name])

		for _, l := range slices.Sorted(maps.Keys(histograms[name])) {
			h := histograms[name][l]
			cumulative := uint64(0)

			le := func(bound string) labels {
				if l == "" {
					return labels(`le="` + bound + `"`)
				}

				return labels(string(l) + `,le="` + bound + `"`)
			}

			for i, bound := range buckets {
				cumulative += h.counts[i]
				line(name+"_bucket", le(value(bound)), float64(cumulative))
			}

			line(name+"_bucket", le("+Inf"), float64(h.count))
			line(name+"_sum", l, h.sum)
			line(name+"_count", l, float64(h.count))
		}
	}

	family("yorvogate_streams_open", "gauge", metricHelp["yorvogate_streams_open"])

	for _, listener := range slices.Sorted(maps.Keys(streams)) {
		line("yorvogate_streams_open", labelsOf("listener", listener), float64(streams[listener]))
	}

	family("yorvogate_requests_in_flight", "gauge", metricHelp["yorvogate_requests_in_flight"])

	for _, l := range slices.Sorted(maps.Keys(inflight)) {
		line("yorvogate_requests_in_flight", l, float64(inflight[l]))
	}

	family("yorvogate_config_last_reload_success", "gauge", metricHelp["yorvogate_config_last_reload_success"])

	if reloaded {
		line("yorvogate_config_last_reload_success", "", 1)
	} else {
		line("yorvogate_config_last_reload_success", "", 0)
	}

	for _, g := range gauges {
		family(g.name, "gauge", g.help)

		samples := g.read()
		slices.SortFunc(samples, func(a, b sample) int { return strings.Compare(string(a.labels), string(b.labels)) })

		for _, s := range samples {
			line(g.name, s.labels, s.value)
		}
	}

	_, err := io.WriteString(w, b.String())

	return err
}

// FlushAuthLog logs how many auth failed lines the last minute dropped, once, when no auth failure
// since has said it.
func (m *Metrics) FlushAuthLog(log *slog.Logger) {
	if m == nil {
		return
	}

	if dropped := m.authLog.flush(time.Now()); dropped > 0 {
		log.Warn("auth failed lines dropped", "log_version", LogVersion, "dropped", dropped)
	}
}
