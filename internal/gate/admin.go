package gate

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/yorvolabs/yorvogate/internal/config"
	"github.com/yorvolabs/yorvogate/internal/scope"
)

// The admin listener answers an operator's monitoring, never Docker's API: /metrics (Prometheus's
// text format), /healthz (the process serves: for liveness, and restarts) and /readyz (scoped
// requests can be served now: for routing and alerts, never for restarts). Its answers hold no secret,
// and name no scope unless admin.scope_labels is on.

// Version is the build's (main sets it), for yorvogate_build_info.
var Version = "dev"

// pinger asks Docker's _ping at most once a second, for every readiness check at once: a storm of
// scrapes is never a storm of pings.
type pinger struct {
	mu   sync.Mutex
	at   time.Time
	err  error
	busy chan struct{}
}

func (p *pinger) check(ctx context.Context, d *Docker) error {
	p.mu.Lock()
	if time.Since(p.at) < time.Second {
		err := p.err
		p.mu.Unlock()

		return err
	}

	if busy := p.busy; busy != nil {
		p.mu.Unlock()
		<-busy

		p.mu.Lock()
		defer p.mu.Unlock()

		return p.err
	}

	busy := make(chan struct{})
	p.busy = busy
	p.mu.Unlock()

	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	err := d.ping(ctx)

	p.mu.Lock()
	p.at, p.err, p.busy = time.Now(), err, nil
	p.mu.Unlock()
	close(busy)

	return err
}

// Readiness is /readyz's answer (schemas/yorvogate-readiness.v1.schema.json).
type Readiness struct {
	Ready  bool              `json:"ready"`
	Checks map[string]string `json:"checks"`
}

// Ready says whether scoped requests can be served now, and each check's state: from what Watch read
// last, and a _ping at most a second old.
func (d *Defaults) Ready(ctx context.Context, c *config.Config, registry *scope.Registry) Readiness {
	r := Readiness{Ready: true, Checks: map[string]string{}}
	set := func(check, why string) {
		if why == "" {
			r.Checks[check] = "ok"

			return
		}

		r.Checks[check], r.Ready = why, false
	}

	if err := d.ping.check(ctx, d.docker); err != nil {
		set("docker", "Docker doesn't answer: "+err.Error())
	} else {
		set("docker", "")
	}

	state := d.state.Load()

	switch {
	case !needsSpool(c):
		// No scoped listener: Docker's defaults decide nothing
		set("defaults", "")
		set("api_versions", "")
	case state == nil:
		set("defaults", "Docker's defaults haven't been read yet (or Docker was down)")
		set("api_versions", "not known yet")
	default:
		why := ""
		if len(state.unsafe) > 0 {
			why = "they would widen what scopes may do: " + join(state.unsafe)
		}

		set("defaults", why)
		set("api_versions", state.apiMismatch)
	}

	scopes := ""
	for _, l := range c.Listeners {
		if l.Mode != config.Scoped {
			continue
		}

		if _, err := os.ReadDir(l.Scopes); err != nil {
			scopes = "listener " + l.Name + ": its scopes folder can't be read: " + err.Error()

			break
		}
	}

	set("scopes", scopes)

	spool := ""
	if needsSpool(c) {
		if err := syscall.Access(c.Spool.Dir, 2 /* W_OK */); err != nil {
			spool = c.Spool.Dir + " can't be written: " + err.Error()
		}
	}

	set("spool", spool)

	return r
}

func join(list []string) string {
	out := ""
	for i, s := range list {
		if i > 0 {
			out += "; "
		}

		out += s
	}

	return out
}

// ping asks Docker's _ping.
func (d *Docker) ping(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker/_ping", nil)
	if err != nil {
		return err
	}

	req.Header.Set("User-Agent", "yorvogate")

	res, err := d.client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return &pingError{res.Status}
	}

	return nil
}

type pingError struct{ status string }

func (e *pingError) Error() string { return "_ping answered " + e.status }

// Admin is the admin listener's handler.
func Admin(c *config.Config, m *Metrics, d *Defaults, registry *scope.Registry, spool *Spool) http.Handler {
	m.gauges = append(m.gauges, processGauges(c, d, registry, spool)...)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		_ = m.Write(w)
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		ready := d.Ready(r.Context(), c, registry)

		w.Header().Set("Content-Type", "application/json")
		if !ready.Ready {
			w.WriteHeader(http.StatusServiceUnavailable)
		}

		_ = json.NewEncoder(w).Encode(ready)
	})

	return mux
}

// processGauges are the gauges read from the process's state when the metrics are written.
func processGauges(c *config.Config, d *Defaults, registry *scope.Registry, spool *Spool) []gauge {
	bit := func(b bool) float64 {
		if b {
			return 1
		}

		return 0
	}

	lowest, highest := c.Versions()

	return []gauge{
		{"yorvogate_build_info", "YorvoGate's version and the API versions it serves.", func() []sample {
			return []sample{{labelsOf("version", Version, "api_min", lowest.String(), "api_max", highest.String()), 1}}
		}},
		{"yorvogate_docker_up", "Whether YorvoGate's last read of Docker reached it.", func() []sample {
			s := d.state.Load()

			return []sample{{"", bit(s != nil && s.reached && !d.down.Load())}}
		}},
		{"yorvogate_docker_defaults_safe", "Whether Docker's defaults are read and safe (scoped requests are refused otherwise).", func() []sample {
			s := d.state.Load()

			return []sample{{"", bit(s != nil && len(s.unsafe) == 0)}}
		}},
		{"yorvogate_spool_bytes", "Bytes the image spool holds for loads in flight, and its limit.", func() []sample {
			if spool == nil {
				return nil
			}

			spool.mu.Lock()
			defer spool.mu.Unlock()

			return []sample{{labelsOf("of", "used"), float64(spool.reserved)}, {labelsOf("of", "limit"), float64(spool.limit)}}
		}},
		{"yorvogate_spool_loads", "Image loads in flight, and how many may be.", func() []sample {
			if spool == nil {
				return nil
			}

			return []sample{{labelsOf("of", "used"), float64(len(spool.global))}, {labelsOf("of", "limit"), float64(cap(spool.global))}}
		}},
		{"yorvogate_scopes", "Scopes by state, on each scoped listener.", func() []sample {
			var out []sample

			for _, l := range c.Listeners {
				if l.Mode != config.Scoped {
					continue
				}

				counts := map[string]int{"loaded": 0, "refused": 0, "reserved": 0}
				valid, invalid, _ := registry.Store(l.Name).Scopes()
				counts["loaded"] = len(valid)

				for name := range invalid {
					if st, _, ok := registry.Status(l.Name, name); ok && (st.State == "refused" || st.State == "reserved") {
						counts[st.State]++
					}
				}

				for _, state := range []string{"loaded", "refused", "reserved"} {
					out = append(out, sample{labelsOf("listener", l.Name, "state", state), float64(counts[state])})
				}
			}

			return out
		}},
	}
}
