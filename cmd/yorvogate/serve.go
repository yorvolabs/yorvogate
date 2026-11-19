package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/yorvolabs/yorvogate/internal/config"
	"github.com/yorvolabs/yorvogate/internal/gate"
	"github.com/yorvolabs/yorvogate/internal/scope"
)

// scanInterval is how often socket-bound listeners look for scope files that came, changed or went
// (and at once on SIGHUP).
var scanInterval = 2 * time.Second

// reloading is called as a reload begins (a test's hook).
var reloading = func() {}

// process is what serve runs: the configuration in effect (live), what every listener shares, and
// each listener's server.
type process struct {
	path string
	log  *slog.Logger
	live *gate.Live

	registry     *scope.Registry
	certificates *gate.TLS
	upstream     *gate.Upstream
	spool        *gate.Spool
	defaults     *gate.Defaults
	metrics      *gate.Metrics
	docker       *gate.Docker
	// What report last logged, so each thing is logged once
	reported map[string]string

	// Listeners with an address (trusted and scoped), by name; socket-bound ones (scoped: they
	// never change while serving)
	served map[string]*served
	bound  []*gate.Sockets
	admin  *http.Server
	failed chan error
}

// served is a listener with an address, serving.
type served struct {
	gate     *gate.Gate
	server   *http.Server
	listener *gate.Tracked
}

// serve listens until the context ends (SIGINT or SIGTERM), then drains (see drain). SIGHUP reloads
// the configuration (see reload), then rescans the scope folders.
func serve(ctx context.Context, path string, log *slog.Logger) error {
	content, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	c, err := config.Parse(content)
	if err != nil {
		return err
	}

	registry := gate.Registry(c)
	if err := registry.Reload(); err != nil {
		return err
	}

	certificates, err := gate.LoadTLS(c, log)
	if err != nil {
		return err
	}

	if err := gate.PrepareSpool(c); err != nil {
		return err
	}

	for _, warn := range stateWarnings(c, registry, false) {
		log.Warn("scopes", "warning", warn)
	}

	for _, d := range c.Deprecations() {
		log.Warn("configuration", "warning", d)
	}

	p := &process{
		path: path, log: log, live: gate.NewLive(c, digest(content)),
		registry: registry, certificates: certificates, reported: map[string]string{},
		docker: gate.NewDocker(c.UpstreamSocket()), served: map[string]*served{}, failed: make(chan error, len(c.Listeners)+1),
	}
	report(c, registry, p.reported, p.docker, log)

	// SIGHUP reloads; it's taken before any socket is made, so it never stops the process. Those
	// that come during a reload make one more after it (the channel holds one).
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)

	p.upstream = gate.NewUpstream(c, log)
	// One spool for every listener: image loads are bounded across them all, and across reloads
	p.spool = gate.NewSpool(c)

	// Docker's defaults, read while scoped listeners serve: until they're read, and while they're
	// unsafe, scoped requests are refused.
	p.defaults = gate.NewDefaults(c)
	if slices.ContainsFunc(c.Listeners, func(l config.Listener) bool { return l.Mode == config.Scoped }) {
		// Read once before the first answer, so a scope isn't refused for a read not yet made
		p.defaults.Read(ctx)

		watching, unwatch := context.WithCancel(context.Background())
		defer unwatch()

		go p.defaults.Watch(watching, log)
	}

	gate.Version = version
	p.metrics = gate.NewMetrics(c.Admin != nil && c.Admin.ScopeLabels)

	for _, l := range c.Listeners {
		if err := p.open(l); err != nil {
			p.close()

			return err
		}
	}

	// The admin listener: metrics, health, readiness (an operator's, never Docker's API)
	if c.Admin != nil {
		listener, err := listen(c.Admin.AdminListener())
		if err != nil {
			p.close()

			return fmt.Errorf("admin: %w", err)
		}

		p.admin = &http.Server{Handler: gate.Admin(p.live, p.metrics, p.defaults, registry, p.spool), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 2 * time.Minute}

		go func() {
			if err := p.admin.Serve(listener); !errors.Is(err, http.ErrServerClosed) {
				p.failed <- fmt.Errorf("admin: %w", err)
			}
		}()

		log.Info("listening", "listener", "admin", "address", c.Admin.Address)
	}

	// Every listener is up, its scopes' sockets open: what the scope-status read answers from
	registry.Publish()

	ticker := time.NewTicker(scanInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			p.drain()

			return nil
		case err := <-p.failed:
			p.close()

			return err
		case <-hup:
			p.reload()
			p.scan()
		case <-ticker.C:
			p.scan()
			p.metrics.FlushAuthLog(log)
		case <-registry.Requests():
			// A scope-status request waits for a scope file just written or removed
			p.scan()
		}

		for _, s := range p.bound {
			select {
			case err := <-s.Failed():
				p.close()

				return err
			default:
			}
		}
	}
}

func digest(content []byte) string {
	sum := sha256.Sum256(content)

	return hex.EncodeToString(sum[:])
}

// listenOn opens a listener's address (a variable, for tests).
var listenOn = listen

// open starts serving a listener of the configuration in effect.
func (p *process) open(l config.Listener) error {
	return p.openOn(l, nil)
}

// openOn starts serving a listener of the configuration in effect on raw, its address already open,
// or on its address opened now (raw nil).
func (p *process) openOn(l config.Listener, raw net.Listener) error {
	c := p.live.Load().Config

	g := gate.New(c, l, p.upstream, p.registry, p.defaults, p.spool, p.log)
	g.UseMetrics(p.metrics)
	g.Follow(p.live)

	if l.SocketBound() {
		sockets, err := gate.NewSockets(g, p.log)
		if err != nil {
			return fmt.Errorf("listener %s: %w", l.Name, err)
		}

		p.bound = append(p.bound, sockets)

		if err := sockets.Scan(); err != nil {
			return fmt.Errorf("listener %s: %w", l.Name, err)
		}

		p.log.Info("listening", "listener", l.Name, "mode", l.Mode, "scope_sockets", l.ScopeSockets)

		return nil
	}

	if raw == nil {
		var err error
		if raw, err = listenOn(l); err != nil {
			return fmt.Errorf("listener %s: %w", l.Name, err)
		}
	}

	// Its connections tracked, upgraded ones (streams) included, so a stop or a reload can close
	// them; TLS on top
	tracked := gate.Track(gate.LimitListener(raw, gate.MaxConnections))

	var listener net.Listener = tracked
	if files := p.certificates.For(l.Name); files != nil {
		listener = tls.NewListener(tracked, files.Config())
		g.UseTLS(files)
	}

	server := gate.NewServer(g)
	server.BaseContext = tracked.Context
	// What the server itself says (a TLS handshake that failed: another CA, no certificate)
	server.ErrorLog = slog.NewLogLogger(p.log.With("listener", l.Name).Handler(), slog.LevelInfo)
	p.served[l.Name] = &served{gate: g, server: server, listener: tracked}

	go func() {
		if err := server.Serve(listener); !errors.Is(err, http.ErrServerClosed) && !tracked.Closed() {
			p.failed <- fmt.Errorf("listener %s: %w", l.Name, err)
		}
	}()

	p.log.Info("listening", "listener", l.Name, "mode", l.Mode, "address", l.Address)

	return nil
}

// end closes a listener at once (a reload removed or moved it): its connections close, its streams
// logged as closed by why.
func (p *process) end(name, why string) {
	s, ok := p.served[name]
	if !ok {
		return
	}

	delete(p.served, name)

	now, cancel := context.WithCancel(context.Background())
	cancel()

	s.listener.Drain(now, s.gate, why)
	_ = s.server.Close()
}

// reload reads the configuration file again and, when it's another than the one in effect and valid
// (as `check` has it, without Docker) and changes nothing only a restart may, puts it in effect: the
// next request of every listener is decided by it, trusted listeners added are opened, removed ones
// closed, moved ones closed and opened again.
//
// A reload opens every listener it names, or isn't taken: each new address is opened first, while
// the running listeners serve, and one that can't be refuses the reload. A listener moved on its own
// address (its tls, plaintext or socket group) can only be opened again once it's closed: if that
// fails, the reload is undone (the running configuration, and its listeners, back) and refused.
// Otherwise it's logged, and the running configuration stays.
func (p *process) reload() {
	reloading()

	running := p.live.Load()

	content, err := os.ReadFile(p.path)
	if err != nil {
		p.refused("", err)

		return
	}

	sha := digest(content)

	// The file in effect, unchanged, its listeners open: SIGHUP is a rescan of the scopes, as it
	// always was
	if sha == running.SHA256 && p.live.AllOpen() {
		return
	}

	next, changes, err := p.validate(running.Config, content)
	if err != nil {
		p.refused(sha, err)

		return
	}

	closing := append(slices.Clone(changes.Removed), changes.Moved...)

	// What's opened: those added and moved, and any of the new configuration's not open now (one a
	// reload undone couldn't open again)
	var opening []config.Listener

	for _, l := range next.Listeners {
		_, open := p.served[l.Name]
		if !l.SocketBound() && (!open || slices.Contains(changes.Added, l.Name) || slices.Contains(changes.Moved, l.Name)) {
			opening = append(opening, l)
		}
	}

	// Their addresses, opened while the running listeners serve: those a listener being closed
	// holds are opened once it's closed
	held := map[string]bool{}

	for _, l := range running.Config.Listeners {
		if slices.Contains(closing, l.Name) {
			held[l.Address] = true
		}
	}

	bound := map[string]net.Listener{}
	unbind := func() {
		for name, raw := range bound {
			_ = raw.Close()
			delete(bound, name)
		}
	}

	for _, l := range opening {
		if held[l.Address] {
			continue
		}

		raw, err := listenOn(l)
		if err != nil {
			unbind()
			p.refused(sha, fmt.Errorf("listener %s can't be opened: %w", l.Name, err))

			return
		}

		bound[l.Name] = raw
	}

	names := make([]string, len(opening))
	for i, l := range opening {
		names[i] = l.Name
	}

	saved := p.certificates.Save()
	if err := p.certificates.Reconfigure(next, names); err != nil {
		unbind()
		p.certificates.Restore(saved)
		p.refused(sha, err)

		return
	}

	p.live.Swap(next, sha)
	p.defaults.Reconfigure(next)

	for _, name := range closing {
		p.end(name, "reload")
	}

	var opened []string

	for _, l := range opening {
		raw := bound[l.Name]
		delete(bound, l.Name)

		if err := p.openOn(l, raw); err != nil {
			unbind()
			p.undo(running, saved, opened, closing)
			p.refused(sha, fmt.Errorf("%w (the reload is undone)", err))

			return
		}

		opened = append(opened, l.Name)
	}

	p.live.Unopened("")
	p.metrics.Reloaded(true, next.Admin != nil && next.Admin.ScopeLabels)
	p.log.Info("configuration reloaded", "sha256", sha, "added", changes.Added, "removed", changes.Removed, "moved", changes.Moved, "changed", changes.Changed)

	for _, d := range next.Deprecations() {
		p.log.Warn("configuration", "warning", d)
	}
}

// undo puts the running configuration back after a reload that couldn't open a listener: what it
// opened is closed, and what it closed is opened again with the running configuration's settings.
// One that can't be is logged, and readiness fails until a reload opens it.
func (p *process) undo(running *gate.Runtime, saved gate.TLSState, opened, closed []string) {
	for _, name := range opened {
		p.end(name, "reload")
	}

	p.certificates.Restore(saved)
	p.live.Swap(running.Config, running.SHA256)
	p.defaults.Reconfigure(running.Config)

	var lost []string

	for _, l := range running.Config.Listeners {
		if !slices.Contains(closed, l.Name) {
			continue
		}

		if err := p.open(l); err != nil {
			p.log.Error("listener not opened again", "listener", l.Name, "error", err.Error())
			lost = append(lost, err.Error())
		}
	}

	if len(lost) > 0 {
		p.live.Unopened("a reload was undone, and these couldn't be opened again: " + strings.Join(lost, "; "))
	}
}

// validate checks a configuration as `check` does without Docker (its scope folders, TLS files and
// spool), and what it changes of the running one.
func (p *process) validate(running *config.Config, content []byte) (*config.Config, config.Reload, error) {
	next, err := config.Parse(content)
	if err != nil {
		return nil, config.Reload{}, err
	}

	changes, err := config.Compare(running, next)
	if err != nil {
		return nil, config.Reload{}, err
	}

	if err := gate.Registry(next).ReadOnly().Reload(); err != nil {
		return nil, config.Reload{}, err
	}

	if _, err := gate.LoadTLS(next, slog.New(slog.DiscardHandler)); err != nil {
		return nil, config.Reload{}, err
	}

	if err := gate.CheckSpool(next); err != nil {
		return nil, config.Reload{}, err
	}

	return next, changes, nil
}

// refused logs a reload that wasn't taken.
func (p *process) refused(sha string, err error) {
	p.metrics.Reloaded(false, false)
	p.log.Error("configuration not reloaded", "sha256", sha, "reason", err.Error())
}

// scan reloads the scope files, ends requests whose scope or credential no longer allows them (the
// configuration's too: a trusted listener's clients), brings each socket-bound listener's sockets in
// line with the files, then publishes the snapshot to the scope-status read. What fails is logged
// and tried again at the next scan: one scope's socket doesn't stop the others'.
func (p *process) scan() {
	if err := p.registry.Reload(); err != nil {
		p.log.Error("scope files", "error", err)
	}

	p.certificates.Reload()

	report(p.live.Load().Config, p.registry, p.reported, p.docker, p.log)

	for _, name := range slices.Sorted(maps.Keys(p.served)) {
		p.served[name].gate.Revoke()
	}

	for _, s := range p.bound {
		if err := s.Scan(); err != nil {
			p.log.Error("scope sockets", "error", err)
		}
	}

	p.registry.Publish()
}

// drain stops the process: readiness fails, every listener stops accepting at once (a unix
// socket's file goes), requests and streams have shutdown_grace to end, then what's still open is
// closed, its streams logged as closed by shutdown. A second SIGINT or SIGTERM ends the wait.
func (p *process) drain() {
	grace := p.live.Load().Config.Grace()

	again := make(chan os.Signal, 1)
	signal.Notify(again, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(again)

	p.live.Drain()
	p.log.Info("stopping", "grace_ms", grace.Milliseconds())

	waiting, cancel := context.WithTimeout(context.Background(), grace)
	defer cancel()

	go func() {
		select {
		case <-again:
			cancel()
		case <-waiting.Done():
		}
	}()

	var wg sync.WaitGroup

	for _, s := range p.served {
		wg.Go(func() {
			// Keep-alive connections take no new request; the server's listener closes
			go func() { _ = s.server.Shutdown(waiting) }()

			s.listener.Drain(waiting, s.gate, "shutdown")
			_ = s.server.Close()
		})
	}

	for _, s := range p.bound {
		wg.Go(func() { s.Drain(waiting, "shutdown") })
	}

	wg.Wait()

	if p.admin != nil {
		closing, done := context.WithTimeout(context.Background(), time.Second)
		_ = p.admin.Shutdown(closing)

		done()
	}

	p.log.Info("stopped")
}

// close stops everything at once (serve failed).
func (p *process) close() {
	for name := range p.served {
		p.end(name, "shutdown")
	}

	now, cancel := context.WithCancel(context.Background())
	cancel()

	for _, s := range p.bound {
		s.Drain(now, "shutdown")
	}

	if p.admin != nil {
		_ = p.admin.Close()
	}
}
