// Command yorvogate is YorvoGate: a policy gate for the Docker API.
//
//	yorvogate serve --config /etc/yorvogate/yorvogate.yaml
//	yorvogate check --config /etc/yorvogate/yorvogate.yaml
//	yorvogate version
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/yorvolabs/yorvogate/internal/config"
	"github.com/yorvolabs/yorvogate/internal/gate"
	"github.com/yorvolabs/yorvogate/internal/scope"
)

// version is set when a release is built (-ldflags "-X main.version=…").
var version = "dev"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: yorvogate serve|check|version [--config FILE]")

		return 2
	}

	command := args[0]
	flags := flag.NewFlagSet("yorvogate "+command, flag.ContinueOnError)
	flags.SetOutput(stderr)
	path := flags.String("config", "/etc/yorvogate/yorvogate.yaml", "the configuration file")

	if err := flags.Parse(args[1:]); err != nil {
		return 2
	}

	switch command {
	case "version":
		fmt.Fprintln(stdout, "yorvogate", version)

		return 0
	case "check":
		if err := check(*path, stdout); err != nil {
			fmt.Fprintln(stderr, "yorvogate:", err)

			return 1
		}

		return 0
	case "serve":
		log := slog.New(slog.NewJSONHandler(stderr, nil))
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()

		if err := serve(ctx, *path, log); err != nil {
			log.Error("stopped", "error", err)

			return 1
		}

		return 0
	}

	fmt.Fprintf(stderr, "yorvogate: unknown command %q (serve, check, version)\n", command)

	return 2
}

// listenerWarnings names a listener's choices that are valid but dangerous, so `check` can point
// them out (it doesn't refuse them: an operator may mean them).
func listenerWarnings(l config.Listener) []string {
	var w []string

	tcpOpen := false
	if hostPort, ok := strings.CutPrefix(l.Address, "tcp://"); ok {
		if host, _, err := net.SplitHostPort(hostPort); err == nil {
			ip := net.ParseIP(host)
			tcpOpen = host != "localhost" && (host == "" || ip == nil || !ip.IsLoopback())
		}
	}

	if tcpOpen && l.Mode == config.Scoped && !l.SocketBound() {
		w = append(w, "a scoped TCP listener on a non-loopback address sends scope tokens in cleartext (there's no TLS): bind it to loopback or a unix socket, or put TLS in front")
	}

	if tcpOpen && l.Mode == config.Trusted {
		for _, access := range l.Allow {
			if access == "write" {
				w = append(w, "a trusted listener with write access on a non-loopback address is full control of Docker, in cleartext")

				break
			}
		}
	}

	if l.Unix() && l.SocketGroup == "" {
		w = append(w, "no socket_group: the listener's unix sockets fall back to the process's primary group, which may let more than the intended clients connect")
	}

	if l.AllowPrivilegedBuilders {
		w = append(w, "allow_privileged_builders is on: a scope's builder is accepted whatever its configuration, so the scope can become root on the host")
	}

	return w
}

// check reads the configuration, and every scope file of its scoped listeners, as a gate starting
// now would (it reads the state file, and never writes it). It names every scope file refused.
func check(path string, stdout io.Writer) error {
	c, err := config.Load(path)
	if err != nil {
		return err
	}

	registry := gate.Registry(c).ReadOnly()
	if err := registry.Reload(); err != nil {
		return err
	}

	for _, d := range c.Deprecations() {
		fmt.Fprintf(stdout, "warning: %s\n", d)
	}

	var refused []string

	seen := map[string]bool{}
	scoped := false

	for _, l := range c.Listeners {
		if l.Mode != config.Scoped {
			fmt.Fprintf(stdout, "%s (%s, %s): ok\n", l.Name, l.Mode, l.Address)
			for _, warn := range listenerWarnings(l) {
				fmt.Fprintf(stdout, "  warning: %s\n", warn)
			}

			continue
		}

		scoped = true

		names, invalid, err := registry.Store(l.Name).Scopes()
		if err != nil {
			return err
		}

		address := l.Address
		if l.SocketBound() {
			address = "scope_sockets " + l.ScopeSockets
		}

		if len(invalid) == 0 {
			fmt.Fprintf(stdout, "%s (%s, %s): ok, %d scopes\n", l.Name, l.Mode, address, len(names))
		} else {
			fmt.Fprintf(stdout, "%s (%s, %s): %d scopes, %d refused\n", l.Name, l.Mode, address, len(names), len(invalid))
		}

		for _, warn := range listenerWarnings(l) {
			fmt.Fprintf(stdout, "  warning: %s\n", warn)
		}

		if old := registry.Store(l.Name).Unversioned(); len(old) > 0 {
			fmt.Fprintf(stdout, "  warning: %s\n", unversioned(old))
		}

		for _, name := range slices.Sorted(maps.Keys(invalid)) {
			if msg := invalid[name].Error(); !seen[msg] {
				seen[msg] = true
				refused = append(refused, msg)
			}
		}
	}

	for _, warn := range stateWarnings(c, registry, scoped) {
		fmt.Fprintf(stdout, "warning: %s\n", warn)
	}

	if len(refused) == 1 {
		return errors.New(refused[0])
	} else if len(refused) > 1 {
		return fmt.Errorf("%d scope files refused:\n  %s", len(refused), strings.Join(refused, "\n  "))
	}

	return nil
}

// unversioned says which scope files have no version (the first few of them).
func unversioned(names []string) string {
	list := names
	if len(list) > 5 {
		list = append(slices.Clone(list[:5]), fmt.Sprintf("and %d more", len(names)-5))
	}

	return fmt.Sprintf("%d scope files have no version (%s): they're read as version %d, and YorvoGate 0.4 refuses them without one (add \"version\": %d)", len(names), strings.Join(list, ", "), config.FormatVersion, config.FormatVersion)
}

// stateWarnings tells what isn't held across a restart.
func stateWarnings(c *config.Config, registry *scope.Registry, scoped bool) []string {
	var w []string

	if scoped && c.StateFile == "" {
		w = append(w, "no state_file: scopes' claims are held only while the gate runs, so a scope file that isn't valid when it starts leaves its names to a scope whose prefix they start with")
	}

	if err := registry.StateProblem(); err != nil {
		w = append(w, err.Error())
	}

	for _, dir := range registry.Missing() {
		w = append(w, "the scopes folder "+dir+" doesn't exist: no scopes there yet, and every claim the state file holds stays reserved until it does and the gate restarts")
	}

	for _, name := range registry.Reserved() {
		w = append(w, "scope "+name+"'s file isn't valid: its last valid claims are held for it, and no other scope gets them")
	}

	return w
}

// scanInterval is how often socket-bound listeners look for scope files that came, changed or went
// (and at once on SIGHUP).
var scanInterval = 2 * time.Second

// serve listens until the context ends (SIGINT or SIGTERM), then lets requests finish.
func serve(ctx context.Context, path string, log *slog.Logger) error {
	c, err := config.Load(path)
	if err != nil {
		return err
	}

	registry := gate.Registry(c)
	if err := registry.Reload(); err != nil {
		return err
	}

	for _, warn := range stateWarnings(c, registry, false) {
		log.Warn("scopes", "warning", warn)
	}

	for _, d := range c.Deprecations() {
		log.Warn("configuration", "warning", d)
	}

	reported := map[string]string{}
	report(c, registry, reported, log)

	// SIGHUP rescans the scope folders; it's taken before any socket is made, so it never stops the
	// process.
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)

	upstream := gate.NewUpstream(c, log)
	servers := make([]*http.Server, 0, len(c.Listeners))
	bound := []*gate.Sockets{}
	failed := make(chan error, len(c.Listeners))

	stop := func() {
		shutdown, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		for _, s := range servers {
			_ = s.Shutdown(shutdown)
		}

		for _, s := range bound {
			s.Shutdown(shutdown)
		}
	}
	defer stop()

	for _, l := range c.Listeners {
		g := gate.New(c, l, upstream, registry, log)

		if l.SocketBound() {
			sockets, err := gate.NewSockets(g, log)
			if err != nil {
				return fmt.Errorf("listener %s: %w", l.Name, err)
			}

			bound = append(bound, sockets)

			if err := sockets.Scan(); err != nil {
				return fmt.Errorf("listener %s: %w", l.Name, err)
			}

			log.Info("listening", "listener", l.Name, "mode", l.Mode, "scope_sockets", l.ScopeSockets)

			continue
		}

		listener, err := listen(l)
		if err != nil {
			return fmt.Errorf("listener %s: %w", l.Name, err)
		}

		server := gate.NewServer(g)
		servers = append(servers, server)

		listener = gate.LimitListener(listener, gate.MaxConnections)

		go func() {
			if err := server.Serve(listener); !errors.Is(err, http.ErrServerClosed) {
				failed <- fmt.Errorf("listener %s: %w", l.Name, err)
			}
		}()

		log.Info("listening", "listener", l.Name, "mode", l.Mode, "address", l.Address)
	}

	// Every listener is up, its scopes' sockets open: what the scope-status read answers from
	registry.Publish()

	ticker := time.NewTicker(scanInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-failed:
			return err
		case <-hup:
			scan(registry, bound, reported, c, log)
		case <-ticker.C:
			scan(registry, bound, reported, c, log)
		case <-registry.Requests():
			// A scope-status request waits for a scope file just written or removed
			scan(registry, bound, reported, c, log)
		}

		for _, s := range bound {
			select {
			case err := <-s.Failed():
				return err
			default:
			}
		}
	}
}

// scan reloads the scope files, brings each socket-bound listener's sockets in line with them, then
// publishes the snapshot to the scope-status read. What fails is logged and tried again at the next
// scan: one scope's socket doesn't stop the others'.
func scan(registry *scope.Registry, bound []*gate.Sockets, reported map[string]string, c *config.Config, log *slog.Logger) {
	if err := registry.Reload(); err != nil {
		log.Error("scope files", "error", err)
	}

	report(c, registry, reported, log)

	for _, s := range bound {
		if err := s.Scan(); err != nil {
			log.Error("scope sockets", "error", err)
		}
	}

	registry.Publish()
}

// report logs, once each, what the last reload refused on token listeners (socket-bound listeners
// log theirs as they close the sockets) and what isn't held across a restart.
func report(c *config.Config, registry *scope.Registry, reported map[string]string, log *slog.Logger) {
	now := map[string]string{}

	for _, l := range c.Listeners {
		if l.Mode != config.Scoped || l.SocketBound() {
			continue
		}

		_, invalid, err := registry.Store(l.Name).Scopes()
		if err != nil {
			continue
		}

		for name, why := range invalid {
			now[l.Name+"/"+name] = why.Error()
		}
	}

	for _, l := range c.Listeners {
		if l.Mode == config.Scoped {
			if old := registry.Store(l.Name).Unversioned(); len(old) > 0 {
				now["unversioned/"+l.Name] = unversioned(old)
			}
		}
	}

	if err := registry.StateProblem(); err != nil {
		now["state"] = err.Error()
	}

	for key, why := range now {
		if reported[key] == why {
			continue
		}

		if key == "state" {
			log.Error("state file", "reason", why)
		} else if listener, ok := strings.CutPrefix(key, "unversioned/"); ok {
			log.Warn("scope files", "listener", listener, "warning", why)
		} else {
			listener, name, _ := strings.Cut(key, "/")
			log.Warn("scope file isn't valid", "listener", listener, "scope", name, "reason", why)
		}
	}

	clear(reported)
	maps.Copy(reported, now)
}

// listen opens a listener's address; a unix socket is made readable and writable by its group only.
func listen(l config.Listener) (net.Listener, error) {
	network, err := l.Network()
	if err != nil {
		return nil, err
	}

	if network[0] != "unix" {
		return net.Listen(network[0], network[1])
	}

	gid, err := gate.Group(l)
	if err != nil {
		return nil, err
	}

	return gate.Listen(network[1], gid)
}
