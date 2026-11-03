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
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
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

// crossListener refuses an owner label, prefix, image namespace or builder that scopes on two
// different scoped listeners share. Within one listener the store refuses the later of two scopes
// that collide, but the listeners share one Docker, so a label or name claimed on two listeners
// lets one listener's scope reach the other's objects. Startup-time: the scope folders are
// re-read, so a collision introduced later is caught by `yorvogate check` or the next start.
func crossListener(c *config.Config) error {
	type claim struct{ listener, scope string }
	owners, prefixes, images, builders := map[string]claim{}, map[string]claim{}, map[string]claim{}, map[string]claim{}

	for _, l := range c.Listeners {
		if l.Mode != config.Scoped {
			continue
		}

		store := scope.NewStore(l.Scopes)
		if l.SocketBound() {
			store = scope.NewSocketStore(l.Scopes)
		}

		files, err := filepath.Glob(filepath.Join(l.Scopes, "*.json"))
		if err != nil {
			return err
		}

		for _, f := range files {
			name := strings.TrimSuffix(filepath.Base(f), ".json")

			sc, err := store.Get(name)
			if err != nil {
				continue // invalid, or a within-listener conflict the store already refuses
			}

			claimed := func(m map[string]claim, key, kind string) error {
				// A different scope claiming the same key is the conflict (one scope could reach the
				// other's objects). The same scope on two listeners (often one scopes folder served
				// both by token and by socket) is fine: a client is that one scope either way.
				if other, ok := m[key]; ok && other.scope != name {
					return fmt.Errorf("%s %q is scope %s's on listener %s and scope %s's on listener %s: two scopes on listeners of one Docker may not share it", kind, key, other.scope, other.listener, name, l.Name)
				}

				m[key] = claim{l.Name, name}

				return nil
			}

			if err := claimed(owners, sc.Owner.Key+"="+sc.Owner.Value, "owner label"); err != nil {
				return err
			}

			for _, p := range sc.Prefixes {
				if err := claimed(prefixes, p, "prefix"); err != nil {
					return err
				}
			}

			for _, i := range sc.Images {
				if err := claimed(images, i, "image namespace"); err != nil {
					return err
				}
			}

			for _, b := range sc.Builders {
				if err := claimed(builders, b, "builder"); err != nil {
					return err
				}
			}
		}
	}

	return nil
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

// check reads the configuration, and every scope file of its scoped listeners.
func check(path string, stdout io.Writer) error {
	c, err := config.Load(path)
	if err != nil {
		return err
	}

	for _, l := range c.Listeners {
		if l.Mode != config.Scoped {
			fmt.Fprintf(stdout, "%s (%s, %s): ok\n", l.Name, l.Mode, l.Address)
			for _, warn := range listenerWarnings(l) {
				fmt.Fprintf(stdout, "  warning: %s\n", warn)
			}

			continue
		}

		files, err := filepath.Glob(filepath.Join(l.Scopes, "*.json"))
		if err != nil {
			return err
		}

		store, address := scope.NewStore(l.Scopes), l.Address
		if l.SocketBound() {
			store, address = scope.NewSocketStore(l.Scopes), "scope_sockets "+l.ScopeSockets
		}

		for _, f := range files {
			if _, err := store.Get(strings.TrimSuffix(filepath.Base(f), ".json")); err != nil {
				return err
			}
		}

		fmt.Fprintf(stdout, "%s (%s, %s): ok, %d scopes\n", l.Name, l.Mode, address, len(files))
		for _, warn := range listenerWarnings(l) {
			fmt.Fprintf(stdout, "  warning: %s\n", warn)
		}
	}

	if err := crossListener(c); err != nil {
		return err
	}

	return nil
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

	if err := crossListener(c); err != nil {
		return err
	}

	// SIGHUP rescans the scope folders; it's taken before any socket is made, so it never stops the
	// process.
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)

	upstream := gate.NewUpstream(c.UpstreamSocket(), log)
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
		g := gate.New(c, l, upstream, log)

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

	ticker := time.NewTicker(scanInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-failed:
			return err
		case <-hup:
			scan(bound, log)
		case <-ticker.C:
			scan(bound, log)
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

// scan brings each socket-bound listener's sockets in line with its scope files. What fails is
// logged and tried again at the next scan: one scope's socket doesn't stop the others'.
func scan(bound []*gate.Sockets, log *slog.Logger) {
	for _, s := range bound {
		if err := s.Scan(); err != nil {
			log.Error("scope sockets", "error", err)
		}
	}
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
