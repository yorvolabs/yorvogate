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

// check reads the configuration, and every scope file of its scoped listeners.
func check(path string, stdout io.Writer) error {
	c, err := config.Load(path)
	if err != nil {
		return err
	}

	for _, l := range c.Listeners {
		if l.Mode != config.Scoped {
			fmt.Fprintf(stdout, "%s (%s, %s): ok\n", l.Name, l.Mode, l.Address)

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
