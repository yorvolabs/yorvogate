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
		if err := serve(*path, log); err != nil {
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

		store := scope.NewStore(l.Scopes)
		for _, f := range files {
			if _, err := store.Get(strings.TrimSuffix(filepath.Base(f), ".json")); err != nil {
				return err
			}
		}

		fmt.Fprintf(stdout, "%s (%s, %s): ok, %d scopes\n", l.Name, l.Mode, l.Address, len(files))
	}

	return nil
}

func serve(path string, log *slog.Logger) error {
	c, err := config.Load(path)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	upstream := gate.NewUpstream(c.UpstreamSocket(), log)
	servers := make([]*http.Server, 0, len(c.Listeners))
	failed := make(chan error, len(c.Listeners))

	for _, l := range c.Listeners {
		listener, err := listen(l)
		if err != nil {
			return fmt.Errorf("listener %s: %w", l.Name, err)
		}

		server := &http.Server{
			Handler:           gate.New(c, l, upstream, log),
			ReadHeaderTimeout: 10 * time.Second,
			IdleTimeout:       2 * time.Minute,
			MaxHeaderBytes:    64 << 10,
		}
		servers = append(servers, server)

		go func() {
			if err := server.Serve(listener); !errors.Is(err, http.ErrServerClosed) {
				failed <- fmt.Errorf("listener %s: %w", l.Name, err)
			}
		}()

		log.Info("listening", "listener", l.Name, "mode", l.Mode, "address", l.Address)
	}

	select {
	case <-ctx.Done():
	case err := <-failed:
		return err
	}

	shutdown, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	for _, s := range servers {
		_ = s.Shutdown(shutdown)
	}

	return nil
}

// listen opens a listener's address; a unix socket is made readable and writable by its group only.
func listen(l config.Listener) (net.Listener, error) {
	network, err := l.Network()
	if err != nil {
		return nil, err
	}

	if network[0] == "unix" {
		if info, err := os.Lstat(network[1]); err == nil && info.Mode()&os.ModeSocket != 0 {
			_ = os.Remove(network[1])
		}
	}

	listener, err := net.Listen(network[0], network[1])
	if err != nil {
		return nil, err
	}

	if network[0] == "unix" {
		if err := os.Chmod(network[1], 0o660); err != nil {
			_ = listener.Close()

			return nil, err
		}
	}

	return listener, nil
}
