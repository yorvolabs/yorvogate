// Command yorvogate is YorvoGate: a policy gate for the Docker API.
//
//	yorvogate serve --config /etc/yorvogate/yorvogate.yaml
//	yorvogate check --config /etc/yorvogate/yorvogate.yaml
//	yorvogate version
package main

import (
	"context"
	"crypto/tls"
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
		fmt.Fprintln(stderr, "usage: yorvogate serve|check|version [--config FILE] [--docker (check)]")

		return 2
	}

	command := args[0]
	flags := flag.NewFlagSet("yorvogate "+command, flag.ContinueOnError)
	flags.SetOutput(stderr)
	path := flags.String("config", "/etc/yorvogate/yorvogate.yaml", "the configuration file")
	docker := flags.Bool("docker", false, "check: also read Docker's defaults, through the configuration's upstream")

	if err := flags.Parse(args[1:]); err != nil {
		return 2
	}

	switch command {
	case "version":
		fmt.Fprintln(stdout, "yorvogate", version)

		return 0
	case "check":
		if err := check(*path, *docker, stdout); err != nil {
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

	if l.Plaintext != "" {
		switch {
		case l.Mode == config.Scoped && l.TLS == nil:
			w = append(w, "plaintext: scope tokens travel off loopback in cleartext, where anyone on the way can read and replay them: use tls with client_ca, or a unix socket")
		case l.Mode == config.Scoped:
			w = append(w, "plaintext: scope tokens travel off loopback, where whatever ends the TLS connection can replay them: use tls.client_ca, so the certificate is the scope")
		default:
			w = append(w, "plaintext: a trusted listener off loopback without client certificates lets anyone who reaches it in: use tls with client_ca")
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

// tlsWarnings: a listener's certificate expiring soon, and on an mTLS listener, the scopes that pin
// no certificate (any its CA issues with their name is theirs).
func tlsWarnings(l config.Listener, certificates *gate.TLS, store *scope.Store, names []string) []string {
	files := certificates.For(l.Name)
	if files == nil {
		return nil
	}

	var w []string

	if expires := files.Expires(); time.Until(expires) < gate.ExpiresSoon {
		w = append(w, fmt.Sprintf("tls.certificate expires %s: renew it (it's read again when it changes)", expires.UTC().Format(time.RFC3339)))
	}

	if store == nil || !l.MutualTLS() {
		return w
	}

	var unpinned []string

	for _, name := range names {
		if s, err := store.Get(name); err == nil && len(s.Certificates) == 0 {
			unpinned = append(unpinned, name)
		}
	}

	if len(unpinned) > 0 {
		w = append(w, fmt.Sprintf("scopes without certificates (%s): any certificate the listener's CA issues with one of their names is that scope, and one can't be revoked without changing the CA; pin their public keys", strings.Join(unpinned, ", ")))
	}

	return w
}

// TokensExpireSoon is how long before a scope's token expires it's warned about.
const TokensExpireSoon = 7 * 24 * time.Hour

// tokenWarnings names, on a token listener, the scopes' tokens that have expired (kept in the file,
// and refused) and those expiring within TokensExpireSoon: each by the first digits of its digest.
func tokenWarnings(l config.Listener, store *scope.Store, names []string) []string {
	if store == nil || l.SocketBound() || l.MutualTLS() {
		return nil
	}

	var w []string

	for _, name := range names {
		s, err := store.Get(name)
		if err != nil {
			continue
		}

		expired, soon := s.Expiring(time.Now(), TokensExpireSoon)
		if len(expired) > 0 {
			w = append(w, fmt.Sprintf("scope %s: tokens expired, and refused (%s): remove them from its file", name, strings.Join(expired, ", ")))
		}

		if len(soon) > 0 {
			w = append(w, fmt.Sprintf("scope %s: tokens expiring within 7 days (%s): give its client another", name, strings.Join(soon, ", ")))
		}
	}

	return w
}

// check reads the configuration, and every scope file of its scoped listeners, as a gate starting
// now would (it reads the state file, and never writes it). It names every scope file refused.
func check(path string, docker bool, stdout io.Writer) error {
	c, err := config.Load(path)
	if err != nil {
		return err
	}

	registry := gate.Registry(c).ReadOnly()
	if err := registry.Reload(); err != nil {
		return err
	}

	certificates, err := gate.LoadTLS(c, slog.New(slog.DiscardHandler))
	if err != nil {
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
			for _, warn := range append(listenerWarnings(l), tlsWarnings(l, certificates, nil, nil)...) {
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

		warnings := append(listenerWarnings(l), tlsWarnings(l, certificates, registry.Store(l.Name), names)...)
		for _, warn := range append(warnings, tokenWarnings(l, registry.Store(l.Name), names)...) {
			fmt.Fprintf(stdout, "  warning: %s\n", warn)
		}

		if old := registry.Store(l.Name).Unversioned(); len(old) > 0 {
			fmt.Fprintf(stdout, "  warning: %s\n", unversioned(old))
		}

		for _, notice := range unlistedRegistries(l, registry.Store(l.Name), names) {
			fmt.Fprintf(stdout, "  notice: %s\n", notice)
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

	if docker {
		unsafe, notes := gate.NewDefaults(c).Check(context.Background())
		if len(unsafe) == 0 {
			fmt.Fprintln(stdout, "Docker's defaults: ok")
		} else {
			fmt.Fprintln(stdout, "Docker's defaults: unsafe, scoped listeners would refuse every request")
			refused = append(refused, "Docker's defaults would widen what scopes may do: "+strings.Join(unsafe, "; "))
		}

		for _, n := range notes {
			fmt.Fprintf(stdout, "  notice: %s\n", n)
		}

		for _, warn := range egressLeaks(c, registry) {
			fmt.Fprintf(stdout, "  warning: %s\n", warn)
		}
	}

	if len(refused) == 1 {
		return errors.New(refused[0])
	} else if len(refused) > 1 {
		return fmt.Errorf("%d scope files refused:\n  %s", len(refused), strings.Join(refused, "\n  "))
	}

	return nil
}

// egressLeaks names, for each egress-free scope, its running containers on a network that isn't
// internal: they keep their way out until they're disconnected or recreated.
func egressLeaks(c *config.Config, registry *scope.Registry) []string {
	docker := gate.NewDocker(c.UpstreamSocket())

	var warnings []string

	for _, l := range c.Listeners {
		if l.Mode != config.Scoped {
			continue
		}

		store := registry.Store(l.Name)
		names, _, err := store.Scopes()
		if err != nil {
			continue
		}

		for _, name := range names {
			s, err := store.Get(name)
			if err != nil || s == nil || (s.Egress != "none" && l.Containers.Egress != "none") {
				continue
			}

			leaks, err := gate.EgressLeaks(context.Background(), docker, config.Lowest.String(), s.Owner.Key, s.Owner.Value)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("scope %s (egress: none): its running containers couldn't be checked: %v", name, err))
			} else if len(leaks) > 0 {
				warnings = append(warnings, fmt.Sprintf("scope %s (egress: none) has running containers on a network that isn't internal: %s; disconnect or recreate them", name, strings.Join(leaks, ", ")))
			}
		}
	}

	return warnings
}

// unlistedRegistries names each scope whose image namespaces are on a registry its listener's pulls
// don't list: its pulls from there are refused. (A registry is listed only for the whole listener:
// listing one trusts it with every scope's content.)
func unlistedRegistries(l config.Listener, store *scope.Store, names []string) []string {
	var notices []string

	for _, name := range names {
		s, err := store.Get(name)
		if err != nil || s == nil {
			continue
		}

		var unlisted []string

		for _, namespace := range s.Images {
			if r := gate.ReferenceRegistry(namespace); !l.Pulls.Allows(r) && !slices.Contains(unlisted, r) {
				unlisted = append(unlisted, r)
			}
		}

		if len(unlisted) > 0 {
			notices = append(notices, fmt.Sprintf("scope %s's images are on %s, which pulls.registries doesn't list: its pulls from there are refused", name, strings.Join(unlisted, ", ")))
		}
	}

	return notices
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

	certificates, err := gate.LoadTLS(c, log)
	if err != nil {
		return err
	}

	for _, warn := range stateWarnings(c, registry, false) {
		log.Warn("scopes", "warning", warn)
	}

	for _, d := range c.Deprecations() {
		log.Warn("configuration", "warning", d)
	}

	reported := map[string]string{}
	docker := gate.NewDocker(c.UpstreamSocket())
	report(c, registry, reported, docker, log)

	// SIGHUP rescans the scope folders; it's taken before any socket is made, so it never stops the
	// process.
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)

	upstream := gate.NewUpstream(c, log)

	// Docker's defaults, read while scoped listeners serve: until they're read, and while they're
	// unsafe, scoped requests are refused.
	defaults := gate.NewDefaults(c)
	if slices.ContainsFunc(c.Listeners, func(l config.Listener) bool { return l.Mode == config.Scoped }) {
		// Read once before the first answer, so a scope isn't refused for a read not yet made
		defaults.Read(ctx)

		watching, unwatch := context.WithCancel(ctx)
		defer unwatch()

		go defaults.Watch(watching, log)
	}

	servers := make([]*http.Server, 0, len(c.Listeners))
	bound := []*gate.Sockets{}
	// Gates of scoped and mTLS listeners with an address: each ends the requests whose allowance goes
	tokens := []*gate.Gate{}
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
		g := gate.New(c, l, upstream, registry, defaults, log)

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

		listener = gate.LimitListener(listener, gate.MaxConnections)
		if files := certificates.For(l.Name); files != nil {
			listener = tls.NewListener(listener, files.Config())
			g.UseTLS(files)
		}

		if l.Mode == config.Scoped || l.MutualTLS() {
			tokens = append(tokens, g)
		}

		server := gate.NewServer(g)
		// What the server itself says (a TLS handshake that failed: another CA, no certificate)
		server.ErrorLog = slog.NewLogLogger(log.With("listener", l.Name).Handler(), slog.LevelInfo)
		servers = append(servers, server)

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
			scan(registry, certificates, bound, tokens, reported, docker, c, log)
		case <-ticker.C:
			scan(registry, certificates, bound, tokens, reported, docker, c, log)
		case <-registry.Requests():
			// A scope-status request waits for a scope file just written or removed
			scan(registry, certificates, bound, tokens, reported, docker, c, log)
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

// scan reloads the scope files, ends token listeners' requests whose scope no longer allows them,
// brings each socket-bound listener's sockets in line with the files, then publishes the snapshot to
// the scope-status read. What fails is logged and tried again at the next scan: one scope's socket
// doesn't stop the others'.
func scan(registry *scope.Registry, certificates *gate.TLS, bound []*gate.Sockets, tokens []*gate.Gate, reported map[string]string, docker *gate.Docker, c *config.Config, log *slog.Logger) {
	if err := registry.Reload(); err != nil {
		log.Error("scope files", "error", err)
	}

	certificates.Reload()

	report(c, registry, reported, docker, log)

	for _, g := range tokens {
		g.Revoke()
	}

	for _, s := range bound {
		if err := s.Scan(); err != nil {
			log.Error("scope sockets", "error", err)
		}
	}

	registry.Publish()
}

// report logs, once each, what the last reload refused on token listeners (socket-bound listeners
// log theirs as they close the sockets) and what isn't held across a restart.
func report(c *config.Config, registry *scope.Registry, reported map[string]string, docker *gate.Docker, log *slog.Logger) {
	now := map[string]string{}

	// A scope that has just become egress-free: its running containers on a network that isn't
	// internal keep their way out until they're disconnected or recreated.
	for _, l := range c.Listeners {
		if l.Mode != config.Scoped {
			continue
		}

		store := registry.Store(l.Name)
		names, _, err := store.Scopes()
		if err != nil {
			continue
		}

		for _, name := range names {
			s, err := store.Get(name)
			if err != nil || s == nil || (s.Egress != "none" && l.Containers.Egress != "none") {
				continue
			}

			key := "egress/" + l.Name + "/" + name
			now[key] = "none"

			if reported[key] == "none" || docker == nil {
				continue
			}

			leaks, err := gate.EgressLeaks(context.Background(), docker, config.Lowest.String(), s.Owner.Key, s.Owner.Value)
			if err != nil {
				log.Warn("egress: none", "listener", l.Name, "scope", name, "warning", "its running containers couldn't be checked: "+err.Error())
			}

			for _, leak := range leaks {
				log.Warn("egress: none", "listener", l.Name, "scope", name, "warning", "a running container is on a network that isn't internal, and keeps its way out until it's disconnected or recreated", "container", leak)
			}
		}
	}

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

			if names, _, err := registry.Store(l.Name).Scopes(); err == nil {
				if w := tokenWarnings(l, registry.Store(l.Name), names); len(w) > 0 {
					now["tokens/"+l.Name] = strings.Join(w, "; ")
				}
			}
		}
	}

	if err := registry.StateProblem(); err != nil {
		now["state"] = err.Error()
	}

	for key, why := range now {
		if reported[key] == why || strings.HasPrefix(key, "egress/") {
			continue
		}

		if key == "state" {
			log.Error("state file", "reason", why)
		} else if listener, ok := strings.CutPrefix(key, "unversioned/"); ok {
			log.Warn("scope files", "listener", listener, "warning", why)
		} else if listener, ok := strings.CutPrefix(key, "tokens/"); ok {
			log.Warn("scope tokens", "listener", listener, "warning", why)
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
