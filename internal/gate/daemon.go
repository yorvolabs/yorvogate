package gate

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/yorvolabs/yorvogate/internal/config"
)

// What a scope's container leaves unset, Docker fills from its own configuration. YorvoGate writes the
// safe value into what it forwards where Docker lets it (a private cgroup namespace, Docker's built-in
// seccomp profile, the default runtime it checked), and reads Docker's defaults for the rest: while
// they would widen what a scope may do (no seccomp in the kernel, no AppArmor or SELinux, a default
// runtime not allowed), or haven't been read, scoped listeners refuse every request.

// How often Docker's defaults are read, and how soon again when they couldn't be
const (
	defaultsEvery = 60 * time.Second
	defaultsRetry = 10 * time.Second
)

// Defaults is what YorvoGate last read of Docker's defaults, shared by every scoped listener.
type Defaults struct {
	docker  *Docker
	runtime func(string) bool
	noLSM   bool
	state   atomic.Pointer[daemonState]
}

// daemonState is one read of Docker's defaults.
type daemonState struct {
	// Why Docker's defaults would widen what scopes may do; none when they're safe
	unsafe []string
	// What's worth knowing but changes nothing YorvoGate checked
	notes []string
	// Docker's default runtime, as this read found it
	runtime string
}

// NewDefaults reads Docker's defaults for a configuration's scoped listeners: a default runtime is
// allowed when it's runc or each scoped listener lists it.
func NewDefaults(c *config.Config) *Defaults {
	var lists [][]string

	for _, l := range c.Listeners {
		if l.Mode == config.Scoped {
			lists = append(lists, l.Containers.Runtimes)
		}
	}

	return &Defaults{
		docker: NewDocker(c.UpstreamSocket()),
		noLSM:  c.Daemon.WithoutLSM,
		runtime: func(r string) bool {
			return r == "runc" || !slices.ContainsFunc(lists, func(l []string) bool { return !slices.Contains(l, r) })
		},
	}
}

// dockerInfo is what YorvoGate reads of Docker's /info.
type dockerInfo struct {
	SecurityOptions []string
	DefaultRuntime  string
}

// Read reads Docker's defaults once. A read that fails is unsafe: what Docker would do isn't known.
func (d *Defaults) Read(ctx context.Context) *daemonState {
	var info dockerInfo

	found, err := d.docker.fetch(ctx, config.Lowest.String(), "/info", &info)
	if err == nil && !found {
		err = errors.New("no /info from Docker")
	}

	state := &daemonState{}
	if err != nil {
		state.unsafe = []string{fmt.Sprintf("they couldn't be read (%v)", err)}
	} else {
		state = judge(info, d.runtime, d.noLSM)
	}

	d.state.Store(state)

	return state
}

// Check reads Docker's defaults once, for `check --docker`: what would widen what scopes may do, and
// what's only noted.
func (d *Defaults) Check(ctx context.Context) (unsafe, notes []string) {
	state := d.Read(ctx)

	return state.unsafe, state.notes
}

// Watch reads Docker's defaults until the context ends, logging each change of what's unsafe.
func (d *Defaults) Watch(ctx context.Context, log *slog.Logger) {
	last := "\x00"

	for ctx.Err() == nil {
		state := d.Read(ctx)
		wait := defaultsEvery

		if now := strings.Join(state.unsafe, "; "); now != last {
			if now == "" {
				log.Info("Docker's defaults are safe", "notes", state.notes)
			} else {
				log.Error("Docker's defaults would widen what scopes may do: scoped listeners refuse every request", "reasons", state.unsafe)
			}

			last = now
		}

		if len(state.unsafe) > 0 {
			wait = defaultsRetry
		}

		select {
		case <-ctx.Done():
		case <-time.After(wait):
		}
	}
}

// current is the last read of Docker's defaults, or why a scope's requests are refused now: they're
// unsafe, or haven't been read.
func (d *Defaults) current() (*daemonState, error) {
	state := d.state.Load()
	if state == nil {
		return nil, refuse(http.StatusServiceUnavailable, "Docker's defaults haven't been read yet: scoped requests wait for them")
	}

	if len(state.unsafe) > 0 {
		return nil, refuse(http.StatusServiceUnavailable, "Docker's defaults would widen what scopes may do: %s", strings.Join(state.unsafe, "; "))
	}

	return state, nil
}

// securityOption reads one of /info's SecurityOptions ("name=seccomp,profile=builtin").
func securityOption(o string) map[string]string {
	fields := map[string]string{}

	for _, kv := range strings.Split(o, ",") {
		k, v, _ := strings.Cut(kv, "=")
		fields[k] = v
	}

	return fields
}

// judge tells, of Docker's defaults, what would widen what scopes may do, and what's only noted.
// (moby 29.9.2, daemon/info.go:198-229, writes SecurityOptions.)
func judge(info dockerInfo, runtimeAllowed func(string) bool, noLSM bool) *daemonState {
	state := &daemonState{runtime: info.DefaultRuntime}
	options := map[string]map[string]string{}

	for _, o := range info.SecurityOptions {
		fields := securityOption(o)
		options[fields["name"]] = fields
	}

	switch seccomp, ok := options["seccomp"]; {
	case !ok:
		state.unsafe = append(state.unsafe, "the kernel has no seccomp (Docker's info lists none), so no container has a seccomp profile")
	case seccomp["profile"] == "unconfined":
		state.notes = append(state.notes, "Docker's own seccomp profile is unconfined: scopes' containers get Docker's built-in one, which YorvoGate asks for")
	case seccomp["profile"] != "builtin":
		state.notes = append(state.notes, fmt.Sprintf("Docker's own seccomp profile is %s: scopes' containers get Docker's built-in one, which YorvoGate asks for", seccomp["profile"]))
	}

	_, apparmor := options["apparmor"]
	_, selinux := options["selinux"]

	switch {
	case !apparmor && !selinux && noLSM:
		state.notes = append(state.notes, "Docker has neither AppArmor nor SELinux, as daemon.without_lsm accepts")
	case !apparmor && !selinux:
		state.unsafe = append(state.unsafe, "Docker has neither AppArmor nor SELinux (set daemon.without_lsm: true to accept that)")
	case apparmor && options["apparmor"]["profile"] != "default" && options["apparmor"]["profile"] != "":
		state.notes = append(state.notes, fmt.Sprintf("Docker's AppArmor profile is %s", options["apparmor"]["profile"]))
	}

	if info.DefaultRuntime == "" {
		state.unsafe = append(state.unsafe, "Docker's info names no default runtime")
	} else if !runtimeAllowed(info.DefaultRuntime) {
		state.unsafe = append(state.unsafe, fmt.Sprintf("Docker's default runtime %s isn't runc, nor one every scoped listener allows", info.DefaultRuntime))
	}

	for name, note := range map[string]string{
		"userns":            "Docker remaps user namespaces (userns-remap): volumes' files are owned by the remapped users",
		"rootless":          "Docker is rootless",
		"no-new-privileges": "Docker runs every container with no-new-privileges",
	} {
		if _, ok := options[name]; ok {
			state.notes = append(state.notes, note)
		}
	}

	if _, ok := options["cgroupns"]; !ok {
		state.notes = append(state.notes, "Docker's default cgroup namespace is the host's: scopes' containers get a private one, which YorvoGate asks for")
	}

	slices.Sort(state.notes)

	return state
}
