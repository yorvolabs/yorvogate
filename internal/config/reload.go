package config

import (
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strings"
)

// A reload (SIGHUP) swaps a new configuration in while YorvoGate serves. Each key is one of:
//
//   - reloadable: what the gate decides by (policies, limits), taken by the next request;
//   - moved (a trusted listener's transport): the listener is closed and opened again with it;
//   - restart: it can't change while serving, and a reload that changes it is refused, the running
//     configuration kept.
//
// Scoped listeners' layout is restart-only: the registry decides claims across every scoped
// listener's folder, by listener name, and each folder's rules (tokens, certificates, peer users)
// come from those keys.

// keyClass is how a reload treats a key.
type keyClass int

const (
	reloadable keyClass = iota
	// a trusted listener's: it's closed and opened again; a scoped listener's: restart
	transport
	// restart only
	restart
	// a listener's identity: a trusted listener renamed is one removed and one added; a scoped
	// listener's can't change
	identity
)

// configKeys classifies every key of the configuration's top level and of its parts. A key added
// to a type and not here fails the test that reads the types' yaml tags.
var configKeys = map[string]keyClass{
	"version":        reloadable,
	"upstream":       restart,
	"api":            reloadable,
	"body_limit":     reloadable,
	"load_limit":     reloadable,
	"listeners":      reloadable, // by listener (listenerKeys)
	"state_file":     restart,
	"spool":          reloadable, // by key (spoolKeys)
	"admin":          reloadable, // by key (adminKeys); adding or removing it is a restart
	"daemon":         reloadable,
	"shutdown_grace": reloadable,
}

var spoolKeys = map[string]keyClass{
	"dir":      restart,
	"limit":    reloadable,
	"loads":    reloadable,
	"ratio":    reloadable,
	"unpacked": reloadable,
}

var adminKeys = map[string]keyClass{
	"address":      restart,
	"socket_group": restart,
	"scope_labels": reloadable,
}

var listenerKeys = map[string]keyClass{
	"name":                      identity,
	"mode":                      identity,
	"address":                   transport,
	"scope_sockets":             transport,
	"socket_group":              transport,
	"tls":                       transport,
	"plaintext":                 transport,
	"scopes":                    restart,
	"require_peer_uids":         restart,
	"allow":                     reloadable,
	"containers":                reloadable,
	"builder_apparmor_profiles": reloadable,
	"allow_privileged_builders": reloadable,
	"pulls":                     reloadable,
	"clients":                   reloadable,
}

// Reload is what a new configuration changes of the running one, by listener name.
type Reload struct {
	// Trusted listeners only in the new configuration, only in the running one, and in both with
	// another transport (closed and opened again)
	Added, Removed, Moved []string
	// Listeners whose policy changed, in place
	Changed []string
}

// Empty says whether no listener is added, removed, moved or changed.
func (r Reload) Empty() bool {
	return len(r.Added)+len(r.Removed)+len(r.Moved)+len(r.Changed) == 0
}

// Compare says what loading next in place of the running configuration changes, or why it can't be
// loaded while serving: a key that only a restart changes.
func Compare(running, next *Config) (Reload, error) {
	var r Reload

	restartOnly := func(key string) error {
		return fmt.Errorf("%s can't change while YorvoGate serves: restart it to change that (the running configuration is kept)", key)
	}

	for _, key := range sorted(configKeys) {
		class := configKeys[key]
		if class == restart && !reflect.DeepEqual(field(running, key), field(next, key)) {
			return r, restartOnly(key)
		}
	}

	for _, key := range sorted(spoolKeys) {
		class := spoolKeys[key]
		if class == restart && !reflect.DeepEqual(field(&running.Spool, key), field(&next.Spool, key)) {
			return r, restartOnly("spool." + key)
		}
	}

	switch {
	case (running.Admin == nil) != (next.Admin == nil):
		return r, restartOnly("admin")
	case running.Admin != nil:
		for _, key := range sorted(adminKeys) {
			class := adminKeys[key]
			if class == restart && !reflect.DeepEqual(field(running.Admin, key), field(next.Admin, key)) {
				return r, restartOnly("admin." + key)
			}
		}
	}

	old, now := byName(running.Listeners), byName(next.Listeners)

	for _, name := range sortedNames(old, now) {
		o, inOld := old[name]
		n, inNew := now[name]

		scoped := inOld && o.Mode == Scoped || inNew && n.Mode == Scoped
		if scoped {
			if !inOld || !inNew {
				return r, restartOnly("listener " + name + " (a scoped listener added or removed)")
			}

			for _, key := range sorted(listenerKeys) {
				class := listenerKeys[key]
				if class != reloadable && !reflect.DeepEqual(field(o, key), field(n, key)) {
					return r, restartOnly("listener " + name + "'s " + key)
				}
			}

			if !reflect.DeepEqual(*o, *n) {
				r.Changed = append(r.Changed, name)
			}

			continue
		}

		switch {
		case !inOld:
			r.Added = append(r.Added, name)
		case !inNew:
			r.Removed = append(r.Removed, name)
		default:
			moved := false

			for _, key := range sorted(listenerKeys) {
				class := listenerKeys[key]
				if class == transport && !reflect.DeepEqual(field(o, key), field(n, key)) {
					moved = true
				}
			}

			switch {
			case moved:
				r.Moved = append(r.Moved, name)
			case !reflect.DeepEqual(*o, *n):
				r.Changed = append(r.Changed, name)
			}
		}
	}

	return r, nil
}

// sorted is a classification's keys, in order: a reload that changes several restart-only keys is
// refused for the same one each time.
func sorted(keys map[string]keyClass) []string {
	return slices.Sorted(maps.Keys(keys))
}

func byName(listeners []Listener) map[string]*Listener {
	out := map[string]*Listener{}
	for i := range listeners {
		out[listeners[i].Name] = &listeners[i]
	}

	return out
}

func sortedNames(a, b map[string]*Listener) []string {
	var names []string

	for name := range a {
		names = append(names, name)
	}

	for name := range b {
		if _, ok := a[name]; !ok {
			names = append(names, name)
		}
	}

	slices.Sort(names)

	return names
}

// field is the value of the field of a struct (by pointer) whose yaml tag is key.
func field(v any, key string) any {
	rv := reflect.ValueOf(v).Elem()
	rt := rv.Type()

	for i := range rt.NumField() {
		if tag, _, _ := strings.Cut(rt.Field(i).Tag.Get("yaml"), ","); tag == key {
			return rv.Field(i).Interface()
		}
	}

	panic("config: no key " + key + " in " + rt.Name())
}
