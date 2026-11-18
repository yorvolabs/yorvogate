package gate

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/yorvolabs/yorvogate/internal/config"
	"github.com/yorvolabs/yorvogate/internal/scope"
)

// A scope's names are those under its prefixes that no longer prefix of another scope's claims. A
// name under its prefixes can still be another owner's object, made before the scope's file was
// valid: by a scope with a shorter prefix while this one didn't exist (a nested sibling, jane
// creating jane-shop-web-1 before site jane-shop), or by one that was removed. Once the scope's file
// is valid, no other scope can make such a name (it's the longest prefix's), so what's there then is
// all there is: it's listed (taken) for the operator, and the scope's own create of that name is
// refused, saying so but not whose (another's objects are answered as ones that aren't there).

// Taken is an object under a scope's prefixes that carries another owner's label.
type Taken struct {
	Kind  string `json:"kind"` // container, network or volume
	Name  string `json:"name"`
	Owner string `json:"owner"` // "scope <name>", or "<label>=<value>" of an owner no scope has now
}

// TakenFrom lists what's taken under a scope's prefixes, as Docker has it now.
func TakenFrom(ctx context.Context, d *Docker, version string, s *scope.Scope) ([]Taken, error) {
	var taken []Taken

	add := func(kind, name string, labels map[string]string) {
		name = strings.TrimPrefix(name, "/")
		if !s.Names(name) || s.Builds(name) {
			return
		}

		if owner := s.OtherOwner(labels); owner != "" {
			taken = append(taken, Taken{Kind: kind, Name: name, Owner: owner})
		}
	}

	var containers []struct {
		Names  []string
		Labels map[string]string
	}
	if _, err := d.fetch(ctx, version, "/containers/json?all=1", &containers); err != nil {
		return nil, err
	}

	for _, c := range containers {
		for _, n := range c.Names {
			add("container", n, c.Labels)
		}
	}

	var networks []struct {
		Name   string
		Labels map[string]string
	}
	if _, err := d.fetch(ctx, version, "/networks", &networks); err != nil {
		return nil, err
	}

	for _, n := range networks {
		add("network", n.Name, n.Labels)
	}

	var volumes struct {
		Volumes []struct {
			Name   string
			Labels map[string]string
		}
	}
	if _, err := d.fetch(ctx, version, "/volumes", &volumes); err != nil {
		return nil, err
	}

	for _, v := range volumes.Volumes {
		add("volume", v.Name, v.Labels)
	}

	slices.SortFunc(taken, func(a, b Taken) int { return strings.Compare(a.Kind+" "+a.Name, b.Kind+" "+b.Name) })

	return taken, nil
}

// notTaken refuses a scope's create of a name another owner's object has, by its exact name.
func (s *scoped) notTaken(kind, name string, lookup func(context.Context, string, string) (*object, error)) error {
	o, err := lookup(s.ctx, s.version, name)
	if err != nil {
		return err
	}

	if o == nil || strings.TrimPrefix(o.Name, "/") != name || s.owned(o) {
		return nil
	}

	return refuse(http.StatusConflict, CodeNameTaken, "%s.create: the name %q is taken: another owner's %s had it before scope %s's file was valid (the operator sees whose in the scope's status)", kind, name, kind, s.scope.Name)
}

// TakenWarnings are check --docker's: every scoped listener's loaded scopes with taken names.
func TakenWarnings(ctx context.Context, c *config.Config, registry *scope.Registry) []string {
	d := NewDocker(c.UpstreamSocket())
	lowest, _ := c.Versions()

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
			if err != nil {
				continue
			}

			taken, err := TakenFrom(ctx, d, lowest.String(), s)
			if err != nil {
				return append(warnings, fmt.Sprintf("taken names couldn't be listed: %v", err))
			}

			for _, t := range taken {
				warnings = append(warnings, fmt.Sprintf("%s: scope %s's %s name %q is taken by %s: the scope can't create it", l.Name, name, t.Kind, t.Name, t.Owner))
			}
		}
	}

	return warnings
}
