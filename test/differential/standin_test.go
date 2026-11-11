package differential

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/distribution/reference"
	"github.com/moby/moby/v2/daemon/server/httputils"
	"github.com/moby/moby/v2/daemon/server/router"
	"github.com/moby/moby/v2/errdefs"
	"github.com/opencontainers/go-digest"
)

// The stand-ins: six endpoints scopes may use whose backend methods take or return a moby internal
// type (daemon/internal/filters.Args, daemon/internal/image), which a backend outside moby can't
// implement. Each reads the request as its moby handler does, with moby's own exported helpers
// (httputils.ParseForm, RepoTagReference), up to the backend call, and records what that call would
// be handed. Routed by moby's own mux and version middleware: this router is registered before
// moby's, and mux takes the first route that matches. Lines are at moby 0367cbe (docker-v29.9.2).
//
//	container.prune  daemon/server/router/container/container_routes.go:1261-1276 postContainersPrune
//	network.prune    daemon/server/router/network/network_routes.go:342-357       postNetworkPrune
//	volume.prune     daemon/server/router/volume/volume_routes.go:191-212         postVolumesPrune
//	volume.list      daemon/server/router/volume/volume_routes.go:27-56           getVolumesList
//	image.tag        daemon/server/router/image/image_routes.go:580-605           postImagesTag
//	image.search     daemon/server/router/image/image_routes.go:607-642           getImagesSearch
//
// The nightly leg compares each of the six with a real daemon by its status class.
var standIns = []string{"container.prune", "network.prune", "volume.prune", "volume.list", "image.tag", "image.search"}

type standInRouter struct{ d *daemon }

func (s standInRouter) Routes() []router.Route {
	return []router.Route{
		router.NewPostRoute("/containers/prune", s.prune("ContainerPrune")),
		router.NewPostRoute("/networks/prune", s.prune("NetworkPrune")),
		router.NewPostRoute("/volumes/prune", s.prune("VolumePrune")),
		router.NewGetRoute("/volumes", s.volumes),
		router.NewPostRoute("/images/{name:.*}/tag", s.tag),
		router.NewGetRoute("/images/search", s.search),
	}
}

// prune is postContainersPrune, postNetworkPrune and postVolumesPrune: ParseForm, then the filters
// from r.Form.Get("filters"). (postVolumesPrune adds all=true below API 1.42, which Engine 29 no
// longer serves: its lowest is 1.44.)
func (s standInRouter) prune(method string) httputils.APIFunc {
	return func(ctx context.Context, w http.ResponseWriter, r *http.Request, _ map[string]string) error {
		if err := httputils.ParseForm(r); err != nil {
			return err
		}

		f, err := fromJSON(r.Form.Get("filters"))
		if err != nil {
			return err
		}

		s.d.record(ctx, method, f)

		return httputils.WriteJSON(w, http.StatusOK, map[string]any{})
	}
}

// volumes is getVolumesList, to its backend.List call (lines 27-36). This node is no swarm
// manager, so lines 41-53 add nothing.
func (s standInRouter) volumes(ctx context.Context, w http.ResponseWriter, r *http.Request, _ map[string]string) error {
	if err := httputils.ParseForm(r); err != nil {
		return err
	}

	f, err := fromJSON(r.Form.Get("filters"))
	if err != nil {
		return errdefs.InvalidParameter(errors.New("error reading volume filters: " + err.Error()))
	}

	s.d.record(ctx, "VolumeList", f)

	return httputils.WriteJSON(w, http.StatusOK, map[string]any{"Volumes": []any{}})
}

// tag is postImagesTag, to its GetImage and TagImage calls (lines 580-600): the image the path
// names, and the reference RepoTagReference makes of repo and tag.
func (s standInRouter) tag(ctx context.Context, w http.ResponseWriter, r *http.Request, vars map[string]string) error {
	if err := httputils.ParseForm(r); err != nil {
		return err
	}

	ref, err := httputils.RepoTagReference(r.Form.Get("repo"), r.Form.Get("tag"))
	if ref == nil || err != nil {
		return errdefs.InvalidParameter(err)
	}

	if reference.FamiliarName(ref) == string(digest.Canonical) {
		return errdefs.InvalidParameter(errors.New("refusing to create an ambiguous tag using digest algorithm as name"))
	}

	if _, _, ok := findImage(vars["name"]); !ok {
		return errdefs.NotFound(notFound{"image: " + vars["name"]})
	}

	s.d.record(ctx, "TagImage", vars["name"], ref.String())
	w.WriteHeader(http.StatusCreated)

	return nil
}

// search is getImagesSearch, to its Search call (lines 607-637): the limit, the filters, the term,
// and the X-Meta- headers it passes on.
func (s standInRouter) search(ctx context.Context, w http.ResponseWriter, r *http.Request, _ map[string]string) error {
	if err := httputils.ParseForm(r); err != nil {
		return err
	}

	var limit int

	if r.Form.Get("limit") != "" {
		var err error

		limit, err = strconv.Atoi(r.Form.Get("limit"))
		if err != nil || limit < 0 {
			return errdefs.InvalidParameter(errors.New("invalid limit specified"))
		}
	}

	f, err := fromJSON(r.Form.Get("filters"))
	if err != nil {
		return err
	}

	meta := http.Header{}

	for k, v := range r.Header {
		if k = http.CanonicalHeaderKey(k); strings.HasPrefix(k, "X-Meta-") {
			meta[k] = v
		}
	}

	s.d.record(ctx, "Search", f, r.Form.Get("term"), limit, meta)

	return httputils.WriteJSON(w, http.StatusOK, []any{})
}

// fromJSON is daemon/internal/filters.FromJSON (daemon/internal/filters/parse.go:63-89 at 0367cbe):
// a map of each key's set of values, or the legacy form, a map of each key's list.
func fromJSON(p string) (map[string]map[string]bool, error) {
	fields := map[string]map[string]bool{}
	if p == "" {
		return fields, nil
	}

	if err := json.Unmarshal([]byte(p), &fields); err == nil {
		return fields, nil
	}

	deprecated := map[string][]string{}
	if err := json.Unmarshal([]byte(p), &deprecated); err != nil {
		return nil, errdefs.InvalidParameter(errors.New("invalid filter"))
	}

	fields = map[string]map[string]bool{}

	for k, values := range deprecated {
		fields[k] = map[string]bool{}
		for _, v := range values {
			fields[k][v] = true
		}
	}

	return fields, nil
}
