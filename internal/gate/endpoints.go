package gate

import (
	"maps"
	"net/http"
	"slices"
)

// What a scope may ask of each endpoint: the rule that decides on it, each query parameter Docker
// gets, and whether it takes a JSON body. An endpoint that isn't here is refused, and so is any
// query parameter its entry doesn't list: a parameter a newer Docker adds stays closed until it's
// added here. The parameters are those Docker's handlers read (moby's daemon/server/router, Docker
// 29.9.2), which are more than its API description lists; a test checks that every one the API
// description lists is decided on.
type descriptor struct {
	rule func(s *scoped, body []byte) ([]byte, error)
	// The query parameters forwarded, and how each is decided on
	query map[string]param
	// The parameters Docker reads that a scope may not give, and why
	refused map[string]string
	// Takes a JSON body, which its rule reads (any other has none, a stream's aside)
	body bool
	// A parameter that may be given more than once (Docker reads each)
	many string
}

// param is how a query parameter is decided on.
type param int

const (
	// free: Docker reads it, and it can't reach past the object the rule checked (a format, a
	// timeout, which streams of the scope's own container, a platform of an image it may read)
	free param = iota + 1
	// checked: the endpoint's rule reads it and decides
	checked
)

// rule adapts a check of the request (no body) to a descriptor's rule.
func rule(check func(s *scoped) error) func(*scoped, []byte) ([]byte, error) {
	return func(s *scoped, _ []byte) ([]byte, error) { return nil, check(s) }
}

func allowed(*scoped) error { return nil }

func freely(names ...string) map[string]param {
	q := make(map[string]param, len(names))
	for _, n := range names {
		q[n] = free
	}

	return q
}

func with(q map[string]param, checkedNames ...string) map[string]param {
	for _, n := range checkedNames {
		q[n] = checked
	}

	return q
}

// The parameters of a stream of a container's output or input (attach)
var attaching = []string{"detachKeys", "logs", "stream", "stdin", "stdout", "stderr"}

var forScopes = map[string]descriptor{
	"system.ping":    {rule: rule(allowed)},
	"system.version": {rule: rule((*scoped).versionOfItsOwn)},
	"system.info":    {rule: rule((*scoped).infoOfItsOwn)},

	"container.list":   {rule: rule((*scoped).ownOnly), query: with(freely("all", "limit", "size"), "filters")},
	"container.prune":  {rule: rule((*scoped).ownOnly), query: with(freely(), "filters")},
	"container.create": {rule: (*scoped).createContainer, body: true, query: with(freely("platform"), "name")},
	"container.update": {rule: (*scoped).updateOwnContainer, body: true},
	"container.rename": {rule: rule((*scoped).rename), query: with(freely(), "name")},

	"container.inspect": {rule: rule((*scoped).onOwnContainer), query: freely("size")},
	"container.top":     {rule: rule((*scoped).onOwnContainer), query: freely("ps_args")},
	"container.logs": {rule: rule((*scoped).onOwnContainer), query: freely(
		"follow", "stdout", "stderr", "since", "until", "timestamps", "tail", "details", "format")},
	"container.changes": {rule: rule((*scoped).onOwnContainer)},
	"container.export":  {rule: rule((*scoped).onOwnContainer)},
	"container.stats":   {rule: rule((*scoped).onOwnContainer), query: freely("stream", "one-shot")},
	"container.resize":  {rule: rule((*scoped).onOwnContainer), query: freely("h", "w")},
	"container.start": {rule: rule((*scoped).onOwnContainer), query: freely("detachKeys"), refused: map[string]string{
		"checkpoint":     "restoring a checkpoint isn't allowed",
		"checkpoint-dir": "restoring a checkpoint isn't allowed",
	}},
	"container.stop":             {rule: rule((*scoped).onOwnContainer), query: freely("signal", "t")},
	"container.restart":          {rule: rule((*scoped).onOwnContainer), query: freely("signal", "t")},
	"container.kill":             {rule: rule((*scoped).onOwnContainer), query: freely("signal")},
	"container.pause":            {rule: rule((*scoped).onOwnContainer)},
	"container.unpause":          {rule: rule((*scoped).onOwnContainer)},
	"container.attach":           {rule: rule((*scoped).onOwnContainer), query: freely(attaching...)},
	"container.attach-websocket": {rule: rule((*scoped).onOwnContainer), query: freely(attaching...)},
	"container.wait":             {rule: rule((*scoped).onOwnContainer), query: freely("condition")},
	"container.delete": {rule: rule((*scoped).onOwnContainer), query: freely("v", "force"), refused: map[string]string{
		"link": "it removes a legacy link by name, which isn't a container YorvoGate checked",
	}},
	"container.archive-info": {rule: rule((*scoped).onOwnContainer), query: freely("path")},
	"container.archive-get":  {rule: rule((*scoped).onOwnContainer), query: freely("path")},
	"container.archive-put":  {rule: rule((*scoped).onOwnContainer), query: freely("path", "noOverwriteDirNonDir", "copyUIDGID")},

	"exec.create":  {rule: (*scoped).createExecIn, body: true},
	"exec.start":   {rule: (*scoped).startOwnExec, body: true},
	"exec.resize":  {rule: rule((*scoped).exec), query: freely("h", "w")},
	"exec.inspect": {rule: rule((*scoped).exec)},

	"image.list": {rule: rule((*scoped).listImages), query: freely("all", "filters", "shared-size", "digests", "manifests", "identity"), refused: map[string]string{
		"filter": "it's the filter of API versions before 1.25",
	}},
	"image.create": {rule: rule((*scoped).pull), query: with(freely("platform"), "fromImage", "tag"), refused: map[string]string{
		"fromSrc": "importing (fromSrc) isn't allowed, only pulls", "repo": "importing (repo) isn't allowed, only pulls",
		"message": "importing (message) isn't allowed, only pulls", "changes": "importing (changes) isn't allowed, only pulls",
	}},
	"image.search":    {rule: rule((*scoped).search), query: with(freely("limit", "filters"), "term")},
	"image.save-many": {rule: rule((*scoped).saveMany), query: with(freely("platform"), "names"), many: "names"},
	"image.load":      {rule: rule((*scoped).load), query: freely("quiet", "platform")},
	"image.inspect":   {rule: rule((*scoped).inspectImage), query: freely("manifests", "platform")},
	"image.history":   {rule: rule((*scoped).imageHistory), query: freely("platform")},
	"image.tag":       {rule: rule((*scoped).tag), query: with(freely(), "repo", "tag")},
	"image.save":      {rule: rule((*scoped).saveImage), query: freely("platform")},
	"image.delete": {rule: rule((*scoped).deleteImage), query: freely("force", "noprune"), refused: map[string]string{
		"platforms": "deleting a platform's content deletes it from every image that has it, other scopes' too",
	}},

	"network.list":       {rule: rule((*scoped).ownOnly), query: with(freely(), "filters")},
	"network.create":     {rule: (*scoped).createNetwork, body: true},
	"network.prune":      {rule: rule((*scoped).ownOnly), query: with(freely(), "filters")},
	"network.inspect":    {rule: rule((*scoped).inspectNetwork), query: freely("verbose", "scope")},
	"network.delete":     {rule: rule((*scoped).ownNetwork)},
	"network.connect":    {rule: (*scoped).connect, body: true},
	"network.disconnect": {rule: (*scoped).disconnect, body: true},

	"volume.list":    {rule: rule((*scoped).ownOnly), query: with(freely(), "filters")},
	"volume.create":  {rule: (*scoped).createVolume, body: true},
	"volume.prune":   {rule: rule((*scoped).ownOnly), query: with(freely(), "filters")},
	"volume.inspect": {rule: rule((*scoped).volume)},
	"volume.delete":  {rule: rule((*scoped).volume), query: freely("force")},

	"distribution.inspect": {rule: rule((*scoped).distribution)},
}

// parameters refuses a query parameter the endpoint's descriptor doesn't forward, and one given more
// than once (Docker reads the first; a check could read another).
func (d descriptor) parameters(endpoint string, query map[string][]string) error {
	// In order, so the same request is always refused for the same reason
	for _, key := range slices.Sorted(maps.Keys(query)) {
		values := query[key]
		if why, ok := d.refused[key]; ok {
			return refuse(http.StatusForbidden, "%s: the parameter %q isn't allowed: %s", endpoint, key, why)
		}

		if d.query[key] == 0 {
			return refuse(http.StatusForbidden, "%s: the parameter %q isn't one YorvoGate forwards", endpoint, key)
		}

		if len(values) > 1 && key != d.many {
			return refuse(http.StatusBadRequest, "the parameter %q is given more than once", key)
		}
	}

	return nil
}

// ScopeEndpoints is the names of the endpoints a scope may send: what the differential suite
// (test/differential) must have a request for.
func ScopeEndpoints() []string {
	return slices.Sorted(maps.Keys(forScopes))
}

// ParameterDecision is how a scope's endpoint decides on a query parameter: "free", "checked",
// "refused" (Docker reads it, and a scope may not give it), or "" when its descriptor doesn't name
// it (refused too, undecided). For apidiff.
func ParameterDecision(endpoint, name string) string {
	d, ok := forScopes[endpoint]
	switch {
	case !ok:
		return ""
	case d.query[name] == free:
		return "free"
	case d.query[name] == checked:
		return "checked"
	}

	if _, refused := d.refused[name]; refused {
		return "refused"
	}

	return ""
}

// HeaderForwarded tells whether a scope's request to an endpoint has a header forwarded. For apidiff.
func HeaderForwarded(endpoint, name string) bool {
	h, ok := forwardedHeaders[http.CanonicalHeaderKey(name)]

	return ok && (h.endpoints == nil || slices.Contains(h.endpoints, endpoint))
}
