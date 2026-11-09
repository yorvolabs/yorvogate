package gate

import (
	"maps"
	"net/http"
	"slices"
	"strings"
)

// header is a request header Docker gets from a scope: how long it may be, and the endpoints it goes
// to (none listed: every endpoint). Each is single-valued: given twice, YorvoGate and Docker could
// read different ones, so the request is refused.
type header struct {
	max       int
	endpoints []string
}

// The headers Docker reads (moby's daemon/server, Docker 29.9.2) that a scope may send. Docker gets
// these, copied from the request, and no others: an unlisted header isn't forwarded, and named in the
// log. YorvoGate sets Content-Type itself, from what it forwards.
var forwardedHeaders = map[string]header{
	// Passed on to registries by Docker
	"User-Agent": {max: 1024},
	// The format of a log or an event stream
	"Accept": {max: 1024},
	// An archive's compression (container.archive-get)
	"Accept-Encoding": {max: 256},
	// OpenTelemetry's context, which Docker's own tracing takes up (W3C's limits)
	"Traceparent": {max: 256},
	"Tracestate":  {max: 512},
	"Baggage":     {max: 8192},
	// A pull's credentials; never logged
	"X-Registry-Auth": {max: 64 << 10, endpoints: []string{"image.create", "distribution.inspect"}},
	// The HTTP upgrade of a stream both ways, forwarded only when the request upgrades. Connection
	// is YorvoGate's own (see forwarded).
	"Upgrade": {max: 64, endpoints: upgrades},
}

// The endpoints that switch protocols (exec.start when it attaches)
var upgrades = []string{"container.attach", "container.attach-websocket", "exec.start"}

// forwarded returns the headers Docker gets for a scope's request to an endpoint, and the names of
// those it doesn't (YorvoGate's own aside); or why the request is refused.
//
// Connection is never the client's: every header it names is dropped on the way to Docker, so a
// client's could take off the Content-Type YorvoGate sets. It's "Upgrade" when the request upgrades
// (which Docker and the proxy need to switch protocols), and absent otherwise.
func forwarded(given http.Header, endpoint string, upgrading bool) (http.Header, []string, error) {
	out := http.Header{}

	var dropped []string

	for _, name := range slices.Sorted(maps.Keys(given)) {
		values := given[name]
		canonical := http.CanonicalHeaderKey(name)
		if canonical == "Connection" {
			continue
		}

		h, listed := forwardedHeaders[canonical]
		if !listed || (h.endpoints != nil && !slices.Contains(h.endpoints, endpoint)) {
			if !strings.HasPrefix(canonical, "X-Yorvogate-") {
				dropped = append(dropped, canonical)
			}

			continue
		}

		if _, seen := out[canonical]; seen || len(values) > 1 {
			return nil, nil, refuse(http.StatusBadRequest, "the header %s is given more than once", canonical)
		}

		if len(values[0]) > h.max {
			return nil, nil, refuse(http.StatusBadRequest, "the header %s is longer than %d bytes", canonical, h.max)
		}

		out[canonical] = []string{values[0]}
	}

	if upgrading && out.Get("Upgrade") != "" {
		out.Set("Connection", "Upgrade")
	} else {
		out.Del("Upgrade")
	}

	return out, dropped, nil
}
