package gate

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"regexp"
	"strconv"
	"time"

	"github.com/yorvolabs/yorvogate/internal/config"
	"github.com/yorvolabs/yorvogate/internal/route"
)

// Upstream is Docker's socket, which allowed requests are forwarded to.
type Upstream struct {
	proxy *httputil.ReverseProxy
}

// NewUpstream forwards to the configuration's Docker socket. Every answer advertises an API version
// the gate accepts, never a newer one, so a client that negotiates (the Docker CLI, Compose, buildx)
// asks for a version the gate serves, whatever version Docker itself has.
func NewUpstream(c *config.Config, log *slog.Logger) *Upstream {
	socket := c.UpstreamSocket()
	lowest, highest := c.Versions()

	dialer := &net.Dialer{Timeout: 10 * time.Second}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "unix", socket)
		},
		MaxIdleConns:          32,
		IdleConnTimeout:       90 * time.Second,
		ResponseHeaderTimeout: 0, // pulls, builds and waits answer when they're done
		DisableCompression:    true,
	}

	return &Upstream{proxy: &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = "http"
			pr.Out.URL.Host = "docker"
			pr.Out.Host = "docker"
		},
		Transport: transport,
		// A rule may change Docker's answer before the client sees it (a list or an inspection with
		// other scopes' objects left out).
		ModifyResponse: func(res *http.Response) error {
			if v := res.Header.Get("Api-Version"); v != "" {
				res.Header.Set("Api-Version", clamp(v, highest))
			}

			change, ok := res.Request.Context().Value(answerKey{}).(func([]byte) ([]byte, error))
			if versionPath.MatchString(res.Request.URL.Path) && res.Request.Method == http.MethodGet {
				// Every listener's: the API versions both serve; then a scope's rule, if it has one
				rule, ruled := change, ok
				change, ok = func(body []byte) ([]byte, error) {
					body, err := versionAnswer(body, lowest, highest)
					if err != nil || !ruled {
						return body, err
					}

					return rule(body)
				}, true
			}

			if !ok || res.StatusCode != http.StatusOK {
				return nil
			}

			body, err := io.ReadAll(io.LimitReader(res.Body, 64<<20))
			_ = res.Body.Close()

			if err != nil {
				return err
			}

			changed, err := change(body)
			if err != nil {
				return err
			}

			res.Body = io.NopCloser(bytes.NewReader(changed))
			res.ContentLength = int64(len(changed))
			res.Header.Set("Content-Length", strconv.Itoa(len(changed)))
			res.Header.Del("Content-Encoding")

			return nil
		},
		// Logs, attach, events and pulls are streams: each piece is passed on as it comes.
		FlushInterval: -1,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Error("Docker didn't answer", "method", r.Method, "path", r.URL.Path, "error", err)
			answer(w, http.StatusBadGateway, "Docker didn't answer")
		},
	}}
}

// versionPath is system.version's path.
var versionPath = regexp.MustCompile(`^/v[0-9]+\.[0-9]+/version$`)

// clamp is the newest API version both Docker and the gate serve: Docker's, or the gate's highest
// if Docker's is newer. A Docker older than the gate's lowest keeps its own (no version is served by
// both, and its clients' requests are refused, saying why). One that isn't a version is left as it is.
func clamp(v string, highest route.Version) string {
	parsed, err := route.ParseVersion(v)
	if err != nil || !highest.Less(parsed) {
		return v
	}

	return highest.String()
}

// clampMin is the oldest API version both serve: Docker's minimum, or the gate's lowest if Docker's
// is older.
func clampMin(v string, lowest route.Version) string {
	parsed, err := route.ParseVersion(v)
	if err != nil || !parsed.Less(lowest) {
		return v
	}

	return lowest.String()
}

// versionAnswer is system.version's answer with the API versions both Docker and the gate serve: the
// server's, and its Engine component's. The rest is Docker's, as it was.
func versionAnswer(body []byte, lowest, highest route.Version) ([]byte, error) {
	var answer map[string]json.RawMessage
	if err := json.Unmarshal(body, &answer); err != nil {
		return nil, err
	}

	fix := func(fields map[string]json.RawMessage) {
		var v string
		if raw, ok := fields["ApiVersion"]; ok && json.Unmarshal(raw, &v) == nil {
			fields["ApiVersion"], _ = json.Marshal(clamp(v, highest))
		}

		if raw, ok := fields["MinAPIVersion"]; ok && json.Unmarshal(raw, &v) == nil {
			fields["MinAPIVersion"], _ = json.Marshal(clampMin(v, lowest))
		}
	}

	fix(answer)

	if raw, ok := answer["Components"]; ok {
		var components []map[string]json.RawMessage
		if err := json.Unmarshal(raw, &components); err == nil {
			for _, component := range components {
				var details map[string]json.RawMessage
				if json.Unmarshal(component["Details"], &details) == nil && details != nil {
					fix(details)
					component["Details"], _ = json.Marshal(details)
				}
			}

			answer["Components"], _ = json.Marshal(components)
		}
	}

	return json.Marshal(answer)
}

// answerKey carries, in a forwarded request's context, the change a rule makes to Docker's answer.
type answerKey struct{}

// Forward sends an allowed request to Docker, and its answer back. An HTTP upgrade (attach, exec)
// becomes a stream both ways once Docker accepts it.
func (u *Upstream) Forward(w http.ResponseWriter, r *http.Request) {
	u.proxy.ServeHTTP(w, r)
}
