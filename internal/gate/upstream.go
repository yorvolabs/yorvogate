package gate

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"strconv"
	"time"
)

// Upstream is Docker's socket, which allowed requests are forwarded to.
type Upstream struct {
	proxy *httputil.ReverseProxy
}

// NewUpstream forwards to Docker's unix socket.
func NewUpstream(socket string, log *slog.Logger) *Upstream {
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
			change, ok := res.Request.Context().Value(answerKey{}).(func([]byte) ([]byte, error))
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

// answerKey carries, in a forwarded request's context, the change a rule makes to Docker's answer.
type answerKey struct{}

// Forward sends an allowed request to Docker, and its answer back. An HTTP upgrade (attach, exec)
// becomes a stream both ways once Docker accepts it.
func (u *Upstream) Forward(w http.ResponseWriter, r *http.Request) {
	u.proxy.ServeHTTP(w, r)
}
