package differential

import (
	"bytes"
	"encoding/json"
	"net/url"
	"strings"
)

// blogMarkers are what's blog's (the neighbour scope's) and no answer to jane may say unless jane's
// request said it first: its image namespace, its prefixes as its file lists them, its owner value
// as a label's.
var blogMarkers = []string{"quire-sites/blog/", "blog-, blog_", `"blog"`}

// checkRefusal holds every refusal of the gate's in the suite to the refusal format (version 1, its
// problems, each with a code), and to telling jane nothing of blog: no marker of blog's that jane's
// request didn't send, and none at all in what a problem says is allowed (the policy's, never
// another scope's).
func (s *suite) checkRefusal(r request, body []byte) {
	s.t.Helper()

	var answer struct {
		Version  int `json:"refusal_version"`
		Problems []struct {
			Code    string          `json:"code"`
			Allowed json.RawMessage `json:"allowed"`
		} `json:"problems"`
	}

	// The HTTP server's own refusals (a malformed request) aren't JSON: not the gate's rules'
	if !bytes.HasPrefix(bytes.TrimSpace(body), []byte("{")) {
		return
	}

	if err := json.Unmarshal(body, &answer); err != nil || answer.Version != 1 || len(answer.Problems) == 0 {
		s.t.Errorf("%s %s: not a refusal of format 1: %s", r.method, r.target, body)

		return
	}

	// As written, and as decoded (a name in a query or path comes percent-encoded)
	sent := string(r.wire())
	if decoded, err := url.QueryUnescape(r.target); err == nil {
		sent += decoded
	}

	for _, m := range blogMarkers {
		if strings.Contains(string(body), m) && !strings.Contains(sent, m) {
			s.t.Errorf("%s %s: the refusal tells %s: %s", r.method, r.target, m, body)
		}
	}

	for _, p := range answer.Problems {
		if p.Code == "" {
			s.t.Errorf("%s %s: a problem without a code: %s", r.method, r.target, body)
		}

		if bytes.Contains(p.Allowed, []byte("blog")) {
			s.t.Errorf("%s %s: allowed names blog's: %s", r.method, r.target, p.Allowed)
		}
	}
}
