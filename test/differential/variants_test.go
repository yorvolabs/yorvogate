package differential

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"net/url"
	"strings"
)

// variant is a request written differently from its base: a class, and a name within it.
type variant struct {
	class, name string
	req         request
}

// smuggled is what a variant tries to make Docker read instead of what the gate checked: the
// parameters Docker's handlers read (the ones of C-1 included), set to another scope's, and an
// import from the suite's fetch server (fromSrc), which records whether Docker fetched from it.
func smuggled(fetch string) url.Values {
	return url.Values{
		"name": {"blog-x"}, "fromImage": {"quire-sites/blog/app"}, "fromSrc": {fetch}, "repo": {"quire-sites/blog/x"},
		"tag": {"9"}, "force": {"1"}, "v": {"1"}, "filters": {`{"label":["com.docker.compose.project=blog"]}`},
		"path": {"/"}, "names": {"quire-sites/blog/app:1"}, "signal": {"KILL"}, "all": {"1"},
	}
}

// toBlog is a value of jane's turned into blog's.
func toBlog(v string) string {
	return strings.NewReplacer("jane", "blog").Replace(v)
}

// split is a request target's path and query.
func split(target string) (string, url.Values) {
	path, raw, _ := strings.Cut(target, "?")
	q, _ := url.ParseQuery(raw)

	return path, q
}

func join(path string, q url.Values) string {
	if len(q) == 0 {
		return path
	}

	return path + "?" + q.Encode()
}

// rawJoin is a target with a query written as given (unescaped, in order).
func rawJoin(path string, pairs ...[2]string) string {
	var parts []string
	for _, p := range pairs {
		parts = append(parts, p[0]+"="+p[1])
	}

	if len(parts) == 0 {
		return path
	}

	return path + "?" + strings.Join(parts, "&")
}

func hasJSONBody(r request) bool {
	return len(r.body) > 0 && json.Valid(r.body)
}

// boolParams are the parameters Docker reads with BoolValue or BoolValueOrDefault: a spelling of
// the same truth (form.go:18-34) is the same request.
var boolParams = map[string]bool{
	"all": true, "size": true, "stream": true, "one-shot": true, "stdin": true, "stdout": true, "stderr": true,
	"logs": true, "follow": true, "timestamps": true, "force": true, "v": true, "noprune": true, "quiet": true,
	"digests": true, "shared-size": true, "copyUIDGID": true, "noOverwriteDirNonDir": true, "verbose": true,
}

// variants are the ways one base is written differently. For a base (attack false) each keeps
// its meaning or smuggles another's: Docker must read it as the base, or not at all. For an attack,
// also those that change a value: all must be refused.
func variants(b request, fetch string, attack bool) []variant {
	var vs []variant

	add := func(class, name string, r request) { vs = append(vs, variant{class, name, r}) }
	path, query := split(b.target)
	smuggle := smuggled(fetch)

	// Form bodies: Docker's ParseForm takes a form body's values before the query's (C-1)
	formBody := []byte(smuggle.Encode())
	for _, ct := range []string{"application/x-www-form-urlencoded", "APPLICATION/X-WWW-FORM-URLENCODED", "application/x-www-form-urlencoded; charset=utf-8"} {
		r := b.with("Content-Type", ct, false)
		r.body = formBody
		add("form body", ct, r)
	}

	// C-1 as the assessment ran it against 0.1.0: no fromImage, so Docker imports from fromSrc
	r0 := b.with("Content-Type", "application/x-www-form-urlencoded", false)
	r0.body = []byte("fromImage=&fromSrc=" + url.QueryEscape(fetch) + "&repo=postgres&tag=18")
	add("form body", "C-1: an import, as the assessment sent it", r0)

	mp := "--x\r\nContent-Disposition: form-data; name=\"fromSrc\"\r\n\r\n" + fetch + "\r\n--x\r\nContent-Disposition: form-data; name=\"name\"\r\n\r\nblog-x\r\n--x--\r\n"
	r := b.with("Content-Type", "multipart/form-data; boundary=x", false)
	r.body = []byte(mp)
	add("form body", "multipart", r)

	// Parameters: smuggled ones added; each of the base's repeated, the other scope's first or last;
	// a key's case; a bool's spelling
	add("parameters", "smuggled in the query", withTarget(b, join(path, merge(query, smuggle))))

	for key, values := range query {
		v := values[0]
		add("parameters", key+" repeated, another's last", withTarget(b, rawJoin(path, append(pairsOf(query, key), [2]string{key, url.QueryEscape(v)}, [2]string{key, url.QueryEscape(toBlog(v) + "x")})...)))
		add("parameters", key+" repeated, another's first", withTarget(b, rawJoin(path, append(pairsOf(query, key), [2]string{key, url.QueryEscape(toBlog(v) + "x")}, [2]string{key, url.QueryEscape(v)})...)))
		add("parameters", key+" in another case", withTarget(b, rawJoin(path, append(pairsOf(query, key), [2]string{strings.ToUpper(key[:1]) + key[1:], url.QueryEscape(v)})...)))

		if boolParams[key] {
			// The same truth, spelled as BoolValue reads it (lower-cased, trimmed)
			spellings := map[string][]string{"1": {"TRUE", "+1", "yes", "%201", "on"}, "0": {"FALSE", "no", "none", "+0"}}[v]
			for _, spelled := range spellings {
				add("parameters", key+"="+spelled, withTarget(b, rawJoin(path, append(pairsOf(query, key), [2]string{key, spelled})...)))
			}
		}

		if attack {
			add("padding", key+" with an overlong /", withTarget(b, rawJoin(path, append(pairsOf(query, key), [2]string{key, url.QueryEscape(v) + "%C0%AF"})...)))
		}
	}

	// JSON bodies: keys in another case, a key twice (another's value last), an unknown field,
	// content after the value, padding
	if hasJSONBody(b) {
		var top map[string]json.RawMessage
		if json.Unmarshal(b.body, &top) == nil {
			lower := map[string]json.RawMessage{}
			for k, v := range top {
				lower[strings.ToLower(k)] = v
			}

			add("JSON", "keys in lower case", withBody(b, mustJSON(lower)))

			for k, v := range top {
				dup := append(bytes.TrimSuffix(bytes.TrimSpace(b.body), []byte("}")), []byte(`,"`+strings.ToLower(k)+`":`+toBlog(string(v))+`}`)...)
				add("JSON", k+" twice, another's last", withBody(b, dup))
			}

			if _, ok := top["HostConfig"]; ok {
				dup := append(bytes.TrimSuffix(bytes.TrimSpace(b.body), []byte("}")), []byte(`,"hostconfig":{"Privileged":true,"Binds":["/:/host"]}}`)...)
				add("JSON", "hostconfig twice, privileged last", withBody(b, dup))
			}
		}

		add("JSON", "an unknown field", withBody(b, append(bytes.TrimSuffix(bytes.TrimSpace(b.body), []byte("}")), []byte(`,"YorvoGateUnknown":1}`)...)))
		add("JSON", "content after the value", withBody(b, append(append([]byte{}, b.body...), []byte(` {"Privileged":true}`)...)))
		add("padding", "whitespace around the body", withBody(b, append(append([]byte("\n \t"), b.body...), []byte(" \n")...)))
		add("padding", "a byte-order mark", withBody(b, append([]byte("\xef\xbb\xbf"), b.body...)))

		// Content-Type, as mime parses it, and what Docker's ReadJSON then takes (F3)
		for _, ct := range []string{"APPLICATION/JSON", "application/json; charset=utf-8", "application/json ; x=y", "text/plain"} {
			add("Content-Type", ct, b.with("Content-Type", ct, false))
		}

		noType := b.clone()
		noType.header = without(noType.header, "Content-Type")
		add("Content-Type", "none, with a body", noType)

		var gz bytes.Buffer
		zw := gzip.NewWriter(&gz)
		_, _ = zw.Write(b.body)
		_ = zw.Close()
		add("Content-Type", "gzip-encoded", withBody(b, gz.Bytes()).with("Content-Encoding", "gzip", false))
	} else if b.method != "GET" && b.method != "HEAD" && len(b.body) == 0 {
		add("JSON", "a body where there's none", withBody(b.with("Content-Type", "application/json", false), []byte(`{"Privileged":true}`)))
	}

	// Framing: chunked, both, a length too short or too long
	if len(b.body) > 0 {
		framings := []string{"chunked", "both", "long"}
		if attack {
			framings = append(framings, "short") // a shorter request: another one, for a stream
		}

		for _, f := range framings {
			r := b.clone()
			r.framing = f
			add("framing", f, r)
		}
	} else {
		r := withBody(b.with("Content-Type", "application/x-www-form-urlencoded", false), formBody)
		r.framing = "chunked"
		add("framing", "a chunked form body", r)
	}

	// Versions: none, other spellings, outside what the gate serves
	version, rest := splitVersion(path)
	for _, v := range []string{"", "/v0" + version[2:], version + ".0", "/v1.43", "/v1.57", "/V" + version[2:], strings.Replace(version, ".", "..", 1)} {
		add("version", "["+v+"]", withTarget(b, join(v+rest, query)))
	}

	// Path forms: an empty segment, a dot, an encoded slash or dot-dot, a trailing slash, case
	segments := strings.Split(strings.TrimPrefix(rest, "/"), "/")
	add("path", "//", withTarget(b, join(version+"//"+strings.Join(segments, "/"), query)))
	add("path", "/./", withTarget(b, join(version+"/./"+strings.Join(segments, "/"), query)))
	add("path", "a trailing /", withTarget(b, join(path+"/", query)))
	add("path", "the first segment in upper case", withTarget(b, join(version+"/"+strings.ToUpper(segments[0])+"/"+strings.Join(segments[1:], "/"), query)))

	if len(segments) > 1 {
		add("path", "an encoded /", withTarget(b, join(version+"/"+segments[0]+"%2F"+strings.Join(segments[1:], "/"), query)))
		add("path", "an encoded ..", withTarget(b, join(version+"/"+segments[0]+"/%2e%2e/"+strings.Join(segments, "/"), query)))
		add("path", "another's object through ..", withTarget(b, join(version+"/"+segments[0]+"/"+toBlog(segments[1])+"/../"+strings.Join(segments[1:], "/"), query)))
	}

	// An upgrade on what doesn't stream
	if b.headerValue("Upgrade") == "" {
		add("upgrade", "Connection: Upgrade, Upgrade: tcp", b.with("Connection", "Upgrade", false).with("Upgrade", "tcp", false))
	}

	return vs
}

// splitVersion is a path's version prefix ("/v1.56") and the rest.
func splitVersion(path string) (string, string) {
	if !strings.HasPrefix(path, "/v") {
		return "/v1.56", path
	}

	i := strings.Index(path[1:], "/")
	if i < 0 {
		return path, "/"
	}

	return path[:i+1], path[i+1:]
}

// atVersion is a request at another API version.
func atVersion(r request, version string) request {
	path, query := splitVersion(strings.SplitN(r.target, "?", 2)[0])
	_ = path

	return withTarget(r, "/v"+version+query+targetQuery(r.target))
}

func targetQuery(target string) string {
	if _, q, ok := strings.Cut(target, "?"); ok {
		return "?" + q
	}

	return ""
}

func withTarget(b request, target string) request {
	r := b.clone()
	r.target = target

	return r
}

func withBody(b request, body []byte) request {
	r := b.clone()
	r.body = body

	return r
}

func without(h [][2]string, name string) [][2]string {
	var kept [][2]string

	for _, x := range h {
		if !strings.EqualFold(x[0], name) {
			kept = append(kept, x)
		}
	}

	return kept
}

func (r request) headerValue(name string) string {
	for _, h := range r.header {
		if strings.EqualFold(h[0], name) {
			return h[1]
		}
	}

	return ""
}

func merge(q, extra url.Values) url.Values {
	m := url.Values{}
	for k, v := range q {
		m[k] = v
	}

	for k, v := range extra {
		if _, ok := m[k]; !ok {
			m[k] = v
		}
	}

	return m
}

// pairsOf is the query's pairs but one key's.
func pairsOf(q url.Values, except string) [][2]string {
	var pairs [][2]string

	for k, values := range q {
		if k == except {
			continue
		}

		for _, v := range values {
			pairs = append(pairs, [2]string{k, url.QueryEscape(v)})
		}
	}

	return pairs
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)

	return b
}
