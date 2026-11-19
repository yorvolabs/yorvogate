package gate

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// A refusal says, besides Docker's message and its code, each of its problems: where in the request
// it is (in, field) and what the policy would accept there (allowed), so a program (an agent, an
// SDK) can fix the request without reading the message. What's allowed is the policy's, never the
// state's: the listener's configuration, the scope's own file, and fixed rules; never another scope's,
// nor what Docker holds, nor what's in use now (a shared spool's free bytes would tell one scope what
// another loads). Answered as schemas/yorvogate-refusal.v1.schema.json.

// RefusalVersion is the refusal body's format version (refusal_version).
const RefusalVersion = 1

// maxProblems is how many of a refusal's problems are answered, and logged by code: past it, the
// refusal says it's truncated (one body of thousands of refused mounts would otherwise answer, and
// log, thousands of times what it asked).
const maxProblems = 32

// place is the part of a request a problem is in. A closed list within version 1.
type place string

const (
	inBody   place = "body"
	inQuery  place = "query"
	inHeader place = "header"
	inPath   place = "path"
)

// where is a problem's place: a part of the request, and in it a field (a body's path by Docker's
// JSON names, with list indexes and map keys; a query parameter's, a header's or a path parameter's
// name). A field left empty is the part as a whole (an image archive).
type where struct {
	in    place
	field string
}

// nowhere is a problem that isn't about one part of the request (Docker's defaults, a route).
var nowhere = where{}

func at(in place, field string) where { return where{in: in, field: field} }

// index is a list element's path: "HostConfig.CapAdd[0]".
func index(path string, i int) string { return path + "[" + strconv.Itoa(i) + "]" }

// key is a map value's path, its key a JSON string: `HostConfig.LogConfig.Config["max-size"]`. (A
// key may hold anything, `"]` included; JSON's escaping reads back.)
func key(path, k string) string {
	quoted, _ := json.Marshal(k)

	return path + "[" + string(quoted) + "]"
}

// Allowed is what the policy would accept where a problem is. Kind is an open list (a consumer
// seeing one it doesn't know reads the problem's message); the other fields are the kind's.
type Allowed struct {
	// unset, required, one-of, at-most, between, prefixed, under, own, none, …
	Kind   string `json:"kind"`
	Values []any  `json:"values,omitempty"`
	Min    *int64 `json:"min,omitempty"`
	Max    *int64 `json:"max,omitempty"`
	Unit   string `json:"unit,omitempty"`
}

// nothingAllowed is a problem where nothing can be said of what's allowed: it isn't the policy's (a
// body that doesn't parse), or saying it would tell something (another scope's object, a scope that
// doesn't exist).
var nothingAllowed *Allowed

// allowUnset: leave it out.
func allowUnset() *Allowed { return &Allowed{Kind: "unset"} }

// allowRequired: it must be set, to one of the values when there are some.
func allowRequired(values ...any) *Allowed { return &Allowed{Kind: "required", Values: values} }

// allowRequiredUpTo: it must be set, from 1 to max.
func allowRequiredUpTo(max int64, unit string) *Allowed {
	return &Allowed{Kind: "required", Min: ptr(int64(1)), Max: ptr(max), Unit: unit}
}

// allowOneOf: one of the values. None listed is to leave it out.
func allowOneOf[T ~string](values []T) *Allowed {
	if len(values) == 0 {
		return allowUnset()
	}

	return &Allowed{Kind: "one-of", Values: anys(values)}
}

func allowAtMost(max int64, unit string) *Allowed {
	return &Allowed{Kind: "at-most", Max: ptr(max), Unit: unit}
}

func allowBetween(min, max int64, unit string) *Allowed {
	return &Allowed{Kind: "between", Min: ptr(min), Max: ptr(max), Unit: unit}
}

// allowPrefixed: a name starting with one of the values.
func allowPrefixed(prefixes []string) *Allowed {
	return &Allowed{Kind: "prefixed", Values: anys(prefixes)}
}

// allowUnder: inside one of the values (an image namespace, a registry, a subnet).
func allowUnder(values []string) *Allowed { return &Allowed{Kind: "under", Values: anys(values)} }

// allowOwn: one of the scope's own objects, or of the shared ones named (never a list of its own:
// listing them is a lookup, and the scope can list its own).
func allowOwn(shared []string) *Allowed { return &Allowed{Kind: "own", Values: anys(shared)} }

// allowNone: nothing here is allowed for this scope.
func allowNone() *Allowed { return &Allowed{Kind: "none"} }

func ptr[T any](v T) *T { return &v }

func anys[T ~string](values []T) []any {
	out := make([]any, len(values))
	for i, v := range values {
		out[i] = string(v)
	}

	return out
}

// text is what's allowed, as a message says it after "allowed: ".
func (a *Allowed) text() string {
	if a == nil {
		return ""
	}

	values := make([]string, len(a.Values))
	for i, v := range a.Values {
		values[i] = fmt.Sprint(v)
	}

	return strings.Join(values, ", ")
}

// refusalBody is a refusal's answer: Docker's error format (message), and what a program reads.
type refusalBody struct {
	Message   string        `json:"message"`
	Code      Code          `json:"code"`
	Version   int           `json:"refusal_version"`
	Problems  []problemBody `json:"problems"`
	Truncated bool          `json:"problems_truncated,omitempty"`
}

type problemBody struct {
	Code       Code     `json:"code"`
	In         place    `json:"in,omitempty"`
	Field      string   `json:"field,omitempty"`
	Allowed    *Allowed `json:"allowed,omitempty"`
	Message    string   `json:"message"`
	RetryAfter int      `json:"retry_after,omitempty"`
}

// answering, set by a test, is told of every refusal answered, with its body.
var answering func(*refusal, []byte)

// answerRefusal answers a refusal of a Docker request, as Docker answers errors (its clients show
// message), with its problems.
func answerRefusal(w http.ResponseWriter, r *refusal) {
	body := refusalBody{Message: "yorvogate: " + r.reason, Code: r.code, Version: RefusalVersion, Truncated: r.total > len(r.problems)}

	for _, p := range r.problems {
		body.Problems = append(body.Problems, problemBody{Code: p.code, In: p.at.in, Field: p.at.field, Allowed: p.allowed, Message: p.text, RetryAfter: r.retryAfter})
	}

	encoded, _ := json.Marshal(body)
	encoded = append(encoded, '\n')

	if answering != nil {
		answering(r, encoded)
	}

	w.Header().Set("Content-Type", "application/json")
	// Its length said, so the answer is whole even when its connection is taken from the server
	// right after (closeSoon)
	w.Header().Set("Content-Length", strconv.Itoa(len(encoded)))
	w.WriteHeader(r.status)
	_, _ = w.Write(encoded)
}
