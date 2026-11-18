package gate

import (
	"errors"
	"fmt"
	"strings"
)

// Code is a refusal's reason code: stable, the part of a refusal a program reads (its message is for
// people, and may change). Every refusal has one, from this list only (a test holds every refusal
// site to it, and the configuration docs' table to this list).
type Code string

// The codes. auth.rejected is the only code of an authentication failure, whatever its cause, so a
// client learns nothing of which scopes exist (its cause is logged, as auth_failure).
const (
	CodeAuthRejected Code = "auth.rejected"
	CodeUndecided    Code = "gate.undecided"

	CodeUnknownEndpoint Code = "route.unknown-endpoint"
	CodeInvalidRoute    Code = "route.invalid"
	CodeListenerDenies  Code = "listener.not-allowed"
	CodeScopeDenies     Code = "scope.endpoint-not-allowed"

	CodeNotFound     Code = "scope.not-found"
	CodeNameNotOwn   Code = "scope.name-not-own"
	CodeNameTaken    Code = "scope.name-taken"
	CodeLabelNotOwn  Code = "scope.label-not-own"
	CodeImageNotOwn  Code = "scope.image-not-own"
	CodeObjectNotOwn Code = "scope.object-not-own"

	CodeBodyMissing     Code = "body.missing"
	CodeBodyUnexpected  Code = "body.unexpected"
	CodeBodyInvalid     Code = "body.invalid"
	CodeBodyTooLarge    Code = "body.too-large"
	CodeBodyUnreadable  Code = "body.unreadable"
	CodeFieldNotAllowed Code = "body.field-not-allowed"

	CodeHeaderTwice       Code = "header.twice"
	CodeHeaderTooLong     Code = "header.too-long"
	CodeHeaderContentType Code = "header.content-type"
	CodeFormBody          Code = "header.form-body"

	CodeQueryNotAllowed Code = "query.not-allowed"
	CodeQueryTwice      Code = "query.twice"
	CodeQueryInvalid    Code = "query.invalid"
	CodeUpgradeOnly     Code = "stream.upgrade-only"

	CodeHostAccess Code = "policy.host-access"
	CodeNamespace  Code = "policy.namespace"
	CodeCapability Code = "policy.capability"
	CodeSecurity   Code = "policy.security"
	CodeRuntime    Code = "policy.runtime"
	CodeLogging    Code = "policy.logging"
	CodeLimit      Code = "policy.limit"
	CodeMount      Code = "policy.mount"
	CodeNetwork    Code = "policy.network"
	CodeEgress     Code = "policy.egress"
	CodeBuilder    Code = "policy.builder"
	CodeExec       Code = "policy.exec"
	CodeRegistry   Code = "policy.registry"
	CodePlatform   Code = "policy.platform"
	CodeImage      Code = "policy.image"

	CodeLoadTooLarge   Code = "load.too-large"
	CodeLoadSpoolFull  Code = "load.spool-full"
	CodeLoadBusy       Code = "load.busy"
	CodeLoadUnpacked   Code = "load.unpacked"
	CodeLoadEntries    Code = "load.entries"
	CodeLoadStalled    Code = "load.stalled"
	CodeLoadUnreadable Code = "load.unreadable"
	CodeLoadInvalid    Code = "load.invalid"

	CodeDefaultsUnread    Code = "daemon.defaults-unread"
	CodeDefaultsUnsafe    Code = "daemon.defaults-unsafe"
	CodeDaemonUnknown     Code = "daemon.unavailable"
	CodeDockerUnreachable Code = "daemon.unreachable"
)

// Codes are the codes and what each means: the configuration docs' table (docs/configuration.md#reason-codes).
var Codes = map[Code]string{
	CodeAuthRejected: "No such scope, or not its credentials (token, certificate, socket or peer user). Every authentication failure has this code; its cause is only logged.",
	CodeUndecided:    "YorvoGate couldn't decide on the request (an error of its own, or Docker's while it looked something up).",

	CodeUnknownEndpoint: "An endpoint YorvoGate doesn't know (a newer Docker's, or none of Docker's).",
	CodeInvalidRoute:    "The path isn't canonical, or its API version isn't one YorvoGate serves.",
	CodeListenerDenies:  "The endpoint isn't one of the trusted listener's groups.",
	CodeScopeDenies:     "The endpoint isn't one a scope may use.",

	CodeNotFound:     "The object isn't the scope's: answered as one that doesn't exist.",
	CodeNameNotOwn:   "The name isn't under the scope's prefixes.",
	CodeNameTaken:    "The name is under the scope's prefixes, but another owner's object has it.",
	CodeLabelNotOwn:  "The object doesn't carry the scope's owner label, or carries another scope's.",
	CodeImageNotOwn:  "The image name isn't in the scope's image namespaces.",
	CodeObjectNotOwn: "What the request joins or mounts (a container, network or volume) isn't the scope's.",

	CodeBodyMissing:     "The endpoint takes a body, and none came.",
	CodeBodyUnexpected:  "The endpoint takes no body, and one came.",
	CodeBodyInvalid:     "The body isn't one value of what Docker reads there.",
	CodeBodyTooLarge:    "The body is larger than body_limit.",
	CodeBodyUnreadable:  "The body couldn't be read (it stopped, or came too slowly).",
	CodeFieldNotAllowed: "A field of the body is set that a scope may not set.",

	CodeHeaderTwice:       "A header YorvoGate reads or forwards is given more than once.",
	CodeHeaderTooLong:     "A header is longer than YorvoGate forwards.",
	CodeHeaderContentType: "The Content-Type isn't one value, or isn't valid.",
	CodeFormBody:          "A form body, whose parameters Docker would read over the checked query.",

	CodeQueryNotAllowed: "A query parameter that isn't allowed, or that YorvoGate doesn't forward, for the endpoint.",
	CodeQueryTwice:      "A query parameter is given more than once.",
	CodeQueryInvalid:    "A query parameter's value isn't valid (filters that aren't JSON lists).",
	CodeUpgradeOnly:     "A stream allowed only as an HTTP upgrade.",

	CodeHostAccess: "It would reach the host: privileged, a host path, devices, published ports.",
	CodeNamespace:  "A namespace mode that isn't allowed (the host's, or one Docker would read as the host's).",
	CodeCapability: "A capability beyond the listener's, or not dropping all where it must.",
	CodeSecurity:   "A security option, or no-new-privileges, that isn't the listener's.",
	CodeRuntime:    "A runtime or isolation that isn't allowed.",
	CodeLogging:    "A log driver or log option that isn't allowed.",
	CodeLimit:      "A resource limit missing, above the listener's, or one that's unlimited.",
	CodeMount:      "A mount or volume that isn't allowed (its type, source, driver, options or subpath).",
	CodeNetwork:    "A network, alias, address, driver or subnet that isn't allowed.",
	CodeEgress:     "A network that isn't internal, for a scope without egress.",
	CodeBuilder:    "A builder that isn't configured as a builder must be, or a use of it beyond buildctl dial-stdio.",
	CodeExec:       "An exec that isn't allowed (privileged).",
	CodeRegistry:   "A registry the listener's scopes may not pull from.",
	CodePlatform:   "A platform that isn't the host's, nor one the listener allows.",
	CodeImage:      "An image reference that isn't valid, or missing.",

	CodeLoadTooLarge:   "The image archive is larger than load_limit, or than the spool (spool.limit).",
	CodeLoadSpoolFull:  "The image spool is full now: retry (Retry-After).",
	CodeLoadBusy:       "Too many image loads at once: retry (Retry-After).",
	CodeLoadUnpacked:   "The archive decompresses to more than its bound (spool.ratio, spool.unpacked), or took too long to check.",
	CodeLoadEntries:    "The archive has more entries than an image archive may.",
	CodeLoadStalled:    "The archive stopped arriving.",
	CodeLoadUnreadable: "The archive couldn't be read.",
	CodeLoadInvalid:    "The archive isn't an image archive YorvoGate reads, or holds names or blobs it may not.",

	CodeDefaultsUnread:    "Docker's defaults haven't been read yet: scoped requests wait for them.",
	CodeDefaultsUnsafe:    "Docker's defaults would widen what scopes may do (or couldn't be read).",
	CodeDaemonUnknown:     "Something of Docker's own that a check needs couldn't be read (its platform).",
	CodeDockerUnreachable: "Docker didn't answer a request YorvoGate forwarded.",
}

// problem is one of the reasons a request is refused, when several are collected (a container's
// configuration): its code and what's wrong.
type problem struct {
	code Code
	text string
}

// problems collects a request's problems.
type problems []problem

func (p *problems) add(code Code, format string, args ...any) {
	*p = append(*p, problem{code: code, text: fmt.Sprintf(format, args...)})
}

// refusal is the one refusal of every problem: the first's code, and all of them.
func (p problems) refusal(status int, prefix string) *refusal {
	texts := make([]string, len(p))
	codes := make([]Code, len(p))

	for i, pr := range p {
		texts[i], codes[i] = pr.text, pr.code
	}

	r := refuse(status, codes[0], "%s: %s", prefix, strings.Join(texts, "; "))
	r.codes = codes

	return r
}

// codeOf is an error's code, when it's a refusal, or else the one given.
func codeOf(err error, otherwise Code) Code {
	var r *refusal
	if errors.As(err, &r) {
		return r.code
	}

	return otherwise
}
