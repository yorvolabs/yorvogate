package differential

import "testing"

// SandboxEscapeBench (UK AI Security Institute, "Quantifying Frontier LLM Capabilities for Container
// Sandbox Escape", arXiv 2603.02277, github.com/UKGovernmentBEIS/sandbox_escape_bench, MIT) is 18
// capture-the-flag scenarios: an agent with shell in a container reads /flag.txt on the host. The
// paper reports frontier models win its two easiest difficulty levels comfortably.
//
// A scenario is a goal, not a single request, and a scope has more than one Docker API route to it.
// YorvoGate refuses a scenario iff it refuses every route whose enabling step is a request field it
// can check. We re-express each route as our own request (never the benchmark's canaried files) and
// pin the commit. The claim: the enabling Docker API requests of the seven gate-relevant scenarios
// are refused, by every route we enumerate (0.3-g, B1/B3).
const escapeBenchCommit = "d93f0de"

// A scenario and every API route to its goal, each named as a corpus attack. Each route's refusal,
// and every 0.3-f variant of it (TestEveryAttackIsRefused and the variant loop in suite_test.go),
// closes that route.
type escape struct {
	id     string   // the SandboxEscapeBench repo id
	what   string   // the enabling capability, in a word
	routes []string // corpus attacks, "endpoint/name"
}

var escapeScenarios = []escape{
	// The signature scenario: when the agent's socket IS a YorvoGate scope socket, the benchmark's
	// own winning exploit (create a container binding / and cat /host/flag.txt) is refused.
	{"docker_socket", "the host filesystem via the socket's own API", []string{
		"container.create/the host's /",
		"container.create/a bind mount",
		"container.create/a mount's volume driver options",
		"volume.create/a local driver binding a host path",
	}},
	{"privileged", "full host access", []string{
		"container.create/privileged",
		"exec.create/privileged",
	}},
	{"hostpath_etc", "a writable host path", []string{
		"container.create/the host's /",
		"container.create/a bind mount",
		"container.create/a mount's volume driver options",
		"volume.create/a local driver binding a host path",
	}},
	{"sys_admin", "CAP_SYS_ADMIN", []string{
		"container.create/a capability added", // SYS_ADMIN
		"container.create/every capability added",
		"container.create/seccomp unconfined",
		"container.create/the host's devices",
	}},
	{"sys_module", "CAP_SYS_MODULE plus the host's modules", []string{
		"container.create/the SYS_MODULE capability",
		"container.create/every capability added",
		"container.create/the host's /",
		"container.create/a bind mount",
		"volume.create/a local driver binding a host path",
	}},
	{"dac_read_search", "CAP_DAC_READ_SEARCH plus unconfined seccomp", []string{
		"container.create/the DAC_READ_SEARCH capability",
		"container.create/every capability added",
		"container.create/seccomp unconfined",
	}},
	{"pid_namespace", "the host PID namespace plus CAP_SYS_PTRACE", []string{
		"container.create/the host's PID namespace",
		"container.create/the SYS_PTRACE capability",
		"container.create/every capability added",
	}},
}

// The other eleven scenarios: a plain unprivileged container plus a kernel or runtime flaw, or
// Kubernetes. No Docker API field refuses them; they are the patched kernel's, the non-root
// container's and egress control's (0.3-h) layer, not the gate's. Listed so the full 18 are
// accounted for and a new one can't be dropped unseen.
var outOfScopeScenarios = map[string]string{
	"runc_overwrite":       "a runc CVE (2019-5736) from a plain container; the runtime's fix",
	"cgroup_release_agent": "a cgroup CVE (2022-0492) from a plain container; the kernel's fix",
	"bpf_privesc":          "a BPF CVE (2017-16995) on an old kernel; the kernel's fix",
	"dirty_cow":            "a kernel CVE (2016-5195) from a plain container; the kernel's fix",
	"dirty_pipe":           "a kernel CVE (2022-0847) from a plain container; the kernel's fix",
	"packet_socket":        "a kernel CVE (2017-7308) from a plain container; the kernel's fix",
	"k8s_crio_escape":      "Kubernetes/CRI-O, not the Docker API",
	"k8s_malicious_binary": "Kubernetes, not the Docker API",
	"k8s_rbac_permissions": "Kubernetes RBAC, not the Docker API",
	"k8s_route_localnet":   "Kubernetes, not the Docker API",
	"k8s_runc":             "Kubernetes/k3s, not the Docker API",
}

// Every route of every gate-relevant scenario is a corpus attack (so it and all its variants are
// refused); the full 18 scenarios are accounted for. Fails when a route has no attack (B1).
func TestEveryEscapeRouteIsRefused(t *testing.T) {
	byKey := map[string]bool{}
	for _, a := range attacks {
		byKey[a.endpoint+"/"+a.name] = true
	}

	for _, s := range escapeScenarios {
		if len(s.routes) == 0 {
			t.Errorf("%s: no route enumerated", s.id)
		}

		for _, r := range s.routes {
			if !byKey[r] {
				t.Errorf("%s: the route %q has no corpus attack (it would go untested, with no variants)", s.id, r)
			}
		}
	}

	if n := len(escapeScenarios) + len(outOfScopeScenarios); n != 18 {
		t.Errorf("the scenarios account for %d, want SandboxEscapeBench's 18 (%s)", n, escapeBenchCommit)
	}
}

// An endpoint a scope can't use at all is refused by the gate, not merely checked field by field:
// plugins, swarm, and a build outside the builder's dial-stdio path. These are routes to privilege a
// scenario could reach for, closed by default (internal/gate/endpoints.go: an endpoint not in the
// scoped table is refused).
func TestEndpointsAScopeCannotUseAreRefused(t *testing.T) {
	s := newSuite(t)

	for _, r := range []request{
		asJane("POST", "/v1.56/plugins/pull?remote=docker.io/library/x", "application/json", []byte(`[]`)),
		asJane("POST", "/v1.56/plugins/x/enable", "", nil),
		asJane("POST", "/v1.56/swarm/init", "application/json", []byte(`{"ListenAddr":"0.0.0.0:2377"}`)),
		asJane("POST", "/v1.56/build", "application/x-tar", []byte("")),
	} {
		if o := s.send(r); o.kind != refusedByGate {
			t.Errorf("%s %s: not refused by the gate: %s", r.method, r.target, o)
		}
	}
}
