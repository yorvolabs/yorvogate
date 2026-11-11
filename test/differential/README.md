# The differential suite

What Docker reads of a request YorvoGate forwards must be what YorvoGate decided on. This suite checks that by putting a scoped gate in front of **Docker's own API server code**: moby's routers, its gorilla/mux routing, its version middleware and its decoders. Their backends record what each call is handed, instead of acting on it. What a backend is handed is Docker's reading of the request.

It's a module of its own, so moby's daemon and its dependencies never enter YorvoGate's `go.mod`, its `govulncheck` or its SBOM. Nothing in YorvoGate's module imports it (`cmd/yorvogate`'s `TestNothingImportsTheDifferentialSuite`).

## The Engine it mirrors

`go.mod` pins `github.com/moby/moby/v2` at **`v2.0.0-beta.28.0.20261020165307-0367cbeb49b9`**: commit 0367cbe, tag `docker-v29.9.2`. That's the Docker Engine CI installs (`DOCKER_VERSION` in `.github/workflows/ci.yaml`). The module tag `v2.0.0-beta.28` is 232 commits older, so it isn't that Engine.

**When CI's Engine moves, this pin moves with it**, in the same pull request: `go get github.com/moby/moby/v2@<the new Engine tag's commit>`, then check that the stand-ins' cited lines still hold. Dependabot leaves moby/v2 alone for that reason. A `go mod tidy` run while nothing imports moby puts back the newest moby, not this pin: check `go.mod` after one.

`TestTheGateIsBuiltAsItShips` checks that every module that gives a package to YorvoGate's binary or its internal packages is the same version here as in YorvoGate's `go.mod`. Go takes the highest version any requirement asks for, so a newer one pulled in by moby would build the gate on different code. A difference is fixed by bumping YorvoGate's `go.mod` deliberately, in its own commit, or by pinning this module down.

## What it checks

- **Every base is read.** Each endpoint a scope may send has a base request in `corpus_test.go`. The gate allows it, forwards it, and Docker reads it, at API 1.56 and 1.44 (`TestEveryBaseIsAllowedAndRead`). A new endpoint without a base fails `TestEveryEndpointHasABaseAndAnAttack`.
- **Every attack is refused.** Each rule that refuses has attack requests. The gate refuses them, and nothing reaches Docker. An endpoint whose rule refuses nothing says why in `noAttack`.
- **The differential property.** Every base and every attack is written in many other ways (`variants_test.go`): form bodies (C-1), repeated parameters, a key's or a bool's spelling, JSON keys in another case or given twice, unknown fields, content after the value, padding, Content-Type and encoding, chunked and mismatched lengths, versions, path forms, and an upgrade on what doesn't stream. A variant of a base is refused by the gate, or Docker reads exactly what it read of the base (deep-equal over the method and every argument). A variant the gate forwards and Docker then refuses before any backend fails too: the gate should have refused it itself, as it read it differently or not at all. The only exceptions are those listed in `forwardedJunk`, each with why it's harmless, and the list is empty today. Each class's tally is logged. A variant of an attack is refused by the gate, with nothing forwarded. No variant makes Docker fetch an import: every smuggled `fromSrc` points at a server the test runs, which counts fetches. None changes what the gate holds of its scopes.
- **Docker makes the scope's own.** On the bases that create or name something, Docker's reading carries the scope's name, owner label or image namespace (`TestDockerMakesTheScopesOwn`).
- **Named readings** (`regressions_test.go`): `containers%2Fcreate` served as `containers/create`, `v01.56` served as 1.56, a lower-case `privileged` given last winning, and a form body's `fromImage` beating the query's. Each is Docker 29.9.2's own reading, and each must be refused by the gate. A moby bump that changes one fails by name.

## What each class guards

Each class was shown to catch the gate defence it's there for, by undoing that defence in a copy:

| Class | The defence undone | What the suite reported |
|---|---|---|
| form body | 0.2-a's three: `notAForm`, the gate's own Content-Type, `image.create` taking no body | Docker pulls `quire-sites/blog/app:9` where the gate checked jane's; the assessment's body reaches `ImportImage`; the named regression fails |
| parameters | a parameter given twice let through, the gate reading the last value | Docker read another scope's name (it reads the first) |
| version | the version range check | forwarded, and refused by Docker |
| path | percent-encoding let through | an attack forwarded |
| Content-Type | the client's Content-Type forwarded | forwarded, and refused by Docker |
| JSON | a gate decoding differently from Docker (`encoding/json/v2`'s defaults: keys case-sensitive, unknown keys ignored), forwarding the client's body | Docker read `Binds: ["/:/host"]` and `Privileged` from a lower-case `hostconfig` given last, which the gate never saw, and every other key given twice with another's value last |

The gate's real defence against the JSON class is that it decodes as Docker does and forwards what it re-encoded. Forwarding the client's raw body, with the same decoder, is read alike, so that one change alone shows nothing. The class is there for a decoder that differs.

## The stand-ins

Six endpoints' backend methods take or return a moby `internal` type, which a backend outside moby can't implement. Each is read as its handler reads it, with moby's exported helpers, up to the backend call (`standin_test.go`, lines at 0367cbe). They're routed by moby's own mux, registered ahead of its routers:

| Endpoint | moby handler |
|---|---|
| `container.prune` | `daemon/server/router/container/container_routes.go:1261-1276` |
| `network.prune` | `daemon/server/router/network/network_routes.go:342-357` |
| `volume.prune` | `daemon/server/router/volume/volume_routes.go:191-212` |
| `volume.list` | `daemon/server/router/volume/volume_routes.go:27-56` |
| `image.tag` | `daemon/server/router/image/image_routes.go:580-605` |
| `image.search` | `daemon/server/router/image/image_routes.go:607-642` |

A request that makes Docker call a backend method with no recorder (an import's `ImportImage`, say) is still seen. The recorder's recover names the method from the stack.

## Running it

- `make differential`, in `make check`: the in-process suite, about 3 seconds once built (budget: 60 s). The first build compiles moby's daemon, which takes minutes, once.
- **The nightly leg** (`TestAgainstARealDocker`, CI's `differential-nightly` job): the same variants, through the same gate, to a real Docker Engine. Set `YGD_DOCKER` to its socket (and `YGD_WITHOUT_LSM=1` for a Docker without AppArmor or SELinux, such as Docker Desktop's).
  - **Status class:** every variant the gate forwards must get the same verdict from the recorder and from the real daemon: read, or refused at parse (a 400). That's the six stand-ins' only check against a real daemon, and each is counted.
  - **State:** what a base created is the scope's, and every attack is refused and leaves nothing behind.

  It creates labelled objects (`yorvogate.differential`), restores them after each request, and removes them at the end. It takes about five minutes.

## Agent escape scenarios (0.3-g)

`escapes_test.go` maps the seven gate-relevant scenarios of [SandboxEscapeBench](https://github.com/UKGovernmentBEIS/sandbox_escape_bench) (UK AI Security Institute, MIT, pinned at commit `d93f0de`) to every Docker API route a scope has to each scenario's goal, each route a corpus attack here. A scenario is a goal, not one request: `TestEveryEscapeRouteIsRefused` fails when a route has no attack, so a route can't go untested (and so miss its variants). The other eleven scenarios (kernel/runtime CVEs, Kubernetes) are listed with the reason they're out of the gate's layer, so the full eighteen are accounted for. `TestEndpointsAScopeCannotUseAreRefused` holds that plugins, swarm and a direct build are refused outright. The nightly leg's `TestTheEscapesWouldWorkWithoutTheGate` is the non-vacuity control: on a raw socket the escapes really reach the host, and through a scope the gate refuses each enabling request. The claim is that *the enabling Docker API requests of the seven scenarios are refused, by every route we enumerate* — not that a container is unescapable once it runs.

**A gap becomes a test first.** Where a model, a fuzzer or a person finds a request that reaches the host or another scope and the gate doesn't refuse it, add it here first as a failing corpus attack (and, if it's a known escape, a scenario route in `escapes_test.go`), then fix the gate so the attack passes. The deterministic suite is the regression guard; a model run is a way to find gaps, never the test.
