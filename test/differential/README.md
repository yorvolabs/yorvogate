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
- **The differential property.** Every base and every attack is written in many other ways (`variants_test.go`): form bodies (C-1), repeated parameters, a key's or a bool's spelling, JSON keys in another case or given twice, unknown fields, content after the value, padding, Content-Type and encoding, chunked and mismatched lengths, versions, path forms, and an upgrade on what doesn't stream. A variant of a base is refused by the gate, or Docker reads exactly what it read of the base (deep-equal over the method and every argument), or Docker refuses it before any backend (counted per class: a class that's mostly that is one the gate should refuse itself). A variant of an attack is refused by the gate, with nothing forwarded. No variant makes Docker fetch an import: every smuggled `fromSrc` points at a server the test runs, which counts fetches. None changes what the gate holds of its scopes.
- **Docker makes the scope's own.** On the bases that create or name something, Docker's reading carries the scope's name, owner label or image namespace (`TestDockerMakesTheScopesOwn`).
- **Named readings** (`regressions_test.go`): `containers%2Fcreate` served as `containers/create`, `v01.56` served as 1.56, a lower-case `privileged` given last winning, and a form body's `fromImage` beating the query's. Each is Docker 29.9.2's own reading, and each must be refused by the gate. A moby bump that changes one fails by name.

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
