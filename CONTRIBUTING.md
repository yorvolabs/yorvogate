# Contributing to YorvoGate

Thank you for helping. YorvoGate stands between its clients and root on the machine, so every change is held to one bar: it can't let a scoped client through to what its policy refuses, and it's tested so that it can't quietly stop holding.

Security issues: please don't open a public issue or pull request, see [SECURITY.md](SECURITY.md).

## Setting up

Everything runs in Docker (`compose.dev.yaml`: Go and its tools, the module cache in a volume):

```bash
export HOST_UID=$(id -u) HOST_GID=$(id -g)
docker compose -f compose.dev.yaml run --rm go make check   # what CI runs
docker compose -f compose.dev.yaml run --rm go make test
docker compose -f compose.dev.yaml run --rm go gofmt -w .
```

`make check` runs gofmt, `go vet`, staticcheck, the tests with the race detector, govulncheck, and the differential suite. Beyond it:

```bash
docker compose -f compose.dev.yaml run --rm go make fuzz FUZZTIME=2m   # each fuzz target in turn
docker compose -f compose.dev.yaml run --rm go make mutation           # each package's tests kill 90% of mutants
docker compose -f compose.dev.yaml run --rm go make build && test/conformance/run.sh
```

- **Fuzzing** (`FuzzParse`, `FuzzCreateContainer`, `FuzzListFilters`, `FuzzArchiveNames`): each checks a property, not only that nothing crashes. `FuzzCreateContainer` checks what was forwarded with a check of its own, written apart from the rules: a rule that lets something through fails it. The seeds run with every `go test`.
- **Mutation testing** (gremlins): a rule whose removal no test notices is a rule that can be lost. Mutants listed as "not covered" in the scoped dispatcher are cases of a `switch` gremlins can't see covered; they are.
- **The conformance suite** (`test/conformance`) runs YorvoGate in front of the Docker your CLI uses, with the real Docker CLI and Compose and raw HTTP: two scopes' projects go up, exec, list and come down; what reaches the host or the other scope is refused, saying why. It runs three times, with scopes by token, on their own sockets, and by client certificate over mTLS (with a whole build through buildx's remote driver), then Quire Server's real use (`quire.sh`): an orchestrator on a trusted unix socket, sites on their own sockets, a Compose build on a rootless BuildKit builder; then an AI agent's socket as [docs/agents.md](docs/agents.md) sets it up (`agents.sh`); then a rootless build from [docs/configuration.md](docs/configuration.md#builders) alone, its listener, scope file and commands taken from the file (`docs.sh`); then SandboxEscapeBench's gate-relevant escape scenarios through a scope socket (`escapes.sh`). CI runs it on both of Docker's image stores, and on a CIS-hardened daemon. Its attacks only create (nothing hostile ever runs), and it removes what it made (names start with `ygc-`, `ygq-`, `ygca-`, `ygd-` and `ygce-`; the volume `ygc-agents`; the image `registry.example.com/tenants/ygd-jane/app:1`); still, CI runs it on throwaway machines, and you may prefer one too. On a host with AppArmor (Ubuntu 23.10 and later), load the [builder's profile](docs/configuration.md#builders) and set `YGC_APPARMOR=yorvogate-buildkit-rootless`, or the builder won't start.

## What a change needs

- **Tests that fail without it.** For a rule, a hostile case: the request an attacker would send, refused, and the request a real client sends, allowed; its edges (a limit exactly reached, a byte over). If a client's behaviour is involved (what Compose sends), a case in the conformance suite.
- **Docker's own types for bodies.** A body is decoded into `github.com/moby/moby/api`'s type for its endpoint, with unknown fields refused, and the re-encoded value is what's forwarded. Never read a body by key (a map, a regular expression): Docker matches keys case-insensitively.
- **Fail-closed.** What isn't named is refused, at every level: an endpoint, a field, a value.
- **A refusal that says why**, as a client will read it: `yorvogate: <endpoint>: <what> isn't allowed (<why>)`.
- **The docs** (`docs/configuration.md`, `docs/threat-model.md`, the README) when what YorvoGate allows, refuses or reads changes.
- **The differential suite passing** (`make differential`, in `make check`): an endpoint a scope may send needs a base request in `test/differential/corpus_test.go`, and a rule that refuses needs an attack. The suite's first build compiles moby's daemon, which takes a few minutes, once. See `test/differential/README.md`.
- **CodeQL's findings answered.** A pull request's CodeQL job fails on a finding at error severity: fix it. An alert that isn't a defect may be dismissed, but only with its reason written in the dismissal (why it can't happen, or what makes it safe), and never by the author of the pull request that raised it.

## A new Docker API version

1. **List what changed:** `go run ./tools/apidiff <old> <new>` (versions of `github.com/moby/moby/api`, e.g. `v1.55.0 v1.56.1`). It lists every endpoint, query parameter, header and request-body field added, removed or changed, with YorvoGate's decision on each, and exits 1 while any is **UNDECIDED**. `-propose` adds what to ask a model of each undecided row: a model may propose, a maintainer decides. See [tools/apidiff](tools/apidiff/README.md).
2. **Update `github.com/moby/moby/api`**, and decide on every row:
   - A body field gets a decision in `internal/gate/fields.go`: free, checked (by the rule that reads it), or refused, each with its reason. A refused list or map also says whether `[]` asks for something. `TestEveryFieldIsDecidedOn` fails until every field of every struct a body reaches has one.
   - A checked field needs a refusal you can see: an attack in `test/differential/corpus_test.go` that sets it (named in `attackFields`), or the `internal/gate` test that refuses it (`refusedElsewhere`).
   - A query parameter goes into its endpoint's descriptor (`internal/gate/endpoints.go`), and a new endpoint into `internal/route/endpoints.go` (with a rule, or refused on scoped listeners).
3. **Rewrite the list of fields:** `go test ./internal/gate -run TestTheFieldsAreTheListedOnes -update`. Review its diff as the change of decisions it is. CI never rewrites it.
4. **Move `config.Highest`**, and the differential suite's moby pin with the Engine CI installs ([test/differential](test/differential/README.md)).
5. Run the checks.
