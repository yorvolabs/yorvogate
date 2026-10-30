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

`make check` runs gofmt, `go vet`, staticcheck, the tests with the race detector, and govulncheck. Beyond it:

```bash
docker compose -f compose.dev.yaml run --rm go make fuzz FUZZTIME=2m   # each fuzz target in turn
docker compose -f compose.dev.yaml run --rm go make mutation           # each package's tests kill 90% of mutants
docker compose -f compose.dev.yaml run --rm go make build && test/conformance/run.sh
```

- **Fuzzing** (`FuzzParse`, `FuzzCreateContainer`, `FuzzListFilters`, `FuzzArchiveNames`): each checks a property, not only that nothing crashes. `FuzzCreateContainer` checks what was forwarded with a check of its own, written apart from the rules: a rule that lets something through fails it. The seeds run with every `go test`.
- **Mutation testing** (gremlins): a rule whose removal no test notices is a rule that can be lost. Mutants listed as "not covered" in the scoped dispatcher are cases of a `switch` gremlins can't see covered; they are.
- **The conformance suite** (`test/conformance`) runs YorvoGate in front of the Docker your CLI uses, with the real Docker CLI and Compose and raw HTTP: two scopes' projects go up, exec, list and come down; what reaches the host or the other scope is refused, saying why. Its attacks only create (nothing hostile ever runs), and it removes what it made; still, CI runs it on throwaway machines, and you may prefer one too.

## What a change needs

- **Tests that fail without it.** For a rule, a hostile case: the request an attacker would send, refused, and the request a real client sends, allowed; its edges (a limit exactly reached, a byte over). If a client's behaviour is involved (what Compose sends), a case in the conformance suite.
- **Docker's own types for bodies.** A body is decoded into `github.com/moby/moby/api`'s type for its endpoint, with unknown fields refused, and the re-encoded value is what's forwarded. Never read a body by key (a map, a regular expression): Docker matches keys case-insensitively.
- **Fail-closed.** What isn't named is refused, at every level: an endpoint, a field, a value.
- **A refusal that says why**, as a client will read it: `yorvogate: <endpoint>: <what> isn't allowed (<why>)`.
- **The docs** (`docs/configuration.md`, `docs/threat-model.md`, the README) when what YorvoGate allows, refuses or reads changes.

## A new Docker API version

1. Update `github.com/moby/moby/api` and `config.Highest`.
2. Compare the API's changes (its `swagger.yaml`, and `docs/api/version-history.md` in moby): new endpoints go into `internal/route/endpoints.go` (and get a rule, or stay refused on scoped listeners); new fields of a checked body are refused until a rule allows them, so look at each.
3. Run the checks.
