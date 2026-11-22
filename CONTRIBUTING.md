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
docker compose -f compose.dev.yaml run --rm go make mutation PACKAGES=./internal/gate   # one package
docker compose -f compose.dev.yaml run --rm go make mutation PACKAGES=./internal/gate EXCLUDE='(^|/)[e-z][^/]*\.go$'   # its files a to d
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

## Branches, pull requests and releases

The same conventions hold across YorvoLabs' repositories.

### Pull requests

Pull requests are squashed: the title becomes the commit's subject on `main`, followed by `(#N)`, and the description its body.

- **The title** is one imperative sentence of at most 72 characters, without a final period, that says what the code does, e.g. "Bound image loads with a shared spool". No `feat:`-style prefixes: only Dependabot's `chore:` stays, so dependency updates can be filtered.
- **Nothing internal in public text.** Titles, descriptions, commit messages, branch names, tag messages, release notes and the changelog say what the code changes and why, for a reader outside the project. They carry no internal plan or finding codes, no names of who decided, reviewed or approved what, and no paths outside the repository.
- **The description** follows the [template](.github/pull_request_template.md): **Why**, **What changes** (as behavior, not files), **Tested** (what ran, and what didn't, with why), **Refs**: only what a reader can open (issues and pull requests, published advisories, RFCs, upstream docs), or left out.
- A release's pull request is titled `Release X.Y.Z`, and the one that moves `main` on to the next minor `Start X.Y`.
- **Commits on a branch** are free-form, since they're squashed away. `Co-authored-by` is the only trailer, for a human co-author.

### Branches

- `<kind>/<slug>`, where the kind is `feat`, `fix`, `docs`, `chore`, `ci` or `security`, and the slug is lowercase with hyphens and describes the change: `feat/per-scope-limits`, `fix/image-list-size`.
- A release is prepared on `chore/release-X.Y.Z`. `release/` is kept for maintenance branches (below).
- **A fix of an embargoed vulnerability** is developed in the repository's private security advisory fork, never on a public branch. Until the advisory is published, its title, description and branch describe the change neutrally: no advisory ID, and no description of the exploit. The changelog's Security entry and the advisory ID are added at the release.

### Tags and versions

- **A release tag** is `vX.Y.Z` or `vX.Y.Z-rc.N`, and nothing else: no other pre-release labels. It's annotated, signed with SSH (`git tag -s v0.4.0 -m "YorvoGate 0.4.0"`), on a commit of `main` that passed CI. The Release workflow refuses any other tag, and one that isn't signed by a key in [`.github/release-signers`](.github/release-signers) as `main` lists it ([`release-check.sh`](.github/release-check.sh), in a job of its own before any step that can publish). Changes to that file and to the workflows need the maintainer's review ([`CODEOWNERS`](.github/CODEOWNERS)). Tags are signed with SSH keys (`git config gpg.format ssh`, and `git config user.signingkey` with the public key's path); a key is added to the file in a pull request of its own.
- **Other tags** live under a namespace and never start with `v`, e.g. `bench/0.4.0`.
- **Before 1.0,** a minor may break things, and a patch only fixes. The changelog's Breaking entries say what to change.
- **Releases come from `main`.** Only when an older minor needs a fix after `main` has moved on is a `release/X.Y` branch created, from `vX.Y.0`'s line: the fix lands on `main` first, then is cherry-picked (`git cherry-pick -x`), and the patch is tagged there. The Release workflow accepts tags on `main` only until the first such branch is needed.

### The changelog

[`CHANGELOG.md`](CHANGELOG.md) follows [Keep a Changelog 1.1](https://keepachangelog.com/en/1.1.0/): `## [Unreleased]`, then `## [X.Y.Z] - YYYY-MM-DD` for each release, newest first. In the pull request titled `Release X.Y.Z`, move `[Unreleased]` under the version. The same pull request updates [docs/performance.md](docs/performance.md) from the benchmark's full run at its commit (run CI's workflow by hand on the branch, and take the `bench` artifact's `results.md`). The GitHub release is titled `YorvoGate X.Y.Z`, with the version's section as its notes (and the image's digest, and the Docker majors it's certified for), and is marked a pre-release for an `-rc.N`.

## A new Docker API version

1. **List what changed:** `go run ./tools/apidiff <old> <new>` (versions of `github.com/moby/moby/api`, e.g. `v1.55.0 v1.56.1`). It lists every endpoint, query parameter, header and request-body field added, removed or changed, with YorvoGate's decision on each, and exits 1 while any is **UNDECIDED**. `-propose` adds what to ask a model of each undecided row: a model may propose, a maintainer decides. See [tools/apidiff](tools/apidiff/README.md).
2. **Update `github.com/moby/moby/api`**, and decide on every row:
   - A body field gets a decision in `internal/gate/fields.go`: free, checked (by the rule that reads it), or refused, each with its reason. A refused list or map also says whether `[]` asks for something. `TestEveryFieldIsDecidedOn` fails until every field of every struct a body reaches has one.
   - A checked field needs a refusal you can see: an attack in `test/differential/corpus_test.go` that sets it (named in `attackFields`), or the `internal/gate` test that refuses it (`refusedElsewhere`).
   - A query parameter goes into its endpoint's descriptor (`internal/gate/endpoints.go`), and a new endpoint into `internal/route/endpoints.go` (with a rule, or refused on scoped listeners).
3. **Rewrite the list of fields:** `go test ./internal/gate -run TestTheFieldsAreTheListedOnes -update`. Review its diff as the change of decisions it is. CI never rewrites it.
4. **Move `config.Highest`**, and the differential suite's moby pin with the Engine CI installs ([test/differential](test/differential/README.md)). The conformance pin moves with them (`ci.yaml`'s `docker_version` and `docker_api`).
5. Run the checks.

[SUPPORT.md](SUPPORT.md#docker-engine) promises a release supporting a certified major's new API version within 14 days of the Docker release that introduced it. The nightly `docker-latest.yaml` opens the `docker-compat` issue that starts the clock.

## A new Docker major

A new major is certified by review, not by its API version: it may change what fields and query keys YorvoGate already allows mean, with the same names and types.

1. **Do every step of [a new Docker API version](#a-new-docker-api-version)** for its first API version.
2. **Read the new major's handlers** (in moby's source, at the major's first release tag) for every endpoint YorvoGate allows on a scoped listener. Look for a field or query key whose meaning changed, not only the added ones `apidiff` lists. Write what was read, and what changed, in the PR.
3. **Run the conformance suite on it:** `docker-latest.yaml` by `workflow_dispatch` once `.github/docker-majors` lists it on the PR's branch.
4. **Add its line to `.github/docker-majors`,** and its number to SUPPORT.md's certified list (`TestSupportNamesTheCertifiedMajors` keeps the two the same). Remove a major only in a minor release, and say so in the changelog's Upgrading section.

SUPPORT.md promises a new major is certified before the newest certified one stops receiving security fixes, or the `docker-compat` issue says why not.
