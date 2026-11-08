# Changelog

All notable changes to YorvoGate. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/). A release is made from a section here: its version's section is its notes.

## [Unreleased]

### Changed

- **Scopes' claims are decided over every scoped listener, as one folder.** Scoped listeners share one Docker, so a name belongs to the scope with the longest prefix it starts with whichever listener each scope is on; image namespaces and owner labels work the same way. `yorvogate check` and a running gate decide the same way, from one snapshot of every scope file, rebuilt every 2 seconds and on `SIGHUP`; a request reads no file.
- **Breaking: of two scopes that collide, the one that held the claim keeps it; two new ones are both refused.** Files' modification times no longer decide which. `serve` starts with a collision, refusing the scopes in it, as it does within one listener.
- **Breaking: a scope file that isn't valid keeps its claims** until it's removed: its names and image namespaces are no other scope's meanwhile. Until now they were its neighbour's at once.
- **Breaking: a change to a scope file on a token listener takes effect at the next scan** (2 seconds, or `SIGHUP`), as on socket listeners. Write scope files by renaming a complete file over the old one.
- **`yorvogate check` names every scope file it refuses**, not only the first, and warns about what isn't held across a restart.

- **Every answer advertises an API version the gate serves.** A newer Docker's `Api-Version` header and `/version` API version are given as the gate's `api.max`, and an older Docker minimum as `api.min`, on every listener; an older Docker keeps its own version, never one it can't serve, so the Docker CLI, Compose and buildx negotiate a version YorvoGate accepts. Before, upgrading Docker past YorvoGate's API version made every negotiating client ask for the newer version and be refused.

### Added

- **Scope status, for orchestrators.** A trusted listener answers `GET /_yorvogate/v1/scopes/<name>` with whether a scope is in effect on a scoped listener (`loaded`, `refused`, `reserved` or `unknown`, with the reason) and the SHA-256 of its file. With `?sha256=<digest>` it waits until that exact file is the one read, and with `?absent` until the scope is gone, scanning at once; a wait that times out answers 408 with `"matched": false`. An orchestrator can wait on its write instead of sleeping past the 2-second scan. The answer's JSON Schema is published with the others.
- **Versioned formats.** The configuration (`version: 1`) and scope files (`"version": 1`) say their format, and a version YorvoGate doesn't read is refused. Without one, a file is read as version 1 with a warning from `yorvogate check` and in the logs; 0.4 refuses it. JSON Schemas for both are published with each release. From now on, before 1.0, a breaking change to a format ships only in a minor release, never in a patch, and an old format keeps working for at least one minor release with a warning.
- **`state_file`**: where YorvoGate keeps each scope's last valid claims across restarts. It only ever refuses names to scopes, never grants any.

### Security

- **Nested names on two scoped listeners weren't resolved (High where a host has two scoped listeners).** The longest-prefix rule saw one listener's scopes only, so with `jane` on one listener and `jane-blog` on another, `jane` could create `jane-blog`'s container names and tag over its image namespace (its next container would run `jane`'s image); `check` passed. Now every listener's scopes are resolved together.
- **A scope file caught half-written gave its names to its neighbour (Medium).** Now it keeps them, as above.

## [0.2.2] - 2026-11-03

Hardening from a security audit of 0.2.1, and a fix for rootless builders on CIS-hardened daemons. Check your configuration with `yorvogate check` before you update: two scoped listeners on one Docker may no longer share an owner label, prefix, image namespace or builder.

### Changed

- **Breaking: two scoped listeners on one Docker may not share an owner label, prefix, image namespace or builder.** Within one listener this was already refused; now it's refused across scoped listeners too, because a value claimed on two listeners lets one listener's scope reach the other's objects. `yorvogate check` reports the collision (naming both listeners and both scopes) and exits non-zero; `serve` refuses the colliding scope. The same scope served on two listeners (a token and a socket over one scope folder) is still fine. The only configurations this breaks are ones that were already cross-scope-leaky.
- **`yorvogate check` warns on valid but dangerous listener settings:** a scoped TCP listener on a non-loopback address (scope tokens in cleartext, as there's no TLS), a trusted write listener on a non-loopback address, a unix-socket listener with no `socket_group`, and `allow_privileged_builders`.

### Security

- **A mount could reach the host filesystem through an owned volume's driver (Medium; High in an orchestrator deployment).** A volume was checked for driver options when it was created, but `container.create` and the builder path trusted an already-owned volume by its labels alone when it was mounted. A volume owned by the scope but backed by a bind, `device` or other non-`local` driver could therefore mount a host path. Now a volume's driver and options are re-checked where it is mounted: only a plain `local` volume with no such options may be mounted.
- **One scope could wedge the gate for every tenant (High).** A slow or stalled request body held a connection open with no deadline, and nothing capped concurrent connections, so one scope could exhaust the gate's file descriptors or hang it (slowloris). Now a non-stream request body has a read deadline (real streams — exec, build, load — stay exempt), and each listener caps its concurrent connections.
- **An image load could starve co-tenants' CPU (Medium).** `image.load` had no per-scope concurrency limit, so several decompression-heavy archives at once could saturate CPU for co-tenants. Now a scope loads one image archive at a time.

### Fixed

- **A rootless builder on a CIS-hardened daemon.** When the daemon defaults to `no-new-privileges`, rootless BuildKit needs the `no-new-privileges=false` security option to map users; 0.2.1 refused it, so no builder could run on the hardened hosts YorvoGate targets. A scope's builder may now opt out of `no-new-privileges`; the inert bare/`=true` form is dropped from the allowlist.

## [0.2.1] - 2026-11-03

Compose can recreate a scope's containers (a changed service), which 0.2.0 refused. Check your scope files with `yorvogate check` before you update: a prefix that starts with 12 hex and `_` is now refused.

### Added

- **[An AI agent's Docker socket](https://github.com/yorvolabs/yorvogate/blob/v0.2.1/docs/agents.md):** why the Docker socket is root on the host, and how to give an agent a scope socket instead, in a container or on the host. Its setup runs in the conformance suite.

### Changed

- **Breaking for scope files: a prefix may not start with 12 hex and `_`** (`deadbeefcafe_`), so the name Compose gives a container it recreates is no other scope's. A scope file with such a prefix is refused, like any scope file that isn't valid: only that scope. Its requests fail, its socket closes, and while it's refused its names fall to a scope whose prefix they start with (`jane` gets `jane-blog-…`). Run `yorvogate check` with 0.2.1 on your scope folders before you switch; it stops at the first file it refuses.

### Fixed

- **Compose recreates a scope's containers.** A container may be created with the name Compose gives one it recreates (a changed service: `up`, deploys, rollbacks), 12 hex and `_` before one of the scope's names; 0.2.0 refused it. The Quire conformance recreates a service of a nested site.

## [0.2.0] - 2026-11-02

Security fixes: update from 0.1.0. A scope file's `containers` is refused; see [migrating from 0.1.0](https://github.com/yorvolabs/yorvogate/blob/v0.2.0/docs/configuration.md#migrating-from-010).

### Added

- **Scope sockets.** A scoped listener can give each scope a unix socket of its own (`scope_sockets: <folder>`, `<scope>.sock` per scope file) instead of an address. A request on it is that scope's without a header or token, so any client works, buildx's own connections included. Sockets come and go with their scope files (read every 2 seconds, and on `SIGHUP`); a scope removed or no longer valid has its socket and its connections closed. `token_sha256` is optional in those scope files.
- **`socket_group`** for a listener's unix sockets.
- **Conformance of Quire Server's real use**, in CI: an orchestrator on a trusted unix socket, sites on their own sockets with nested names, a Compose build on a rootless BuildKit builder under the shipped AppArmor profile.
- **`builder_apparmor_profiles`**: the AppArmor profiles a scope's builder may run under, and the profile for rootless BuildKit on Ubuntu 26.04 (`examples/apparmor`).

### Changed

- CI's conformance runs against Docker Engine 29.9.2 (API 1.56), installed pinned from Docker's repository, with its CLI, Compose 5.6.1 and buildx 0.38.1.
- **Breaking:** a scope file's `containers` is refused; use `builders` (exact names), with a builder configured as [builders](https://github.com/yorvolabs/yorvogate/blob/v0.2.0/docs/configuration.md#builders) says.
- A listener's unix socket is made under a restrictive umask: no one but YorvoGate's user can connect to it before its mode (`0660`) and group are set.

### Security

- **A container a scope could use was fully its own, privileged or not (Critical).** The documented builder setup (buildx's `docker-container` driver, named in a scope's `containers`) is always privileged, and a scope could run any command in it: root on the host. Now:
  - `containers` is replaced by `builders`: exact names, no wildcard, each one scope's;
  - a scope may only inspect its builder and run `buildctl dial-stdio` in it (created and started), and nothing may join its namespaces or volumes;
  - a builder is accepted only while it's rootless and unprivileged, with nothing of the host's ([builders](https://github.com/yorvolabs/yorvogate/blob/v0.2.0/docs/configuration.md#builders)); `allow_privileged_builders` accepts any, for trusted clients only.
- **A scope's form body could override what YorvoGate checked (Critical).** Docker reads a request's parameters from a form-encoded body as well as the query, and the body's win. YorvoGate 0.1.0 checked the query and forwarded the body and its `Content-Type` as they came. So a scope could import an image from any URL under any name (replacing e.g. `postgres:18` for everyone), make the daemon fetch any URL from the host's network, or pull into another scope's protected namespace. Now:
  - a scoped request with a form body (`application/x-www-form-urlencoded`, `multipart/*`), a `Content-Type` that doesn't parse, or two of them is refused;
  - Docker gets the `Content-Type` YorvoGate sets (`application/json` for a checked body, `application/x-tar` for an archive, none without a body), never the client's;
  - `image.create` (a pull) takes no body.
- **Scopes whose names nest could take each other's names (High).** With scopes `jane` and `jane-blog`, `jane` could create `jane-blog`'s names first, and saw `jane-blog`'s containers on a shared network. Now a name or image namespace belongs to the scope with the longest prefix it starts with; a shared network's containers are a scope's by their owner label, not their names; and two scopes may not share an owner label, a prefix or an image namespace (the later one is refused, and `yorvogate check` names both).
- **A scope could label what it created as another scope's (High).** A container's volume mount could create a volume labelled as another scope's, which that scope then listed, inspected and could remove. Now labels a scope sets on what it creates (a container, a network, a volume, a mount's volume) never mark it as another scope's, whatever owner label each scope uses, and a volume a mount creates carries the scope's owner label.
- **Image answers could name other scopes' images (High).** The image list kept every `RepoDigests` entry, and inspect and history answered as Docker did, so a scope saw the names and digests other scopes use for a shared image. Now the list, inspect and history name an image only by the tags and digests the scope may see.

## [0.1.0] - 2026-10-30

The first release.

### Added

- **Listeners**, trusted or scoped, on TCP or unix sockets; one strict YAML configuration (`yorvogate check` reads it and every scope file).
- **Requests read the way Docker reads them:** canonical paths only, Docker API versions 1.44 to 1.56, an endpoint table of API 1.56 (an unknown endpoint is refused), bodies decoded with Docker's own types (unknown fields refused) and re-encoded before they're forwarded.
- **Trusted listeners:** endpoint groups allowed for reading or writing.
- **Scoped listeners:** a scope per request, proven by its token; scope files read again when they change.
  - Containers: created only with what the listener allows (never privileged, the host's namespaces, host paths, devices, kernel parameters, published ports, unmasked /proc…), its own only for everything else, lists filtered; execs never privileged.
  - Networks and volumes: its own, without driver options; shared networks it may join, with only its aliases and addresses; a shared network's inspection without other scopes' containers.
  - Images: names written only in its own namespaces (tag, load, delete); none of another scope's read; image archives' names checked before Docker loads them.
- **Every decision logged** as JSON; every refusal a Docker-style error that says why.
- **Releases:** an image for x86_64 and arm64 (static, on distroless, as a user without privileges), signed with Sigstore, with its SBOM and build provenance; reproducible binaries with signed checksums.

[Unreleased]: https://github.com/yorvolabs/yorvogate/compare/v0.2.2...HEAD
[0.2.2]: https://github.com/yorvolabs/yorvogate/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/yorvolabs/yorvogate/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/yorvolabs/yorvogate/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/yorvolabs/yorvogate/releases/tag/v0.1.0
