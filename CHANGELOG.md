# Changelog

All notable changes to YorvoGate. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/). A release is made from a section here: its version's section is its notes.

## [Unreleased]

### Added

- **[An AI agent's Docker socket](docs/agents.md):** why the Docker socket is root on the host, and how to give an agent a scope socket instead, in a container or on the host. Its setup runs in the conformance suite.

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

[Unreleased]: https://github.com/yorvolabs/yorvogate/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/yorvolabs/yorvogate/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/yorvolabs/yorvogate/releases/tag/v0.1.0
