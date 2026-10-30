# Changelog

All notable changes to YorvoGate. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/). A release is made from a section here: its version's section is its notes.

## [Unreleased]

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

[Unreleased]: https://github.com/yorvolabs/yorvogate/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/yorvolabs/yorvogate/releases/tag/v0.1.0
