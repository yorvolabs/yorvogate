# Changelog

All notable changes to YorvoGate. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/). A release is made from a section here: its version's section is its notes.

## [Unreleased]

### Changed

- **Scopes' claims are decided over every scoped listener, as one folder.** Scoped listeners share one Docker, so a name belongs to the scope with the longest prefix it starts with whichever listener each scope is on; image namespaces and owner labels work the same way. `yorvogate check` and a running gate decide the same way, from one snapshot of every scope file, rebuilt every 2 seconds and on `SIGHUP`; a request reads no file.
- **Breaking: of two scopes that collide, the one that held the claim keeps it; two new ones are both refused.** Files' modification times no longer decide which. `serve` starts with a collision, refusing the scopes in it, as it does within one listener.
- **Breaking: a scope file that isn't valid keeps its claims** until it's removed: its names and image namespaces are no other scope's meanwhile. Until now they were its neighbour's at once.
- **Breaking: a change to a scope file on a token listener takes effect at the next scan** (2 seconds, or `SIGHUP`), as on socket listeners. Write scope files by renaming a complete file over the old one.
- **`yorvogate check` names every scope file it refuses**, not only the first, and warns about what isn't held across a restart.
- **The conformance suite runs on both of Docker's image stores**, containerd and classic, and loads real `docker save` archives through a scope: its own, one named only by a bare `ref.name`, and one whose `manifest.json` names another scope's image.
- **On a listener with an address, a scope removed, no longer valid, or given a new token ends the requests it's being answered**, streams included (attach, exec, logs that follow), at the next read of the scope files, as closing a scope's socket does. Until now a stream begun before went on until the client ended it.
- **The examples in the docs and `examples/yorvogate.yaml` get no warning from `yorvogate check`:** the trusted listener with `write` is on a unix socket instead of a TCP address, each socket has its `socket_group`, and a `state_file` is set. The README's Compose service mounts the sockets' folder and a volume for the state file.
- **The image has its state file's folder, `/var/lib/yorvogate`, owned by YorvoGate's user**, so a volume mounted there is YorvoGate's to write.

- **Breaking: a scope's query parameters and headers are allow-lists.** Each endpoint forwards the query parameters Docker reads for it that YorvoGate lists, and refuses any other (403, naming it), so one a newer Docker adds stays closed until it's listed. Docker gets only the headers it reads that YorvoGate lists (`User-Agent`, `Accept`, `Accept-Encoding`, the OpenTelemetry context, a pull's `X-Registry-Auth`, an attach's `Upgrade`); `Connection` is YorvoGate's own (`Upgrade` on a request that upgrades, otherwise none); any other isn't forwarded, and is named in the log. A listed header given twice is refused. See [query parameters and headers](docs/configuration.md#query-parameters-and-headers).

- **A scope file that isn't valid is answered as a scope that doesn't exist** (401, "no such scope, or not its token") to a client of a listener with an address, not with a 500 that named the file and why; the log of the scan that read it says why, as `yorvogate check` and scope status do; the refusal is logged as a missing scope's. On such a listener, a request that couldn't be decided on is answered without the error, which only the log has.

- **Every answer advertises an API version the gate serves.** A newer Docker's `Api-Version` header and `/version` API version are given as the gate's `api.max`, and an older Docker minimum as `api.min`, on every listener; an older Docker keeps its own version, never one it can't serve, so the Docker CLI, Compose and buildx negotiate a version YorvoGate accepts. Before, upgrading Docker past YorvoGate's API version made every negotiating client ask for the newer version and be refused.

- **Breaking: a scope's container runs the image that was checked for it, named by its ID.** On Docker's containerd image store, the container's image is `<repository>@<ID>` for the name it was created with (`quire-sites/jane/php-prod@sha256:…`); on the classic store, and for an image asked by its ID, it's the ID. A container's `Config.Image` (what `docker ps` shows) changes form accordingly, and a tool that compares it with the name it asked for, or uses it as a name, needs to change. Which form an older client gets depends on its API version: before 1.48, Docker doesn't say which store it has, and the ID is used. An image's inspection, history and the source of a tag go to its ID too; a save and a delete still go by name (a save by ID has no names, a delete by ID deletes the image, not the name).

- **Breaking: `image.load` refuses an archive that refers to content it doesn't hold.** On the containerd store, `docker save` of a pulled multi-platform image (without `--platform`) gives such an archive: its index names platforms that weren't pulled. Save it with `--platform linux/<arch>` (which loads), or pull every platform first. Archives of images built locally, and buildx `--load` output with attestations, load as before.
- **Breaking: a builder whose name a scope's prefix covers is refused.** A builder is named exactly in its scope file, and a scope's containers by their prefixes, so `jane-buildkit` under the prefix `jane-` was both. The scope file that brings the overlap is refused, naming the builder, the prefix and both scopes; the scope that held its claim before keeps it. If both scopes held theirs before (a configuration that overlapped before this check), both are refused, so on upgrade both lose access until one is renamed: run the new version's `yorvogate check` on your configuration before you switch, which names every such pair. Name builders outside every scope's prefixes (`buildkit-jane`, as the docs do).
- **Breaking: a builder that mounts a volume with driver options, or of another driver than `local`, is refused**, as a scope's own container is.
- **A scope's aliases may have `_`, as Compose's do.** A project named `demo_x` gives its containers the alias `demo_x-php-1` on each network, which a scope file refused (aliases had to be strict DNS hostnames). Now an alias is a name as Docker's DNS keeps it: lowercase letters, digits, `-` and `_`, in labels of 1 to 63 separated by `.`. A container's alias is compared as Docker resolves it, in any case; one with a trailing dot or a character outside ASCII is refused (Docker keeps a trailing dot in the name, so `web.` is another name than `web`), and so is an alias with a label of a container ID's form (12 or 64 hex digits), which Docker gives each container as a name.
- **Breaking: two scopes may not have one dotted alias on one shared network, nor an alias under another scope's prefix.** An alias with a dot (`jane.quire.internal`) is the scope's on that network, as a prefix is, and collides as a prefix does: the scope that held it keeps it. An alias under a scope's prefix (`jane-web-1`) is that scope's container's name, and a scope file listing it under another's prefix is refused. A bare alias (`web`, which Compose gives every service) stays shared: see the threat model.
- **The docs say what becomes of an image a rebuild replaces:** with no name left, it's no one's, and a scope doesn't see it by its ID. To keep it, tag it before rebuilding. The conformance suite tags an image before a rebuild and checks the tag keeps it, and that the same image, once its last name is removed, isn't seen by its ID.
- **The CI's conformance job clears Docker's start limit before restarting it** after installing the pinned version, and prints Docker's journal if it doesn't start.
- **Breaking: a scope's pulls reach only the listener's registries.** A pull, a distribution inspection and a search reach only a registry in the listener's new `pulls.registries` (Docker Hub alone by default). Each entry is a host with an optional port, matched exactly. Loopback, link-local and private addresses are refused unless listed. Which registry a request names is read with Docker's own rule for that request, a pull's or a search's. A registry is listed for the whole listener: a scope's image namespace on a registry (`ghcr.io/jane/`) doesn't allow it, and `yorvogate check` gives a notice for each such scope. List each registry your scopes pull from.
- **Breaking: a pull's platform is the host's, or one in `pulls.platforms`.** It's read with containerd's table (`linux/x86_64` is `linux/amd64`), and refused in uppercase or in any other form than `os/arch[/variant]`. If Docker's own platform can't be read, a pull that names a platform is refused. One that names none isn't.
- **Breaking: scoped listeners refuse every request while Docker's defaults would widen what scopes may do:** no seccomp in the kernel, neither AppArmor nor SELinux, or a default runtime other than `runc` that not every scoped listener allows. YorvoGate reads them (`/info`) before it answers a scope, and every 60 seconds. Set `daemon: {without_lsm: true}` for a Docker without an LSM (Docker Desktop, rootless Docker). `yorvogate check --docker` reads them too.
- **What a scope's container leaves unset, YorvoGate writes:** a private cgroup namespace, Docker's built-in seccomp profile (`seccomp=builtin`), and the default runtime it read. A container's `HostConfig` shows them. The IPC mode is left as asked.

### Added

- **Scope status, for orchestrators.** A trusted listener answers `GET /_yorvogate/v1/scopes/<name>` with whether a scope is in effect on a scoped listener (`loaded`, `refused`, `reserved` or `unknown`, with the reason) and the SHA-256 of its file. With `?sha256=<digest>` it waits until that exact file is the one read, and with `?absent` until the scope is gone, scanning at once; a wait that times out answers 408 with `"matched": false`. An orchestrator can wait on its write instead of sleeping past the 2-second scan. The answer's JSON Schema is published with the others.
- **Versioned formats.** The configuration (`version: 1`) and scope files (`"version": 1`) say their format, and a version YorvoGate doesn't read is refused. Without one, a file is read as version 1 with a warning from `yorvogate check` and in the logs; 0.4 refuses it. JSON Schemas for both are published with each release. From now on, before 1.0, a breaking change to a format ships only in a minor release, never in a patch, and an old format keeps working for at least one minor release with a warning.
- **`state_file`**: where YorvoGate keeps each scope's last valid claims across restarts. It only ever refuses names to scopes, never grants any.
- **[How YorvoGate compares](docs/comparison.md)** with other Docker API proxies and AuthZ plugins: the work it builds on (sockguard, swarmgate, wollomatic's bind filtering, OPA), what it does differently, and what it doesn't do.
- **A rootless build from the configuration docs alone, in the conformance suite** (`test/conformance/docs.sh`): the listener, scope file, builder and buildx commands are taken from `docs/configuration.md` and run as written.
- **The AppArmor profile for rootless BuildKit builders is a release file**, `yorvogate-buildkit-rootless`, in `SHA256SUMS` like the binaries: install the copy of the version you run. The configuration docs show its content.

### Security

- **What a scope's container left unset was Docker's to decide (Medium on a loosely configured Docker).** A Docker with `default-cgroupns-mode: host`, `seccomp-profile: unconfined`, another `default-runtime`, or no AppArmor gave scopes' containers more than YorvoGate checked. Now YorvoGate writes the cgroup namespace, the seccomp profile and the runtime, and refuses scopes on a Docker without kernel seccomp or an LSM.
- **A scope could make the daemon reach any registry (Medium).** That included loopback, link-local and private addresses and the metadata address, and on the containerd store a registry of the scope's choosing could give it content Docker already had. The daemon now fetches only from the listener's registries. This covers only what the daemon fetches: a scope's builder and containers reach what their own networks reach (the [threat model](docs/threat-model.md#out-of-scope) says so).
- **Nested names on two scoped listeners weren't resolved (High where a host has two scoped listeners).** The longest-prefix rule saw one listener's scopes only, so with `jane` on one listener and `jane-blog` on another, `jane` could create `jane-blog`'s container names and tag over its image namespace (its next container would run `jane`'s image); `check` passed. Now every listener's scopes are resolved together.
- **A scope file caught half-written gave its names to its neighbour (Medium).** Now it keeps them, as above.
- **A scope could delete an image's content from other scopes' images (Medium).** On the containerd image store, deleting an image with `platforms` (and `force`) deletes that platform's content from every image that has it. YorvoGate checked only that the name deleted was the scope's, so a scope could tag a shared image (`postgres:18`) into its own namespace and delete its content for every scope through that name. `platforms` is now refused on an image delete. Releases up to 0.2.2 are affected, and the fix ships only in 0.3: upgrade from 0.2.x.
- **An OCI archive's image named only by a bare `org.opencontainers.image.ref.name` was loaded unchecked (Medium).** On the containerd image store, Docker names such an image by the bare value as it is (`postgres`, `latest`); YorvoGate read a `ref.name` only when it looked like a full reference, so the name escaped the scope's namespaces. No client could resolve such a name, so it couldn't replace an image anything ran. Now every name is read as containerd reads it, and checked.
- **Which of another scope's names exist could be told by timing (Medium).** Another scope's container, network or volume was refused as one that doesn't exist, but later: Docker inspects an object that exists, and answers at once for one that doesn't. Timed over thousands of requests, a scope could confirm a name it guessed (4.5 ms slower on a container, measured). Now a refused decision is held until it has taken as long as the slowest of the endpoint's recent decisions that found an object (at most 250 ms), which bounds the difference without closing it: see the [threat model](docs/threat-model.md#out-of-scope).
- **A scope could run a container of another scope's image (High where `protected_images` is set).** A container's image was checked by name only, so an image all of whose names are in another scope's protected namespace could be run by its ID, or by as few as 4 of its digits, which Docker takes: the container held that image's code, and whatever its layers have. Now a container's image is checked as an inspect is: one with a name the scope may see. Releases up to 0.2.2 are affected, and the fix ships only in 0.3: upgrade from 0.2.x.
- **What an image operation did could differ from what was checked (Low).** An image was checked by its name and then named to Docker by that name again, so a name moved in between (by the operator: a scope can't move a name onto an image it may not read) changed what a container ran, or what was inspected or tagged. Now Docker gets the image that was checked, by its ID.
- **An image archive's manifest could go unchecked on the classic image store (Medium).** YorvoGate read an archive's `manifest.json` by its exact name, but the classic store's loader strips a leading `/` from each entry and keeps the last of a name, so a second `/manifest.json` was the one Docker read, with names YorvoGate never checked. Now an entry whose name is absolute or has a `..` element is refused; Docker's own `docker save` writes neither. Releases up to 0.2.2 are affected on the classic store, and the fix ships only in 0.3: upgrade from 0.2.x.
- **An image archive could refer to content it didn't hold.** On Docker's containerd store, an import doesn't write, or read, a blob whose digest Docker already has, so an archive's names could be given to content already on the host, which may be another scope's. Now `image.load` loads an archive only if it holds every blob its `index.json` and `manifest.json` reach (nested indexes, manifests, configs, layers, attestations), each with the digest and size it's referred to by. A descriptor it can't read (another media type, another digest algorithm, `urls`) is refused, and so is a `manifest.json` `LayerSources` entry whose blob the archive doesn't hold. Whether this could be used wasn't tested; it's closed by construction.
- **A scope file's change could go unread (Medium).** YorvoGate read a scope file again only when its modification time or size changed. A file rewritten at the same size within one tick of the clock (a new token is the same size), or copied with its times kept (`cp -p`, `rsync -t`, a tar archive), wasn't read again: the old token kept working, and a token listener's open streams weren't ended. A change of mode alone (a file made writable by others) wasn't seen either. Now every scope file is read and hashed at every scan, and parsed again when its content or mode changed. A file that can't be read (an I/O error, a file over 1 MiB) is now refused alone, its claims held as reserved, instead of failing the whole scan. Releases up to 0.2.2 are affected, and the fix ships only in 0.3: upgrade from 0.2.x.
- **A token for a scope that doesn't exist was refused sooner (Low).** It's now hashed and compared, as a wrong token is, and a missing scope, a wrong token and a scope file that isn't valid are refused with the same work: the error of each is made when the files are read, not on each request (a few µs apart before, measured locally). A scope file is opened once, and what's checked (a plain file, its mode) is what's read, not a path that could be swapped between the two.
- **A client's `Connection` header could take headers off the request Docker got (Low).** On an attach or an exec start, `Connection` was forwarded as given, and every header it names is dropped on the way to Docker, so `Connection: Upgrade, Content-Type` took off the `Content-Type` YorvoGate sets for the body it checked. Now YorvoGate writes `Connection` itself.
- **A builder's volumes weren't checked (Low).** A builder that binds a host path is refused, but one that mounts a volume whose driver options bind one (`type=none,o=bind,device=/`) wasn't. Now each volume a builder mounts is read at each use and must be a plain local one; one that can't be read is refused. It takes an orchestrator creating such a builder.
- **A scope could take another's name on a shared network (Low).** Two scope files could list one alias on one shared network, and Docker's DNS answered it with both scopes' containers: a site's name could be taken over, in part, by a tenant beside it. Only whoever writes the scope files could set it up. Now a dotted alias, and one under a scope's prefix, is one scope's only, as above.

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
- **Releases:** an image for x86_64 and arm64 (static, on distroless, as a user without privileges), with its SBOM and build provenance; reproducible binaries with signed checksums. The image of this release isn't signed: image signatures start with 0.2.0.

[Unreleased]: https://github.com/yorvolabs/yorvogate/compare/v0.2.2...HEAD
[0.2.2]: https://github.com/yorvolabs/yorvogate/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/yorvolabs/yorvogate/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/yorvolabs/yorvogate/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/yorvolabs/yorvogate/releases/tag/v0.1.0
