# Threat model

What YorvoGate holds, so you can tell a vulnerability from a limit, and set it up so it holds.

## Who's trusted

- Whoever can write YorvoGate's configuration or a scoped listener's scope files: they decide the policy.
- A client of a **trusted** listener: it gets what the listener's allowlist names. Access to Docker's containers or exec endpoints is root on the machine, so give a trusted listener only to a client that is root-equivalent anyway.
- Docker, runc and the kernel. Docker's own configuration only as YorvoGate checks it: what a scope's container leaves unset, YorvoGate writes itself (a private cgroup namespace, Docker's built-in seccomp profile, the default runtime it read), and while Docker's defaults would widen what a scope may do (no seccomp in the kernel, neither AppArmor nor SELinux, a default runtime not allowed), scoped listeners refuse every request. They're read every 60 seconds; what's checked that way changes only when Docker restarts (its LSM, its kernel's seccomp), and a default runtime reloaded in between doesn't reach scopes' containers, which get the one YorvoGate read. See [Docker's defaults](configuration.md#dockers-defaults).

## Who isn't

**A client of a scoped listener**, whatever requests it sends, however it writes them. Whatever it asks:

1. It can't get root on the host, or out of a container's isolation, through the Docker API: no privileged containers, host mounts, host namespaces, devices, capabilities beyond the listener's list, kernel parameters, unconfined security profiles or unmasked `/proc` paths.
2. It can't read, change or join another scope's containers, volumes, networks or images, nor shared networks beyond what its scope names, with only its own aliases. Another's object is refused as one that isn't there is, by any name or ID, and its images aren't run either. What its timing tells of which of another's names exist is bounded, not closed: see below. Its builders are reached only by `buildctl dial-stdio`, and only while they're rootless and unprivileged.
3. It can't use an endpoint its policy doesn't name; endpoints YorvoGate doesn't know (a newer Docker's) are refused.
4. It can't make YorvoGate read a request one way and Docker another: bodies are decoded with Docker's own types and the same decoder, unknown fields are refused, and what's forwarded is the re-encoded value that was checked. Parameters are read only from the query, as checked, and only those listed for the endpoint go to Docker: any other is refused, as a host path (`checkpoint-dir`) or a deletion that reaches other scopes' images (`platforms` on an image delete) is. Headers too are an allow-list, of those Docker reads: an unlisted header isn't forwarded, and a listed one given twice is refused. A scope's form body (`application/x-www-form-urlencoded`, `multipart/*`) is refused, since Docker would read parameters from it over the query, and Docker gets a `Content-Type` YorvoGate sets, never the client's. Paths must be canonical (no dot segments, empty segments or percent-encoding) and carry an API version YorvoGate knows.
5. It can't act as another scope: each request proves its scope with a token, hashed and compared in constant time with the hash in the scope's file, or with a random one when there's no such scope or its file isn't valid; a client learns nothing about which scopes exist, nor where their files are. A scope removed, no longer valid, or given a new token loses what it was doing at the next read of the scope files (every 2 seconds): its streams end, on a listener with an address as on its own socket. On a listener with [scope sockets](configuration.md#scope-sockets), the socket a request comes on is its scope, and a request that names another scope is refused.

> What a scope may do, endpoint by endpoint: [configuration](configuration.md#what-a-scope-may-do).

**Registries are the operator's.** The daemon fetches from a registry only when the listener lists it ([`pulls.registries`](configuration.md#pulls-scoped-listeners), Docker Hub alone by default), whether a scope pulls from it, inspects a manifest on it or searches it. A loopback, link-local or private address is refused unless it's listed, and so is every other registry. A pull's platform is the host's unless another is listed.

**Names are owned.** Docker names images globally: a scope that retags or loads an image as `postgres:18` would change what every other container that names it runs next. So a scope writes image names (tag, load, delete) only in its own namespaces, and reads none in another's protected namespace.

## Compared with other gates

A gate that checks a request and then forwards the client's own bytes holds only if it reads them exactly as Docker will; CVE-2024-41110 is Docker's AuthZ plugins failing that. YorvoGate forwards the value it checked (point 4 above), so it doesn't depend on reading as Docker does. [How YorvoGate compares](comparison.md) sets this, and the rest, against the other proxies and AuthZ plugins.

## Out of scope

- A flaw in Docker, runc or the kernel, and what runs inside an allowed container.
- A flaw in BuildKit, reached through a builder's `buildctl dial-stdio` (it runs rootless and unprivileged, which limits what one can do).
- Anyone who can reach Docker's socket directly, or write the configuration or scope files.
- A client of a trusted listener reading [scope status](configuration.md#scope-status): it learns which scopes exist and whether each is in effect. A trusted client is root-equivalent anyway; scoped listeners and scope sockets never answer it.
- Anyone who can write YorvoGate's [state file](configuration.md#the-state-file): they can keep names from scopes (deny service), never give a scope more than its own file.
- Anyone who can open a scope's socket: they are that scope. Keep the `scope_sockets` folder out of clients' reach, and give each client only its own socket.
- Resource use through allowed requests (how many containers a scope creates, how much it pulls).
- Timing, bounded but not closed. Docker takes longer to look up an object that exists than to say it doesn't, so a scope could time refusals to tell which of another's names exist. A refusal is held as long as the slowest of the endpoint's last 256 lookups that found an object (at most 250 ms): a lookup slower than all of those still shows, about once in 257, so confirming a guessed name takes thousands of requests. Where Docker is slower than 250 ms, the bound doesn't hold (the gate's debug log says when). A scope whose requests are slow lengthens every scope's refusals on that endpoint, never what's allowed.
- A bare alias on a shared network. Compose gives every service its name as an alias (`web`) on each network it joins, so on a shared network `web` is every tenant's `web`, and Docker's DNS answers it with all their addresses. Only names that identify one site are claimed: an alias with a dot (`jane.quire.internal`), and one under a scope's prefix (its container's name, `jane-web-1`), which only that scope may take. Route traffic on a shared network by a claimed name, never by a bare service name. An alias of a container ID's form (a label of 12 or 64 hex digits) is refused: Docker gives each container its short ID as a name, and such an alias would answer for another's.
- A dotted name Docker splits. When the whole name isn't on any of the asking container's networks, Docker's DNS tries it as `<name>.<network>`, from the right: `a.b.c` on network `d`, then `a.b` on `c.d`, then `a` on `b.c.d`. The whole name is tried first, on every network the container is on, and the first match is the answer. A scope's own networks are named under its prefixes, so a split can only reach the scope's own containers. The one setup this depends on is the orchestrator's: don't name a shared network after the end of a claimed name (no network `quire.internal` while `jane.quire.internal` is claimed), or a bare `jane` there answers for it.
- A listed registry, which is trusted with every scope's images. On Docker's containerd image store, a pulled image is made of the blobs its manifest names, and Docker doesn't fetch a blob it already has. A registry that serves a manifest naming blobs the puller can't read gives the puller those blobs, which may be another scope's layers. Docker Hub and ghcr.io refuse such manifests. A listed registry also decides where the daemon fetches blobs from (it may redirect it anywhere), and a listed host is trusted whatever it resolves to: YorvoGate doesn't resolve names.
- What isn't the daemon's fetch. A scope's builder fetches its `FROM` images over its own container's network (`FROM 10.0.0.5:5000/x`, the cloud's metadata address), and so can any of its containers. Restricting where they reach is egress control: the networks scopes get, and the host's firewall.
- A shared name moves when any scope pulls it. A pull of `postgres:18` gives every scope the newest `postgres:18`, as on any shared host. Only its registry and platform are checked.
- A network an attacker can listen on: TCP listeners speak plain HTTP and the scope's token travels with each request. Bind TCP listeners to a private network only its clients reach, or use a unix socket.

## Setting it up so it holds

- Run YorvoGate as the only way to Docker's socket for scoped clients; give them no other route to it.
- Give each scope a long random token (32 bytes or more) and keep only its SHA-256 in the scope file; scope files and the configuration writable by their owner only (YorvoGate refuses a scope file others can write, and links).
- Set a [`state_file`](configuration.md#the-state-file), and write each scope file by renaming a complete file over the old one: a scope file caught half-written then keeps its names, across restarts too.
- Keep `api.max` at what YorvoGate knows. YorvoGate tells clients the API version it serves, never a newer Docker's, so the Docker CLI, Compose and buildx keep working when Docker is upgraded first; but a newer Docker's new endpoints and fields stay closed until YorvoGate is updated for them.
