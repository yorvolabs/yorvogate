# Threat model

What YorvoGate holds, so you can tell a vulnerability from a limit, and set it up so it holds.

## Who's trusted

- Whoever can write YorvoGate's configuration or a scoped listener's scope files: they decide the policy.
- A client of a **trusted** listener: it gets what the listener's allowlist names. Access to Docker's containers or exec endpoints is root on the machine, so give a trusted listener only to a client that is root-equivalent anyway.
- Docker, runc and the kernel.

## Who isn't

**A client of a scoped listener**, whatever requests it sends, however it writes them. Whatever it asks:

1. It can't get root on the host, or out of a container's isolation, through the Docker API: no privileged containers, host mounts, host namespaces, devices, capabilities beyond the listener's list, kernel parameters, unconfined security profiles or unmasked `/proc` paths.
2. It can't read, change or join another scope's containers, volumes, networks or images, nor shared networks beyond what its scope names, with only its own aliases. Its builders are reached only by `buildctl dial-stdio`, and only while they're rootless and unprivileged.
3. It can't use an endpoint its policy doesn't name; endpoints YorvoGate doesn't know (a newer Docker's) are refused.
4. It can't make YorvoGate read a request one way and Docker another: bodies are decoded with Docker's own types and the same decoder, unknown fields are refused, and what's forwarded is the re-encoded value that was checked. Parameters are read only from the query, as checked: a scope's form body (`application/x-www-form-urlencoded`, `multipart/*`) is refused, since Docker would read parameters from it over the query, and Docker gets a `Content-Type` YorvoGate sets, never the client's. Paths must be canonical (no dot segments, empty segments or percent-encoding) and carry an API version YorvoGate knows.
5. It can't act as another scope: each request proves its scope with a token, compared in constant time with the hash in the scope's file; a client learns nothing about which scopes exist. A scope removed, no longer valid, or given a new token loses what it was doing at the next read of the scope files (every 2 seconds): its streams end, on a listener with an address as on its own socket. On a listener with [scope sockets](configuration.md#scope-sockets), the socket a request comes on is its scope, and a request that names another scope is refused.

> What a scope may do, endpoint by endpoint: [configuration](configuration.md#what-a-scope-may-do).

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
- A network an attacker can listen on: TCP listeners speak plain HTTP and the scope's token travels with each request. Bind TCP listeners to a private network only its clients reach, or use a unix socket.

## Setting it up so it holds

- Run YorvoGate as the only way to Docker's socket for scoped clients; give them no other route to it.
- Give each scope a long random token (32 bytes or more) and keep only its SHA-256 in the scope file; scope files and the configuration writable by their owner only (YorvoGate refuses a scope file others can write, and links).
- Set a [`state_file`](configuration.md#the-state-file), and write each scope file by renaming a complete file over the old one: a scope file caught half-written then keeps its names, across restarts too.
- Keep `api.max` at what YorvoGate knows. YorvoGate tells clients the API version it serves, never a newer Docker's, so the Docker CLI, Compose and buildx keep working when Docker is upgraded first; but a newer Docker's new endpoints and fields stay closed until YorvoGate is updated for them.
