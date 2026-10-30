# Threat model

What YorvoGate holds, so you can tell a vulnerability from a limit, and set it up so it holds.

## Who's trusted

- Whoever can write YorvoGate's configuration or a scoped listener's scope files: they decide the policy.
- A client of a **trusted** listener: it gets what the listener's allowlist names. Access to Docker's containers or exec endpoints is root on the machine, so give a trusted listener only to a client that is root-equivalent anyway.
- Docker, runc and the kernel.

## Who isn't

**A client of a scoped listener**, whatever requests it sends, however it writes them. Whatever it asks:

1. It can't get root on the host, or out of a container's isolation, through the Docker API: no privileged containers, host mounts, host namespaces, devices, capabilities beyond the listener's list, kernel parameters, unconfined security profiles or unmasked `/proc` paths.
2. It can't read, change or join another scope's containers, volumes, networks or images, nor shared networks beyond what its scope names, with only its own aliases.
3. It can't use an endpoint its policy doesn't name; endpoints YorvoGate doesn't know (a newer Docker's) are refused.
4. It can't make YorvoGate read a request one way and Docker another: bodies are decoded with Docker's own types and the same decoder, unknown fields are refused, and what's forwarded is the re-encoded value that was checked. Paths must be canonical (no dot segments, empty segments or percent-encoding) and carry an API version YorvoGate knows.
5. It can't act as another scope: each request proves its scope with a token, compared in constant time with the hash in the scope's file; a client learns nothing about which scopes exist.

> Today (early development), a scoped listener allows only `_ping` and `version`; each endpoint's rules come as they're written and tested.

## Out of scope

- A flaw in Docker, runc or the kernel, and what runs inside an allowed container.
- Anyone who can reach Docker's socket directly, or write the configuration or scope files.
- Resource use through allowed requests (how many containers a scope creates, how much it pulls).
- A network an attacker can listen on: TCP listeners speak plain HTTP and the scope's token travels with each request. Bind TCP listeners to a private network only its clients reach, or use a unix socket.

## Setting it up so it holds

- Run YorvoGate as the only way to Docker's socket for scoped clients; give them no other route to it.
- Give each scope a long random token (32 bytes or more) and keep only its SHA-256 in the scope file; scope files and the configuration writable by their owner only (YorvoGate refuses a scope file others can write, and links).
- Keep `api.max` at what YorvoGate knows: a newer Docker API is refused until YorvoGate is updated for it, so update YorvoGate before (or with) Docker.
