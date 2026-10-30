# YorvoGate

**A policy gate for the Docker API.** By YorvoLabs.

Access to the Docker API is root on the machine: whoever can create a container can create one that mounts `/`, runs privileged, or joins the host's namespaces. Proxies that filter by path (allow "containers", deny "swarm") don't change that, since every escape is in the body of a request they allow. YorvoGate reads every request, its body included, the way Docker reads it, and lets through only what its policy allows, **per client**: a client can be limited to its own containers, volumes, networks and images, created only in ways that can't reach the host.

> **Status:** early development, nothing to install yet. What works: trusted listeners (endpoint allowlists), and scoped listeners with authenticated scopes and their rules for containers, exec, networks, volumes and images (image archives' names checked before they're loaded); real Docker Compose runs through it. Next: fuzzing, conformance tests against a real Docker in CI, and the first release.

## How it works

```
orchestrator ─── trusted listener ───┐
                                     ├── YorvoGate ── Docker's socket
a scope's client ─ scoped listener ──┘
  (X-YorvoGate-Scope, X-YorvoGate-Token)
```

- **Trusted listeners** allow groups of endpoints, each for reading or writing, like a path filter. They're for a client that's trusted anyway (an orchestrator's own operations).
- **Scoped listeners** act for one scope per request. Each request names its scope and proves it with the scope's token (`X-YorvoGate-Scope`, `X-YorvoGate-Token`: the Docker CLI and Compose send them from `config.json`'s `HttpHeaders`). A scope owns what carries its owner label; what it creates must carry that label and start with its name prefixes, and every body is checked against the listener's rules.
- **Read the way Docker reads it.** Bodies are decoded into the Docker Engine's own API types, with unknown fields refused, then re-encoded: what was checked is exactly what Docker gets, whatever the keys' case or duplicates. Paths must be canonical and carry an API version YorvoGate knows (1.44 to 1.56); an endpoint it doesn't know is refused, so a newer Docker's new endpoints stay closed until they're reviewed.
- **Fail-closed and said:** every refusal is a Docker-style error (`{"message": "yorvogate: …"}`) that clients show, and every decision is logged as JSON.

## Configuration

```yaml
upstream: unix:///var/run/docker.sock

listeners:
  - name: orchestrator
    address: tcp://10.10.0.2:2375
    mode: trusted
    allow: {system: read, containers: write, exec: write, images: write, networks: write, volumes: write}

  - name: tenants
    address: unix:///run/yorvogate/tenants.sock
    mode: scoped
    scopes: /etc/yorvogate/scopes
```

A scope is a file in the scoped listener's folder, written by your orchestrator (`/etc/yorvogate/scopes/jane.json`):

```json
{
  "token_sha256": "<the SHA-256 of the scope's token, as hex>",
  "owner": {"label": "com.docker.compose.project", "value": "jane"},
  "prefixes": ["jane-", "jane_"]
}
```

Scope files are read again when they change: adding or removing a scope needs no restart. [docs/configuration.md](docs/configuration.md) has every setting; [docs/threat-model.md](docs/threat-model.md) what YorvoGate holds and what it doesn't.

```bash
yorvogate check --config /etc/yorvogate/yorvogate.yaml   # the configuration and every scope file
yorvogate serve --config /etc/yorvogate/yorvogate.yaml
```

## Working on YorvoGate

See [CONTRIBUTING.md](CONTRIBUTING.md). Everything runs in Docker:

```bash
export HOST_UID=$(id -u) HOST_GID=$(id -g)
docker compose -f compose.dev.yaml run --rm go make check   # format, vet, staticcheck, tests (race), govulncheck
```

## Security

YorvoGate is security software: please report vulnerabilities privately, as [SECURITY.md](SECURITY.md) says.

## License

Apache License 2.0: see [LICENSE](LICENSE) and [NOTICE](NOTICE).
