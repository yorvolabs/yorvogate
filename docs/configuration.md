# Configuration

One YAML file (`--config`, by default `/etc/yorvogate/yorvogate.yaml`). It's read strictly: an unknown key, a second document or an invalid value stops YorvoGate with the reason, never a default in its place. `yorvogate check --config …` reads it and every scope file without starting.

```yaml
upstream: unix:///var/run/docker.sock   # Docker's socket (required)

api:                                    # Docker API versions accepted (optional)
  min: "1.44"                           # the oldest; 1.44 is the lowest allowed
  max: "1.56"                           # the newest; at most what this build knows

body_limit: 1048576                     # the largest body read whole, in bytes (4096 to 64 MiB)

listeners:                              # at least one
  - name: orchestrator                  # lowercase letters, digits and dashes; in logs
    address: tcp://10.10.0.2:2375       # tcp://host:port, or unix:///absolute/path (made 0660)
    mode: trusted
    allow:                              # endpoint group => read or write
      system: read
      containers: write

  - name: tenants
    address: unix:///run/yorvogate/tenants.sock
    mode: scoped
    scopes: /etc/yorvogate/scopes       # the folder of scope files
```

## Endpoint groups (trusted listeners)

`read` allows a group's endpoints that change nothing; `write` allows all of them.

| Group | Endpoints |
|---|---|
| `system` | `_ping`, `version`, `info`, `events`, `system/df`; `auth` (write) |
| `containers` | list, create, inspect, logs, stats, start, stop, kill, update, rename, attach, wait, delete, archive… |
| `exec` | exec create, start, resize, inspect |
| `images` | list, pull, inspect, history, tag, push, delete, save, load, search, prune, commit |
| `build` | `/build`, build prune and cancel |
| `networks` | list, create, inspect, connect, disconnect, delete, prune |
| `volumes` | list, create, inspect, update, delete, prune |
| `distribution` | `distribution/{name}/json` |
| `plugins` | every plugin endpoint |
| `swarm` | swarm, nodes, services, tasks, secrets, configs |
| `session` | BuildKit's `/session` and `/grpc` |

An endpoint YorvoGate doesn't know is in no group, and refused on every listener.

## Scope files (scoped listeners)

`<scopes>/<name>.json`, one per scope. The name: lowercase letters, digits, `_`, `.` and `-`, up to 63 characters. The file must be a plain file (not a link) that only its owner can write. It's read again whenever it changes.

```json
{
  "token_sha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
  "owner": {"label": "com.docker.compose.project", "value": "jane"},
  "prefixes": ["jane-", "jane_"]
}
```

- `token_sha256`: the SHA-256 of the scope's token, 64 lowercase hex digits. The client sends the token itself.
- `owner`: the label (and its value) that marks the scope's objects. For Compose projects, `com.docker.compose.project` and the project's name.
- `prefixes`: what its containers', networks' and volumes' names start with. Each ends with `-`, `_` or `.`, so `jane-` never matches `janet-…`.

A client sends its scope with each request. With the Docker CLI or Compose, through its `config.json` (`DOCKER_CONFIG` pointing at the scope's own folder):

```json
{"HttpHeaders": {"X-YorvoGate-Scope": "jane", "X-YorvoGate-Token": "<the token>"}}
```

## Logs

One JSON line per decision on standard error: `listener`, `method`, `path`, `scope` (scoped listeners), `endpoint`, and for a refusal its `status` and `reason`.
