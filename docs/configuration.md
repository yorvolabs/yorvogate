# Configuration

One YAML file (`--config`, by default `/etc/yorvogate/yorvogate.yaml`). It's read strictly: an unknown key, a second document or an invalid value stops YorvoGate with the reason, never a default in its place. `yorvogate check --config …` reads it and every scope file without starting.

```yaml
upstream: unix:///var/run/docker.sock   # Docker's socket (required)

api:                                    # Docker API versions accepted (optional)
  min: "1.44"                           # the oldest; 1.44 is the lowest allowed
  max: "1.56"                           # the newest; at most what this build knows

body_limit: 1048576                     # the largest body read whole, in bytes (4096 to 64 MiB)
load_limit: 8589934592                  # the largest image archive a scope loads (1 MiB to 256 GiB)

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
    containers:                         # what scopes' containers may ask of the host (below)
      capabilities: [NET_BIND_SERVICE]
      drop_all_capabilities: true
      no_new_privileges: true
      max_memory: 1073741824
      max_pids: 512
      protected_images: [registry.example.com/tenants/]
```

## Containers (scoped listeners)

What a scope's containers may ask of the host. Whatever isn't listed is refused, and some things never are allowed: privileged containers, the host's namespaces (`host` PID, IPC, UTS, user, cgroup and network modes), host paths (bind mounts, volumes bound to the host), devices and GPUs, kernel parameters, published ports, links, another cgroup parent, runtime annotations, storage options, Docker's default bridge, unmasked or writable `/proc` paths, real-time scheduling, a disabled OOM killer.

| Key | Default | Meaning |
|---|---|---|
| `capabilities` | none | Capabilities that may be added, by name without `CAP_` (`ALL` never) |
| `drop_all_capabilities` | `false` | Every container drops all capabilities first (`CapDrop: [ALL]`) |
| `no_new_privileges` | `false` | Every container runs with `no-new-privileges` |
| `security_options` | none | Other security options allowed, exactly as written (`no-new-privileges` always is) |
| `runtimes` | none | Runtimes allowed besides Docker's default |
| `log_drivers` | none | Log drivers allowed besides `json-file`, `local` and `none` |
| `ulimits` | none | Ulimits that may be set, by name (e.g. `nofile`) |
| `max_memory` | — | When set (bytes, at least 6 MiB): every container has a memory limit up to this |
| `max_pids` | — | When set: every container has a process limit up to this |
| `protected_images` | none | Image name prefixes (ending with `/`) a scope may use only within its own `images` |

A container's configuration is read field by field with Docker's own types: each field is either free (it has no power over the host or other scopes: the command, environment, user, health check, restart policy, CPU shares…), checked by a rule, or refused when set. A field a newer Docker adds is refused until YorvoGate is updated for it. Empty maps and lists ask for nothing, as Docker reads them, but for `MaskedPaths` and `ReadonlyPaths`, where an empty list unmasks `/proc`.

## What a scope may do

| Endpoints | Allowed |
|---|---|
| `_ping`, `version`, `info` | Yes |
| Containers: create | With the rules above; its name starts with a prefix of its scope, it carries the owner label |
| Containers: inspect, logs, stats, start, stop, kill, wait, attach, archive, delete, rename… | Its own only (by the owner label, or named in its scope's `containers`); a rename keeps a name of its own |
| Containers: update | New limits, checked as at create |
| Containers, networks, volumes: list; containers: prune | Only its own: its owner label is added to the request's filters |
| Exec: create, start, resize, inspect | In its own containers only, never privileged |
| Networks: create | A bridge of its own: its name and owner label, no driver options, the default IPAM, inside its `subnets` when it has some |
| Networks: inspect, connect, disconnect | Its own, and the shared networks its scope names (with only its aliases and addresses there); a shared network's inspection lists only its own containers |
| Networks: delete; volumes: inspect, delete | Its own |
| Networks, volumes: prune | Only its own (its owner label is added to the filters) |
| Volumes: create | A local volume of its own: its name and owner label, no driver options (with them, a local volume mounts any host path) |
| Images: list | Without other scopes' images (any name in a protected namespace not its own) and without nameless leftovers |
| Images: inspect, history, save, distribution | By name or ID, unless one of the image's names is in another's protected namespace |
| Images: pull | From a registry, by name, not into another's protected namespace; never an import (`fromSrc`) |
| Images: tag, delete | Only names in its own image namespaces (its scope file's `images`): any other name may be another's to run |
| Images: load | The archive is kept on disk (up to `load_limit`) while every name it gives (Docker's `manifest.json` and `repositories`, the OCI `index.json`) is checked: only names in its own namespaces. Plain, gzip and bzip2 archives (xz and zstd are refused) |
| Images: search | Yes |
| Everything else | No: push, prune, commit, import, build, events, auth, plugins, swarm, BuildKit sessions |

Another scope's objects are answered as Docker answers objects that don't exist. A request names its object by the full ID YorvoGate checked, so what Docker acts on is what was checked.

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
  "prefixes": ["jane-", "jane_"],
  "images": ["registry.example.com/tenants/jane/"],
  "networks": {"edge-jane": {"aliases": ["jane.example.internal"], "addresses": ["10.213.0.4"]}},
  "containers": ["buildx_buildkit_jane-*"],
  "subnets": ["10.213.0.32/27"]
}
```

- `token_sha256`: the SHA-256 of the scope's token, 64 lowercase hex digits. The client sends the token itself.
- `owner`: the label (and its value) that marks the scope's objects. For Compose projects, `com.docker.compose.project` and the project's name.
- `prefixes`: what its containers', networks' and volumes' names start with. Each ends with `-`, `_` or `.`, so `jane-` never matches `janet-…`.
- `images` (optional): its own image namespaces, as prefixes ending with `/`: it may use images there even where the listener protects them.
- `networks` (optional): shared networks it may join besides its own, each with the `aliases` it may take and the `addresses` it may ask for there (none if left out).
- `subnets` (optional): where its networks' addresses must be, in CIDR form: each network it creates names its subnet, inside one of these (otherwise Docker picks from its own pools).
- `containers` (optional): containers it may use without carrying its label, by name, a trailing `*` matching any end (e.g. its BuildKit builder, created by the orchestrator).

A client sends its scope with each request. With the Docker CLI or Compose, through its `config.json` (`DOCKER_CONFIG` pointing at the scope's own folder):

```json
{"HttpHeaders": {"X-YorvoGate-Scope": "jane", "X-YorvoGate-Token": "<the token>"}}
```

## Logs

One JSON line per decision on standard error: `listener`, `method`, `path`, `scope` (scoped listeners), `endpoint`, and for a refusal its `status` and `reason`.
