# Configuration

One YAML file (`--config`, by default `/etc/yorvogate/yorvogate.yaml`). It's read strictly: an unknown key, a second document or an invalid value stops YorvoGate with the reason, never a default in its place. `yorvogate check --config …` reads it and every scope file without starting.

```yaml
version: 1                              # the format (required from 0.4)
upstream: unix:///var/run/docker.sock   # Docker's socket (required)

api:                                    # Docker API versions accepted (optional)
  min: "1.44"                           # the oldest; 1.44 is the lowest allowed
  max: "1.56"                           # the newest; at most what this build knows

body_limit: 1048576                     # the largest body read whole, in bytes (4096 to 64 MiB)
load_limit: 8589934592                  # the largest image archive a scope loads (1 MiB to 256 GiB)
state_file: /var/lib/yorvogate/state.json  # scopes' last valid claims, kept across restarts (optional; see below)

listeners:                              # at least one
  - name: orchestrator                  # lowercase letters, digits and dashes; in logs
    address: unix:///run/yorvogate/orchestrator.sock  # unix:///absolute/path (made 0660), or tcp://host:port
    socket_group: orchestrator          # a unix socket's group, a name or a number (optional)
    mode: trusted
    allow:                              # endpoint group => read or write
      system: read
      containers: write

  - name: tenants
    address: unix:///run/yorvogate/tenants.sock
    socket_group: tenants
    mode: scoped
    scopes: /etc/yorvogate/scopes       # the folder of scope files
    containers:                         # what scopes' containers may ask of the host (below)
      capabilities: [NET_BIND_SERVICE]
      drop_all_capabilities: true
      no_new_privileges: true
      max_memory: 1073741824
      max_pids: 512
      protected_images: [registry.example.com/tenants/]

  - name: sites                         # each scope on a socket of its own, instead of an address
    scope_sockets: /run/yorvogate/sites # <scope>.sock for each valid scope file
    socket_group: quire                 # who may connect (optional; YorvoGate's own group if left out)
    mode: scoped
    scopes: /etc/yorvogate/sites
    builder_apparmor_profiles: [yorvogate-buildkit-rootless]  # profiles a builder may run under
    # allow_privileged_builders: true   # any builder, privileged included: the scope is root on the host
```

Every answer tells the client the newest API version both Docker and YorvoGate serve: a newer Docker's own (in the `Api-Version` header and in `/version`) is given as `max`, and Docker's minimum as `min` when it's older. A Docker older than `min` keeps its own version: no version is served by both, and YorvoGate refuses its clients' requests, saying so. A client that negotiates its version, as the Docker CLI, Compose and buildx do, then asks for one YorvoGate serves, so upgrading Docker before YorvoGate doesn't lock clients out.

## Scope sockets

A scoped listener can give each scope a unix socket of its own instead of one address: `scope_sockets: <folder>` in place of `address`. For each valid scope file, YorvoGate makes `<folder>/<scope>.sock`; a request on it is that scope's, with no header and no token. This is how builds are scoped: buildx doesn't send `config.json`'s `HttpHeaders` on its own connections, but it connects to whatever socket its Docker context names.

- A socket comes with its scope file and goes with it. The folders of scope files are read again every 2 seconds, and at once on `SIGHUP`. A scope removed, or no longer valid, has its socket closed, with every connection on it, streams (attach, exec) included.
- A request on a scope's socket that names a scope (`X-YorvoGate-Scope`) must name that one: one that names another is refused, never acted on as the other.
- `token_sha256` is optional in the scope files of such a listener. A scope file with one may serve a token listener too.
- YorvoGate makes the sockets, so its user needs write access to the folder. Sockets are mode `0660`, owned by YorvoGate's user and `socket_group`. They're made so that no one else can connect before the mode and group are set. A file at a socket's path that isn't a socket is left alone, and the scope's socket isn't made (it's logged, and tried again at the next scan).

**Whoever can open a scope's socket is that scope.** The folder belongs where only the orchestrator, or the one client each socket is given to, can reach it: a volume only the orchestrator mounts, then each scope's socket alone mounted into that scope's client. Never give a client the folder.

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
| Containers: create | With the rules above; its name starts with a prefix of its scope, it carries the owner label; its image is one it may read, as for an inspect, by name or ID |
| Containers: inspect, logs, stats, start, stop, kill, wait, attach, archive, delete, rename… | Its own only (by the owner label); a rename keeps a name of its own. Its builders: inspect only |
| Exec: create, start | In its own containers, never privileged. In its builders, only `buildctl dial-stdio` (no resize, no inspect) |
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
| Images: load | The archive is kept on disk (up to `load_limit`) while every name it gives, whichever image store Docker has, is checked: only names in its own namespaces. That's `manifest.json`'s tags and `repositories` (the classic store), and each image `index.json` lists, by its `io.containerd.image.name` or else its `org.opencontainers.image.ref.name` as it is, a bare one too (the containerd store). The archive must also hold every blob its `index.json` and `manifest.json` reach (nested indexes, manifests, configs, layers, attestations), each matching its digest and size: an archive that refers to content it doesn't hold is refused, naming the first digest. A pulled multi-platform image saved without `--platform` names platforms it lacks, so save it with `docker save --platform linux/<arch>`, or pull every platform first. Plain, gzip and bzip2 archives (xz and zstd are refused) |
| Images: search | Yes |
| Everything else | No: push, prune, commit, import, build, events, auth, plugins, swarm, BuildKit sessions |

Another scope's objects are answered as Docker answers objects that don't exist, and in about the same time: a refusal is held until it has taken as long as the slowest of the endpoint's last 256 decisions that found an object (at most 250 ms), so how long Docker takes to look up a name tells little of whether it's another's (the [threat model](threat-model.md#out-of-scope) says how little). A request allowed isn't held. A request names its object by the full ID YorvoGate checked, so what Docker acts on is what was checked.

### Query parameters and headers

**Query parameters: an allow-list, and an unlisted one is refused.** Each endpoint a scope may use forwards the query parameters Docker reads for it, and refuses any other, so a parameter a newer Docker adds stays closed until YorvoGate lists it. Most parameters are Docker's to read (a log's `tail`, a stop's `t`, a `platform`); the rule reads the rest (a create's `name`, a list's `filters`, a pull's `fromImage`). A parameter given twice is refused, except `names` on `image.save-many`. Some parameters Docker reads are refused outright:

| Endpoint | Refused | Why |
|---|---|---|
| containers: start | `checkpoint`, `checkpoint-dir` | Restoring a checkpoint; `checkpoint-dir` names a folder on the host |
| containers: delete | `link` | It removes a legacy link by name, not the container checked |
| images: delete | `platforms` | Docker deletes a platform's content from every image that has it, other scopes' too |
| images: pull | `fromSrc`, `repo`, `message`, `changes` | An import's |
| images: list | `filter` | The filter of API versions before 1.25 |

A pull's `platform` isn't checked yet: until 0.3-d, a scope may pull another platform of a shared name.

**Headers: an allow-list, and an unlisted one isn't forwarded.** Docker gets only the headers it reads that YorvoGate lists, copied from the request: `User-Agent`, `Accept`, `Accept-Encoding`, `traceparent`, `tracestate` and `baggage` everywhere, `X-Registry-Auth` on a pull and a distribution inspect only, `Upgrade` and `Connection` on attach and exec start only. Any other header (a proxy's `Via` or `X-Forwarded-For`, a client's `X-Request-Id`) is left out, without refusing the request, and named in the decision's log line (`headers_not_forwarded`); the first time each name is seen on a listener, it's also a warning. A listed header given twice, under any spelling of its name, or longer than its limit is refused. `Content-Type` is YorvoGate's own, from what it forwards. A trusted listener forwards the client's headers as they come, YorvoGate's own aside.

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

`<scopes>/<name>.json`, one per scope. The name: lowercase letters, digits, `_`, `.` and `-`, up to 63 characters. The file must be a plain file (not a link) that only its owner can write. YorvoGate reads the scope folders again every 2 seconds, and at once on `SIGHUP`; a change takes effect then. Write a scope file by renaming a complete file over it (write `jane.json.new`, then `mv` it to `jane.json`), so YorvoGate never reads half of one.

```json
{
  "version": 1,
  "token_sha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
  "owner": {"label": "com.docker.compose.project", "value": "jane"},
  "prefixes": ["jane-", "jane_"],
  "images": ["registry.example.com/tenants/jane/"],
  "networks": {"edge-jane": {"aliases": ["jane.example.internal"], "addresses": ["10.213.0.4"]}},
  "builders": ["buildkit-jane"],
  "subnets": ["10.213.0.32/27"]
}
```

- `version`: the format, `1`. A scope file without one is read as version 1, with a warning; YorvoGate 0.4 refuses it. See [formats and versions](#formats-and-versions).
- `token_sha256`: the SHA-256 of the scope's token, 64 lowercase hex digits. The client sends the token itself. Optional where each scope has its own socket ([scope sockets](#scope-sockets)).
- `owner`: the label (and its value) that marks the scope's objects. For Compose projects, `com.docker.compose.project` and the project's name. An object is a scope's by this label only, never by its name. What a scope creates must carry it, and no other scope's owner label; a volume a container's mount creates gets it from YorvoGate.
- `prefixes`: what the names of the containers, networks and volumes it creates start with. Each ends with `-`, `_` or `.`, so `jane-` never matches `janet-…`. A container may also take the name Compose gives one it recreates, 12 hex and `_` before one of the scope's names (`f5dba3e4fa27_jane-php-1`), so no prefix may start with 12 hex and `_`.
- `images` (optional): its own image namespaces, as prefixes ending with `/`: it may use images there even where the listener protects them.

Scopes' names may nest, as Compose projects' do (sites `jane` and `jane-blog`): a name belongs to the scope with the **longest** prefix it starts with. While scope `jane-blog` exists, `jane` can't create `jane-blog-php-1` or `jane-blog_default`; image namespaces work the same way. This holds across scoped listeners: they share one Docker, so YorvoGate decides every scope's names, images and labels over all of them, as if their scope files were in one folder. The same scope name on two listeners (one folder served by token and by socket) is one scope.

Two scopes may not share an owner label, a prefix, an image namespace or a builder, on one listener or two. The scope that held it first keeps it and the other is refused (its requests fail); two new scopes that collide (or two at a start without a [state file](#the-state-file)) are both refused. Files' times play no part. `yorvogate check` names every scope it refuses, and why.

A scope file that isn't valid (or that conflicts) is refused alone: its requests fail and its socket closes, the other scopes keep working, and YorvoGate keeps running. **It keeps what it claimed:** the owner label, prefixes, image namespaces and builders it last had while valid stay its own, so while `jane-blog.json` is half-written or wrong, `jane` can't create `jane-blog-php-1` or tag over `quire-sites/jane/blog/`. Its claims go when its file does. With a [state file](#the-state-file) they're held across restarts too; without one, a scope file that isn't valid when YorvoGate starts claims nothing until it's fixed. (Until 0.2.2, a refused scope's names were its neighbour's at once.)

One case is left to the orchestrator: if tenant `jane` has a Compose service named `blog-php` before a scope `jane-blog` exists, its container `jane-blog-php-1` is jane's. Once `jane-blog` arrives, `jane-blog`'s Compose project can't take that name. Nothing crosses between the scopes, since ownership is by label, but it's a denial of service. An orchestrator that lets tenants pick nested names should refuse dashes in service names.
- `networks` (optional): shared networks it may join besides its own, each with the `aliases` it may take and the `addresses` it may ask for there (none if left out).
- `subnets` (optional): where its networks' addresses must be, in CIDR form: each network it creates names its subnet, inside one of these (otherwise Docker picks from its own pools).
- `builders` (optional): its BuildKit builders, by exact name (no wildcard), each one scope's only. See [builders](#builders). 0.1's `containers` key is refused: a container a scope "used" was fully its own, privileged or not.

## The state file

`state_file` (optional) is where YorvoGate keeps each scope's last valid claims (owner label, prefixes, image namespaces, builders), so they're held across restarts. It's YorvoGate's own file: written at once (a new file renamed over it), readable by its owner only, in a folder YorvoGate can write. It must be outside every scopes folder, where whoever writes scope files can't write it.

- It only keeps names from other scopes. It's read only to refuse a scope a name, label or image another scope held, never to let a scope do anything its own file doesn't allow: an edited state file can deny a scope names, never give one any.
- A record goes when its scope file does. While a scopes folder doesn't exist at the start, every record is kept.
- A state file that's missing, or that YorvoGate can't trust (others can write it, or it isn't valid), holds nothing. `yorvogate check` and the logs say so, and `check` warns when there's no `state_file` at all.

## Builders

A scope builds images through a BuildKit builder the orchestrator runs for it: a container named in the scope's `builders`. The scope reaches BuildKit through it and nothing more:

- It may inspect the builder, create an exec of exactly `buildctl dial-stdio` (no user, environment, working directory or TTY), and start that exec. That's all buildx's `remote` driver sends. Everything else is refused: other commands, exec resize and inspect, archive, attach, logs, start, stop, delete, and joining its namespaces or volumes (`PidMode`, `IpcMode`, `NetworkMode: container:…`, `VolumesFrom`). A builder is never one of the scope's own containers, whatever its labels.
- YorvoGate inspects the builder on each use, and accepts it only if it's configured as below. Otherwise every use is refused, naming what failed:
  - not privileged; no added capabilities; no devices, device requests or device cgroup rules;
  - no binds or host paths (volumes and tmpfs only); no host namespaces (PID, IPC, UTS, user, cgroup, network `host`), and none of another container's; no published ports; no `Sysctls`;
  - it runs as a user other than root (`moby/buildkit:<version>-rootless` runs as `1000:1000`);
  - its security options only `seccomp=unconfined`, `systempaths=unconfined`, `no-new-privileges`, and `apparmor=<a profile in the listener's builder_apparmor_profiles>`. YorvoGate sees only a profile's name, so the operator vouches for each name listed. `apparmor=unconfined` is accepted only if listed.
- These options widen the kernel's attack surface for an unprivileged, capability-less process: the accepted risk of builds on a shared kernel.
- `allow_privileged_builders: true` accepts any builder. A privileged builder is root on the host for whoever can exec into it: never for tenants.

The orchestrator creates the builder on its trusted listener (buildx's `docker-container` driver always makes privileged builders), with BuildKit's rootless image, pinned:

```sh
docker run -d --name buildkit-jane \
  --security-opt seccomp=unconfined \
  --security-opt apparmor=yorvogate-buildkit-rootless \
  --security-opt systempaths=unconfined \
  -v buildkit-jane-state:/home/user/.local/share/buildkit \
  moby/buildkit:v0.34.0-rootless@sha256:65eca3c01cd1180c8f64565c4e3c5983af5145818b0e6fa863385d099eb73855
```

Don't add `no-new-privileges`: it breaks rootless BuildKit (`newuidmap: Could not set caps`).

On Ubuntu 24.04 and later, unprivileged user namespaces are restricted by AppArmor (`kernel.apparmor_restrict_unprivileged_userns=1`), and rootless BuildKit doesn't start under `apparmor=unconfined`. Load YorvoGate's profile for it, `yorvogate-buildkit-rootless`, and list it in the listener's `builder_apparmor_profiles`. It grants only `userns`, which is all the restriction takes away:

```
abi <abi/4.0>,
include <tunables/global>

profile yorvogate-buildkit-rootless flags=(unconfined) {
  userns,
}
```

Each release carries it, in its `SHA256SUMS` (signed, as the [README](../README.md#installing) shows), so take the copy of the version you run:

```sh
version=0.3.0
base=https://github.com/yorvolabs/yorvogate/releases/download/v$version
curl -fsSLO "$base/yorvogate-buildkit-rootless" -O "$base/SHA256SUMS" -O "$base/SHA256SUMS.sigstore.json"
# check SHA256SUMS's signature as the README shows, then:
sha256sum --check --ignore-missing SHA256SUMS
sudo install -m 0644 yorvogate-buildkit-rootless /etc/apparmor.d/
sudo apparmor_parser -r /etc/apparmor.d/yorvogate-buildkit-rootless
```

It's also in the repo, at [`examples/apparmor/yorvogate-buildkit-rootless`](../examples/apparmor/yorvogate-buildkit-rootless). Prefer it to setting that sysctl to 0, which lifts the restriction for every process on the host.

The scope uses the builder with buildx's `remote` driver, on its own [socket](#scope-sockets) (buildx sends no header tokens on its own connections). In the scope's `DOCKER_CONFIG`, a context whose endpoint is the scope's socket must be both the current context and the builder's, since `--load` sends the image to the current endpoint (where `image.load` checks its names against the scope's `images`):

```sh
export DOCKER_CONFIG=/srv/scopes/jane/docker
docker context create scope --docker host=unix:///run/yorvogate/sites/jane.sock
docker context use scope
docker buildx create --name jane --driver remote 'docker-container://buildkit-jane?context=scope'
docker buildx build --builder jane --load -t registry.example.com/tenants/jane/app:1 .
```

On a listener with an address, a client sends its scope with each request. With the Docker CLI or Compose, through its `config.json` (`DOCKER_CONFIG` pointing at the scope's own folder):

```json
{"HttpHeaders": {"X-YorvoGate-Scope": "jane", "X-YorvoGate-Token": "<the token>"}}
```

Each request is decided on the scope files as last read. A request already being answered ends at the next read when its scope file is removed, is no longer valid, or has a new `token_sha256`: streams (attach, exec, logs that follow) included, as a scope's socket closes on a [scope-sockets](#scope-sockets) listener. Another scope's requests go on.

## Scope status

An orchestrator that writes or removes a scope file can ask YorvoGate when it's in effect, rather than sleep and hope. A trusted listener answers (a scoped listener or a scope's socket never does):

```
GET /_yorvogate/v1/scopes/<name>?listener=<scoped listener>
GET /_yorvogate/v1/scopes/<name>?listener=<scoped listener>&sha256=<the file's SHA-256>
GET /_yorvogate/v1/scopes/<name>?listener=<scoped listener>&absent
```

`listener` may be left out where there is one scoped listener. The answer ([schema](../schemas/yorvogate-scope-status.v1.schema.json), published with each release):

```
{"version": 1, "generation": 12, "listener": "sites", "scope": "jane", "file_sha256": "…", "state": "loaded", "matched": true}
```

- `state`: `loaded` (in effect; on a listener with scope sockets, its socket is open), `refused` (its file isn't valid, or collides, and it holds no claims), `reserved` (refused, but the claims it last had while valid are held for it) or `unknown` (no file). `reason` says why it's refused or reserved.
- `file_sha256`: the SHA-256 of the scope file the state is about, a refused one included.
- With `sha256`, the request waits (10 seconds at most) until that listener's scope file is the one with that SHA-256, whatever its state: write the file (by renaming a complete one over it), then ask with its SHA-256, and the answer is about that file and no older one. With `absent`, it waits until the scope has no file (`unknown`). YorvoGate scans the folders at once for such a request, rather than at its next scan.
- A wait that ends without what it waited for answers **408** with `"matched": false` and the state as it is: treat it as a failure, never as the state you waited for. A match answers 200 with `"matched": true`.
- `generation` counts the snapshots of the scope files since the start: it's for information, not proof that a write is in one.

## Formats and versions

The configuration and the scope files each say their format: `version: 1` (YAML) and `"version": 1` (JSON). YorvoGate refuses a version it doesn't read, so a file written for a newer format fails at once, saying so, instead of being half-understood. Each format has a JSON Schema, published with every release (`yorvogate-config.v1.schema.json`, `yorvogate-scope.v1.schema.json`, and `yorvogate-scope-status.v1.schema.json` for the [scope status](#scope-status) answer) and kept in [`schemas/`](../schemas): an orchestrator can check what it writes before YorvoGate reads it.

- Before 1.0, a change that breaks a format ships only in a minor release (0.4, 0.5), never in a patch release (0.3.1).
- An old format keeps working for at least one minor release after its successor, with a warning from `yorvogate check` and in the logs.
- Files without `version` are read as version 1 in 0.3, with that warning, and refused from 0.4.

## Migrating from 0.1.0

Run `yorvogate check` with the new version on your configuration and scope folders before you switch: it names every file 0.2 refuses, and why.

- **`containers` in a scope file is refused.** Name the scope's BuildKit builders in `builders`, exactly (no `*`). A builder is no longer a container the scope may use: it may only be inspected and reached with `buildctl dial-stdio`, and only while it's configured as [builders](#builders) says. In practice:
  - create each builder yourself, with BuildKit's rootless image (buildx's `docker-container` driver always makes privileged ones), and register it with buildx's `remote` driver;
  - on Ubuntu 23.10 and later, load the [AppArmor profile](#builders) (a release file, and in `examples/apparmor`) and list it in the listener's `builder_apparmor_profiles`;
  - builds go through a [scope socket](#scope-sockets), since buildx sends no header tokens on its own connections.
- **Scopes may not share an owner label, a prefix, an image namespace or a builder.** The scope file that came later is refused. Names that nest (`jane`, `jane-blog`) are fine: a name belongs to the longest prefix it starts with.
- **What a scope creates may not carry another scope's owner label**, and a volume a container's mount creates gets the scope's own.
- **A scope's request may not have a form body** (`application/x-www-form-urlencoded`, `multipart/*`), and `image.create` (a pull) may not have a body at all. The Docker CLI and Compose send neither.
- **Image answers** (list, inspect, history) name an image only by the tags and digests the scope may see.
- New, optional: [`scope_sockets`](#scope-sockets) (a socket per scope, where `token_sha256` becomes optional) and `socket_group` on any listener with unix sockets.

## Logs

One JSON line per decision on standard error: `listener`, `method`, `path`, `scope` (scoped listeners), `endpoint`, the headers that weren't forwarded (`headers_not_forwarded`, names only), and for a refusal its `status` and `reason`.
