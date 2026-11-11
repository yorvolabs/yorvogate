# An AI agent's Docker socket

Coding and operations agents are given Docker so they can run tests, services and builds. They're usually given `/var/run/docker.sock`, and **that socket is root on the host**. This page explains why, and how to give an agent a socket of its own through YorvoGate instead: the agent keeps a Docker that works, limited to its own containers, networks, volumes and images, created only in ways that can't reach the host.

## Why the Docker socket is root

Whoever can talk to Docker's socket can ask Docker to start a container that mounts the host's `/`, runs privileged, or joins the host's namespaces:

```bash
docker run --rm -v /:/host alpine chroot /host   # a root shell on the host
```

Docker runs it as root on the host, whoever asked. Docker's own documentation says so: only trusted users should control the daemon. An agent that can run commands and has the socket doesn't need a bug to get out: it asks.

This isn't only theory:

- **Real agents' sandboxes.** In July 2026, Pillar Security showed the sandboxes of Codex CLI, Cursor and Gemini CLI escaped through the Docker socket the sandbox left reachable: the agent ran the Docker CLI and started a privileged container with a bind mount, outside the sandbox's control. Cursor fixed it as a high-severity issue (GHSA-v4xv-rqh3-w9mc). ([Pillar Security, "One Docker socket to rule them all"](https://www.pillar.security/blog/one-docker-socket-to-rule-them-all-escaping-codex-cursor-and-gemini-clis-sandboxes))
- **Models do it.** SandboxEscapeBench, from the UK AI Security Institute, measures whether language models escape containers. Its scenarios range from simple misconfigurations (an exposed Docker socket, a privileged container) to kernel flaws; given such a weakness, models find and exploit it. ([arXiv:2603.02277](https://arxiv.org/abs/2603.02277); [AISI's summary](https://www.aisi.gov.uk/blog/can-ai-agents-escape-their-sandboxes-a-benchmark-for-safely-measuring-container-breakout-capabilities))

Filtering what an agent may call as a tool doesn't close this: an agent that can write and run code opens the socket itself. Neither does a proxy that filters by path ("containers" allowed, "swarm" denied): every escape above is a request to create a container, which such a proxy allows. What decides is the body of that request, and that's what YorvoGate reads.

## One agent, one scope, one socket

Each agent is a [scope](configuration.md#scope-files-scoped-listeners) of a scoped listener with [scope sockets](configuration.md#scope-sockets): YorvoGate makes a socket for it, and a request on that socket is that agent's. No token to hand out or leak: the agent's Docker client needs nothing but the socket, which it uses as it would use Docker's.

```yaml
version: 1
upstream: unix:///var/run/docker.sock
state_file: /var/lib/yorvogate/state.json
listeners:
  - name: agents
    scope_sockets: /run/yorvogate/agents   # ana.sock, bob.sock: one per scope file
    socket_group: "2100"                   # the group that may connect (the agents')
    mode: scoped
    scopes: /etc/yorvogate/agents
```

YorvoGate's own user must be in the group to give it its sockets (in its container: `group_add: ["2100"]`, besides Docker's socket's group).

`/etc/yorvogate/agents/ana.json`, the agent `ana`:

```json
{
  "version": 1,
  "owner": {"label": "com.docker.compose.project", "value": "ana"},
  "prefixes": ["ana-", "ana_"],
  "images": ["agents/ana/"]
}
```

- **Its objects** are the ones with its owner label. The label is Compose's project label, so `docker compose -p ana` works as it is: Compose names and labels everything for the project. Other scopes' (and the host's) containers, networks and volumes don't exist for it.
- **What it creates** must carry the label, and its names must start with `ana-` or `ana_`. With the plain CLI, that's `--label com.docker.compose.project=ana --name ana-…`. Docker's default bridge is refused (every container on it can reach every other), so containers join a network of its own, or `none`. Put this in the agent's instructions; a refusal says what was missing:

  ```bash
  docker network create --label com.docker.compose.project=ana ana-net
  docker run -d --name ana-web --label com.docker.compose.project=ana --network ana-net nginx
  ```
- **What it may never do**, whatever it asks: privileged containers, host paths, devices, the host's namespaces, published ports, added capabilities (none are listed here), and the rest of [the containers' rules](configuration.md#containers-scoped-listeners).
- **Stricter containers**, with the listener's [`containers`](configuration.md#containers-scoped-listeners) keys: `drop_all_capabilities`, `no_new_privileges`, `max_memory` and `max_pids` are requirements, not defaults. Each container must then ask for them (`--cap-drop ALL --security-opt no-new-privileges --memory 1g --pids-limit 256`, or the same in a Compose file), and one that doesn't is refused.
- **Images** it pulls are shared with the host; it may tag and delete only in its own namespace (`agents/ana/`).

YorvoGate reads the folder of scope files every 2 seconds: write `bob.json` and `bob.sock` appears; remove it and the socket closes, with every connection on it. Give each agent its own name; two scopes may not share an owner label, a prefix or an image namespace.

## An agent in a container

Mount the agent's socket, alone, where Docker's clients look for it, and give the agent's user the socket's group:

```bash
docker run -d --name agent-ana \
  --user 1000:1000 --group-add 2100 \
  -v /run/yorvogate/agents/ana.sock:/var/run/docker.sock \
  your-agent-image
```

When YorvoGate runs in a container with the folder in a named volume (say `yorvogate-agents`, mounted at `/run/yorvogate/agents` in YorvoGate's container), mount the one socket from the volume:

```bash
docker run -d --name agent-ana \
  --user 1000:1000 --group-add 2100 \
  --mount type=volume,src=yorvogate-agents,dst=/var/run/docker.sock,volume-subpath=ana.sock \
  your-agent-image
```

- **Never mount the folder.** Whoever can open a scope's socket is that scope: an agent with the folder could open every other agent's socket.
- **No `DOCKER_HOST`, no context, no configuration.** The Docker CLI, Compose and SDKs find `/var/run/docker.sock` as they would Docker's.
- **When YorvoGate restarts**, it makes the sockets anew: a container that mounted the old one doesn't see the new one. Restart the agent's container after YorvoGate (or start agents' containers from the same orchestration, after it).

## An agent on the host

An agent running as a user on the host reaches what its user may open. The sockets of one listener share one `socket_group`, so a user in that group could open every one of them. On the host, give each agent a user of its own and a listener of its own, with its own folder and group:

```yaml
version: 1
upstream: unix:///var/run/docker.sock
state_file: /var/lib/yorvogate/state.json
listeners:
  - name: agent-ana
    scope_sockets: /run/yorvogate/agent-ana   # only ana.sock in it
    socket_group: agent-ana                   # the group of ana's user only
    mode: scoped
    scopes: /etc/yorvogate/agent-ana          # only ana.json in it
```

Then, as ana's user:

```bash
export DOCKER_HOST=unix:///run/yorvogate/agent-ana/ana.sock
```

The agent's user must not be in the `docker` group, nor able to read `/var/run/docker.sock` some other way (sudo, a setuid helper): YorvoGate limits what reaches Docker through it, not what reaches Docker around it.

## What it refuses

[SandboxEscapeBench](https://github.com/UKGovernmentBEIS/sandbox_escape_bench) (UK AI Security Institute) measures whether a frontier model with a shell in a container can break out to the host, and finds that current models do so comfortably where the container is misconfigured: a mounted Docker socket, a privileged container, a writable host mount, a dangerous capability, the host's PID namespace. An agent given a YorvoGate scope can't create such a container in the first place. Each of those is a Docker API request, and the gate refuses it, by every route a scope has to it:

- **the mounted-socket escape** — when the agent's socket *is* a scope socket, the benchmark's own winning move (create a container binding `/` and read the host's files) is refused, as are the bind-mount and host-binding-volume routes to the same reach;
- **a privileged container**, at `container.create` and at `exec`;
- **a host path**, bound directly or through a `local` volume with driver options (a two-step the gate stops at the `volume.create`);
- **a dangerous capability** (`SYS_ADMIN`, `SYS_MODULE`, `DAC_READ_SEARCH`, `SYS_PTRACE`, or `ALL`), an unconfined seccomp profile, a host device;
- **the host's PID namespace**;
- and the endpoints a scope has no use for at all — plugins, swarm, a direct build.

The replay of these scenarios runs in CI, and a nightly control on a real Docker shows each escape reaching the host through a raw socket and the gate refusing the request that enables it ([test/differential](../test/differential/README.md#agent-escape-scenarios-03-g), [test/conformance/escapes.sh](../test/conformance/escapes.sh)). The claim is exact: **the enabling Docker API requests of these scenarios are refused, by every route we enumerate.** It is not that a container, once running, is unescapable — a kernel or runtime flaw reached from a plain unprivileged container (SandboxEscapeBench's other scenarios: Dirty COW, Dirty Pipe, a runc or cgroup CVE) is the host kernel's and runtime's to fix, and egress control's to contain, not the gate's.

## What it doesn't cover

- **The network, unless you say so.** An agent's containers reach whatever its networks reach, the internet included. Give its scope `"egress": "none"` (or its listener `containers.egress: none`): its containers and builders then join only internal networks ([egress](configuration.md#egress)). For a way out, run a proxy on a shared internal network its scope names (`"networks": {"agent-egress-ana": {}}`) and on a network of its own: the agent reaches only the proxy, and **the proxy's allowlist is the agent's egress policy**. Its Compose file names that network as external, and its own networks as `internal: true`. Its builder, if it has one, fetches through the proxy too (BuildKit's `HTTP_PROXY`). Turning `egress: none` on for an agent that's running means disconnecting or recreating its containers, which `yorvogate check --docker` lists.
- **Builds.** A scope has no `docker build` on Docker's own builder. An agent that builds needs a [builder](configuration.md#builders) of its own.
- **The agent itself.** YorvoGate limits what the agent can ask of Docker, not what it can do with what it's allowed: run code in its containers, use their network, fill its memory limits. See the [threat model](threat-model.md).

The setup on this page runs in the conformance suite in CI (`test/conformance/agents.sh`): an agent in a container, its socket mounted alone from the volume, as a user in the socket's group. Its Docker CLI and Compose run, exec, read logs and remove its own containers; it can't mount the host's `/`, run privileged, join the host's namespaces, use the default bridge, or see, use or remove another agent's or the host's containers; a user outside the group can't connect at all.
