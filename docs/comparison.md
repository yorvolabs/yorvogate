# How YorvoGate compares

YorvoGate isn't the first gate in front of the Docker API, nor the first to read request bodies or keep clients to their own objects. This page names the work it builds on, and says what YorvoGate does differently and what it doesn't do.

Each tool is described as its own README describes it, checked on 8 November 2026. Tecnativa's and wollomatic's proxies and OPA's AuthZ plugin were also tested by hand against Docker 29.9.2 in November 2026: in the setup an operator would use, each let `docker run --privileged -v /:/host` through and the host's files be read. That doesn't make them bad tools. They were built to limit a trusted client, not to contain one that isn't.

| | Decides on | A create's body | Clients told apart | Each client kept to its own objects |
|---|---|---|---|---|
| [Tecnativa docker-socket-proxy](https://github.com/Tecnativa/docker-socket-proxy) | API sections and methods (HAProxy) | not read | no | no |
| [wollomatic socket-proxy](https://github.com/wollomatic/socket-proxy) | a regex on the path per method, and the sources of bind mounts (`-allowbindmountfrom`, off by default) | bind sources only; "a request filter, not a sandbox for otherwise untrusted Docker API clients" | by source address or container, each with its own allowlist | no |
| [OPA's Docker AuthZ plugin](https://github.com/open-policy-agent/opa-docker-authz) | a Rego policy over the request, body included ([Docker's AuthZ plugins](https://docs.docker.com/engine/extend/plugins_authorization/)) | as far as the policy goes: each dangerous field has to be named in it | by the TLS client's user, where Docker has TLS | no |
| [buildkite/sockguard](https://github.com/buildkite/sockguard) (archived; last changed 2021) | an owner label on what it creates; no `privileged`, host network or host binds (paths can be allowed) | the fields it knows to be dangerous | one owner per proxy instance | yes, per instance |
| [CodesWhat/sockguard](https://github.com/CodesWhat/sockguard) (active; v2.4.6) | default-deny method and path rules, body inspectors for most writes, owner labels, per-client profiles, image archives' names checked before a load, image signatures | "only the policy-relevant subset of Docker's schema", leaving the rest to Docker | by address, container labels, TLS certificate or unix peer credentials | yes: an owner label per proxy instance |
| [neuroforgede/swarmgate](https://github.com/neuroforgede/swarmgate) | owner labels on Swarm services, networks, volumes, secrets and configs | mount types and volume drivers | one tenant per proxy | yes, per proxy; alpha, "Please don't use this for separating swarms into tenants and then giving people you can't trust access" |
| **YorvoGate** | a default-deny policy per listener; a scope per request, by token, client certificate or its own socket | decoded whole into Docker's own types, unknown fields refused, then re-encoded | by scope: many on one gate | yes, each scope, decided over every listener |

## What isn't new

- **Reading the body.** buildkite's sockguard refused privileged containers and host binds years before YorvoGate (its repository dates from 2017), and an AuthZ plugin sees the body too.
- **Owner labels.** sockguard and swarmgate keep each owner to what carries its label, as YorvoGate keeps each scope.
- **Checking an image archive's names before it's loaded.** The CodesWhat sockguard fork does it too, OCI index included.
- **A unix socket as the client's identity.** That's how operating systems tell callers apart, and CodesWhat's sockguard uses unix peer credentials to choose a profile.
- **A TLS client certificate as the client's identity.** OPA's plugin takes the TLS client's user from Docker, and CodesWhat's sockguard chooses a profile by certificate.

## What YorvoGate does differently

- **What Docker gets is what was checked.** Every body YorvoGate allows is decoded into the Docker Engine's own API types and then re-encoded, and the re-encoded value is what's forwarded. Duplicate keys, a key's case, `Content-Length: 0` or a form body can't make Docker read a request other than the one YorvoGate decided on ([threat model](threat-model.md), point 4). This is the class of flaw that bypassed Docker's AuthZ plugins in [CVE-2024-41110](https://github.com/moby/moby/security/advisories/GHSA-v23v-6jw2-98fq): the plugin was asked about a request without its body, and Docker then acted on the body. A gate that checks a request and then forwards the client's own bytes has to read them exactly as Docker will. One that forwards what it checked doesn't. None of the tools above documents forwarding the checked value. YorvoGate's differential suite runs the gate in front of Docker's own API server code and checks, for every endpoint a scope may send, in thousands of spellings, that what Docker reads is what the gate decided on ([test/differential](../test/differential/README.md)).
- **Allowlist, not denylist.** A field YorvoGate doesn't know is refused, so a field a newer Docker adds stays closed until YorvoGate is updated for it. Query parameters are too, per endpoint, and Docker gets only the headers YorvoGate lists. A gate that looks only at the fields it knows to be dangerous lets new ones through.
- **Many scopes on one gate.** Each request is one scope's, by its token, its client certificate or the socket it comes on. Scopes' names, labels, image namespaces and builders are decided together over every scoped listener on the same Docker, so names that nest (`jane`, `jane-blog`) stay apart across listeners too. The owner-label tools above keep one owner per proxy instance.
- **Image names are owned.** A scope writes image names only in its own namespaces, and reads none in another's protected ones, so it can't retag what other scopes' containers run next.

## What YorvoGate doesn't do (yet)

- **Podman, Swarm, image signatures, rate limits and read redaction**, which CodesWhat's sockguard covers.
- **`docker build` on Docker's own builder.** A scope builds on a rootless BuildKit builder of its own ([builders](configuration.md#builders)).
