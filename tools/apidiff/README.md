# apidiff

What changed in Docker's API between two versions, and what YorvoGate decided on each change:

```sh
go run ./tools/apidiff v1.55.0 v1.56.1            # versions of github.com/moby/moby/api
go run ./tools/apidiff -propose v1.55.0 v1.56.1   # and what to ask a model of each undecided row
```

It reads each version's `swagger.yaml` from Go's module cache (`go mod download` fetches it). It imports neither version. It writes a Markdown review sheet: one row per change, with an empty Decision column for the reviewer. It exits 1 while any row is **UNDECIDED**.

| Kind | What's compared | YorvoGate's column |
|---|---|---|
| endpoint | an operation added or removed | its route (`internal/route`), and whether scopes may use it; a new one isn't routed until it's added, so it's refused, and UNDECIDED |
| query, header, path | a parameter added, removed, of another type, or with a reworded description (a new filter shows only there) | free, checked, refused (`internal/gate/endpoints.go`), forwarded or not (headers); UNDECIDED for a query parameter of a scope's endpoint that its descriptor doesn't name |
| body | a field of the request body of an endpoint scopes may use, added, removed or of another type, through `$ref` and `allOf` | the gate's decision on it (`internal/gate/fields.go`), the classification it's in, or "refused, under X" when it's inside a refused field; UNDECIDED otherwise |

Body fields are named as the gate names them: Docker's API names, `[]` for a list's element, `{}` for a map's value (`HostConfig.Mounts[].VolumeOptions.Labels`). `TestTheToolReadsBodiesAsTheGateDoes` checks that swagger and moby's Go types name the same fields at the gate's version. It lists the two that differ, and why.

Docker's handlers read some query parameters that swagger doesn't list. Those are decided on by hand in the endpoint descriptors, and exercised by the differential suite. Response bodies are out of scope: the gate allow-lists what it passes on (0.3-c).

## `-propose`

`-propose` adds a section for a model: what YorvoGate is for, the three decisions, and each undecided row with swagger's description. Give it to a model by hand. Nothing here calls one, and no key or network access is needed.

The model proposes; a maintainer decides each row, and writes the decision with its reason into the code. Only that decision counts.
