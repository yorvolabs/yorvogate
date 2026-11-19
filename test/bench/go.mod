// The benchmark: YorvoGate's overhead against Docker's own, and how it scales with scopes, through the
// built gate and a real Docker. Its own module, standard library only, so `go test ./...` of
// YorvoGate's never runs it.
module github.com/yorvolabs/yorvogate/test/bench

go 1.27.4
