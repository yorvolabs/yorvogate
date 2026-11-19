// The load test (0.4-d2): one scope can't starve another, through the built gate and a real Docker.
// Its own module, standard library only, so `go test ./...` of YorvoGate's never runs it.
module github.com/yorvolabs/yorvogate/test/load

go 1.27.4
