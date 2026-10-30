# The checks CI runs. In the development container: docker compose -f compose.dev.yaml run --rm go make check

STATICCHECK := honnef.co/go/tools/cmd/staticcheck@v0.8.2
GOVULNCHECK := golang.org/x/vuln/cmd/govulncheck@v1.9.0

.PHONY: check format lint test vulnerabilities build

check: format lint test vulnerabilities

# Code formatted as gofmt does (fails on any difference)
format:
	@test -z "$$(gofmt -l .)" || { gofmt -l .; echo 'Not formatted: run gofmt -w .'; exit 1; }

lint:
	go vet ./...
	go run $(STATICCHECK) ./...

test:
	go test -race -count=1 ./...

# Known vulnerabilities in what YorvoGate calls of its dependencies and Go's standard library
vulnerabilities:
	go run $(GOVULNCHECK) ./...

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o bin/yorvogate ./cmd/yorvogate
