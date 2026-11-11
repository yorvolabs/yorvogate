# The checks CI runs. In the development container: docker compose -f compose.dev.yaml run --rm go make check

STATICCHECK := honnef.co/go/tools/cmd/staticcheck@v0.8.2
GOVULNCHECK := golang.org/x/vuln/cmd/govulncheck@v1.9.0
GREMLINS := github.com/go-gremlins/gremlins/cmd/gremlins@v0.5.1

# How long each fuzz target runs (make fuzz FUZZTIME=10m)
FUZZTIME ?= 30s
# The least share of mutants the tests must kill, per package
EFFICACY ?= 90

# The version a release's binaries say they are (make dist VERSION=1.2.3)
VERSION ?= dev

.PHONY: check format lint test vulnerabilities differential build fuzz mutation dist

check: format lint test vulnerabilities differential

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

# The differential suite: the gate in front of Docker's own API server code (moby's routers, at the
# Engine version CI installs), whose backends record what they're handed; what Docker reads of what
# the gate forwards must be what the gate decided on (test/differential/README.md). Its own module,
# so moby's daemon stays out of YorvoGate's go.mod. Budget: 60 s once its modules are downloaded
# and built (about 3 s of tests); the first build takes minutes. Without cgo (one of moby's network
# packages wants libnftables with it), so without -race.
differential:
	cd test/differential && CGO_ENABLED=0 go vet ./... && CGO_ENABLED=0 go test -count=1 -timeout 60s ./...

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o bin/yorvogate ./cmd/yorvogate

# Each fuzz target in turn (Go fuzzes one target at a time)
fuzz:
	go test -run '^$$' -fuzz '^FuzzParse$$' -fuzztime $(FUZZTIME) ./internal/route
	go test -run '^$$' -fuzz '^FuzzCreateContainer$$' -fuzztime $(FUZZTIME) ./internal/gate
	go test -run '^$$' -fuzz '^FuzzListFilters$$' -fuzztime $(FUZZTIME) ./internal/gate
	go test -run '^$$' -fuzz '^FuzzArchiveNames$$' -fuzztime $(FUZZTIME) ./internal/gate

# Mutation testing: each package's tests must kill at least EFFICACY % of the mutants they cover.
# gremlins v0.5.1's --threshold-efficacy does not fail the run, so the floor is enforced here by
# reading "Test efficacy" from its output. One worker: in parallel, the gate's tests slow each
# other down, and mutants that time out don't count (efficacy looks higher). Without Go's test cache,
# which leaves gremlins no coverage.
mutation:
	@fail=0; \
	for p in ./internal/route ./internal/config ./internal/scope ./internal/gate ./cmd/yorvogate; do \
		floor=$(EFFICACY); \
		out=$$(GOFLAGS=-count=1 go run $(GREMLINS) unleash --workers 1 --timeout-coefficient 10 $$p 2>&1); \
		printf '%s\n' "$$out"; \
		eff=$$(printf '%s\n' "$$out" | sed -n 's/.*[Tt]est efficacy: \([0-9.]*\)%.*/\1/p' | tail -1); \
		if [ -z "$$eff" ]; then echo "mutation: $$p: no efficacy reported"; fail=1; continue; fi; \
		if awk "BEGIN{exit !($$eff < $$floor)}"; then echo "mutation: $$p efficacy $$eff%% is below the $$floor%% floor"; fail=1; fi; \
	done; \
	[ $$fail -eq 0 ]

# A release's binaries (Linux, x86_64 and arm64), reproducible, and their SHA256SUMS
dist:
	rm -rf dist && mkdir -p dist
	for arch in amd64 arm64; do \
		CGO_ENABLED=0 GOOS=linux GOARCH=$$arch go build -trimpath -buildvcs=false -ldflags "-s -w -buildid= -X main.version=$(VERSION)" \
			-o dist/yorvogate ./cmd/yorvogate && \
		tar -C dist --owner=0 --group=0 --numeric-owner --mtime='2026-01-01 00:00Z' -czf dist/yorvogate-$(VERSION)-linux-$$arch.tar.gz yorvogate && \
		rm dist/yorvogate || exit 1; \
	done
	cp schemas/*.schema.json examples/apparmor/yorvogate-buildkit-rootless dist/
	cd dist && sha256sum yorvogate-*.tar.gz *.schema.json yorvogate-buildkit-rootless > SHA256SUMS
