#syntax=docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e

# YorvoGate's image: its static binary on distroless, as a user without privileges (uid 65532). It
# reaches Docker's socket through the socket's group, given when it runs:
#   docker run --group-add "$(stat -c %g /var/run/docker.sock)" -v /var/run/docker.sock:/var/run/docker.sock …
#
# Images are pinned by digest (a tag can be moved, a digest can't); Dependabot proposes new ones.
FROM --platform=$BUILDPLATFORM golang:1.27.4-alpine@sha256:0a5f7fe796599ff487605987432e7619ae45beeb2fba4c2ce0b907879932aebf AS build

ARG TARGETOS TARGETARCH
ARG VERSION=dev

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY cmd cmd/
COPY internal internal/

# Reproducible: no paths, no build ID, no VCS stamp (the version says which release it is)
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -buildvcs=false \
        -ldflags "-s -w -buildid= -X main.version=${VERSION}" -o /yorvogate ./cmd/yorvogate

# Its state file's folder, its own: a volume mounted there starts as YorvoGate's
RUN mkdir -p /out/var/lib/yorvogate

FROM gcr.io/distroless/static-debian13:nonroot@sha256:25ac8f0c3b2334a9eb05452266bd4697864a8c8ef0ef71e5e6480d7f92868329

ARG VERSION=dev
LABEL org.opencontainers.image.title="YorvoGate" \
      org.opencontainers.image.description="A policy gate for the Docker API: every request's body read, each client scoped to its own Compose project." \
      org.opencontainers.image.source="https://github.com/yorvolabs/yorvogate" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.vendor="YorvoLabs" \
      org.opencontainers.image.authors="YorvoLabs <contact@yorvolabs.com>" \
      org.opencontainers.image.version="${VERSION}"

COPY --from=build /yorvogate /usr/local/bin/yorvogate
COPY --from=build --chown=65532:65532 /out/var/lib/yorvogate /var/lib/yorvogate

USER 65532:65532
ENTRYPOINT ["/usr/local/bin/yorvogate"]
CMD ["serve", "--config", "/etc/yorvogate/yorvogate.yaml"]
