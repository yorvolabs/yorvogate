#syntax=docker/dockerfile:1

# YorvoGate's image: its static binary on distroless, as a user without privileges (uid 65532). It
# reaches Docker's socket through the socket's group, given when it runs:
#   docker run --group-add "$(stat -c %g /var/run/docker.sock)" -v /var/run/docker.sock:/var/run/docker.sock …
#
# Images are pinned by digest (a tag can be moved, a digest can't); Dependabot proposes new ones.
FROM --platform=$BUILDPLATFORM golang:1.27.3-alpine@sha256:d200d2dd76b03a99b52651fd1325aff7dcd35422c35c01bac56571b0507f3deb AS build

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

FROM gcr.io/distroless/static-debian13:nonroot@sha256:18f4cc26c9ffa7f20a359298be7deadac5c607c8e03a02b8119f1a5fc2f82c99

ARG VERSION=dev
LABEL org.opencontainers.image.title="YorvoGate" \
      org.opencontainers.image.description="A policy gate for the Docker API: every request's body read, each client scoped to its own Compose project." \
      org.opencontainers.image.source="https://github.com/yorvolabs/yorvogate" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.vendor="YorvoLabs" \
      org.opencontainers.image.version="${VERSION}"

COPY --from=build /yorvogate /usr/local/bin/yorvogate

USER 65532:65532
ENTRYPOINT ["/usr/local/bin/yorvogate"]
CMD ["serve", "--config", "/etc/yorvogate/yorvogate.yaml"]
