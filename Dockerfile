# syntax=docker/dockerfile:1

# --- build stage -------------------------------------------------------------
FROM --platform=$BUILDPLATFORM golang:1.23-alpine AS build

ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG VERSION=dev

RUN apk add --no-cache ca-certificates

WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY . .

RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -buildvcs=false \
      -ldflags "-s -w -X main.version=${VERSION}" \
      -o /out/sentineld ./cmd/sentineld

# --- runtime stage -----------------------------------------------------------
# scratch keeps the image at roughly the size of the static binary (~12 MB).
FROM scratch

# CA roots only matter for HTTPS-based providers; harmless otherwise.
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/sentineld /sentineld

# Default config; mount your own over it.
COPY config.example.yaml /etc/sentinel-dns/config.yaml

# Non-root. Docker allows binding port 53 with
# net.ipv4.ip_unprivileged_port_start=0 (see docker-compose.yml); RouterOS
# containers need `user=0:0` instead (see README).
USER 65532:65532

VOLUME ["/var/lib/sentinel-dns"]
EXPOSE 53/udp 53/tcp

ENTRYPOINT ["/sentineld"]
CMD ["-config", "/etc/sentinel-dns/config.yaml"]
