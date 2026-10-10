# Socrate (go-oauth2) — multi-stage build → distroless static (nonroot) image.
# Referenced by `make docker-build` (docker build -t oauth-server .).
#
# Runtime needs (mount as read-only volumes):
#   /opt/socrate/keys   RSA signing keys (see `make gen-keys`)
#   /opt/socrate/data   optional GeoIP databases
# Pinned to the exact patch release in go.mod's toolchain line; CI fails if the
# two drift. The golang images set GOTOOLCHAIN=local, so this tag — not go.mod —
# is the Go that compiles the shipped binary.
FROM golang:1.27.2-alpine AS build
WORKDIR /src
RUN apk add --no-cache ca-certificates
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/socrate ./cmd/server

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /opt/socrate
COPY --from=build /out/socrate /usr/local/bin/socrate
# Public OAuth :8080. Admin API :8081 (bind loopback in non-container deployments;
# in containers reach it via the container network and isolate by network policy).
EXPOSE 8080 8081
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/socrate"]
