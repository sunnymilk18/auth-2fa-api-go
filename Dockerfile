# syntax=docker/dockerfile:1

# ---- build stage ------------------------------------------------------
# Matches go.mod's `go 1.26.0` — bump both together.
FROM golang:1.26-alpine AS builder

WORKDIR /src

# Cache deps in their own layer: only re-downloads when go.mod/go.sum change.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# CGO_ENABLED=0: static binary, no libc dependency — lets the runtime stage
# be a minimal image (no glibc/musl toolchain needed at run time).
# Building all three cmd/ binaries into the same image keeps one Dockerfile
# for the API, the one-shot migration runner, and the tenant-management CLI
# — docker-compose picks which one to run per service via `command:`.
ENV CGO_ENABLED=0 GOOS=linux
RUN go build -ldflags="-s -w" -o /out/api ./cmd/api && \
    go build -ldflags="-s -w" -o /out/migrate ./cmd/migrate && \
    go build -ldflags="-s -w" -o /out/createclient ./cmd/createclient

# ---- runtime stage ------------------------------------------------------
FROM alpine:3.20

# ca-certificates: needed for outbound TLS to Neon/Upstash/Resend (or
# whatever Postgres/Redis/mailer endpoints POSTGRES_DSN/REDIS_URL/
# RESEND_API_KEY point at) — without it those handshakes fail.
# wget: used by the HEALTHCHECK below, already in the base image otherwise.
RUN apk add --no-cache ca-certificates && \
    adduser -D -u 10001 appuser

WORKDIR /app
COPY --from=builder /out/api /out/migrate /out/createclient ./
# The migrate binary reads *.sql relative to its working directory.
COPY migrations ./migrations

# Not copied: keys/ (gitignored, holds the RSA keypair — mount it as a
# volume, or set JWT_PRIVATE_KEY_PEM_BASE64 instead for a platform with no
# persistent/writable filesystem to mount it on.

USER appuser
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget -qO- http://localhost:8080/health || exit 1

# CMD (not ENTRYPOINT): docker-compose's `command: ["./migrate"]` needs to
# fully replace this, not get appended as an argument to it — which is
# exactly what happens with an exec-form ENTRYPOINT here instead. This
# default (no override) is what runs when the image is used as-is, i.e.
# the API server.
CMD ["./api"]
