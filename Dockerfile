# syntax=docker/dockerfile:1.7
#
# Multi-stage build for the k7s-web single-binary server (monorepo layout).
#
# Produces a musl-linked static binary (no glibc dependency).
# The runtime image is alpine-based (~12 MB total).
#
# Expects the build context to be the repository root:
#   - Cargo.toml / Cargo.lock   (workspace)
#   - crates/                   (all workspace members)
#   - dist/                     (pre-built frontend)
#
# Build from the repo root:
#   docker build -t ghcr.io/yi-nology/k7s:latest \
#     -f crates/k7s-server/Dockerfile .

# ─────────────────────────────────────────────────────────────────
# Stage 1 — front-end (pre-built in CI or local build)
# ─────────────────────────────────────────────────────────────────
FROM alpine:3.21 AS frontend
COPY dist /dist

# ─────────────────────────────────────────────────────────────────
# Stage 2 — Rust binary (musl static, multi-arch)
# ─────────────────────────────────────────────────────────────────
FROM rust:1-bookworm AS backend

ARG TARGETARCH

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      musl-tools \
      pkg-config libssl-dev ca-certificates \
      build-essential file \
 && rm -rf /var/lib/apt/lists/*

# Install the correct musl target for the build platform.
RUN case "${TARGETARCH}" in \
      amd64) rustup target add x86_64-unknown-linux-musl ;; \
      arm64) rustup target add aarch64-unknown-linux-musl ;; \
      *) echo "unsupported arch: ${TARGETARCH}" && exit 1 ;; \
    esac

WORKDIR /src

# Dependency manifests first for layer caching.
COPY Cargo.toml ./
COPY crates/k7s-deps/Cargo.toml ./crates/k7s-deps/
COPY crates/k7s-core/Cargo.toml ./crates/k7s-core/
COPY crates/k7s-commands/Cargo.toml ./crates/k7s-commands/
COPY crates/k7s-server/Cargo.toml ./crates/k7s-server/

# Stub sources so cargo fetch can resolve the dependency graph.
RUN mkdir -p crates/k7s-deps/src crates/k7s-core/src crates/k7s-commands/src crates/k7s-server/src \
 && echo "pub fn dummy() {}" > crates/k7s-deps/src/lib.rs \
 && echo "pub fn dummy() {}" > crates/k7s-core/src/lib.rs \
 && echo "pub fn dummy() {}" > crates/k7s-commands/src/lib.rs \
 && echo "pub fn dummy() {}" > crates/k7s-server/src/lib.rs \
 && echo "fn main() {}" > crates/k7s-server/src/main.rs \
 && cargo fetch

# Real sources.
COPY crates ./crates
# rust-embed #[folder = "../../dist"] is relative to crates/k7s-server/,
# so it looks for /src/dist/ — copy the frontend there.
COPY dist ./dist

# Static musl build from the workspace root.
RUN ARCH_TRIPLE=$(case "${TARGETARCH}" in \
          amd64) echo "x86_64-unknown-linux-musl" ;; \
          arm64) echo "aarch64-unknown-linux-musl" ;; \
        esac) \
 && cargo build --release -p k7s-server --features k7s-server/web \
      --bin k7s-web --target "${ARCH_TRIPLE}" \
 && cp "target/${ARCH_TRIPLE}/release/k7s-web" /k7s-web

# ─────────────────────────────────────────────────────────────────
# Stage 3 — runtime (minimal, no glibc)
# ─────────────────────────────────────────────────────────────────
FROM alpine:3.21 AS runtime

RUN addgroup -S k7s && adduser -S -G k7s -h /home/k7s k7s \
 && mkdir -p /home/k7s /data && chown -R k7s:k7s /home/k7s /data

USER k7s:k7s
WORKDIR /app

COPY --from=backend --chown=k7s:k7s /k7s-web /app/k7s-web
COPY --from=frontend --chown=k7s:k7s /dist /app/dist

ENV XDG_CONFIG_HOME=/data
ENV KUBECONFIG=/home/k7s/.kube/config
ENV RUST_LOG=info

VOLUME ["/data"]
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --retries=3 --start-period=10s \
  CMD wget --no-verbose --tries=1 --spider http://localhost:8080/ || exit 1

ENTRYPOINT ["/app/k7s-web"]
CMD ["--addr", "0.0.0.0:8080", "--static", "/app/dist", "--no-tray", "--no-open"]
