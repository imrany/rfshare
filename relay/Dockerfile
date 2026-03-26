# ── Stage 1: build ────────────────────────────────────────────────────────────
# Use 1.94 or 'rust:latest'
FROM rust:1.94-bookworm AS builder

WORKDIR /build

# ── Dependency-cache layer ────────────────────────────────────────────────────
# Copy workspace + crate manifests first.
# Docker will reuse this layer as long as Cargo.toml / Cargo.lock don't change.
COPY Cargo.toml Cargo.lock ./
COPY relay/Cargo.toml ./relay/Cargo.toml

# Stub the crate source so `cargo build` can download and compile all deps
# without the real source code being present yet.
RUN mkdir -p relay/src \
    && echo 'fn main() {}' > relay/src/main.rs \
    && cargo build --release -p rfshare-relay \
    && rm -rf relay/src

# ── Real build ────────────────────────────────────────────────────────────────
COPY relay/src ./relay/src

# Force Cargo to recompile the crate (deps are already cached above)
RUN touch relay/src/main.rs \
    && cargo build --release -p rfshare-relay

# ── Stage 2: minimal runtime image ───────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Run as a dedicated non-root user
RUN useradd --system --no-create-home --shell /usr/sbin/nologin relay

COPY --from=builder /build/target/release/rfshare-relay /usr/local/bin/rfshare-relay

RUN chmod +x /usr/local/bin/rfshare-relay

USER relay

# Port the relay listens on (must match RELAY_PORT in the rfshare client)
EXPOSE 9000

ENTRYPOINT ["rfshare-relay"]
CMD ["0.0.0.0:9000"]
