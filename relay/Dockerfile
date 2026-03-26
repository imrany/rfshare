# ── Stage 1: build ────────────────────────────────────────────────────────────
# Build context must be the repo root so the workspace Cargo.toml is available.
# The relay crate lives at ./relay/  (source at ./relay/src/).
FROM rust:1.94-bookworm AS builder

WORKDIR /build

# ── Dependency-cache layer ────────────────────────────────────────────────────
# Copy all manifests first so Docker can cache the dep-download layer
# independently of source changes.
COPY Cargo.toml Cargo.lock ./
COPY relay/Cargo.toml ./relay/Cargo.toml

# Stub the crate source so `cargo build` resolves and compiles all deps
# without the real source being present yet.
# We do NOT use -p here: let Cargo discover the package name from the manifest
# so this never breaks if the crate is renamed.
RUN mkdir -p relay/src \
    && echo 'fn main() {}' > relay/src/main.rs \
    && cargo build --release --manifest-path relay/Cargo.toml \
    && rm -rf relay/src

# ── Real build ────────────────────────────────────────────────────────────────
COPY relay/src ./relay/src

# Touch main.rs so Cargo detects the source has changed
RUN touch relay/src/main.rs \
    && cargo build --release --manifest-path relay/Cargo.toml

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
