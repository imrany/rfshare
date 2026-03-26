# ── Stage 1: build ────────────────────────────────────────────────────────────
# Use 1.94 or 'rust:latest'
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

# Locate the produced binary regardless of its name and copy it to a fixed path
RUN BIN=$(cargo metadata --manifest-path relay/Cargo.toml --no-deps --format-version 1 \
          | grep -o '"name":"[^"]*"' | head -1 | cut -d'"' -f4) \
    && cp target/release/"$BIN" target/release/relay-server

# ── Stage 2: minimal runtime image ───────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Run as a dedicated non-root user
RUN useradd --system --no-create-home --shell /usr/sbin/nologin relay

COPY --from=builder /build/target/release/relay-server /usr/local/bin/relay-server

RUN chmod +x /usr/local/bin/relay-server

USER relay

# Port the relay listens on (must match RELAY_PORT in the rfshare client)
EXPOSE 9000

ENTRYPOINT ["relay-server"]
CMD ["0.0.0.0:9000"]
