# ── Stage 1: build ────────────────────────────────────────────────────────────
FROM rust:1.82-slim AS builder

WORKDIR /build

# Cache dependencies before copying source
COPY Cargo.toml Cargo.lock ./
# Create a dummy main so `cargo build` can cache deps
RUN mkdir src && echo 'fn main(){}' > src/main.rs \
    && cargo build --release \
    && rm -rf src

# Now copy the real source and do the final build
COPY src ./src
# Touch main.rs so Cargo knows it changed
RUN touch src/main.rs && cargo build --release

# ── Stage 2: minimal runtime image ────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create a non-root user for the relay process
RUN useradd --system --no-create-home --shell /usr/sbin/nologin relay

COPY --from=builder /build/target/release/rfshare-relay /usr/local/bin/rfshare-relay

RUN chmod +x /usr/local/bin/rfshare-relay

USER relay

# Port the relay listens on (matches RELAY_PORT in the client)
EXPOSE 9000

# Pass the bind address as a CLI argument; override via CMD in docker-compose
ENTRYPOINT ["rfshare-relay"]
CMD ["0.0.0.0:9000"]
