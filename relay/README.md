# Remote Sharing via Relay Tunnel — No Port Forwarding Needed

All changes to `src/main.rs` plus a new `relay/src/main.rs` for the server.

---

## Architecture

```
┌─────────────┐                    ┌─────────────┐                    ┌─────────────┐
│   Sender    │                    │    Relay    │                    │  Receiver   │
│  (Client)   │                    │   Server    │                    │  (Client)   │
└─────────────┘                    └─────────────┘                    └─────────────┘
      │                                   │                                   │
      │                                   │ 1. Receiver: "Go Online"          │
      │                                   │<──────────────────────────────────│
      │                                   │    GET /receiver/ABC123           │
      │                                   │                                   │
      │                                   │ 2. Returns share code: ABC123     │
      │                                   │──────────────────────────────────>│
      │                                   │                                   │
      │ 3. Sender: Enter code ABC123      │                                   │
      │──────────────────────────────────>│                                   │
      │    GET /sender/ABC123             │                                   │
      │                                   │                                   │
      │                                   │ 4. Pair connections               │
      │                                   │                                   │
      │ 5. Bidirectional encrypted pipe   │                                   │
      │<════════════════════════════════════════════════════════════════════>│
      │                                   │                                   │
```

- Both sides connect **outbound** on port 443 (or 9000) — no port forwarding
- Relay just pipes bytes between the two sockets — never sees plaintext
- Session code is `XXXX-XXXX` (8 random chars), ephemeral, single-use
- Receiver clicks "Go Online" → gets a code → shares it with sender
- Sender enters code → connect → relay pairs them → transfer proceeds normally

A minimal Rust relay server you can run on any VPS.

Deploy with:
```bash
# On your VPS (e.g. relay.rfshare.dev)
git clone https://github.com/imrany/rfshare
cd rfshare/relay
cargo build --release
# Run on port 443 for firewall friendliness, or 9000
sudo ./target/release/relay 0.0.0.0:443
``` 

Using Docker
```bash
docker pull ghcr.io/imrany/rfshare-relay:latest

# Run the relay server in a Docker container
# Expose port 443 (for firewall friendliness) or 9000
# The Docker image listens on port 9000 internally
docker run -d --restart unless-stopped -p 443:9000 --name rfshare-relay ghcr.io/imrany/rfshare-relay:latest

# To run on port 9000 instead:
# docker run -d --restart unless-stopped -p 9000:9000 --name rfshare-relay ghcr.io/imrany/rfshare-relay:latest

# To stop the container later:
# docker stop rfshare-relay
```

**Changed constant:** `RELAY_HOST` and `RELAY_PORT` — update these to match your deployed relay server before shipping

## Test with curl
Replace `example.com` with real domain name.

```bash
# Test receiver endpoint
curl -v https://relay.example.com/receiver/TEST123

# Should return:
# RECEIVER TEST123

# Test sender endpoint  
curl -v https://relay.example.com/sender/TEST123

# Should return:
# SENDER TEST123
```
