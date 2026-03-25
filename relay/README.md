# Remote Sharing via Relay Tunnel — No Port Forwarding Needed

All changes to `src/main.rs` plus a new `relay/src/main.rs` for the server.

---

## Architecture

```
Sender App                  Relay Server              Receiver App
    |                           |                           |
    |-- TCP connect ----------->|                           |
    |-- "SENDER <code>\n" ----->|                           |
    |                           |<-- TCP connect -----------|
    |                           |<-- "RECEIVER <code>\n" --|
    |                           |-- "PAIRED\n" ----------->|
    |<-- "PAIRED\n" ------------|                           |
    |<====== proxied E2E encrypted rfshare protocol ======>|
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

**Changed constant:** `RELAY_HOST` and `RELAY_PORT` — update these to match your deployed relay server before shipping
