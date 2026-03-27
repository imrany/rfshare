// Run: cargo run --release -- 0.0.0.0:9000
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH, Instant};

type WaitMap = Arc<Mutex<HashMap<String, (TcpStream, Instant)>>>;

// ─── Stats ────────────────────────────────────────────────────────────────────
#[derive(Default)]
struct Stats {
    total_connections: u64,
    total_pairings:    u64,
    total_bytes_piped: u64,
    active_pipes:      u32,
}

type SharedStats = Arc<Mutex<Stats>>;

// ─── Logging ──────────────────────────────────────────────────────────────────
fn now_str() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let s  = secs % 60;
    let m  = (secs / 60) % 60;
    let h  = (secs / 3600) % 24;
    let z  = secs / 86400 + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y   = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp  = (5 * doy + 2) / 153;
    let d   = doy - (153 * mp + 2) / 5 + 1;
    let mo  = if mp < 10 { mp + 3 } else { mp - 9 };
    let yr  = if mo <= 2 { y + 1 } else { y };
    format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC", yr, mo, d, h, m, s)
}

macro_rules! log {
    ($lvl:expr, $($arg:tt)*) => {
        println!("[{}] [{}] {}", now_str(), $lvl, format!($($arg)*))
    };
}
macro_rules! info  { ($($a:tt)*) => { log!("INFO ", $($a)*) } }
macro_rules! warn  { ($($a:tt)*) => { log!("WARN ", $($a)*) } }
macro_rules! error { ($($a:tt)*) => { log!("ERROR", $($a)*) } }

// ─── Bidirectional pipe ───────────────────────────────────────────────────────
fn pipe(
    mut a: TcpStream,
    mut b: TcpStream,
    sender_addr:   String,
    receiver_addr: String,
    code:          String,
    stats:         SharedStats,
) {
    { let mut s = stats.lock().unwrap(); s.active_pipes += 1; }
    info!("PIPE_START  code={}  sender={}  receiver={}", code, sender_addr, receiver_addr);

    let mut a2 = match a.try_clone() {
        Ok(s) => s,
        Err(e) => { error!("PIPE_CLONE_FAIL  code={}  err={}", code, e); return; }
    };
    let mut b2 = match b.try_clone() {
        Ok(s) => s,
        Err(e) => { error!("PIPE_CLONE_FAIL  code={}  err={}", code, e); return; }
    };

    // sender → receiver
    {
        let code2  = code.clone();
        let stats2 = Arc::clone(&stats);
        thread::spawn(move || {
            match std::io::copy(&mut a, &mut b2) {
                Ok(n)  => {
                    stats2.lock().unwrap().total_bytes_piped += n;
                    info!("PIPE_HALF  code={}  dir=sender->receiver  bytes={}", code2, n);
                }
                Err(e) => warn!("PIPE_ERR  code={}  dir=sender->receiver  err={}", code2, e),
            }
            b2.shutdown(std::net::Shutdown::Write).ok();
        });
    }

    // receiver → sender
    {
        let code3  = code.clone();
        let stats3 = Arc::clone(&stats);
        thread::spawn(move || {
            match std::io::copy(&mut b, &mut a2) {
                Ok(n)  => {
                    let mut s = stats3.lock().unwrap();
                    s.total_bytes_piped += n;
                    s.active_pipes = s.active_pipes.saturating_sub(1);
                    info!("PIPE_DONE  code={}  dir=receiver->sender  bytes={}", code3, n);
                }
                Err(e) => {
                    stats3.lock().unwrap().active_pipes = stats3.lock().unwrap().active_pipes.saturating_sub(1);
                    warn!("PIPE_ERR  code={}  dir=receiver->sender  err={}", code3, e);
                }
            }
            a2.shutdown(std::net::Shutdown::Write).ok();
        });
    }
}

// ─── Handle HTTP request ────────────────────────────────────────────────────────
fn handle_http_request(mut stream: TcpStream, peer: &str) -> Option<String> {
    let mut reader = BufReader::new(stream.try_clone().ok()?);
    let mut first_line = String::new();

    match reader.read_line(&mut first_line) {
        Ok(0) => return None,
        Ok(_) => {
            info!("HTTP request from {}: {}", peer, first_line.trim());

            // Parse the path to extract code
            let parts: Vec<&str> = first_line.split_whitespace().collect();
            if parts.len() >= 2 {
                let path = parts[1];

                // Handle receiver endpoint
                if path.starts_with("/receiver/") {
                    let code = path.strip_prefix("/receiver/").unwrap_or("");
                    if !code.is_empty() {
                        info!("Receiver request for code: {}", code);
                        // Read and discard remaining headers
                        let mut line = String::new();
                        while let Ok(len) = reader.read_line(&mut line) {
                            if len == 0 || line == "\r\n" || line == "\n" {
                                break;
                            }
                            line.clear();
                        }

                        // Send HTTP response
                        let response = format!(
                            "HTTP/1.1 200 OK\r\n\
                             Content-Type: text/plain\r\n\
                             Connection: keep-alive\r\n\
                             Content-Length: {}\r\n\
                             \r\n\
                             RECEIVER {}\r\n",
                            format!("RECEIVER {}", code).len(),
                            code
                        );
                        let _ = stream.write_all(response.as_bytes());
                        let _ = stream.flush();
                        return Some(format!("RECEIVER {}", code));
                    }
                }
                // Handle sender endpoint
                else if path.starts_with("/sender/") {
                    let code = path.strip_prefix("/sender/").unwrap_or("");
                    if !code.is_empty() {
                        info!("Sender request for code: {}", code);
                        // Read and discard remaining headers
                        let mut line = String::new();
                        while let Ok(len) = reader.read_line(&mut line) {
                            if len == 0 || line == "\r\n" || line == "\n" {
                                break;
                            }
                            line.clear();
                        }

                        // Send HTTP response
                        let response = format!(
                            "HTTP/1.1 200 OK\r\n\
                             Content-Type: text/plain\r\n\
                             Connection: keep-alive\r\n\
                             Content-Length: {}\r\n\
                             \r\n\
                             SENDER {}\r\n",
                            format!("SENDER {}", code).len(),
                            code
                        );
                        let _ = stream.write_all(response.as_bytes());
                        let _ = stream.flush();
                        return Some(format!("SENDER {}", code));
                    }
                }
            }
        }
        Err(e) => {
            warn!("Error reading HTTP request: {}", e);
        }
    }
    None
}

// ─── Handle raw TCP command ────────────────────────────────────────────────────
fn handle_raw_command(stream: TcpStream, peer: &str) -> Option<String> {
    let mut reader = BufReader::new(stream.try_clone().ok()?);
    let mut line = String::new();
    match reader.read_line(&mut line) {
        Ok(0) => None,
        Ok(_) => Some(line.trim().to_string()),
        Err(e) => {
            warn!("READ_ERR  peer={}  err={}", peer, e);
            None
        }
    }
}

// ─── Connection handler ───────────────────────────────────────────────────────
fn handle(stream: TcpStream, waiting: WaitMap, stats: SharedStats) {
    let peer = stream.peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    { stats.lock().unwrap().total_connections += 1; }

    stream.set_read_timeout(Some(std::time::Duration::from_secs(130))).ok();

    // Peek to see if it's HTTP
    let mut peek_buf = [0u8; 4];
    let command = match stream.peek(&mut peek_buf) {
        Ok(n) if n > 0 => {
            // Check if it's HTTP (starts with G, P, H)
            if peek_buf[0] == b'G' || peek_buf[0] == b'P' || peek_buf[0] == b'H' {
                handle_http_request(stream.try_clone().unwrap(), &peer)
            } else {
                handle_raw_command(stream.try_clone().unwrap(), &peer)
            }
        }
        _ => None,
    };

    match command {
        Some(cmd) => process_command(stream, peer, cmd, waiting, stats),
        None => {
            warn!("No valid command from {}", peer);
        }
    }
}

fn process_command(
    mut stream: TcpStream,
    peer: String,
    line: String,
    waiting: WaitMap,
    stats: SharedStats,
) {
    // ── RECEIVER <code> ───────────────────────────────────────────────────
    if let Some(code) = line.strip_prefix("RECEIVER ") {
        let code = code.trim().to_string();
        if code.is_empty() {
            warn!("BAD_CODE  peer={}  role=receiver", peer);
            let _ = writeln!(stream, "BAD_REQUEST");
            return;
        }
        info!("RECEIVER_WAITING  peer={}  code={}", peer, code);

        // If a stale entry exists with the same code, log it
        if waiting.lock().unwrap().contains_key(&code) {
            warn!("CODE_COLLISION  code={}  new_peer={}  (replacing stale)", code, peer);
        }
        waiting.lock().unwrap().insert(code, (stream, Instant::now()));

    // ── SENDER <code> ─────────────────────────────────────────────────────
    } else if let Some(code) = line.strip_prefix("SENDER ") {
        let code = code.trim().to_string();
        if code.is_empty() {
            warn!("BAD_CODE  peer={}  role=sender", peer);
            let _ = writeln!(stream, "BAD_REQUEST");
            return;
        }
        info!("SENDER_CONNECTING  peer={}  code={}", peer, code);

        let entry = waiting.lock().unwrap().remove(&code);
        match entry {
            Some((mut recv_stream, registered_at)) => {
                let wait_ms   = registered_at.elapsed().as_millis();
                let recv_addr = recv_stream.peer_addr()
                    .map(|a| a.to_string()).unwrap_or_default();
                info!("PAIRING  code={}  sender={}  receiver={}  wait_ms={}",
                    code, peer, recv_addr, wait_ms);

                // Notify receiver: "PAIRED <sender_ip>"
                if let Err(e) = writeln!(recv_stream, "PAIRED {}", peer) {
                    error!("NOTIFY_RECEIVER_FAIL  code={}  err={}", code, e);
                    let _ = writeln!(stream, "NOT_FOUND");
                    return;
                }
                recv_stream.flush().ok();

                // Notify sender: "PAIRED receiver"
                if let Err(e) = writeln!(stream, "PAIRED receiver") {
                    error!("NOTIFY_SENDER_FAIL  code={}  err={}", code, e);
                    return;
                }
                stream.flush().ok();

                stats.lock().unwrap().total_pairings += 1;
                pipe(stream, recv_stream, peer, recv_addr, code, stats);
            }
            None => {
                warn!("CODE_NOT_FOUND  code={}  peer={}", code, peer);
                let _ = writeln!(stream, "NOT_FOUND");
            }
        }

    // ── Unknown ───────────────────────────────────────────────────────────
    } else {
        warn!("UNKNOWN_CMD  peer={}  line={:?}", peer, &line[..line.len().min(80)]);
        let _ = writeln!(stream, "BAD_REQUEST");
    }
}

// ─── Main ─────────────────────────────────────────────────────────────────────
fn main() {
    let addr     = std::env::args().nth(1).unwrap_or_else(|| "0.0.0.0:9000".into());
    let listener = TcpListener::bind(&addr).expect("Cannot bind");
    info!("Version={}", env!("CARGO_PKG_VERSION"));
    info!("RELAY_START  addr={}", addr);

    let waiting: WaitMap    = Arc::new(Mutex::new(HashMap::new()));
    let stats:   SharedStats = Arc::new(Mutex::new(Stats::default()));

    // ── Expiry + stats thread ─────────────────────────────────────────────
    {
        let w = Arc::clone(&waiting);
        let s = Arc::clone(&stats);
        thread::spawn(move || loop {
            thread::sleep(std::time::Duration::from_secs(300));

            // Expire sessions older than 5 minutes
            let mut map    = w.lock().unwrap();
            let before     = map.len();
            map.retain(|code, (_, ts)| {
                let keep = ts.elapsed().as_secs() < 300;
                if !keep { info!("SESSION_EXPIRED  code={}", code); }
                keep
            });
            let expired = before - map.len();
            let waiting_now = map.len();
            drop(map);

            // Print periodic stats
            let st = s.lock().unwrap();
            info!(
                "STATS  connections={}  pairings={}  bytes_piped={}  \
                 active_pipes={}  waiting_receivers={}  expired={}",
                st.total_connections, st.total_pairings,
                format_bytes(st.total_bytes_piped),
                st.active_pipes, waiting_now, expired
            );
        });
    }

    // ── Accept loop ───────────────────────────────────────────────────────
    for stream in listener.incoming().flatten() {
        let w = Arc::clone(&waiting);
        let s = Arc::clone(&stats);
        thread::spawn(move || handle(stream, w, s));
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────
fn format_bytes(b: u64) -> String {
    const U: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut v = b as f64;
    let mut i = 0;
    while v >= 1024.0 && i < U.len() - 1 { v /= 1024.0; i += 1; }
    if i == 0 { format!("{} B", b) } else { format!("{:.1} {}", v, U[i]) }
}
