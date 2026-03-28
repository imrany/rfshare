// Run: cargo run --release -- 0.0.0.0:9000
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH, Instant, Duration};

type WaitMap = Arc<Mutex<HashMap<String, (TcpStream, Instant)>>>;
type SharedStats = Arc<Mutex<Stats>>;

#[derive(Default)]
struct Stats {
    total_connections: u64,
    total_pairings:    u64,
    total_bytes_piped: u64,
    active_pipes:      u32,
}

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
            let _ = b2.shutdown(std::net::Shutdown::Write);
            // Drop original streams to close cleanly
            drop(a);
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
                    let mut s = stats3.lock().unwrap();
                    s.active_pipes = s.active_pipes.saturating_sub(1);
                    warn!("PIPE_ERR  code={}  dir=receiver->sender  err={}", code3, e);
                }
            }
            let _ = a2.shutdown(std::net::Shutdown::Write);
            // Drop original streams to close cleanly
            drop(b);
        });
    }
}

fn handle_http_request(mut stream: TcpStream, peer: &str) -> Option<String> {
    let mut reader = BufReader::new(stream.try_clone().ok()?);
    let mut first_line = String::new();

    match reader.read_line(&mut first_line) {
        Ok(0) => return None,
        Ok(_) => {
            info!("HTTP request from {}: {}", peer, first_line.trim());

            let parts: Vec<&str> = first_line.trim().split_whitespace().collect();
            if parts.len() >= 2 {
                let path = parts[1];

                if path.starts_with("/receiver/") {
                    let code = path.strip_prefix("/receiver/").unwrap_or("");
                    if !code.is_empty() {
                        info!("Receiver request for code: {}", code);
                        // Read and discard remaining headers - FIXED
                        let mut line = String::new();
                        loop {
                            line.clear();
                            if reader.read_line(&mut line).map_or(true, |len| len == 0 || line.trim().is_empty()) {
                                break;
                            }
                        }

                        let response = format!(
r#"HTTP/1.1 200 OK
Content-Type: text/plain
Connection: keep-alive
Content-Length: {}

RECEIVER {}"#,
                            format!("RECEIVER {}", code).len(),
                            code
                        );
                        let _ = stream.write_all(response.as_bytes());
                        let _ = stream.flush();
                        return Some(format!("RECEIVER {}", code));
                    }
                }
                else if path.starts_with("/sender/") {
                    let code = path.strip_prefix("/sender/").unwrap_or("");
                    if !code.is_empty() {
                        info!("Sender request for code: {}", code);
                        // Read and discard remaining headers - FIXED
                        let mut line = String::new();
                        loop {
                            line.clear();
                            if reader.read_line(&mut line).map_or(true, |len| len == 0 || line.trim().is_empty()) {
                                break;
                            }
                        }

                        let response = format!(
r#"HTTP/1.1 200 OK
Content-Type: text/plain
Connection: keep-alive
Content-Length: {}

SENDER {}"#,
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

fn handle(stream: TcpStream, waiting: WaitMap, stats: SharedStats) {
    let peer = stream.peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    { stats.lock().unwrap().total_connections += 1; }

    stream.set_read_timeout(Some(Duration::from_secs(130))).ok();

    // FIXED: Better HTTP detection
    let mut peek_buf = [0u8; 8];
    let command = match stream.peek(&mut peek_buf) {
        Ok(n) if n > 0 => {
            // Check for HTTP methods more comprehensively
            if let Ok(s) = std::str::from_utf8(&peek_buf[..n.min(7)]) {
                if s.starts_with("GET ") || s.starts_with("POST ") || s.starts_with("HEAD ") ||
                   s.starts_with("PUT ") || s.starts_with("OPT ") || s.starts_with("DEL ") {
                    handle_http_request(stream.try_clone().unwrap(), &peer)
                } else {
                    handle_raw_command(stream.try_clone().unwrap(), &peer)
                }
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
    if let Some(code) = line.strip_prefix("RECEIVER ") {
        let code = code.trim().to_string();
        if code.is_empty() {
            warn!("BAD_CODE  peer={}  role=receiver", peer);
            let _ = writeln!(stream, "BAD_REQUEST");
            return;
        }
        info!("RECEIVER_WAITING  peer={}  code={}", peer, code);

        if waiting.lock().unwrap().contains_key(&code) {
            warn!("CODE_COLLISION  code={}  new_peer={}  (replacing stale)", code, peer);
        }
        waiting.lock().unwrap().insert(code, (stream, Instant::now()));

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

                if let Err(e) = writeln!(recv_stream, "PAIRED {}", peer) {
                    error!("NOTIFY_RECEIVER_FAIL  code={}  err={}", code, e);
                    let _ = writeln!(stream, "NOT_FOUND");
                    return;
                }
                recv_stream.flush().ok();

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

    } else {
        warn!("UNKNOWN_CMD  peer={}  line={:?}", peer, &line[..line.len().min(80)]);
        let _ = writeln!(stream, "BAD_REQUEST");
    }
}

fn format_bytes(b: u64) -> String {
    const U: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut v = b as f64;
    let mut i = 0;
    while v >= 1024.0 && i < U.len() - 1 { v /= 1024.0; i += 1; }
    if i == 0 { format!("{} B", b) } else { format!("{:.1} {}", v, U[i]) }
}

fn main() {
    let addr     = std::env::args().nth(1).unwrap_or_else(|| "0.0.0.0:9000".into());
    let listener = TcpListener::bind(&addr).expect("Cannot bind");
    info!("Version={}", env!("CARGO_PKG_VERSION"));
    info!("RELAY_START  addr={}", addr);

    let waiting: WaitMap    = Arc::new(Mutex::new(HashMap::new()));
    let stats:   SharedStats = Arc::new(Mutex::new(Stats::default()));

    // FIXED: Better expiry with minimal lock contention
    {
        let w = Arc::clone(&waiting);
        let s = Arc::clone(&stats);
        thread::spawn(move || loop {
            thread::sleep(Duration::from_secs(300));

            let expired_codes: Vec<String>;
            {
                let mut map = w.lock().unwrap();
                let _before = map.len();
                let keys: Vec<String> = map.keys().cloned().collect();
                expired_codes = keys.into_iter()
                    .filter(|code| {
                        if let Some((_, ts)) = map.get(code) {
                            let elapsed = ts.elapsed().as_secs();
                            if elapsed >= 300 {
                                info!("SESSION_EXPIRED  code={}", code);
                                true
                            } else {
                                false
                            }
                        } else {
                            false
                        }
                    })
                    .collect();
                for code in &expired_codes {
                    map.remove(code);
                }
            }

            let waiting_now = w.lock().unwrap().len();
            let st = s.lock().unwrap();
            info!(
                "STATS  connections={}  pairings={}  bytes_piped={}  \
                 active_pipes={}  waiting_receivers={}  expired={}",
                st.total_connections, st.total_pairings,
                format_bytes(st.total_bytes_piped),
                st.active_pipes, waiting_now, expired_codes.len()
            );
        });
    }

    for stream in listener.incoming().flatten() {
        let w = Arc::clone(&waiting);
        let s = Arc::clone(&stats);
        thread::spawn(move || handle(stream, w, s));
    }
}
