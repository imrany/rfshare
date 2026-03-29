// Hide the console window on Windows when the exe is double-clicked
#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, KeyInit, OsRng as AeadOsRng},
};
use egui::{Color32, CornerRadius, RichText, Sense, Stroke, Vec2};
use egui_material_icons::icons;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write, BufRead, BufReader};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};
use x25519_dalek::{EphemeralSecret, PublicKey};

mod tray;
use tray::{TrayEvent, TrayManager};

const DISCOVER_PORT: u16 = 44444;
const TRANSFER_PORT: u16 = 44445;
const DISCOVER_MSG: &[u8] = b"RFSHARE_DISCOVER";
const PEER_PREFIX: &str = "RFSHARE_PEER:";
const CHUNK_SIZE: usize = 256 * 1024;
const AES_NONCE_LEN: usize = 12;
const AES_TAG_LEN: usize = 16;
const X25519_KEY_LEN: usize = 32;
const MAGIC_OFFER: u8 = 0x01;
const MAGIC_RESUME: u8 = 0x02;
const MAGIC_DATA: u8 = 0x03;
const MAGIC_DONE: u8 = 0x04;
const MAGIC_SKIP: u8 = 0x05; // receiver already has this version — sender should skip
const SYNC_POLL_MS: u64 = 2_000; // how often the sync watcher polls each folder
const RELAY_HOST: &str = "relay.triple-ts-mediclinic.com";
const RELAY_PORT: u16  = 80;

//  network monitoring
struct NetworkMonitor {
    current_ip: Arc<Mutex<String>>,
    rx: std::sync::mpsc::Receiver<String>,
}

impl NetworkMonitor {
    fn new() -> (Self, std::sync::mpsc::Sender<String>) {
        let (tx, rx) = std::sync::mpsc::channel();
        let current_ip = Arc::new(Mutex::new(local_ip()));

        // Start network monitoring thread
        let current_ip_clone = current_ip.clone();
        let tx_clone = tx.clone();
        std::thread::spawn(move || {
            let mut last_ip = current_ip_clone.lock().unwrap().clone();
            loop {
                std::thread::sleep(std::time::Duration::from_secs(5));
                let new_ip = local_ip();
                if new_ip != last_ip {
                    last_ip = new_ip.clone();
                    *current_ip_clone.lock().unwrap() = new_ip;
                    let _ = tx_clone.send(last_ip.clone());
                }
            }
        });

        (Self { current_ip, rx }, tx)
    }

    fn has_changed(&mut self) -> Option<String> {
        self.rx.try_recv().ok()
    }
}

/// Generate a random 8-char session code like "A3F7-K2M9"
fn gen_session_code() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    // Use entropy from current time + stack address
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH).unwrap_or_default()
        .subsec_nanos();
    let chars: Vec<char> = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789".chars().collect();
    let mut n = seed as usize;
    let mut code = String::new();
    for i in 0..8 {
        if i == 4 { code.push('-'); }
        n = n.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        code.push(chars[(n >> 33) % chars.len()]);
    }
    code
}

fn relay_listen(tx: std::sync::mpsc::Sender<RelayMsg>) {
    let code = gen_session_code();
    let _ = tx.send(RelayMsg::Code(code.clone()));

    match std::net::TcpStream::connect((RELAY_HOST, RELAY_PORT)) {
        Ok(mut stream) => {
            let request = format!(
                "GET /receiver/{} HTTP/1.1\r\n\
                 Host: {}\r\n\
                 User-Agent: {}/{}\r\n\
                 Accept: */*\r\n\
                 Connection: keep-alive\r\n\
                 \r\n",
                code, RELAY_HOST, env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION")
            );

            if stream.write_all(request.as_bytes()).is_err() {
                let _ = tx.send(RelayMsg::Error("Write error".into()));
                return;
            }

            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut response = String::new();

            // Read HTTP status line
            if reader.read_line(&mut response).is_err() {
                let _ = tx.send(RelayMsg::Error("Read error".into()));
                return;
            }

            // Check if status is 200 OK
            if !response.contains("200 OK") {
                let _ = tx.send(RelayMsg::Error(format!("HTTP error: {}", response.trim())));
                return;
            }

            // Read headers until empty line
            let mut line = String::new();
            while let Ok(len) = reader.read_line(&mut line) {
                if len == 0 || line == "\r\n" || line == "\n" {
                    break;
                }
                line.clear();
            }

            // Read the body (our command)
            let mut body = String::new();
            if reader.read_line(&mut body).is_ok() {
                let body_trimmed = body.trim();
                if body_trimmed.starts_with("RECEIVER") {
                    let peer = "remote".to_string();
                    let _ = tx.send(RelayMsg::Paired { peer: peer.clone() });

                    // The connection is now established - keep it alive
                    let holder = Arc::new(Mutex::new(Some(stream)));
                    let _ = tx.send(RelayMsg::Ready(holder));
                } else {
                    let _ = tx.send(RelayMsg::Error(format!("Unexpected response: {}", body_trimmed)));
                }
            } else {
                let _ = tx.send(RelayMsg::Error("Empty response body".into()));
            }
        }
        Err(e) => {
            let _ = tx.send(RelayMsg::Error(format!("Cannot connect: {}", e)));
        }
    }
}

fn relay_connect(code: &str, tx: std::sync::mpsc::Sender<RelayMsg>) {
    let code = code.trim();
    match std::net::TcpStream::connect((RELAY_HOST, RELAY_PORT)) {
        Ok(mut stream) => {
            let request = format!(
                "GET /sender/{} HTTP/1.1\r\n\
                 Host: {}\r\n\
                 User-Agent: {}/{}\r\n\
                 Accept: */*\r\n\
                 Connection: keep-alive\r\n\
                 \r\n",
                code, RELAY_HOST, env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION")
            );

            if stream.write_all(request.as_bytes()).is_err() {
                let _ = tx.send(RelayMsg::Error("Write error".into()));
                return;
            }

            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut response = String::new();

            if reader.read_line(&mut response).is_err() {
                let _ = tx.send(RelayMsg::Error("Read error".into()));
                return;
            }

            // Check if status is 200 OK
            if !response.contains("200 OK") {
                let _ = tx.send(RelayMsg::Error(format!("HTTP error: {}", response.trim())));
                return;
            }

            // Read headers until empty line
            let mut line = String::new();
            while let Ok(len) = reader.read_line(&mut line) {
                if len == 0 || line == "\r\n" || line == "\n" {
                    break;
                }
                line.clear();
            }

            // Read the body
            let mut body = String::new();
            if reader.read_line(&mut body).is_ok() {
                let body_trimmed = body.trim();
                if body_trimmed.starts_with("SENDER") {
                    let peer = "remote".to_string();
                    let _ = tx.send(RelayMsg::Paired { peer: peer.clone() });

                    let holder = Arc::new(Mutex::new(Some(stream)));
                    let _ = tx.send(RelayMsg::Ready(holder));
                } else if body_trimmed == "NOT_FOUND" {
                    let _ = tx.send(RelayMsg::Error("Code not found or expired".into()));
                } else {
                    let _ = tx.send(RelayMsg::Error(format!("Unexpected response: {}", body_trimmed)));
                }
            } else {
                let _ = tx.send(RelayMsg::Error("Empty response body".into()));
            }
        }
        Err(e) => {
            let _ = tx.send(RelayMsg::Error(format!("Cannot connect: {}", e)));
        }
    }
}
// ─── Persistence helpers ─────────────────────────────────────────────────────
fn prefs_path() -> Option<PathBuf> {
    dirs::config_dir().map(|d| d.join(env!("CARGO_PKG_NAME")).join("prefs.json"))
}

/// Minimal JSON-free prefs. Format:
///   selected_peer_name=<name>
///   selected_peer_addr=<ip>
///   sync_folder_0=<path>
///   sync_folder_1=<path>
///   ...
fn save_prefs(
    peer_name: &str,
    peer_addr: &str,
    sync_map: &std::collections::HashMap<String, PathBuf>,
    save_dir: Option<&PathBuf>,
    notify_on_receive: bool,
    auto_open_folder: bool,
    manual_peers: &[(String,String)],
    auto_detect_theme: bool,
    dark_mode: Option<bool>,
) {
    let Some(path) = prefs_path() else { return };
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let mut out = String::new();
    out.push_str(&format!("selected_peer_name={}\n", peer_name));
    out.push_str(&format!("selected_peer_addr={}\n", peer_addr));
    // Format:  sync_device_<safe_addr>=<path>  (one folder per device)
    for (device_addr, folder) in sync_map {
        let safe = device_addr.replace('.', "_").replace(':', "_");
        out.push_str(&format!("sync_device_{}={}\n", safe, folder.display()));
    }
    for (i, (name, addr)) in manual_peers.iter().enumerate() {
        out.push_str(&format!("manual_peer_{}_name={}\n", i, name));
        out.push_str(&format!("manual_peer_{}_addr={}\n", i, addr));
    }
    if let Some(ref d) = save_dir {
        out.push_str(&format!("save_dir={}\n", d.display()));
    }
    out.push_str(&format!("notify_on_receive={}\n", notify_on_receive as u8));
    out.push_str(&format!("auto_open_folder={}\n", auto_open_folder as u8));
    // Add auto_detect_theme and dark_mode
    out.push_str(&format!("auto_detect_theme={}\n", auto_detect_theme as u8));
    if let Some(dark) = dark_mode {
        out.push_str(&format!("dark_mode={}\n", dark as u8));
    }
    let _ = fs::write(&path, out);
}
#[derive(Default)]
struct SavedPrefs {
    peer_name: String,
    peer_addr: String,
    // one sync folder per device: key = peer_addr string
    sync_map: std::collections::HashMap<String, PathBuf>,
    save_dir: Option<PathBuf>,
    notify_on_receive: bool,
    auto_open_folder: bool,
    manual_peers: Vec<(String, String)>,  // (name, addr_str)
    auto_detect_theme: bool,  // Whether to auto-detect system theme
    dark_mode: Option<bool>,   // User's manual theme choice (if auto-detect is off)
}

fn load_prefs() -> SavedPrefs {
    let mut prefs = SavedPrefs::default();
    let Some(path) = prefs_path() else { return prefs };
    let Ok(text) = fs::read_to_string(&path) else { return prefs };

    let mut mp_names: std::collections::HashMap<usize, String> = Default::default();
    let mut mp_addrs: std::collections::HashMap<usize, String> = Default::default();

    for line in text.lines() {
        if let Some(v) = line.strip_prefix("selected_peer_name=") { prefs.peer_name = v.to_string(); }
        if let Some(v) = line.strip_prefix("selected_peer_addr=") { prefs.peer_addr = v.to_string(); }
        if let Some(rest) = line.strip_prefix("sync_device_") {
            if let Some(eq) = rest.find('=') {
                let addr = rest[..eq].replace('_', ".");
                prefs.sync_map.insert(addr, PathBuf::from(&rest[eq + 1..]));
            }
        }
        if let Some(v) = line.strip_prefix("save_dir=")           { prefs.save_dir = Some(PathBuf::from(v)); }
        if let Some(v) = line.strip_prefix("notify_on_receive=")  { prefs.notify_on_receive = v == "1"; }
        if let Some(v) = line.strip_prefix("auto_open_folder=")   { prefs.auto_open_folder  = v == "1"; }
        if let Some(v) = line.strip_prefix("auto_detect_theme=") { prefs.auto_detect_theme = v == "1"; }
        if let Some(v) = line.strip_prefix("dark_mode=") { prefs.dark_mode = Some(v == "1"); }
        if let Some(rest) = line.strip_prefix("manual_peer_") {
            if let Some(idx_end) = rest.find('_') {
                if let Ok(idx) = rest[..idx_end].parse::<usize>() {
                    let suffix = &rest[idx_end + 1..];
                    if let Some(v) = suffix.strip_prefix("name=") { mp_names.insert(idx, v.to_string()); }
                    if let Some(v) = suffix.strip_prefix("addr=") { mp_addrs.insert(idx, v.to_string()); }
                }
            }
        }
    }

    let mut i = 0;
    while let (Some(name), Some(addr)) = (mp_names.remove(&i), mp_addrs.remove(&i)) {
        prefs.manual_peers.push((name, addr));
        i += 1;
    }
    prefs
}

fn toggle_switch(ui: &mut egui::Ui, p: &Pal, on: bool) -> egui::Response {
    let desired = Vec2::new(36.0, 20.0);
    let (rect, resp) = ui.allocate_exact_size(desired, Sense::click());

    let track_col = if on { p.accent } else { tint(p.text_faint, 80) };
    let knob_x = if on { rect.right() - 10.0 } else { rect.left() + 10.0 };

    ui.painter().rect_filled(rect, CornerRadius::same(10), track_col);
    ui.painter().circle_filled(
        egui::pos2(knob_x, rect.center().y),
        8.0,
        Color32::WHITE,
    );
    resp
}

/// Fetch the latest version from GitHub releases
fn fetch_latest_version() -> Option<String> {
    let url = format!(
        "https://api.github.com/repos/imrany/{}/releases/latest",
        env!("CARGO_PKG_NAME")
    );

    let user_agent = format!("{}/{}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));

    match minreq::get(url)
        .with_timeout(5)
        .with_header("User-Agent", user_agent)
        .send()
    {
        Ok(response) => {
            if response.status_code == 200 {
                if let Ok(body) = response.as_str() {
                    parse_version_from_json(body)
                } else {
                    None
                }
            } else {
                eprintln!("GitHub API returned status: {}", response.status_code);
                None
            }
        }
        Err(e) => {
            eprintln!("Failed to check for updates: {}", e);
            None
        }
    }
}

/// Parse version from GitHub API JSON response
fn parse_version_from_json(body: &str) -> Option<String> {
    // Look for "tag_name":"vX.X.X"
    if let Some(tag_start) = body.find("\"tag_name\":\"") {
        let start = tag_start + 11;
        if let Some(tag_end) = body[start..].find('"') {
            let tag = &body[start..start + tag_end];
            if tag.starts_with('v') {
                return Some(tag.to_string());
            }
        }
    }
    None
}

/// Compare two version strings and return true if latest > current
fn is_newer(latest: &str, current: &str) -> bool {
    fn parse(v: &str) -> Option<(u32, u32, u32)> {
        let v = v.trim_start_matches('v');
        let mut parts = v.splitn(3, '.');

        let major = parts.next()?.parse().ok()?;
        let minor = parts.next()?.parse().ok()?;
        let patch = parts.next()?.split('-').next()?.parse().ok()?;

        Some((major, minor, patch))
    }

    match (parse(latest), parse(current)) {
        (Some(l), Some(c)) => l > c,
        _ => false,
    }
}

fn device_row(
    ui: &mut egui::Ui,
    p: &Pal,
    peer: &Peer,
    selected: bool,
    is_recent: bool,
    is_remote: bool,
) -> egui::Response {
    let fill = if selected { tint(p.accent, 30) }
                else        { Color32::TRANSPARENT };
    let stroke = if selected { Stroke::new(1.0, tint(p.accent, 60)) }
                    else        { Stroke::NONE };

    let (rect, resp) = ui.allocate_exact_size(
        Vec2::new(ui.available_width(), 44.0), Sense::click());

    // Hover highlight
    let bg = if resp.hovered() && !selected { tint(p.accent, 12) } else { fill };
    ui.painter().rect(rect, CornerRadius::same(0), bg, stroke,
        egui::StrokeKind::Inside);

    let margin = 12.0f32;
    let content = rect.shrink2(Vec2::new(margin, 0.0));

    // ── Avatar circle ─────────────────────────────────────────────────────
    let av_c = egui::pos2(content.left() + 16.0, content.center().y);
    let av_col = if is_remote { p.accent2 }
                 else if is_recent { p.accent }
                 else { tint(p.accent, 180) };
    ui.painter().circle_filled(av_c, 14.0, tint(av_col, 30));
    ui.painter().text(av_c, egui::Align2::CENTER_CENTER,
        &peer.name.chars().next().unwrap_or('?').to_uppercase().to_string(),
        egui::FontId::proportional(14.0), av_col);

    // ── Name ─────────────────────────────────────────────────────
    let name_x = content.left() + 40.0;
    ui.painter().text(
        egui::pos2(name_x, content.center().y - 7.0),
        egui::Align2::LEFT_CENTER,
        &peer.name,
        egui::FontId::proportional(13.0),
        if selected { p.accent } else { p.text });

    // Subtitle: remote label or "Recently connected"
    let sub = if is_remote { "Remote device".to_string() }
              else if is_recent { "Recently connected".to_string() }
              else { String::new() };
    if !sub.is_empty() {
        ui.painter().text(
            egui::pos2(name_x, content.center().y + 8.0),
            egui::Align2::LEFT_CENTER,
            &sub,
            egui::FontId::proportional(10.0),
            p.text_faint);
    }

    // ── Right side columns ────────────────────────────────────────────────
    // Address
    let addr_str = peer.addr.to_string();
    ui.painter().text(
        egui::pos2(content.right() - 160.0, content.center().y),
        egui::Align2::LEFT_CENTER,
        &addr_str,
        egui::FontId::proportional(11.0), p.text_dim);

    // Latency
    let lat_str = match peer.latency {
        Some(ms) => format!("{} ms", ms),
        None     => "—".to_string(),
    };
    let lat_col = match peer.latency {
        Some(ms) if ms < 10  => p.success,
        Some(ms) if ms < 50  => p.warn,
        Some(_)              => p.danger,
        None                 => p.text_faint,
    };
    ui.painter().text(
        egui::pos2(content.right() - 75.0, content.center().y),
        egui::Align2::LEFT_CENTER,
        &lat_str,
        egui::FontId::proportional(11.0), lat_col);

    // Type badge
    let (type_lbl, type_col) = if is_remote {
        ("Remote", p.accent2)
    } else {
        ("Local", p.success)
    };
    let badge_rect = egui::Rect::from_center_size(
        egui::pos2(content.right() - 18.0, content.center().y),
        Vec2::new(40.0, 16.0));
    ui.painter().rect_filled(badge_rect, 4.0, tint(type_col, 25));
    ui.painter().text(badge_rect.center(), egui::Align2::CENTER_CENTER,
        type_lbl, egui::FontId::proportional(9.0), type_col);

    resp
}

// ─── License ─────────────────────────────────────────────────────────────────
#[derive(Clone, Debug, PartialEq)]
enum Plan {
    Free,
    Pro,
}

#[derive(Clone, Debug)]
struct License {
    plan: Plan,
    email: String,
    key: String,
}

impl License {
    fn config_path() -> Option<PathBuf> {
        dirs::config_dir().map(|d| d.join(env!("CARGO_PKG_NAME")).join("license"))
    }
    fn load() -> Self {
        let path = Self::config_path();
        if let Some(p) = &path {
            if let Ok(text) = fs::read_to_string(p) {
                let mut email = String::new();
                let mut key = String::new();
                for line in text.lines() {
                    if let Some(v) = line.strip_prefix("email=") {
                        email = v.trim().to_string();
                    }
                    if let Some(v) = line.strip_prefix("key=") {
                        key = v.trim().to_string();
                    }
                }
                if Self::validate_key(&key) {
                    return Self {
                        plan: Plan::Pro,
                        email,
                        key,
                    };
                }
            }
        }
        Self {
            plan: Plan::Free,
            email: String::new(),
            key: String::new(),
        }
    }
    fn save(&self) {
        if let Some(p) = Self::config_path() {
            if let Some(parent) = p.parent() {
                let _ = fs::create_dir_all(parent);
            }
            let _ = fs::write(&p, format!("email={}\nkey={}\n", self.email, self.key));
        }
    }

    fn validate_key(key: &str) -> bool {
        let parts: Vec<&str> = key.split('-').collect();
        if parts.len() != 5 || parts.iter().any(|p| p.len() != 5) {
            return false;
        }
        let body = parts[..4].join("-");
        let mut h = Sha256::new();
        h.update(body.as_bytes());
        h.update(b"rfshare-pro-salt");
        let hash = format!("{:X}", h.finalize());
        parts[4].to_uppercase() == hash[..5].to_uppercase()
    }

    fn is_pro(&self) -> bool {
        self.plan == Plan::Pro
    }
}

// ─── Palette ─────────────────────────────────────────────────────────────────
struct Pal {
    bg: Color32,
    surface: Color32,
    surface2: Color32,
    border: Color32,
    text: Color32,
    text_dim: Color32,
    text_faint: Color32,
    accent: Color32,
    accent2: Color32,
    success: Color32,
    danger: Color32,
    warn: Color32,
    pro: Color32,
}
impl Pal {
    fn dark() -> Self {
        Self {
            bg: Color32::from_rgb(10, 11, 16),
            surface: Color32::from_rgb(16, 17, 24),
            surface2: Color32::from_rgb(22, 24, 34),
            border: Color32::from_rgb(38, 42, 62),
            text: Color32::from_rgb(228, 230, 240),
            text_dim: Color32::from_rgb(130, 135, 165),
            text_faint: Color32::from_rgb(58, 62, 88),
            accent: Color32::from_rgb(88, 148, 255),
            accent2: Color32::from_rgb(140, 90, 255),
            success: Color32::from_rgb(52, 199, 120),
            danger: Color32::from_rgb(235, 75, 75),
            warn: Color32::from_rgb(240, 170, 50),
            pro: Color32::from_rgb(255, 195, 60),
        }
    }
    fn light() -> Self {
        Self {
            bg: Color32::from_rgb(245, 246, 252),
            surface: Color32::from_rgb(255, 255, 255),
            surface2: Color32::from_rgb(238, 240, 250),
            border: Color32::from_rgb(210, 214, 235),
            text: Color32::from_rgb(16, 18, 32),
            text_dim: Color32::from_rgb(100, 105, 135),
            text_faint: Color32::from_rgb(185, 190, 215),
            accent: Color32::from_rgb(50, 110, 230),
            accent2: Color32::from_rgb(100, 60, 220),
            success: Color32::from_rgb(32, 165, 90),
            danger: Color32::from_rgb(210, 50, 50),
            warn: Color32::from_rgb(190, 125, 20),
            pro: Color32::from_rgb(200, 140, 0),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
enum TransferType {
    Local,
    Remote,
}

// ─── History ─────────────────────────────────────────────────────────────────
#[derive(Clone, Debug)]
struct HistoryEntry {
    timestamp: u64,
    direction: TransferDir,
    file_name: String,
    file_size: u64,
    peer_name: String,
    success: bool,
    error: Option<String>,
    transfer_type: TransferType,
    file_path: Option<PathBuf>,
}
#[derive(Clone, Debug, PartialEq)]
enum TransferDir {
    Sent,
    Received,
}

impl HistoryEntry {
    fn time_display(&self) -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let diff = now.saturating_sub(self.timestamp);
        if diff < 60 {
            "just now".into()
        } else if diff < 3600 {
            format!("{} min ago", diff / 60)
        } else if diff < 86400 {
            format!("{} hr ago", diff / 3600)
        } else if diff < 604800 {
            format!("{} days ago", diff / 86400)
        } else {
            format!("{} wks ago", diff / 604800)
        }
    }
    fn file_exists(&self) -> bool {
        self.file_path.as_ref().map(|p| p.exists()).unwrap_or(false)
    }
}

fn history_path() -> Option<PathBuf> {
    dirs::config_dir().map(|d| d.join(env!("CARGO_PKG_NAME")).join("history.csv"))
}

fn load_history() -> Vec<HistoryEntry> {
    let Some(path) = history_path() else {
        return Vec::new();
    };
    let Ok(text) = fs::read_to_string(&path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for line in text.lines().skip(1) {
        let cols: Vec<&str> = line.splitn(9, ',').collect();
        if cols.len() < 8 {
            continue;
        }
        let ts = cols[0].parse::<u64>().unwrap_or(0);
        let dir = if cols[1] == "sent" {
            TransferDir::Sent
        } else {
            TransferDir::Received
        };
        // Handle both old and new format (with type field)
        let trans_type = if cols.len() >= 3 {
            if cols[2] == "remote" {
                TransferType::Remote
            } else {
                TransferType::Local
            }
        } else {
            TransferType::Local // Default for old entries
        };

        let name = if cols.len() >= 4 { cols[3].to_string() } else { cols[2].to_string() };
        let size = if cols.len() >= 5 { cols[4].parse::<u64>().unwrap_or(0) } else { cols[3].parse::<u64>().unwrap_or(0) };
        let peer = if cols.len() >= 6 { cols[5].to_string() } else { cols[4].to_string() };
        let ok = if cols.len() >= 7 { cols[6] == "1" } else { cols[5] == "1" };
        let err = if cols.len() >= 8 {
            if cols[7].is_empty() { None } else { Some(cols[7].to_string()) }
        } else {
            if cols[6].is_empty() { None } else { Some(cols[6].to_string()) }
        };
        let fpath = cols.get(8)
            .filter(|s| !s.is_empty())
            .map(|s| PathBuf::from(s));

        out.push(HistoryEntry {
            timestamp: ts,
            direction: dir,
            transfer_type: trans_type,
            file_name: name,
            file_size: size,
            peer_name: peer,
            success: ok,
            error: err,
            file_path: fpath,
        });
    }
    out.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
    out
}

fn append_history(entry: &HistoryEntry) {
    let Some(path) = history_path() else { return };
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let needs_header = !path.exists();
    if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).open(&path) {
        if needs_header {
            let _ = writeln!(f, "timestamp,direction,type,name,size,peer,ok,error,file_path");
        }
        let dir = if entry.direction == TransferDir::Sent {
            "sent"
        } else {
            "received"
        };
        let trans_type = if entry.transfer_type == TransferType::Local {
            "local"
        } else {
            "remote"
        };
        let err = entry.error.as_deref().unwrap_or("").replace(',', ";");
        let fpath = entry
            .file_path
            .as_ref()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default()
            .replace(',', ";");
        let ok = if entry.success { 1 } else { 0 };
        let _ = writeln!(
            f,
            "{},{},{},{},{},{},{},{},{}",
            entry.timestamp, dir, trans_type, entry.file_name, entry.file_size, entry.peer_name, ok, err, fpath
        );
    }
}

// ─── Folder sync ─────────────────────────────────────────────────────────────
#[derive(Clone, Debug)]
struct SyncJob {
    folder: PathBuf,
    peer_addr: std::net::IpAddr,
    peer_name: String,
    /// key = absolute path string, value = mtime (unix secs) at time of last successful send
    file_mtimes: std::collections::HashMap<String, u64>,
}

/// Outcome returned by send_file_sync
#[derive(Debug)]
enum SyncResult {
    Sent,
    Skipped,
}

enum SyncMsg {
    FileSent { name: String, path: String },
    FileError { name: String, error: String },
    FileFound { name: String },
    FileSkipped { name: String },
}

// ─── Transfer types ──────────────────────────────────────────────────────────
#[derive(Clone, Debug)]
struct QueueItem {
    path: PathBuf,
    name: String,
    size: u64,
    progress: Option<f32>,
    error: Option<String>,
}
impl QueueItem {
    fn new(path: PathBuf) -> Self {
        let name = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        let size = fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        Self {
            path,
            name,
            size,
            progress: None,
            error: None,
        }
    }
    fn is_done(&self) -> bool {
        self.progress == Some(1.0)
    }
    fn is_failed(&self) -> bool {
        self.error.is_some()
    }
    fn is_pending(&self) -> bool {
        self.progress.is_none() && self.error.is_none()
    }
    fn is_active(&self) -> bool {
        matches!(self.progress, Some(p) if p >= 0.0 && p < 1.0) && self.error.is_none()
    }
}

#[derive(Debug)]
enum QueueMsg {
    Progress { index: usize, progress: f32 },
    Done { index: usize },
    Failed { index: usize, error: String },
}

#[derive(Clone, Debug, PartialEq)]
enum PeerKind {
    Local,   // discovered via UDP broadcast
    Remote,  // manually added by IP/hostname
}

#[derive(Clone, Debug)]
struct Peer {
    name:    String,
    addr:    std::net::IpAddr,
    kind:    PeerKind,
    latency: Option<u32>,   // ms, from ping probe
}

#[derive(Clone, Debug, PartialEq)]
enum Tab {
    Scan,
    Send,
    History,
    Sync,
    Settings,
}

#[derive(Clone, Debug, PartialEq)]
enum ScanState {
    Idle,
    Scanning,
    Done,
}

#[derive(Clone, Debug, PartialEq)]
enum SettingsTab {
    Device,
    License,
    About,
    Preferences,
}

#[derive(Clone, Debug)]
struct ReceivedFile {
    name: String,
    size: u64,
    path: PathBuf,
    seen: bool,
    peer_name: String,
}

#[derive(Default)]
struct RecvState {
    files:             Vec<ReceivedFile>,
    error:             Option<String>,
    recv_bytes:        u64,
    recv_files:        u32,
    notify_on_receive: bool,
    auto_open_folder:  bool,
    save_dir:          Option<PathBuf>,
}

#[derive(Clone, Debug, PartialEq)]
enum ScanMode { Local, Remote }

#[derive(Clone, Debug, PartialEq)]
enum RelayState {
    Offline,
    Connecting,
    Online { code: String },
    Paired  { peer_name: String },
    Error   (String),
}

// ─── App ─────────────────────────────────────────────────────────────────────
pub struct App {
    peers: Vec<Peer>,
    scan_rx: Option<std::sync::mpsc::Receiver<Vec<Peer>>>,
    scan_state: ScanState,
    selected: Option<usize>,

    saved_peer_name: String,
    saved_peer_addr: String,

    queue: Vec<QueueItem>,
    queue_rx: Option<std::sync::mpsc::Receiver<QueueMsg>>,
    recv_state: Arc<Mutex<RecvState>>,

    history: Vec<HistoryEntry>,
    history_filter: String,

    sync_jobs: Vec<SyncJob>,
    sync_rx: Option<std::sync::mpsc::Receiver<SyncMsg>>,
    sync_active: bool,
    sync_log: Vec<String>,
    sync_map: std::collections::HashMap<String, PathBuf>,
    scan_filter: String,

    license: License,
    settings_tab: SettingsTab,
    license_key_buf: String,
    license_email_buf: String,
    license_msg: Option<(String, bool)>,

    tab: Tab,
    dark_mode: bool,
    scan_pulse: f32,
    show_upgrade: bool,
    version: String,

    this_hostname: String,
    this_ip: String,

    // ── User preferences ──────────────────────────────────────────────────
    save_dir: PathBuf,          // where received files are saved (default: ~/Downloads)
    notify_on_receive: bool,    // desktop notification on file received
    auto_open_folder: bool,     // open folder after receiving

    // ── Session metrics ───────────────────────────────────────────────────
    session_sent_bytes: u64,
    session_sent_files: u32,

    // ── Update checker ────────────────────────────────────────────────────
    update_available: Option<String>,
    update_rx: Option<std::sync::mpsc::Receiver<Option<String>>>,

    // Remote peer entry
    remote_ip_buf:   String,   // text field contents
    remote_name_buf: String,
    remote_msg:      Option<(String, bool)>,  // (message, is_error)

    // Persisted manual peers (survive restarts)
    manual_peers: Vec<Peer>,
    latency_rx: Option<std::sync::mpsc::Receiver<(std::net::IpAddr, u32)>>,
    scan_mode:  ScanMode,
    relay_state: RelayState,
    relay_rx:   Option<std::sync::mpsc::Receiver<RelayMsg>>,
    relay_code_input: String,   // sender: code entry field

    network_monitor: NetworkMonitor,
    network_monitor_sender: std::sync::mpsc::Sender<String>,
    is_online: bool,
    last_internet_check: std::time::Instant,
    relay_stream: Option<Arc<Mutex<Option<TcpStream>>>>,
    is_relay_mode: bool,
    relay_sync_map: std::collections::HashMap<String, PathBuf>,  // key = peer_addr string
    relay_sync_active: bool,
    relay_sync_jobs: Vec<SyncJob>,
    relay_sync_rx: Option<std::sync::mpsc::Receiver<SyncMsg>>,
    relay_sync_log: Vec<String>,
    auto_detect_theme: bool,

    minimize_to_tray: bool,
    window_visible: bool,
    tray: Option<TrayManager>,
}

enum RelayMsg {
    Code(String),
    Paired { peer: String },
    Ready(Arc<Mutex<Option<TcpStream>>>),
    Error(String),
}

impl Default for App {
    fn default() -> Self {
        let prefs = load_prefs();
        // Determine initial theme
        let initial_auto_detect = prefs.auto_detect_theme;
        let initial_dark_mode = if initial_auto_detect {
            detect_system_theme()
        } else {
            prefs.dark_mode.unwrap_or(true)
        };

        // Setup tray
        let tray = TrayManager::new(env!("CARGO_PKG_NAME")).ok();

        let (network_monitor, network_monitor_sender) = NetworkMonitor::new();
        let recv_state = Arc::new(Mutex::new(RecvState::default()));
        let save_dir = prefs.save_dir.clone().unwrap_or_else(|| {
            dirs::download_dir()
                .unwrap_or_else(|| dirs::home_dir().unwrap_or_else(|| PathBuf::from(".")))
        });
        let rs = Arc::clone(&recv_state);
        let sd = save_dir.clone();
        thread::spawn(move || receive_server(rs, sd));
        if let Ok(mut rs) = recv_state.lock() {
            rs.notify_on_receive = prefs.notify_on_receive;
            rs.auto_open_folder  = prefs.auto_open_folder;
            rs.save_dir          = prefs.save_dir.clone();
        }
        let license = License::load();
        Self {
            peers: Vec::new(),
            scan_rx: None,
            scan_state: ScanState::Idle,
            selected: None,
            saved_peer_name: prefs.peer_name,
            saved_peer_addr: prefs.peer_addr,
            queue: Vec::new(),
            queue_rx: None,
            recv_state,
            history: load_history(),
            history_filter: String::new(),
            sync_jobs: Vec::new(),
            sync_rx: None,
            sync_active: false,
            sync_log: Vec::new(),
            sync_map: prefs.sync_map,
            scan_filter: String::new(),
            license_key_buf: String::new(),
            license_email_buf: String::new(),
            license_msg: None,
            settings_tab: SettingsTab::Device,
            tab: Tab::Scan,
            auto_detect_theme: initial_auto_detect,
            dark_mode: initial_dark_mode,
            scan_pulse: 0.0,
            show_upgrade: false,
            version: format!("v{}", env!("CARGO_PKG_VERSION")),
            this_hostname: hostname(),
            this_ip: local_ip(),
            save_dir: prefs.save_dir.clone().unwrap_or_else(|| {
                dirs::download_dir()
                    .unwrap_or_else(|| dirs::home_dir().unwrap_or_else(|| PathBuf::from(".")))
            }),
            notify_on_receive: prefs.notify_on_receive,
            auto_open_folder: prefs.auto_open_folder,
            session_sent_bytes: 0,
            session_sent_files: 0,
            update_available: None,
            update_rx: None,
            license,
            remote_ip_buf:   String::new(),
            remote_name_buf: String::new(),
            remote_msg:      None,
            manual_peers: prefs.manual_peers.iter().filter_map(|(name, addr_str)| {
                addr_str.parse::<std::net::IpAddr>().ok().map(|addr| Peer {
                    name: name.clone(), addr,
                    kind: PeerKind::Remote, latency: None,
                })
            }).collect(),
            latency_rx: None,
            scan_mode:        ScanMode::Local,
            relay_state:      RelayState::Offline,
            relay_rx:         None,
            relay_code_input: String::new(),
            network_monitor,
            network_monitor_sender,
            is_online: false,
            last_internet_check: std::time::Instant::now(),
            relay_stream: None,
            is_relay_mode: false,
            relay_sync_map: std::collections::HashMap::new(),
            relay_sync_active: false,
            relay_sync_jobs: Vec::new(),
            relay_sync_rx: None,
            relay_sync_log: Vec::new(),
            minimize_to_tray: true,  // Default to minimize to tray
            window_visible: true,     // Window starts visible
            tray,
        }
    }
}

impl App {
    fn p(&self) -> Pal {
        if self.dark_mode {
            Pal::dark()
        } else {
            Pal::light()
        }
    }

    fn is_pro(&self) -> bool {
        self.license.is_pro()
    }

    fn check_internet_connection(&self) -> bool {
        // Try to connect to a reliable host
        std::net::TcpStream::connect_timeout(
            &("8.8.8.8:53").parse().unwrap(),
            std::time::Duration::from_secs(3),
        ).is_ok()
    }

    fn _try_auto_select(&mut self) {
        if self.selected.is_some() || self.saved_peer_addr.is_empty() {
            return;
        }
        for (i, peer) in self.peers.iter().enumerate() {
            if peer.addr.to_string() == self.saved_peer_addr {
                self.selected = Some(i);
                return;
            }
        }
    }

    fn selected_peer(&self) -> Option<&Peer> {
        self.selected.and_then(|i| self.peers.get(i))
    }

    fn persist_prefs(&self) {
        let (name, addr) = self.selected_peer()
            .map(|p| (p.name.as_str(), p.addr.to_string()))
            .unwrap_or((&self.saved_peer_name, self.saved_peer_addr.clone()));
        let manual: Vec<(String, String)> = self.manual_peers.iter()
            .map(|p| (p.name.clone(), p.addr.to_string()))
            .collect();

        // Create a combined sync map (local + remote)
        let mut all_sync = self.sync_map.clone();
        all_sync.extend(self.relay_sync_map.clone());

        save_prefs(name, &addr, &all_sync,
            Some(&self.save_dir), self.notify_on_receive,
            self.auto_open_folder, &manual,
            self.auto_detect_theme,
            Some(self.dark_mode),
        );
    }

    fn start_scan(&mut self) {
        self.peers.clear();
        self.selected = None;
        self.scan_state = ScanState::Scanning;
        let (tx, rx) = std::sync::mpsc::channel::<Vec<Peer>>();
        self.scan_rx = Some(rx);
        thread::spawn(move || {
            let mut found: Vec<Peer> = Vec::new();
            if let Ok(sock) = UdpSocket::bind("0.0.0.0:0") {
                let _ = sock.set_broadcast(true);
                let _ = sock.set_read_timeout(Some(std::time::Duration::from_millis(250)));
                for dest in [
                    "255.255.255.255",
                    "192.168.1.255",
                    "192.168.0.255",
                    "10.0.0.255",
                ] {
                    let _ = sock.send_to(DISCOVER_MSG, (dest, DISCOVER_PORT));
                }
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
                let mut buf = [0u8; 512];
                while std::time::Instant::now() < deadline {
                    if let Ok((n, addr)) = sock.recv_from(&mut buf) {
                        let msg = String::from_utf8_lossy(&buf[..n]);
                        if let Some(name) = msg.strip_prefix(PEER_PREFIX) {
                            let name = name.trim().to_string();
                            let ip = addr.ip();
                            if !found.iter().any(|p| p.addr == ip) {
                                found.push(Peer { name, addr: ip, kind: PeerKind::Local, latency: None });
                            }
                        }
                    }
                }
            }
            let _ = tx.send(found);
        });
    }

    fn add_files(&mut self, paths: Vec<PathBuf>) {
        for path in paths {
            if path.is_file() && !self.queue.iter().any(|q| q.path == path) {
                self.queue.push(QueueItem::new(path));
            }
        }
    }

    fn remove_queue_item(&mut self, idx: usize) {
        if idx < self.queue.len() {
            self.queue.remove(idx);
        }
    }

    fn clear_done(&mut self) {
        self.queue.retain(|q| !q.is_done() && !q.is_failed());
    }

    fn retry_failed(&mut self) {
        for item in &mut self.queue {
            if item.is_failed() {
                item.error = None;
                item.progress = None;
            }
        }
    }

    fn start_send_queue(&mut self) {
        let Some(peer) = self.selected.and_then(|i| self.peers.get(i)).cloned() else {
            return;
        };

        if self.queue.is_empty() {
            return;
        }

        // Check if we're in relay mode
        let use_relay = self.is_relay_mode && self.relay_stream.is_some();

        // Take the relay stream if in relay mode (only once)
        let relay_stream_opt = if use_relay {
            if let Some(stream_arc) = &self.relay_stream {
                if let Ok(mut guard) = stream_arc.lock() {
                    guard.take()
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };

        for item in &mut self.queue {
            if item.is_pending() {
                item.progress = Some(0.0);
            }
        }

        let items: Vec<(usize, PathBuf, String, u64)> = self
            .queue
            .iter()
            .enumerate()
            .filter(|(_, q)| q.is_active() || q.progress == Some(0.0))
            .map(|(i, q)| (i, q.path.clone(), q.name.clone(), q.size))
            .collect();

        let (tx, rx) = std::sync::mpsc::channel::<QueueMsg>();
        self.queue_rx = Some(rx);
        let peer_name = peer.name.clone();
        let use_relay_clone = use_relay;

        // Move relay_stream_opt into the thread - but need to handle multiple files
        // Since we have multiple files, we need to wrap the stream in Arc<Mutex> to share it
        // But we already took it from self.relay_stream, so we need to rewrap it

        // For multiple files, we need to wrap the stream in Arc<Mutex> to share
        let shared_stream = if let Some(stream) = relay_stream_opt {
            Some(Arc::new(Mutex::new(Some(stream))))
        } else {
            None
        };

        thread::spawn(move || {
            for (index, path, name, size) in items {
                let tx2 = tx.clone();
                let pn = peer_name.clone();
                let nm = name.clone();

                let result = if use_relay_clone {
                    if let Some(stream_arc) = &shared_stream {
                        if let Ok(mut guard) = stream_arc.lock() {
                            if let Some(mut stream) = guard.take() {
                                send_file_via_relay(&path, &name, size, &mut stream, move |p| {
                                    let _ = tx2.send(QueueMsg::Progress { index, progress: p });
                                })
                            } else {
                                Err("No relay stream available".into())
                            }
                        } else {
                            Err("Failed to lock relay stream".into())
                        }
                    } else {
                        Err("No relay stream available".into())
                    }
                } else {
                    // Use direct connection
                    send_file_resumable(&path, &name, size, peer.addr, move |p| {
                        let _ = tx2.send(QueueMsg::Progress { index, progress: p });
                    })
                };

                let ts = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();

                match result {
                    Ok(()) => {
                        append_history(&HistoryEntry {
                            timestamp: ts,
                            direction: TransferDir::Sent,
                            transfer_type: TransferType::Local,
                            file_name: nm,
                            file_size: size,
                            peer_name: pn,
                            success: true,
                            error: None,
                            file_path: Some(path.clone()),
                        });
                        let _ = tx.send(QueueMsg::Done { index });
                    }
                    Err(e) => {
                        append_history(&HistoryEntry {
                            timestamp: ts,
                            direction: TransferDir::Sent,
                            transfer_type: TransferType::Local,
                            file_name: nm,
                            file_size: size,
                            peer_name: pn,
                            success: false,
                            error: Some(e.clone()),
                            file_path: Some(path.clone()),
                        });
                        let _ = tx.send(QueueMsg::Failed { index, error: e });
                    }
                }
            }
        });
    }

    fn start_sync_watcher(&mut self) {
        if !self.is_pro() {
            self.show_upgrade = true;
            return;
        }
        if self.sync_jobs.is_empty() || self.sync_active {
            return;
        }

        self.sync_active = true;
        let jobs = self.sync_jobs.clone();
        let (tx, rx) = std::sync::mpsc::channel::<SyncMsg>();
        self.sync_rx = Some(rx);

        thread::spawn(move || {
            let mut job_mtimes: Vec<std::collections::HashMap<String, u64>> = jobs
                .iter()
                .map(|_| std::collections::HashMap::new())
                .collect();

            let mut last_scan = std::time::Instant::now();

            loop {
                // Throttle scanning to avoid CPU spikes
                if last_scan.elapsed() < std::time::Duration::from_millis(SYNC_POLL_MS) {
                    thread::sleep(std::time::Duration::from_millis(100));
                    continue;
                }
                last_scan = std::time::Instant::now();

                for (job_idx, job) in jobs.iter().enumerate() {
                    let Ok(entries) = fs::read_dir(&job.folder) else {
                        continue;
                    };

                    // Collect files to process
                    let mut files_to_send = Vec::new();

                    for entry in entries.flatten() {
                        let path = entry.path();
                        if !path.is_file() {
                            continue;
                        }

                        let key = path.to_string_lossy().to_string();
                        let current_mtime = fs::metadata(&path)
                            .and_then(|m| m.modified())
                            .map(|t| {
                                t.duration_since(std::time::UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_secs()
                            })
                            .unwrap_or(0);

                        if let Some(&last_sent_mtime) = job_mtimes[job_idx].get(&key) {
                            if last_sent_mtime >= current_mtime {
                                continue;
                            }
                        }

                        let name = path
                            .file_name()
                            .unwrap_or_default()
                            .to_string_lossy()
                            .to_string();
                        let size = fs::metadata(&path).map(|m| m.len()).unwrap_or(0);

                        files_to_send.push((path, key, name, size, current_mtime));
                    }

                    // Send files with a small delay between each
                    for (path, key, name, size, current_mtime) in files_to_send {
                        let _ = tx.send(SyncMsg::FileFound { name: name.clone() });

                        match send_file_sync(&path, &name, size, current_mtime, job.peer_addr) {
                            Ok(SyncResult::Sent) => {
                                job_mtimes[job_idx].insert(key.clone(), current_mtime);
                                let _ = tx.send(SyncMsg::FileSent { name, path: key });
                            }
                            Ok(SyncResult::Skipped) => {
                                job_mtimes[job_idx].insert(key, current_mtime);
                                let _ = tx.send(SyncMsg::FileSkipped { name });
                            }
                            Err(e) => {
                                let _ = tx.send(SyncMsg::FileError { name, error: e });
                            }
                        }

                        // Small delay between file sends
                        thread::sleep(std::time::Duration::from_millis(50));
                    }
                }
            }
        });
    }

    fn rebuild_sync_jobs(&mut self) {
        let Some(peer) = self.selected_peer().cloned() else {
            self.sync_jobs.clear();
            return;
        };
        let addr_key = peer.addr.to_string();
        if let Some(folder) = self.sync_map.get(&addr_key).cloned() {
            if folder.exists() {
                self.sync_jobs = vec![SyncJob {
                    folder,
                    peer_addr: peer.addr,
                    peer_name: peer.name.clone(),
                    file_mtimes: std::collections::HashMap::new(),
                }];
            } else {
                self.sync_jobs.clear();
            }
        } else {
            self.sync_jobs.clear();
        }
    }

    fn add_sync_folder(&mut self, folder: PathBuf) {
        if !self.is_pro() {
            self.show_upgrade = true;
            return;
        }
        let Some(peer) = self.selected_peer().cloned() else {
            return;
        };
        let addr_key = peer.addr.to_string();
        if self.sync_active {
            self.sync_rx = None;
            self.sync_active = false;
        }
        self.sync_map.insert(addr_key, folder);
        self.rebuild_sync_jobs();
        self.persist_prefs();
    }

    fn stop_sync(&mut self) {
        self.sync_rx = None;
        self.sync_active = false;
        self.sync_log.push("-- Watching stopped".to_string());
    }

    fn remove_sync_folder(&mut self) {
        if let Some(peer) = self.selected_peer().cloned() {
            if self.sync_active {
                self.sync_rx = None;
                self.sync_active = false;
            }
            self.sync_map.remove(&peer.addr.to_string());
            self.rebuild_sync_jobs();
            self.persist_prefs();
        }
    }

    fn selected_peer_available(&self) -> bool {
        self.selected.is_some()
    }

    fn poll(&mut self, ctx: &egui::Context) {
        // ── Tray events ───────────────────────────────────────────────────
        if let Some(ref tray) = self.tray {
            while let Some(event) = tray.try_recv() {
                match event {
                    tray::TrayEvent::ShowWindow => {
                        self.window_visible = true;
                        ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
                    }
                    tray::TrayEvent::Quit => {
                        std::process::exit(0);
                    }
                }
            }
        }

        // Use try_lock instead of lock to avoid blocking
        if let Ok(mut recv_state) = self.recv_state.try_lock() {
            // Process received files
            for file in recv_state.files.iter_mut() {
                if !file.seen && self.notify_on_receive {
                    let _ = notify(&format!("File Received"), &file.name);
                    file.seen = true;

                    if self.auto_open_folder {
                        open_folder(&file.path);
                    }
                }
            }
        }

        // Process scan results with try_recv
        if let Some(rx) = &self.scan_rx {
            if let Ok(peers) = rx.try_recv() {
                self.scan_rx = None;
                let local_ips: std::collections::HashSet<String> = {
                    let mut ips = std::collections::HashSet::new();
                    ips.insert(self.this_ip.clone());
                    ips
                };
                self.peers = peers
                    .into_iter()
                    .filter(|p| {
                        !local_ips.contains(&p.addr.to_string()) && p.name != self.this_hostname
                    })
                    .collect();

                // Append persisted manual peers
                for mp in &self.manual_peers {
                    if !self.peers.iter().any(|p| p.addr == mp.addr) {
                        self.peers.push(mp.clone());
                    }
                }

                self.scan_state = ScanState::Done;
                if self.selected.is_some() {
                    self.rebuild_sync_jobs();
                    if !self.sync_active && self.is_pro() {
                        if let Some(peer) = self.selected_peer() {
                            let has_folders = self
                                .sync_map
                                .get(&peer.addr.to_string())
                                .map(|_| true)
                                .unwrap_or(false);
                            if has_folders {
                                self.start_sync_watcher();
                            }
                        }
                    }
                }
            }
        }

        // Process queue messages with non-blocking
        if let Some(rx) = &self.queue_rx {
            while let Ok(msg) = rx.try_recv() {
                match msg {
                    QueueMsg::Progress { index, progress } => {
                        if let Some(item) = self.queue.get_mut(index) {
                            item.progress = Some(progress);
                        }
                    }
                    QueueMsg::Done { index } => {
                        if let Some(item) = self.queue.get_mut(index) {
                            item.progress = Some(1.0);
                            self.session_sent_bytes += item.size;
                            self.session_sent_files += 1;
                        }
                    }
                    QueueMsg::Failed { index, error } => {
                        if let Some(item) = self.queue.get_mut(index) {
                            item.error = Some(error);
                            item.progress = None;
                        }
                    }
                }
            }
        }

        // Process sync messages with non-blocking
        if let Some(rx) = &self.sync_rx {
            while let Ok(msg) = rx.try_recv() {
                match msg {
                    SyncMsg::FileFound { name } => {
                        self.sync_log.push(format!("... sending {}", name));
                        if self.sync_log.len() > 100 {
                            self.sync_log.drain(0..50);
                        }
                    }
                    SyncMsg::FileSent { name, .. } => {
                        self.sync_log.retain(|l| !l.contains(&format!("... sending {}", name)));
                        self.sync_log.push(format!("OK {}", name));
                        if self.sync_log.len() > 100 {
                            self.sync_log.drain(0..50);
                        }
                    }
                    SyncMsg::FileError { name, error } => {
                        self.sync_log.retain(|l| !l.contains(&format!("... sending {}", name)));
                        self.sync_log.push(format!("ERR {} — {}", name, error));
                        if self.sync_log.len() > 100 {
                            self.sync_log.drain(0..50);
                        }
                    }
                    SyncMsg::FileSkipped { name } => {
                        self.sync_log.retain(|l| !l.contains(&format!("... sending {}", name)));
                    }
                }
            }
        }

        // Process update checker
        if let Some(rx) = &self.update_rx {
            if let Ok(v) = rx.try_recv() {
                self.update_available = v;
                self.update_rx = None;
            }
        }

        // Process latency measurements
        if let Some(rx) = &self.latency_rx {
            while let Ok((addr, ms)) = rx.try_recv() {
                if let Some(p) = self.peers.iter_mut().find(|p| p.addr == addr) {
                    p.latency = Some(ms);
                }
            }
        }

        // Process relay messages with non-blocking
        if let Some(rx) = self.relay_rx.take() {
            let mut keep = true;
            let start = std::time::Instant::now();

            while keep && start.elapsed() < std::time::Duration::from_millis(50) {
                match rx.try_recv() {
                    Ok(RelayMsg::Code(code)) => {
                        self.relay_state = RelayState::Online { code };
                    }
                    Ok(RelayMsg::Paired { peer }) => {
                        self.relay_state = RelayState::Paired { peer_name: peer };
                    }
                    Ok(RelayMsg::Ready(holder)) => {
                        self.relay_stream = Some(holder.clone());  // Store the relay stream
                        self.is_relay_mode = true;  // Enable relay mode

                        if let RelayState::Paired { ref peer_name } = self.relay_state {
                            let dummy_ip: std::net::IpAddr = "127.0.0.2".parse().unwrap();
                            let relay_peer = Peer {
                                name: peer_name.clone(),
                                addr: dummy_ip,
                                kind: PeerKind::Remote,
                                latency: None,
                            };
                            if !self.peers.iter().any(|p| p.addr == dummy_ip) {
                                self.peers.push(relay_peer);
                            }
                            if let Some(idx) = self.peers.iter().position(|p| p.addr == dummy_ip) {
                                self.selected = Some(idx);
                                self.saved_peer_name = peer_name.clone();
                                self.saved_peer_addr = dummy_ip.to_string();
                                self.tab = Tab::Send;
                            }
                            // Start listening for incoming files via relay
                            self.start_relay_receiver();
                        }
                        keep = false;
                    }
                    Ok(RelayMsg::Error(e)) => {
                        self.relay_state = RelayState::Error(e.clone());
                        self.remote_msg = Some((format!("Connection failed: {}", e), true));
                        keep = false;
                    }
                    Err(_) => break,
                }
            }

            if keep {
                self.relay_rx = Some(rx);
            }
        }

        // Process relay sync messages with non-blocking
        if let Some(rx) = &self.relay_sync_rx {
            while let Ok(msg) = rx.try_recv() {
                match msg {
                    SyncMsg::FileFound { name } => {
                        self.relay_sync_log.push(format!("... sending via relay {}", name));
                        if self.relay_sync_log.len() > 100 {
                            self.relay_sync_log.drain(0..50);
                        }
                    }
                    SyncMsg::FileSent { name, .. } => {
                        self.relay_sync_log.retain(|l| !l.contains(&format!("... sending via relay {}", name)));
                        self.relay_sync_log.push(format!("OK via relay: {}", name));
                        if self.relay_sync_log.len() > 100 {
                            self.relay_sync_log.drain(0..50);
                        }
                    }
                    SyncMsg::FileError { name, error } => {
                        self.relay_sync_log.retain(|l| !l.contains(&format!("... sending via relay {}", name)));
                        self.relay_sync_log.push(format!("ERR via relay {} — {}", name, error));
                        if self.relay_sync_log.len() > 100 {
                            self.relay_sync_log.drain(0..50);
                        }
                    }
                    SyncMsg::FileSkipped { name } => {
                        self.relay_sync_log.retain(|l| !l.contains(&format!("... sending via relay {}", name)));
                    }
                }
            }
        }

        // Network change detection - safe version without static mut
        thread_local! {
            static LAST_NETWORK_CHECK: std::cell::RefCell<std::time::Instant> =
                std::cell::RefCell::new(std::time::Instant::now());
        }

        LAST_NETWORK_CHECK.with(|last_check| {
            let mut last = last_check.borrow_mut();
            if last.elapsed() > std::time::Duration::from_secs(10) {
                if let Some(new_ip) = self.network_monitor.has_changed() {
                    self.this_ip = new_ip;
                    if self.tab == Tab::Scan && self.scan_mode == ScanMode::Local {
                        self.start_scan();
                    }
                    if matches!(self.relay_state, RelayState::Online { .. } | RelayState::Error(_)) {
                        self.go_offline();
                        self.go_online();
                    }
                }
                *last = std::time::Instant::now();
            }
        });
    }

    fn any_active(&self) -> bool {
        self.queue.iter().any(|q| q.is_active())
    }

    fn unread_count(&self) -> usize {
        self.recv_state
            .lock()
            .unwrap()
            .files
            .iter()
            .filter(|f| !f.seen)
            .count()
    }

    fn show_preferences_panel(&mut self, ui: &mut egui::Ui) {
        let p = self.p();

        // ── Save location ─────────────────────────────────────────────────
        ui.label(RichText::new("Save Location").strong().size(13.0).color(p.text_dim));
        ui.add_space(8.0);
        egui::Frame::new()
            .fill(p.surface2).stroke(Stroke::new(1.0, p.border))
            .corner_radius(10.0).inner_margin(egui::Margin::same(14))
            .show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                ui.horizontal(|ui| {
                    let (r, _) = ui.allocate_exact_size(Vec2::new(20.0, 20.0), Sense::hover());
                    ui.painter().text(r.center(), egui::Align2::CENTER_CENTER,
                        icons::ICON_FOLDER, egui::FontId::proportional(14.0), p.accent);
                    ui.add_space(8.0);
                    ui.vertical(|ui| {
                        ui.label(RichText::new("Received files folder")
                            .size(12.0).color(p.text));
                        let path_str = self.save_dir.to_string_lossy();
                        let display = if path_str.len() > 48 {
                            format!("…{}", &path_str[path_str.len().saturating_sub(46)..])
                        } else { path_str.to_string() };
                        ui.label(RichText::new(display).size(10.5).color(p.text_faint));
                    });
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.add(pill_btn("Browse…", p.accent)).clicked() {
                            if let Some(folder) = rfd::FileDialog::new()
                                .set_directory(&self.save_dir)
                                .pick_folder()
                            {
                                self.save_dir = folder;
                                self.persist_prefs();
                            }
                        }
                        if self.save_dir != dirs::download_dir()
                            .unwrap_or_else(|| PathBuf::from("."))
                        {
                            ui.add_space(6.0);
                            if ui.add(pill_btn("Reset", p.text_dim)).clicked() {
                                self.save_dir = dirs::download_dir()
                                    .unwrap_or_else(|| PathBuf::from("."));
                                self.persist_prefs();
                            }
                        }
                    });
                });
            });

        ui.add_space(20.0);

        // ── Notifications ─────────────────────────────────────────────────
        ui.label(RichText::new("Notifications").strong().size(13.0).color(p.text_dim));
        ui.add_space(8.0);
        egui::Frame::new()
            .fill(p.surface2).stroke(Stroke::new(1.0, p.border))
            .corner_radius(10.0).inner_margin(egui::Margin::same(14))
            .show(ui, |ui| {
                ui.set_min_width(ui.available_width());

                let mut changed = false;
                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        ui.label(RichText::new("Desktop notification on receive")
                            .size(12.0).color(p.text));
                        ui.label(RichText::new("Show a system notification when a file arrives")
                            .size(10.5).color(p.text_faint));
                    });
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if toggle_switch(ui, &p, self.notify_on_receive).clicked() {
                            self.notify_on_receive = !self.notify_on_receive;
                            changed = true;
                        }
                    });
                });

                ui.add_space(12.0);
                ui.separator();
                ui.add_space(12.0);

                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        ui.label(RichText::new("Open folder after receiving")
                            .size(12.0).color(p.text));
                        ui.label(RichText::new("Automatically open the save folder when a transfer completes")
                            .size(10.5).color(p.text_faint));
                    });
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if toggle_switch(ui, &p, self.auto_open_folder).clicked() {
                            self.auto_open_folder = !self.auto_open_folder;
                            changed = true;
                        }
                    });
                });

                if changed { self.persist_prefs(); }
            });

        ui.add_space(20.0);

        // ── Appearance ────────────────────────────────────────────────────
        ui.label(RichText::new("Appearance").strong().size(13.0).color(p.text_dim));
        ui.add_space(8.0);
        egui::Frame::new()
            .fill(p.surface2).stroke(Stroke::new(1.0, p.border))
            .corner_radius(10.0).inner_margin(egui::Margin::same(14))
            .show(ui, |ui| {
                ui.set_min_width(ui.available_width());

                // Auto-detect toggle
                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        ui.label(RichText::new("Auto-detect system theme").size(12.0).color(p.text));
                        ui.label(RichText::new("Follow your operating system theme").size(10.5).color(p.text_faint));
                    });
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if toggle_switch(ui, &p, self.auto_detect_theme).clicked() {
                            self.auto_detect_theme = !self.auto_detect_theme;
                            if self.auto_detect_theme {
                                self.dark_mode = detect_system_theme();
                            }
                            self.persist_prefs();
                        }
                    });
                });

                ui.add_space(12.0);
                ui.separator();
                ui.add_space(12.0);

                // Manual theme toggle
                ui.horizontal(|ui| {
                    ui.label(RichText::new("Manual theme override").size(12.0).color(p.text));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        for (lbl, is_dark) in [("Dark", true), ("Light", false)] {
                            let active = self.dark_mode == is_dark;
                            let disabled = self.auto_detect_theme;
                            let col = if active && !disabled { p.accent } else if disabled { p.text_faint } else { p.text_dim };
                            let fill = if active && !disabled { tint(p.accent, 22) } else if disabled { tint(p.surface, 50) } else { p.surface };

                            ui.add_enabled_ui(!disabled, |ui| {
                                if ui.add(egui::Button::new(
                                    RichText::new(lbl).size(12.0).color(col))
                                    .fill(fill)
                                    .stroke(Stroke::new(1.0, if active && !disabled { p.accent } else { p.border }))
                                    .corner_radius(6.0)
                                    .min_size(Vec2::new(60.0, 28.0))).clicked()
                                {
                                    self.dark_mode = is_dark;
                                    self.persist_prefs();
                                }
                            });
                            ui.add_space(4.0);
                        }
                    });
                });

                if self.auto_detect_theme {
                    ui.add_space(8.0);
                    ui.label(RichText::new(format!("System theme: {}", if detect_system_theme() { "Dark" } else { "Light" }))
                        .size(10.5).color(p.text_faint));
                }

            });

        ui.add_space(20.0);

        // ── Tray Settings ────────────────────────────────────────────────────
        ui.label(RichText::new("System Tray").strong().size(13.0).color(p.text_dim));
        ui.add_space(8.0);

        egui::Frame::new()
            .fill(p.surface2)
            .stroke(Stroke::new(1.0, p.border))
            .corner_radius(10.0)
            .inner_margin(egui::Margin::same(14))
            .show(ui, |ui| {
                ui.set_min_width(ui.available_width());

                // Platform-specific behavior
                #[cfg(target_os = "macos")]
                {
                    ui.horizontal(|ui| {
                        ui.vertical(|ui| {
                            ui.label(RichText::new("Window close behavior")
                                .size(12.0)
                                .color(p.text));
                            ui.label(RichText::new("macOS typically quits apps when the last window closes")
                                .size(10.5)
                                .color(p.text_faint));
                        });
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if toggle_switch(ui, &p, self.minimize_to_tray).clicked() {
                                self.minimize_to_tray = !self.minimize_to_tray;
                                self.persist_prefs();
                            }
                        });
                    });

                    ui.add_space(8.0);
                    ui.separator();
                    ui.add_space(8.0);

                    let behavior_text = if self.minimize_to_tray {
                        "App will minimize to tray when window is closed"
                    } else {
                        "App will quit when window is closed"
                    };
                    ui.label(
                        RichText::new(behavior_text)
                            .size(11.0)
                            .color(p.text_dim)
                    );
                }

                #[cfg(not(target_os = "macos"))]
                {
                    // Minimize to tray option (standard behavior)
                    ui.horizontal(|ui| {
                        ui.vertical(|ui| {
                            ui.label(RichText::new("Minimize to system tray")
                                .size(12.0)
                                .color(p.text));
                            ui.label(RichText::new("Keep app running in background when window is closed")
                                .size(10.5)
                                .color(p.text_faint));
                        });
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if toggle_switch(ui, &p, self.minimize_to_tray).clicked() {
                                self.minimize_to_tray = !self.minimize_to_tray;
                                self.persist_prefs();
                            }
                        });
                    });
                }

                ui.add_space(12.0);

                // Platform-specific tips
                #[cfg(target_os = "windows")]
                {
                    ui.label(
                        RichText::new("💡 Tip: When minimized, the app stays in the system tray (notification area). Click the tray icon to restore the window.")
                            .size(10.0)
                            .color(p.text_faint)
                    );
                }

                #[cfg(target_os = "macos")]
                {
                    ui.label(
                        RichText::new("💡 Tip: When minimized to tray, the app stays in the menu bar. Click the icon to restore the window.")
                            .size(10.0)
                            .color(p.text_faint)
                    );
                }

                #[cfg(target_os = "linux")]
                {
                    ui.label(
                        RichText::new("💡 Tip: When minimized, the app stays in the system tray. If you don't see the icon, you may need a GNOME extension like 'AppIndicator'.")
                            .size(10.0)
                            .color(p.text_faint)
                    );
                }
            });
    }

    fn select_peer(&mut self, peer_idx: usize, peer: &Peer) {
        let was_selected = self.selected == Some(peer_idx);
        self.selected = if was_selected { None } else { Some(peer_idx) };
        if self.selected.is_some() {
            self.saved_peer_name = peer.name.clone();
            self.saved_peer_addr = peer.addr.to_string();
            self.rebuild_sync_jobs();
            self.persist_prefs();
        } else {
            self.rebuild_sync_jobs();
        }
    }

    fn go_online(&mut self) {
        // Allow retrying from Error state as well
        if !matches!(self.relay_state, RelayState::Offline | RelayState::Error(_)) {
            return;
        }

        if !self.check_internet_connection() {
            self.remote_msg = Some(("No internet connection. Please check your network.".into(), true));
            return;
        }

        self.relay_state = RelayState::Connecting;
        let (tx, rx) = std::sync::mpsc::channel();
        self.relay_rx = Some(rx);
        let tx_clone = tx.clone();
        thread::spawn(move || {
            relay_listen(tx_clone);
        });

        // Set timeout - if no response in 10 seconds, fail
        let tx_timeout = tx.clone();
        thread::spawn(move || {
            thread::sleep(std::time::Duration::from_secs(10));
            let _ = tx_timeout.send(RelayMsg::Error("Connection timeout".into()));
        });
    }

    fn go_offline(&mut self) {
        self.relay_state = RelayState::Offline;
        self.relay_rx = None;
        self.remote_msg = None;
    }

    fn connect_via_relay(&mut self) {
        let code = self.relay_code_input.trim().to_uppercase().replace(' ', "");
        if code.len() != 9 {
            self.remote_msg = Some(("Enter the 9-character code".into(), true));
            return;
        }
        if !self.check_internet_connection() {
            self.remote_msg = Some(("No internet connection. Please check your network.".into(), true));
            return;
        }
        self.relay_state = RelayState::Connecting;
        let (tx, rx) = std::sync::mpsc::channel();
        self.relay_rx = Some(rx);
        let code_clone = code.clone();
        thread::spawn(move || relay_connect(&code_clone, tx));
    }

    fn start_relay_receiver(&mut self) {
        if let Some(stream_arc) = &self.relay_stream {
            if let Ok(mut guard) = stream_arc.lock() {
                if let Some(stream) = guard.take() {
                    let state = Arc::clone(&self.recv_state);
                    let save_dir = self.save_dir.clone();
                    thread::spawn(move || {
                        match receive_file_via_relay(stream, &save_dir) {
                            Ok(f) => {
                                let ts = SystemTime::now()
                                    .duration_since(UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_secs();
                                append_history(&HistoryEntry {
                                    timestamp: ts,
                                    direction: TransferDir::Received,
                                    transfer_type: TransferType::Remote,
                                    file_name: f.name.clone(),
                                    file_size: f.size,
                                    peer_name: f.peer_name.clone(),
                                    success: true,
                                    error: None,
                                    file_path: Some(f.path.clone()),
                                });
                                if let Ok(mut s) = state.lock() {
                                    s.recv_bytes += f.size;
                                    s.recv_files += 1;
                                    if s.auto_open_folder {
                                        open_folder(&f.path);
                                    }
                                    s.files.push(f);
                                }
                            }
                            Err(e) => {
                                if let Ok(mut s) = state.lock() {
                                    s.error = Some(e);
                                }
                            }
                        }
                    });
                }
            }
        }
    }

    fn start_relay_sync_watcher(&mut self) {
        if !self.is_pro() {
            self.show_upgrade = true;
            return;
        }

        if self.relay_sync_jobs.is_empty() || self.relay_sync_active {
            return;
        }

        if !self.is_relay_mode || self.relay_stream.is_none() {
            self.remote_msg = Some(("Cannot start remote sync: No active relay connection".into(), true));
            return;
        }

        self.relay_sync_active = true;
        let jobs = self.relay_sync_jobs.clone();
        let (tx, rx) = std::sync::mpsc::channel::<SyncMsg>();
        self.relay_sync_rx = Some(rx);

        // Clone the relay stream for the sync thread
        let relay_stream_arc = self.relay_stream.clone();

        thread::spawn(move || {
            let mut job_mtimes: Vec<std::collections::HashMap<String, u64>> = jobs
                .iter()
                .map(|_| std::collections::HashMap::new())
                .collect();

            let mut last_scan = std::time::Instant::now();

            loop {
                // Throttle scanning to avoid CPU spikes
                if last_scan.elapsed() < std::time::Duration::from_millis(SYNC_POLL_MS) {
                    thread::sleep(std::time::Duration::from_millis(100));
                    continue;
                }
                last_scan = std::time::Instant::now();

                for (job_idx, job) in jobs.iter().enumerate() {
                    let Ok(entries) = fs::read_dir(&job.folder) else {
                        continue;
                    };

                    let mut files_to_send = Vec::new();

                    for entry in entries.flatten() {
                        let path = entry.path();
                        if !path.is_file() {
                            continue;
                        }

                        let key = path.to_string_lossy().to_string();
                        let current_mtime = fs::metadata(&path)
                            .and_then(|m| m.modified())
                            .map(|t| {
                                t.duration_since(std::time::UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_secs()
                            })
                            .unwrap_or(0);

                        if let Some(&last_sent_mtime) = job_mtimes[job_idx].get(&key) {
                            if last_sent_mtime >= current_mtime {
                                continue;
                            }
                        }

                        let name = path
                            .file_name()
                            .unwrap_or_default()
                            .to_string_lossy()
                            .to_string();
                        let size = fs::metadata(&path).map(|m| m.len()).unwrap_or(0);

                        files_to_send.push((path, key, name, size, current_mtime));
                    }

                    // Send files via relay
                    for (path, key, name, size, current_mtime) in files_to_send {
                        let _ = tx.send(SyncMsg::FileFound { name: name.clone() });

                        // Get a relay stream for this file transfer
                        if let Some(stream_arc) = &relay_stream_arc {
                            if let Ok(mut guard) = stream_arc.lock() {
                                if let Some(mut stream) = guard.take() {
                                    match send_file_via_relay(&path, &name, size, &mut stream, |_| {}) {
                                        Ok(()) => {
                                            job_mtimes[job_idx].insert(key.clone(), current_mtime);
                                            let _ = tx.send(SyncMsg::FileSent { name, path: key });
                                        }
                                        Err(e) => {
                                            let _ = tx.send(SyncMsg::FileError { name, error: e });
                                        }
                                    }
                                    // Put the stream back
                                    *guard = Some(stream);
                                } else {
                                    let _ = tx.send(SyncMsg::FileError {
                                        name: name.clone(),
                                        error: "No relay stream available".into()
                                    });
                                }
                            }
                        }

                        // Small delay between file sends
                        thread::sleep(std::time::Duration::from_millis(100));
                    }
                }
            }
        });
    }

    fn add_relay_sync_folder(&mut self, folder: PathBuf) {
        if !self.is_pro() {
            self.show_upgrade = true;
            return;
        }

        if !self.is_relay_mode {
            self.remote_msg = Some(("Remote sync requires an active relay connection".into(), true));
            return;
        }

        let peer = self.selected_peer().cloned();
        if let Some(peer) = peer {
            let addr_key = peer.addr.to_string();
            if self.relay_sync_active {
                self.relay_sync_rx = None;
                self.relay_sync_active = false;
            }
            self.relay_sync_map.insert(addr_key, folder);
            self.rebuild_relay_sync_jobs();
            self.persist_prefs();
        }
    }

    fn remove_relay_sync_folder(&mut self) {
        if let Some(peer) = self.selected_peer().cloned() {
            if self.relay_sync_active {
                self.relay_sync_rx = None;
                self.relay_sync_active = false;
            }
            self.relay_sync_map.remove(&peer.addr.to_string());
            self.rebuild_relay_sync_jobs();
            self.persist_prefs();
        }
    }

    fn stop_relay_sync(&mut self) {
        self.relay_sync_rx = None;
        self.relay_sync_active = false;
        self.relay_sync_log.push("-- Remote sync stopped".to_string());
    }

    fn rebuild_relay_sync_jobs(&mut self) {
        let Some(peer) = self.selected_peer().cloned() else {
            self.relay_sync_jobs.clear();
            return;
        };
        let addr_key = peer.addr.to_string();
        if let Some(folder) = self.relay_sync_map.get(&addr_key).cloned() {
            if folder.exists() {
                self.relay_sync_jobs = vec![SyncJob {
                    folder,
                    peer_addr: peer.addr,
                    peer_name: peer.name.clone(),
                    file_mtimes: std::collections::HashMap::new(),
                }];
            } else {
                self.relay_sync_jobs.clear();
            }
        } else {
            self.relay_sync_jobs.clear();
        }
    }
}

// ─── eframe::App ─────────────────────────────────────────────────────────────
impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Handle window close request
        if ctx.input(|i| i.viewport().close_requested()) {
            if self.minimize_to_tray {
                // Hide window instead of closing
                ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
                ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
                self.window_visible = false;

                return; // Don't process further
            } else {
                // Actually quit the app
                std::process::exit(0);
            }
        }

        // Handle tray events
        while let Some(event) = self.tray.as_ref().and_then(|t| t.try_recv()) {
            match event {
                TrayEvent::ShowWindow => {
                    self.window_visible = true;
                    ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
                    ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
                }
                TrayEvent::Quit => {
                    self.persist_prefs();
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }
            }
        }

        // Request repaint only when needed - not every frame
        let needs_repaint = self.scan_state == ScanState::Scanning
            || self.any_active()
            || self.sync_active
            || self.relay_state == RelayState::Connecting;

        if needs_repaint {
            ctx.request_repaint_after(std::time::Duration::from_millis(100));
        } else {
            ctx.request_repaint_after(std::time::Duration::from_millis(500));
        }

        let p = self.p();
        ctx.set_visuals({
            let mut v = if self.dark_mode {
                egui::Visuals::dark()
            } else {
                egui::Visuals::light()
            };
            v.panel_fill = p.bg;
            v.window_fill = p.surface;
            v.extreme_bg_color = p.bg;
            v.faint_bg_color = p.surface2;
            v.override_text_color = Some(p.text);
            v.widgets.noninteractive.bg_fill = p.surface;
            v.widgets.noninteractive.bg_stroke = Stroke::new(1.0, p.border);
            v.widgets.noninteractive.fg_stroke = Stroke::new(1.0, p.text_dim);
            v.widgets.inactive.bg_fill = p.surface2;
            v.widgets.inactive.fg_stroke = Stroke::new(1.0, p.text);
            v.widgets.hovered.bg_fill = tint(p.accent, 20);
            v.widgets.hovered.fg_stroke = Stroke::new(1.5, p.accent);
            v.widgets.active.bg_fill = tint(p.accent, 38);
            v.widgets.active.fg_stroke = Stroke::new(1.5, p.accent);
            v.widgets.open.bg_fill = p.surface2;
            v.widgets.open.fg_stroke = Stroke::new(1.0, p.text);
            v.selection.bg_fill = tint(p.accent, 50);
            v.selection.stroke = Stroke::new(1.0, p.accent);
            v.window_corner_radius = CornerRadius::same(14);
            v.window_stroke = Stroke::new(1.0, p.border);
            v
        });

        self.poll(ctx);
        self.check_for_update();
        let scanning = self.scan_state == ScanState::Scanning;
        if scanning {
            self.scan_pulse += ctx.input(|i| i.unstable_dt) * 2.5;
        }
        if scanning || self.any_active() || self.sync_active {
            ctx.request_repaint_after(std::time::Duration::from_millis(40));
        }
        let _unread = self.unread_count();
        let wide = ctx.viewport_rect().width() > 640.0;

        ctx.input(|i| {
            if !i.raw.dropped_files.is_empty() {
                let paths: Vec<PathBuf> = i
                    .raw
                    .dropped_files
                    .iter()
                    .filter_map(|f| f.path.clone())
                    .collect();
                if !paths.is_empty() {
                    self.add_files(paths);
                    self.tab = Tab::Send;
                }
            }
        });

        // ── Upgrade modal ──────────────────────────────────────────────────
        if self.show_upgrade {
            let p2 = self.p();
            egui::Window::new("Upgrade to Pro")
                .collapsible(false)
                .resizable(false)
                .min_width(360.0)
                .anchor(egui::Align2::CENTER_CENTER, Vec2::ZERO)
                .frame(
                    egui::Frame::new()
                        .fill(p2.surface)
                        .stroke(Stroke::new(1.0, p2.border))
                        .corner_radius(16.0),
                )
                .show(ctx, |ui| {
                    ui.add_space(8.0);
                    ui.vertical_centered(|ui| {
                        ui.label(
                            RichText::new(format!("{} Pro", env!("CARGO_PKG_NAME")))
                                .size(20.0)
                                .strong()
                                .color(p2.pro),
                        );
                        ui.add_space(6.0);
                        ui.label(
                            RichText::new("$5/month  or  $48/year")
                                .size(13.0)
                                .color(p2.text_dim),
                        );
                        ui.add_space(16.0);

                        let feat_w = 300.0f32;
                        for (icon, feat) in [
                            (icons::ICON_GLOBE, "Remote file sharing"),
                            ("📁", "Folder sync — auto-send new files in a folder"),
                            ("🏢", "Unlimited devices  /  org license"),
                            ("🔐", "End-to-end encrypted transfers"),
                        ] {
                            ui.allocate_ui_with_layout(
                                Vec2::new(feat_w, 30.0),
                                egui::Layout::left_to_right(egui::Align::Center),
                                |ui| {
                                    let (r, _) =
                                        ui.allocate_exact_size(Vec2::splat(26.0), Sense::hover());
                                    ui.painter().circle_filled(
                                        r.center(),
                                        13.0,
                                        tint(p2.accent, 18),
                                    );
                                    ui.painter().text(
                                        r.center(),
                                        egui::Align2::CENTER_CENTER,
                                        icon,
                                        egui::FontId::proportional(14.0),
                                        Color32::WHITE,
                                    );
                                    ui.add_space(10.0);
                                    ui.label(RichText::new(feat).size(12.0).color(p2.text));
                                },
                            );
                            ui.add_space(4.0);
                        }

                        ui.add_space(16.0);
                        if ui
                            .add(
                                egui::Button::new(
                                    RichText::new("  Get Pro  ")
                                        .size(14.0)
                                        .strong()
                                        .color(Color32::BLACK),
                                )
                                .fill(p2.pro)
                                .corner_radius(10.0)
                                .min_size(Vec2::new(160.0, 42.0)),
                            )
                            .clicked()
                        {
                            open_url("https://github.com/sponsors/imrany");
                        }
                        ui.add_space(6.0);
                        if ui
                            .add(
                                egui::Button::new(
                                    RichText::new("I have a key").size(11.0).color(p2.text_dim),
                                )
                                .frame(false),
                            )
                            .clicked()
                        {
                            self.show_upgrade = false;
                            self.tab = Tab::Settings;
                            self.settings_tab = SettingsTab::License;
                        }
                        ui.add_space(4.0);
                        if ui
                            .add(
                                egui::Button::new(
                                    RichText::new("Not now").size(11.0).color(p2.text_faint),
                                )
                                .frame(false),
                            )
                            .clicked()
                        {
                            self.show_upgrade = false;
                        }
                        ui.add_space(8.0);
                    });
                });
        }

        // ── Top bar ────────────────────────────────────────────────────────
        egui::TopBottomPanel::top("topbar")
            .frame(
                egui::Frame::new()
                    .fill(p.surface)
                    .inner_margin(egui::Margin {
                        left: 20,
                        right: 12,
                        top: 0,
                        bottom: 0,
                    }),
            )
            .exact_height(52.0)
            .show(ctx, |ui| {
                ui.horizontal_centered(|ui| {
                    ui.add(
                        egui::Image::new(egui::include_image!("../assets/icon.png"))
                            .fit_to_exact_size(Vec2::splat(28.0))
                            .corner_radius(7.0),
                    );
                    ui.add_space(6.0);
                    ui.label(RichText::new(env!("CARGO_PKG_NAME")).size(15.0).strong().color(p.text));

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let tab_defs: &[(&str, Tab, bool)] = &[
                            ("Settings", Tab::Settings, false),
                            ("History", Tab::History, false),
                            ("Sync", Tab::Sync, !self.is_pro()),
                            ("Send", Tab::Send, false),
                            ("Scan", Tab::Scan, false),
                        ];

                        let history_new = self
                            .recv_state
                            .lock()
                            .map(|rs| rs.files.iter().filter(|f| !f.seen).count())
                            .unwrap_or(0);
                        for (lbl, t, locked) in tab_defs {
                            let active = &self.tab == t;
                            let col = if active {
                                p.accent
                            } else if *locked {
                                p.text_faint
                            } else {
                                p.text_dim
                            };

                            let display = if *locked {
                                format!("{lbl}  🔒")
                            } else {
                                lbl.to_string()
                            };

                            let resp = ui.add(
                                egui::Button::new(RichText::new(&display).size(12.5).color(col))
                                    .frame(false)
                                    .min_size(Vec2::new(0.0, 52.0)),
                            );

                            if resp.clicked() {
                                if *locked {
                                    self.show_upgrade = true;
                                } else {
                                    self.tab = t.clone();
                                    if self.tab == Tab::History {
                                        if let Ok(mut rs) = self.recv_state.lock() {
                                            for f in &mut rs.files {
                                                f.seen = true;
                                            }
                                        }
                                    }
                                    if self.tab == Tab::History {
                                        self.history = load_history();
                                    }
                                }
                            }

                            if active {
                                let r = resp.rect;
                                ui.painter().line_segment(
                                    [
                                        egui::pos2(r.left() + 4.0, r.bottom() - 1.0),
                                        egui::pos2(r.right() - 4.0, r.bottom() - 1.0),
                                    ],
                                    Stroke::new(2.0, p.accent),
                                );
                            }

                            if *lbl == "History" && history_new > 0 {
                                let dot =
                                    egui::pos2(resp.rect.right() + 4.0, resp.rect.top() + 11.0);
                                ui.painter().circle_filled(dot, 5.5, p.warn);
                                ui.painter().text(
                                    dot,
                                    egui::Align2::CENTER_CENTER,
                                    if history_new > 9 {
                                        "9+".to_string()
                                    } else {
                                        history_new.to_string()
                                    },
                                    egui::FontId::proportional(7.5),
                                    p.text,
                                );
                            }

                            ui.add_space(2.0);
                        }
                    });
                });
            });

        // At the bottom (statusbar)
        egui::TopBottomPanel::bottom("statusbar")
            .frame(egui::Frame::new()
                .fill(p.surface)
                .stroke(Stroke::new(1.0, p.border))
                .inner_margin(egui::Margin { left: 12, right: 12, top: 0, bottom: 0 }))
            .exact_height(28.0)
            .show(ctx, |ui| {
                ui.horizontal_centered(|ui| {
                    ui.label(
                        RichText::new(format!("{} {}", env!("CARGO_PKG_NAME"), self.version))
                            .size(10.5).color(p.text_faint),
                    );

                    if let Some(ref latest) = self.update_available {
                        ui.add_space(6.0);
                        let resp = ui.add(
                            egui::Button::new(
                                RichText::new(format!("{} {} available",icons::ICON_ARROW_UPWARD, latest))
                                    .size(10.0).color(p.warn).strong()
                            ).frame(false)
                        );
                        if resp.clicked() {
                            open_url(format!("{}/releases/latest", env!("CARGO_PKG_REPOSITORY")).as_str());
                        }
                    }

                    ui.with_layout(egui::Layout::centered_and_justified(
                        egui::Direction::LeftToRight), |ui| {
                        ui.horizontal(|ui| {
                            let total_sent = self.history.iter()
                                .filter(|e| e.direction == TransferDir::Sent && e.success)
                                .count();
                            let total_recv = self.history.iter()
                                .filter(|e| e.direction == TransferDir::Received && e.success)
                                .count();
                            let bytes_sent: u64 = self.history.iter()
                                .filter(|e| e.direction == TransferDir::Sent && e.success)
                                .map(|e| e.file_size).sum();
                            let bytes_recv: u64 = self.history.iter()
                                .filter(|e| e.direction == TransferDir::Received && e.success)
                                .map(|e| e.file_size).sum();
                            status_metric(ui, &p, icons::ICON_UPLOAD,
                                &format!("{} · {} file{}",
                                    format_size(bytes_sent),
                                    total_sent,
                                    if total_sent == 1 { "" } else { "s" }));
                            ui.add_space(16.0);
                            status_metric(ui, &p, icons::ICON_DOWNLOAD,
                                &format!("{} · {} file{}",
                                    format_size(bytes_recv),
                                    total_recv,
                                    if total_recv == 1 { "" } else { "s" }));
                        });
                    });

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if self.is_pro() {
                            let (r, _) = ui.allocate_exact_size(
                                Vec2::new(26.0, 14.0), Sense::hover());
                            ui.painter().rect_filled(r, 3.0, tint(p.pro, 30));
                            ui.painter().text(r.center(), egui::Align2::CENTER_CENTER,
                                "PRO", egui::FontId::proportional(8.0), p.pro);
                            ui.add_space(6.0);
                        }

                        ui.label({
                            let device = if self.this_hostname.is_empty() {
                                &self.this_ip
                            } else {
                                &self.this_hostname
                            };

                            RichText::new(device)
                                .size(10.5)
                                .color(p.text_dim)
                        });

                    });
                });
            });

        egui::CentralPanel::default()
            .frame(egui::Frame::new().fill(p.bg))
            .show(ctx, |ui| match self.tab {
                Tab::Scan => self.show_scan(ui, ctx, wide),
                Tab::Send => self.show_send(ui, ctx, wide),
                Tab::History => self.show_history(ui, ctx, wide),
                Tab::Sync => self.show_sync(ui, ctx, wide),
                Tab::Settings => self.show_settings(ui, ctx, wide),
            });
    }
}

// ─── Send tab ────────────────────────────────────────────────────────────────
impl App {
    fn show_scan(&mut self, ui: &mut egui::Ui, ctx: &egui::Context, _wide: bool) {
        let p = self.p();
        let scanning = self.scan_state == ScanState::Scanning;

        // ── Toolbar ───────────────────────────────────────────────────────
        if !scanning {
            egui::Frame::new()
                .inner_margin(egui::Margin { left: 12, right: 12, top: 8, bottom: 8 })
                .show(ui, |ui| {
                    ui.set_min_width(ui.available_width());
                    ui.horizontal(|ui| {
                        // Only check internet connection every 60 seconds instead of every frame
                        if self.last_internet_check.elapsed() > std::time::Duration::from_secs(60) {
                            self.is_online = self.check_internet_connection();
                            self.last_internet_check = std::time::Instant::now();
                        }

                        if self.is_pro() {
                            // ── Local / Remote toggle ─────────────────────────────
                            for (label, mode) in [
                                ("  Local  ", ScanMode::Local),
                                ("  Remote  ", ScanMode::Remote),
                            ] {
                                let active = self.scan_mode == mode;
                                let (fill, text_col) = if active {
                                    (p.accent, Color32::WHITE)
                                } else {
                                    (p.surface2, p.text_dim)
                                };
                                if ui.add(egui::Button::new(
                                    RichText::new(label).size(12.0).color(text_col))
                                    .fill(fill)
                                    .corner_radius(6.0)
                                    .min_size(Vec2::new(0.0, 30.0))).clicked()
                                {
                                    self.scan_mode = mode;
                                }
                            }
                            ui.add_space(8.0);
                        }

                        // Only show local scan controls when in Local mode
                        if self.scan_mode == ScanMode::Local {
                            let n = self.peers.iter().filter(|p| p.kind == PeerKind::Local).count();
                            if n > 0 {
                                let scan_lbl = format!("{}  Rescan", icons::ICON_SEARCH);
                                ui.add_enabled_ui(!scanning, |ui| {
                                    if ui.add(egui::Button::new(
                                        RichText::new(&scan_lbl).size(12.0).color(Color32::WHITE))
                                        .fill(p.surface2).corner_radius(6.0)
                                        .stroke(Stroke::new(1.0, p.border))
                                        .min_size(Vec2::new(80.0, 30.0))).clicked()
                                    {
                                        self.start_scan();
                                    }
                                });
                                ui.add_space(8.0);

                                egui::Frame::new()
                                    .fill(p.bg)
                                    .stroke(Stroke::new(1.0,
                                        if !self.scan_filter.is_empty() { p.accent } else { p.border }))
                                    .corner_radius(6.0)
                                    .inner_margin(egui::Margin { left: 8, right: 8, top: 5, bottom: 5 })
                                    .show(ui, |ui| {
                                        ui.set_min_width(160.0);
                                        ui.horizontal(|ui| {
                                            ui.label(RichText::new(icons::ICON_SEARCH)
                                                .size(13.0).color(p.text_faint));
                                            ui.add_space(4.0);
                                            ui.add(egui::TextEdit::singleline(&mut self.scan_filter)
                                                .hint_text("Filter…")
                                                .desired_width(110.0)
                                                .frame(false));
                                            if !self.scan_filter.is_empty() {
                                                if ui.add(egui::Button::new(
                                                    RichText::new(icons::ICON_CLOSE).size(11.0)
                                                    .color(p.text_faint)).frame(false)).clicked()
                                                {
                                                    self.scan_filter.clear();
                                                }
                                            }
                                        });
                                    });
                                if self.scan_state == ScanState::Done {
                                    ui.add_space(8.0);
                                    ui.label(RichText::new(format!(
                                        "{} device{}", n, if n == 1 {""} else {"s"}))
                                        .size(11.0).color(p.text_faint));
                                }
                            }
                        }

                        // Remote mode controls
                        if self.scan_mode == ScanMode::Remote {
                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                match &self.relay_state {
                                    RelayState::Online { .. } | RelayState::Paired { .. } => {
                                        if ui.add(pill_btn("Go Offline", p.danger)).clicked() {
                                            self.go_offline();
                                        }
                                        ui.add_space(8.0);
                                        ui.painter().circle_filled(
                                            ui.cursor().left_top() + Vec2::new(4.0, 10.0),
                                            5.0, p.success);
                                        ui.add_space(14.0);
                                        ui.label(RichText::new("Online").size(11.5)
                                            .color(p.success).strong());
                                    }
                                    RelayState::Connecting => {
                                        ui.spinner();
                                        ui.add_space(6.0);
                                        ui.label(RichText::new("Connecting…")
                                            .size(11.5).color(p.text_dim));
                                    }
                                    _ => {
                                        if ui.add(egui::Button::new(
                                            RichText::new("  Go Online  ").size(12.0)
                                            .color(Color32::WHITE))
                                            .fill(p.success).corner_radius(6.0)
                                            .min_size(Vec2::new(0.0, 30.0))).clicked()
                                        {
                                            self.go_online();
                                        }
                                        ui.add_space(8.0);
                                        ui.painter().circle_filled(
                                            ui.cursor().left_top() + Vec2::new(4.0, 10.0),
                                            5.0, p.text_faint);
                                        ui.add_space(14.0);
                                        ui.label(RichText::new("Offline").size(11.5)
                                            .color(p.text_faint));
                                    }
                                }
                            });
                        }

                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if scanning && self.scan_mode == ScanMode::Local {
                                ui.spinner();
                                ctx.request_repaint_after(std::time::Duration::from_millis(40));
                            }
                        });
                    });
                });
        }

        // ── Content ───────────────────────────────────────────────────────
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.add_space(8.0);

                match self.scan_mode {
                    ScanMode::Local => self.show_local_scan(ui, ctx),
                    ScanMode::Remote => self.show_remote_panel(ui, ctx),
                }
            });
    }

    // ── Local scan content ────────────────────────────────────────────────
    fn show_local_scan(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let p = self.p();
        let scanning = self.scan_state == ScanState::Scanning;

        if self.scan_state == ScanState::Idle {
            ui.add_space(40.0);
            ui.vertical_centered(|ui| {
                radar_graphic(ui, &p, self.scan_pulse, false);
                ui.add_space(16.0);
                ui.label(RichText::new("Find devices on your network")
                    .size(14.0).strong().color(p.text));
                ui.add_space(6.0);
                ui.label(RichText::new(
                    format!("Devices running {} on the same Wi-Fi will appear here.", env!("CARGO_PKG_NAME")))
                    .size(12.0).color(p.text_dim));
                ui.add_space(20.0);
                if ui.add(big_btn(&format!("  {}  Scan  ", icons::ICON_SEARCH), p.accent))
                    .clicked() { self.start_scan(); }
            });
            ui.add_space(32.0);
        }

        if scanning {
            ui.add_space(32.0);
            ui.vertical_centered(|ui| {
                radar_graphic(ui, &p, self.scan_pulse, true);
                ui.add_space(14.0);
                ui.label(RichText::new("Scanning your network…")
                    .size(13.0).color(p.text_dim));
            });
            ui.add_space(32.0);
            ctx.request_repaint_after(std::time::Duration::from_millis(40));
        }

        if self.scan_state == ScanState::Done {
            let filter = self.scan_filter.to_lowercase();
            let all_peers = self.peers.clone();
            let local_peers: Vec<(usize, &Peer)> = {
                let tmp: Vec<_> = all_peers.iter().enumerate()
                    .filter(|(_, p)| p.kind == PeerKind::Local)
                    .collect();
                let mut sorted: Vec<(usize, &Peer)> = tmp.into_iter().map(|(i,p)|(i,p)).collect();
                sorted.sort_by(|(_, a), (_, b)| {
                    let a_rec = a.addr.to_string() == self.saved_peer_addr;
                    let b_rec = b.addr.to_string() == self.saved_peer_addr;
                    b_rec.cmp(&a_rec).then(a.name.cmp(&b.name))
                });
                sorted
            };

            let filtered: Vec<(usize, &Peer)> = local_peers.iter()
                .filter(|(_, p)| filter.is_empty()
                    || p.name.to_lowercase().contains(&filter)
                    || p.addr.to_string().contains(&filter))
                .map(|(i, p)| (*i, *p))
                .collect();

            if !filtered.is_empty() {
                // Column headers
                egui::Frame::new()
                    .fill(p.surface2)
                    .inner_margin(egui::Margin { left:16, right:16, top:4, bottom:4 })
                    .show(ui, |ui| {
                        ui.set_min_width(ui.available_width());
                        ui.horizontal(|ui| {
                            ui.label(RichText::new("Name").size(10.5).strong().color(p.text_faint));
                            ui.add_space(ui.available_width() - 180.0);
                            ui.label(RichText::new("Address").size(10.5).strong().color(p.text_faint));
                            ui.add_space(16.0);
                            ui.label(RichText::new("Latency").size(10.5).strong().color(p.text_faint));
                            ui.add_space(16.0);
                            ui.label(RichText::new("Type").size(10.5).strong().color(p.text_faint));
                        });
                    });

                for (peer_idx, peer) in &filtered {
                    let is_recent = peer.addr.to_string() == self.saved_peer_addr;
                    let sel = self.selected == Some(*peer_idx);
                    let resp = device_row(ui, &p, peer, sel, is_recent, false);
                    if resp.clicked() { self.select_peer(*peer_idx, peer); }
                    if resp.double_clicked() {
                        self.select_peer(*peer_idx, peer);
                        self.tab = Tab::Send;
                    }
                }
            } else {
                ui.add_space(24.0);
                ui.vertical_centered(|ui| {
                    ui.label(RichText::new("📡").size(40.0));
                    ui.add_space(8.0);
                    ui.label(RichText::new("No devices found")
                        .size(14.0).strong().color(p.text));
                    ui.add_space(4.0);
                    ui.label({
                        RichText::new(
                            format!("Make sure the other device is on the same Wi-Fi and running {}", env!("CARGO_PKG_NAME"))
                        ).size(11.5).color(p.text_dim)
                    });
                    ui.add_space(12.0);
                    if ui.add(pill_btn("Scan again", p.accent)).clicked() {
                        self.start_scan();
                    }
                });
            }
        }
    }

    // ── Remote panel ──────────────────────────────────────────────────────
    fn show_remote_panel(&mut self, ui: &mut egui::Ui, _ctx: &egui::Context) {
        let p = self.p();

        // Use a scroll area with proper centering
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.add_space(12.0);

                // Center the content horizontally
                ui.vertical_centered(|ui| {
                    ui.set_width(ui.available_width());

                    match self.relay_state.clone() {
                        // ── Offline ───────────────────────────────────────────────────
                        RelayState::Offline | RelayState::Error(_) => {
                            // Extract and clone the error message if present, *before* creating the UI closure
                            let error_to_display = if let RelayState::Error(ref e) = self.relay_state {
                                Some(e.clone()) // Clone the error message to own it
                            } else {
                                None
                            };

                            if let Some(e) = error_to_display { // Now 'e' is an owned String, not borrowing from self
                                egui::Frame::new()
                                    .fill(tint(p.danger, 10))
                                    .stroke(Stroke::new(1.0, tint(p.danger, 40)))
                                    .corner_radius(8.0)
                                    .inner_margin(egui::Margin::same(10))
                                    .show(ui, |ui| {
                                        ui.set_width((ui.available_width() - 40.0).min(500.0));
                                        ui.horizontal(|ui| {
                                            ui.label(RichText::new(icons::ICON_CLOSE).size(13.0).color(p.danger));
                                            ui.add_space(4.0);
                                            ui.label(RichText::new(&e).size(11.5).color(p.danger)); // Use a reference to the owned String
                                            ui.add_space(8.0);
                                            if ui.add(pill_btn("Retry", p.accent)).clicked() {
                                                // Now self.go_online() can borrow self mutably without conflict
                                                // because 'e' no longer holds an immutable borrow on self.relay_state.
                                                self.go_online();
                                            }
                                        });
                                    });
                                ui.add_space(12.0);
                            }

                            // Only show "Go Online" button if device is online
                            if self.is_online {
                                // Main content card - centered with fixed width
                                let avail = ui.available_width();
                                let card_width = (avail  - 40.0).min(500.0);
                                ui.vertical(|ui| {
                                    ui.set_width(avail);
                                    ui.vertical_centered(|ui| {
                                        // Receive card
                                        egui::Frame::new()
                                            .fill(p.surface)
                                            .stroke(Stroke::new(1.0, p.border))
                                            .corner_radius(10.0)
                                            .inner_margin(egui::Margin::same(14))
                                            .show(ui, |ui| {
                                                ui.set_width(card_width);
                                                ui.vertical_centered(|ui| {
                                                    ui.label(RichText::new("📥").size(28.0));
                                                    ui.add_space(6.0);
                                                    ui.label(RichText::new("Receive files")
                                                        .size(13.0).strong().color(p.text));
                                                    ui.add_space(4.0);
                                                    ui.label(RichText::new("Go online to get a share code")
                                                        .size(11.0).color(p.text_dim));
                                                    ui.add_space(10.0);
                                                    if ui.add(egui::Button::new(
                                                        RichText::new("  Go Online  ").size(12.5)
                                                        .color(Color32::WHITE))
                                                        .fill(p.success).corner_radius(8.0)
                                                        .min_size(Vec2::new(ui.available_width(), 36.0))).clicked()
                                                    {
                                                        self.go_online();
                                                    }
                                                });
                                            });

                                        ui.add_space(12.0);

                                        // Send card
                                        egui::Frame::new()
                                            .fill(p.surface)
                                            .stroke(Stroke::new(1.0, p.border))
                                            .corner_radius(10.0)
                                            .inner_margin(egui::Margin::same(14))
                                            .show(ui, |ui| {
                                                ui.set_width(card_width);
                                                ui.vertical_centered(|ui| {
                                                    ui.label(RichText::new("📤").size(28.0));
                                                    ui.add_space(6.0);
                                                    ui.label(RichText::new("Send files")
                                                        .size(13.0).strong().color(p.text));
                                                    ui.add_space(4.0);
                                                    ui.label(RichText::new("Enter the code from the receiver")
                                                        .size(11.0).color(p.text_dim));
                                                    ui.add_space(10.0);
                                                    egui::Frame::new()
                                                        .fill(p.bg)
                                                        .stroke(Stroke::new(1.0, p.border))
                                                        .corner_radius(6.0)
                                                        .inner_margin(egui::Margin { left:8, right:8, top:6, bottom:6 })
                                                        .show(ui, |ui| {
                                                            ui.set_width(ui.available_width());
                                                            ui.add(egui::TextEdit::singleline(
                                                                &mut self.relay_code_input)
                                                                .hint_text("XXXX-XXXX")
                                                                .desired_width(f32::INFINITY)
                                                                .frame(false));
                                                        });
                                                    ui.add_space(6.0);
                                                    let can = self.relay_code_input.trim().len() == 9;
                                                    ui.add_enabled_ui(can, |ui| {
                                                        if ui.add(egui::Button::new(
                                                            RichText::new("  Connect  ").size(12.5)
                                                            .color(Color32::WHITE))
                                                            .fill(if can { p.accent } else { p.text_faint })
                                                            .corner_radius(8.0)
                                                            .min_size(Vec2::new(ui.available_width(), 36.0))).clicked()
                                                            || (ui.input(|i| i.key_pressed(egui::Key::Enter)) && can)
                                                        {
                                                            self.connect_via_relay();
                                                        }
                                                    });
                                                });
                                            });

                                    });
                                });
                            } else {
                                // Device is offline - show offline message
                                ui.add_space(60.0);
                                ui.vertical_centered(|ui| {
                                    ui.label(RichText::new("📡").size(40.0));
                                    ui.add_space(12.0);
                                    ui.label(RichText::new("No Internet Connection")
                                        .size(16.0).strong().color(p.text));
                                    ui.add_space(8.0);
                                    ui.label(RichText::new(
                                        "Please check your network connection and try again.")
                                        .size(12.0).color(p.text_dim));
                                    ui.add_space(16.0);
                                    if ui.add(pill_btn("Check Again", p.accent)).clicked() {
                                        self.is_online = self.check_internet_connection();
                                    }
                                });
                            }

                            if let Some((ref msg, is_err)) = self.remote_msg && !self.is_online {
                                ui.add_space(8.0);
                                let col = if is_err { p.danger } else { p.success };
                                ui.label(RichText::new(msg).size(11.0).color(col));
                            }

                            // Instructions at the bottom
                            ui.add_space(32.0);
                            egui::Frame::new()
                                .fill(tint(p.surface2, 50))
                                .stroke(Stroke::new(1.0, p.border))
                                .corner_radius(8.0)
                                .inner_margin(egui::Margin::same(12))
                                .show(ui, |ui| {
                                    ui.set_width((ui.available_width() - 40.0).min(500.0));
                                    ui.vertical(|ui| {
                                        ui.label(RichText::new(format!("{}  How to use remote sharing:", icons::ICON_INFO))
                                            .size(11.0).strong().color(p.text_dim));
                                        ui.add_space(4.0);
                                        ui.label(RichText::new("1. Receiver clicks 'Go Online' to get a share code")
                                            .size(10.0).color(p.text_faint));
                                        ui.label(RichText::new("2. Receiver shares the code with the sender")
                                            .size(10.0).color(p.text_faint));
                                        ui.label(RichText::new("3. Sender enters the code and connects")
                                            .size(10.0).color(p.text_faint));
                                        ui.label(RichText::new("4. Files transfer securely via relay")
                                            .size(10.0).color(p.text_faint));
                                    });
                                });
                            ui.add_space(60.0);
                        }

                        // ── Connecting ────────────────────────────────────────────────
                        RelayState::Connecting => {
                            ui.add_space(60.0);
                            ui.vertical_centered(|ui| {
                                ui.spinner();
                                ui.add_space(12.0);
                                ui.label(RichText::new("Connecting to relay…")
                                    .size(13.0).color(p.text_dim));
                                ui.add_space(6.0);
                                ui.label(RichText::new("This only takes a moment")
                                    .size(11.0).color(p.text_faint));
                                ui.add_space(16.0);
                                if ui.add(pill_btn("Cancel", p.danger)).clicked() {
                                    self.go_offline();
                                }
                            });
                        }

                        // ── Online: receiver waiting with code ────────────────────────
                        RelayState::Online { ref code } => {
                            let code = code.clone();
                            ui.add_space(8.0);
                            ui.vertical_centered(|ui| {
                                // Status dot
                                ui.horizontal(|ui| {
                                    let (r, _) = ui.allocate_exact_size(Vec2::new(10.0, 10.0), Sense::hover());
                                    ui.painter().circle_filled(r.center(), 5.0, p.success);
                                    ui.add_space(6.0);
                                    ui.label(RichText::new("You're online — waiting for sender…")
                                        .size(12.0).color(p.success));
                                });
                                ui.add_space(20.0);

                                // Big code display
                                ui.label(RichText::new("Your share code").size(12.0).color(p.text_dim));
                                ui.add_space(8.0);
                                egui::Frame::new()
                                    .fill(tint(p.accent, 18))
                                    .stroke(Stroke::new(2.0, tint(p.accent, 60)))
                                    .corner_radius(12.0)
                                    .inner_margin(egui::Margin { left: 24, right: 24, top: 16, bottom: 16 })
                                    .show(ui, |ui| {
                                        ui.label(RichText::new(&code)
                                            .size(32.0).strong()
                                            .color(p.accent)
                                            .monospace());
                                    });

                                ui.add_space(12.0);
                                if ui.add(pill_btn("Copy code", p.accent)).clicked() {
                                    ui.ctx().copy_text(code.clone());
                                }
                                ui.add_space(6.0);
                                ui.label(RichText::new("Share this code with the sender.")
                                    .size(11.0).color(p.text_dim));
                                ui.label(RichText::new("Code expires when used or after 5 minutes.")
                                    .size(10.5).color(p.text_faint));
                                ui.add_space(16.0);
                                if ui.add(pill_btn("Cancel", p.danger)).clicked() {
                                    self.go_offline();
                                }
                            });
                        }

                        // ── Paired ────────────────────────────────────────────────────
                        RelayState::Paired { ref peer_name } => {
                            let peer_name = peer_name.clone();
                            ui.add_space(60.0);
                            ui.vertical_centered(|ui| {
                                ui.label(RichText::new(icons::ICON_CHECK).size(36.0).color(p.success));
                                ui.add_space(8.0);
                                ui.label(RichText::new(format!("Connected to {}", peer_name))
                                    .size(14.0).strong().color(p.text));
                                ui.add_space(4.0);
                                ui.label(RichText::new("Switching to Send tab…")
                                    .size(11.0).color(p.text_dim));
                            });
                        }
                    }
                });
            });
    }


    fn show_send(&mut self, ui: &mut egui::Ui, ctx: &egui::Context, wide: bool) {
        let avail = ui.available_size();
        let pad = if wide { 28.0f32 } else { 16.0f32 };
        let gap = 16.0f32;
        if let Some(peer) = self.selected_peer().cloned() {
            let p2 = self.p();
            egui::Frame::new()
                .fill(tint(p2.accent, 15))
                .stroke(Stroke::new(1.0, tint(p2.accent, 45)))
                .corner_radius(6.0)
                .inner_margin(egui::Margin { left: 12, right: 8, top: 6, bottom: 6 })
                .show(ui, |ui| {
                    ui.set_min_width(ui.available_width());
                    ui.horizontal(|ui| {
                        ui.painter().circle_filled(
                            ui.cursor().left_top() + Vec2::new(4.0, 8.0),
                            4.0, p2.success);
                        ui.add_space(12.0);
                        ui.label(RichText::new(format!(
                            "Selected  {}  ·  {}", peer.name, peer.addr))
                            .size(12.0).color(p2.accent));
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.add(egui::Button::new(
                                RichText::new("Change").size(11.0).color(p2.text_dim))
                                .frame(false)).clicked()
                            {
                                self.scan_mode = ScanMode::Local;
                                self.tab = Tab::Scan;
                                self.start_scan();
                            }
                        });
                    });
                });
            ui.add_space(8.0);
        } else {
            let p2 = self.p();
            egui::Frame::new()
                .fill(tint(p2.warn, 10))
                .stroke(Stroke::new(1.0, tint(p2.warn, 40)))
                .corner_radius(6.0)
                .inner_margin(egui::Margin { left: 12, right: 8, top: 6, bottom: 6 })
                .show(ui, |ui| {
                    ui.set_min_width(ui.available_width());
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("⚠  No device selected")
                            .size(12.0).color(p2.warn));
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.add(egui::Button::new(
                                RichText::new("Scan now").size(11.0).color(p2.accent))
                                .frame(false)).clicked()
                            {
                                self.scan_mode = ScanMode::Local;
                                self.tab = Tab::Scan;
                                self.start_scan();
                            }
                        });
                    });
                });
            ui.add_space(8.0);
        }
        if wide {
            let col = (avail.x - pad * 2.0 - gap) / 2.0;
            ui.add_space(24.0);
            ui.allocate_ui_with_layout(
                Vec2::new(avail.x, avail.y - 24.0),
                egui::Layout::left_to_right(egui::Align::TOP),
                |ui| {
                    ui.add_space(pad);
                    ui.vertical(|ui| {
                        ui.set_width(col);
                        self.card_queue(ui, ctx);
                    });
                    ui.add_space(gap);
                    ui.vertical(|ui| {
                        ui.set_width(col);
                        self.card_send_action(ui, ctx);
                    });
                },
            );
        } else {
            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    ui.add_space(20.0);
                    ui.horizontal(|ui| {
                        ui.add_space(pad);
                        ui.vertical(|ui| {
                            ui.set_width(avail.x - pad * 2.0);
                            self.card_queue(ui, ctx);
                            ui.add_space(14.0);
                            self.card_send_action(ui, ctx);
                            ui.add_space(20.0);
                        });
                    });
                });
        }
    }

    fn card_queue(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let p = self.p();
        let hovering_drop = ctx.input(|i| !i.raw.hovered_files.is_empty());
        let has_items = !self.queue.is_empty();
        let done_count = self.queue.iter().filter(|q| q.is_done()).count();
        let failed_count = self.queue.iter().filter(|q| q.is_failed()).count();
        card(ui, &p, |ui| {
            ui.horizontal(|ui| {
                icon_badge(ui, "📂", Color32::from_rgb(255, 178, 55));
                ui.add_space(8.0);
                let hdr = if has_items {
                    format!("Files  ({})", self.queue.len())
                } else {
                    "Files to Send".to_string()
                };
                ui.label(RichText::new(hdr).strong().size(14.0).color(p.text));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let lbl = if has_items {
                        "Add files…"
                    } else {
                        "Browse…"
                    };
                    if ui.add(pill_btn(lbl, p.accent)).clicked() {
                        if let Some(paths) = rfd::FileDialog::new().pick_files() {
                            self.add_files(paths);
                        }
                    }
                    if done_count > 0 {
                        ui.add_space(4.0);
                        if ui.add(pill_btn("Clear done", p.text_dim)).clicked() {
                            self.clear_done();
                        }
                    }
                    if failed_count > 0 {
                        ui.add_space(4.0);
                        if ui.add(pill_btn("Retry failed", p.warn)).clicked() {
                            self.retry_failed();
                        }
                    }
                });
            });
            ui.add_space(10.0);
            ui.separator();
            ui.add_space(10.0);
            if has_items {
                let mut remove_idx: Option<usize> = None;
                let items = self.queue.clone();
                for (i, item) in items.iter().enumerate() {
                    queue_item_row(ui, &p, item, i, &mut remove_idx);
                    ui.add_space(4.0);
                }
                if let Some(idx) = remove_idx {
                    self.remove_queue_item(idx);
                }
                ui.add_space(4.0);
                drop_hint(ui, &p, hovering_drop);
            } else {
                drop_zone(ui, &p, hovering_drop);
            }
        });
    }

    fn card_send_action(&mut self, ui: &mut egui::Ui, _ctx: &egui::Context) {
        let p = self.p();
        let peer_ok = self.selected.is_some();
        let has_pending = self.queue.iter().any(|q| q.is_pending());
        let active = self.any_active();
        let can_send = peer_ok && has_pending && !active;
        let pending_count = self.queue.iter().filter(|q| q.is_pending()).count();
        card(ui, &p, |ui| {
            if active {
                let total = self.queue.len();
                let done = self.queue.iter().filter(|q| q.is_done()).count();
                let failed = self.queue.iter().filter(|q| q.is_failed()).count();
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.add_space(6.0);
                    let sending = total.saturating_sub(done + failed + pending_count);
                    ui.label(
                        RichText::new(format!(
                            "Sending {} file{}…",
                            sending,
                            if sending == 1 { "" } else { "s" }
                        ))
                        .size(13.0)
                        .color(p.text),
                    );
                });
                ui.add_space(8.0);
                let overall = if total > 0 {
                    self.queue
                        .iter()
                        .map(|q| q.progress.unwrap_or(0.0).max(0.0))
                        .sum::<f32>()
                        / total as f32
                } else {
                    0.0
                };
                ui.add(
                    egui::ProgressBar::new(overall)
                        .desired_width(ui.available_width())
                        .desired_height(9.0)
                        .text(RichText::new(format!("{}/{} files", done, total)).size(10.0)),
                );
                if done + failed == total {
                    ui.add_space(8.0);
                    let msg = if failed > 0 {
                        format!("{} sent  {}  {} failed", done, icons::ICON_CHECK, failed)
                    } else {
                        format!(
                            "{} All {} file{} sent!",
                            icons::ICON_CHECK,
                            total,
                            if total == 1 { "" } else { "s" }
                        )
                    };
                    ui.label(RichText::new(msg).size(12.0).color(if failed > 0 {
                        p.warn
                    } else {
                        p.success
                    }));
                }
            } else {
                ui.horizontal(|ui| {
                    check_item(ui, &p, !self.queue.is_empty(), "Files added");
                });
                ui.add_space(12.0);
                let btn_label = if pending_count > 0 {
                    format!(
                        "  {}  Send {} file{}  ",
                        icons::ICON_SEND,
                        pending_count,
                        if pending_count == 1 { "" } else { "s" }
                    )
                } else {
                    format!("  {}  Send Now  ", icons::ICON_SEND)
                };
                let btn_fill = if can_send { p.accent } else { p.text_faint };
                let btn_txt = if can_send { Color32::WHITE } else { p.text_dim };
                ui.add_enabled_ui(can_send, |ui| {
                    if ui
                        .add(
                            egui::Button::new(
                                RichText::new(&btn_label).size(14.0).strong().color(btn_txt),
                            )
                            .fill(btn_fill)
                            .corner_radius(12.0)
                            .min_size(Vec2::new(ui.available_width(), 48.0)),
                        )
                        .clicked()
                    {
                        self.start_send_queue();
                    }
                });
                if !can_send {
                    ui.add_space(6.0);
                    let hint = match (peer_ok, !self.queue.is_empty(), has_pending) {
                        (false, false, _) => "Select a device and add files above",
                        (false, _, _) => "Select a destination device above",
                        (_, false, _) => "Add files to the queue above",
                        _ => "No pending files to send",
                    };
                    ui.label(RichText::new(hint).size(11.0).color(p.text_faint));
                }
            }
        });
    }

    fn show_history(&mut self, ui: &mut egui::Ui, _ctx: &egui::Context, wide: bool) {
        let p = self.p();
        let avail_w = ui.available_width();
        let col_w = if wide {
            (avail_w - 64.0).min(700.0)
        } else {
            avail_w - 32.0
        };
        let x_pad = (avail_w - col_w) / 2.0;
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.add_space(24.0);
                ui.horizontal(|ui| {
                    ui.add_space(x_pad);
                    ui.vertical(|ui| {
                        ui.set_width(col_w);

                        ui.horizontal(|ui| {
                            if !self.history.is_empty() {
                                icon_badge(ui, "📜", p.accent);
                                ui.add_space(8.0);
                                ui.label(
                                    RichText::new("Transfer History")
                                        .strong()
                                        .size(15.0)
                                        .color(p.text),
                                );
                            }

                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    if !self.history.is_empty() {
                                        if ui.add(pill_btn("Clear all", p.danger)).clicked() {
                                            if let Some(path) = history_path() {
                                                let _ = fs::remove_file(&path);
                                            }
                                            self.history.clear();
                                            self.history_filter.clear();
                                        }
                                        ui.add_space(6.0);
                                        let count = self.history.len();
                                        ui.label(
                                            RichText::new(format!(
                                                "{} transfer{}",
                                                count,
                                                if count == 1 { "" } else { "s" }
                                            ))
                                            .size(11.0)
                                            .color(p.text_faint),
                                        );
                                    }
                                },
                            );
                        });
                        ui.add_space(10.0);

                        if !self.history.is_empty() {
                            egui::Frame::new()
                                .fill(p.surface2)
                                .stroke(Stroke::new(
                                    1.0,
                                    if !self.history_filter.is_empty() {
                                        p.accent
                                    } else {
                                        p.border
                                    },
                                ))
                                .corner_radius(8.0)
                                .inner_margin(egui::Margin {
                                    left: 10,
                                    right: 10,
                                    top: 6,
                                    bottom: 6,
                                })
                                .show(ui, |ui| {
                                    ui.set_min_width(ui.available_width());
                                    ui.horizontal(|ui| {
                                        ui.label(
                                            RichText::new(icons::ICON_SEARCH)
                                                .size(14.0)
                                                .color(p.text_dim),
                                        );
                                        ui.add_space(3.0);

                                        let resp = ui.add(
                                            egui::TextEdit::singleline(&mut self.history_filter)
                                                .hint_text("Search by filename or device…")
                                                .desired_width(ui.available_width() - 33.0)
                                                .frame(false),
                                        );
                                        if !self.history_filter.is_empty() {
                                            if ui
                                                .add(
                                                    egui::Button::new(
                                                        RichText::new(icons::ICON_CLOSE)
                                                            .size(12.0)
                                                            .color(p.text_dim),
                                                    )
                                                    .frame(false),
                                                )
                                                .clicked()
                                            {
                                                self.history_filter.clear();
                                            }
                                        }
                                        let _ = resp;
                                    });
                                });
                        }
                        ui.add_space(12.0);
                        let filter = self.history_filter.to_lowercase();
                        let entries: Vec<HistoryEntry> = self
                            .history
                            .iter()
                            .filter(|e| {
                                filter.is_empty()
                                    || e.file_name.to_lowercase().contains(&filter)
                                    || e.peer_name.to_lowercase().contains(&filter)
                            })
                            .cloned()
                            .collect();
                        if entries.is_empty() {
                            ui.vertical_centered(|ui| {
                                ui.add_space(60.0);
                                ui.label(RichText::new("📭").size(52.0));
                                ui.add_space(14.0);
                                ui.label(
                                    RichText::new(if filter.is_empty() {
                                        "No transfers yet"
                                    } else {
                                        "No results"
                                    })
                                    .strong()
                                    .size(15.0)
                                    .color(p.text),
                                );
                                ui.add_space(6.0);
                                ui.label(
                                    RichText::new(
                                        "File transfers appear here when you send or receive files",
                                    )
                                    .size(12.0)
                                    .color(p.text_dim),
                                );
                                ui.add_space(4.0);
                                if let Some(dir) = dirs::download_dir() {
                                    ui.label(
                                        RichText::new(format!(
                                            "All files saved to {}",
                                            dir.display()
                                        ))
                                        .size(11.0)
                                        .color(p.text_faint),
                                    );
                                }
                            });
                        } else {
                            for entry in &entries {
                                history_row(ui, &p, entry);
                                ui.add_space(6.0);
                            }
                        }
                    });
                });
                ui.add_space(24.0);
            });
    }

    fn show_sync(&mut self, ui: &mut egui::Ui, ctx: &egui::Context, wide: bool) {
        let p = self.p();
        let avail_w = ui.available_width();
        let col_w = if wide {
            (avail_w - 64.0).min(700.0)
        } else {
            avail_w - 32.0
        };
        let x_pad = (avail_w - col_w) / 2.0;
        let peer_available = self.selected_peer_available();
        let is_relay_mode = self.is_relay_mode;

        // Clone the sync log to avoid borrowing issues
        let sync_log_clone = if is_relay_mode {
            self.relay_sync_log.clone()
        } else {
            self.sync_log.clone()
        };
        let sync_active = if is_relay_mode { self.relay_sync_active } else { self.sync_active };
        let current_folder = if is_relay_mode {
            self.selected_peer()
                .and_then(|peer| self.relay_sync_map.get(&peer.addr.to_string()))
                .cloned()
        } else {
            self.selected_peer()
                .and_then(|peer| self.sync_map.get(&peer.addr.to_string()))
                .cloned()
        };
        let sent_count = if is_relay_mode {
            self.relay_sync_jobs.first().map(|j| j.file_mtimes.len()).unwrap_or(0)
        } else {
            self.sync_jobs.first().map(|j| j.file_mtimes.len()).unwrap_or(0)
        };
        let has_folder = if is_relay_mode {
            self.selected_peer()
                .and_then(|p| self.relay_sync_map.get(&p.addr.to_string()))
                .is_some()
        } else {
            self.selected_peer()
                .and_then(|p| self.sync_map.get(&p.addr.to_string()))
                .is_some()
        };

        egui::ScrollArea::vertical().auto_shrink([false,false]).show(ui, |ui| {
            ui.add_space(24.0);
            ui.horizontal(|ui| {
                ui.add_space(x_pad);
                ui.vertical(|ui| {
                    ui.set_width(col_w);

                    ui.horizontal(|ui| {
                        icon_badge(ui, "📁", p.accent);
                        ui.add_space(8.0);
                        if is_relay_mode {
                            ui.label(RichText::new("Remote Folder Sync").strong().size(15.0).color(p.text));
                        } else {
                            ui.label(RichText::new("Folder Sync").strong().size(15.0).color(p.text));
                        }
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if is_relay_mode {
                                if sync_active {
                                    if ui.add(pill_btn(&format!("{}  Stop remote sync", icons::ICON_STOP_CIRCLE), p.danger)).clicked() {
                                        self.stop_relay_sync();
                                    }
                                    ui.add_space(8.0);
                                    ui.spinner();
                                    ui.add_space(4.0);
                                    ui.label(RichText::new("Syncing remotely…").size(11.0).color(p.success));
                                } else if peer_available {
                                    if has_folder {
                                        if ui.add(big_btn(&format!("{}  Start remote sync", icons::ICON_SYNC), p.accent)).clicked() {
                                            self.rebuild_relay_sync_jobs();
                                            self.start_relay_sync_watcher();
                                        }
                                    }
                                }
                            } else {
                                if sync_active {
                                    if ui.add(pill_btn(&format!("{}  Stop watching", icons::ICON_STOP_CIRCLE), p.danger)).clicked() {
                                        self.stop_sync();
                                    }
                                    ui.add_space(8.0);
                                    ui.spinner();
                                    ui.add_space(4.0);
                                    ui.label(RichText::new("Watching…").size(11.0).color(p.success));
                                } else if peer_available {
                                    if has_folder {
                                        if ui.add(big_btn(&format!("{}  Start watching", icons::ICON_SYNC), p.accent)).clicked() {
                                            self.rebuild_sync_jobs();
                                            self.start_sync_watcher();
                                        }
                                    }
                                }
                            }
                        });
                    });
                    ui.add_space(6.0);

                    if is_relay_mode {
                        ui.label(RichText::new("Add folders below. New files added will be automatically sent to the remote device via relay.")
                            .size(12.0).color(p.text_dim));
                    } else {
                        ui.label(RichText::new("Add folders below. New files dropped in are automatically sent to the selected device.")
                            .size(12.0).color(p.text_dim));
                    }
                    ui.add_space(14.0);

                    if !peer_available {
                        egui::Frame::new().fill(tint(p.warn,12)).stroke(Stroke::new(1.0,tint(p.warn,50)))
                            .corner_radius(8.0).inner_margin(egui::Margin::same(12))
                            .show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    ui.label(RichText::new("⚠").size(14.0).color(p.warn));
                                    ui.add_space(6.0);
                                    if is_relay_mode {
                                        ui.label(RichText::new("No remote connection active. Connect via remote mode first.")
                                            .size(12.0).color(p.warn));
                                    } else if !self.saved_peer_name.is_empty() {
                                        ui.label(RichText::new(format!("{} is not available  ·  scan to reconnect",
                                            self.saved_peer_name)).size(12.0).color(p.warn));
                                    } else {
                                        ui.label(RichText::new("Select a device on the Send tab first")
                                            .size(12.0).color(p.warn));
                                    }
                                });
                            });
                        ui.add_space(12.0);
                    }

                    ui.add_enabled_ui(peer_available, |ui| {
                        let btn_text = if is_relay_mode {
                            if has_folder { &format!("{}  Change remote folder", icons::ICON_FOLDER) }
                            else { &format!("{}  Set remote folder to sync", icons::ICON_FOLDER) }
                        } else {
                            if has_folder { &format!("{}  Change folder", icons::ICON_FOLDER) }
                            else { &format!("{}  Set folder to watch", icons::ICON_FOLDER) }
                        };
                        if ui.add(pill_btn(btn_text, p.accent)).clicked() {
                            if !self.is_pro() {
                                self.show_upgrade = true;
                            } else if is_relay_mode && !self.is_relay_mode {
                                self.remote_msg = Some(("Please connect via remote mode first".into(), true));
                            } else if let Some(folder) = rfd::FileDialog::new().pick_folder() {
                                if is_relay_mode {
                                    self.add_relay_sync_folder(folder);
                                } else {
                                    self.add_sync_folder(folder);
                                }
                            }
                        }
                    });
                    ui.add_space(12.0);

                    if let Some(ref folder) = current_folder {
                        let folder_exists = folder.exists();
                        let border_col = if !folder_exists { tint(p.warn, 55) }
                                            else if sync_active { tint(p.success, 55) }
                                            else { p.border };
                        let fill_col   = if !folder_exists { tint(p.warn, 10) }
                                            else if sync_active { tint(p.success, 8) }
                                            else { p.surface };

                        egui::Frame::new().fill(fill_col).stroke(Stroke::new(1.0, border_col))
                            .corner_radius(10.0)
                            .inner_margin(egui::Margin { left:14, right:14, top:12, bottom:12 })
                            .show(ui, |ui| {
                                ui.set_min_width(ui.available_width());
                                ui.horizontal(|ui| {
                                    let (r, _) = ui.allocate_exact_size(Vec2::splat(38.0), Sense::hover());
                                    let ic_col = if !folder_exists { p.warn } else { p.accent };
                                    ui.painter().circle_filled(r.center(), 18.0, tint(ic_col, 20));
                                    ui.painter().text(r.center(), egui::Align2::CENTER_CENTER,
                                        icons::ICON_FOLDER, egui::FontId::proportional(17.0), ic_col);
                                    ui.add_space(12.0);

                                    ui.vertical(|ui| {
                                        ui.horizontal(|ui| {
                                            ui.label(RichText::new(
                                                folder.file_name().unwrap_or_default().to_string_lossy())
                                                .strong().size(13.0).color(p.text));
                                            ui.add_space(6.0);
                                            if sync_active {
                                                if is_relay_mode {
                                                    status_badge(ui, "REMOTE SYNC", p.success);
                                                } else {
                                                    status_badge(ui, "WATCHING", p.success);
                                                }
                                            }
                                            if !folder_exists {
                                                status_badge(ui, "MISSING", p.warn);
                                            }
                                        });
                                        let full = folder.to_string_lossy();
                                        let display = if full.len() > 50 {
                                            format!("…{}", &full[full.len().saturating_sub(48)..])
                                        } else { full.to_string() };
                                        let sync_text = if is_relay_mode {
                                            format!("{}  ·  {} file{} synced remotely",
                                                display, sent_count, if sent_count==1{""} else{"s"})
                                        } else {
                                            format!("{}  ·  {} file{} synced",
                                                display, sent_count, if sent_count==1{""} else{"s"})
                                        };
                                        ui.label(RichText::new(sync_text)
                                            .size(11.0).color(p.text_dim));
                                    });

                                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                        if ui.add(egui::Button::new(
                                            RichText::new(icons::ICON_CLOSE).size(13.0).color(p.text_dim))
                                            .frame(false)).clicked()
                                        {
                                            if is_relay_mode {
                                                self.remove_relay_sync_folder();
                                            } else {
                                                self.remove_sync_folder();
                                            }
                                        }
                                    });
                                });
                            });
                    } else {
                        ui.vertical_centered(|ui| {
                            ui.add_space(30.0);
                            ui.label(RichText::new("📁").size(44.0));
                            ui.add_space(10.0);
                            ui.label(RichText::new("No folder selected yet")
                                .size(13.0).color(p.text_dim));
                            ui.add_space(4.0);
                            let help_text = if is_relay_mode {
                                "Click 'Set remote folder' above. New files added will be automatically sent to the remote device via relay."
                            } else {
                                "Click 'Set folder' above, new files added will be automatically sent to the selected device."
                            };
                            ui.label(RichText::new(help_text)
                                .size(11.0).color(p.text_faint));
                            ui.add_space(18.0);
                        });
                    }

                    if !sync_log_clone.is_empty() && peer_available {
                        ui.add_space(16.0);
                        ui.separator();
                        ui.add_space(8.0);
                        ui.horizontal(|ui| {
                            ui.label(
                                RichText::new("Activity log")
                                    .size(12.0).strong().color(p.text_dim),
                            );
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                    if ui.add(pill_btn("Clear", p.text_faint)).clicked() {
                                        if is_relay_mode {
                                            self.relay_sync_log.clear();
                                        } else {
                                            self.sync_log.clear();
                                        }
                                    }
                                },
                            );
                        });
                        ui.add_space(6.0);

                        let remaining = ui.available_height().max(180.0);
                        egui::Frame::new()
                            .fill(p.surface2)
                            .corner_radius(8.0)
                            .inner_margin(egui::Margin::same(10))
                            .show(ui, |ui| {
                                ui.set_min_size(Vec2::new(ui.available_width(), remaining - 20.0));
                                egui::ScrollArea::vertical()
                                    .max_height(f32::INFINITY)
                                    .auto_shrink([false, false])
                                    .stick_to_bottom(true)
                                    .show(ui, |ui| {
                                        ui.set_min_width(ui.available_width());
                                        for line in sync_log_clone.iter().rev() {
                                            let col = if line.starts_with("OK") { p.success }
                                                        else if line.starts_with("...") { p.text_dim }
                                                        else { p.danger };
                                            ui.label(
                                                RichText::new(line).size(11.0).color(col),
                                            );
                                        }
                                    });
                            });
                    }
                });
            });
            ui.add_space(24.0);
        });

        if self.sync_active || self.relay_sync_active {
            ctx.request_repaint_after(std::time::Duration::from_millis(500));
        }
    }

    fn show_settings(&mut self, ui: &mut egui::Ui, _ctx: &egui::Context, wide: bool) {
        let p = self.p();
        let avail_w = ui.available_width();
        let col_w = if wide {
            (avail_w - 64.0).min(520.0)
        } else {
            avail_w - 32.0
        };
        let x_pad = (avail_w - col_w) / 2.0;
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.add_space(24.0);
                ui.horizontal(|ui| {
                    ui.add_space(x_pad);
                    ui.vertical(|ui| {
                        ui.set_width(col_w);
                        ui.horizontal(|ui| {
                            for (lbl, st) in [
                                ("Device", SettingsTab::Device),
                                ("Preferences", SettingsTab::Preferences),
                                ("License", SettingsTab::License),
                                ("About", SettingsTab::About),
                            ] {
                                let active = self.settings_tab == st;
                                let col = if active { p.accent } else { p.text_dim };
                                let resp = ui.add(
                                    egui::Button::new(RichText::new(lbl).size(13.0).color(col))
                                        .frame(false),
                                );
                                if resp.clicked() {
                                    self.settings_tab = st;
                                }
                                if active {
                                    let r = resp.rect;
                                    ui.painter().line_segment(
                                        [
                                            egui::pos2(r.left(), r.bottom() + 2.0),
                                            egui::pos2(r.right(), r.bottom() + 2.0),
                                        ],
                                        Stroke::new(2.0, p.accent),
                                    );
                                }
                                ui.add_space(16.0);
                            }
                        });
                        ui.separator();
                        ui.add_space(14.0);
                        match self.settings_tab {
                            SettingsTab::Device => self.show_device_panel(ui),
                            SettingsTab::License => self.show_license_panel(ui),
                            SettingsTab::About => self.show_about_panel(ui),
                            SettingsTab::Preferences => self.show_preferences_panel(ui),
                        }
                    });
                });
                ui.add_space(24.0);
            });
    }

    fn show_device_panel(&self, ui: &mut egui::Ui) {
        let p = self.p();

        ui.label(
            RichText::new("This Device")
                .strong()
                .size(13.0)
                .color(p.text_dim),
        );
        ui.add_space(8.0);

        egui::Frame::new()
            .fill(p.surface2)
            .stroke(Stroke::new(1.0, p.border))
            .corner_radius(10.0)
            .inner_margin(egui::Margin::same(14))
            .show(ui, |ui| {
                ui.set_min_width(ui.available_width());

                let this_hostname = self.this_hostname.as_str();
                let this_ip = self.this_ip.as_str();

                info_row(ui, &p, icons::ICON_DEVICES, "Hostname", &this_hostname);
                ui.add_space(8.0);
                info_row(ui, &p, icons::ICON_WIFI, "Local IP", &this_ip);
                ui.add_space(8.0);
                info_row(
                    ui,
                    &p,
                    icons::ICON_LOCK,
                    "Transfer port",
                    &format!("TCP {TRANSFER_PORT}  ·  UDP {DISCOVER_PORT}"),
                );
                ui.add_space(8.0);
                info_row(
                    ui,
                    &p,
                    icons::ICON_SECURITY,
                    "Encryption",
                    "X25519 ECDH + AES-256-GCM (per connection)",
                );
            });

        ui.add_space(20.0);

        ui.label(
            RichText::new("Connected Device")
                .strong()
                .size(13.0)
                .color(p.text_dim),
        );
        ui.add_space(8.0);

        if let Some(peer) = self.selected_peer() {
            egui::Frame::new()
                .fill(tint(p.accent, 12))
                .stroke(Stroke::new(1.0, tint(p.accent, 50)))
                .corner_radius(10.0)
                .inner_margin(egui::Margin::same(14))
                .show(ui, |ui| {
                    ui.set_min_width(ui.available_width());
                    ui.horizontal(|ui| {
                        let av = ui.label(
                            RichText::new(
                                peer.name
                                    .chars()
                                    .next()
                                    .unwrap_or('?')
                                    .to_uppercase()
                                    .to_string(),
                            )
                            .size(22.0)
                            .strong()
                            .color(p.accent2),
                        );
                        let _ = av;
                    });
                    ui.add_space(6.0);
                    info_row(ui, &p, icons::ICON_DEVICES, "Name", &peer.name);
                    ui.add_space(8.0);
                    info_row(ui, &p, icons::ICON_WIFI, "Address", &peer.addr.to_string());
                    ui.add_space(8.0);
                    let sync_folder = self
                        .sync_map
                        .get(&peer.addr.to_string())
                        .and_then(|p| p.file_name())
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_else(|| "None".to_string());
                    info_row(ui, &p, icons::ICON_FOLDER, "Sync folder", &sync_folder);
                    ui.add_space(8.0);
                    let status_text = if self.sync_active {
                        "Watching  ●"
                    } else {
                        "Idle"
                    };
                    let status_col = if self.sync_active {
                        p.success
                    } else {
                        p.text_dim
                    };
                    ui.horizontal(|ui| {
                        let (r, _) = ui.allocate_exact_size(Vec2::new(20.0, 16.0), Sense::hover());
                        ui.painter().text(
                            r.center(),
                            egui::Align2::CENTER_CENTER,
                            icons::ICON_SYNC,
                            egui::FontId::proportional(13.0),
                            p.text_faint,
                        );
                        ui.add_space(8.0);
                        ui.label(RichText::new("Sync status").size(11.0).color(p.text_faint));
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            ui.label(
                                RichText::new(status_text)
                                    .size(11.5)
                                    .strong()
                                    .color(status_col),
                            );
                        });
                    });
                });
        } else if !self.saved_peer_name.is_empty() {
            egui::Frame::new()
                .fill(tint(p.warn, 10))
                .stroke(Stroke::new(1.0, tint(p.warn, 45)))
                .corner_radius(10.0)
                .inner_margin(egui::Margin::same(14))
                .show(ui, |ui| {
                    ui.set_min_width(ui.available_width());
                    info_row(
                        ui,
                        &p,
                        icons::ICON_DEVICES,
                        "Last used",
                        &self.saved_peer_name,
                    );
                    ui.add_space(8.0);
                    info_row(ui, &p, icons::ICON_WIFI, "Address", &self.saved_peer_addr);
                    ui.add_space(8.0);
                    ui.label(
                        RichText::new(format!(
                            "  {}  Not on network  —  scan to reconnect",
                            icons::ICON_WIFI_OFF
                        ))
                        .size(11.0)
                        .color(p.warn),
                    );
                });
        } else {
            egui::Frame::new()
                .fill(p.surface2)
                .stroke(Stroke::new(1.0, p.border))
                .corner_radius(10.0)
                .inner_margin(egui::Margin::same(14))
                .show(ui, |ui| {
                    ui.label(
                        RichText::new("No device selected yet")
                            .size(12.0)
                            .color(p.text_faint),
                    );
                    ui.add_space(4.0);
                    ui.label(
                        RichText::new("Go to the Send tab, scan, and select a device.")
                            .size(11.0)
                            .color(p.text_faint),
                    );
                });
        }
    }

    fn show_license_panel(&mut self, ui: &mut egui::Ui) {
        let p = self.p();
        if self.is_pro() {
            egui::Frame::new()
                .fill(tint(p.pro, 15))
                .stroke(Stroke::new(1.0, tint(p.pro, 55)))
                .corner_radius(12.0)
                .inner_margin(egui::Margin::same(16))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("★").size(24.0).color(p.pro));
                        ui.add_space(10.0);
                        ui.vertical(|ui| {
                            ui.label(
                                RichText::new(format!("{} Pro — Active", env!("CARGO_PKG_NAME")))
                                    .strong()
                                    .size(14.0)
                                    .color(p.pro),
                            );
                            ui.label(
                                RichText::new(&self.license.email)
                                    .size(12.0)
                                    .color(p.text_dim),
                            );
                        });
                    });
                    ui.add_space(12.0);
                    if ui.add(pill_btn("Deactivate", p.danger)).clicked() {
                        self.license = License {
                            plan: Plan::Free,
                            email: String::new(),
                            key: String::new(),
                        };
                        if let Some(path) = License::config_path() {
                            let _ = fs::remove_file(path);
                        }
                        self.license_msg = Some(("License deactivated.".into(), false));
                    }
                });
        } else {
            ui.label(
                RichText::new("Activate Pro License")
                    .strong()
                    .size(14.0)
                    .color(p.text),
            );
            ui.add_space(8.0);
            ui.label(RichText::new("Email").size(11.0).color(p.text_dim));
            ui.add(
                egui::TextEdit::singleline(&mut self.license_email_buf)
                    .hint_text("your@email.com")
                    .desired_width(f32::INFINITY),
            );
            ui.add_space(8.0);
            ui.label(RichText::new("License Key").size(11.0).color(p.text_dim));
            ui.add(
                egui::TextEdit::singleline(&mut self.license_key_buf)
                    .hint_text("XXXXX-XXXXX-XXXXX-XXXXX-XXXXX")
                    .desired_width(f32::INFINITY),
            );
            ui.add_space(12.0);
            let can = !self.license_email_buf.is_empty() && self.license_key_buf.len() >= 29;
            ui.add_enabled_ui(can, |ui| {
                if ui
                    .add(
                        egui::Button::new(
                            RichText::new("  Activate  ")
                                .size(13.0)
                                .strong()
                                .color(Color32::WHITE),
                        )
                        .fill(p.accent)
                        .corner_radius(10.0)
                        .min_size(Vec2::new(ui.available_width(), 42.0)),
                    )
                    .clicked()
                {
                    if License::validate_key(&self.license_key_buf) {
                        self.license = License {
                            plan: Plan::Pro,
                            email: self.license_email_buf.clone(),
                            key: self.license_key_buf.clone(),
                        };
                        self.license.save();
                        self.license_msg =
                            Some((format!("Pro activated! Enjoy {} Pro.", env!("CARGO_PKG_NAME")).into(), false));
                        self.license_key_buf.clear();
                    } else {
                        self.license_msg =
                            Some(("Invalid license key. Check and try again.".into(), true));
                    }
                }
            });
            ui.add_space(8.0);
            if ui.add(pill_btn("Buy a license", p.pro)).clicked() {
                open_url("https://github.com/sponsors/imrany");
            }
        }
        if let Some((msg, is_err)) = &self.license_msg {
            ui.add_space(10.0);
            let col = if *is_err { p.danger } else { p.success };
            ui.label(RichText::new(msg).size(12.0).color(col));
        }
    }

    fn show_about_panel(&self, ui: &mut egui::Ui) {
        let p = self.p();
        ui.vertical_centered(|ui| {
            ui.add_space(16.0);
            ui.add(
                egui::Image::new(egui::include_image!("../assets/icon.png"))
                    .fit_to_exact_size(Vec2::splat(64.0))
                    .corner_radius(14.0),
            );
            ui.add_space(10.0);
            ui.label(RichText::new(env!("CARGO_PKG_NAME").to_string()).strong().size(18.0).color(p.text));
            ui.label(
                RichText::new(format!("{}", self.version.clone()))
                    .size(12.0)
                    .color(p.text_dim),
            );
            ui.add_space(6.0);
            ui.label(
                RichText::new(env!("CARGO_PKG_DESCRIPTION").to_string())
                    .size(12.0)
                    .color(p.text_dim),
            );
            ui.add_space(16.0);
            for (label, url) in [
                ("GitHub", format!("{}", env!("CARGO_PKG_REPOSITORY"))),
                ("Changelog", format!("{}/releases", env!("CARGO_PKG_REPOSITORY"))),
                ("Bug Report", format!("{}/issues", env!("CARGO_PKG_REPOSITORY"))),
            ] {
                if ui.add(pill_btn(label, p.accent)).clicked() {
                    open_url(url.as_str());
                }
                ui.add_space(6.0);
            }
        });
    }

    fn check_for_update(&mut self) {
        if self.update_rx.is_some() || self.update_available.is_some() {
            return;
        }
        let current = self.version.clone();
        let (tx, rx) = std::sync::mpsc::channel::<Option<String>>();
        self.update_rx = Some(rx);

        thread::spawn(move || {
            let latest = fetch_latest_version();
            if let Some(latest) = latest {
                if is_newer(&latest, &current) {
                    let _ = tx.send(Some(latest));
                    return;
                }
            }
            let _ = tx.send(None);
        });
    }
}


fn history_row(ui: &mut egui::Ui, p: &Pal, entry: &HistoryEntry) {
    let file_exists = entry.file_exists();
    let is_received = entry.direction == TransferDir::Received;
    let is_remote = entry.transfer_type == TransferType::Remote;

    let (fill, border) = if !file_exists && is_received {
        (tint(p.warn, 10), tint(p.warn, 45))
    } else if !entry.success {
        (tint(p.danger, 10), tint(p.danger, 50))
    } else {
        (p.surface, p.border)
    };

    egui::Frame::new()
        .fill(fill)
        .stroke(Stroke::new(1.0, border))
        .corner_radius(10.0)
        .inner_margin(egui::Margin {
            left: 12,
            right: 12,
            top: 10,
            bottom: 10,
        })
        .show(ui, |ui| {
            ui.set_min_width(ui.available_width());

            let right_w = 88.0f32;
            let total_w = ui.available_width();
            let left_w = (total_w - right_w - 10.0).max(80.0);

            ui.horizontal(|ui| {
                let (dir_icon, dir_col) = if entry.direction == TransferDir::Sent {
                    (icons::ICON_UPLOAD, p.accent)
                } else {
                    (icons::ICON_DOWNLOAD, p.success)
                };
                let (r, _) = ui.allocate_exact_size(Vec2::splat(32.0), Sense::hover());
                ui.painter()
                    .circle_filled(r.center(), 15.0, tint(dir_col, 22));
                ui.painter().text(
                    r.center(),
                    egui::Align2::CENTER_CENTER,
                    dir_icon,
                    egui::FontId::proportional(14.0),
                    dir_col,
                );

                ui.add_space(10.0);
                ui.vertical(|ui| {
                    ui.set_width(left_w - 52.0);
                    ui.horizontal_wrapped(|ui| {
                        ui.label(
                            RichText::new(truncate_filename(&entry.file_name, 32))
                                .strong()
                                .size(12.5)
                                .color(p.text),
                        );
                        ui.add_space(4.0);
                        if !entry.success {
                            status_badge(ui, "FAILED", p.danger);
                        }
                        if !file_exists && is_received {
                            status_badge(ui, "DELETED", p.warn);
                        }
                        // Add remote/local badge
                        if is_remote {
                            status_badge(ui, "REMOTE", p.accent2);
                        } else {
                            status_badge(ui, "LOCAL", p.success);
                        }
                    });
                    ui.add_space(2.0);
                    let dir_word = if entry.direction == TransferDir::Sent {
                        "to"
                    } else {
                        "from"
                    };
                    ui.label(
                        RichText::new(format!(
                            "{} {}  ·  {}",
                            dir_word,
                            entry.peer_name,
                            format_size(entry.file_size)
                        ))
                        .size(11.0)
                        .color(p.text_dim),
                    );
                    if let Some(ref fpath) = entry.file_path {
                        let path_str = fpath.to_string_lossy();
                        let display = if path_str.len() > 50 {
                            format!("…{}", &path_str[path_str.len().saturating_sub(48)..])
                        } else {
                            path_str.to_string()
                        };
                        ui.label(RichText::new(display).size(10.0).color(p.text_faint));
                    }
                    if let Some(ref err) = entry.error {
                        ui.label(
                            RichText::new(truncate_filename(err, 50))
                                .size(10.5)
                                .color(p.danger),
                        );
                    }
                });

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.set_width(right_w);
                    ui.vertical(|ui| {
                        ui.set_width(right_w);
                        ui.with_layout(egui::Layout::top_down(egui::Align::RIGHT), |ui| {
                            ui.label(
                                RichText::new(entry.time_display())
                                    .size(10.5)
                                    .color(p.text_faint),
                            );
                            if is_received && file_exists {
                                if let Some(ref fpath) = entry.file_path {
                                    ui.add_space(4.0);
                                    if ui.add(pill_btn("Open folder", p.accent)).clicked() {
                                        open_folder(fpath);
                                    }
                                }
                            }
                        });
                    });
                });
            });
        });
}

// ─── Queue widgets ────────────────────────────────────────────────────────────
fn queue_item_row(
    ui: &mut egui::Ui,
    p: &Pal,
    item: &QueueItem,
    idx: usize,
    remove: &mut Option<usize>,
) {
    let (border_col, fill) = if item.is_done() {
        (tint(p.success, 55), tint(p.success, 10))
    } else if item.is_failed() {
        (tint(p.danger, 55), tint(p.danger, 10))
    } else if item.is_active() {
        (tint(p.accent, 55), tint(p.accent, 10))
    } else {
        (p.border, p.surface2)
    };
    egui::Frame::new()
        .fill(fill)
        .stroke(Stroke::new(1.0, border_col))
        .corner_radius(10.0)
        .inner_margin(egui::Margin {
            left: 10,
            right: 10,
            top: 8,
            bottom: 8,
        })
        .show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.label(RichText::new(file_icon(&item.name)).size(20.0));
                ui.add_space(6.0);
                ui.vertical(|ui| {
                    ui.horizontal(|ui| {
                        ui.label(
                            RichText::new(truncate_filename(&item.name, 35))
                                .strong()
                                .size(12.0)
                                .color(p.text),
                        );
                        ui.add_space(6.0);
                        if item.is_done() {
                            status_badge(ui, "DONE", p.success);
                        } else if item.is_failed() {
                            status_badge(ui, "FAILED", p.danger);
                        } else if item.is_active() {
                            status_badge(ui, "SENDING", p.accent);
                        }
                    });
                    ui.label(
                        RichText::new(format_size(item.size))
                            .size(10.5)
                            .color(p.text_dim),
                    );
                    if let Some(progress) = item.progress {
                        if progress < 1.0 {
                            ui.add_space(4.0);
                            ui.add(
                                egui::ProgressBar::new(progress.clamp(0.0, 1.0))
                                    .desired_width(ui.available_width())
                                    .desired_height(9.0)
                                    .text(
                                        RichText::new(format!("{:.0}%", progress * 100.0))
                                            .size(10.0),
                                    ),
                            );
                        }
                    }
                    if let Some(ref err) = item.error {
                        ui.label(RichText::new(err).size(10.0).color(p.danger));
                    }
                });
                if !item.is_active() {
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui
                            .add(
                                egui::Button::new(
                                    RichText::new(icons::ICON_CLOSE)
                                        .size(12.0)
                                        .color(p.text_dim),
                                )
                                .frame(false),
                            )
                            .clicked()
                        {
                            *remove = Some(idx);
                        }
                    });
                }
            });
        });
}

fn drop_zone(ui: &mut egui::Ui, p: &Pal, hovering: bool) {
    let (rect, _) = ui.allocate_exact_size(Vec2::new(ui.available_width(), 86.0), Sense::hover());
    let fill = if hovering {
        tint(p.accent, 22)
    } else {
        p.surface2
    };
    let stroke = if hovering {
        Stroke::new(2.0, p.accent)
    } else {
        Stroke::new(1.0, p.border)
    };
    ui.painter().rect(
        rect,
        CornerRadius::same(10),
        fill,
        stroke,
        egui::StrokeKind::Outside,
    );
    ui.painter().text(
        rect.center() - Vec2::new(0.0, 11.0),
        egui::Align2::CENTER_CENTER,
        icons::ICON_ARROW_UPWARD,
        egui::FontId::proportional(20.0),
        if hovering { p.accent } else { p.text_faint },
    );
    ui.painter().text(
        rect.center() + Vec2::new(0.0, 13.0),
        egui::Align2::CENTER_CENTER,
        if hovering {
            "Release to add files"
        } else {
            "Drag & drop files  or  Browse…"
        },
        egui::FontId::proportional(11.5),
        if hovering { p.text_dim } else { p.text_faint },
    );
}

fn drop_hint(ui: &mut egui::Ui, p: &Pal, hovering: bool) {
    let (rect, _) = ui.allocate_exact_size(Vec2::new(ui.available_width(), 34.0), Sense::hover());
    let fill = if hovering {
        tint(p.accent, 18)
    } else {
        Color32::TRANSPARENT
    };
    let stroke = if hovering {
        Stroke::new(1.0, p.accent)
    } else {
        Stroke::new(1.0, tint(p.border, 100))
    };
    ui.painter().rect(
        rect,
        CornerRadius::same(8),
        fill,
        stroke,
        egui::StrokeKind::Outside,
    );
    ui.painter().text(
        rect.center(),
        egui::Align2::CENTER_CENTER,
        if hovering {
            "Release to add more files"
        } else {
            "+ Drop more files here"
        },
        egui::FontId::proportional(11.0),
        if hovering { p.accent } else { p.text_faint },
    );
}

fn info_row(ui: &mut egui::Ui, p: &Pal, icon: &str, label: &str, value: &str) {
    ui.horizontal(|ui| {
        let (r, _) = ui.allocate_exact_size(Vec2::new(20.0, 16.0), Sense::hover());
        ui.painter().text(
            r.center(),
            egui::Align2::CENTER_CENTER,
            icon,
            egui::FontId::proportional(13.0),
            p.text_faint,
        );
        ui.add_space(8.0);
        ui.label(RichText::new(label).size(11.0).color(p.text_faint));
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.label(RichText::new(value).size(11.5).color(p.text));
        });
    });
}

fn status_badge(ui: &mut egui::Ui, text: &str, color: Color32) {
    egui::Frame::new()
        .fill(tint(color, 25))
        .corner_radius(4.0)
        .inner_margin(egui::Margin {
            left: 4,
            right: 4,
            top: 1,
            bottom: 1,
        })
        .show(ui, |ui| {
            ui.label(RichText::new(text).size(8.5).strong().color(color));
        });
}

// ─── Shared widgets ───────────────────────────────────────────────────────────
fn tint(c: Color32, a: u8) -> Color32 {
    Color32::from_rgba_unmultiplied(c.r(), c.g(), c.b(), a)
}

fn card<R>(ui: &mut egui::Ui, p: &Pal, f: impl FnOnce(&mut egui::Ui) -> R) {
    egui::Frame::new()
        .fill(p.surface)
        .stroke(Stroke::new(1.0, p.border))
        .corner_radius(14.0)
        .inner_margin(egui::Margin {
            left: 18,
            right: 18,
            top: 16,
            bottom: 16,
        })
        .show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            f(ui);
        });
}

fn icon_badge(ui: &mut egui::Ui, icon: &str, color: Color32) {
    let (r, _) = ui.allocate_exact_size(Vec2::splat(26.0), Sense::hover());
    ui.painter()
        .circle_filled(r.center(), 13.0, tint(color, 25));
    ui.painter().text(
        r.center(),
        egui::Align2::CENTER_CENTER,
        icon,
        egui::FontId::proportional(13.0),
        color,
    );
}

fn pill_btn(text: &str, accent: Color32) -> egui::Button<'static> {
    egui::Button::new(RichText::new(text.to_string()).size(12.0).color(accent))
        .fill(tint(accent, 28))
        .corner_radius(20.0)
}

fn big_btn(text: &str, accent: Color32) -> egui::Button<'static> {
    egui::Button::new(
        RichText::new(text.to_string())
            .size(13.0)
            .strong()
            .color(Color32::WHITE),
    )
    .fill(accent)
    .corner_radius(10.0)
    .min_size(Vec2::new(150.0, 38.0))
}

fn check_item(ui: &mut egui::Ui, p: &Pal, done: bool, label: &str) {
    ui.horizontal(|ui| {
        let (r, _) = ui.allocate_exact_size(Vec2::splat(16.0), Sense::hover());
        if done {
            ui.painter()
                .circle_filled(r.center(), 7.0, tint(p.success, 30));
            ui.painter().text(
                r.center(),
                egui::Align2::CENTER_CENTER,
                icons::ICON_CHECK,
                egui::FontId::proportional(12.0),
                p.success,
            );
        } else {
            ui.painter()
                .circle_stroke(r.center(), 7.0, Stroke::new(1.0, p.text_faint));
        }
        ui.add_space(4.0);
        ui.label(
            RichText::new(label)
                .size(12.0)
                .color(if done { p.text } else { p.text_dim }),
        );
    });
}

fn radar_graphic(ui: &mut egui::Ui, p: &Pal, pulse: f32, animated: bool) {
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(72.0), Sense::hover());
    let c = rect.center();
    if animated {
        for i in 0..3u32 {
            let phase = (pulse - i as f32 * 0.6).sin() * 0.5 + 0.5;
            let r = 12.0 + i as f32 * 16.0;
            let a = (phase * 100.0) as u8;
            ui.painter()
                .circle_stroke(c, r, Stroke::new(1.5, tint(p.accent, a)));
        }
    } else {
        for (r, a) in [(36u8, 35u8), (26, 55), (16, 80)] {
            ui.painter()
                .circle_stroke(c, r as f32, Stroke::new(1.0, tint(p.accent, a)));
        }
    }
    ui.painter().circle_filled(c, 9.0, tint(p.accent, 180));
    ui.painter().text(
        c,
        egui::Align2::CENTER_CENTER,
        "✈",
        egui::FontId::proportional(11.0),
        Color32::WHITE,
    );
}

fn status_metric(ui: &mut egui::Ui, p: &Pal, icon: &str, text: &str) {
    ui.horizontal(|ui| {
        ui.label(RichText::new(icon).size(11.0).color(p.text_faint));
        ui.add_space(3.0);
        ui.label(RichText::new(text).size(10.5).color(p.text_dim));
    });
}

// ─── Networking ───────────────────────────────────────────────────────────────
fn receive_server(state: Arc<Mutex<RecvState>>, save_dir: PathBuf) {
    let su = Arc::clone(&state);
    thread::spawn(move || discovery_responder(su));
    let listener = match TcpListener::bind(("0.0.0.0", TRANSFER_PORT)) {
        Ok(l) => l,
        Err(e) => {
            if let Ok(mut s) = state.lock() {
                s.error = Some(format!("Cannot listen: {}", e));
            }
            return;
        }
    };
    for stream in listener.incoming().flatten() {
        let s2 = Arc::clone(&state);
        let sd = save_dir.clone();
        thread::spawn(move || match receive_file_resumable(stream, &sd) {
            Ok(f) => {
                let ts = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                append_history(&HistoryEntry {
                    timestamp: ts,
                    direction: TransferDir::Received,
                    transfer_type: TransferType::Local,
                    file_name: f.name.clone(),
                    file_size: f.size,
                    peer_name: f.peer_name.clone(),
                    success: true,
                    error: None,
                    file_path: Some(f.path.clone()),
                });
                if let Ok(mut s) = s2.lock() {
                    s.recv_bytes += f.size;
                    s.recv_files += 1;
                    let auto_open = s.auto_open_folder;
                    if auto_open { open_folder(&f.path); }
                    s.files.push(f);
                }
            }
            Err(e) if e.starts_with("__skip__") => {
                // Receiver sent MAGIC_SKIP — not a real error, just means file was up to date
            }
            Err(e) => {
                if let Ok(mut s) = s2.lock() {
                    s.error = Some(e);
                }
            }
        });
    }
}

fn discovery_responder(_: Arc<Mutex<RecvState>>) {
    let Ok(sock) = UdpSocket::bind(("0.0.0.0", DISCOVER_PORT)) else {
        return;
    };
    let name = hostname();
    let mut buf = [0u8; 512];
    loop {
        if let Ok((n, from)) = sock.recv_from(&mut buf) {
            let msg = String::from_utf8_lossy(&buf[..n]);
            if msg.trim_matches('\0').starts_with("RFSHARE_DISCOVER") {
                let _ = sock.send_to(format!("{}{}", PEER_PREFIX, name).as_bytes(), from);
            }
        }
    }
}

// ─── Encryption ──────────────────────────────────────────────────────────────
fn derive_key(shared: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(shared);
    h.update(format!("{}-v1", env!("CARGO_PKG_NAME")).as_bytes());
    h.finalize().into()
}
fn encrypt_chunk(cipher: &Aes256Gcm, plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let mut nonce_bytes = [0u8; AES_NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| format!("Enc: {}", e))?;
    let mut out = Vec::with_capacity(AES_NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}
fn decrypt_chunk(cipher: &Aes256Gcm, data: &[u8]) -> Result<Vec<u8>, String> {
    if data.len() < AES_NONCE_LEN + AES_TAG_LEN {
        return Err("Chunk too short".into());
    }
    let nonce = Nonce::from_slice(&data[..AES_NONCE_LEN]);
    cipher
        .decrypt(nonce, &data[AES_NONCE_LEN..])
        .map_err(|_| "Decryption failed — corrupted or tampered".to_string())
}
fn write_encrypted(stream: &mut TcpStream, cipher: &Aes256Gcm, pt: &[u8]) -> Result<(), String> {
    let enc = encrypt_chunk(cipher, pt)?;
    stream
        .write_all(&(enc.len() as u32).to_le_bytes())
        .map_err(|e| e.to_string())?;
    stream.write_all(&enc).map_err(|e| e.to_string())?;
    Ok(())
}
fn read_encrypted(stream: &mut TcpStream, cipher: &Aes256Gcm) -> Result<Vec<u8>, String> {
    let mut lb = [0u8; 4];
    stream.read_exact(&mut lb).map_err(|e| e.to_string())?;
    let len = u32::from_le_bytes(lb) as usize;
    if len > CHUNK_SIZE + AES_TAG_LEN + AES_NONCE_LEN + 64 {
        return Err(format!("Packet too large: {}", len));
    }
    let mut enc = vec![0u8; len];
    stream.read_exact(&mut enc).map_err(|e| e.to_string())?;
    decrypt_chunk(cipher, &enc)
}

fn send_file_sync(
    path: &std::path::Path,
    name: &str,
    file_size: u64,
    mtime: u64,
    addr: std::net::IpAddr,
) -> Result<SyncResult, String> {
    let mut stream =
        TcpStream::connect((addr, TRANSFER_PORT)).map_err(|e| format!("Cannot connect: {}", e))?;

    let sender_secret = EphemeralSecret::random_from_rng(AeadOsRng);
    let sender_pub = PublicKey::from(&sender_secret);
    stream
        .write_all(sender_pub.as_bytes())
        .map_err(|e| e.to_string())?;
    stream.flush().map_err(|e| e.to_string())?;
    let mut recv_pub_bytes = [0u8; X25519_KEY_LEN];
    stream
        .read_exact(&mut recv_pub_bytes)
        .map_err(|e| e.to_string())?;
    let receiver_pub = PublicKey::from(recv_pub_bytes);
    let shared = sender_secret.diffie_hellman(&receiver_pub);
    let aes_key = derive_key(shared.as_bytes());
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&aes_key));

    let nb = name.as_bytes();
    let hn = hostname();
    let hb = hn.as_bytes();
    let mut offer = Vec::with_capacity(1 + 4 + nb.len() + 8 + 4 + hb.len() + 8);
    offer.push(MAGIC_OFFER);
    offer.extend_from_slice(&(nb.len() as u32).to_le_bytes());
    offer.extend_from_slice(nb);
    offer.extend_from_slice(&file_size.to_le_bytes());
    offer.extend_from_slice(&(hb.len() as u32).to_le_bytes());
    offer.extend_from_slice(hb);
    offer.extend_from_slice(&mtime.to_le_bytes());
    write_encrypted(&mut stream, &cipher, &offer)?;
    stream.flush().map_err(|e| e.to_string())?;

    let mut resp_buf = [0u8; 1];
    stream
        .read_exact(&mut resp_buf)
        .map_err(|e| e.to_string())?;

    if resp_buf[0] == MAGIC_SKIP {
        return Ok(SyncResult::Skipped);
    }
    if resp_buf[0] != MAGIC_RESUME {
        return Err("Bad handshake response".into());
    }

    let resume_payload = read_encrypted(&mut stream, &cipher)?;
    if resume_payload.len() < 8 {
        return Err("Short resume payload".into());
    }
    let resume_offset = u64::from_le_bytes(resume_payload[..8].try_into().unwrap());

    let mut file = fs::File::open(path).map_err(|e| format!("Cannot open file: {}", e))?;
    if resume_offset > 0 {
        file.seek(SeekFrom::Start(resume_offset))
            .map_err(|e| e.to_string())?;
    }
    let mut buf = vec![0u8; CHUNK_SIZE];
    loop {
        let n = file.read(&mut buf).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        stream.write_all(&[MAGIC_DATA]).map_err(|e| e.to_string())?;
        write_encrypted(&mut stream, &cipher, &buf[..n])?;
    }
    stream.write_all(&[MAGIC_DONE]).map_err(|e| e.to_string())?;
    stream.flush().map_err(|e| e.to_string())?;
    Ok(SyncResult::Sent)
}

fn send_file_resumable(
    path: &std::path::Path,
    name: &str,
    file_size: u64,
    addr: std::net::IpAddr,
    on_progress: impl Fn(f32) + Send + 'static,
) -> Result<(), String> {
    let socket_addr = std::net::SocketAddr::new(addr, TRANSFER_PORT);
    let mut stream = TcpStream::connect_timeout(
        &socket_addr,
        std::time::Duration::from_secs(5),
    ).map_err(|e| format!("Cannot connect: {}", e))?;

    // Fix: Handle io::Error properly
    stream.set_read_timeout(Some(std::time::Duration::from_secs(30)))
        .map_err(|e| e.to_string())?;
    stream.set_write_timeout(Some(std::time::Duration::from_secs(30)))
        .map_err(|e| e.to_string())?;

    let sender_secret = EphemeralSecret::random_from_rng(AeadOsRng);
    let sender_pub = PublicKey::from(&sender_secret);
    stream
        .write_all(sender_pub.as_bytes())
        .map_err(|e| e.to_string())?;
    stream.flush().map_err(|e| e.to_string())?;
    let mut recv_pub_bytes = [0u8; X25519_KEY_LEN];
    stream
        .read_exact(&mut recv_pub_bytes)
        .map_err(|e| e.to_string())?;
    let receiver_pub = PublicKey::from(recv_pub_bytes);
    let shared = sender_secret.diffie_hellman(&receiver_pub);
    let aes_key = derive_key(shared.as_bytes());
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&aes_key));

    // Rest of the function remains the same...
    let nb = name.as_bytes();
    let hn = hostname();
    let hb = hn.as_bytes();
    let mut offer = Vec::with_capacity(1 + 4 + nb.len() + 8 + 4 + hb.len());
    offer.push(MAGIC_OFFER);
    offer.extend_from_slice(&(nb.len() as u32).to_le_bytes());
    offer.extend_from_slice(nb);
    offer.extend_from_slice(&file_size.to_le_bytes());
    offer.extend_from_slice(&(hb.len() as u32).to_le_bytes());
    offer.extend_from_slice(hb);
    write_encrypted(&mut stream, &cipher, &offer)?;
    stream.flush().map_err(|e| e.to_string())?;
    let mut magic_buf = [0u8; 1];
    stream
        .read_exact(&mut magic_buf)
        .map_err(|e| e.to_string())?;
    if magic_buf[0] != MAGIC_RESUME {
        return Err("Bad handshake response".into());
    }
    let resume_payload = read_encrypted(&mut stream, &cipher)?;
    if resume_payload.len() < 8 {
        return Err("Short resume payload".into());
    }
    let resume_offset = u64::from_le_bytes(resume_payload[..8].try_into().unwrap());
    let mut file = fs::File::open(path).map_err(|e| format!("Cannot open: {}", e))?;
    if resume_offset > 0 {
        file.seek(SeekFrom::Start(resume_offset))
            .map_err(|e| e.to_string())?;
    }
    let mut sent = resume_offset;
    let mut buf = vec![0u8; CHUNK_SIZE];
    loop {
        let n = file.read(&mut buf).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        stream.write_all(&[MAGIC_DATA]).map_err(|e| e.to_string())?;
        write_encrypted(&mut stream, &cipher, &buf[..n])?;
        sent += n as u64;
        if file_size > 0 {
            on_progress(sent as f32 / file_size as f32);
        }
    }
    stream.write_all(&[MAGIC_DONE]).map_err(|e| e.to_string())?;
    stream.flush().map_err(|e| e.to_string())?;
    Ok(())
}

fn receive_file_resumable(
    mut stream: TcpStream,
    save_dir: &std::path::Path,
) -> Result<ReceivedFile, String> {
    let sender_ip = stream
        .peer_addr()
        .map(|a| a.ip().to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    let mut sender_pub_bytes = [0u8; X25519_KEY_LEN];
    stream
        .read_exact(&mut sender_pub_bytes)
        .map_err(|e| e.to_string())?;
    let sender_pub = PublicKey::from(sender_pub_bytes);
    let receiver_secret = EphemeralSecret::random_from_rng(AeadOsRng);
    let receiver_pub = PublicKey::from(&receiver_secret);
    stream
        .write_all(receiver_pub.as_bytes())
        .map_err(|e| e.to_string())?;
    stream.flush().map_err(|e| e.to_string())?;
    let shared = receiver_secret.diffie_hellman(&sender_pub);
    let aes_key = derive_key(shared.as_bytes());
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&aes_key));
    let offer = read_encrypted(&mut stream, &cipher)?;
    if offer.is_empty() || offer[0] != MAGIC_OFFER {
        return Err("Bad offer".into());
    }
    if offer.len() < 5 {
        return Err("Offer too short".into());
    }
    let name_len = u32::from_le_bytes(offer[1..5].try_into().unwrap()) as usize;
    if name_len == 0 || name_len > 4096 {
        return Err("Bad name length".into());
    }
    if offer.len() < 5 + name_len + 8 {
        return Err("Truncated offer".into());
    }
    let name = String::from_utf8_lossy(&offer[5..5 + name_len]).to_string();
    let file_size = u64::from_le_bytes(offer[5 + name_len..5 + name_len + 8].try_into().unwrap());
    if file_size > 8 * 1024 * 1024 * 1024 {
        return Err("File too large (>8 GB)".into());
    }

    let base = 5 + name_len + 8;
    let sender_hostname: String = if offer.len() >= base + 4 {
        let hn_len = u32::from_le_bytes(offer[base..base + 4].try_into().unwrap()) as usize;
        if hn_len > 0 && hn_len <= 256 && offer.len() >= base + 4 + hn_len {
            String::from_utf8_lossy(&offer[base + 4..base + 4 + hn_len]).to_string()
        } else {
            sender_ip.clone()
        }
    } else {
        sender_ip.clone()
    };

    let mtime_base = if offer.len() >= base + 4 {
        let hn_len = u32::from_le_bytes(offer[base..base + 4].try_into().unwrap()) as usize;
        base + 4 + hn_len.min(256)
    } else {
        base
    };
    let sender_mtime: Option<u64> = if offer.len() >= mtime_base + 8 {
        Some(u64::from_le_bytes(
            offer[mtime_base..mtime_base + 8].try_into().unwrap(),
        ))
    } else {
        None
    };

    let _ = fs::create_dir_all(save_dir);
    let dest = save_dir.join(&name);

    if let Some(incoming_mtime) = sender_mtime {
        if dest.exists() {
            let existing_mtime = fs::metadata(&dest)
                .and_then(|m| m.modified())
                .map(|t| {
                    t.duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs()
                })
                .unwrap_or(0);
            if existing_mtime >= incoming_mtime {
                stream.write_all(&[MAGIC_SKIP]).map_err(|e| e.to_string())?;
                stream.flush().map_err(|e| e.to_string())?;
                return Err(format!("__skip__{}", name));
            }
            let _ = fs::remove_file(&dest);
        }
    }

    let is_sync = sender_mtime.is_some();
    let resume_offset: u64 = if !is_sync && dest.exists() {
        fs::metadata(&dest).map(|m| m.len()).unwrap_or(0)
    } else {
        0
    };
    let (dest, resume_offset) = if !is_sync && resume_offset >= file_size && file_size > 0 {
        (unique_path(save_dir, &name), 0u64)
    } else {
        (dest, resume_offset)
    };

    stream
        .write_all(&[MAGIC_RESUME])
        .map_err(|e| e.to_string())?;
    write_encrypted(&mut stream, &cipher, &resume_offset.to_le_bytes())?;
    stream.flush().map_err(|e| e.to_string())?;
    let mut file = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .append(resume_offset > 0)
        .truncate(resume_offset == 0)
        .open(&dest)
        .map_err(|e| format!("Cannot open dest: {}", e))?;
    let mut received = resume_offset;
    let mut magic = [0u8; 1];
    loop {
        stream.read_exact(&mut magic).map_err(|e| e.to_string())?;
        match magic[0] {
            MAGIC_DATA => {
                let pt = read_encrypted(&mut stream, &cipher)?;
                file.write_all(&pt).map_err(|e| e.to_string())?;
                received += pt.len() as u64;
            }
            MAGIC_DONE => break,
            other => return Err(format!("Unknown packet 0x{:02x}", other)),
        }
    }
    if received != file_size {
        return Err(format!("Size mismatch: {} vs {}", file_size, received));
    }
    let _ = notify(
        &format!("{} — File Received", env!("CARGO_PKG_NAME")),
        &format!(
            "'{}' saved to {}",
            truncate_filename(&name, 45),
            save_dir.display()
        ),
    );

    Ok(ReceivedFile {
        name,
        size: file_size,
        path: dest,
        seen: false,
        peer_name: sender_hostname,
    })
}

fn send_file_via_relay(
    path: &std::path::Path,
    name: &str,
    file_size: u64,
    relay_stream: &mut TcpStream,
    on_progress: impl Fn(f32) + Send + 'static,
) -> Result<(), String> {
    // Set timeouts - handle errors properly
    if let Err(e) = relay_stream.set_read_timeout(Some(std::time::Duration::from_secs(300))) {
        return Err(format!("Failed to set read timeout: {}", e));
    }
    if let Err(e) = relay_stream.set_write_timeout(Some(std::time::Duration::from_secs(300))) {
        return Err(format!("Failed to set write timeout: {}", e));
    }

    // Key exchange
    let sender_secret = EphemeralSecret::random_from_rng(AeadOsRng);
    let sender_pub = PublicKey::from(&sender_secret);
    relay_stream
        .write_all(sender_pub.as_bytes())
        .map_err(|e| e.to_string())?;
    relay_stream.flush().map_err(|e| e.to_string())?;

    let mut recv_pub_bytes = [0u8; X25519_KEY_LEN];
    relay_stream
        .read_exact(&mut recv_pub_bytes)
        .map_err(|e| e.to_string())?;

    let receiver_pub = PublicKey::from(recv_pub_bytes);
    let shared = sender_secret.diffie_hellman(&receiver_pub);
    let aes_key = derive_key(shared.as_bytes());
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&aes_key));

    // Send offer with file info
    let nb = name.as_bytes();
    let hn = hostname();
    let hb = hn.as_bytes();
    let mut offer = Vec::with_capacity(1 + 4 + nb.len() + 8 + 4 + hb.len());
    offer.push(MAGIC_OFFER);
    offer.extend_from_slice(&(nb.len() as u32).to_le_bytes());
    offer.extend_from_slice(nb);
    offer.extend_from_slice(&file_size.to_le_bytes());
    offer.extend_from_slice(&(hb.len() as u32).to_le_bytes());
    offer.extend_from_slice(hb);
    write_encrypted(relay_stream, &cipher, &offer)?;
    relay_stream.flush().map_err(|e| e.to_string())?;

    // Wait for resume response
    let mut magic_buf = [0u8; 1];
    relay_stream
        .read_exact(&mut magic_buf)
        .map_err(|e| e.to_string())?;
    if magic_buf[0] != MAGIC_RESUME {
        return Err("Bad handshake response".into());
    }

    let resume_payload = read_encrypted(relay_stream, &cipher)?;
    if resume_payload.len() < 8 {
        return Err("Short resume payload".into());
    }
    let resume_offset = u64::from_le_bytes(resume_payload[..8].try_into().unwrap());

    // Send file data
    let mut file = fs::File::open(path).map_err(|e| format!("Cannot open: {}", e))?;
    if resume_offset > 0 {
        file.seek(SeekFrom::Start(resume_offset))
            .map_err(|e| e.to_string())?;
    }
    let mut sent = resume_offset;
    let mut buf = vec![0u8; CHUNK_SIZE];
    loop {
        let n = file.read(&mut buf).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        relay_stream.write_all(&[MAGIC_DATA]).map_err(|e| e.to_string())?;
        write_encrypted(relay_stream, &cipher, &buf[..n])?;
        sent += n as u64;
        if file_size > 0 {
            on_progress(sent as f32 / file_size as f32);
        }
    }
    relay_stream.write_all(&[MAGIC_DONE]).map_err(|e| e.to_string())?;
    relay_stream.flush().map_err(|e| e.to_string())?;
    Ok(())
}

fn receive_file_via_relay(
    mut relay_stream: TcpStream,
    save_dir: &std::path::Path,
) -> Result<ReceivedFile, String> {
    let sender_ip = relay_stream
        .peer_addr()
        .map(|a| a.ip().to_string())
        .unwrap_or_else(|_| "relay".to_string());

    // Key exchange
    let mut sender_pub_bytes = [0u8; X25519_KEY_LEN];
    relay_stream
        .read_exact(&mut sender_pub_bytes)
        .map_err(|e| e.to_string())?;
    let sender_pub = PublicKey::from(sender_pub_bytes);

    let receiver_secret = EphemeralSecret::random_from_rng(AeadOsRng);
    let receiver_pub = PublicKey::from(&receiver_secret);
    relay_stream
        .write_all(receiver_pub.as_bytes())
        .map_err(|e| e.to_string())?;
    relay_stream.flush().map_err(|e| e.to_string())?;

    let shared = receiver_secret.diffie_hellman(&sender_pub);
    let aes_key = derive_key(shared.as_bytes());
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&aes_key));

    // Read offer
    let offer = read_encrypted(&mut relay_stream, &cipher)?;
    if offer.is_empty() || offer[0] != MAGIC_OFFER {
        return Err("Bad offer".into());
    }
    if offer.len() < 5 {
        return Err("Offer too short".into());
    }

    let name_len = u32::from_le_bytes(offer[1..5].try_into().unwrap()) as usize;
    if name_len == 0 || name_len > 4096 {
        return Err("Bad name length".into());
    }
    if offer.len() < 5 + name_len + 8 {
        return Err("Truncated offer".into());
    }

    let name = String::from_utf8_lossy(&offer[5..5 + name_len]).to_string();
    let file_size = u64::from_le_bytes(offer[5 + name_len..5 + name_len + 8].try_into().unwrap());
    if file_size > 8 * 1024 * 1024 * 1024 {
        return Err("File too large (>8 GB)".into());
    }

    let base = 5 + name_len + 8;
    let sender_hostname: String = if offer.len() >= base + 4 {
        let hn_len = u32::from_le_bytes(offer[base..base + 4].try_into().unwrap()) as usize;
        if hn_len > 0 && hn_len <= 256 && offer.len() >= base + 4 + hn_len {
            String::from_utf8_lossy(&offer[base + 4..base + 4 + hn_len]).to_string()
        } else {
            sender_ip.clone()
        }
    } else {
        sender_ip.clone()
    };

    // Create save directory and file path
    let _ = fs::create_dir_all(save_dir);
    let dest = unique_path(save_dir, &name);

    // Send resume response (start from beginning)
    relay_stream
        .write_all(&[MAGIC_RESUME])
        .map_err(|e| e.to_string())?;
    write_encrypted(&mut relay_stream, &cipher, &0u64.to_le_bytes())?;
    relay_stream.flush().map_err(|e| e.to_string())?;

    // Receive file data
    let mut file = fs::File::create(&dest).map_err(|e| format!("Cannot create file: {}", e))?;
    let mut received = 0u64;
    let mut magic = [0u8; 1];

    loop {
        relay_stream.read_exact(&mut magic).map_err(|e| e.to_string())?;
        match magic[0] {
            MAGIC_DATA => {
                let pt = read_encrypted(&mut relay_stream, &cipher)?;
                file.write_all(&pt).map_err(|e| e.to_string())?;
                received += pt.len() as u64;
            }
            MAGIC_DONE => break,
            other => return Err(format!("Unknown packet 0x{:02x}", other)),
        }
    }

    if received != file_size {
        return Err(format!("Size mismatch: {} vs {}", file_size, received));
    }

    let _ = notify(
        &format!("{} — File Received", env!("CARGO_PKG_NAME")),
        &format!(
            "'{}' saved to {}",
            truncate_filename(&name, 45),
            save_dir.display()
        ),
    );

    Ok(ReceivedFile {
        name,
        size: file_size,
        path: dest,
        seen: false,
        peer_name: sender_hostname,
    })
}

// ─── Utilities ────────────────────────────────────────────────────────────────
fn unique_path(dir: &std::path::Path, name: &str) -> PathBuf {
    let p = dir.join(name);
    if !p.exists() {
        return p;
    }
    let stem = std::path::Path::new(name)
        .file_stem()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    let ext = std::path::Path::new(name)
        .extension()
        .map(|e| format!(".{}", e.to_string_lossy()))
        .unwrap_or_default();
    for i in 1u32.. {
        let c = dir.join(format!("{} ({}){}", stem, i, ext));
        if !c.exists() {
            return c;
        }
    }
    p
}
fn truncate_filename(name: &str, max_len: usize) -> String {
    if name.len() <= max_len {
        return name.to_string();
    }
    let mut t = name.to_string();
    t.truncate(max_len);
    format!("{}…{}", t, &name[name.len().saturating_sub(4)..])
}
fn local_ip() -> String {
    std::net::UdpSocket::bind("0.0.0.0:0")
        .and_then(|s| {
            s.connect("8.8.8.8:80")?;
            s.local_addr()
        })
        .map(|a| a.ip().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}

fn hostname() -> String {
    std::process::Command::new("hostname")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .unwrap_or_else(|| "this-device".into())
        .trim()
        .to_string()
}

fn notify(title: &str, body: &str) -> Result<(), ()> {
    #[cfg(target_os = "linux")]
    {
        let _ = std::process::Command::new("notify-send")
            .arg(title)
            .arg(body)
            .spawn();
    }
    #[cfg(target_os = "macos")]
    {
        let sc = format!("display notification \"{}\" with title \"{}\"", body, title);
        let _ = std::process::Command::new("osascript")
            .arg("-e")
            .arg(&sc)
            .spawn();
    }
    // Windows 10/11 toast notifications (the modern ones that appear in the action center)
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const CNW: u32 = 0x08000000;

        // Create a temp PowerShell script file for better reliability
        let temp_dir = std::env::temp_dir();
        let script_path = temp_dir.join(format!("toast_{}.ps1", std::process::id()));

        // Escape strings for PowerShell
        let title_escaped = title.replace("'", "''");
        let body_escaped = body.replace("'", "''");

        // Get the executable path for icon
        let exe_path = std::env::current_exe().unwrap_or_default();
        let exe_path_str = exe_path.to_string_lossy().replace('\\', "\\\\");

        // Create PowerShell script content
        let script_content = format!(
            "$title = '{}'
            $body = '{}'
            $exePath = '{}'

            # Try to load Windows.UI.Notifications
            try {{
                [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null

                # Create a template
                $template = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02)

                # Set text
                $textNodes = $template.GetElementsByTagName('text')
                $textNodes[0].AppendChild($template.CreateTextNode($title)) | Out-Null
                $textNodes[1].AppendChild($template.CreateTextNode($body)) | Out-Null

                # Set app ID
                $appId = '{}.{}'
                $notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($appId)
                $toast = [Windows.UI.Notifications.ToastNotification]::new($template)
                $toast.Tag = 'FileTransfer'
                $toast.Group = 'Transfers'
                $toast.ExpirationTime = [DateTimeOffset]::Now.AddSeconds(30)

                # Show notification
                $notifier.Show($toast)
            }}
            catch {{
                # Fallback to balloon tip
                Add-Type -AssemblyName System.Windows.Forms
                $notification = New-Object System.Windows.Forms.NotifyIcon
                if (Test-Path $exePath) {{
                    $notification.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon($exePath)
                }}
                $notification.BalloonTipTitle = $title
                $notification.BalloonTipText = $body
                $notification.BalloonTipIcon = [System.Windows.Forms.ToolTipIcon]::Info
                $notification.Visible = $true
                $notification.ShowBalloonTip(3000)
                Start-Sleep -Seconds 3
                $notification.Dispose()
            }}",
            title_escaped, body_escaped, exe_path_str, env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION")
        );

        // Write script to temp file
        let _ = std::fs::write(&script_path, script_content);

        // Execute the script
        let _ = std::process::Command::new("powershell")
            .args([
                "-WindowStyle", "Hidden",
                "-ExecutionPolicy", "Bypass",
                "-File", script_path.to_str().unwrap()
            ])
            .creation_flags(CNW)
            .spawn();

        // Clean up script after a delay
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_secs(5));
            let _ = std::fs::remove_file(script_path);
        });
    }

    Ok(())
}

fn open_folder(p: &std::path::Path) {
    let d = p.parent().unwrap_or(p);
    #[cfg(target_os = "linux")]
    {
        let _ = std::process::Command::new("xdg-open").arg(d).spawn();
    }
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("open").arg(d).spawn();
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;

        let _ = std::process::Command::new("cmd")
            .args(["/c", "start", ""])
            .arg(d)
            .creation_flags(0x08000000) // CREATE_NO_WINDOW
            .spawn();
    }

}

fn open_url(url: &str) {
    #[cfg(target_os = "linux")]
    {
        let _ = std::process::Command::new("xdg-open").arg(url).spawn();
    }
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("open").arg(url).spawn();
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const CNW: u32 = 0x08000000;
        let _ = std::process::Command::new("cmd")
            .args(["/C", "start", "", url])
            .creation_flags(CNW)
            .spawn();
    }
}

fn format_size(b: u64) -> String {
    const U: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut s = b as f64;
    let mut i = 0;
    while s >= 1024.0 && i < U.len() - 1 {
        s /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{} B", b)
    } else {
        format!("{:.1} {}", s, U[i])
    }
}

fn file_icon(name: &str) -> &'static str {
    let ext = std::path::Path::new(name)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();
    match ext.as_str() {
        "pdf" => "📕",
        "png" | "jpg" | "jpeg" | "gif" | "svg" | "bmp" | "webp" | "heic" => icons::ICON_IMAGE,
        "mp3" | "wav" | "ogg" | "flac" | "aac" | "m4a" => "🎵",
        "mp4" | "avi" | "mkv" | "mov" | "webm" => "🎬",
        "zip" | "tar" | "gz" | "7z" | "rar" => "📦",
        "rs" | "py" | "js" | "ts" | "cpp" | "c" | "java" | "go" | "rb" | "sql" | "html" | "css"
        | "txt" | "md" | "log" => "📄",
        "doc" | "docx" => "📝",
        "xls" | "xlsx" | "csv" => "📊",
        "ppt" | "pptx" => "📽️",
        _ => "📁",
    }
}

fn detect_system_theme() -> bool {
    #[cfg(target_os = "macos")]
    {
        // macOS dark mode detection
        use std::process::Command;
        let output = Command::new("defaults")
            .args(["read", "-g", "AppleInterfaceStyle"])
            .output();
        matches!(output, Ok(o) if String::from_utf8_lossy(&o.stdout).trim() == "Dark")
    }

    #[cfg(target_os = "windows")]
    {
        use winreg::RegKey;
        use winreg::enums::HKEY_CURRENT_USER;
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let path = r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize";
        if let Ok(key) = hkcu.open_subkey(path) {
            // Fix: Specify the type explicitly
            if let Ok(value) = key.get_value::<u32, _>("AppsUseLightTheme") {
                return value == 0;
            }
        }
        false
    }

    #[cfg(target_os = "linux")]
    {
        // Linux GTK dark mode detection
        use std::process::Command;
        let output = Command::new("gsettings")
            .args(["get", "org.gnome.desktop.interface", "gtk-theme"])
            .output();
        if let Ok(o) = output {
            let theme = String::from_utf8_lossy(&o.stdout);
            return theme.to_lowercase().contains("dark");
        }
        false
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    {
        false // Default to light mode
    }
}

fn main() -> eframe::Result<()> {
    // Initialize GTK on Linux for system tray support
    #[cfg(target_os = "linux")]
    {
        if let Err(e) = gtk::init() {
            eprintln!("Warning: Failed to initialize GTK: {}", e);
            eprintln!("System tray may not work properly");
        }
    }

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title(format!("{}", env!("CARGO_PKG_NAME")))
            .with_inner_size([560.0, 680.0])
            .with_min_inner_size([340.0, 480.0])
            .with_maximize_button(false)
            .with_resizable(false)
            .with_icon(
                eframe::icon_data::from_png_bytes(include_bytes!("../assets/icon.png"))
                    .unwrap_or_default(),
            ),
        ..Default::default()
    };

    eframe::run_native(
        env!("CARGO_PKG_NAME"),
        options,
        Box::new(|cc| {
            egui_extras::install_image_loaders(&cc.egui_ctx);
            egui_material_icons::initialize(&cc.egui_ctx);

            Ok(Box::new(App::default()))
        }),
    )
}
