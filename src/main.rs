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
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};
use x25519_dalek::{EphemeralSecret, PublicKey};

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

// ─── Persistence helpers ─────────────────────────────────────────────────────
fn prefs_path() -> Option<PathBuf> {
    dirs::config_dir().map(|d| d.join("rfshare").join("prefs.json"))
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
    if let Some(ref d) = save_dir {
        out.push_str(&format!("save_dir={}\n", d.display()));
    }
    out.push_str(&format!("notify_on_receive={}\n", notify_on_receive as u8));
    out.push_str(&format!("auto_open_folder={}\n", auto_open_folder as u8));
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
}

fn load_prefs() -> SavedPrefs {
    let mut prefs = SavedPrefs::default();
    let Some(path) = prefs_path() else {
        return prefs;
    };
    let Ok(text) = fs::read_to_string(&path) else {
        return prefs;
    };
    for line in text.lines() {
        if let Some(v) = line.strip_prefix("selected_peer_name=") {
            prefs.peer_name = v.to_string();
        }
        if let Some(v) = line.strip_prefix("selected_peer_addr=") {
            prefs.peer_addr = v.to_string();
        }
        // sync_device_<safe_addr>=<folder_path>
        if let Some(rest) = line.strip_prefix("sync_device_") {
            if let Some(eq) = rest.find('=') {
                let safe_addr = &rest[..eq];
                let folder = &rest[eq + 1..];
                // Restore dots from underscores (safe for IPv4; IPv6 uses colons stored as _)
                let addr = safe_addr.replace('_', ".");
                prefs.sync_map.insert(addr, PathBuf::from(folder));
            }
        }
        if let Some(v) = line.strip_prefix("save_dir=") {
            prefs.save_dir = Some(PathBuf::from(v));
        }
        if let Some(v) = line.strip_prefix("notify_on_receive=") {
            prefs.notify_on_receive = v == "1";
        }
        if let Some(v) = line.strip_prefix("auto_open_folder=") {
            prefs.auto_open_folder = v == "1";
        }
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

fn fetch_latest_version() -> Option<String> {
    use std::io::{BufRead, BufReader, Write};
    let mut stream = std::net::TcpStream::connect(("github.com", 80)).ok()?;
    stream.set_read_timeout(Some(std::time::Duration::from_secs(5))).ok()?;
    write!(stream,
        "GET /imrany/rfshare/releases/latest HTTP/1.1\r\nHost: github.com\r\nUser-Agent: rfshare\r\nConnection: close\r\n\r\n"
    ).ok()?;
    for line in BufReader::new(stream).lines().take(20).flatten() {
        if line.to_ascii_lowercase().starts_with("location:") {
            if let Some(tag) = line.rsplit('/').next() {
                if tag.trim().starts_with('v') {
                    return Some(tag.trim().to_string());
                }
            }
        }
    }
    None
}

fn is_newer(latest: &str, current: &str) -> bool {
    fn parse(v: &str) -> Option<(u32,u32,u32)> {
        let v = v.trim_start_matches('v');
        let mut p = v.splitn(3,'.');
        Some((p.next()?.parse().ok()?, p.next()?.parse().ok()?,
              p.next()?.split('-').next()?.parse().ok()?))
    }
    matches!((parse(latest), parse(current)), (Some(l), Some(c)) if l > c)
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
        dirs::config_dir().map(|d| d.join("rfshare").join("license"))
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
    dirs::config_dir().map(|d| d.join("rfshare").join("history.csv"))
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
        let cols: Vec<&str> = line.splitn(8, ',').collect();
        if cols.len() < 7 {
            continue;
        }
        let ts = cols[0].parse::<u64>().unwrap_or(0);
        let dir = if cols[1] == "sent" {
            TransferDir::Sent
        } else {
            TransferDir::Received
        };
        let name = cols[2].to_string();
        let size = cols[3].parse::<u64>().unwrap_or(0);
        let peer = cols[4].to_string();
        let ok = cols[5] == "1";
        let err = if cols[6].is_empty() {
            None
        } else {
            Some(cols[6].to_string())
        };
        let fpath = cols
            .get(7)
            .filter(|s| !s.is_empty())
            .map(|s| PathBuf::from(s));
        out.push(HistoryEntry {
            timestamp: ts,
            direction: dir,
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
            let _ = writeln!(f, "timestamp,direction,name,size,peer,ok,error,file_path");
        }
        let dir = if entry.direction == TransferDir::Sent {
            "sent"
        } else {
            "received"
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
            "{},{},{},{},{},{},{},{}",
            entry.timestamp, dir, entry.file_name, entry.file_size, entry.peer_name, ok, err, fpath
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
#[derive(Clone, Debug)]
struct Peer {
    name: String,
    addr: std::net::IpAddr,
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
    session_recv_bytes: u64,
    session_sent_files: u32,
    session_recv_files: u32,

    // ── Update checker ────────────────────────────────────────────────────
    update_available: Option<String>,
    update_rx: Option<std::sync::mpsc::Receiver<Option<String>>>,
}

impl Default for App {
    fn default() -> Self {
        let prefs = load_prefs();
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
            dark_mode: true,
            scan_pulse: 0.0,
            show_upgrade: false,
            version: env!("CARGO_PKG_VERSION").to_string(),
            this_hostname: hostname(),
            this_ip: local_ip(),
            save_dir: prefs.save_dir.clone().unwrap_or_else(|| {
                dirs::download_dir()
                    .unwrap_or_else(|| dirs::home_dir().unwrap_or_else(|| PathBuf::from(".")))
            }),
            notify_on_receive: prefs.notify_on_receive,
            auto_open_folder: prefs.auto_open_folder,
            session_sent_bytes: 0,
            session_recv_bytes: 0,
            session_sent_files: 0,
            session_recv_files: 0,
            update_available: None,
            update_rx: None,
            license,
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
        save_prefs(name, &addr, &self.sync_map,
            Some(&self.save_dir), self.notify_on_receive, self.auto_open_folder);
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
                                found.push(Peer { name, addr: ip });
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
        thread::spawn(move || {
            for (index, path, name, size) in items {
                let tx2 = tx.clone();
                let pn = peer_name.clone();
                let nm = name.clone();
                let result = send_file_resumable(&path, &name, size, peer.addr, move |p| {
                    let _ = tx2.send(QueueMsg::Progress { index, progress: p });
                });
                let ts = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                match result {
                    Ok(()) => {
                        append_history(&HistoryEntry {
                            timestamp: ts,
                            direction: TransferDir::Sent,
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
        if self.sync_jobs.is_empty() {
            return;
        }
        if self.sync_active {
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

            loop {
                for (job_idx, job) in jobs.iter().enumerate() {
                    let Ok(entries) = fs::read_dir(&job.folder) else {
                        continue;
                    };

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
                        let tx2 = tx.clone();
                        let nm = name.clone();
                        let _ = tx2.send(SyncMsg::FileFound { name: nm.clone() });

                        match send_file_sync(&path, &name, size, current_mtime, job.peer_addr) {
                            Ok(SyncResult::Sent) => {
                                let key_clone = key.clone();
                                job_mtimes[job_idx].insert(key, current_mtime);
                                let _ = tx2.send(SyncMsg::FileSent {
                                    name: nm,
                                    path: key_clone,
                                });
                            }
                            Ok(SyncResult::Skipped) => {
                                job_mtimes[job_idx].insert(key, current_mtime);
                                let _ = tx2.send(SyncMsg::FileSkipped { name: nm });
                            }
                            Err(e) => {
                                let _ = tx2.send(SyncMsg::FileError { name: nm, error: e });
                            }
                        }
                    }
                }
                thread::sleep(std::time::Duration::from_millis(SYNC_POLL_MS));
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

    fn poll(&mut self) {
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

        if let Some(rx) = &self.queue_rx {
            let mut done = false;
            loop {
                match rx.try_recv() {
                    Ok(QueueMsg::Progress { index, progress }) => {
                        if let Some(item) = self.queue.get_mut(index) {
                            item.progress = Some(progress);
                        }
                    }
                    Ok(QueueMsg::Done { index }) => {
                        if let Some(item) = self.queue.get_mut(index) {
                            item.progress = Some(1.0);
                            self.session_sent_bytes += item.size;
                            self.session_sent_files += 1;
                        }
                    }
                    Ok(QueueMsg::Failed { index, error }) => {
                        if let Some(item) = self.queue.get_mut(index) {
                            item.error = Some(error);
                            item.progress = None;
                        }
                    }
                    Err(std::sync::mpsc::TryRecvError::Empty) => break,
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                        done = true;
                        break;
                    }
                }
            }
            if done {
                self.queue_rx = None;
                self.history = load_history();
            }
        }

        if let Some(rx) = &self.sync_rx {
            let mut disconnected = false;
            loop {
                match rx.try_recv() {
                    Ok(SyncMsg::FileFound { name }) => {
                        self.sync_log.push(format!("... sending {}", name));
                    }
                    Ok(SyncMsg::FileSent { name, .. }) => {
                        let placeholder = format!("... sending {}", name);
                        self.sync_log.retain(|l| l != &placeholder);
                        self.sync_log.push(format!("OK {}", name));
                    }
                    Ok(SyncMsg::FileSkipped { name }) => {
                        let placeholder = format!("... sending {}", name);
                        self.sync_log.retain(|l| l != &placeholder);
                    }
                    Ok(SyncMsg::FileError { name, error }) => {
                        let placeholder = format!("... sending {}", name);
                        self.sync_log.retain(|l| l != &placeholder);
                        self.sync_log.push(format!("ERR {} — {}", name, error));
                    }
                    Err(std::sync::mpsc::TryRecvError::Empty) => break,
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                        disconnected = true;
                        break;
                    }
                }
            }
            if disconnected {
                self.sync_rx = None;
                self.sync_active = false;
            }
        }

        if let Some(rx) = &self.update_rx {
            if let Ok(v) = rx.try_recv() {
                self.update_available = v;
                self.update_rx = None;
            }
        }
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
                ui.horizontal(|ui| {
                    ui.label(RichText::new("Theme").size(12.0).color(p.text));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        for (lbl, is_dark) in [("Dark", true), ("Light", false)] {
                            let active = self.dark_mode == is_dark;
                            let col = if active { p.accent } else { p.text_dim };
                            let fill = if active { tint(p.accent, 22) } else { p.surface };
                            if ui.add(egui::Button::new(
                                RichText::new(lbl).size(12.0).color(col))
                                .fill(fill)
                                .stroke(Stroke::new(1.0, if active { p.accent } else { p.border }))
                                .corner_radius(6.0)
                                .min_size(Vec2::new(60.0, 28.0))).clicked()
                            {
                                self.dark_mode = is_dark;
                            }
                            ui.add_space(4.0);
                        }
                    });
                });
            });
    }
}

// ─── eframe::App ─────────────────────────────────────────────────────────────
impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
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

        self.poll();
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
                            RichText::new("rfshare Pro")
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
                            ("📁", "Folder sync — auto-send new files in a folder"),
                            ("🏢", "Unlimited devices  /  org license"),
                            ("🔐", "End-to-end encrypted transfers"),
                            ("⚡", "Priority support"),
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
                    ui.label(RichText::new("rfshare").size(15.0).strong().color(p.text));

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
                        RichText::new(format!("rfshare v{}", self.version))
                            .size(10.5).color(p.text_faint),
                    );

                    if let Some(ref latest) = self.update_available {
                        ui.add_space(6.0);
                        let resp = ui.add(
                            egui::Button::new(
                                RichText::new(format!("↑ {} available", latest))
                                    .size(10.0).color(p.warn).strong()
                            ).frame(false)
                        );
                        if resp.clicked() {
                            open_url("https://github.com/imrany/rfshare/releases/latest");
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
                        if let Some(peer) = self.selected_peer() {
                            ui.painter().circle_filled(
                                ui.cursor().left_top() + Vec2::new(4.0, 7.0),
                                4.0, p.success);
                            ui.add_space(12.0);
                            ui.label(
                                RichText::new(&peer.name)
                                    .size(10.5).color(p.text_dim),
                            );
                        } else {
                            ui.painter().circle_filled(
                                ui.cursor().left_top() + Vec2::new(4.0, 7.0),
                                4.0, p.text_faint);
                            ui.add_space(12.0);
                            ui.label(
                                RichText::new("No device connected")
                                    .size(10.5).color(p.text_faint),
                            );
                        }
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

// ─── Scan tab ────────────────────────────────────────────────────────────────
impl App {
    fn show_scan(&mut self, ui: &mut egui::Ui, ctx: &egui::Context, wide: bool) {
        let p = self.p();
        let avail_w = ui.available_width();
        let col_w = if wide {
            (avail_w - 64.0).min(580.0)
        } else {
            avail_w - 32.0
        };
        let x_pad = (avail_w - col_w) / 2.0;
        let scanning = self.scan_state == ScanState::Scanning;

        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            ui.add_space(20.0);
            ui.horizontal(|ui| {
                ui.add_space(x_pad);
                ui.vertical(|ui| {
                    ui.set_width(col_w);
                    ui.horizontal(|ui| {
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if self.scan_state != ScanState::Idle && !scanning {
                                if ui.add(egui::Button::new(
                                    RichText::new(format!("  {}  ", "Rescan")).size(13.0).strong().color(Color32::WHITE))
                                    .fill(p.accent).corner_radius(8.0)
                                    .min_size(Vec2::new(80.0, 32.0))).clicked()
                                {
                                    self.start_scan();
                                }
                                ui.add_space(8.0);
                                egui::Frame::new()
                                    .fill(p.surface2)
                                    .stroke(Stroke::new(1.0, if !self.scan_filter.is_empty() { p.accent } else { p.border }))
                                    .corner_radius(8.0)
                                    .inner_margin(egui::Margin { left: 10, right: 10, top: 6, bottom: 6 })
                                    .show(ui, |ui| {
                                        ui.set_min_width(ui.available_width());
                                        ui.horizontal(|ui| {
                                            ui.label(RichText::new(icons::ICON_SEARCH).size(14.0).color(p.text_dim));
                                            ui.add_space(6.0);
                                            ui.add(egui::TextEdit::singleline(&mut self.scan_filter)
                                                .hint_text("Search by name or IP…")
                                                .desired_width(ui.available_width() - 33.0)
                                                .frame(false));
                                            if !self.scan_filter.is_empty() {
                                                if ui.add(egui::Button::new(
                                                    RichText::new(icons::ICON_CLOSE).size(12.0).color(p.text_dim))
                                                    .frame(false)).clicked()
                                                {
                                                    self.scan_filter.clear();
                                                }
                                            }
                                        });
                                    });
                            }
                        });
                    });
                    ui.add_space(12.0);

                    if self.scan_state == ScanState::Idle {
                        ui.vertical_centered(|ui| {
                            ui.add_space(24.0);
                            radar_graphic(ui, &p, self.scan_pulse, false);
                            ui.add_space(12.0);
                            ui.label(RichText::new("Scan your network to find devices running rfshare")
                                .size(12.0).color(p.text_dim));
                            ui.add_space(16.0);
                            if ui.add(big_btn("  Scan for Devices  ", p.accent)).clicked() {
                                self.start_scan();
                            }
                        });
                        ui.add_space(24.0);
                    }

                    if self.scan_state == ScanState::Scanning {
                        ui.vertical_centered(|ui| {
                            ui.add_space(24.0);
                            radar_graphic(ui, &p, self.scan_pulse, true);
                            ui.add_space(12.0);
                            ui.label(RichText::new("Looking for devices on your network…")
                                .size(12.0).color(p.text_dim));
                            ui.add_space(24.0);
                        });
                        ctx.request_repaint_after(std::time::Duration::from_millis(40));
                    }

                    if self.scan_state == ScanState::Done {
                        let filter = self.scan_filter.to_lowercase();

                        let peers = self.peers.clone();
                        let (mut recent, mut others): (Vec<_>, Vec<_>) = peers.iter()
                            .enumerate()
                            .partition(|(_, p)| p.addr.to_string() == self.saved_peer_addr);
                        others.sort_by(|(_, a), (_, b)| a.name.cmp(&b.name));
                        let ordered: Vec<(usize, &Peer)> = recent.drain(..).chain(others.drain(..)).collect();

                        let visible: Vec<(usize, &Peer)> = ordered.into_iter()
                            .filter(|(_, peer)| filter.is_empty()
                                || peer.name.to_lowercase().contains(&filter)
                                || peer.addr.to_string().contains(&filter))
                            .collect();

                        if visible.is_empty() {
                            ui.vertical_centered(|ui| {
                                ui.add_space(20.0);
                                if !filter.is_empty() {
                                    ui.label(RichText::new("No devices match your search")
                                        .size(13.0).color(p.text_dim));
                                } else {
                                    ui.label(RichText::new("No devices found on this network")
                                        .strong().size(13.0).color(p.text));
                                    ui.add_space(4.0);
                                    ui.label(RichText::new("Ensure the other device is running rfshare on the same Wi-Fi")
                                        .size(11.0).color(p.text_dim));
                                }
                                ui.add_space(20.0);
                            });
                        } else {
                            let first_is_recent = !self.saved_peer_addr.is_empty()
                                && visible.first().map(|(_, p)| p.addr.to_string() == self.saved_peer_addr)
                                .unwrap_or(false);

                            for (list_idx, (peer_idx, peer)) in visible.iter().enumerate() {
                                let is_recent = peer.addr.to_string() == self.saved_peer_addr;
                                let sel = self.selected == Some(*peer_idx);

                                if list_idx == 0 && first_is_recent {
                                    ui.label(RichText::new("Recently connected")
                                        .size(11.0).strong().color(p.text_faint));
                                    ui.add_space(4.0);
                                } else if list_idx == 1 && first_is_recent {
                                    ui.add_space(6.0);
                                    ui.label(RichText::new("Other devices")
                                        .size(11.0).strong().color(p.text_faint));
                                    ui.add_space(4.0);
                                } else if list_idx == 0 && !first_is_recent && !visible.is_empty() {
                                    ui.label(RichText::new("Available devices")
                                        .size(11.0).strong().color(p.text_faint));
                                    ui.add_space(4.0);
                                }

                                if scan_peer_row(ui, &p, peer, sel, is_recent).clicked() {
                                    self.selected = if sel { None } else { Some(*peer_idx) };
                                    if self.selected.is_some() {
                                        self.saved_peer_name = peer.name.clone();
                                        self.saved_peer_addr = peer.addr.to_string();
                                        self.rebuild_sync_jobs();
                                        self.persist_prefs();
                                        self.tab = Tab::Send;
                                    } else {
                                        self.rebuild_sync_jobs();
                                    }
                                }
                                ui.add_space(6.0);
                            }
                        }
                    }

                    if self.scan_state == ScanState::Done
                        && !self.saved_peer_name.is_empty()
                        && !self.peers.iter().any(|p| p.addr.to_string() == self.saved_peer_addr)
                    {
                        ui.add_space(8.0);
                        egui::Frame::new()
                            .fill(tint(p.danger, 10))
                            .stroke(Stroke::new(1.0, tint(p.danger, 40))).corner_radius(8.0)
                            .inner_margin(egui::Margin::same(10))
                            .show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    ui.label(RichText::new(icons::ICON_DEVICES.to_string()).size(11.0).color(p.danger));
                                    ui.add_space(6.0);
                                    ui.label(RichText::new(format!("{} — not available on this network",
                                        self.saved_peer_name)).size(11.5).color(p.danger));
                                });
                            });
                    }
                });
            });
            ui.add_space(24.0);
        });
    }
}

// ─── Send tab ────────────────────────────────────────────────────────────────
impl App {
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
                            "Sending to  {}  ·  {}", peer.name, peer.addr))
                            .size(12.0).color(p2.accent));
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.add(egui::Button::new(
                                RichText::new("Change").size(11.0).color(p2.text_dim))
                                .frame(false)).clicked()
                            {
                                self.tab = Tab::Scan;
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
                    check_item(ui, &p, peer_ok, "Device selected");
                    ui.add_space(20.0);
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
}

// ─── History tab ─────────────────────────────────────────────────────────────
impl App {
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
}

fn history_row(ui: &mut egui::Ui, p: &Pal, entry: &HistoryEntry) {
    let file_exists = entry.file_exists();
    let is_received = entry.direction == TransferDir::Received;

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

// ─── Sync tab ─────────────────────────────────────────────────────────────────
impl App {
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

        egui::ScrollArea::vertical().auto_shrink([false,false]).show(ui, |ui| {
            ui.add_space(24.0);
            ui.horizontal(|ui| {
                ui.add_space(x_pad);
                ui.vertical(|ui| {
                    ui.set_width(col_w);

                    ui.horizontal(|ui| {
                        icon_badge(ui, "📁", p.accent);
                        ui.add_space(8.0);
                        ui.label(RichText::new("Folder Sync").strong().size(15.0).color(p.text));
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if self.sync_active {
                                if ui.add(pill_btn(&format!("{}  Stop watching", icons::ICON_STOP_CIRCLE), p.danger)).clicked() {
                                    self.stop_sync();
                                }
                                ui.add_space(8.0);
                                ui.spinner();
                                ui.add_space(4.0);
                                ui.label(RichText::new("Watching…").size(11.0).color(p.success));
                            } else if peer_available {
                                let has_folder = self.sync_map
                                    .contains_key(&self.selected_peer()
                                        .map(|p| p.addr.to_string()).unwrap_or_default());
                                if has_folder {
                                    if ui.add(big_btn(&format!("{}  Start watching", icons::ICON_SYNC), p.accent)).clicked() {
                                        self.rebuild_sync_jobs();
                                        self.start_sync_watcher();
                                    }
                                }
                            }
                        });
                    });
                    ui.add_space(6.0);
                    ui.label(RichText::new("Add folders below. New files dropped in are automatically sent to the selected device.")
                        .size(12.0).color(p.text_dim));
                    ui.add_space(14.0);

                    if !peer_available {
                        egui::Frame::new().fill(tint(p.warn,12)).stroke(Stroke::new(1.0,tint(p.warn,50)))
                            .corner_radius(8.0).inner_margin(egui::Margin::same(12))
                            .show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    ui.label(RichText::new("⚠").size(14.0).color(p.warn));
                                    ui.add_space(6.0);
                                    if !self.saved_peer_name.is_empty() {
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
                        let has_folder = self.selected_peer()
                            .and_then(|p| self.sync_map.get(&p.addr.to_string()))
                            .is_some();
                        let lbl = if has_folder { &format!("{}  Change folder", icons::ICON_FOLDER) }
                                  else { &format!("{}  Set folder to watch", icons::ICON_FOLDER) };
                        if ui.add(pill_btn(lbl, p.accent)).clicked() {
                            if !self.is_pro() {
                                self.show_upgrade = true;
                            } else if let Some(folder) = rfd::FileDialog::new().pick_folder() {
                                self.add_sync_folder(folder);
                            }
                        }
                    });
                    ui.add_space(12.0);

                    let current_folder: Option<PathBuf> = self.selected_peer()
                        .and_then(|peer| self.sync_map.get(&peer.addr.to_string()))
                        .cloned();

                    if let Some(ref folder) = current_folder {
                        let folder_exists = folder.exists();
                        let sent_count = self.sync_jobs.first()
                            .map(|j| j.file_mtimes.len()).unwrap_or(0);
                        let border_col = if !folder_exists { tint(p.warn, 55) }
                                         else if self.sync_active { tint(p.success, 55) }
                                         else { p.border };
                        let fill_col   = if !folder_exists { tint(p.warn, 10) }
                                         else if self.sync_active { tint(p.success, 8) }
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
                                            if self.sync_active {
                                                status_badge(ui, "WATCHING", p.success);
                                            }
                                            if !folder_exists {
                                                status_badge(ui, "MISSING", p.warn);
                                            }
                                        });
                                        let full = folder.to_string_lossy();
                                        let display = if full.len() > 50 {
                                            format!("…{}", &full[full.len().saturating_sub(48)..])
                                        } else { full.to_string() };
                                        ui.label(RichText::new(format!("{}  ·  {} file{} synced",
                                            display, sent_count, if sent_count==1{""} else{"s"}))
                                            .size(11.0).color(p.text_dim));
                                    });

                                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                        if ui.add(egui::Button::new(
                                            RichText::new(icons::ICON_CLOSE).size(13.0).color(p.text_dim))
                                            .frame(false)).clicked()
                                        {
                                            self.remove_sync_folder();
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
                            ui.label(RichText::new(
                                "Click 'Set folder' above, new files added will be automatically sent to the selected device.")
                                .size(11.0).color(p.text_faint));
                            ui.add_space(18.0);
                        });
                    }

                    if !self.sync_log.is_empty() && peer_available {
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
                                        self.sync_log.clear();
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
                                        for line in self.sync_log.iter().rev() {
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

        if self.sync_active {
            ctx.request_repaint_after(std::time::Duration::from_millis(500));
        }
    }
}

// ─── Settings tab ─────────────────────────────────────────────────────────────
impl App {
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
                                RichText::new("rfshare Pro — Active")
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
                            Some(("Pro activated! Enjoy rfshare Pro.".into(), false));
                        self.license_key_buf.clear();
                    } else {
                        self.license_msg =
                            Some(("Invalid license key. Check and try again.".into(), true));
                    }
                }
            });
            ui.add_space(8.0);
            if ui.add(pill_btn("Buy a license", p.pro)).clicked() {
                open_url("https://rfshare.imrany.dev/pro");
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
            ui.label(RichText::new("rfshare").strong().size(18.0).color(p.text));
            ui.label(
                RichText::new(format!("v{}", self.version.clone()))
                    .size(12.0)
                    .color(p.text_dim),
            );
            ui.add_space(6.0);
            ui.label(
                RichText::new("Fast, encrypted LAN file transfers.")
                    .size(12.0)
                    .color(p.text_dim),
            );
            ui.add_space(16.0);
            for (label, url) in [
                ("GitHub", "https://github.com/imrany/rfshare"),
                ("Changelog", "https://github.com/imrany/rfshare/releases"),
                ("Bug Report", "https://github.com/imrany/rfshare/issues"),
            ] {
                if ui.add(pill_btn(label, p.accent)).clicked() {
                    open_url(url);
                }
                ui.add_space(6.0);
            }
        });
    }

    fn check_for_update(&mut self) {
        if self.update_rx.is_some() || self.update_available.is_some() { return; }
        let current = self.version.clone();
        let (tx, rx) = std::sync::mpsc::channel::<Option<String>>();
        self.update_rx = Some(rx);
        thread::spawn(move || {
            let _ = tx.send(fetch_latest_version()
                .filter(|v| is_newer(v, &current)));
        });
    }
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

fn scan_peer_row(
    ui: &mut egui::Ui,
    p: &Pal,
    peer: &Peer,
    selected: bool,
    is_recent: bool,
) -> egui::Response {
    let fill = if selected {
        tint(p.accent, 22)
    } else {
        p.surface
    };
    let stroke = if selected {
        Stroke::new(1.5, p.accent)
    } else {
        Stroke::new(1.0, p.border)
    };
    let (rect, resp) =
        ui.allocate_exact_size(Vec2::new(ui.available_width(), 62.0), Sense::click());
    let bg = if resp.hovered() {
        tint(p.accent, 14)
    } else {
        fill
    };
    ui.painter().rect(
        rect,
        CornerRadius::same(10),
        bg,
        stroke,
        egui::StrokeKind::Outside,
    );

    let av = egui::pos2(rect.left() + 30.0, rect.center().y);
    let av_col = if is_recent { p.accent } else { p.accent2 };
    ui.painter().circle_filled(av, 20.0, tint(av_col, 35));
    ui.painter().text(
        av,
        egui::Align2::CENTER_CENTER,
        &peer
            .name
            .chars()
            .next()
            .unwrap_or('?')
            .to_uppercase()
            .to_string(),
        egui::FontId::proportional(17.0),
        av_col,
    );

    ui.painter().text(
        egui::pos2(rect.left() + 60.0, rect.center().y - 9.0),
        egui::Align2::LEFT_CENTER,
        &peer.name,
        egui::FontId::proportional(13.5),
        p.text,
    );
    ui.painter().text(
        egui::pos2(rect.left() + 60.0, rect.center().y + 9.0),
        egui::Align2::LEFT_CENTER,
        peer.addr.to_string(),
        egui::FontId::proportional(11.0),
        p.text_dim,
    );

    if selected {
        ui.painter().text(
            egui::pos2(rect.right() - 16.0, rect.center().y),
            egui::Align2::RIGHT_CENTER,
            icons::ICON_CHECK,
            egui::FontId::proportional(16.0),
            p.success,
        );
    } else if is_recent {
        ui.painter().text(
            egui::pos2(rect.right() - 16.0, rect.center().y),
            egui::Align2::RIGHT_CENTER,
            icons::ICON_SCHEDULE,
            egui::FontId::proportional(14.0),
            p.text_faint,
        );
    }

    resp
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
    h.update(b"rfshare-v1");
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
    on_progress: impl Fn(f32),
) -> Result<(), String> {
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
        "rfshare — File Received",
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
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const CNW: u32 = 0x08000000;
        let sc = format!(
            "[Windows.UI.Notifications.ToastNotificationManager,Windows.UI.Notifications,ContentType=WindowsRuntime]>$null;\
         $t=[Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02);\
         $t.SelectSingleNode('//text[@id=1]').InnerText='{}';\
         $t.SelectSingleNode('//text[@id=2]').InnerText='{}';\
         [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('rfshare').Show([Windows.UI.Notifications.ToastNotification]::new($t))",
            title, body
        );
        let _ = std::process::Command::new("powershell")
            .args(["-WindowStyle", "Hidden", "-Command", &sc])
            .creation_flags(CNW)
            .spawn();
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
        let _ = std::process::Command::new("explorer")
            .arg(d)
            .creation_flags(0x08000000)
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

// ─── main ─────────────────────────────────────────────────────────────────────
fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("rfshare")
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
        "rfshare",
        options,
        Box::new(|cc| {
            egui_extras::install_image_loaders(&cc.egui_ctx);
            egui_material_icons::initialize(&cc.egui_ctx);
            Ok(Box::new(App::default()))
        }),
    )
}
