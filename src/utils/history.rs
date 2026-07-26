use std::{
    fs,
    io::Write,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::App;

// ─── History ─────────────────────────────────────────────────────────────────
#[derive(Clone, Debug, PartialEq)]
pub struct HistoryEntry {
    pub timestamp: u64,
    pub direction: TransferDir,
    pub file_name: String,
    pub file_size: u64,
    pub peer_name: String,
    pub success: bool,
    pub error: Option<String>,
    pub transfer_type: TransferType,
    pub file_path: Option<PathBuf>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum TransferType {
    Local,
    Remote,
}

#[derive(Clone, Debug, PartialEq)]
pub enum TransferDir {
    Sent,
    Received,
}

impl HistoryEntry {
    pub fn time_display(&self) -> String {
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

    pub fn file_exists(&self) -> bool {
        self.file_path.as_ref().map(|p| p.exists()).unwrap_or(false)
    }

    // Helper to format an entry consistently for CSV writing
    pub fn to_csv_line(&self) -> String {
        let dir = if self.direction == TransferDir::Sent {
            "sent"
        } else {
            "received"
        };
        let trans_type = if self.transfer_type == TransferType::Local {
            "local"
        } else {
            "remote"
        };
        let err = self.error.as_deref().unwrap_or("").replace(',', ";");
        let fpath = self
            .file_path
            .as_ref()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default()
            .replace(',', ";");
        let success = if self.success { 1 } else { 0 };

        format!(
            "{},{},{},{},{},{},{},{},{}\n",
            self.timestamp,
            dir,
            trans_type,
            self.file_name,
            self.file_size,
            self.peer_name,
            success,
            err,
            fpath
        )
    }
}

pub fn history_path() -> Option<PathBuf> {
    dirs::config_dir().map(|d| d.join(env!("CARGO_PKG_NAME")).join("history.csv"))
}

pub fn load_history() -> Vec<HistoryEntry> {
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
        let trans_type = if cols.len() >= 3 {
            if cols[2] == "remote" {
                TransferType::Remote
            } else {
                TransferType::Local
            }
        } else {
            TransferType::Local
        };
        let name = if cols.len() >= 4 {
            cols[3].to_string()
        } else {
            cols[2].to_string()
        };
        let size = if cols.len() >= 5 {
            cols[4].parse::<u64>().unwrap_or(0)
        } else {
            cols[3].parse::<u64>().unwrap_or(0)
        };
        let peer = if cols.len() >= 6 {
            cols[5].to_string()
        } else {
            cols[4].to_string()
        };
        let success = if cols.len() >= 7 {
            cols[6] == "1"
        } else {
            cols[5] == "1"
        };
        let err = if cols.len() >= 8 {
            if cols[7].is_empty() {
                None
            } else {
                Some(cols[7].to_string())
            }
        } else {
            if cols[6].is_empty() {
                None
            } else {
                Some(cols[6].to_string())
            }
        };
        let fpath = cols
            .get(8)
            .filter(|s| !s.is_empty())
            .map(|s| PathBuf::from(s));
        out.push(HistoryEntry {
            timestamp: ts,
            direction: dir,
            transfer_type: trans_type,
            file_name: name,
            file_size: size,
            peer_name: peer,
            success,
            error: err,
            file_path: fpath,
        });
    }
    out.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
    out
}

pub fn append_history(entry: &HistoryEntry) {
    let Some(path) = history_path() else {
        return;
    };
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }

    let needs_header = !path.exists();
    if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).open(&path) {
        if needs_header {
            let _ = writeln!(
                f,
                "timestamp,direction,type,name,size,peer,success,error,file_path"
            );
        }
        let _ = f.write_all(entry.to_csv_line().as_bytes());
    }
}

// Rewrites the ENTIRE file with a fresh list of remaining vector entries
pub fn save_all_history(entries: &[HistoryEntry]) -> std::io::Result<()> {
    let Some(path) = history_path() else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "History path unavailable",
        ));
    };

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let mut f = fs::File::create(&path)?;
    writeln!(
        f,
        "timestamp,direction,type,name,size,peer,success,error,file_path"
    )?;
    for entry in entries {
        f.write_all(entry.to_csv_line().as_bytes())?;
    }
    Ok(())
}

pub fn delete_from_history(
    app: &mut App,
    entry: &HistoryEntry,
) -> Result<Vec<HistoryEntry>, String> {
    if app.history.is_empty() {
        return Err("History memory is already empty".to_string());
    }

    // Filter out the target entry
    let updated_history: Vec<HistoryEntry> = app
        .history
        .iter()
        .filter(|en| *en != entry)
        .cloned()
        .collect();

    // Persist changes to disk safely
    if let Err(e) = save_all_history(&updated_history) {
        return Err(format!("Failed to save updated history: {}", e));
    }

    Ok(updated_history)
}
