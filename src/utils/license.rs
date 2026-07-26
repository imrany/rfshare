use std::{fs, path::PathBuf};

use sha2::{Digest, Sha256};

use crate::PRO_SALT;

// ─── License ─────────────────────────────────────────────────────────────────
#[derive(Clone, Debug, PartialEq)]
pub enum Plan {
    Free,
    Pro,
}

#[derive(Clone, Debug)]
pub struct License {
    pub plan: Plan,
    pub email: String,
    pub key: String,
}

impl License {
    pub fn config_path() -> Option<PathBuf> {
        dirs::config_dir().map(|d| d.join(env!("CARGO_PKG_NAME")).join("license"))
    }

    pub fn load() -> Self {
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

    pub fn save(&self) {
        if let Some(p) = Self::config_path() {
            if let Some(parent) = p.parent() {
                let _ = fs::create_dir_all(parent);
            }
            let _ = fs::write(&p, format!("email={}\nkey={}\n", self.email, self.key));
        }
    }

    pub fn validate_key(key: &str) -> bool {
        let parts: Vec<&str> = key.split('-').collect();
        if parts.len() != 5 || parts.iter().any(|p| p.len() != 5) {
            return false;
        }
        let body = parts[..4].join("-");
        let mut h = Sha256::new();
        h.update(body.as_bytes());
        h.update(PRO_SALT);
        let hash = format!("{:X}", h.finalize());
        parts[4].to_uppercase() == hash[..5].to_uppercase()
    }

    pub fn is_pro(&self) -> bool {
        self.plan == Plan::Pro
    }
}
