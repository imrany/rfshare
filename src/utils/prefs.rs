use std::{collections::HashMap, fs, path::PathBuf};

#[derive(Default)]
pub struct SavedPrefs {
    pub peer_name: String,
    pub peer_addr: String,
    pub sync_map: HashMap<String, PathBuf>,
    pub save_dir: Option<PathBuf>,
    pub notify_on_receive: bool,
    pub auto_open_folder: bool,
    pub manual_peers: Vec<(String, String)>,
    pub auto_detect_theme: bool,
    pub dark_mode: Option<bool>,
}

pub fn prefs_path() -> Option<PathBuf> {
    dirs::config_dir().map(|d| d.join(env!("CARGO_PKG_NAME")).join("prefs.json"))
}

pub fn save_prefs(prefs: SavedPrefs) {
    let Some(path) = prefs_path() else { return };
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let mut out = String::new();
    out.push_str(&format!("selected_peer_name={}\n", prefs.peer_name));
    out.push_str(&format!("selected_peer_addr={}\n", prefs.peer_addr));
    for (device_addr, folder) in prefs.sync_map {
        let safe = device_addr.replace('.', "_").replace(':', "_");
        out.push_str(&format!("sync_device_{}={}\n", safe, folder.display()));
    }
    for (i, (name, addr)) in prefs.manual_peers.iter().enumerate() {
        out.push_str(&format!("manual_peer_{}_name={}\n", i, name));
        out.push_str(&format!("manual_peer_{}_addr={}\n", i, addr));
    }
    if let Some(ref d) = prefs.save_dir {
        out.push_str(&format!("save_dir={}\n", d.display()));
    }
    out.push_str(&format!(
        "notify_on_receive={}\n",
        prefs.notify_on_receive as u8
    ));
    out.push_str(&format!(
        "auto_open_folder={}\n",
        prefs.auto_open_folder as u8
    ));
    out.push_str(&format!(
        "auto_detect_theme={}\n",
        prefs.auto_detect_theme as u8
    ));
    if let Some(dark) = prefs.dark_mode {
        out.push_str(&format!("dark_mode={}\n", dark as u8));
    }
    let _ = fs::write(&path, out);
}

pub fn load_prefs() -> SavedPrefs {
    let mut prefs = SavedPrefs::default();
    let Some(path) = prefs_path() else {
        return prefs;
    };
    let Ok(text) = fs::read_to_string(&path) else {
        return prefs;
    };

    let mut mp_names: std::collections::HashMap<usize, String> = Default::default();
    let mut mp_addrs: std::collections::HashMap<usize, String> = Default::default();

    for line in text.lines() {
        if let Some(v) = line.strip_prefix("selected_peer_name=") {
            prefs.peer_name = v.to_string();
        }
        if let Some(v) = line.strip_prefix("selected_peer_addr=") {
            prefs.peer_addr = v.to_string();
        }
        if let Some(rest) = line.strip_prefix("sync_device_") {
            if let Some(eq) = rest.find('=') {
                let addr = rest[..eq].replace('_', ".");
                prefs.sync_map.insert(addr, PathBuf::from(&rest[eq + 1..]));
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
        if let Some(v) = line.strip_prefix("auto_detect_theme=") {
            prefs.auto_detect_theme = v == "1";
        }
        if let Some(v) = line.strip_prefix("dark_mode=") {
            prefs.dark_mode = Some(v == "1");
        }
        if let Some(rest) = line.strip_prefix("manual_peer_") {
            if let Some(idx_end) = rest.find('_') {
                if let Ok(idx) = rest[..idx_end].parse::<usize>() {
                    let suffix = &rest[idx_end + 1..];
                    if let Some(v) = suffix.strip_prefix("name=") {
                        mp_names.insert(idx, v.to_string());
                    }
                    if let Some(v) = suffix.strip_prefix("addr=") {
                        mp_addrs.insert(idx, v.to_string());
                    }
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
