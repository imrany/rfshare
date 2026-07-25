use std::{
    net::UdpSocket,
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

use egui_material_icons::icons;

// ─── Utilities ────────────────────────────────────────────────────────────────
pub fn unique_path(dir: &Path, name: &str) -> PathBuf {
    let p = dir.join(name);
    if !p.exists() {
        return p;
    }
    let stem = Path::new(name)
        .file_stem()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    let ext = Path::new(name)
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

pub fn truncate_filename(name: &str, max_len: usize) -> String {
    if name.len() <= max_len {
        return name.to_string();
    }
    let mut t = name.to_string();
    t.truncate(max_len);
    format!("{}…{}", t, &name[name.len().saturating_sub(4)..])
}

pub fn local_ip() -> String {
    UdpSocket::bind("0.0.0.0:0")
        .and_then(|s| {
            s.connect("8.8.8.8:80")?;
            s.local_addr()
        })
        .map(|a| a.ip().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}

pub fn hostname() -> String {
    Command::new("hostname")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .unwrap_or_else(|| "this-device".into())
        .trim()
        .to_string()
}

pub fn notify(title: &str, body: &str) -> Result<(), ()> {
    #[cfg(target_os = "linux")]
    {
        let _ = Command::new("notify-send").arg(title).arg(body).spawn();
    }
    #[cfg(target_os = "macos")]
    {
        let sc = format!("display notification \"{}\" with title \"{}\"", body, title);
        let _ = Command::new("osascript").arg("-e").arg(&sc).spawn();
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const CNW: u32 = 0x08000000;
        let temp_dir = std::env::temp_dir();
        let script_path = temp_dir.join(format!("toast_{}.ps1", std::process::id()));
        let title_escaped = title.replace("'", "''");
        let body_escaped = body.replace("'", "''");
        let exe_path = std::env::current_exe().unwrap_or_default();
        let exe_path_str = exe_path.to_string_lossy().replace('\\', "\\\\");
        let script_content = format!(
            "$title = '{}'
            $body = '{}'
            $exePath = '{}'
            try {{
                [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
                $template = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02)
                $textNodes = $template.GetElementsByTagName('text')
                $textNodes[0].AppendChild($template.CreateTextNode($title)) | Out-Null
                $textNodes[1].AppendChild($template.CreateTextNode($body)) | Out-Null
                $appId = '{}.{}'
                $notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($appId)
                $toast = [Windows.UI.Notifications.ToastNotification]::new($template)
                $toast.Tag = 'FileTransfer'
                $toast.Group = 'Transfers'
                $toast.ExpirationTime = [DateTimeOffset]::Now.AddSeconds(30)
                $notifier.Show($toast)
            }} catch {{
                Add-Type -AssemblyName System.Windows.Forms
                $notification = New-Object System.Windows.Forms.NotifyIcon
                if (Test-Path $exePath) {{ $notification.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon($exePath) }}
                $notification.BalloonTipTitle = $title
                $notification.BalloonTipText = $body
                $notification.BalloonTipIcon = [System.Windows.Forms.ToolTipIcon]::Info
                $notification.Visible = $true
                $notification.ShowBalloonTip(3000)
                Start-Sleep -Seconds 3
                $notification.Dispose()
            }}",
            title_escaped, body_escaped, exe_path_str,
            env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION")
        );
        let _ = std::fs::write(&script_path, script_content);
        let _ = std::process::Command::new("powershell")
            .args([
                "-WindowStyle",
                "Hidden",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                script_path.to_str().unwrap(),
            ])
            .creation_flags(CNW)
            .spawn();
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_secs(5));
            let _ = std::fs::remove_file(script_path);
        });
    }
    Ok(())
}

pub fn open_folder(p: &Path) {
    let d = p.parent().unwrap_or(p);
    #[cfg(target_os = "linux")]
    {
        let _ = Command::new("xdg-open").arg(d).spawn();
    }
    #[cfg(target_os = "macos")]
    {
        let _ = Command::new("open").arg(d).spawn();
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const CNW: u32 = 0x08000000;
        let _ = std::process::Command::new("cmd")
            .args(["/c", "start", ""])
            .arg(d)
            .creation_flags(CNW)
            .spawn();
    }
}

pub fn open_url(url: &str) {
    #[cfg(target_os = "linux")]
    {
        let _ = Command::new("xdg-open").arg(url).spawn();
    }
    #[cfg(target_os = "macos")]
    {
        let _ = Command::new("open").arg(url).spawn();
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

pub fn format_size(b: u64) -> String {
    const U: &[&str; 5] = &["B", "KB", "MB", "GB", "TB"];
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

pub fn file_icon(name: &str) -> &'static str {
    let ext = Path::new(name)
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

pub fn detect_system_theme() -> bool {
    #[cfg(target_os = "macos")]
    {
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
            if let Ok(value) = key.get_value::<u32, _>("AppsUseLightTheme") {
                return value == 0;
            }
        }
        false
    }
    #[cfg(target_os = "linux")]
    {
        use std::process::Command;
        let output = Command::new("gsettings")
            .args(["get", "org.gnome.desktop.interface", "gtk-theme"])
            .output();
        if let Ok(o) = output {
            return String::from_utf8_lossy(&o.stdout)
                .to_lowercase()
                .contains("dark");
        }
        false
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    {
        false
    }
}

/// Generate a random 8-char session code like "A3F7-K2M9"
pub fn gen_session_code() -> String {
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    let chars: Vec<char> = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789".chars().collect();
    let mut n = seed as usize;
    let mut code = String::new();
    for i in 0..8 {
        if i == 4 {
            code.push('-');
        }
        n = n
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        code.push(chars[(n >> 33) % chars.len()]);
    }
    code
}
