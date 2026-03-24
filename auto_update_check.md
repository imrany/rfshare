# Adding auto-update check to rfshare

These are the exact changes to make in `src/main.rs`.

---

## 1. Add fields to the `App` struct

After the `version` and `this_ip` fields, add:

```rust
    // Update checker
    update_available: Option<String>,   // Some("v0.5.7") when a newer version exists
    update_rx: Option<std::sync::mpsc::Receiver<Option<String>>>,
```

---

## 2. Initialize in `App::default()`

After `this_ip: local_ip(),` add:

```rust
            update_available: None,
            update_rx:        None,
```

---

## 3. Add `check_for_update()` method

Add this method inside `impl App` (alongside `start_scan`, `poll`, etc.):

```rust
    fn check_for_update(&mut self) {
        // Only check once per session
        if self.update_rx.is_some() || self.update_available.is_some() { return; }

        let current = self.version.clone();
        let (tx, rx) = std::sync::mpsc::channel::<Option<String>>();
        self.update_rx = Some(rx);

        thread::spawn(move || {
            let result = fetch_latest_version();
            match result {
                Some(latest) if is_newer(&latest, &current) => {
                    let _ = tx.send(Some(latest));
                }
                _ => { let _ = tx.send(None); }
            }
        });
    }
```

---

## 4. Add `fetch_latest_version()` and `is_newer()` free functions

Add these near the other utility functions (e.g. near `hostname()`):

```rust
/// Fetch the latest release tag from GitHub API.
/// Uses only std — no reqwest dependency needed.
fn fetch_latest_version() -> Option<String> {
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpStream;

    // HTTPS over raw TCP requires TLS — use a simple HTTP redirect trick:
    // connect to api.github.com:443 via std TcpStream with native-tls, OR
    // fall back to the redirect endpoint on port 80 which returns a 301
    // pointing to the latest release URL containing the tag in the Location header.
    //
    // github.com/owner/repo/releases/latest  →  301  →  /releases/tag/vX.Y.Z
    let host = "github.com";
    let path = "/imrany/rfshare/releases/latest";

    let stream = TcpStream::connect((host, 80)).ok()?;
    stream.set_read_timeout(Some(std::time::Duration::from_secs(5))).ok()?;
    {
        let mut w = stream.try_clone().ok()?;
        write!(w,
            "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: rfshare-updater\r\nConnection: close\r\n\r\n",
            path, host
        ).ok()?;
    }

    let reader = BufReader::new(stream);
    for line in reader.lines().take(20) {
        let line = line.ok()?;
        // Location: https://github.com/imrany/rfshare/releases/tag/v0.5.7
        if line.to_ascii_lowercase().starts_with("location:") {
            let loc = line[9..].trim();
            if let Some(tag) = loc.rsplit('/').next() {
                if tag.starts_with('v') {
                    return Some(tag.to_string());
                }
            }
        }
    }
    None
}

/// Returns true if `latest` is strictly newer than `current`.
/// Compares semver numeric components: "v0.5.7" > "v0.5.3".
fn is_newer(latest: &str, current: &str) -> bool {
    fn parse(v: &str) -> Option<(u32, u32, u32)> {
        let v = v.trim_start_matches('v');
        let mut p = v.splitn(3, '.');
        Some((
            p.next()?.parse().ok()?,
            p.next()?.parse().ok()?,
            p.next()?.split('-').next()?.parse().ok()?,   // strip pre-release suffix
        ))
    }
    match (parse(latest), parse(current)) {
        (Some(l), Some(c)) => l > c,
        _ => false,
    }
}
```

---

## 5. Poll the update channel in `poll()`

At the **end** of `fn poll(&mut self)`, after the sync channel polling, add:

```rust
        // Update checker
        if let Some(rx) = &self.update_rx {
            if let Ok(result) = rx.try_recv() {
                self.update_available = result;
                self.update_rx = None;
            }
        }
```

---

## 6. Start the check in `update()` (eframe::App)

In `fn update(&mut self, ctx, _frame)`, right after `self.poll();`, add:

```rust
        // Kick off update check once on first frame
        self.check_for_update();
```

---

## 7. Show the update banner in the top bar

In the topbar `show()` closure, after the PRO badge block (the `if self.is_pro()` block)
and before the `ui.with_layout(right_to_left ...)` block, add:

```rust
                    // Update available banner
                    if let Some(ref latest) = self.update_available {
                        let latest = latest.clone();
                        let (r, _) = ui.allocate_exact_size(
                            Vec2::new(ui.available_width().min(220.0), 22.0),
                            Sense::hover(),
                        );
                        ui.painter().rect_filled(r, 4.0, tint(p.warn, 30));
                        let label = format!("↑ {} available", latest);
                        let text_resp = ui.put(r, egui::Label::new(
                            RichText::new(&label).size(11.0).color(p.warn).strong()
                        ));
                        if text_resp.clicked() {
                            open_url("https://github.com/imrany/rfshare/releases/latest");
                        }
                    }
```

---

## 8. Show update notice in the footer

In `show_about_panel`, replace the plain version label:

```rust
            ui.label(RichText::new(format!("v{}", self.version)).size(12.0).color(p.text_dim));
```

with:

```rust
            ui.label(RichText::new(format!("v{}", self.version)).size(12.0).color(p.text_dim));
            if let Some(ref latest) = self.update_available {
                ui.add_space(4.0);
                if ui.add(pill_btn(
                    &format!("↑ {} available — download", latest), p.warn
                )).clicked() {
                    open_url("https://github.com/imrany/rfshare/releases/latest");
                }
            }
```

---

## How it works

- On first frame `check_for_update()` spawns a background thread.
- The thread connects to `github.com:80`, sends a plain HTTP `GET` to
  `/imrany/rfshare/releases/latest`, and reads the `Location:` header from
  the 301 redirect — the tag name (`v0.5.7`) is the last path segment.
- No new dependencies needed — uses only `std::net::TcpStream`.
- The result is sent back via an `mpsc` channel and picked up in `poll()`.
- If the latest tag is numerically greater than `env!("CARGO_PKG_VERSION")`,
  `update_available` is set to `Some("v0.5.7")` and the banner appears.
- Clicking the banner or the Settings button opens the releases page.
