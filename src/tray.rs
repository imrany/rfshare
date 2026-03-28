use std::sync::mpsc::{self, Receiver};
use tray_icon::{
    menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem},
    TrayIcon, TrayIconBuilder,
};

/// Events the tray can send back to the application.
pub enum TrayEvent {
    ShowWindow,
    Quit,
}

/// Owns the tray icon for its lifetime.
/// Drop this to remove the tray icon.
pub struct TrayManager {
    // Kept alive to keep the icon visible
    _icon: Option<TrayIcon>,
    pub event_rx: Receiver<TrayEvent>,
}

impl TrayManager {
    /// Build and show the tray icon.
    /// Call this once from main() BEFORE starting the eframe event loop.
    pub fn new(app_name: &str) -> Result<Self, Box<dyn std::error::Error>> {
        // Check if running on GNOME
        #[cfg(target_os = "linux")]
        {
            if std::env::var("XDG_CURRENT_DESKTOP")
                .unwrap_or_default()
                .contains("GNOME")
            {
                eprintln!("Note: GNOME hides tray icons by default. Install an extension like 'AppIndicator' to see the tray icon.");
            }
        }

        let (event_tx, event_rx) = mpsc::channel::<TrayEvent>();

        // ── Menu ──────────────────────────────────────────────────────────
        let show_item = MenuItem::new("Show", true, None);
        let quit_item = MenuItem::new("Quit", true, None);

        let menu = Menu::new();
        menu.append(&show_item)?;
        menu.append(&PredefinedMenuItem::separator())?;
        menu.append(&quit_item)?;

        let show_id = show_item.id().clone();
        let quit_id = quit_item.id().clone();

        let menu_rx = MenuEvent::receiver().clone();  // &'static Receiver<MenuEvent>
        std::thread::spawn(move || {
            for event in menu_rx.iter() {
                if event.id == show_id {
                    let _ = event_tx.send(TrayEvent::ShowWindow);
                } else if event.id == quit_id {
                    let _ = event_tx.send(TrayEvent::Quit);
                }
            }
        });

        // ── Icon ──────────────────────────────────────────────────────────
        let icon = load_icon()?;

        // ── Build tray ────────────────────────────────────────────────────
        let tray_icon = TrayIconBuilder::new()
            .with_menu(Box::new(menu))
            .with_tooltip(app_name)
            .with_icon(icon)
            .build()?;

        Ok(Self {
            _icon: Some(tray_icon),
            event_rx,
        })
    }

    /// Poll for pending tray events (non-blocking).
    /// Call this inside App::poll() or eframe update().
    pub fn try_recv(&self) -> Option<TrayEvent> {
        self.event_rx.try_recv().ok()
    }
}

// read actual image dimensions from the PNG instead of hardcoding 32×32.
fn load_icon() -> Result<tray_icon::Icon, Box<dyn std::error::Error>> {
    let icon_bytes = include_bytes!("../assets/icon.png");
    let image      = image::load_from_memory(icon_bytes)?;
    let rgba       = image.to_rgba8();
    let width      = rgba.width();
    let height     = rgba.height();
    let pixels     = rgba.into_raw();
    tray_icon::Icon::from_rgba(pixels, width, height).map_err(|e| e.into())
}
