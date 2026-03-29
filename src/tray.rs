use tray_icon::{
    menu::{Menu, MenuEvent, MenuId, MenuItem, PredefinedMenuItem},
    TrayIcon, TrayIconBuilder,
};

pub enum TrayEvent {
    ShowWindow,
    Quit,
}

/// Owns the tray icon for its lifetime — dropping it removes the icon.
pub struct TrayManager {
    _icon:   Option<TrayIcon>,   // must stay alive; drop = tray icon disappears
    show_id: MenuId,
    quit_id: MenuId,
}

impl TrayManager {
    /// Build and show the system tray icon.
    ///
    /// Platform timing requirements:
    ///   - Linux:  call AFTER `gtk::init()` in main()
    ///   - Windows / macOS: call before `eframe::run_native()`
    pub fn new(app_name: &str) -> Result<Self, Box<dyn std::error::Error>> {
        #[cfg(target_os = "linux")]
        {
            let desktop = std::env::var("XDG_CURRENT_DESKTOP").unwrap_or_default();
            if desktop.to_uppercase().contains("GNOME") {
                eprintln!(
                    "[tray] GNOME hides tray icons by default. \
                     Install the 'AppIndicator and KStatusNotifierItem' \
                     GNOME Shell extension to see the icon."
                );
            }
        }

        let show_item = MenuItem::new("Show", true, None);
        let quit_item = MenuItem::new("Quit", true, None);

        // Clone the IDs before the items are moved into the menu
        let show_id = show_item.id().clone();
        let quit_id = quit_item.id().clone();

        let menu = Menu::new();
        menu.append(&show_item)?;
        menu.append(&PredefinedMenuItem::separator())?;
        menu.append(&quit_item)?;

        let icon = load_icon()?;

        let tray_icon = TrayIconBuilder::new()
            .with_menu(Box::new(menu))
            .with_tooltip(app_name)
            .with_icon(icon)
            .build()?;

        Ok(Self {
            _icon: Some(tray_icon),
            show_id,
            quit_id,
        })
    }

    pub fn try_recv(&self) -> Option<TrayEvent> {
        match MenuEvent::receiver().try_recv() {
            Ok(event) if event.id == self.show_id => Some(TrayEvent::ShowWindow),
            Ok(event) if event.id == self.quit_id  => Some(TrayEvent::Quit),
            _ => None,
        }
    }
}

fn load_icon() -> Result<tray_icon::Icon, Box<dyn std::error::Error>> {
    let icon_bytes = include_bytes!("../assets/icon.png");
    let image      = image::load_from_memory(icon_bytes)?;
    let rgba       = image.to_rgba8();
    let (width, height) = (rgba.width(), rgba.height());
    let pixels     = rgba.into_raw();
    tray_icon::Icon::from_rgba(pixels, width, height).map_err(|e| e.into())
}
