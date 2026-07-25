// ─── Shared UI helpers ────────────────────────────────────────────────────────
use egui::{
    Align, Align2, Button, Color32, CornerRadius, FontId, Frame, Margin, RichText, Sense, Stroke,
    StrokeKind, Ui, Vec2,
};
use egui_material_icons::icons;

use crate::{
    HistoryEntry, Pal, QueueItem, TransferDir, TransferType,
    utils::{file_icon, format_size, open_folder, truncate_filename},
};

pub fn card<R>(ui: &mut Ui, p: &Pal, f: impl FnOnce(&mut Ui) -> R) {
    Frame::new()
        .fill(p.surface)
        .stroke(Stroke::new(1.0_f32, p.border))
        .corner_radius(14.0)
        .inner_margin(Margin {
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

pub fn history_row(ui: &mut Ui, p: &Pal, entry: &HistoryEntry) {
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
    Frame::new()
        .fill(fill)
        .stroke(Stroke::new(1.0_f32, border))
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
                            format!("…{}", &path_str[path_str.len().saturating_sub(59)..])
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

pub fn queue_item_row(
    ui: &mut Ui,
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
    Frame::new()
        .fill(fill)
        .stroke(Stroke::new(1.0_f32, border_col))
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

pub fn drop_zone(ui: &mut Ui, p: &Pal, hovering: bool) {
    let (rect, _) = ui.allocate_exact_size(Vec2::new(ui.available_width(), 86.0), Sense::hover());
    let fill = if hovering {
        tint(p.accent, 22)
    } else {
        p.surface2
    };
    let stroke = if hovering {
        Stroke::new(2.0_f32, p.accent)
    } else {
        Stroke::new(1.0_f32, p.border)
    };
    ui.painter().rect(
        rect,
        CornerRadius::same(10),
        fill,
        stroke,
        StrokeKind::Outside,
    );
    ui.painter().text(
        rect.center() - Vec2::new(0.0, 11.0),
        Align2::CENTER_CENTER,
        icons::ICON_ARROW_UPWARD,
        FontId::proportional(20.0),
        if hovering { p.accent } else { p.text_faint },
    );
    ui.painter().text(
        rect.center() + Vec2::new(0.0, 13.0),
        Align2::CENTER_CENTER,
        if hovering {
            "Release to add files"
        } else {
            "Drag & drop files  or  Browse…"
        },
        FontId::proportional(11.5),
        if hovering { p.text_dim } else { p.text_faint },
    );
}

pub fn drop_hint(ui: &mut Ui, p: &Pal, hovering: bool) {
    let (rect, _) = ui.allocate_exact_size(Vec2::new(ui.available_width(), 34.0), Sense::hover());
    let fill = if hovering {
        tint(p.accent, 18)
    } else {
        Color32::TRANSPARENT
    };
    let stroke = if hovering {
        Stroke::new(1.0_f32, p.accent)
    } else {
        Stroke::new(1.0_f32, tint(p.border, 100))
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

pub fn info_row(ui: &mut Ui, p: &Pal, icon: &str, label: &str, value: &str) {
    ui.horizontal(|ui| {
        let (r, _) = ui.allocate_exact_size(Vec2::new(20.0, 16.0), Sense::hover());
        ui.painter().text(
            r.center(),
            Align2::CENTER_CENTER,
            icon,
            FontId::proportional(13.0),
            p.text_faint,
        );
        ui.add_space(8.0);
        ui.label(RichText::new(label).size(11.0).color(p.text_faint));
        ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
            ui.label(RichText::new(value).size(11.5).color(p.text));
        });
    });
}

pub fn status_badge(ui: &mut Ui, text: &str, color: Color32) {
    Frame::new()
        .fill(tint(color, 25))
        .corner_radius(4.0)
        .inner_margin(Margin {
            left: 4,
            right: 4,
            top: 1,
            bottom: 1,
        })
        .show(ui, |ui| {
            ui.label(RichText::new(text).size(8.5).strong().color(color));
        });
}

pub fn tint(c: Color32, a: u8) -> Color32 {
    Color32::from_rgba_unmultiplied(c.r(), c.g(), c.b(), a)
}

pub fn icon_badge(ui: &mut Ui, icon: &str, color: Color32) {
    let (r, _) = ui.allocate_exact_size(Vec2::splat(26.0), Sense::hover());
    ui.painter()
        .circle_filled(r.center(), 13.0, tint(color, 25));
    ui.painter().text(
        r.center(),
        Align2::CENTER_CENTER,
        icon,
        FontId::proportional(13.0),
        color,
    );
}

pub fn pill_btn(text: &str, accent: Color32) -> egui::Button<'static> {
    Button::new(RichText::new(text.to_string()).size(12.0).color(accent))
        .fill(tint(accent, 28))
        .corner_radius(20.0)
}

pub fn big_btn(text: &str, accent: Color32) -> egui::Button<'static> {
    Button::new(
        RichText::new(text.to_string())
            .size(13.0)
            .strong()
            .color(Color32::WHITE),
    )
    .fill(accent)
    .corner_radius(10.0)
    .min_size(Vec2::new(150.0, 38.0))
}

pub fn check_item(ui: &mut Ui, p: &Pal, done: bool, label: &str) {
    ui.horizontal(|ui| {
        let (r, _) = ui.allocate_exact_size(Vec2::splat(16.0), Sense::hover());
        if done {
            ui.painter()
                .circle_filled(r.center(), 7.0, tint(p.success, 30));
            ui.painter().text(
                r.center(),
                Align2::CENTER_CENTER,
                icons::ICON_CHECK,
                FontId::proportional(12.0),
                p.success,
            );
        } else {
            ui.painter()
                .circle_stroke(r.center(), 7.0, Stroke::new(1.0_f32, p.text_faint));
        }
        ui.add_space(4.0);
        ui.label(
            RichText::new(label)
                .size(12.0)
                .color(if done { p.text } else { p.text_dim }),
        );
    });
}

pub fn radar_graphic(ui: &mut Ui, p: &Pal, pulse: f32, animated: bool) {
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(72.0), Sense::hover());
    let c = rect.center();
    if animated {
        for i in 0..3u32 {
            let phase = (pulse - i as f32 * 0.6).sin() * 0.5 + 0.5;
            let r = 12.0 + i as f32 * 16.0;
            let a = (phase * 100.0) as u8;
            ui.painter()
                .circle_stroke(c, r, Stroke::new(1.5_f32, tint(p.accent, a)));
        }
    } else {
        for (r, a) in [(36u8, 35u8), (26, 55), (16, 80)] {
            ui.painter()
                .circle_stroke(c, r as f32, Stroke::new(1.0_f32, tint(p.accent, a)));
        }
    }
    ui.painter().circle_filled(c, 9.0, tint(p.accent, 180));
    ui.painter().text(
        c,
        Align2::CENTER_CENTER,
        "✈",
        FontId::proportional(11.0),
        Color32::WHITE,
    );
}

pub fn status_metric(ui: &mut Ui, p: &Pal, icon: &str, text: &str) {
    ui.horizontal(|ui| {
        ui.label(RichText::new(icon).size(11.0).color(p.text_faint));
        ui.add_space(3.0);
        ui.label(RichText::new(text).size(10.5).color(p.text_dim));
    });
}
