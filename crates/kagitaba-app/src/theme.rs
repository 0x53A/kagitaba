use eframe::egui::{self, Color32};

pub const BACKGROUND: Color32 = Color32::from_rgb(6, 10, 13);
pub const SURFACE: Color32 = Color32::from_rgb(11, 18, 22);
pub const INK: Color32 = Color32::from_rgb(216, 230, 234);
pub const AQUA: Color32 = Color32::from_rgb(47, 224, 200);
pub const LINE: Color32 = Color32::from_rgb(52, 82, 92);
pub const ERROR: Color32 = Color32::from_rgb(245, 182, 212);

pub fn install(ctx: &egui::Context) {
    let mut style = (*ctx.style_of(egui::Theme::Dark)).clone();
    style.visuals = egui::Visuals::dark();
    style.visuals.override_text_color = Some(INK);
    style.visuals.panel_fill = BACKGROUND;
    style.visuals.window_fill = SURFACE;
    style.visuals.extreme_bg_color = BACKGROUND;
    style.visuals.selection.bg_fill = Color32::from_rgb(24, 66, 70);
    style.visuals.selection.stroke = egui::Stroke::new(1.0, AQUA);
    style.visuals.window_corner_radius = egui::CornerRadius::ZERO;
    style.visuals.window_shadow = egui::epaint::Shadow::NONE;
    style.visuals.menu_corner_radius = egui::CornerRadius::ZERO;
    style.visuals.popup_shadow = egui::epaint::Shadow::NONE;
    #[cfg(feature = "smoke")]
    if std::env::var_os("KAGITABA_SMOKE_SCENE").is_some() {
        style.animation_time = 0.0;
    }
    style.spacing.item_spacing = egui::vec2(10.0, 10.0);
    style.spacing.button_padding = egui::vec2(14.0, 9.0);
    style.spacing.interact_size.y = 36.0;
    for (kind, size) in [
        (egui::TextStyle::Body, 16.0),
        (egui::TextStyle::Button, 16.0),
        (egui::TextStyle::Heading, 25.0),
        (egui::TextStyle::Small, 13.0),
    ] {
        style
            .text_styles
            .insert(kind, egui::FontId::proportional(size));
    }
    for widget in [
        &mut style.visuals.widgets.active,
        &mut style.visuals.widgets.inactive,
        &mut style.visuals.widgets.hovered,
        &mut style.visuals.widgets.noninteractive,
        &mut style.visuals.widgets.open,
    ] {
        widget.corner_radius = egui::CornerRadius::ZERO;
        widget.bg_stroke = egui::Stroke::new(1.0, LINE);
        widget.fg_stroke.color = INK;
    }
    style.visuals.widgets.inactive.bg_fill = SURFACE;
    style.visuals.widgets.inactive.weak_bg_fill = SURFACE;
    style.visuals.widgets.hovered.bg_fill = Color32::from_rgb(24, 46, 52);
    style.visuals.widgets.hovered.weak_bg_fill = Color32::from_rgb(24, 46, 52);
    style.visuals.widgets.active.bg_fill = Color32::from_rgb(24, 66, 70);
    ctx.set_style_of(egui::Theme::Dark, style);
    ctx.set_theme(egui::Theme::Dark);
}

pub fn primary(ui: &mut egui::Ui, text: &str) -> egui::Response {
    ui.add(egui::Button::new(egui::RichText::new(text).color(BACKGROUND)).fill(AQUA))
}

pub fn surface() -> egui::Frame {
    egui::Frame::new()
        .fill(SURFACE)
        .stroke(egui::Stroke::new(1.0, LINE))
        .inner_margin(18)
}
