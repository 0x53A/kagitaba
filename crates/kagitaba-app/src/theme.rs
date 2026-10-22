use eframe::egui::{self, Color32};

pub const BACKGROUND: Color32 = Color32::from_rgb(6, 10, 13);
pub const SURFACE: Color32 = Color32::from_rgb(11, 18, 22);
pub const INK: Color32 = Color32::from_rgb(216, 230, 234);
pub const AQUA: Color32 = Color32::from_rgb(47, 224, 200);
pub const LINE: Color32 = Color32::from_rgb(52, 82, 92);
pub const MUTED: Color32 = Color32::from_rgb(135, 157, 165);
pub const ERROR: Color32 = Color32::from_rgb(245, 182, 212);

pub fn install(ctx: &egui::Context) {
    // Discrete mouse-wheel lines only: retain precise touchpad point deltas.
    ctx.options_mut(|options| options.input_options.line_scroll_speed = 100.0);
    let mut fonts = egui::FontDefinitions::default();
    fonts.font_data.insert(
        "Kagitaba data".into(),
        egui::FontData::from_static(include_bytes!("../../../assets/fonts/DejaVuSansMono.ttf"))
            .into(),
    );
    fonts
        .families
        .entry(egui::FontFamily::Monospace)
        .or_default()
        .insert(0, "Kagitaba data".into());
    // Preserve arrow/checkmark coverage after the proportional interface font.
    fonts
        .families
        .entry(egui::FontFamily::Proportional)
        .or_default()
        .push("Kagitaba data".into());
    fonts.font_data.insert(
        "DejaVu Sans Bold".into(),
        egui::FontData::from_static(include_bytes!("../assets/DejaVuSans-Bold.ttf")).into(),
    );
    fonts.families.insert(
        egui::FontFamily::Name("bold".into()),
        vec!["DejaVu Sans Bold".into()],
    );
    ctx.set_fonts(fonts);
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
    style.spacing.scroll = egui::style::ScrollStyle::solid();
    style.spacing.scroll.foreground_color = true;
    style.spacing.scroll.bar_width = 8.0;
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
    style
        .text_styles
        .insert(egui::TextStyle::Monospace, egui::FontId::monospace(16.0));
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
    style.visuals.widgets.inactive.fg_stroke.color = MUTED;
    style.visuals.widgets.inactive.bg_fill = SURFACE;
    style.visuals.widgets.inactive.weak_bg_fill = SURFACE;
    style.visuals.widgets.hovered.bg_fill = Color32::from_rgb(24, 46, 52);
    style.visuals.widgets.hovered.weak_bg_fill = Color32::from_rgb(24, 46, 52);
    style.visuals.widgets.active.bg_fill = Color32::from_rgb(24, 66, 70);
    ctx.set_style_of(egui::Theme::Dark, style);
    ctx.set_theme(egui::Theme::Dark);
}

/// Secondary labels and instructions; values keep normal foreground contrast.
pub fn caption(ui: &mut egui::Ui, text: impl Into<String>) -> egui::Response {
    ui.label(egui::RichText::new(text).size(13.0).color(MUTED))
}

pub fn section(ui: &mut egui::Ui, text: &str) -> egui::Response {
    ui.add_space(6.0);
    ui.label(egui::RichText::new(text).size(18.0).strong())
}

pub fn primary(ui: &mut egui::Ui, text: &str) -> egui::Response {
    ui.scope(|ui| {
        let widgets = &mut ui.visuals_mut().widgets;
        widgets.inactive.weak_bg_fill = AQUA;
        widgets.hovered.weak_bg_fill = Color32::from_rgb(113, 245, 225);
        widgets.active.weak_bg_fill = Color32::from_rgb(27, 172, 156);
        ui.add(egui::Button::new(
            egui::RichText::new(text).color(BACKGROUND),
        ))
    })
    .inner
}

pub fn surface() -> egui::Frame {
    egui::Frame::new()
        .fill(SURFACE)
        .stroke(egui::Stroke::new(1.0, LINE))
        .inner_margin(18)
}

pub fn pin_input(ui: &mut egui::Ui, pin: &mut String, editable: bool, key_available: bool) -> bool {
    let mut submit = false;
    let mut focused = false;
    let frame = egui::Frame::new()
        .fill(BACKGROUND)
        .stroke(egui::Stroke::new(1.0, LINE))
        .show(ui, |ui| {
            ui.spacing_mut().item_spacing.x = 0.0;
            ui.horizontal(|ui| {
                let input = ui
                    .add_enabled_ui(editable, |ui| {
                        ui.add_sized(
                            [200.0, 36.0],
                            egui::TextEdit::singleline(pin)
                                .id(egui::Id::new("piv-pin"))
                                .password(true)
                                .vertical_align(egui::Align::Center)
                                .frame(egui::Frame::NONE)
                                .margin(egui::vec2(8.0, 8.0)),
                        )
                    })
                    .inner;
                focused = input.has_focus();
                let enter = (input.has_focus() || input.lost_focus())
                    && ui.input(|i| i.key_pressed(egui::Key::Enter));
                let ready = editable && key_available && !pin.is_empty();
                let clicked = ui
                    .add_enabled_ui(ready, |ui| {
                        primary(ui, "→").on_hover_text("Unlock key").clicked()
                    })
                    .inner;
                submit = ui.is_enabled() && ready && (enter || clicked);
            });
        });
    if focused {
        ui.painter().rect_stroke(
            frame.response.rect,
            egui::CornerRadius::ZERO,
            egui::Stroke::new(1.0, AQUA),
            egui::StrokeKind::Inside,
        );
    }
    submit
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enter_submits_only_a_ready_focused_pin() {
        for (pin, editable, available, focused, enabled, expected) in [
            ("123456", true, true, true, true, true),
            ("", true, true, true, true, false),
            ("123456", true, false, true, true, false),
            ("123456", false, true, true, true, false),
            ("123456", true, true, false, true, false),
            ("123456", true, true, true, false, false),
        ] {
            let ctx = egui::Context::default();
            let mut pin = pin.to_owned();
            let mut submitted = false;
            let mut draw = |ui: &mut egui::Ui| {
                egui::CentralPanel::default().show(ui, |ui| {
                    ui.add_enabled_ui(enabled, |ui| {
                        submitted = pin_input(ui, &mut pin, editable, available);
                    });
                });
            };
            let mut output = ctx.run_ui(Default::default(), &mut draw);
            output.textures_delta.clear();
            if focused {
                ctx.memory_mut(|memory| memory.request_focus(egui::Id::new("piv-pin")));
            }
            let input = egui::RawInput {
                events: vec![egui::Event::Key {
                    key: egui::Key::Enter,
                    physical_key: None,
                    pressed: true,
                    repeat: false,
                    modifiers: Default::default(),
                }],
                ..Default::default()
            };
            let mut output = ctx.run_ui(input, &mut draw);
            output.textures_delta.clear();
            assert_eq!(submitted, expected);
        }
    }
}
