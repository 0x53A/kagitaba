use super::*;

impl App {
    pub(super) fn access_ui(&mut self, ui: &mut egui::Ui) {
        ui.heading("Manage access");
        theme::caption(ui, "Participant");
        let previous = self.access_target;
        egui::ComboBox::from_id_salt("access-participant")
            .selected_text(self.access_target.map(|id| participant_label(&id, &self.participant_names)).unwrap_or_else(|| "Choose participant…".into()))
            .show_ui(ui, |ui| {
                for id in &self.participants {
                    ui.selectable_value(&mut self.access_target, Some(*id), participant_label(id, &self.participant_names));
                }
            });
        if previous != self.access_target {
            self.access_preview = None;
            self.send(Command::DiscardAccess);
        }
        if let Some(id) = self.access_target { ui.add(egui::Label::new(egui::RichText::new(id.to_string()).monospace().small().color(theme::MUTED)).wrap()); }
        if let Some(preview) = &self.access_preview {
            theme::section(ui, "All readable entries and collections");
            for (label, count) in [("New grants", preview.new_grants), ("Already granted", preview.already_granted), ("Unavailable", preview.unavailable)] {
                ui.horizontal(|ui| { theme::caption(ui, label); ui.label(count.to_string()); });
            }
            if ui.add_enabled_ui(self.unlocked.is_some() && preview.new_grants > 0, |ui| theme::primary(ui, "Grant access and sign")).inner.clicked() {
                self.access_preview = None;
                self.send(Command::ApplyAccess);
            }
        }
        if ui.add_enabled(self.unlocked.is_some() && self.access_target.is_some(), egui::Button::new(if self.access_preview.is_some() { "Refresh preview" } else { "Preview access" })).clicked() {
            self.access_preview = None;
            self.send(Command::PreviewAccess(self.access_target.unwrap()));
        }
    }
}
