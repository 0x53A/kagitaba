use super::*;

impl App {
    pub(super) fn duplicates_ui(&mut self, ui: &mut egui::Ui) {
        ui.heading("Delete duplicates");
        let Some(preview) = &self.duplicate_preview else {
            if ui.add_enabled(self.unlocked.is_some(), egui::Button::new("Find exact duplicates")).clicked() {
                self.send(Command::PreviewDuplicates);
            }
            return;
        };
        let removed: usize = preview.groups.iter().map(|group| group.removed.len()).sum();
        if preview.unavailable_entries > 0 {
            theme::caption(ui, format!("{} entries are not available to this key", preview.unavailable_entries));
        }
        if removed == 0 { ui.label("No exact duplicates found."); }
        for group in &preview.groups {
            ui.push_id(group.survivor, |ui| {
                theme::section(ui, group.title.as_str());
                theme::caption(ui, format!("Keep {} · remove {} copies · {} recipients", &group.survivor.to_string()[..8], group.removed.len(), group.recipient_count));
                egui::CollapsingHeader::new("Entry IDs").show(ui, |ui| {
                    ui.label(format!("Keep {}", group.survivor));
                    for id in &group.removed { ui.label(format!("Remove {id}")); }
                });
                ui.separator();
            });
        }
        if removed > 0 {
            theme::caption(ui, "Recipients are combined. Readable collection links are updated.");
            if ui.add_enabled(self.unlocked.is_some(), egui::Button::new(egui::RichText::new(format!("Delete {removed} duplicates and sign")).color(theme::BACKGROUND)).fill(theme::ERROR)).clicked() {
                self.send(Command::DeleteDuplicates);
            }
        }
        if ui.button("Scan again").clicked() {
            self.duplicate_preview = None;
            self.send(Command::PreviewDuplicates);
        }
    }
}
