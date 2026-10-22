use super::*;

impl App {
    pub(super) fn copy_ui(&mut self, ui: &mut egui::Ui) {
        ui.heading("Copy to wallet");
        if self.copy_complete {
            ui.label("Entries copied. Source unchanged.");
            if ui.button("Copy more entries").clicked() { self.copy_complete = false; }
            return;
        }
        if let Some(preview) = &mut self.copy_preview {
            theme::caption(ui, "Destination");
            ui.label(preview.path.display().to_string());
            if preview.requires_unlock {
                theme::section(ui, "Destination signing key");
                ui.horizontal(|ui| {
                    egui::ComboBox::from_id_salt("copy-device").selected_text(self.devices.get(self.device).map(|d| d.label.as_str()).unwrap_or("Choose key"))
                        .show_ui(ui, |ui| { for (i, device) in self.devices.iter().enumerate() { ui.selectable_value(&mut self.device, i, &device.label); } });
                    if ui.button("⟳").on_hover_text("Refresh destination keys").clicked() { self.send(Command::ScanCopyDevices); }
                });
                for (label, slot) in [("Encryption slot", &mut self.encryption_slot), ("Signature slot", &mut self.signing_slot)] {
                    ui.horizontal(|ui| {
                        theme::caption(ui, label);
                        egui::ComboBox::from_id_salt(("copy-slot", label)).selected_text(format!("{slot:02X}"))
                            .show_ui(ui, |ui| { for value in 0x82..=0x95 { ui.selectable_value(slot, value, format!("{value:02X}")); } });
                    });
                }
                theme::caption(ui, "PIV PIN");
                if theme::pin_input(ui, &mut self.pin, true, self.devices.get(self.device).is_some())
                    && let Some(device) = self.devices.get(self.device).cloned()
                    && let Ok(slots) = kagitaba_device::Slots::new(self.encryption_slot, self.signing_slot) {
                    let pin = Zeroizing::new(std::mem::take(&mut self.pin));
                    self.send(Command::UnlockCopy(device, slots, pin));
                }
                return;
            }
            import_preview::duplicate_differences(ui, &preview.review.duplicate_differences);
            ui.checkbox(&mut self.copy_skip_duplicates, format!("Skip {} existing duplicates", preview.review.existing_duplicates));
            if preview.review.unavailable_entries > 0 {
                theme::caption(ui, format!("{} entries are not available to this key", preview.review.unavailable_entries));
            }
            import_preview::entries_focused(ui, &mut preview.review.entries, None, self.copy_skip_duplicates);
            theme::section(ui, "Destination access");
            recipient_ui(ui, &preview.participants, &BTreeMap::new(), &mut self.copy_recipients);
            if ui.add_enabled_ui(!self.copy_recipients.is_empty(), |ui| theme::primary(ui, "Copy and sign")).inner.clicked() {
                self.send(Command::CopyEntries(self.copy_recipients.clone(), self.copy_skip_duplicates));
            }
            if ui.button("Choose another wallet").clicked() {
                self.copy_preview = None;
                self.copy_recipients.clear();
                self.send(Command::DiscardCopy);
            }
            return;
        }
        theme::caption(ui, "Select entries");
        let mut entries: Vec<_> = self.index_rows.iter().filter(|(_,row)| row.kind == kagitaba_cxf::PayloadKind::Item).collect();
        entries.sort_by(|(a_id,a),(b_id,b)| a.title.cmp(&b.title).then(a_id.cmp(b_id)));
        ui.horizontal(|ui| {
            if ui.button("Select all").clicked() { self.copy_selection = entries.iter().map(|(id,_)| **id).collect(); }
            if ui.button("Clear").clicked() { self.copy_selection.clear(); }
        });
        for (id,row) in entries {
            let mut selected = self.copy_selection.contains(id);
            if ui.checkbox(&mut selected, &row.title).changed() {
                if selected { self.copy_selection.insert(*id); } else { self.copy_selection.remove(id); }
            }
        }
        if ui.add_enabled_ui(!self.copy_selection.is_empty() && self.unlocked.is_some(), |ui| theme::primary(ui, "Choose destination wallet…")).inner.clicked() {
            self.pick(Pick::CopyDestination);
        }

    }
}
