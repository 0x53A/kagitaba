use crate::{backend::import_preview::PreviewEntry, theme};
use eframe::egui;

pub fn diagnostics(ui: &mut egui::Ui, warnings: &crate::backend::ImportWarnings, entries: &mut [PreviewEntry], skip_duplicates: bool) -> Option<usize> {
    let mut focus = None;
    let visible = |diagnostic: &crate::backend::ImportDiagnostic| !skip_duplicates || !diagnostic.entry_index.and_then(|i| entries.get(i)).is_some_and(|entry| entry.existing_duplicate);
    let count = warnings.details.iter().filter(|d| visible(d)).count();
    if count == 0 { return focus; }
    egui::CollapsingHeader::new(format!("Import issues ({count})"))
        .default_open(true).show(ui, |ui| {
        for (index, diagnostic) in warnings.details.iter().enumerate() {
            if skip_duplicates && diagnostic.entry_index.and_then(|i| entries.get(i)).is_some_and(|entry| entry.existing_duplicate) { continue; }
            ui.push_id(("import-warning", index), |ui| {
                if let Some(entry_index) = diagnostic.entry_index
                    && let Some(entry) = entries.get_mut(entry_index) {
                    ui.horizontal_wrapped(|ui| {
                        ui.label(entry.title.as_str());
                        if ui.button("Inspect fields").clicked() {
                            entry.expanded = true;
                            focus = Some(entry_index);
                        }
                    });
                }
                ui.label(diagnostic.detail.reason);
                if let Some(field) = diagnostic.detail.field { theme::caption(ui, field); }
                theme::caption(ui, diagnostic.detail.action);
                ui.add_space(8.0);
            });
        }
    });
    focus
}

pub(super) fn duplicate_differences(ui: &mut egui::Ui, differences: &std::collections::BTreeMap<&'static str, usize>) {
    if differences.is_empty() { return; }
    egui::CollapsingHeader::new("Why other entries were not matched").show(ui, |ui| {
        for (label, count) in differences {
            ui.horizontal_wrapped(|ui| { theme::caption(ui, *label); ui.label(count.to_string()); });
        }
    });
}

#[cfg(test)]
pub fn entries(ui: &mut egui::Ui, entries: &mut [PreviewEntry]) {
    entries_focused(ui, entries, None, false);
}

pub fn entries_focused(ui: &mut egui::Ui, entries: &mut [PreviewEntry], focus: Option<usize>, skip_duplicates: bool) {
    theme::section(ui, "Entries to import");
    if entries.iter().all(|entry| skip_duplicates && entry.existing_duplicate) {
        theme::caption(ui, "No new entries to import.");
    }
    for (index, entry) in entries.iter_mut().enumerate() {
        if skip_duplicates && entry.existing_duplicate { continue; }
        ui.push_id(("import-entry", index), |ui| {
            let header = ui.horizontal_wrapped(|ui| {
                let label = match (entry.expanded, entry.collection) {
                    (false, false) => "▸ Entry", (true, false) => "▾ Entry",
                    (false, true) => "▸ Collection", (true, true) => "▾ Collection",
                };
                ui.toggle_value(&mut entry.expanded, label);
                ui.label(entry.title.as_str());
            });
            if focus == Some(index) { header.response.scroll_to_me(Some(egui::Align::Min)); }
            let mut counts = Vec::new();
            if entry.custom_fields > 0 { counts.push(format!("{} custom fields", entry.custom_fields)); }
            if entry.history_count > 0 { counts.push(format!("{} history {}", entry.history_count, if entry.history_count == 1 { "record" } else { "records" })); }
            if entry.attachment_count > 0 { counts.push(format!("{} {}", entry.attachment_count, if entry.attachment_count == 1 { "file" } else { "files" })); }
            if !counts.is_empty() { theme::caption(ui, counts.join(" · ")); }
            if !entry.expanded { return; }
            ui.indent("details", |ui| {
                for (index, field) in entry.fields.iter_mut().enumerate() {
                    ui.push_id(index, |ui| {
                        theme::caption(ui, field.label.as_str());
                        if field.sensitive {
                            ui.checkbox(&mut field.revealed, "Reveal value");
                        }
                        if !field.sensitive || field.revealed {
                            ui.label(field.value.as_str());
                        } else {
                            ui.label("••••••••");
                        }
                    });
                }
                if entry.history_count > 0 {
                    theme::section(ui, "Retained history");
                    ui.checkbox(&mut entry.reveal_history, "Reveal history (includes secrets)");
                    if entry.reveal_history {
                        egui::ScrollArea::vertical().id_salt("history").max_height(260.0).show(ui, |ui| {
                            ui.add(egui::Label::new(egui::RichText::new(entry.history.as_str()).monospace()).wrap());
                        });
                    }
                }
                theme::section(ui, "Complete retained data");
                ui.checkbox(&mut entry.reveal_raw, "Reveal complete data (includes secrets)");
                if entry.reveal_raw {
                    egui::ScrollArea::vertical().id_salt("raw").max_height(260.0).show(ui, |ui| {
                        ui.add(egui::Label::new(egui::RichText::new(entry.raw.as_str()).monospace()).wrap());
                    });
                }
            });
        });
        ui.separator();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroizing;
    #[test]
    fn skip_toggle_filters_duplicates_without_removing_review_state() {
        let mut entries = ["Matched duplicate", "New credential", "Import collection"].into_iter().enumerate().map(|(index,title)| {
            let id = kagitaba_core::EntryId::from_bytes([index as u8;16]);
            let payload = kagitaba_cxf::Payload::new(id,kagitaba_cxf::PayloadKind::Item,&serde_json::to_vec(&serde_json::json!({
                "id":data_encoding::BASE64URL_NOPAD.encode(id.as_bytes()),"title":title,"credentials":[]
            })).unwrap()).unwrap();
            let mut entry = PreviewEntry::from_payload(&payload).unwrap();
            entry.existing_duplicate = index == 0;
            entry.collection = index == 2;
            entry.expanded = index == 0;
            entry
        }).collect::<Vec<_>>();
        let ctx = egui::Context::default();
        for skip in [false,true,false] {
            let input = egui::RawInput { screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO,egui::vec2(1200.0,1400.0))), ..Default::default() };
            let mut first = ctx.run_ui(input.clone(), |ui| entries_focused(ui,&mut entries,None,skip));
            first.textures_delta.clear();
            let mut output = ctx.run_ui(input, |ui| entries_focused(ui,&mut entries,None,skip));
            output.textures_delta.clear();
            fn text(shape: &egui::epaint::Shape, out: &mut String) {
                match shape {
                    egui::epaint::Shape::Text(t) => out.push_str(&t.galley.job.text),
                    egui::epaint::Shape::Vec(shapes) => for shape in shapes { text(shape,out); },
                    _ => (),
                }
            }
            let mut visible = String::new();
            for shape in output.shapes { text(&shape.shape,&mut visible); }
            assert_eq!(visible.contains("Matched duplicate"),!skip);
            assert!(visible.contains("New credential"));
            assert!(visible.contains("Import collection"));
            assert_eq!(entries.len(),3);
            assert!(entries[0].expanded);
        }
    }

    #[test]
    fn expanded_preview_masks_fields_history_and_source_until_reveal() {
        let mut entry = PreviewEntry {
            title: Zeroizing::new("Synthetic entry".into()), collection: false, existing_duplicate: false,
            custom_fields: 1, attachment_count: 0, history_count: 1, history: Zeroizing::new("SECRET_HISTORY".into()),
            raw: Zeroizing::new("SECRET_SOURCE".into()), expanded: true, reveal_raw: false, reveal_history: false,
            fields: vec![crate::backend::import_preview::PreviewField {
                label: Zeroizing::new("Recovery".into()), value: Zeroizing::new("SECRET_VALUE".into()), sensitive: true, revealed: false,
            }],
        };
        let ctx = egui::Context::default();
        for reveal in [false, true] {
            entry.reveal_history = reveal;
            entry.reveal_raw = reveal;
            entry.fields[0].revealed = reveal;
            let input = egui::RawInput { screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(1200.0, 1400.0))), ..Default::default() };
            let mut first = ctx.run_ui(input.clone(), |ui| entries(ui, std::slice::from_mut(&mut entry)));
            first.textures_delta.clear();
            let mut output = ctx.run_ui(input, |ui| entries(ui, std::slice::from_mut(&mut entry)));
            output.textures_delta.clear();
            fn text(shape: &egui::epaint::Shape, out: &mut String) {
                match shape {
                    egui::epaint::Shape::Text(t) => out.push_str(&t.galley.job.text),
                    egui::epaint::Shape::Vec(shapes) => for shape in shapes { text(shape, out); },
                    _ => (),
                }
            }
            let mut visible = Zeroizing::new(String::new());
            for shape in output.shapes { text(&shape.shape, &mut visible); }
            assert_eq!(visible.contains("SECRET_VALUE"), reveal);
            assert_eq!(visible.contains("SECRET_HISTORY"), reveal);
            assert_eq!(visible.contains("SECRET_SOURCE"), reveal);
        }
    }
}
