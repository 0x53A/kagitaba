use crate::backend::{Command, Event};
use eframe::egui;
use kagitaba_core::{EntryId, KeyId};
use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::mpsc,
    time::{Duration, Instant},
};
use zeroize::{Zeroize, Zeroizing};
#[derive(Clone, Copy)]
enum Pick {
    Pull,
    Backup,
    Create,
    Open,
    ExportParticipant,
    Participant,
    Import,
    Keyfile,
}
pub struct App {
    ctx: egui::Context,
    editor_epoch: u64,
    tx: mpsc::Sender<Command>,
    rx: mpsc::Receiver<Event>,
    busy: bool,
    status: String,
    devices: Vec<kagitaba_device::usb::Device>,
    device: usize,
    pin: String,
    management: String,
    provision: bool,
    consent: bool,
    unlocked: Option<String>,
    wallet: Option<PathBuf>,
    entries: Vec<EntryId>,
    participants: Vec<KeyId>,
    head: String,
    titles: BTreeMap<EntryId, Zeroizing<String>>,
    search: String,
    selected: Option<EntryId>,
    json: String,
    recipients: Vec<KeyId>,
    import_recipients: Vec<KeyId>,
    import_format: String,
    import_password: String,
    import_use_password: bool,
    keyfile: Option<PathBuf>,
    preview: Option<String>,
    trust: Option<(PathBuf, String)>,
    reveal: bool,
    delete_confirm: bool,
    last_activity: Instant,
    locking: bool,
    participant_preview: Option<(
        kagitaba_core::crypto::PublicKey,
        kagitaba_core::crypto::PublicKey,
    )>,
    clipboard: crate::editor::Clipboard,
    dialog: egui_file_dialog::FileDialog,
    pick: Option<Pick>,
    clear_ui_memory: bool,
    revoke: Option<KeyId>,
}
impl App {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let mut style = (*cc.egui_ctx.style_of(egui::Theme::Dark)).clone();
        style.visuals = egui::Visuals::dark();
        style.visuals.selection.bg_fill = egui::Color32::from_rgb(174, 62, 12);
        style.spacing.item_spacing = egui::vec2(8.0, 8.0);
        style.spacing.button_padding = egui::vec2(10.0, 6.0);
        style.spacing.interact_size.y = 28.0;
        style
            .text_styles
            .insert(egui::TextStyle::Body, egui::FontId::proportional(15.0));
        style
            .text_styles
            .insert(egui::TextStyle::Button, egui::FontId::proportional(15.0));
        style
            .text_styles
            .insert(egui::TextStyle::Heading, egui::FontId::proportional(23.0));
        for widget in [
            &mut style.visuals.widgets.active,
            &mut style.visuals.widgets.inactive,
            &mut style.visuals.widgets.hovered,
            &mut style.visuals.widgets.noninteractive,
            &mut style.visuals.widgets.open,
        ] {
            widget.corner_radius = egui::CornerRadius::ZERO;
        }
        cc.egui_ctx.set_style_of(egui::Theme::Dark, style);
        cc.egui_ctx.set_theme(egui::Theme::Dark);
        let (tx, rx) = crate::backend::start(cc.egui_ctx.clone());
        let mut app = Self::state(cc.egui_ctx.clone(), tx, rx);
        app.send(Command::Scan);
        app
    }
    fn state(ctx: egui::Context, tx: mpsc::Sender<Command>, rx: mpsc::Receiver<Event>) -> Self {
        Self {
            ctx,
            editor_epoch: 0,
            tx,
            rx,
            busy: false,
            status: "Connect a YubiKey 5 with PIV enabled.".into(),
            devices: vec![],
            device: 0,
            pin: String::new(),
            management: String::new(),
            provision: false,
            consent: false,
            unlocked: None,
            wallet: None,
            entries: vec![],
            participants: vec![],
            head: String::new(),
            titles: BTreeMap::new(),
            search: String::new(),
            selected: None,
            json: String::new(),
            recipients: vec![],
            import_recipients: vec![],
            import_format: "Bitwarden".into(),
            import_password: String::new(),
            import_use_password: true,
            keyfile: None,
            preview: None,
            trust: None,
            reveal: false,
            delete_confirm: false,
            last_activity: Instant::now(),
            locking: false,
            participant_preview: None,
            clipboard: crate::editor::Clipboard::new(),
            dialog: egui_file_dialog::FileDialog::new(),
            pick: None,
            clear_ui_memory: false,
            revoke: None,
        }
    }
    fn send(&mut self, c: Command) {
        if self.tx.send(c).is_ok() {
            self.busy = true;
            self.status = "Working — touch the YubiKey if it blinks.".into();
        }
    }
    fn clear_secrets(&mut self) {
        self.reset_entry();
        self.clear_ui_memory = true;
        self.pick = None;
        self.dialog = egui_file_dialog::FileDialog::new();
        self.clipboard.clear();
        self.pin.zeroize();
        self.management.zeroize();
        self.import_password.zeroize();
        self.json.zeroize();
        self.search.zeroize();
        self.titles.clear();
        self.selected = None;
        self.preview = None;
        self.import_recipients.clear();
        self.reveal = false;
        self.unlocked = None;
    }
    fn events(&mut self) {
        while let Ok(e) = self.rx.try_recv() {
            // Snapshot metadata must track successful worker writes even while
            // secret results and intermediate completions are suppressed.
            if self.locking
                && !matches!(
                    e,
                    Event::Locked | Event::LockComplete | Event::Wallet { .. } | Event::Devices(_)
                )
            {
                continue;
            }
            match e {
                Event::Devices(d) => {
                    self.devices = d;
                    self.device = 0;
                }
                Event::Unlocked(id) => {
                    self.unlocked = Some(id);
                    self.last_activity = Instant::now();
                    self.provision = false;
                }
                Event::Locked => {
                    self.clear_secrets();
                }
                Event::LockComplete => {
                    self.clear_secrets();
                    self.locking = false;
                }
                Event::Wallet {
                    path,
                    entries,
                    participants,
                    head,
                } => {
                    self.reset_entry();
                    self.json.zeroize();
                    self.titles.clear();
                    self.selected = None;
                    self.recipients.clear();
                    self.import_recipients.clear();
                    self.wallet = Some(path);
                    self.entries = entries;
                    self.participants = participants;
                    self.head = head;
                    self.preview = None;
                }
                Event::Trust(p, id) => self.trust = Some((p, id)),
                Event::Participant(enc, sign) => self.participant_preview = Some((enc, sign)),
                Event::Preview(s) => self.preview = Some(s),
                Event::Entry(id, json, recipients) => {
                    self.reset_entry();
                    self.json = json.to_string();
                    self.selected = Some(id);
                    self.recipients = recipients;
                    self.reveal = false;
                    self.delete_confirm = false;
                }
                Event::Titles(t) => {
                    self.titles = t.into_iter().collect();
                }
                Event::Done(result) => {
                    self.busy = false;
                    self.status = match result {
                        Ok(()) => "Ready".into(),
                        Err(e) => format!("Could not complete action: {e}"),
                    };
                }
            }
        }
    }
    fn reset_entry(&mut self) {
        self.json.zeroize();
        self.selected = None;
        self.recipients.clear();
        self.reveal = false;
        self.delete_confirm = false;
        self.editor_epoch = self.editor_epoch.wrapping_add(1);
        self.ctx.memory_mut(|m| m.data.clear());
    }
    fn select_entry(&mut self, id: EntryId) {
        self.reset_entry();
        self.selected = Some(id);
    }
    fn request_lock(&mut self) {
        if !self.locking {
            self.clear_secrets();
            self.locking = true;
            self.send(Command::Lock);
        }
    }
    fn enforce_idle_lock(&mut self, now: Instant) {
        if self.unlocked.is_some()
            && now.saturating_duration_since(self.last_activity) > Duration::from_secs(300)
        {
            self.request_lock();
        }
    }
    fn hardware_ui(&mut self, ui: &mut egui::Ui) {
        ui.heading("Hardware");
        egui::ComboBox::from_id_salt("device")
            .selected_text(
                self.devices
                    .get(self.device)
                    .map(|d| d.label.as_str())
                    .unwrap_or("No key detected"),
            )
            .show_ui(ui, |ui| {
                for (i, d) in self.devices.iter().enumerate() {
                    ui.selectable_value(&mut self.device, i, &d.label);
                }
            });
        if ui.button("Refresh USB devices").clicked() {
            self.send(Command::Scan);
        }
        if let Some(id) = &self.unlocked {
            ui.label(format!("Unlocked: {}…", &id[..16]));
        } else {
            ui.label("PIV PIN");
            ui.add(egui::TextEdit::singleline(&mut self.pin).password(true));
            if ui.button("Unlock").clicked()
                && let Some(d) = self.devices.get(self.device).cloned()
            {
                let pin = Zeroizing::new(std::mem::take(&mut self.pin));
                self.send(Command::Unlock(d, pin));
            }
        }
        ui.checkbox(&mut self.provision, "Set up a new key");
        if self.provision {
            ui.label("Generates P-256 keys in PIV slots 82 and 83. Occupied slots are never overwritten. FIDO credentials remain untouched.");
            ui.label("Encryption touch is cached briefly; signing requires a touch. Uses your existing PIV PIN and management key.");
            ui.label("Management key (hex)");
            ui.add(egui::TextEdit::singleline(&mut self.management).password(true));
            if ui.button("Use factory management key").clicked() {
                self.management = "010203040506070801020304050607080102030405060708".into();
            }
            ui.checkbox(
                &mut self.consent,
                "I authorize generating keys in empty slots 82 and 83",
            );
            if ui
                .add_enabled(self.consent, egui::Button::new("Generate on device"))
                .clicked()
                && let Some(d) = self.devices.get(self.device).cloned()
            {
                let key = Zeroizing::new(std::mem::take(&mut self.management));
                let pin = Zeroizing::new(std::mem::take(&mut self.pin));
                self.send(Command::Provision(d, key, pin));
                self.consent = false;
            }
        }
        ui.separator();
        ui.heading("Wallet");
        if ui.button("Create wallet in empty folder…").clicked() {
            self.pick(Pick::Create);
        }
        if ui.button("Open wallet folder…").clicked() {
            self.pick(Pick::Open);
        }
        if let Some(path) = &self.wallet {
            ui.label(path.display().to_string());
            ui.label(format!(
                "{} entries · {} participants",
                self.entries.len(),
                self.participants.len()
            ));
            ui.label(format!(
                "Verified {}…",
                self.head.get(..12).unwrap_or(&self.head)
            ));
        }
        if ui
            .add_enabled(
                self.wallet.is_some(),
                egui::Button::new("Pull verified updates from wallet folder…"),
            )
            .clicked()
        {
            self.pick(Pick::Pull);
        }
        if ui
            .add_enabled(
                self.wallet.is_some(),
                egui::Button::new("Create encrypted backup in empty folder…"),
            )
            .clicked()
        {
            self.pick(Pick::Backup);
        }
        ui.separator();
        if ui.button("Export this device’s public keys…").clicked() {
            self.pick(Pick::ExportParticipant);
        }
        ui.label(
            "Enrolled participants may sign wallet changes. Entry access is granted separately.",
        );
        if ui.button("Enroll participant from public keys…").clicked() {
            self.pick(Pick::Participant);
        }
        ui.collapsing("Revoke a participant",|ui|{
            ui.label("Removes signing authority and rotates every affected entry. Old copies remain readable by that key.");
            for id in &self.participants{ui.selectable_value(&mut self.revoke,Some(*id),id.to_string());}
            if ui.add_enabled(self.revoke.is_some(),egui::Button::new("Revoke selected participant and rotate")).clicked()&&let Some(id)=self.revoke.take(){self.send(Command::RemoveParticipant(id));}
        });
    }
    fn import_ui(&mut self, ui: &mut egui::Ui) {
        ui.collapsing("Import credentials",|ui|{
            egui::ComboBox::from_id_salt("format").selected_text(&self.import_format).show_ui(ui,|ui|{for f in ["Bitwarden","CXF","KeePass"]{ui.selectable_value(&mut self.import_format,f.to_string(),f);}});
            if self.import_format=="KeePass"{
                if ui.checkbox(&mut self.import_use_password,"Use password (may be empty)").changed()&&!self.import_use_password{self.import_password.zeroize();}
                ui.add_enabled(self.import_use_password,egui::TextEdit::singleline(&mut self.import_password).password(true));
                if ui.button("Choose optional key file…").clicked(){self.pick(Pick::Keyfile);}
                if ui.button("Clear key file").clicked(){self.keyfile=None;}
                if let Some(p)=&self.keyfile{ui.label(p.display().to_string());}
            }
            if ui.button("Preview import…").clicked(){self.pick(Pick::Import);}
            if let Some(report)=&self.preview{ui.label(report);ui.label("Choose recipients below. Import creates new copies; source files remain untouched. Keep source backups for attachments and unsupported credentials.");recipient_ui(ui,&self.participants,&mut self.import_recipients);if ui.add_enabled(!self.import_recipients.is_empty(),egui::Button::new("Encrypt and import selected file")).clicked(){self.send(Command::Import(self.import_recipients.clone()));}}
        });
    }
    fn entry_ui(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            if ui.button("New login").clicked() {
                self.new_entry(false);
            }
            if ui.button("New collection").clicked() {
                self.new_entry(true);
            }
            if ui.button("Decrypt titles").clicked() {
                self.send(Command::Titles);
            }
        });
        ui.add(egui::TextEdit::singleline(&mut self.search).hint_text("Search decrypted titles"));
        egui::ScrollArea::vertical()
            .max_height(180.0)
            .show(ui, |ui| {
                let mut open = None;
                for id in &self.entries {
                    let label = self
                        .titles
                        .get(id)
                        .map(|s| s.as_str())
                        .unwrap_or("Encrypted entry");
                    if !self.search.is_empty()
                        && !label.to_lowercase().contains(&self.search.to_lowercase())
                    {
                        continue;
                    }
                    if ui
                        .selectable_label(
                            self.selected == Some(*id),
                            format!("{label}  ·  {}", &id.to_string()[..8]),
                        )
                        .clicked()
                    {
                        open = Some(*id);
                    }
                }
                if let Some(id) = open {
                    self.select_entry(id);
                    self.send(Command::Read(id));
                }
            });
        ui.separator();
        if let Some(id) = self.selected {
            ui.label(format!("Entry {id}"));
            if self.json.is_empty() {
                ui.label("Encrypted entry selected. Decryption is not required to delete it.");
                if ui.button("Decrypt selected entry").clicked() {
                    self.send(Command::Read(id));
                }
            } else {
                ui.push_id((id, self.editor_epoch), |ui| {
                    if let Some(status) = crate::editor::show(ui, &mut self.json, &mut self.clipboard) {
                        self.status = status;
                    }
                    ui.checkbox(&mut self.reveal, "Reveal and edit complete CXF payload");
                    if self.reveal {
                        ui.label("All fields are preserved, including import provenance. Password edits do not change the password at the website.");
                        egui::ScrollArea::vertical()
                            .max_height(350.0)
                            .show(ui, |ui| {
                                ui.add(
                                    egui::TextEdit::multiline(&mut self.json)
                                        .code_editor()
                                        .desired_width(f32::INFINITY)
                                        .desired_rows(16),
                                );
                            });
                    } else {
                        ui.label("Credential content is concealed. Reveal to inspect or edit.");
                    }
                    ui.label("Recipients for the next revision");
                    recipient_ui(ui, &self.participants, &mut self.recipients);
                    if ui
                        .add_enabled(
                            self.entries.contains(&id) && !self.recipients.is_empty(),
                            egui::Button::new("Add selected grants without changing payload"),
                        )
                        .clicked()
                    {
                        self.send(Command::Grant(id, self.recipients.clone()));
                    }
                    ui.label("Adding grants retains existing access. To remove recipients, save a new revision with only the recipients you want.");
                    if ui
                        .add_enabled(
                            !self.recipients.is_empty(),
                            egui::Button::new("Encrypt new revision and sign"),
                        )
                        .clicked()
                    {
                        self.send(Command::Save(
                            id,
                            Zeroizing::new(self.json.clone()),
                            self.recipients.clone(),
                        ));
                    }
                });
            }
            ui.checkbox(
                &mut self.delete_confirm,
                "Confirm deletion (history remains readable)",
            );
            if ui
                .add_enabled(
                    self.delete_confirm && self.entries.contains(&id),
                    egui::Button::new("Delete entry"),
                )
                .clicked()
            {
                self.send(Command::Delete(id));
                self.json.zeroize();
                self.selected = None;
            }
        }
    }
    fn new_entry(&mut self, collection: bool) {
        match EntryId::generate(&mut rand::rngs::SysRng) {
            Ok(id) => {
                self.reset_entry();
                let encoded = data_encoding::BASE64URL_NOPAD.encode(id.as_bytes());
                let entity = if collection {
                    serde_json::json!({"id":encoded,"title":"New collection","items":[],"subCollections":[]})
                } else {
                    serde_json::json!({"id":encoded,"title":"New login","credentials":[{"type":"basic-auth","username":{"fieldType":"string","value":""},"password":{"fieldType":"concealed-string","value":""}}]})
                };
                let value = serde_json::json!({"format":"kagitaba-cxf","version":1,"cxfVersion":{"major":1,"minor":0},"kind":if collection{"collection"}else{"item"},"entity":entity});
                self.json.zeroize();
                self.json = serde_json::to_string_pretty(&value).unwrap_or_default();
                self.selected = Some(id);
                self.recipients = self.participants.clone();
                self.reveal = false;
            }
            Err(e) => self.status = e.to_string(),
        }
    }
    fn pick(&mut self, pick: Pick) {
        self.pick = Some(pick);
        match pick {
            Pick::Create | Pick::Open | Pick::Pull | Pick::Backup => self.dialog.pick_directory(),
            Pick::ExportParticipant => self.dialog.save_file(),
            _ => self.dialog.pick_file(),
        }
    }
    fn preview_import(&mut self, path: PathBuf) {
        let password = self
            .import_use_password
            .then(|| Zeroizing::new(std::mem::take(&mut self.import_password)));
        self.send(Command::Preview(
            path,
            self.import_format.clone(),
            password,
            self.keyfile.clone(),
        ));
    }
    fn dialog(&mut self, ctx: &egui::Context) {
        self.dialog.update(ctx);
        if let Some(path) = self.dialog.take_picked()
            && let Some(pick) = self.pick.take()
        {
            match pick {
                Pick::Pull => self.send(Command::Pull(path)),
                Pick::Backup => self.send(Command::Backup(path)),
                Pick::Create => self.send(Command::Create(path)),
                Pick::Open => self.send(Command::Open(path, None)),
                Pick::ExportParticipant => self.send(Command::ExportParticipant(path)),
                Pick::Participant => self.send(Command::AddParticipant(path)),
                Pick::Keyfile => self.keyfile = Some(path),
                Pick::Import => {
                    self.preview_import(path);
                }
            }
        }
    }
}
fn recipient_ui(ui: &mut egui::Ui, participants: &[KeyId], selected: &mut Vec<KeyId>) {
    for id in participants {
        let mut checked = selected.contains(id);
        if ui.checkbox(&mut checked, id.to_string()).changed() {
            if checked {
                selected.push(*id);
            } else {
                selected.retain(|p| p != id);
            }
        }
    }
}
impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _: &mut eframe::Frame) {
        egui::Frame::new()
            .fill(egui::Color32::from_rgb(22, 23, 24))
            .inner_margin(18)
            .show(ui, |ui| {
                ui.set_min_size(ui.available_size());
                self.content(ui);
            });
    }
}
impl App {
    fn content(&mut self, ui: &mut egui::Ui) {
        // Latch the timeout before processing late results or fresh input.
        self.enforce_idle_lock(Instant::now());
        self.events();
        if self.clear_ui_memory {
            ui.ctx().memory_mut(|m| m.data.clear());
            self.clear_ui_memory = false;
        }
        self.dialog(ui.ctx());
        self.clipboard.tick();
        if ui.input(|i| !i.events.is_empty()) {
            self.last_activity = Instant::now();
        }
        ui.ctx().request_repaint_after(Duration::from_secs(1));
        ui.horizontal(|ui| {
            ui.heading(
                egui::RichText::new("KAGITABA").color(egui::Color32::from_rgb(255, 100, 24)),
            );
            ui.label("A bundle of keys");
            if ui
                .add_enabled(!self.locking, egui::Button::new("Lock / clear secrets"))
                .clicked()
            {
                self.request_lock();
            }
        });
        ui.label(&self.status);
        if self.busy {
            ui.spinner();
        }
        ui.separator();
        if let Some((enc, sign)) = self.participant_preview.clone() {
            ui.label("Verify these public-key fingerprints before enrollment. This participant may sign wallet changes.");
            ui.monospace(format!("Encryption: {}\nSigning: {}", enc.id(), sign.id()));
            if ui
                .add_enabled(!self.busy, egui::Button::new("Enroll these keys"))
                .clicked()
            {
                self.participant_preview = None;
                self.send(Command::Enroll(enc, sign));
            }
            if ui.button("Cancel enrollment").clicked() {
                self.participant_preview = None;
            }
        }
        if let Some((p, fingerprint)) = self.trust.clone() {
            ui.label("First open: compare this genesis signing fingerprint with a trusted device or backup record.");
            ui.monospace(&fingerprint);
            if ui.button("Trust this signer and verify history").clicked() {
                self.trust = None;
                self.send(Command::Open(p, Some(fingerprint)));
            }
            if ui.button("Cancel").clicked() {
                self.trust = None;
            }
        }
        ui.add_enabled_ui(!self.busy, |ui| {
            ui.columns(2, |columns| {
                egui::ScrollArea::vertical()
                    .id_salt("settings")
                    .show(&mut columns[0], |ui| {
                        self.hardware_ui(ui);
                        ui.add_enabled_ui(self.wallet.is_some() && self.unlocked.is_some(), |ui| {
                            self.import_ui(ui)
                        });
                    });
                egui::ScrollArea::vertical()
                    .id_salt("entries")
                    .show(&mut columns[1], |ui| {
                        ui.add_enabled_ui(self.wallet.is_some() && self.unlocked.is_some(), |ui| {
                            self.entry_ui(ui)
                        });
                    });
            });
        });
    }
}
impl Drop for App {
    fn drop(&mut self) {
        self.clear_secrets();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app() -> (App, mpsc::Receiver<Command>, mpsc::Sender<Event>) {
        let (tx, commands) = mpsc::channel();
        let (events, rx) = mpsc::channel();
        (
            App::state(egui::Context::default(), tx, rx),
            commands,
            events,
        )
    }

    #[test]
    fn entry_changes_and_snapshot_replacement_discard_text_undo() {
        let (mut app, _, events) = app();
        let a = EntryId::from_bytes([1; 16]);
        let b = EntryId::from_bytes([2; 16]);
        let widget = egui::Id::new("password");
        let mut state = egui::text_edit::TextEditState::default();
        let mut undo = state.undoer();
        let before = (Default::default(), "secret-A".to_owned());
        let after = (Default::default(), "edited-A".to_owned());
        undo.feed_state(0.0, &before);
        undo.feed_state(1.0, &after);
        assert_eq!(undo.clone().undo(&after), Some(&before));
        state.set_undoer(undo);
        app.selected = Some(a);
        state.clone().store(&app.ctx, widget);
        let epoch = app.editor_epoch;
        app.select_entry(b);
        assert_ne!(app.editor_epoch, epoch);
        assert!(egui::text_edit::TextEditState::load(&app.ctx, widget).is_none());
        state.store(&app.ctx, widget);
        events
            .send(Event::Wallet {
                path: "updated".into(),
                entries: vec![b],
                participants: vec![],
                head: "new-head".into(),
            })
            .unwrap();
        app.events();
        assert!(egui::text_edit::TextEditState::load(&app.ctx, widget).is_none());
        assert!(app.selected.is_none());
    }

    #[test]
    fn idle_lock_while_busy_suppresses_secrets_but_keeps_completed_wallet_updates() {
        let (mut app, commands, events) = app();
        let id = EntryId::from_bytes([3; 16]);
        let participant = KeyId::from_bytes([4; 32]);
        app.unlocked = Some("device".into());
        app.busy = true;
        app.json = "visible secret".into();
        app.titles
            .insert(id, Zeroizing::new("private title".into()));
        app.last_activity = Instant::now() - Duration::from_secs(301);
        app.enforce_idle_lock(Instant::now());
        assert!(matches!(commands.try_recv(), Ok(Command::Lock)));
        assert!(app.json.is_empty() && app.titles.is_empty() && app.unlocked.is_none());
        app.enforce_idle_lock(Instant::now());
        assert!(commands.try_recv().is_err());
        for event in [
            Event::Locked,
            Event::Entry(id, Zeroizing::new("late secret".into()), vec![]),
            Event::Titles(vec![(id, Zeroizing::new("late title".into()))]),
            Event::Preview("late preview".into()),
            Event::Unlocked("late unlock".into()),
            Event::Wallet {
                path: "new-wallet".into(),
                entries: vec![id],
                participants: vec![participant],
                head: "new-head".into(),
            },
            Event::Done(Ok(())),
        ] {
            events.send(event).unwrap();
        }
        app.events();
        assert!(app.locking && app.busy);
        assert!(
            app.json.is_empty()
                && app.titles.is_empty()
                && app.preview.is_none()
                && app.unlocked.is_none()
        );
        assert_eq!(app.wallet, Some(PathBuf::from("new-wallet")));
        assert_eq!(app.entries, vec![id]);
        assert_eq!(app.participants, vec![participant]);
        assert_eq!(app.head, "new-head");
        events.send(Event::LockComplete).unwrap();
        events.send(Event::Done(Ok(()))).unwrap();
        app.events();
        assert!(!app.locking && !app.busy);
        assert_eq!(app.entries, vec![id]);
    }

    #[test]
    fn failed_decryption_keeps_encrypted_entry_selected() {
        let (mut app, commands, events) = app();
        let id = EntryId::from_bytes([5; 16]);
        app.entries = vec![id];
        app.select_entry(id);
        events.send(Event::Done(Err("No grant".into()))).unwrap();
        app.events();
        assert_eq!(app.selected, Some(id));
        assert!(app.json.is_empty());
        // The encrypted selection renders the deletion controls without parsing a payload.
        app.delete_confirm = true;
        let ctx = app.ctx.clone();
        let mut output = ctx.run_ui(Default::default(), |ui| app.entry_ui(ui));
        let position = output
            .shapes
            .iter()
            .find_map(|shape| match &shape.shape {
                egui::epaint::Shape::Text(text) if text.galley.text() == "Delete entry" => {
                    Some(text.pos + text.galley.size() * 0.5)
                }
                _ => None,
            })
            .expect("encrypted entries must have a delete button");
        output.textures_delta.clear();
        let input = egui::RawInput {
            events: vec![
                egui::Event::PointerMoved(position),
                egui::Event::PointerButton {
                    pos: position,
                    button: egui::PointerButton::Primary,
                    pressed: true,
                    modifiers: Default::default(),
                },
                egui::Event::PointerButton {
                    pos: position,
                    button: egui::PointerButton::Primary,
                    pressed: false,
                    modifiers: Default::default(),
                },
            ],
            ..Default::default()
        };
        let mut output = ctx.run_ui(input, |ui| app.entry_ui(ui));
        output.textures_delta.clear();
        assert!(matches!(commands.try_recv(), Ok(Command::Delete(deleted)) if deleted == id));
    }

    #[test]
    fn import_password_presence_is_independent_of_contents() {
        let (mut app, commands, _) = app();
        app.preview_import("empty-password.kdbx".into());
        let Command::Preview(_, _, Some(password), _) = commands.recv().unwrap() else {
            panic!("missing password component")
        };
        assert!(password.is_empty());
        app.import_use_password = false;
        app.preview_import("keyfile-only.kdbx".into());
        assert!(matches!(
            commands.recv().unwrap(),
            Command::Preview(_, _, None, _)
        ));
    }
}
