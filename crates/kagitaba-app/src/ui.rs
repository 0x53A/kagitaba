use crate::backend::{Command, Event};
use crate::{preferences::Preferences, theme};
use eframe::egui;
use kagitaba_core::{EntryId, KeyId};
use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::mpsc,
    time::{Duration, Instant},
};
use zeroize::{Zeroize, Zeroizing};
mod workflows;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Screen {
    Home,
    Create,
    Unlock,
    Wallet,
    Import,
    Keys,
    Transfer,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Operation {
    Other,
    Open,
    Create,
    Unlock,
    Import,
    Save,
}

#[derive(Clone, Copy)]
enum Leave {
    Select(EntryId),
    New(bool),
    Screen(Screen),
    Close,
    DismissEntry,
}
#[derive(Clone, Copy)]
enum Pick {
    Pull,
    Merge,
    Backup,
    Create,
    Open,
    ExportParticipant,
    Participant,
    Import,
    Keyfile,
}
pub struct App {
    screen: Screen,
    operation: Operation,
    preferences: Preferences,
    preferences_path: Option<PathBuf>,
    preference_error: Option<String>,
    create_path: Option<PathBuf>,
    import_complete: bool,
    entry_original: Zeroizing<String>,
    original_recipients: Vec<KeyId>,
    leave_action: Option<Leave>,
    after_save: Option<EntryId>,
    ctx: egui::Context,
    editor_epoch: u64,
    tx: mpsc::Sender<Command>,
    rx: mpsc::Receiver<Event>,
    busy: bool,
    status: String,
    devices: Vec<kagitaba_device::usb::Device>,
    device_hints: BTreeMap<KeyId, kagitaba_store::DeviceHint>,
    device: usize,
    encryption_slot: u8,
    signing_slot: u8,
    pin: String,
    management: String,
    provision: bool,
    consent: bool,
    unlocked: Option<String>,
    wallet: Option<PathBuf>,
    entries: Vec<EntryId>,
    participants: Vec<KeyId>,
    participant_names: BTreeMap<KeyId, String>,
    participant_names_unavailable: bool,
    name_edit: Option<(KeyId, String)>,
    head: String,
    remote_status: Option<crate::remote::Status>,
    remote_configured: Option<bool>,
    remote_busy: Option<crate::remote::Action>,
    remote_error: Option<String>,
    push_error: Option<String>,
    remote_due: Option<Instant>,
    remote_checked: Option<Instant>,
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
    revoke_confirm: bool,
}
impl App {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        theme::install(&cc.egui_ctx);
        #[cfg(feature = "smoke")]
        if let Ok(scene) = std::env::var("KAGITABA_SMOKE_SCENE") {
            return Self::smoke(cc.egui_ctx.clone(), &scene);
        }
        let (tx, rx) = crate::backend::start(cc.egui_ctx.clone());
        let mut app = Self::state(cc.egui_ctx.clone(), tx, rx);
        app.preferences_path = Preferences::path();
        if let Some(path) = &app.preferences_path {
            match Preferences::load(path) {
                Ok(preferences) => app.preferences = preferences,
                Err(e) => app.preference_error = Some(format!("Could not load saved wallets: {e}")),
            }
        }
        app
    }
    fn state(ctx: egui::Context, tx: mpsc::Sender<Command>, rx: mpsc::Receiver<Event>) -> Self {
        Self {
            screen: Screen::Home,
            operation: Operation::Other,
            preferences: Preferences::default(),
            preferences_path: None,
            preference_error: None,
            create_path: None,
            import_complete: false,
            entry_original: Zeroizing::new(String::new()),
            original_recipients: vec![],
            leave_action: None,
            after_save: None,
            ctx,
            editor_epoch: 0,
            tx,
            rx,
            busy: false,
            status: String::new(),
            devices: vec![],
            device_hints: BTreeMap::new(),
            device: 0,
            encryption_slot: kagitaba_device::ENCRYPTION_SLOT,
            signing_slot: kagitaba_device::SIGNING_SLOT,
            pin: String::new(),
            management: String::new(),
            provision: false,
            consent: false,
            unlocked: None,
            wallet: None,
            entries: vec![],
            participants: vec![],
            participant_names: BTreeMap::new(),
            participant_names_unavailable: false,
            name_edit: None,
            head: String::new(),
            remote_status: None,
            remote_configured: None,
            remote_busy: None,
            remote_error: None,
            push_error: None,
            remote_due: None,
            remote_checked: None,
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
            revoke_confirm: false,
        }
    }
    fn send(&mut self, c: Command) {
        if let Command::Save(id, ..) = &c {
            self.after_save = Some(*id);
        }
        self.operation = match &c {
            Command::Open(..) => Operation::Open,
            Command::Create(_) => Operation::Create,
            Command::Unlock(..) | Command::Provision(..) => Operation::Unlock,
            Command::Import(_) => Operation::Import,
            Command::Save(..) | Command::Grant(..) | Command::Delete(_) => Operation::Save,
            _ => Operation::Other,
        };
        if self.tx.send(c).is_ok() {
            self.busy = true;
            self.status = "Working… Touch your key if it blinks.".into();
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
        for name in self.participant_names.values_mut() { name.zeroize(); }
        self.participant_names.clear();
        self.participant_names_unavailable = false;
        self.selected = None;
        self.preview = None;
        self.import_recipients.clear();
        self.reveal = false;
        self.unlocked = None;
        self.leave_action = None;
        self.participant_preview = None;
        self.consent = false;
        self.revoke_confirm = false;
        self.after_save = None;
        if let Some((_, name)) = &mut self.name_edit { name.zeroize(); }
        self.name_edit = None;
    }
    fn events(&mut self) {
        while let Ok(e) = self.rx.try_recv() {
            // Snapshot metadata must track successful worker writes even while
            // secret results and intermediate completions are suppressed.
            if self.locking
                && !matches!(
                    e,
                    Event::Locked
                        | Event::LockComplete
                        | Event::Wallet { .. }
                        | Event::Devices(_)
                        | Event::DeviceHints(_)
                        | Event::Closed
                        | Event::Remote(_)
                )
            {
                continue;
            }
            match e {
                Event::Devices(d) => {
                    self.devices = d;
                    self.device = 0;
                    self.match_device_slots(true);
                }
                Event::DeviceHints(hints) => {
                    self.device_hints = hints;
                    self.match_device_slots(true);
                }
                Event::ParticipantNames(names) => {
                    for name in self.participant_names.values_mut() { name.zeroize(); }
                    self.participant_names = names;
                    self.participant_names_unavailable = false;
                    self.name_edit = None;
                }
                Event::ParticipantNamesUnavailable => {
                    self.participant_names_unavailable = true;
                }
                Event::Unlocked(id) => {
                    self.unlocked = Some(id);
                    self.last_activity = Instant::now();
                    self.provision = false;
                    if self.screen == Screen::Unlock {
                        self.screen = Screen::Wallet;
                    }
                }
                Event::Closed => {
                    self.wallet = None;
                    self.entries.clear();
                    self.participants.clear();
                    self.participant_names.clear();
                    self.name_edit = None;
                    self.device_hints.clear();
                    self.head.clear();
                    self.trust = None;
                    self.create_path = None;
                    self.screen = Screen::Home;
                    self.remote_status = None;
                    self.remote_configured = None;
                    self.remote_busy = None;
                    self.remote_error = None;
                    self.push_error = None;
                    self.remote_due = None;
                    self.remote_checked = None;
                }
                Event::Locked => {
                    self.clear_secrets();
                }
                Event::LockComplete => {
                    self.clear_secrets();
                    self.locking = false;
                    self.match_device_slots(true);
                }
                Event::Wallet {
                    path,
                    entries,
                    participants,
                    head,
                } => {
                    let changed_wallet = self.wallet.as_ref() != Some(&path);
                    if changed_wallet || self.head != head {
                        for name in self.participant_names.values_mut() { name.zeroize(); }
                        self.participant_names.clear();
                        self.participant_names_unavailable = false;
                        self.remote_status = None;
                        self.remote_due = Some(Instant::now());
                    }
                    if changed_wallet {
                        self.participant_names.clear();
                        self.name_edit = None;
                        self.remote_busy = None;
                        self.remote_configured = None;
                        self.remote_error = None;
                        self.push_error = None;
                        self.remote_checked = None;
                    }
                    self.reset_entry();
                    self.json.zeroize();
                    self.titles.clear();
                    self.selected = None;
                    self.recipients.clear();
                    self.import_recipients.clear();
                    if changed_wallet {
                        self.preferences.opened(&path);
                        self.save_preferences();
                    }
                    self.wallet = Some(path);
                    self.entries = entries;
                    self.participants = participants;
                    self.head = head;
                    self.preview = None;
                    if matches!(self.operation, Operation::Open | Operation::Create) {
                        self.create_path = None;
                        self.screen = if self.unlocked.is_some() {
                            Screen::Wallet
                        } else {
                            Screen::Unlock
                        };
                    }
                }
                Event::Trust(p, id) => self.trust = Some((p, id)),
                Event::Participant(enc, sign) => {
                    self.participant_preview = Some((enc, sign))
                }
                Event::Preview(s) => self.preview = Some(s),
                Event::Entry(id, json, recipients) => {
                    self.reset_entry();
                    self.json = json.to_string();
                    self.selected = Some(id);
                    self.recipients = recipients;
                    self.entry_original = Zeroizing::new(self.json.clone());
                    self.original_recipients = self.recipients.clone();
                    self.reveal = false;
                    self.delete_confirm = false;
                }
                Event::Titles(t) => {
                    self.titles = t.into_iter().collect();
                }
                Event::Remote(report) => {
                    if self.wallet.as_ref() != Some(&report.path) {
                        continue;
                    }
                    self.remote_busy = None;
                    if report.action == crate::remote::Action::Push {
                        self.push_error = report.result.as_ref().err().cloned();
                    }
                    if self.head != report.checkpoint {
                        self.remote_due = Some(Instant::now());
                        // A failed push is still useful feedback even if a newer
                        // local edit completed while transport was running.
                        continue;
                    }
                    self.remote_due = Some(Instant::now() + Duration::from_secs(60));
                    match report.result {
                        Ok(status) => {
                            self.remote_configured = Some(status.is_some());
                            self.remote_status = status;
                            self.remote_checked = Some(Instant::now());
                            self.remote_error = None;
                        }
                        Err(error) => {
                            self.remote_status = None;
                            self.remote_error = Some(error);
                        }
                    }
                }
                Event::Done(result) => {
                    self.busy = false;
                    let success = result.is_ok();
                    let load_titles = success
                        && self.operation == Operation::Unlock
                        && self.screen == Screen::Wallet
                        && self.wallet.is_some();
                    let read_saved = if self.operation == Operation::Save {
                        self.after_save.take().filter(|_| success)
                    } else {
                        None
                    };
                    if result.is_ok() && self.operation == Operation::Import {
                        self.import_complete = true;
                    }
                    self.status = match result {
                        Ok(()) => match self.operation {
                            Operation::Save => "Changes saved and signed.".into(),
                            Operation::Import => {
                                "Import complete. Your new entries are ready.".into()
                            }
                            _ => String::new(),
                        },
                        Err(e) => format!("Could not complete action: {e}"),
                    };
                    if load_titles {
                        self.send(Command::Titles);
                    } else if let Some(id) = read_saved {
                        self.select_entry(id);
                        self.send(Command::Read(id));
                    }
                }
            }
        }
    }
    fn reset_entry(&mut self) {
        self.entry_original.zeroize();
        self.original_recipients.clear();
        self.json.zeroize();
        self.selected = None;
        self.recipients.clear();
        self.reveal = false;
        self.delete_confirm = false;
        self.editor_epoch = self.editor_epoch.wrapping_add(1);
        self.ctx.memory_mut(|m| m.data.clear());
    }
    fn request_remote(&mut self, action: crate::remote::Action) {
        if self.wallet.is_some()
            && self.remote_busy.is_none()
            && self.tx.send(Command::Remote(action)).is_ok()
        {
            self.remote_busy = Some(action);
        }
    }
    fn poll_remote(&mut self, now: Instant) {
        if !self.busy && !self.locking && self.remote_due.is_some_and(|due| now >= due) {
            self.request_remote(crate::remote::Action::Fetch);
        }
    }
    fn remote_ui(&mut self, ui: &mut egui::Ui) {
        if self.wallet.is_none() {
            return;
        }
        ui.horizontal_wrapped(|ui| {
            if let Some(action) = self.remote_busy {
                ui.spinner();
                ui.label(match action {crate::remote::Action::Fetch => "Fetching origin…", crate::remote::Action::Push => "Pushing signed changes…"});
            } else if self.remote_configured == Some(false) {
                ui.label("No origin remote configured.");
            } else if let Some(status) = &self.remote_status {
                let (ahead, behind) = (status.relation.ahead, status.relation.behind);
                ui.label(match (ahead, behind) {
                    (0, 0) => "Up to date with origin/wallet".to_owned(),
                    (a, 0) => format!("{a} local commit(s) not pushed"),
                    (0, b) => format!("{b} remote commit(s) available"),
                    (a, b) => format!("Diverged: {a} local, {b} remote commit(s)"),
                });
            } else { ui.label("Remote status not checked."); }
            let enabled = !self.busy && !self.locking && self.remote_busy.is_none() && self.leave_action.is_none() && self.trust.is_none();
            if ui.add_enabled(enabled, egui::Button::new("Fetch")).clicked() { self.request_remote(crate::remote::Action::Fetch); }
            if let Some(status) = self.remote_status.clone() {
                let (a, b) = (status.relation.ahead, status.relation.behind);
                if a > 0 && b == 0 && ui.add_enabled(enabled, egui::Button::new("Push")).clicked() { self.request_remote(crate::remote::Action::Push); }
                if b > 0 {
                    let merge = a > 0;
                    let label = if merge { "Merge and sign" } else { "Pull" };
                    if ui.add_enabled(enabled && !self.dirty() && (!merge || self.unlocked.is_some()), egui::Button::new(label)).on_hover_text("Save or discard entry edits first. Merging also requires an unlocked key authorized on both sides.").clicked() {
                        self.send(if merge {Command::MergeRemote(status.head)} else {Command::PullRemote(status.head)});
                    }
                }
            }
        });
        if let Some(error) = &self.remote_error {
            ui.colored_label(theme::ERROR, error);
        }
        if let Some(error) = &self.push_error
            && self.remote_error.as_ref() != Some(error)
        {
            ui.colored_label(theme::ERROR, error);
        }
        if let Some(checked) = self.remote_checked {
            ui.small(format!(
                "Remote checked {}s ago · fetch every 60s · pull/merge and push are explicit",
                checked.elapsed().as_secs()
            ));
        }
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
    fn match_device_slots(&mut self, choose_device: bool) {
        if self.unlocked.is_some() {
            return;
        }
        let serials: Vec<_> = self.devices.iter().map(|d| d.serial.as_deref()).collect();
        if let Some((device, slots)) = matching_slots(
            &serials,
            &self.device_hints,
            if choose_device {
                None
            } else {
                Some(self.device)
            },
        ) {
            self.device = device;
            self.encryption_slot = slots.encryption();
            self.signing_slot = slots.signing();
            self.consent = false;
        }
    }
    fn hardware_ui(&mut self, ui: &mut egui::Ui) {
        ui.label("Connect your YubiKey with PIV enabled.");
        let serials: Vec<_> = self.devices.iter().map(|d| d.serial.as_deref()).collect();
        if matching_slots(&serials, &self.device_hints, None).is_some_and(|(index, slots)| {
            index == self.device
                && slots.encryption() == self.encryption_slot
                && slots.signing() == self.signing_slot
        }) {
            ui.colored_label(
                theme::AQUA,
                "A saved participant was detected. Its key and slots are selected.",
            );
        } else if self.wallet.is_some() {
            ui.label("Choose a key. Select slots manually if no device is recorded.");
        }
        let previous_selection = (self.device, self.encryption_slot, self.signing_slot);
        ui.add_enabled_ui(self.unlocked.is_none(), |ui| {
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
        });
        if previous_selection.0 != self.device {
            self.match_device_slots(false);
        }
        if self.unlocked.is_none() && !self.device_hints.is_empty() {
            egui::ComboBox::from_id_salt("participant-route")
                .selected_text("Choose a saved participant…")
                .show_ui(ui, |ui| {
                    for (id, hint) in &self.device_hints {
                        let connected = self
                            .devices
                            .iter()
                            .position(|d| d.serial.as_deref() == Some(hint.serial.as_str()));
                        if ui
                            .add_enabled(
                                connected.is_some(),
                                egui::Button::selectable(
                                    false,
                                    format!(
                                        "{} · key {} · {:02X}/{:02X}",
                                        participant_label(id, &self.participant_names),
                                        hint.serial,
                                        hint.encryption_slot,
                                        hint.signing_slot
                                    ),
                                ),
                            )
                            .on_disabled_hover_text(
                                "Connect this participant’s key, then refresh devices.",
                            )
                            .clicked()
                        {
                            self.encryption_slot = hint.encryption_slot;
                            self.signing_slot = hint.signing_slot;
                            if let Some(index) = connected {
                                self.device = index;
                            }
                        }
                    }
                });
        }
        if ui
            .add_enabled(
                self.unlocked.is_none(),
                egui::Button::new("Refresh USB devices"),
            )
            .clicked()
        {
            self.consent = false;
            self.send(Command::Scan);
        }
        ui.collapsing("Advanced: PIV slots", |ui| {
            ui.add_enabled_ui(self.unlocked.is_none() && !self.busy, |ui| {
                for (label, slot) in [
                    ("Encryption slot", &mut self.encryption_slot),
                    ("Signing slot", &mut self.signing_slot),
                ] {
                    egui::ComboBox::from_id_salt(label)
                        .selected_text(format!("{label}: {slot:02X}"))
                        .show_ui(ui, |ui| {
                            for value in 0x82..=0x95 {
                                ui.selectable_value(slot, value, format!("{value:02X}"));
                            }
                        });
                }
            });
        });
        if previous_selection != (self.device, self.encryption_slot, self.signing_slot) {
            self.consent = false;
        }
        let slots = kagitaba_device::Slots::new(self.encryption_slot, self.signing_slot).ok();
        if slots.is_none() {
            ui.colored_label(egui::Color32::LIGHT_RED, "Choose two different slots.");
        }
        if let Some(id) = &self.unlocked {
            ui.colored_label(theme::AQUA, format!("Key ready · {}…", &id[..16]));
            if ui
                .add_enabled(
                    self.wallet.is_some(),
                    egui::Button::new("Remember device in wallet"),
                )
                .clicked()
            {
                self.send(Command::RememberDevice);
            }
        } else {
            ui.label("PIV PIN");
            ui.add(egui::TextEdit::singleline(&mut self.pin).password(true));
            if ui
                .add_enabled(
                    slots.is_some()
                        && !self.devices.is_empty()
                        && !self.pin.is_empty()
                        && !self.provision,
                    egui::Button::new(if self.screen == Screen::Unlock {
                        "Unlock & load entry names"
                    } else {
                        "Unlock key"
                    }),
                )
                .clicked()
                && let Some(d) = self.devices.get(self.device).cloned()
                && let Some(slots) = slots
            {
                let pin = Zeroizing::new(std::mem::take(&mut self.pin));
                self.send(Command::Unlock(d, slots, pin));
            }
        }
        if self.unlocked.is_none()
            && ui
                .checkbox(&mut self.provision, "Set up an unused key for Kagitaba")
                .changed()
        {
            self.consent = false;
            self.management.zeroize();
        }
        if self.provision {
            ui.label(format!("Generates P-256 keys in PIV slots {:02X} and {:02X}. Occupied slots are never overwritten. FIDO credentials remain untouched.", self.encryption_slot, self.signing_slot));
            ui.label("Encryption touch is cached briefly; signing requires a touch. Uses your existing PIV PIN and management key.");
            ui.label("Management key (hex)");
            ui.add(egui::TextEdit::singleline(&mut self.management).password(true));
            if ui.button("Use factory management key").clicked() {
                self.management = "010203040506070801020304050607080102030405060708".into();
            }
            ui.checkbox(
                &mut self.consent,
                format!(
                    "I authorize generating keys in empty slots {:02X} and {:02X}",
                    self.encryption_slot, self.signing_slot
                ),
            );
            if ui
                .add_enabled(
                    self.consent
                        && slots.is_some()
                        && !self.devices.is_empty()
                        && !self.pin.is_empty(),
                    egui::Button::new("Generate on device"),
                )
                .clicked()
                && let Some(d) = self.devices.get(self.device).cloned()
                && let Some(slots) = slots
            {
                let key = Zeroizing::new(std::mem::take(&mut self.management));
                let pin = Zeroizing::new(std::mem::take(&mut self.pin));
                self.send(Command::Provision(d, slots, key, pin));
                self.consent = false;
            }
        }
    }
    fn transfer_ui(&mut self, ui: &mut egui::Ui) {
        ui.heading("Backups & updates");
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
        ui.label("Combine diverged histories");
        ui.small("Merge requires an unlocked signer on both sides. Conflicting edits stop the merge.");
        if ui
            .add_enabled(
                self.wallet.is_some() && self.unlocked.is_some(),
                egui::Button::new("Merge and sign from wallet folder…"),
            )
            .clicked()
        {
            self.pick(Pick::Merge);
        }
        if ui
            .add_enabled(
                self.wallet.is_some() && self.unlocked.is_some(),
                egui::Button::new("Merge and sign fetched origin/wallet"),
            )
            .clicked()
        {
            self.send(Command::MergeOrigin);
        }
        ui.small("Use Fetch to refresh remote updates.");
    }
    fn keys_ui(&mut self, ui: &mut egui::Ui) {
        ui.heading("Keys & access");
        ui.label("An enrolled participant can sign wallet changes. Access to each entry is granted separately.");
        self.participant_names_ui(ui);
        ui.collapsing("This device", |ui| self.hardware_ui(ui));
        ui.separator();
        if ui
            .add_enabled(
                self.unlocked.is_some(),
                egui::Button::new("Export this device’s public keys…"),
            )
            .clicked()
        {
            self.pick(Pick::ExportParticipant);
        }
        if ui
            .add_enabled(
                self.unlocked.is_some(),
                egui::Button::new("Add participant from public keys…"),
            )
            .clicked()
        {
            self.pick(Pick::Participant);
        }
        ui.add_enabled_ui(self.unlocked.is_some(), |ui| { ui.collapsing("Remove a participant",|ui|{
            ui.label("Removes signing authority and rotates every affected entry. Old copies remain readable by that key.");
            for id in &self.participants{if ui.selectable_value(&mut self.revoke,Some(*id),participant_label(id, &self.participant_names)).on_hover_text(id.to_string()).changed() { self.revoke_confirm = false; }}
            ui.checkbox(&mut self.revoke_confirm, "I understand that this removes signing authority and rotates affected entries.");
            if ui.add_enabled(self.revoke.is_some() && self.revoke_confirm,egui::Button::new("Revoke selected participant and rotate")).clicked()&&let Some(id)=self.revoke.take(){self.revoke_confirm = false; self.send(Command::RemoveParticipant(id));}
        }); });
        if let Some((enc, sign)) = self.participant_preview.clone() {
            ui.separator();
            ui.heading("Verify this participant");
            ui.label("Compare both fingerprints with the owner before enrolling. Enrollment grants wallet-wide signing authority.");
            ui.label(format!("Encryption: {}\nSigning: {}", enc.id(), sign.id()));
            if theme::primary(ui, "Enroll verified participant").clicked() {
                self.participant_preview = None;
                self.send(Command::Enroll(enc, sign));
            }
            if ui.button("Cancel enrollment").clicked() {
                self.participant_preview = None;
            }
        }
    }
    fn participant_names_ui(&mut self, ui: &mut egui::Ui) {
        ui.collapsing("Participant names", |ui| {
            ui.small("Encrypted names are shared with all participants.");
            if self.participant_names_unavailable {
                ui.label("The signed wallet is available, but participant names could not be loaded. Unlock again to retry.");
            }
            for id in self.participants.clone() {
                ui.horizontal_wrapped(|ui| {
                    ui.label(participant_label(&id, &self.participant_names)).on_hover_text(id.to_string());
                    if ui.add_enabled(self.unlocked.is_some() && self.name_edit.is_none(), egui::Button::new("Rename")).clicked() {
                        self.name_edit = Some((id, self.participant_names.get(&id).cloned().unwrap_or_default()));
                    }
                });
            }
            let mut save = None;
            let mut cancel = false;
            if let Some((id, draft)) = &mut self.name_edit {
                ui.label(format!("Participant {id}"));
                ui.add(egui::TextEdit::singleline(draft).char_limit(128).hint_text("e.g. Pixel, Firefox, backup YubiKey"));
                ui.small("Leave empty to remove the name.");
                let valid = draft.trim().is_empty() || kagitaba_store::validate_name(draft.trim()).is_ok();
                ui.horizontal(|ui| {
                    if ui.add_enabled(valid && self.unlocked.is_some(), egui::Button::new("Save name and sign")).clicked() { save = Some((*id, draft.trim().to_owned())); }
                    cancel = ui.button("Cancel naming").clicked();
                });
            }
            if cancel { self.name_edit = None; }
            if let Some((id, name)) = save { self.send(Command::NameParticipant(id, name)); }
        });
    }
    fn import_ui(&mut self, ui: &mut egui::Ui) {
        ui.heading("Import credentials");
        if self.import_complete {
            ui.colored_label(theme::AQUA, "Import complete");
            ui.label("Entries added. Source file kept.");
            if theme::primary(ui, "View entries").clicked() {
                self.screen = Screen::Wallet;
            }
            if ui.button("Import another file").clicked() {
                self.import_complete = false;
            }
            return;
        }
        if let Some(report) = &self.preview {
            ui.label("2 / 2 · Review & choose access");
            ui.label(report);
            ui.label("Select the participants who should be able to decrypt these entries.");
            recipient_ui(ui, &self.participants, &self.participant_names, &mut self.import_recipients);
            ui.small("Import creates new copies. Keep source backups for attachments and unsupported credentials.");
            if ui
                .add_enabled(
                    !self.import_recipients.is_empty(),
                    egui::Button::new("Encrypt and import"),
                )
                .clicked()
            {
                self.send(Command::Import(self.import_recipients.clone()));
            }
            if ui.button("Choose a different file").clicked() {
                self.preview = None;
                self.import_recipients.clear();
                self.send(Command::DiscardImport);
            }
        } else {
            ui.label("1 / 2 · Choose a source");
            egui::ComboBox::from_id_salt("format")
                .selected_text(&self.import_format)
                .show_ui(ui, |ui| {
                    for f in ["Bitwarden", "CXF", "KeePass"] {
                        ui.selectable_value(&mut self.import_format, f.to_string(), f);
                    }
                });
            if self.import_format == "KeePass" {
                if ui
                    .checkbox(&mut self.import_use_password, "Use password (may be empty)")
                    .changed()
                    && !self.import_use_password
                {
                    self.import_password.zeroize();
                }
                ui.add_enabled(
                    self.import_use_password,
                    egui::TextEdit::singleline(&mut self.import_password).password(true),
                );
                if ui.button("Choose optional key file…").clicked() {
                    self.pick(Pick::Keyfile);
                }
                if ui.button("Clear key file").clicked() {
                    self.keyfile = None;
                }
                if let Some(p) = &self.keyfile {
                    ui.label(p.display().to_string());
                }
            }
            ui.small(match self.import_format.as_str() { "KeePass" => "Encrypted KDBX/KDB database. Password and key file are combined when both are selected.", "Bitwarden" => "Unencrypted JSON export. Encrypted JSON and CSV are not supported.", _ => "Plaintext CXF document. Encrypted CXP transport is not supported." });
            if theme::primary(ui, "Choose file & preview…").clicked() {
                self.pick(Pick::Import);
            }
        }
    }
    fn entry_list(&mut self, ui: &mut egui::Ui) {
        ui.heading("Entries");
        ui.add_enabled_ui(self.unlocked.is_some(), |ui| {
            ui.horizontal_wrapped(|ui| {
                if ui.button("New login").clicked() {
                    self.navigate(Leave::New(false));
                }
                if ui.button("New collection").clicked() {
                    self.navigate(Leave::New(true));
                }
                if ui.button("Load entry names").clicked() {
                    self.send(Command::Titles);
                }
            });
        });
        ui.add(egui::TextEdit::singleline(&mut self.search).hint_text("Search decrypted titles"));
        egui::ScrollArea::vertical()
            .id_salt("entry-list")
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
                        .add_sized(
                            [ui.available_width(), 44.0],
                            egui::Button::selectable(
                                self.selected == Some(*id),
                                format!("{label}  ·  {}", &id.to_string()[..8]),
                            )
                            .wrap(),
                        )
                        .clicked()
                    {
                        open = Some(*id);
                    }
                }
                if let Some(id) = open {
                    self.navigate(Leave::Select(id));
                }
                if self.entries.is_empty() {
                    ui.label("No entries.");
                }
            });
    }
    fn entry_ui(&mut self, ui: &mut egui::Ui) {
        if let Some(id) = self.selected {
            ui.heading(if self.entries.contains(&id) {
                "Entry details"
            } else {
                "New entry"
            });
            ui.small(format!("Entry {id}"));
            if self.json.is_empty() {
                ui.label("Encrypted entry selected. Decryption is not required to delete it.");
                if ui
                    .add_enabled(
                        self.unlocked.is_some(),
                        egui::Button::new("Decrypt selected entry"),
                    )
                    .clicked()
                {
                    self.send(Command::Read(id));
                }
            } else {
                ui.push_id((id, self.editor_epoch), |ui| {
                    if let Some(status) = crate::editor::show(ui, &mut self.json, &mut self.clipboard) {
                        self.status = status;
                    }
                    ui.checkbox(&mut self.reveal, "Advanced: reveal and edit complete payload");
                    if self.reveal {
                        ui.label("Editing here does not change your password at the website.");
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
                    }
                    ui.collapsing("Who can access this entry?", |ui| {
                    ui.label("Recipients for the next revision");
                    recipient_ui(ui, &self.participants, &self.participant_names, &mut self.recipients);
                    if ui
                        .add_enabled(
                            self.entries.contains(&id) && !self.recipients.is_empty() && self.json == *self.entry_original,
                            egui::Button::new("Add selected grants without changing payload"),
                        )
                        .clicked()
                    {
                        self.send(Command::Grant(id, self.recipients.clone()));
                    }
                    ui.label("Adding grants retains existing access. To remove recipients, save a new revision with only the recipients you want.");
                    });
                    if ui
                        .add_enabled(
                            !self.recipients.is_empty(),
                            egui::Button::new(egui::RichText::new("Save encrypted entry").color(theme::BACKGROUND)).fill(theme::AQUA),
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
            ui.separator();
            ui.checkbox(
                &mut self.delete_confirm,
                "Confirm deletion (history remains readable)",
            );
            if ui
                .add_enabled(
                    self.delete_confirm && self.entries.contains(&id) && self.unlocked.is_some(),
                    egui::Button::new("Delete entry"),
                )
                .clicked()
            {
                self.send(Command::Delete(id));
                self.json.zeroize();
                self.selected = None;
            }
        } else {
            ui.heading("Your credentials, close at hand");
            ui.label("Select an entry to view it, or add a new login.");
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
                self.recipients = self
                    .participants
                    .iter()
                    .filter(|id| self.unlocked.as_deref() == Some(id.to_string().as_str()))
                    .copied()
                    .collect();
                self.reveal = false;
            }
            Err(e) => self.status = e.to_string(),
        }
    }
    fn pick(&mut self, pick: Pick) {
        self.pick = Some(pick);
        match pick {
            Pick::Create | Pick::Open | Pick::Pull | Pick::Merge | Pick::Backup => self.dialog.pick_directory(),
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
                Pick::Merge => self.send(Command::Merge(path)),
                Pick::Backup => self.send(Command::Backup(path)),
                Pick::Create => {
                    self.create_path = Some(path);
                    self.screen = Screen::Create;
                    if self.unlocked.is_none() {
                        self.send(Command::Scan);
                    }
                }
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
fn participant_label(id: &KeyId, names: &BTreeMap<KeyId, String>) -> String {
    format!(
        "{} · {}…",
        names
            .get(id)
            .map(String::as_str)
            .unwrap_or("Unnamed participant"),
        &id.to_string()[..16]
    )
}
fn recipient_ui(
    ui: &mut egui::Ui,
    participants: &[KeyId],
    names: &BTreeMap<KeyId, String>,
    selected: &mut Vec<KeyId>,
) {
    for id in participants {
        let mut checked = selected.contains(id);
        if ui
            .checkbox(&mut checked, participant_label(id, names))
            .on_hover_text(id.to_string())
            .changed()
        {
            if checked {
                selected.push(*id);
            } else {
                selected.retain(|p| p != id);
            }
        }
    }
}
fn matching_slots(
    serials: &[Option<&str>],
    hints: &BTreeMap<KeyId, kagitaba_store::DeviceHint>,
    selected: Option<usize>,
) -> Option<(usize, kagitaba_device::Slots)> {
    let mut matches = Vec::new();
    for (index, serial) in serials.iter().enumerate() {
        if selected.is_some_and(|s| s != index) {
            continue;
        }
        for hint in hints.values() {
            if *serial == Some(hint.serial.as_str()) {
                let slots =
                    kagitaba_device::Slots::new(hint.encryption_slot, hint.signing_slot).ok()?;
                matches.push((index, slots));
            }
        }
    }
    if matches.len() == 1 {
        matches.pop()
    } else {
        None
    }
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _: &mut eframe::Frame) {
        egui::Frame::new()
            .fill(theme::BACKGROUND)
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
        self.poll_remote(Instant::now());
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
        self.shell(ui);
    }
}
impl Drop for App {
    fn drop(&mut self) {
        self.clear_secrets();
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn device_matching_requires_a_unique_serial_and_slot_pair() {
        use kagitaba_core::crypto::SoftwareIdentity;
        use kagitaba_store::DeviceHint;
        let id = SoftwareIdentity::from_bytes(&[1; 32])
            .unwrap()
            .public_key()
            .id();
        let other = SoftwareIdentity::from_bytes(&[2; 32])
            .unwrap()
            .public_key()
            .id();
        let mut hints = std::collections::BTreeMap::from([(
            id,
            DeviceHint {
                serial: "123456".into(),
                encryption_slot: 0x94,
                signing_slot: 0x95,
            },
        )]);
        let serials = [None, Some("654321"), Some("123456")];
        let (index, slots) = super::matching_slots(&serials, &hints, None).unwrap();
        assert_eq!(index, 2);
        assert_eq!((slots.encryption(), slots.signing()), (0x94, 0x95));
        assert!(super::matching_slots(&serials[..2], &hints, None).is_none());
        hints.insert(
            other,
            DeviceHint {
                serial: "654321".into(),
                encryption_slot: 0x82,
                signing_slot: 0x83,
            },
        );
        assert!(super::matching_slots(&serials, &hints, None).is_none());
        assert_eq!(
            super::matching_slots(&serials, &hints, Some(1)).unwrap().0,
            1
        );
        hints.get_mut(&other).unwrap().serial = "123456".into();
        assert!(super::matching_slots(&serials, &hints, Some(2)).is_none());
        hints.remove(&other);
        assert!(super::matching_slots(&[Some("123456"), Some("123456")], &hints, None).is_none());
    }
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
    fn duplicate_friendly_names_keep_identity_visible_and_drafts_are_guarded() {
        let a = KeyId::from_bytes([1; 32]);
        let b = KeyId::from_bytes([2; 32]);
        let names = BTreeMap::from([(a, "Backup".into()), (b, "Backup".into())]);
        assert_ne!(participant_label(&a, &names), participant_label(&b, &names));
        assert!(participant_label(&a, &names).contains(&a.to_string()[..16]));
        let (mut app, _, _) = app();
        app.name_edit = Some((a, "Draft".into()));
        app.navigate(Leave::Screen(Screen::Wallet));
        assert!(app.leave_action.is_some());
        app.clear_secrets();
        assert!(app.name_edit.is_none());
    }

    #[test]
    fn remote_poll_on_open_and_timer_preserves_edits_and_idle_lock() {
        let (mut app, commands, events) = app();
        events
            .send(Event::Wallet {
                path: "synthetic".into(),
                entries: vec![],
                participants: vec![],
                head: "head".into(),
            })
            .unwrap();
        app.events();
        app.selected = Some(EntryId::from_bytes([1; 16]));
        app.json = "synthetic unsaved edit".into();
        let idle = app.last_activity;
        app.poll_remote(Instant::now());
        assert!(matches!(
            commands.try_recv(),
            Ok(Command::Remote(crate::remote::Action::Fetch))
        ));
        assert!(!app.busy);
        assert_eq!(app.last_activity, idle);
        assert_eq!(app.json, "synthetic unsaved edit");
        app.poll_remote(Instant::now() + Duration::from_secs(70));
        assert!(commands.try_recv().is_err()); // Only one transport job at a time.
        events
            .send(Event::Remote(crate::remote::Report {
                path: "synthetic".into(),
                checkpoint: "head".into(),
                action: crate::remote::Action::Fetch,
                result: Ok(None),
            }))
            .unwrap();
        app.events();
        app.poll_remote(Instant::now());
        assert!(commands.try_recv().is_err());
        app.poll_remote(Instant::now() + Duration::from_secs(61));
        assert!(matches!(
            commands.try_recv(),
            Ok(Command::Remote(crate::remote::Action::Fetch))
        ));
        app.unlocked = Some("synthetic".into());
        app.last_activity = Instant::now() - Duration::from_secs(301);
        app.enforce_idle_lock(Instant::now());
        assert!(matches!(commands.try_recv(), Ok(Command::Lock)));
        assert!(app.locking && app.json.is_empty());
    }

    #[test]
    fn push_errors_survive_timer_success_and_stale_reports_cannot_offer_old_heads() {
        let (mut app, _, events) = app();
        app.wallet = Some("synthetic".into());
        app.head = "head".into();
        events
            .send(Event::Remote(crate::remote::Report {
                path: "synthetic".into(),
                checkpoint: "head".into(),
                action: crate::remote::Action::Push,
                result: Err("Push rejected".into()),
            }))
            .unwrap();
        app.events();
        events
            .send(Event::Remote(crate::remote::Report {
                path: "synthetic".into(),
                checkpoint: "head".into(),
                action: crate::remote::Action::Fetch,
                result: Ok(Some(crate::remote::Status {
                    head: "remote".into(),
                    relation: kagitaba_store::HistoryRelation {
                        ahead: 1,
                        behind: 0,
                    },
                })),
            }))
            .unwrap();
        app.events();
        assert_eq!(app.push_error.as_deref(), Some("Push rejected"));
        assert!(app.remote_error.is_none());
        events
            .send(Event::Wallet {
                path: "synthetic".into(),
                entries: vec![],
                participants: vec![],
                head: "new-head".into(),
            })
            .unwrap();
        events
            .send(Event::Remote(crate::remote::Report {
                path: "synthetic".into(),
                checkpoint: "head".into(),
                action: crate::remote::Action::Fetch,
                result: Ok(Some(crate::remote::Status {
                    head: "old-remote".into(),
                    relation: kagitaba_store::HistoryRelation {
                        ahead: 0,
                        behind: 1,
                    },
                })),
            }))
            .unwrap();
        app.events();
        assert!(app.remote_status.is_none());
        assert!(app.remote_due.unwrap() <= Instant::now());
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
        app.participant_names.insert(participant, "private name".into());
        app.last_activity = Instant::now() - Duration::from_secs(301);
        app.enforce_idle_lock(Instant::now());
        assert!(matches!(commands.try_recv(), Ok(Command::Lock)));
        assert!(app.json.is_empty() && app.titles.is_empty() && app.unlocked.is_none());
        assert!(app.participant_names.is_empty());
        app.enforce_idle_lock(Instant::now());
        assert!(commands.try_recv().is_err());
        for event in [
            Event::Locked,
            Event::Entry(id, Zeroizing::new("late secret".into()), vec![]),
            Event::Titles(vec![(id, Zeroizing::new("late title".into()))]),
            Event::ParticipantNames(BTreeMap::from([(participant, "late private name".into())])),
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
        assert!(app.participant_names.is_empty());
        events.send(Event::LockComplete).unwrap();
        events.send(Event::Done(Ok(()))).unwrap();
        app.events();
        assert!(!app.locking && !app.busy);
        assert_eq!(app.entries, vec![id]);
    }

    #[test]
    fn failed_decryption_keeps_encrypted_entry_selected() {
        let (mut app, commands, events) = app();
        app.unlocked = Some("device".into());
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

    #[test]
    fn trust_preview_is_not_history_and_verified_open_selects_unlock() {
        let (mut app, _, events) = app();
        app.preferences.set_remember(true);
        app.operation = Operation::Open;
        events
            .send(Event::Trust("/example/wallet".into(), "fingerprint".into()))
            .unwrap();
        app.events();
        assert!(app.preferences.recent.is_empty());
        app.trust = None;
        events
            .send(Event::Wallet {
                path: "/example/wallet".into(),
                entries: vec![],
                participants: vec![],
                head: "head".into(),
            })
            .unwrap();
        app.events();
        assert!(app.screen == Screen::Unlock);
        assert_eq!(
            app.preferences.recent,
            vec![PathBuf::from("/example/wallet")]
        );
    }

    #[test]
    fn unsaved_edits_block_navigation_but_lock_discards_them() {
        let (mut app, commands, _) = app();
        app.new_entry(false);
        let selected = app.selected;
        app.navigate(Leave::New(true));
        assert!(app.leave_action.is_some());
        assert_eq!(app.selected, selected);
        assert!(commands.try_recv().is_err());
        app.request_lock();
        assert!(app.leave_action.is_none() && app.json.is_empty() && app.entry_original.is_empty());
        assert!(matches!(commands.try_recv(), Ok(Command::Lock)));
    }

    #[test]
    fn close_waits_for_worker_and_suppresses_late_secrets() {
        let (mut app, commands, events) = app();
        app.wallet = Some("/example/wallet".into());
        app.screen = Screen::Wallet;
        app.unlocked = Some("key".into());
        app.navigate(Leave::Close);
        assert!(app.locking);
        assert!(matches!(commands.try_recv(), Ok(Command::Close)));
        events
            .send(Event::Titles(vec![(
                EntryId::from_bytes([1; 16]),
                Zeroizing::new("late".into()),
            )]))
            .unwrap();
        events.send(Event::LockComplete).unwrap();
        events.send(Event::Closed).unwrap();
        events.send(Event::Done(Ok(()))).unwrap();
        app.events();
        assert!(app.wallet.is_none() && app.titles.is_empty() && app.screen == Screen::Home);
        assert!(!app.busy && !app.locking);
    }

    #[test]
    fn unlocking_loads_titles_only_after_success_and_not_after_lock() {
        let (mut app, commands, events) = app();
        app.wallet = Some("/example/wallet".into());
        app.screen = Screen::Unlock;
        app.operation = Operation::Unlock;
        events.send(Event::Unlocked("key".into())).unwrap();
        events.send(Event::Done(Ok(()))).unwrap();
        app.events();
        assert!(app.screen == Screen::Wallet);
        assert!(matches!(commands.try_recv(), Ok(Command::Titles)));
        app.request_lock();
        assert!(matches!(commands.try_recv(), Ok(Command::Lock)));
        events.send(Event::Unlocked("late".into())).unwrap();
        events.send(Event::Done(Ok(()))).unwrap();
        app.events();
        assert!(commands.try_recv().is_err());
    }

    #[test]
    fn narrow_wallet_details_are_a_modal_with_a_lock_route() {
        let (mut app, _, _) = app();
        theme::install(&app.ctx);
        app.wallet = Some("/example/wallet".into());
        app.screen = Screen::Wallet;
        app.unlocked = Some(KeyId::from_bytes([1; 32]).to_string());
        app.new_entry(false);
        let ctx = app.ctx.clone();
        let input = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(440.0, 780.0),
            )),
            ..Default::default()
        };
        // egui sizes an area on its first pass; inspect the settled frame.
        let mut first = ctx.run_ui(input.clone(), |ui| app.content(ui));
        first.textures_delta.clear();
        let mut output = ctx.run_ui(input, |ui| app.content(ui));
        output.textures_delta.clear();
        let texts: Vec<_> = output
            .shapes
            .iter()
            .filter_map(|shape| match &shape.shape {
                egui::epaint::Shape::Text(text) => Some(text.galley.text()),
                _ => None,
            })
            .collect();
        assert!(texts.contains(&"Close details"));
        assert!(texts.contains(&"Password"));
        assert!(texts.iter().filter(|text| **text == "Lock").count() >= 2);
    }
}
