use crate::backend::{Command, Event};
use crate::{preferences::Preferences, theme};
use eframe::egui;
use kagitaba_core::{EntryId, KeyId};
use kagitaba_device::{KeyPolicy, Policies, PinPolicy, TouchPolicy, PrivateOperation};
use std::{
    cell::RefCell,
    collections::BTreeMap,
    path::PathBuf,
    sync::mpsc,
    time::{Duration, Instant},
};
use zeroize::{Zeroize, Zeroizing};
mod access;
mod collections;
mod copy;
mod dialog;
mod duplicates;
mod import_preview;
mod workflows;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Screen {
    Home,
    Create,
    Enrollment,
    Unlock,
    Wallet,
    Import,
    Keys,
    Transfer,
    Duplicates,
    Access,
    Copy,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Operation {
    Other,
    Open,
    Create,
    Unlock,
    Import,
    Save,
    Copy,
}

#[derive(Clone, Copy)]
enum Leave {
    Select(EntryId),
    New(bool),
    Screen(Screen),
    Close,
    DismissEntry,
    RevertEntry,
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
    CopyDestination,
    AddFile {
        owner: EntryId,
        digest: [u8; 32],
    },
    ExportFile {
        owner: EntryId,
        digest: [u8; 32],
        file: EntryId,
    },
}
#[derive(Default)]
struct EntryListCache {
    generation: u64,
    order: Vec<EntryId>,
    titles: BTreeMap<EntryId, Zeroizing<String>>,
    query: Zeroizing<String>,
    filtered: Vec<EntryId>,
}
pub struct App {
    tools: crate::credential_tools::Tools,
    gateway: Option<crate::gateway::Server>,
    gateway_request: Option<crate::gateway::Request>,
    gateway_selection: Option<EntryId>,
    gateway_error: bool,
    gateway_accounts: Option<Vec<crate::gateway_passkey::Account>>,
    gateway_account: Option<usize>,
    gateway_pin: String,
    screen: Screen,
    operation: Operation,
    preferences: Preferences,
    preferences_path: Option<PathBuf>,
    preference_error: Option<String>,
    create_path: Option<PathBuf>,
    import_complete: bool,
    entry_original: Zeroizing<String>,
    entry_digest: Option<[u8; 32]>,
    rename_file: Option<(EntryId, Zeroizing<String>)>,
    file_permit: Option<crate::backend::FilePermit>,
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
    policies: Policies,
    device_policies: Option<(Option<KeyPolicy>, Option<KeyPolicy>)>,
    private_operation: Option<Option<TouchPolicy>>,
    pin: String,
    focus_pin: bool,
    management: String,
    provision: bool,
    inspected_slots: Option<Vec<u8>>,
    use_prepared: bool,
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
    search_terms: BTreeMap<EntryId, Zeroizing<String>>,
    index_warning: Option<String>,
    index_rows: BTreeMap<EntryId, kagitaba_store::index::Row>,
    collection_selection: Option<(EntryId, Vec<usize>)>,
    unfiled_selection: bool,
    entry_generation: u64,
    entry_list_cache: RefCell<EntryListCache>,
    search: String,
    selected: Option<EntryId>,
    json: String,
    recipients: Vec<KeyId>,
    import_recipients: Vec<KeyId>,
    import_format: String,
    import_save_original: bool,
    import_skip_duplicates: bool,
    import_password: String,
    import_use_password: bool,
    keyfile: Option<PathBuf>,
    preview: Option<crate::backend::ImportPreview>,
    access_target: Option<KeyId>,
    access_preview: Option<crate::backend::access::AccessPreview>,
    duplicate_preview: Option<crate::backend::duplicates::DuplicatePreview>,
    copy_preview: Option<crate::backend::CopyPreview>,
    copy_selection: std::collections::BTreeSet<EntryId>,
    copy_recipients: Vec<KeyId>,
    copy_skip_duplicates: bool,
    copy_complete: bool,
    copy_active: bool,
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
    dialog: dialog::Dialog,
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
        match crate::gateway::start(cc.egui_ctx.clone()) {
            Ok(server) => app.gateway = Some(server),
            Err(_) => app.gateway_error = true,
        }
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
            tools: Default::default(),
            gateway: None,
            gateway_request: None,
            gateway_selection: None,
            gateway_error: false,
            gateway_accounts: None,
            gateway_account: None,
            gateway_pin: String::new(),
            screen: Screen::Home,
            operation: Operation::Other,
            preferences: Preferences::default(),
            preferences_path: None,
            preference_error: None,
            create_path: None,
            import_complete: false,
            entry_original: Zeroizing::new(String::new()),
            entry_digest: None,
            rename_file: None,
            file_permit: None,
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
            policies: Policies::default(),
            device_policies: None,
            private_operation: None,
            pin: String::new(),
            focus_pin: false,
            management: String::new(),
            provision: true,
            inspected_slots: None,
            use_prepared: false,
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
            search_terms: BTreeMap::new(),
            index_warning: None,
            index_rows: BTreeMap::new(),
            collection_selection: None,
            unfiled_selection: false,
            entry_generation: 1,
            entry_list_cache: RefCell::new(EntryListCache::default()),
            search: String::new(),
            selected: None,
            json: String::new(),
            recipients: vec![],
            import_recipients: vec![],
            import_format: "Bitwarden".into(),
            import_save_original: false,
            import_skip_duplicates: true,
            import_password: String::new(),
            import_use_password: true,
            keyfile: None,
            preview: None,
            access_target: None,
            access_preview: None,
            duplicate_preview: None,
            copy_preview: None,
            copy_selection: Default::default(),
            copy_recipients: Vec::new(),
            copy_skip_duplicates: true,
            copy_complete: false,
            copy_active: false,
            trust: None,
            reveal: false,
            delete_confirm: false,
            last_activity: Instant::now(),
            locking: false,
            participant_preview: None,
            clipboard: crate::editor::Clipboard::new(),
            dialog: dialog::Dialog::new(),
            pick: None,
            clear_ui_memory: false,
            revoke: None,
            revoke_confirm: false,
        }
    }
    fn send(&mut self, c: Command) {
        self.after_save = match &c {
            Command::Save(id, ..) | Command::AddFile(id, ..) | Command::RemoveFile(id, ..) | Command::RenameFile(id, ..) => Some(*id),
            _ => None,
        };
        self.operation = match &c {
            Command::Open(..) => Operation::Open,
            Command::Create(_) => Operation::Create,
            Command::Unlock(..) | Command::UsePreparedKey(..) | Command::ProvisionPrepared(..) => {
                Operation::Unlock
            }
            Command::Import(..) => Operation::Import,
            Command::CopyEntries(..) => { self.copy_preview = None; Operation::Copy },
            Command::Save(..)
            | Command::Grant(..)
            | Command::ApplyAccess
            | Command::DeleteDuplicates
            | Command::Delete(_)
            | Command::AddFile(..)
            | Command::RemoveFile(..)
            | Command::RenameFile(..) => Operation::Save,
            _ => Operation::Other,
        };
        if self.tx.send(c).is_ok() {
            self.busy = true;
            self.status = if matches!(self.operation, Operation::Open) {
                "Opening wallet and verifying signed history…"
            } else {
                "Working…"
            }.into();
        }
    }
    fn clear_gateway(&mut self) {
        self.gateway_request = None;
        self.gateway_selection = None;
        self.gateway_accounts = None;
        self.gateway_account = None;
        self.gateway_pin.zeroize();
    }
    fn clear_secrets(&mut self) {
        self.focus_pin = false;
        self.tools = Default::default();
        self.clear_gateway();
        self.reset_entry();
        self.clear_ui_memory = true;
        self.pick = None;
        self.dialog = dialog::Dialog::new();
        self.clipboard.clear();
        self.pin.zeroize();
        self.management.zeroize();
        self.inspected_slots = None;
        self.use_prepared = false;
        self.import_password.zeroize();
        self.json.zeroize();
        self.search.zeroize();
        self.titles.clear();
        self.entry_generation = self.entry_generation.wrapping_add(1);
        *self.entry_list_cache.borrow_mut() = EntryListCache::default();
        self.search_terms.clear();
        self.index_rows.clear();
        self.collection_selection = None;
        self.unfiled_selection = false;
        self.index_warning = None;
        for name in self.participant_names.values_mut() {
            name.zeroize();
        }
        self.participant_names.clear();
        self.participant_names_unavailable = false;
        self.selected = None;
        self.preview = None;
        self.duplicate_preview = None;
        self.access_target = None;
        self.access_preview = None;
        self.copy_preview = None;
        self.copy_selection.clear();
        self.copy_recipients.clear();
        self.copy_complete = false;
        self.copy_active = false;
        self.import_recipients.clear();
        self.reveal = false;
        self.unlocked = None;
        self.device_policies = None;
        self.private_operation = None;
        self.leave_action = None;
        self.participant_preview = None;
        self.consent = false;
        self.revoke_confirm = false;
        self.after_save = None;
        if let Some((_, name)) = &mut self.name_edit {
            name.zeroize();
        }
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
                Event::Policies(encryption, signing) => self.device_policies = Some((encryption, signing)),
                Event::PrivateOperation(event) => self.private_operation = match event {
                    PrivateOperation::Started(policy) => Some(policy),
                    PrivateOperation::Finished => None,
                },
                Event::GatewayLogin(id, response) => {
                    if self.gateway_request.as_ref().is_some_and(|r| r.id == id)
                        && let Some(request) = self.gateway_request.take()
                    {
                        if request.live() {
                            let _ = request.reply.try_send(response);
                        }
                        self.clear_gateway();
                    }
                }
                Event::GatewayAccounts(id, accounts) => {
                    if self
                        .gateway_request
                        .as_ref()
                        .is_some_and(|r| r.id == id && r.live())
                    {
                        self.gateway_accounts = Some(accounts);
                        self.gateway_account = None;
                    }
                }
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
                    for name in self.participant_names.values_mut() {
                        name.zeroize();
                    }
                    self.participant_names = names;
                    self.participant_names_unavailable = false;
                    self.name_edit = None;
                }
                Event::ParticipantNamesUnavailable => {
                    self.participant_names_unavailable = true;
                }
                Event::KeyInspected(slots) => {
                    self.last_activity = Instant::now();
                    self.provision = slots.len() < 2;
                    if slots.len() >= 2 {
                        self.encryption_slot = if slots.contains(&0x82) {
                            0x82
                        } else {
                            slots[0]
                        };
                        self.signing_slot = if slots.contains(&0x83) && self.encryption_slot != 0x83
                        {
                            0x83
                        } else {
                            *slots.iter().find(|s| **s != self.encryption_slot).unwrap()
                        };
                    }
                    self.inspected_slots = Some(slots);
                }
                Event::Unlocked(id) => {
                    self.unlocked = Some(id);
                    self.last_activity = Instant::now();
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
                        self.clear_gateway();
                        for name in self.participant_names.values_mut() {
                            name.zeroize();
                        }
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
                    self.entry_generation = self.entry_generation.wrapping_add(1);
                    *self.entry_list_cache.borrow_mut() = EntryListCache::default();
                    self.search_terms.clear();
                    self.index_rows.clear();
        self.collection_selection = None;
        self.unfiled_selection = false;
                    self.index_warning = None;
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
        self.duplicate_preview = None;
        self.access_target = None;
        self.access_preview = None;
        self.copy_preview = None;
        self.copy_selection.clear();
        self.copy_recipients.clear();
        self.copy_complete = false;
        self.copy_active = false;
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
                Event::Participant(enc, sign) => self.participant_preview = Some((enc, sign)),
                Event::CopyPreview(preview) => {
                    if self.screen == Screen::Copy && !self.locking {
                        self.copy_recipients = preview.default_recipient.into_iter().collect();
                        self.copy_skip_duplicates = true;
                        self.copy_active = true;
                        self.copy_preview = Some(preview);
                    }
                }
                Event::Copied => { self.copy_active = false; self.copy_preview = None; self.copy_recipients.clear(); self.copy_complete = true; }
                Event::AccessPreview(preview) => {
                    if self.screen == Screen::Access && self.unlocked.is_some() && !self.locking && self.access_target == Some(preview.target) {
                        self.access_preview = Some(preview);
                    }
                }
                Event::DuplicatePreview(preview) => {
                    if self.screen == Screen::Duplicates && self.unlocked.is_some() {
                        self.duplicate_preview = Some(preview);
                    }
                }
                Event::Preview(s) => { self.import_skip_duplicates = true; self.preview = Some(s); },
                Event::Entry(id, json, recipients, digest) => {
                    if !self.entries.contains(&id) { continue; }
                    self.reset_entry();
                    self.json = json.to_string();
                    self.entry_digest = Some(digest);
                    self.selected = Some(id);
                    self.recipients = recipients;
                    self.entry_original = Zeroizing::new(self.json.clone());
                    self.original_recipients = self.recipients.clone();
                    self.reveal = false;
                    self.delete_confirm = false;
                }
                Event::SearchTerms(terms) => {
                    self.entry_generation = self.entry_generation.wrapping_add(1);
                    self.search_terms = terms
                        .into_iter()
                        .filter(|(id, _)| self.entries.contains(id))
                        .map(|(id, terms)| (id, Zeroizing::new(terms.to_lowercase())))
                        .collect();
                }
                Event::IndexRows {
                    head,
                    participant,
                    rows,
                } => {
                    if self.head == head
                        && self.unlocked.as_deref() == Some(participant.to_string().as_str())
                    {
                        self.entry_generation = self.entry_generation.wrapping_add(1);
                        self.index_rows = rows
                            .into_iter()
                            .filter(|(id, _)| self.entries.contains(id))
                            .collect();
                    }
                }
                Event::IndexWarning(warning) => self.index_warning = Some(warning.into()),
                Event::Titles(t) => {
                    self.entry_generation = self.entry_generation.wrapping_add(1);
                    self.index_warning = None;
                    self.titles = t.into_iter().filter(|(id, _)| self.entries.contains(id)).collect();
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
                        self.after_save.take().filter(|id| success && self.entries.contains(id))
                    } else {
                        None
                    };
                    if self.operation == Operation::Copy { self.copy_active = false; self.copy_preview = None; }
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
                    if self.use_prepared {
                        self.use_prepared = false;
                        if success && self.unlocked.is_some() {
                            if self.screen == Screen::Create {
                                if let Some(path) = self.create_path.clone() {
                                    self.send(Command::Create(path));
                                }
                            } else if self.screen == Screen::Enrollment {
                                self.pick(Pick::ExportParticipant);
                            }
                        }
                    } else if load_titles {
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
        self.rename_file = None;
        self.entry_digest = None;
        if let Some(permit) = self.file_permit.take() {
            permit.cancel();
        }
        self.tools = Default::default();
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
        if let Some(action) = self.remote_busy {
            ui.spinner();
            ui.label(match action {
                crate::remote::Action::Fetch => "Fetching origin…",
                crate::remote::Action::Push => "Pushing signed changes…",
            });
        } else if self.remote_configured == Some(false) {
            ui.weak("No remote");
        } else if let Some(status) = &self.remote_status {
            let (ahead, behind) = (status.relation.ahead, status.relation.behind);
            ui.label(egui::RichText::new(match (ahead, behind) {
                (0, 0) => "Up to date".to_owned(),
                (a, 0) => format!("↑ {a} ahead"),
                (0, b) => format!("↓ {b} behind"),
                (a, b) => format!("↑ {a}  ↓ {b} · Diverged"),
            }).size(13.0).color(theme::MUTED));
        } else {
            ui.weak("Not fetched");
        }
        let enabled = !self.busy
            && !self.locking
            && self.remote_busy.is_none()
            && self.leave_action.is_none()
            && self.trust.is_none();
        if ui
            .add_enabled(enabled, egui::Button::new("⟳"))
            .on_hover_text("Fetch remote updates")
            .clicked()
        {
            self.request_remote(crate::remote::Action::Fetch);
        }
        if let Some(status) = self.remote_status.clone() {
            let (a, b) = (status.relation.ahead, status.relation.behind);
            if a > 0 && b == 0 && ui.add_enabled(enabled, egui::Button::new("Push")).clicked() {
                self.request_remote(crate::remote::Action::Push);
            }
            if b > 0 {
                let merge = a > 0;
                let label = if merge { "Merge and sign" } else { "Pull" };
                if ui.add_enabled(enabled && !self.dirty() && (!merge || self.unlocked.is_some()), egui::Button::new(label)).on_hover_text("Save or discard entry edits first. Merging also requires an unlocked key authorized on both sides.").clicked() {
                        self.send(if merge {Command::MergeRemote(status.head)} else {Command::PullRemote(status.head)});
                    }
            }
        }
        if let Some(error) = &self.remote_error {
            ui.colored_label(theme::ERROR, error);
        }
        if let Some(error) = &self.push_error
            && self.remote_error.as_ref() != Some(error)
        {
            ui.colored_label(theme::ERROR, error);
        }
    }

    fn select_entry(&mut self, id: EntryId) {
        self.reset_entry();
        if self.entries.contains(&id) { self.selected = Some(id); }
    }
    fn request_lock(&mut self) {
        if !self.locking {
            self.clear_secrets();
            self.locking = true;
            self.send(Command::Lock);
        }
    }
    fn enforce_idle_lock(&mut self, now: Instant) {
        if (self.unlocked.is_some() || self.inspected_slots.is_some() || self.copy_active)
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
            if self.wallet.is_some() && self.screen == Screen::Unlock {
                self.focus_pin = true;
            }
            self.device = device;
            self.encryption_slot = slots.encryption();
            self.signing_slot = slots.signing();
            self.consent = false;
        }
    }
    fn hardware_ui(&mut self, ui: &mut egui::Ui) {
        let setup = matches!(self.screen, Screen::Create | Screen::Enrollment);
        theme::section(ui, "Key");
        if !setup && self.unlocked.is_some() {
            if let Some(device) = self.devices.get(self.device) {
                ui.label(&device.label);
            } else { ui.label("Hardware key"); }
            ui.colored_label(theme::AQUA, "Unlocked");
            for (label, slot) in [("Encryption slot", self.encryption_slot), ("Signature slot", self.signing_slot)] {
                ui.horizontal(|ui| { theme::caption(ui, label); ui.monospace(format!("{slot:02X}")); });
            }
            return;
        }
        if setup {
            theme::caption(ui, "Kagitaba requires a hardware key with support for Personal Identity Verification (PIV).\nYou can add additional independent keys after wallet creation.");
        }
        let previous = (self.device, self.encryption_slot, self.signing_slot);
        ui.horizontal(|ui| {
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
                if ui
                    .button("⟳")
                    .on_hover_text("Refresh USB devices")
                    .clicked()
                {
                    self.inspected_slots = None;
                    self.consent = false;
                    self.send(Command::Scan);
                }
            });
        });
        if previous.0 != self.device {
            self.inspected_slots = None;
            self.send(Command::Lock);
            self.pin.zeroize();
            self.management.zeroize();
            self.match_device_slots(false);
        }
        if !setup && self.unlocked.is_none() && !self.device_hints.is_empty() {
            let selected = self
                .device_hints
                .iter()
                .find(|(_, hint)| {
                    self.devices
                        .get(self.device)
                        .and_then(|d| d.serial.as_deref())
                        == Some(hint.serial.as_str())
                        && hint.encryption_slot == self.encryption_slot
                        && hint.signing_slot == self.signing_slot
                })
                .map(|(id, _)| participant_label(id, &self.participant_names))
                .unwrap_or_else(|| "Choose a saved participant…".into());
            egui::ComboBox::from_id_salt("participant-route")
                .selected_text(selected)
                .show_ui(ui, |ui| {
                    for (id, hint) in &self.device_hints {
                        let connected = self
                            .devices
                            .iter()
                            .position(|d| d.serial.as_deref() == Some(hint.serial.as_str()));
                        if ui
                            .add_enabled(
                                connected.is_some(),
                                egui::Button::new(participant_label(id, &self.participant_names)),
                            )
                            .on_disabled_hover_text("Connect this key and refresh")
                            .clicked()
                        {
                            self.device = connected.unwrap();
                            self.encryption_slot = hint.encryption_slot;
                            self.signing_slot = hint.signing_slot;
                        }
                    }
                });
        }
        if self.unlocked.is_none() {
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("PIV PIN:").font(egui::FontId::new(16.0, egui::FontFamily::Name("bold".into()))));
                if self.focus_pin && ui.is_enabled() && self.devices.get(self.device).is_some() {
                    ui.memory_mut(|m| m.request_focus(egui::Id::new("piv-pin")));
                    self.focus_pin = false;
                }
                if theme::pin_input(
                    ui,
                    &mut self.pin,
                    self.inspected_slots.is_none(),
                    self.devices.get(self.device).is_some(),
                ) && let Some(device) = self.devices.get(self.device).cloned()
                {
                    let pin = Zeroizing::new(std::mem::take(&mut self.pin));
                    if setup {
                        self.send(Command::InspectKey(device, pin));
                    } else if let Ok(slots) =
                        kagitaba_device::Slots::new(self.encryption_slot, self.signing_slot)
                    {
                        self.send(Command::Unlock(device, slots, pin));
                    }
                }
                if self.inspected_slots.is_some() {
                    ui.colored_label(theme::AQUA, "✓");
                }
            });
        }
        if setup {
            ui.horizontal(|ui| {
                let existing = self.inspected_slots.as_ref().is_some_and(|s| s.len() >= 2);
                ui.add_enabled_ui(existing && self.unlocked.is_none(), |ui| {
                    if ui
                        .radio_value(&mut self.provision, false, "Use existing slots")
                        .changed()
                    {
                        self.consent = false;
                    }
                });
                ui.add_enabled_ui(
                    self.inspected_slots.is_some() && self.unlocked.is_none(),
                    |ui| {
                        if ui
                            .radio_value(&mut self.provision, true, "Enroll new slots")
                            .changed()
                        {
                            self.consent = false;
                        }
                    },
                );
            });
            theme::caption(ui, "Kagitaba uses two slots: one to encrypt and decrypt the wallet, and one to cryptographically sign updates.");
            self.slot_controls(ui, true);
        } else {
            ui.collapsing("PIV slots", |ui| self.slot_controls(ui, false));
        }
        if previous != (self.device, self.encryption_slot, self.signing_slot) {
            self.consent = false;
        }
        let slots = kagitaba_device::Slots::new(self.encryption_slot, self.signing_slot).ok();
        if slots.is_none() {
            ui.colored_label(theme::ERROR, "Choose two different slots.");
        }
        if self.unlocked.is_some() { self.device_policies_ui(ui); }
        if setup && self.provision {
            let previous = self.policies;
            for (label, policy) in [("Encryption", &mut self.policies.encryption), ("Signing", &mut self.policies.signing)] {
                ui.strong(label);
                egui::ComboBox::from_id_salt((label, "pin"))
                    .selected_text(format!("PIN: {:?}", policy.pin)).show_ui(ui, |ui| {
                        ui.selectable_value(&mut policy.pin, PinPolicy::Once, "Once per session (default)");
                        ui.selectable_value(&mut policy.pin, PinPolicy::Never, "Never — no hardware PIN requirement");
                    });
                egui::ComboBox::from_id_salt((label, "touch"))
                    .selected_text(format!("Touch: {:?}", policy.touch)).show_ui(ui, |ui| {
                        for value in [TouchPolicy::Never, TouchPolicy::Always, TouchPolicy::Cached] {
                            ui.selectable_value(&mut policy.touch, value, format!("{value:?}"));
                        }
                    });
            }
            if previous != self.policies { self.consent = false; }
            ui.label("Cached touch lasts briefly. PIN Always requires per-operation PIN prompts, which are not supported. Kagitaba still asks for a PIV PIN to unlock with PIN Never.");
            ui.label("Policies are fixed when each key is created. Changing them later requires replacing that key.");
            theme::caption(ui, "Management key:");
            ui.horizontal(|ui| {
                let input_width = (ui.available_width() - 86.0).clamp(40.0, 320.0);
                ui.add_enabled(
                    self.unlocked.is_none(),
                    egui::TextEdit::singleline(&mut self.management)
                        .desired_width(input_width)
                        .password(true),
                );
                if ui
                    .add_enabled(self.unlocked.is_none(), egui::Button::new("Default"))
                    .clicked()
                {
                    self.management = "010203040506070801020304050607080102030405060708".into();
                }
            });
            ui.add_enabled_ui(self.unlocked.is_none(), |ui| {
                ui.checkbox(
                    &mut self.consent,
                    format!(
                        "Yes, create keys in slots {:02X} and {:02X}",
                        self.encryption_slot, self.signing_slot
                    ),
                );
            });
            ui.add_enabled_ui(
                self.unlocked.is_none()
                    && self.inspected_slots.is_some()
                    && slots.is_some()
                    && self.consent
                    && !self.management.is_empty(),
                |ui| {
                    if theme::primary(ui, "Create keys").clicked() {
                        let key = Zeroizing::new(std::mem::take(&mut self.management));
                        self.send(Command::ProvisionPrepared(slots.unwrap(), self.policies, key));
                        self.consent = false;
                    }
                },
            );
        }
        if self.unlocked.is_some() {
            ui.colored_label(theme::AQUA, "✓");
        }
    }

    fn slot_controls(&mut self, ui: &mut egui::Ui, setup: bool) {
        ui.add_enabled_ui(self.unlocked.is_none(), |ui| {
            for (label, slot, default) in [
                ("Encryption slot", &mut self.encryption_slot, 0x82),
                ("Signature slot", &mut self.signing_slot, 0x83),
            ] {
                ui.horizontal(|ui| {
                    ui.label(label);
                    let label_value = |value| {
                        if value == default {
                            format!("{value:02X} default")
                        } else {
                            format!("{value:02X}")
                        }
                    };
                    egui::ComboBox::from_id_salt(label)
                        .selected_text(label_value(*slot))
                        .show_ui(ui, |ui| {
                            for value in 0x82..=0x95 {
                                let allowed = !setup
                                    || self.provision
                                    || self
                                        .inspected_slots
                                        .as_ref()
                                        .is_some_and(|s| s.contains(&value));
                                ui.add_enabled_ui(allowed, |ui| {
                                    ui.selectable_value(slot, value, label_value(value));
                                });
                            }
                        });
                });
            }
        });
    }
    fn device_policies_ui(&self, ui: &mut egui::Ui) {
        if let Some((encryption, signing)) = self.device_policies {
            ui.label("Current policies reported by the YubiKey (read-only):");
            for (label, policy) in [("Encryption", encryption), ("Signing", signing)] {
                ui.label(match policy {
                    Some(p) => format!("{label}: PIN {:?} · touch {:?}", p.pin, p.touch),
                    None => format!("{label}: policies unavailable from device"),
                });
                if policy.is_some_and(|p| p.pin == PinPolicy::Always) {
                    ui.colored_label(theme::ERROR, "PIN Always needs a fresh PIN for every operation; repeated operations with this key are not supported.");
                }
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
        theme::section(ui, "Combine diverged histories");
        theme::caption(ui,
            "Merge requires an unlocked signer on both sides. Conflicting edits stop the merge.",
        );
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
        theme::caption(ui, "Use Fetch to refresh remote updates.");
    }
    fn keys_ui(&mut self, ui: &mut egui::Ui) {
        ui.heading("Keys & access");
        theme::caption(ui, "An enrolled participant can sign wallet changes. Access to each entry is granted separately.");
        self.participant_names_ui(ui);
        egui::CollapsingHeader::new("This device").default_open(true).show(ui, |ui| {
            self.hardware_ui(ui);
            let remembered = self.unlocked.as_ref().and_then(|id| self.device_hints.iter().find(|(key, _)| key.to_string() == *id).map(|(_, hint)| hint)).is_some_and(|hint| {
                self.devices.get(self.device).and_then(|d| d.serial.as_deref()) == Some(hint.serial.as_str())
                    && hint.encryption_slot == self.encryption_slot && hint.signing_slot == self.signing_slot
            });
            if remembered { theme::caption(ui, "Device saved in wallet"); }
            if !remembered && ui
                .add_enabled(
                    self.unlocked.is_some(),
                    egui::Button::new("Remember device in wallet"),
                )
                .clicked()
            {
                self.send(Command::RememberDevice);
            }
        });
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
            theme::caption(ui, "Compare both fingerprints with the owner before enrolling. Enrollment grants wallet-wide signing authority.");
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
            theme::caption(ui, "Encrypted names are shared with all participants.");
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
                ui.add(egui::TextEdit::singleline(draft).font(egui::TextStyle::Monospace).char_limit(128).hint_text("e.g. Pixel, Firefox, backup YubiKey"));
                theme::caption(ui, "Leave empty to remove the name.");
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
        if let Some(report) = &mut self.preview {
            theme::caption(ui, "2 / 2 · Review & choose access");
            let counts = &report.report;
            ui.scope(|ui| {
            ui.spacing_mut().interact_size.y = 18.0;
            ui.spacing_mut().item_spacing.y = 6.0;
            theme::section(ui, "Summary");
            for (label, count) in [("Entries", counts.items), ("Collections", counts.root_collections), ("Source accounts", counts.accounts), ("Files", report.imported_files)] {
                if count > 0 { ui.horizontal_wrapped(|ui| { theme::caption(ui, label).on_hover_text(if label == "Source accounts" { "Source export containers, not individual login credentials." } else { label }); ui.label(count.to_string()); }); }
            }
            if !counts.opaque_credential_types.is_empty() || !report.warnings.retained.is_empty() {
                ui.add_space(12.0);
                theme::section(ui, "Unknown data");
                for (kind, count) in &counts.opaque_credential_types {
                    // Type labels are untrusted source metadata, never credential values.
                    let label: String = kind.chars().filter(|c| !c.is_control() && !matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')).take(80).collect();
                    ui.horizontal_wrapped(|ui| { theme::caption(ui, if kind == "totp" { format!("{label} (unsupported algorithm)") } else { format!("{label} (preserved)") }); ui.label(count.to_string()); });
                    if kind == "custom-fields" && !counts.preserved_custom_field_types.is_empty() {
                        ui.indent("custom-field-types", |ui| {
                            for (field_type, field_count) in &counts.preserved_custom_field_types {
                                let label: String = field_type.chars().filter(|c| !c.is_control() && !matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')).take(80).collect();
                                ui.horizontal_wrapped(|ui| { theme::caption(ui, label); ui.label(format!("{field_count} {}", if *field_count == 1 { "field" } else { "fields" })); });
                            }
                        });
                    }
                }
                for (&label, count) in &report.warnings.retained { ui.horizontal_wrapped(|ui| { theme::caption(ui, label); ui.label(count.to_string()); }); }
            }
            if counts.external_files > 0 || counts.empty_accounts > 0 || !report.warnings.omitted.is_empty() {
                ui.add_space(12.0);
                theme::section(ui, "Not imported");
                if counts.external_files > 0 { ui.label(format!("External file bytes: {} (descriptors retained)", counts.external_files)); }
                if counts.empty_accounts > 0 { ui.label(format!("Empty accounts: {} (no entries)", counts.empty_accounts)); }
                for (&label, count) in &report.warnings.omitted { ui.horizontal_wrapped(|ui| { theme::caption(ui, label); ui.label(count.to_string()); }); }
            }
            if counts.unresolved_links > 0 || !report.warnings.review.is_empty() {
                ui.add_space(12.0);
                theme::section(ui, "Review before use");
                if counts.unresolved_links > 0 { ui.label(format!("Unresolved links retained: {}", counts.unresolved_links)); }
                for (&label, count) in &report.warnings.review { ui.horizontal_wrapped(|ui| { theme::caption(ui, label); ui.label(count.to_string()); }); }
            }
            });
            ui.add_space(16.0);
            ui.checkbox(&mut self.import_skip_duplicates, format!("Skip {} existing duplicates", report.existing_duplicates));
            if report.unavailable_entries > 0 {
                theme::caption(ui, format!("{} entries are not available to this key", report.unavailable_entries));
            }
            import_preview::duplicate_differences(ui, &report.duplicate_differences);
            let focus = import_preview::diagnostics(ui, &report.warnings, &mut report.entries, self.import_skip_duplicates);
            import_preview::entries_focused(ui, &mut report.entries, focus, self.import_skip_duplicates);
            theme::section(ui, "Access");
            recipient_ui(
                ui,
                &self.participants,
                &self.participant_names,
                &mut self.import_recipients,
            );
            theme::caption(ui, "Unmatched entries are imported as new copies.");
            if ui
                .add_enabled_ui(!self.import_recipients.is_empty(), |ui| theme::primary(ui, "Encrypt and import"))
                .inner.clicked()
            {
                self.send(Command::Import(self.import_recipients.clone(), self.import_skip_duplicates));
            }
            if ui.button("Choose a different file").clicked() {
                self.preview = None;
        self.duplicate_preview = None;
        self.copy_preview = None;
        self.copy_selection.clear();
        self.copy_recipients.clear();
        self.copy_complete = false;
        self.copy_active = false;
                self.import_recipients.clear();
                self.send(Command::DiscardImport);
            }
        } else {
            theme::caption(ui, "1 / 2 · Choose a source");
            egui::ComboBox::from_id_salt("format")
                .selected_text(&self.import_format)
                .show_ui(ui, |ui| {
                    for f in ["Bitwarden", "Firefox CSV", "CXF", "KeePass"] {
                        ui.selectable_value(&mut self.import_format, f.to_string(), f);
                    }
                });
            ui.checkbox(&mut self.import_save_original, "Save original file as an entry");
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
                    egui::TextEdit::singleline(&mut self.import_password)
                        .font(egui::TextStyle::Monospace)
                        .password(true),
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
            ui.small(match self.import_format.as_str() { "KeePass" => "Encrypted KDBX/KDB database. Password and key file are combined when both are selected.", "Bitwarden" => "Unencrypted JSON export. Encrypted JSON and CSV are not supported.", "Firefox CSV" => "Firefox password CSV export.", _ => "Plaintext CXF document. Encrypted CXP transport is not supported." });
            if theme::primary(ui, "Choose file & preview…").clicked() {
                self.pick(Pick::Import);
            }
        }
    }
    fn visible_entries(&self) -> Vec<EntryId> {
        let query = Zeroizing::new(self.search.trim().to_lowercase());
        let mut cache = self.entry_list_cache.borrow_mut();
        let changed = cache.generation != self.entry_generation;
        if changed {
            cache.titles = self
                .titles
                .iter()
                .map(|(id, title)| (*id, Zeroizing::new(title.to_lowercase())))
                .collect();
            let members = self.selected_collection().map(|node| node.entries.iter().copied().collect::<std::collections::BTreeSet<_>>());
            let filed = if self.unfiled_selection { self.filed_entries() } else { Default::default() };
            let mut order: Vec<_> = self.entries.iter().copied().filter(|id| {
                !self.index_rows.get(id).is_some_and(|row| row.kind == kagitaba_cxf::PayloadKind::Collection)
                    && (!self.unfiled_selection || !filed.contains(id))
                    && match &self.collection_selection {
                        None => true,
                        Some(_) => members.as_ref().is_some_and(|ids| ids.contains(id)) && self.index_rows.contains_key(id),
                    }
            }).collect();
            order.sort_by(|a, b| {
                let left = cache.titles.get(a).map(|title| title.as_str());
                let right = cache.titles.get(b).map(|title| title.as_str());
                (left.is_none(), left, a).cmp(&(right.is_none(), right, b))
            });
            cache.order = order;
            cache.generation = self.entry_generation;
        }
        if changed || *cache.query != *query {
            cache.filtered = cache
                .order
                .iter()
                .copied()
                .filter(|id| {
                    query.is_empty()
                        || id.to_string().contains(query.as_str())
                        || self
                            .search_terms
                            .get(id)
                            .is_some_and(|terms| terms.contains(query.as_str()))
                        || cache
                            .titles
                            .get(id)
                            .is_some_and(|title| title.contains(query.as_str()))
                })
                .collect();
            cache.query = query;
        }
        cache.filtered.clone()
    }

    fn entry_list(&mut self, ui: &mut egui::Ui) {
        ui.heading("Entries");
        if let Some(warning) = &self.index_warning {
            ui.colored_label(theme::ERROR, warning);
        }
        ui.add_enabled_ui(self.unlocked.is_some(), |ui| {
            ui.horizontal_wrapped(|ui| {
                if ui.button("New login").clicked() {
                    self.navigate(Leave::New(false));
                }
                if ui.button("New collection").clicked() {
                    self.navigate(Leave::New(true));
                }
                if self.titles.len() < self.entries.len() && ui.button("Refresh index").clicked() {
                    self.send(Command::Titles);
                }
            });
        });
        ui.horizontal(|ui| {
            let search = ui.add(
                egui::TextEdit::singleline(&mut self.search)
                    .font(egui::TextStyle::Monospace)
                    .desired_width((ui.available_width() - 60.0).max(80.0))
                    .hint_text("Search names, accounts or URLs"),
            );
            if search.has_focus() && ui.input(|i| i.key_pressed(egui::Key::Escape)) {
                self.search.zeroize();
            }
            if ui
                .add_enabled(!self.search.is_empty(), egui::Button::new("Clear"))
                .clicked()
            {
                self.search.zeroize();
                search.request_focus();
            }
        });
        let entries = self.visible_entries();
        theme::caption(ui, format!(
            "{} of {} entries",
            entries.len(),
            self.entries.iter().filter(|id| !self.index_rows.get(id).is_some_and(|row| row.kind == kagitaba_cxf::PayloadKind::Collection)).count()
        ));
        if self.unlocked.is_none() {
            theme::caption(ui, "Unlock to search credentials.");
        }
        egui::ScrollArea::vertical()
            .scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::VisibleWhenNeeded)
            .id_salt("entry-list")
            .show_rows(ui, 60.0, entries.len(), |ui, rows| {
                for id in &entries[rows] {
                    let label = self
                        .titles
                        .get(id)
                        .map(|s| s.as_str())
                        .unwrap_or("Encrypted entry");
                    let mut text = egui::text::LayoutJob::default();
                    text.append(label, 0.0, egui::TextFormat { font_id: egui::FontId::proportional(16.0), color: theme::INK, ..Default::default() });
                    if let Some(row) = self.index_rows.get(id) {
                        let usernames = Zeroizing::new(row.usernames.join(" · "));
                        if !usernames.is_empty() {
                            text.append(&format!("\n{}", usernames.as_str()), 0.0, egui::TextFormat { font_id: egui::FontId::proportional(14.0), color: theme::MUTED, ..Default::default() });
                        }
                    }
                    text.append(&format!("\n{}", &id.to_string()[..8]), 0.0, egui::TextFormat { font_id: egui::FontId::monospace(11.0), color: theme::MUTED, ..Default::default() });
                    text.wrap.max_width = (ui.available_width() - 28.0).max(1.0);
                    text.wrap.max_rows = 3;
                    let text = ui.fonts_mut(|fonts| fonts.layout_job(text));
                    if ui
                        .add_sized(
                            [ui.available_width(), 60.0],
                            egui::Button::selectable(self.selected == Some(*id), "").left_text(text),
                        )
                        .on_hover_text(id.to_string())
                        .clicked()
                    {
                        self.navigate(Leave::Select(*id));
                    }
                }
            });
        if self.entries.is_empty() {
            ui.label("No entries yet. Add a login or import an existing wallet.");
        } else if entries.is_empty() {
            ui.label("No matching entries.");
        }
    }
    fn entry_ui(&mut self, ui: &mut egui::Ui) {
        if let Some(id) = self.selected {
            if self.json.is_empty() && self.index_rows.contains_key(&id) {
                ui.label(egui::RichText::new("Entry details").size(13.0).color(theme::MUTED));
            } else {
                ui.heading(if self.entries.contains(&id) { "Entry details" } else { "New entry" });
            }
            ui.label(egui::RichText::new(format!("Entry {id}")).size(12.0).color(theme::MUTED));
            let paths = self.entry_collection_paths(id);
            if !paths.is_empty() {
                theme::caption(ui, "Collections");
                for path in paths { ui.add(egui::Label::new(path).selectable(true)); }
            }

            if !self.json.is_empty() {
                ui.horizontal_wrapped(|ui| {
                    if ui
                        .add_enabled(
                            self.dirty() && !self.recipients.is_empty(),
                            egui::Button::new(
                                egui::RichText::new(if self.entries.contains(&id) {
                                    "Save changes"
                                } else {
                                    "Create entry"
                                })
                                .color(theme::BACKGROUND),
                            )
                            .fill(theme::AQUA),
                        )
                        .clicked()
                    {
                        self.send(Command::Save(
                            id,
                            Zeroizing::new(self.json.clone()),
                            self.recipients.clone(),
                        ));
                    }
                    if self.dirty() {
                        if ui.button("Discard edits…").clicked() {
                            self.navigate(Leave::RevertEntry);
                        }
                        ui.label("Unsaved changes");
                    } else {
                        ui.label("All changes saved");
                    }
                });
                if self.recipients.is_empty() {
                    ui.label(
                        "Select at least one recipient under “Who can access this entry?” to save.",
                    );
                }
                ui.separator();
            }
            if self.json.is_empty() {
                if let Some(row) = self.index_rows.get(&id) {
                    ui.add(egui::Label::new(egui::RichText::new(&row.title).size(22.0).strong()).selectable(true));
                    if !row.usernames.is_empty() {
                        ui.label(egui::RichText::new("Usernames").size(13.0).color(theme::MUTED));
                        for username in &row.usernames {
                            ui.add(egui::Label::new(username).selectable(true));
                        }
                    }
                    if !row.scopes.is_empty() {
                        ui.label(egui::RichText::new("Scopes").size(13.0).color(theme::MUTED));
                        for scope in &row.scopes {
                            let label = preview_scope(scope);
                            ui.add(egui::Label::new(label.as_str()).selectable(true));
                        }
                    }
                    ui.horizontal_wrapped(|ui| {
                        for (label, present) in [
                            ("Password", row.password),
                            ("TOTP", row.totp),
                            ("Passkey", row.passkey),
                        ] {
                            ui.label(egui::RichText::new(format!("{} {label}", if present { "✓" } else { "—" })).size(13.0).color(if present { theme::AQUA } else { theme::MUTED }));
                        }
                    });
                } else if let Some(title) = self.titles.get(&id) {
                    ui.label(title.as_str());
                }
                if ui
                    .add_enabled(self.unlocked.is_some() && self.entries.contains(&id), egui::Button::new("Show more"))
                    .clicked()
                {
                    self.send(Command::Read(id));
                }
            } else {
                ui.push_id((id, self.editor_epoch), |ui| {
                    if let Some(status) = crate::editor::show(ui, &mut self.json, &mut self.clipboard, &mut self.tools) {
                        self.status = status;
                    }
                    ui.checkbox(&mut self.reveal, "Advanced: reveal and edit complete payload");
                    if self.reveal {
                        theme::caption(ui, "Editing here does not change your password at the website.");
                        egui::ScrollArea::vertical()
            .scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::VisibleWhenNeeded)
                            .max_height(350.0)
                            .show(ui, |ui| {
                                ui.add(
                                    egui::TextEdit::multiline(&mut self.json).font(egui::TextStyle::Monospace)
                                        .code_editor()
                                        .desired_width(f32::INFINITY)
                                        .desired_rows(16),
                                );
                            });
                    }
                    ui.collapsing("Who can access this entry?", |ui| {
                    theme::section(ui, "Recipients for the next revision");
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
                    theme::caption(ui, "Adding grants retains existing access. To remove recipients, save a new revision with only the recipients you want.");
                    });
                });
            }
            if !self.json.is_empty() {
                self.attachments_ui(ui, id);
            }
            if self.entries.contains(&id) {
                egui::CollapsingHeader::new("Delete entry…")
                    .id_salt(("delete-entry", id, self.editor_epoch))
                    .default_open(self.json.is_empty() && !self.index_rows.contains_key(&id))
                    .show(ui, |ui| {
                        ui.checkbox(
                            &mut self.delete_confirm,
                            "Confirm deletion (history remains readable)",
                        );
                        if ui
                            .add_enabled(
                                self.delete_confirm
                                    && self.entries.contains(&id)
                                    && self.unlocked.is_some(),
                                egui::Button::new("Delete entry"),
                            )
                            .clicked()
                        {
                            self.send(Command::Delete(id));
                            self.json.zeroize();
                            self.selected = None;
                        }
                    });
            }
        } else {
            ui.heading("Entry details");
            ui.label("Select an entry.");
        }
    }
    fn attachments_ui(&mut self, ui: &mut egui::Ui, owner: EntryId) {
        let Ok(payload) = kagitaba_cxf::Payload::from_json(owner, self.json.as_bytes()) else {
            return;
        };
        if payload.kind() != kagitaba_cxf::PayloadKind::Item { return; }
        let Ok(files) = kagitaba_cxf::attachments::list(&payload) else {
            return;
        };
        ui.separator();
        ui.heading("Attachments");
        let ready = self.unlocked.is_some()
            && self.entries.contains(&owner)
            && self.entry_digest.is_some()
            && !self.dirty();
        ui.add_enabled_ui(ready, |ui| {
            for file in files {
                ui.horizontal_wrapped(|ui| {
                    ui.label(&file.name);
                    ui.weak(format!("{} bytes", file.size));
                    if ui.button("Save as…").clicked() {
                        self.pick(Pick::ExportFile {
                            owner,
                            digest: self.entry_digest.unwrap(),
                            file: file.id,
                        });
                    }
                    if ui.button("Rename").clicked() {
                        self.rename_file = Some((file.id, Zeroizing::new(file.name.clone())));
                        ui.memory_mut(|m| m.request_focus(egui::Id::new(("attachment-name", file.id))));
                    }
                    if ui.button("Remove").clicked() {
                        let permit = self.new_file_permit();
                        self.send(Command::RemoveFile(
                            owner,
                            self.entry_digest.unwrap(),
                            file.id,
                            permit,
                        ));
                    }
                });
            }
            let mut rename = None;
            let mut cancel = false;
            if let Some((file, name)) = &mut self.rename_file {
                ui.horizontal_wrapped(|ui| {
                    let input = ui.add(egui::TextEdit::singleline(&mut **name)
                        .id(egui::Id::new(("attachment-name", *file))).desired_width(260.0));
                    let enter = (input.has_focus() || input.lost_focus()) && ui.input(|i| i.key_pressed(egui::Key::Enter));
                    let changed = attachments_name_changed(&payload, *file, name);
                    if ui.add_enabled(changed, egui::Button::new("Save name")).clicked() || (changed && enter) {
                        rename = Some((*file, Zeroizing::new(name.to_string())));
                    }
                    cancel = ui.button("Cancel").clicked() || (input.has_focus() && ui.input(|i| i.key_pressed(egui::Key::Escape)));
                });
            }
            if cancel { self.rename_file = None; }
            if let Some((file, name)) = rename {
                self.rename_file = None;
                let permit = self.new_file_permit();
                self.send(Command::RenameFile(owner, self.entry_digest.unwrap(), file, name, permit));
            }
            if ui.button("Add file…").clicked() {
                self.pick(Pick::AddFile {
                    owner,
                    digest: self.entry_digest.unwrap(),
                });
            }
        });
    }

    fn new_file_permit(&mut self) -> crate::backend::FilePermit {
        if let Some(previous) = self.file_permit.take() {
            previous.cancel();
        }
        let permit = crate::backend::FilePermit::for_head(self.head.clone());
        self.file_permit = Some(permit.clone());
        permit
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
        if matches!(pick, Pick::AddFile { .. } | Pick::ExportFile { .. }) {
            self.new_file_permit();
        }
        self.pick = Some(pick);
        self.dialog.open(pick, self.ctx.clone());
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
            self.import_save_original,
        ));
    }
    fn file_picked(&mut self, pick: Pick, path: PathBuf) {
        let (owner, digest) = match pick {
            Pick::AddFile { owner, digest } | Pick::ExportFile { owner, digest, .. } => {
                (owner, digest)
            }
            _ => return,
        };
        if self.selected == Some(owner)
            && self.entry_digest == Some(digest)
            && self.unlocked.is_some()
            && !self.dirty()
        {
            if let Some(permit) = self.file_permit.clone() {
                self.send(match pick {
                    Pick::AddFile { .. } => Command::AddFile(owner, digest, path, permit),
                    Pick::ExportFile { file, .. } => {
                        Command::ExportFile(owner, digest, file, path, permit)
                    }
                    _ => unreachable!(),
                });
            }
        } else if let Some(permit) = self.file_permit.take() {
            permit.cancel();
        }
    }

    fn dialog(&mut self, ctx: &egui::Context) {
        self.dialog.update(ctx);
        if self.dialog.take_finished_empty() {
            self.pick = None;
            if let Some(permit) = self.file_permit.take() { permit.cancel(); }
            self.status = "No file selected — chooser cancelled or unavailable".into();
        }
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
                Pick::CopyDestination => self.send(Command::PreviewCopy(path, self.copy_selection.iter().copied().collect())),
                Pick::AddFile { .. } | Pick::ExportFile { .. } => self.file_picked(pick, path),
                Pick::Import => {
                    self.preview_import(path);
                }
            }
        }
    }
}
fn attachments_name_changed(payload: &kagitaba_cxf::Payload, id: EntryId, name: &str) -> bool {
    kagitaba_cxf::attachments::list(payload).is_ok_and(|files| files.iter().any(|file| file.id == id && file.name != name))
        && kagitaba_cxf::attachments::rename(payload, id, name).is_ok()
}
fn preview_scope(scope: &str) -> Zeroizing<String> {
    let mut label = Zeroizing::new(scope.to_owned());
    if let Some(json) = scope.strip_prefix("android:")
        && let Ok(mut app) = serde_json::from_str::<serde_json::Value>(json)
    {
        if let Some(bundle) = app["bundleId"].as_str() {
            label.zeroize();
            label.push_str("Android: ");
            if let Some(name) = app["name"].as_str() {
                label.push_str(name);
                label.push_str(" · ");
            }
            label.push_str(bundle);
            if let Some(fingerprint) = app["certificate"]["fingerprint"].as_str() {
                label.push('\n');
                if let Some(algorithm) = app["certificate"]["hashAlg"].as_str() {
                    label.push_str(algorithm);
                    label.push_str(": ");
                }
                label.push_str(fingerprint);
            }
        }
        fn wipe(value: &mut serde_json::Value) {
            match value {
                serde_json::Value::String(text) => text.zeroize(),
                serde_json::Value::Array(values) => values.iter_mut().for_each(wipe),
                serde_json::Value::Object(values) => values.values_mut().for_each(wipe),
                _ => {}
            }
        }
        wipe(&mut app);
    }
    label
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
    fn gateway_passkey_ui(&mut self, ui: &mut egui::Ui, passkey: crate::gateway_passkey::Request) {
        let mut approve = false;
        let mut load = false;
        let mut cancel = false;
        let mut fallback = false;
        egui::Window::new("Browser passkey request").collapsible(false).show(ui.ctx(), |ui| {
            ui.heading(if passkey.create {"Create a passkey"} else {"Sign in with a passkey"});
            ui.monospace(&passkey.origin);
            ui.label(format!("Relying party: {}", passkey.rp_id));
            if self.unlocked.is_none() {
                ui.label("Open and unlock your wallet, then retry from Firefox.");
            } else {
                if passkey.create {
                    ui.label(format!("Account: {}", passkey.input["user"]["name"].as_str().unwrap_or("")));
                    theme::caption(ui, "The new passkey will be encrypted for this participant and saved before registration succeeds.");
                } else if let Some(accounts) = &self.gateway_accounts {
                    if accounts.is_empty() { ui.label("No accessible ES256 passkey matches this request."); }
                    for (index, account) in accounts.iter().enumerate() {
                        ui.selectable_value(&mut self.gateway_account, Some(index), format!("{} · {}", account.title.as_str(), account.username.as_str()));
                    }
                } else {
                    load = ui.add_enabled(!self.busy, egui::Button::new("Find matching passkeys")).clicked();
                }
                ui.label("Verify with your PIV PIN for this request. A failed attempt is not retried.");
                // Do not retain a PIN in egui's text-edit undo history.
                let pin_id = egui::Id::new("gateway-passkey-pin");
                ui.add(egui::TextEdit::singleline(&mut self.gateway_pin).font(egui::TextStyle::Monospace).password(true).id(pin_id));
                ui.ctx().data_mut(|data| data.remove::<egui::text_edit::TextEditState>(pin_id));
                approve = ui.add_enabled(!self.busy && !self.locking && !self.gateway_pin.is_empty()
                    && (passkey.create || self.gateway_account.is_some()), egui::Button::new("Verify PIN and approve")).clicked();
            }
            ui.horizontal(|ui| {
                cancel = ui.button("Deny").clicked();
                fallback = ui.button("Use Firefox instead").clicked();
            });
        });
        if fallback {
            if let Some(request) = self.gateway_request.take() {
                let _ = request
                    .reply
                    .try_send(Zeroizing::new("{\"version\":1,\"fallback\":true}".into()));
            }
            self.clear_gateway();
        } else if cancel {
            self.clear_gateway();
        } else if let Some(request) = &self.gateway_request {
            let id = request.id;
            let permit = request.permit();
            if load {
                self.send(Command::GatewayAccounts(id, Box::new(passkey), permit));
            } else if approve {
                let selected = self
                    .gateway_account
                    .and_then(|index| self.gateway_accounts.as_ref()?.get(index))
                    .map(|account| (account.entry, account.credential.clone()));
                let pin = Zeroizing::new(std::mem::take(&mut self.gateway_pin));
                self.last_activity = Instant::now();
                self.send(Command::GatewayPasskey {
                    id,
                    request: Box::new(passkey),
                    selected,
                    pin,
                    permit,
                });
            }
        }
    }
    fn gateway_ui(&mut self, ui: &mut egui::Ui) {
        if self.gateway_error {
            ui.label("Browser gateway unavailable: check the private runtime directory or another running client.");
        }
        if let Some(server) = &self.gateway {
            while let Ok(request) = server.requests.try_recv() {
                if self.gateway_request.is_none() && request.live() && !self.locking {
                    self.gateway_selection = None;
                    self.gateway_accounts = None;
                    self.gateway_account = None;
                    self.gateway_pin.zeroize();
                    self.gateway_request = Some(request);
                    self.ctx
                        .send_viewport_cmd(egui::ViewportCommand::RequestUserAttention(
                            egui::UserAttentionType::Informational,
                        ));
                }
            }
        }
        if self.gateway_request.as_ref().is_some_and(|r| !r.live()) {
            self.clear_gateway();
        }
        let Some(request) = &self.gateway_request else {
            return;
        };
        let origin = request.origin.clone();
        if let Some(passkey) = request.passkey.clone() {
            self.gateway_passkey_ui(ui, passkey);
            return;
        }
        let mut approve = false;
        let mut cancel = false;
        egui::Window::new("Browser login request")
            .collapsible(false)
            .resizable(false)
            .show(ui.ctx(), |ui| {
                ui.label("Send a login to this website?");
                ui.monospace(&origin);
                theme::caption(ui, "Only a login with an exactly matching HTTPS origin can be sent.");
                if self.unlocked.is_none() {
                    ui.label("Open and unlock your wallet, then retry from Firefox.");
                } else {
                    let selected = self
                        .gateway_selection
                        .and_then(|id| self.titles.get(&id))
                        .map(|s| s.as_str())
                        .unwrap_or("Choose an entry");
                    egui::ComboBox::from_id_salt("gateway-entry")
                        .selected_text(selected)
                        .show_ui(ui, |ui| {
                            for id in &self.entries {
                                let title = self
                                    .titles
                                    .get(id)
                                    .map(|s| s.to_string())
                                    .unwrap_or_else(|| id.to_string());
                                ui.selectable_value(&mut self.gateway_selection, Some(*id), title);
                            }
                        });
                    approve = ui
                        .add_enabled(
                            !self.busy && !self.locking && self.gateway_selection.is_some(),
                            egui::Button::new("Approve and fill"),
                        )
                        .clicked();
                }
                cancel = ui.button("Deny").clicked();
            });
        if cancel {
            self.clear_gateway();
        } else if approve
            && let (Some(request), Some(id)) = (&self.gateway_request, self.gateway_selection)
        {
            let request_id = request.id;
            self.last_activity = Instant::now();
            self.send(Command::GatewayLogin(request_id, id, origin));
        }
    }
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
        self.gateway_ui(ui);
        if self.last_activity.elapsed() >= Duration::from_secs(300) {
            self.tools = Default::default();
        }
        self.tools
            .show(ui.ctx(), &mut self.json, &mut self.clipboard);
    }
}
impl Drop for App {
    fn drop(&mut self) {
        self.clear_secrets();
    }
}

#[cfg(test)]
mod tests {
    fn preview_row() -> kagitaba_store::index::Row {
        kagitaba_store::index::Row {
            digest: [1; 32],
            grant_digest: [2; 32],
            title: "Example".into(),
            kind: kagitaba_cxf::PayloadKind::Item,
            collection: None,
            usernames: vec!["alice".into()],
            scopes: vec!["https://example.test".into()],
            password: true,
            totp: false,
            passkey: true,
        }
    }

    #[test]
    fn cached_collection_filters_do_not_read_and_unfiled_includes_nested_membership() {
        use kagitaba_store::index::CollectionNode;
        let (mut app, commands, _) = app();
        let ids: Vec<_> = (1..=5).map(|n| EntryId::from_bytes([n;16])).collect();
        let (root, direct, child, unfiled, inaccessible) = (ids[0],ids[1],ids[2],ids[3],ids[4]);
        app.entries = ids.clone();
        for id in [direct,child,unfiled] { app.index_rows.insert(id,preview_row()); }
        let mut row = preview_row(); row.kind = kagitaba_cxf::PayloadKind::Collection;
        row.collection = Some(CollectionNode {id:root.as_bytes().to_vec(),title:"Root".into(),entries:vec![direct,inaccessible,EntryId::from_bytes([9;16])],unresolved_links:0,children:vec![CollectionNode {id:vec![8],title:"Child".into(),entries:vec![child],children:vec![],unresolved_links:0}]});
        app.index_rows.insert(root,row);
        assert_eq!(app.visible_entries(),vec![direct,child,unfiled,inaccessible]);
        app.select_collection(Some((root,vec![])),false);
        assert_eq!(app.visible_entries(),vec![direct]);
        app.select_collection(Some((root,vec![0])),false);
        assert_eq!(app.visible_entries(),vec![child]);
        app.select_collection(None,true);
        assert_eq!(app.visible_entries(),vec![unfiled]);
        app.select_collection(Some((root,vec![99])),false);
        assert!(app.visible_entries().is_empty());
        assert!(commands.try_recv().is_err());
        app.clear_secrets();
        assert!(app.collection_selection.is_none() && !app.unfiled_selection);
    }

    #[test]
    fn attachment_rename_draft_is_cleared_on_navigation_and_lock() {
        let (mut app, _, _) = app();
        app.rename_file = Some((EntryId::from_bytes([1;16]), Zeroizing::new("private-name".into())));
        app.reset_entry();
        assert!(app.rename_file.is_none());
        app.rename_file = Some((EntryId::from_bytes([1;16]), Zeroizing::new("private-name".into())));
        app.clear_secrets();
        assert!(app.rename_file.is_none());
    }
    #[test]
    fn selecting_index_preview_needs_explicit_show_more_before_read() {
        let (mut app, commands, events) = app();
        let participant = KeyId::from_bytes([4; 32]);
        let id = EntryId::from_bytes([5; 16]);
        app.unlocked = Some(participant.to_string());
        app.head = "current".into();
        app.entries = vec![id];
        events
            .send(Event::IndexRows {
                head: "current".into(),
                participant,
                rows: BTreeMap::from([(id, preview_row())]),
            })
            .unwrap();
        app.events();
        app.navigate(Leave::Select(id));
        assert!(app.json.is_empty());
        assert!(commands.try_recv().is_err());
        let ctx = app.ctx.clone();
        let mut output = ctx.run_ui(Default::default(), |ui| app.entry_ui(ui));
        let texts: Vec<_> = output
            .shapes
            .iter()
            .filter_map(|shape| match &shape.shape {
                egui::epaint::Shape::Text(text) => Some(text.galley.text()),
                _ => None,
            })
            .collect();
        assert!(texts.contains(&"alice") && texts.contains(&"https://example.test"));
        let position = output
            .shapes
            .iter()
            .find_map(|shape| match &shape.shape {
                egui::epaint::Shape::Text(text) if text.galley.text() == "Show more" => {
                    Some(text.pos + text.galley.size() * 0.5)
                }
                _ => None,
            })
            .unwrap();
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
        assert!(matches!(commands.try_recv(), Ok(Command::Read(selected)) if selected == id));
    }

    #[test]
    fn preview_rejects_old_snapshot_or_participant_and_clears_on_lock() {
        let (mut app, _, events) = app();
        let participant = KeyId::from_bytes([4; 32]);
        let id = EntryId::from_bytes([5; 16]);
        app.unlocked = Some(participant.to_string());
        app.head = "current".into();
        app.entries = vec![id];
        for (head, owner) in [
            ("old", participant),
            ("current", KeyId::from_bytes([6; 32])),
        ] {
            events
                .send(Event::IndexRows {
                    head: head.into(),
                    participant: owner,
                    rows: BTreeMap::from([(id, preview_row())]),
                })
                .unwrap();
        }
        app.events();
        assert!(app.index_rows.is_empty());
        events
            .send(Event::IndexRows {
                head: "current".into(),
                participant,
                rows: BTreeMap::from([(id, preview_row())]),
            })
            .unwrap();
        app.events();
        assert!(app.index_rows.contains_key(&id));
        events
            .send(Event::Wallet {
                path: "synthetic".into(),
                entries: vec![id],
                participants: vec![participant],
                head: "next".into(),
            })
            .unwrap();
        events
            .send(Event::IndexRows {
                head: "current".into(),
                participant,
                rows: BTreeMap::from([(id, preview_row())]),
            })
            .unwrap();
        app.events();
        assert!(app.index_rows.is_empty());
        events
            .send(Event::IndexRows {
                head: "next".into(),
                participant,
                rows: BTreeMap::from([(id, preview_row())]),
            })
            .unwrap();
        app.events();
        assert!(app.index_rows.contains_key(&id));
        app.request_lock();
        assert!(app.index_rows.is_empty());
        events
            .send(Event::IndexRows {
                head: "current".into(),
                participant,
                rows: BTreeMap::from([(id, preview_row())]),
            })
            .unwrap();
        app.events();
        assert!(app.index_rows.is_empty());
    }

    #[test]
    fn attachment_picker_rechecks_owner_revision_draft_and_lock() {
        let (mut app, commands, _) = app();
        app.unlocked = Some("key".into());
        app.new_entry(false);
        let id = app.selected.unwrap();
        app.entries.push(id);
        app.entry_original = Zeroizing::new(app.json.clone());
        app.original_recipients = app.recipients.clone();
        app.entry_digest = Some([7; 32]);
        let pick = Pick::AddFile {
            owner: id,
            digest: [7; 32],
        };
        app.new_file_permit();
        app.entry_digest = Some([8; 32]);
        app.file_picked(pick, "fixture".into());
        assert!(commands.try_recv().is_err());
        app.entry_digest = Some([7; 32]);
        app.new_file_permit();
        app.json.push(' ');
        app.file_picked(pick, "fixture".into());
        assert!(commands.try_recv().is_err());
        app.json.pop();
        app.new_file_permit();
        app.file_picked(pick, "fixture".into());
        assert!(
            matches!(commands.try_recv(), Ok(Command::AddFile(owner, [7, ..], _, _)) if owner == id)
        );
        app.clear_secrets();
        app.file_picked(pick, "fixture".into());
        assert!(commands.try_recv().is_err());
    }

    #[test]
    fn existing_key_creation_waits_for_success_and_uses_selected_pair() {
        let (mut app, commands, events) = app();
        app.screen = Screen::Create;
        app.create_path = Some("/synthetic/new-wallet".into());
        events.send(Event::KeyInspected(vec![0x90, 0x91])).unwrap();
        events.send(Event::Done(Ok(()))).unwrap();
        app.events();
        assert!(!app.provision && app.key_ready());
        assert_eq!((app.encryption_slot, app.signing_slot), (0x90, 0x91));
        app.prepare_selected_key();
        assert!(
            matches!(commands.try_recv(), Ok(Command::UsePreparedKey(slots)) if slots.encryption() == 0x90 && slots.signing() == 0x91)
        );
        assert!(commands.try_recv().is_err());
        events.send(Event::Unlocked("synthetic".into())).unwrap();
        events.send(Event::Done(Ok(()))).unwrap();
        app.events();
        assert!(
            matches!(commands.try_recv(), Ok(Command::Create(path)) if path == std::path::Path::new("/synthetic/new-wallet"))
        );
    }

    #[test]
    fn inspecting_insufficient_slots_requires_provision_and_lock_clears_preparation() {
        let (mut app, commands, events) = app();
        app.screen = Screen::Create;
        events.send(Event::KeyInspected(vec![0x82])).unwrap();
        app.events();
        assert!(app.provision && !app.key_ready());
        app.last_activity = Instant::now() - Duration::from_secs(301);
        app.enforce_idle_lock(Instant::now());
        assert!(matches!(commands.try_recv(), Ok(Command::Lock)));
        assert!(app.inspected_slots.is_none());
        events.send(Event::KeyInspected(vec![0x82, 0x83])).unwrap();
        app.events();
        assert!(app.inspected_slots.is_none());
    }

    #[test]
    fn index_terms_search_accounts_and_scopes_and_clear_on_lock() {
        let (mut app, _, events) = app();
        let id = EntryId::from_bytes([8; 16]);
        app.entries = vec![id];
        events
            .send(Event::SearchTerms(vec![(
                id,
                Zeroizing::new("Alice EXAMPLE.test".into()),
            )]))
            .unwrap();
        app.events();
        app.search = "example.TEST".into();
        assert_eq!(app.visible_entries(), vec![id]);
        app.search = "alice".into();
        assert_eq!(app.visible_entries(), vec![id]);
        app.clear_secrets();
        assert!(app.search_terms.is_empty());
    }

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
    fn access_review_is_bound_to_target_and_discarded_on_navigation_and_lock() {
        let (mut app, commands, events) = app();
        let target = KeyId::from_bytes([7;32]);
        let other = KeyId::from_bytes([8;32]);
        app.screen = Screen::Access;
        app.unlocked = Some(other.to_string());
        app.access_target = Some(target);
        let preview = |target| crate::backend::access::AccessPreview { target, already_granted: 2, new_grants: 3, unavailable: 1 };
        events.send(Event::AccessPreview(preview(other))).unwrap(); app.events();
        assert!(app.access_preview.is_none());
        events.send(Event::AccessPreview(preview(target))).unwrap(); app.events();
        assert_eq!(app.access_preview.as_ref().unwrap().new_grants,3);
        app.leave(Leave::Screen(Screen::Keys));
        assert!(matches!(commands.try_recv().unwrap(),Command::DiscardAccess));
        assert!(app.access_preview.is_none() && app.access_target.is_none());
        events.send(Event::AccessPreview(preview(target))).unwrap(); app.events();
        assert!(app.access_preview.is_none());
        app.screen=Screen::Access; app.access_target=Some(target); app.access_preview=Some(preview(target));
        app.clear_secrets();
        assert!(app.access_preview.is_none() && app.access_target.is_none());
        events.send(Event::AccessPreview(preview(target))).unwrap(); app.events();
        assert!(app.access_preview.is_none());
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
    fn gateway_late_secrets_are_suppressed_on_lock_snapshot_and_cancellation() {
        for scenario in ["lock", "snapshot", "cancel", "expired", "approved"] {
            let (mut app, _, events) = app();
            app.unlocked = Some("synthetic".into());
            let (reply, receive) = mpsc::sync_channel(1);
            let cancelled = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            app.gateway_request = Some(crate::gateway::Request {
                id: 7,
                origin: "https://example.com".into(),
                passkey: None,
                deadline: Instant::now() + Duration::from_secs(90),
                cancelled: cancelled.clone(),
                reply,
            });
            app.gateway_pin = "synthetic PIN".into();
            app.gateway_accounts = Some(vec![]);
            match scenario {
                "lock" => app.clear_secrets(),
                "snapshot" => {
                    events
                        .send(Event::Wallet {
                            path: "synthetic".into(),
                            entries: vec![],
                            participants: vec![],
                            head: "changed".into(),
                        })
                        .unwrap();
                }
                "cancel" => cancelled.store(true, std::sync::atomic::Ordering::Release),
                "expired" => {
                    app.gateway_request.as_mut().unwrap().deadline =
                        Instant::now() - Duration::from_secs(1)
                }
                _ => (),
            }
            events.send(Event::GatewayAccounts(7, vec![])).unwrap();
            events
                .send(Event::GatewayLogin(
                    7,
                    Zeroizing::new("synthetic response".into()),
                ))
                .unwrap();
            app.events();
            assert_eq!(receive.try_recv().is_ok(), scenario == "approved");
            assert!(app.gateway_pin.is_empty() && app.gateway_accounts.is_none());
        }
    }

    #[test]
    fn idle_lock_while_busy_suppresses_secrets_but_keeps_completed_wallet_updates() {
        let (mut app, commands, events) = app();
        let id = EntryId::from_bytes([3; 16]);
        let participant = KeyId::from_bytes([4; 32]);
        app.unlocked = Some("device".into());
        app.busy = true;
        app.private_operation = Some(Some(TouchPolicy::Always));
        app.json = "visible secret".into();
        app.titles
            .insert(id, Zeroizing::new("private title".into()));
        app.participant_names
            .insert(participant, "private name".into());
        app.last_activity = Instant::now() - Duration::from_secs(301);
        app.enforce_idle_lock(Instant::now());
        assert!(matches!(commands.try_recv(), Ok(Command::Lock)));
        assert!(app.json.is_empty() && app.titles.is_empty() && app.unlocked.is_none());
        assert!(app.participant_names.is_empty());
        assert!(app.private_operation.is_none());
        app.enforce_idle_lock(Instant::now());
        assert!(commands.try_recv().is_err());
        for event in [
            Event::Locked,
            Event::PrivateOperation(PrivateOperation::Started(Some(TouchPolicy::Always))),
            Event::Entry(id, Zeroizing::new("late secret".into()), vec![], [0; 32]),
            Event::Titles(vec![(id, Zeroizing::new("late title".into()))]),
            Event::ParticipantNames(BTreeMap::from([(participant, "late private name".into())])),
            Event::Preview(crate::backend::ImportPreview::default()),
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
        assert!(app.private_operation.is_none());
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
    fn deleted_entry_refresh_drops_cached_row_and_rejects_late_details() {
        let (mut app, commands, events) = app();
        let removed = EntryId::from_bytes([5;16]);
        let kept = EntryId::from_bytes([6;16]);
        app.unlocked = Some("device".into());
        app.wallet = Some("wallet".into());
        app.entries = vec![removed,kept];
        app.titles.insert(removed,Zeroizing::new("Deleted".into()));
        app.index_rows.insert(removed,preview_row());
        app.select_entry(removed);
        assert!(app.visible_entries().contains(&removed));
        // No completed save may carry a reread across a subsequent delete.
        app.after_save = Some(removed);
        app.send(Command::Delete(removed));
        assert!(app.after_save.is_none());
        assert!(matches!(commands.try_recv(),Ok(Command::Delete(id)) if id==removed));
        events.send(Event::Wallet {path:"wallet".into(),entries:vec![kept],participants:vec![],head:"new-head".into()}).unwrap();
        events.send(Event::Titles(vec![(removed,Zeroizing::new("Late deleted title".into()))])).unwrap();
        events.send(Event::SearchTerms(vec![(removed,Zeroizing::new("Late deleted username".into()))])).unwrap();
        events.send(Event::Entry(removed,Zeroizing::new("late payload".into()),vec![],[1;32])).unwrap();
        events.send(Event::Done(Ok(()))).unwrap();
        app.events();
        assert_eq!(app.visible_entries(),vec![kept]);
        assert!(!app.titles.contains_key(&removed) && !app.search_terms.contains_key(&removed));
        assert!(app.selected.is_none() && app.json.is_empty() && app.index_rows.is_empty());
        app.select_entry(removed);
        assert!(app.selected.is_none());
        assert!(commands.try_recv().is_err());
    }

    #[test]
    fn failed_delete_without_snapshot_change_keeps_the_existing_entry() {
        let (mut app, commands, events) = app();
        let id = EntryId::from_bytes([5;16]);
        app.entries = vec![id];
        app.titles.insert(id,Zeroizing::new("Keep on failure".into()));
        assert_eq!(app.visible_entries(),vec![id]);
        app.send(Command::Delete(id));
        let _ = commands.try_recv();
        events.send(Event::Done(Err("Signing failed".into()))).unwrap();
        app.events();
        assert_eq!(app.visible_entries(),vec![id]);
        app.select_entry(id);
        assert_eq!(app.selected,Some(id));
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
        let Command::Preview(_, _, Some(password), _, _) = commands.recv().unwrap() else {
            panic!("missing password component")
        };
        assert!(password.is_empty());
        app.import_use_password = false;
        app.preview_import("keyfile-only.kdbx".into());
        assert!(matches!(
            commands.recv().unwrap(),
            Command::Preview(_, _, None, _, _)
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
    fn entry_search_orders_titles_and_finds_encrypted_ids() {
        let (mut app, _, _) = app();
        let a = EntryId::from_bytes([1; 16]);
        let b = EntryId::from_bytes([2; 16]);
        let c = EntryId::from_bytes([3; 16]);
        app.entries = vec![a, b, c];
        app.titles.insert(a, Zeroizing::new("Zulu".into()));
        app.titles.insert(b, Zeroizing::new("alpha".into()));
        assert_eq!(app.visible_entries(), vec![b, a, c]);
        app.search = "  ALP  ".into();
        assert_eq!(app.visible_entries(), vec![b]);
        app.search = "0303".into();
        assert_eq!(app.visible_entries(), vec![c]);
        app.search = "missing".into();
        assert!(app.visible_entries().is_empty());
        app.clear_secrets();
        assert!(app.search.is_empty() && app.titles.is_empty());
        assert_eq!(app.visible_entries(), vec![a, b, c]);
    }

    #[test]
    fn reselect_preserves_edits_and_discard_restores_without_hardware() {
        let (mut app, commands, _) = app();
        app.new_entry(false);
        let id = app.selected.unwrap();
        app.entries.push(id);
        app.entry_original = Zeroizing::new(app.json.clone());
        app.original_recipients = app.recipients.clone();
        app.json.push(' ');
        app.recipients.push(KeyId::from_bytes([5; 32]));
        app.navigate(Leave::Select(id));
        assert!(app.leave_action.is_none());
        assert!(app.dirty());
        let epoch = app.editor_epoch;
        app.navigate(Leave::RevertEntry);
        assert!(app.leave_action.is_some());
        // Confirm discard through the same action the dialog invokes.
        app.leave(app.leave_action.unwrap());
        assert_eq!(app.selected, Some(id));
        assert_eq!(app.json, *app.entry_original);
        assert_eq!(app.recipients, app.original_recipients);
        assert!(!app.dirty());
        assert_ne!(app.editor_epoch, epoch);
        assert!(commands.try_recv().is_err());
        app.new_entry(false);
        app.navigate(Leave::RevertEntry);
        app.leave(app.leave_action.unwrap());
        assert!(app.selected.is_none() && app.json.is_empty());
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
        fn collect<'a>(shape: &'a egui::epaint::Shape, texts: &mut Vec<&'a str>) {
            match shape {
                egui::epaint::Shape::Text(text) => texts.push(text.galley.text()),
                egui::epaint::Shape::Vec(shapes) => {
                    for shape in shapes {
                        collect(shape, texts);
                    }
                }
                _ => (),
            }
        }
        let mut texts = Vec::new();
        for shape in &output.shapes {
            collect(&shape.shape, &mut texts);
        }
        assert!(texts.contains(&"Close details"));
        assert!(texts.contains(&"Password"), "{texts:?}");
        assert!(texts.iter().filter(|text| **text == "Lock").count() >= 2);
    }
    #[test]
    fn import_preview_reveal_state_is_dropped_on_lock_and_navigation() {
        let (mut app, _, _) = app();
        for lock in [true, false] {
            let mut preview = crate::backend::ImportPreview::default();
            preview.entries.push(crate::backend::import_preview::PreviewEntry {
                existing_duplicate: false,
                title: Zeroizing::new("Synthetic".into()), collection: false,
                custom_fields: 0, attachment_count: 0, history_count: 1, fields: Vec::new(),
                history: Zeroizing::new("synthetic secret".into()), raw: Zeroizing::new("synthetic secret".into()),
                expanded: true, reveal_history: true, reveal_raw: true,
            });
            app.preview = Some(preview);
            if lock { app.clear_secrets(); } else { app.leave(Leave::Screen(Screen::Wallet)); }
            assert!(app.preview.is_none());
        }
    }

    #[test]
    fn destination_copy_session_stays_lockable_without_source_session() {
        let (mut app, commands, events) = app();
        app.screen = Screen::Copy;
        app.unlocked = Some("source".into());
        let target = kagitaba_core::crypto::SoftwareIdentity::from_bytes(&[7;32]).unwrap().public_key().id();
        let preview = || crate::backend::CopyPreview {
            path: "destination".into(), participants: vec![target],
            review: crate::backend::ImportPreview::default(), requires_unlock: false,
            default_recipient: Some(target),
        };
        events.send(Event::Locked).unwrap();
        events.send(Event::CopyPreview(preview())).unwrap();
        app.events();
        assert!(app.unlocked.is_none() && app.copy_active && app.copy_preview.is_some());
        assert_eq!(app.copy_recipients, vec![target]);
        app.send(Command::CopyEntries(vec![target], true));
        assert!(app.copy_preview.is_none() && app.copy_active);
        assert!(matches!(commands.try_recv(), Ok(Command::CopyEntries(_, true))));
        app.last_activity = Instant::now() - Duration::from_secs(301);
        app.enforce_idle_lock(Instant::now());
        assert!(app.locking && !app.copy_active && app.copy_recipients.is_empty());
        assert!(matches!(commands.try_recv(), Ok(Command::Lock)));
        events.send(Event::CopyPreview(preview())).unwrap();
        app.events();
        assert!(app.copy_preview.is_none() && !app.copy_active);
    }

    #[test]
    fn each_import_review_defaults_to_skipping_existing_duplicates() {
        let (mut app, _, events) = app();
        app.import_skip_duplicates = false;
        events.send(Event::Preview(crate::backend::ImportPreview::default())).unwrap();
        app.events();
        assert!(app.import_skip_duplicates);
    }

}
