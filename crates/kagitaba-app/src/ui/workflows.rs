use super::*;

impl App {
    #[cfg(feature = "smoke")]
    pub(super) fn smoke(ctx: egui::Context, scene: &str) -> Self {
        let (tx, _) = mpsc::channel();
        let (_, rx) = mpsc::channel();
        let mut app = Self::state(ctx, tx, rx);
        app.preferences.remember = true;
        app.preferences.favorites = vec!["/home/example/Wallets/Personal".into()];
        app.preferences.recent = vec![
            "/home/example/Wallets/Travel".into(),
            "/media/backup/Family".into(),
        ];
        if scene == "home" {
            return app;
        }
        app.wallet = Some("/home/example/Wallets/Personal".into());
        app.screen = Screen::Wallet;
        let participant = KeyId::from_bytes([7; 32]);
        app.participants = vec![participant];
        app.participant_names
            .insert(participant, "Everyday YubiKey".into());
        app.unlocked = Some(participant.to_string());
        let id = EntryId::from_bytes([1; 16]);
        app.selected = Some(id);
        app.recipients = vec![participant];
        app.json = serde_json::json!({
            "format":"kagitaba-cxf", "version":1, "cxfVersion":{"major":1,"minor":0}, "kind":"item",
            "entity":{"id":data_encoding::BASE64URL_NOPAD.encode(id.as_bytes()),"title":"Example account",
                "credentials":[{"type":"basic-auth",
                    "username":{"fieldType":"string","value":"alex@example.test"},
                    "password":{"fieldType":"concealed-string","value":"synthetic-example-only"}}]}
        }).to_string();
        app.entry_original = Zeroizing::new(app.json.clone());
        app.original_recipients = app.recipients.clone();
        app.entries = vec![
            id,
            EntryId::from_bytes([2; 16]),
            EntryId::from_bytes([3; 16]),
        ];
        app.head = "0123456789abcdef0123456789abcdef01234567".into();
        app.remote_configured = Some(true);
        app.remote_status = Some(crate::remote::Status {
            head: "fedcba9876543210fedcba9876543210fedcba98".into(),
            relation: kagitaba_store::HistoryRelation {
                ahead: 1,
                behind: 2,
            },
        });
        app.remote_checked = Some(Instant::now());
        for (id, title) in
            app.entries
                .iter()
                .zip(["Example account", "Home network", "Travel notes"])
        {
            app.titles.insert(*id, Zeroizing::new(title.to_owned()));
        }
        match scene {
            "urls" => {
                let mut value: serde_json::Value = serde_json::from_str(&app.json).unwrap();
                value["entity"]["scope"]["urls"] = serde_json::json!([
                    "https://primary.example.test", "https://accounts.example.test/login", "https://portal.example.test/a/long/path?with=parameters", "https://mail.example.test"
                ]);
                app.json = serde_json::to_string(&value).unwrap();
                app.entry_original = Zeroizing::new(app.json.clone());
            }
            "collections" | "collection-selected" | "collection-unfiled" => {
                app.selected = None;
                app.json.clear();
                app.entry_original.clear();
                for (index, entry) in app.entries.iter().enumerate() {
                    app.index_rows.insert(*entry, kagitaba_store::index::Row {
                        digest:[1;32],grant_digest:[2;32],title:app.titles[entry].to_string(),
                        kind:kagitaba_cxf::PayloadKind::Item,collection:None,
                        usernames:vec![format!("account{}@example.test",index+1)],scopes:vec![],password:true,totp:false,passkey:false,
                    });
                }
                let owner = EntryId::from_bytes([4;16]);
                app.entries.push(owner);
                app.titles.insert(owner,Zeroizing::new("Personal".into()));
                app.index_rows.insert(owner,kagitaba_store::index::Row {
                    digest:[3;32],grant_digest:[4;32],title:"Personal".into(),kind:kagitaba_cxf::PayloadKind::Collection,
                    collection:Some(kagitaba_store::index::CollectionNode {
                        id:owner.as_bytes().to_vec(),title:"Personal".into(),entries:vec![id],unresolved_links:1,children:vec![kagitaba_store::index::CollectionNode {
                            id:vec![8],title:"Home".into(),entries:vec![EntryId::from_bytes([2;16])],children:vec![],unresolved_links:0,
                        }],
                    }),usernames:vec![],scopes:vec![],password:false,totp:false,passkey:false,
                });
                if scene == "collection-selected" { app.select_collection(Some((owner,vec![])),false); }
                if scene == "collection-unfiled" { app.select_collection(None,true); }
            }
            "passkey" => {
                use p256::pkcs8::EncodePrivateKey;
                let key = p256::SecretKey::from_slice(&[7; 32]).unwrap().to_pkcs8_der().unwrap();
                let mut value: serde_json::Value = serde_json::from_str(&app.json).unwrap();
                value["entity"]["credentials"] = serde_json::json!([{
                    "type":"passkey", "rpId":"example.test", "username":"alex@example.test",
                    "userDisplayName":"Alex Example", "credentialId":"c3ludGhldGljLWNyZWRlbnRpYWw",
                    "userHandle":"c3ludGhldGljLWhhbmRsZQ", "key":data_encoding::BASE64URL_NOPAD.encode(key.as_bytes()),
                    "kagitabaBackupFlags":{"eligible":true,"state":false}
                }]);
                app.json = serde_json::to_string(&value).unwrap();
                app.entry_original = Zeroizing::new(app.json.clone());
            }
            "custom-fields" => {
                let mut value: serde_json::Value = serde_json::from_str(&app.json).unwrap();
                value["entity"]["credentials"] = serde_json::json!([{"type":"custom-fields","fields":[
                    {"label":"Pin","fieldType":"string","value":"synthetic-hidden-pin"},
                    {"label":"Reference","fieldType":"string","value":"EXAMPLE-42"},
                    {"label":"Enabled","fieldType":"boolean","value":"true"}
                ]}]);
                app.json = serde_json::to_string(&value).unwrap();
                app.entry_original = Zeroizing::new(app.json.clone());
            }
            "attachments" => {
                let payload = kagitaba_cxf::Payload::new(id, kagitaba_cxf::PayloadKind::Item, &serde_json::to_vec(&serde_json::json!({
                    "id":data_encoding::BASE64URL_NOPAD.encode(id.as_bytes()), "title":"Project documents", "credentials":[]
                })).unwrap()).unwrap();
                let (payload, _) = kagitaba_cxf::attachments::add(
                    &payload,
                    "Example.txt",
                    b"Synthetic attachment fixture",
                    &mut rand::rngs::SysRng,
                )
                .unwrap();
                app.json = String::from_utf8(payload.to_json().unwrap().to_vec()).unwrap();
                app.entry_original = Zeroizing::new(app.json.clone());
                app.entry_digest = Some([1; 32]);
            }
            "index-preview" => {
                app.json.zeroize();
                app.entry_original.zeroize();
                app.index_rows.insert(
                    id,
                    kagitaba_store::index::Row {
                        digest: [1; 32],
                        grant_digest: [2; 32],
                        title: "Example account".into(),
                        kind: kagitaba_cxf::PayloadKind::Item,
                        collection: None,
                        usernames: vec!["alex@example.test".into()],
                        scopes: vec![
                            "https://example.test".into(),
                            "example.test".into(),
                            "android:{\"bundleId\":\"test.example\"}".into(),
                        ],
                        password: true,
                        totp: true,
                        passkey: false,
                    },
                );
            }
            "import" => app.screen = Screen::Import,
            "review" => {
                app.screen = Screen::Import;
                app.preview = Some(crate::backend::ImportPreview {
                    entries: Vec::new(),
                    imported_files: 0,
                    existing_duplicates: 0,
                    duplicate_differences: Default::default(),
                    unavailable_entries: 0,
                    report: kagitaba_cxf::ImportReport {
                        items: 3, root_collections: 1, accounts: 1,
                        opaque_credentials: 3,
                        opaque_credential_types: BTreeMap::from([("credit-card".into(), 2), ("ssh-key".into(), 1)]),
                        ..Default::default()
                    },
                    warnings: crate::backend::ImportWarnings {
                        omitted: BTreeMap::from([("Items with attachment bytes not imported", 1)]),
                        ..Default::default()
                    },
                });
            }
            "import-item" | "import-item-details" | "import-item-history" | "import-warnings" => {
                app.screen = Screen::Import;
                let source = serde_json::json!({"encrypted":false,"folders":[],"items":[{
                    "id":"synthetic-account","type":1,"name":"Example account","notes":"Synthetic account note",
                    "login":{"username":"alex@example.test","password":"synthetic-current-password","uris":[{"uri":"https://example.test","match":null}]},
                    "fields":[{"name":"Support reference","type":0,"value":"EXAMPLE-42"},{"name":"Recovery phrase","type":1,"value":"synthetic-recovery-value"}],
                    "passwordHistory":[{"password":"synthetic-previous-password","lastUsedDate":"2025-01-01T00:00:00Z"}],
                    "futureField":{"example":"preserved vendor data"}
                }]});
                let conversion = kagitaba_cxf::bitwarden::from_json(&serde_json::to_vec(&source).unwrap()).unwrap();
                let plan = conversion.document().plan_import(&kagitaba_core::wallet::Wallet::default(), &mut rand::rngs::SysRng).unwrap();
                let mut preview = crate::backend::ImportPreview::from_plan(&plan, Default::default()).unwrap();
                let (payload, _) = kagitaba_cxf::attachments::add(&plan.entries()[0], "Example.txt", b"Synthetic imported file", &mut rand::rngs::SysRng).unwrap();
                preview.entries[0] = crate::backend::import_preview::PreviewEntry::from_payload(&payload).unwrap();
                preview.imported_files = 1;
                if scene != "import-item" {
                    for entry in &mut preview.entries {
                        entry.expanded = true;
                        entry.reveal_history = scene == "import-item-history";
                    }
                }
                if scene == "import-warnings" {
                    preview.existing_duplicates = 1;
                    preview.unavailable_entries = 2;
                    preview.warnings.retained.insert("Unsupported passkeys: source data only", 1);
                    preview.warnings.details.push(crate::backend::ImportDiagnostic {
                        source_id: Zeroizing::new(String::new()), entry_index: Some(0),
                        detail: kagitaba_cxf::WarningDetail {
                            reason: "The original passkey backup flag is missing.",
                            field: Some("KPEX_PASSKEY_FLAG_BE"),
                            action: "Confirm the original registration flag in the source app. Do not guess its value.",
                        },
                    });
                    preview.entries[0].expanded = false;
                }
                app.preview = Some(preview);
                app.import_recipients = vec![participant];
            }
            "generator" => app.tools.open_generator(None),
            "totp" => app.tools.totp = true,
            "access" => {
                app.screen = Screen::Access;
                app.access_target = Some(participant);
                app.access_preview = Some(crate::backend::access::AccessPreview { target: participant, already_granted: 3, new_grants: 12, unavailable: 1 });
            }
            "duplicates" => {
                app.screen = Screen::Duplicates;
                app.duplicate_preview = Some(crate::backend::duplicates::DuplicatePreview {
                    groups: vec![crate::backend::duplicates::DuplicateGroup {
                        survivor: id, removed: vec![EntryId::from_bytes([2;16])], title: Zeroizing::new("Example account".into()), recipient_count: 2,
                    }], unavailable_entries: 1,
                });
            }
            "copy" | "copy-review" | "copy-unlock" => {
                app.screen = Screen::Copy;
                app.copy_selection.insert(id);
                app.index_rows.insert(id, kagitaba_store::index::Row {
                    digest: [1;32], grant_digest: [2;32], title: "Example account".into(), kind: kagitaba_cxf::PayloadKind::Item, collection: None,
                    usernames: vec!["alex@example.test".into()], scopes: vec![], password: true, totp: false, passkey: false,
                });
                if scene != "copy" {
                    app.copy_active = true;
                    app.copy_recipients = vec![participant];
                    app.copy_preview = Some(crate::backend::CopyPreview {
                        path: "/home/example/Wallets/Family".into(), participants: vec![participant],
                        review: crate::backend::ImportPreview { existing_duplicates: 1, ..Default::default() },
                        requires_unlock: scene == "copy-unlock", default_recipient: Some(participant),
                    });
                }
            }
            "keys" => app.screen = Screen::Keys,
            "transfer" => app.screen = Screen::Transfer,
            "unlock" => {
                app.clear_secrets();
                app.screen = Screen::Unlock;
                app.pin = "123456".into();
            }
            "create" | "provision" | "create-ready-new" | "create-created" | "enrollment" => {
                app.clear_secrets();
                app.provision = scene == "provision";
                app.wallet = None;
                app.create_path = Some("/home/example/Wallets/New wallet".into());
                app.screen = if scene == "enrollment" {
                    Screen::Enrollment
                } else {
                    Screen::Create
                };
                if matches!(scene, "create-ready-new" | "create-created") {
                    app.inspected_slots = Some(vec![]);
                    app.provision = true;
                    app.management = "synthetic".into();
                    app.consent = scene == "create-ready-new";
                }
                if scene == "create-created" {
                    app.unlocked = Some(participant.to_string());
                }
            }
            "touch" => {
                app.busy = true;
                app.private_operation = Some(Some(TouchPolicy::Always));
            }
            _ => {}
        }
        app
    }

    pub(super) fn save_preferences(&mut self) {
        if let Some(path) = &self.preferences_path {
            self.preference_error = self
                .preferences
                .save(path)
                .err()
                .map(|e| format!("Could not save wallet list: {e}"));
        }
    }

    pub(super) fn dirty(&self) -> bool {
        self.name_edit.is_some()
            || self.selected.is_some()
                && (!self.json.is_empty() && self.json != *self.entry_original
                    || self.recipients != self.original_recipients)
    }

    pub(super) fn navigate(&mut self, action: Leave) {
        if matches!(action, Leave::Select(id) if self.selected == Some(id)) {
            return;
        }
        if self.dirty() {
            self.leave_action = Some(action);
        } else {
            self.leave(action);
        }
    }

    pub(super) fn leave(&mut self, action: Leave) {
        if matches!(action, Leave::RevertEntry) {
            self.tools = Default::default();
            self.leave_action = None;
            if self.selected.is_some_and(|id| self.entries.contains(&id)) {
                self.json.zeroize();
                self.json = self.entry_original.to_string();
                self.recipients = self.original_recipients.clone();
                self.reveal = false;
                self.delete_confirm = false;
                self.editor_epoch = self.editor_epoch.wrapping_add(1);
                self.ctx.memory_mut(|m| m.data.clear());
            } else {
                self.reset_entry();
            }
            return;
        }
        if self.screen == Screen::Access { self.send(Command::DiscardAccess); }
        self.access_preview = None;
        self.access_target = None;
        self.name_edit = None;
        self.reset_entry();
        self.leave_action = None;
        match action {
            Leave::Select(id) => {
                self.select_entry(id);
            }
            Leave::New(collection) => self.new_entry(collection),
            Leave::Screen(screen) => {
                if self.screen == Screen::Import {
                    self.send(Command::DiscardImport);
                }
                if self.screen == Screen::Copy { self.send(Command::DiscardCopy); }
                self.copy_preview = None;
                self.copy_complete = false;
                self.copy_active = false;
                self.copy_recipients.clear();
                if self.screen == Screen::Duplicates { self.send(Command::DiscardDuplicates); }
                self.duplicate_preview = None;
                self.screen = screen;
                self.consent = false;
                self.revoke_confirm = false;
                self.provision = true;
                self.preview = None;
                self.import_complete = false;
                self.import_password.zeroize();
                self.import_recipients.clear();
                self.participant_preview = None;
                self.pin.zeroize();
                self.management.zeroize();
            }
            Leave::Close => {
                self.clear_secrets();
                self.locking = true;
                self.send(Command::Close);
            }
            Leave::DismissEntry | Leave::RevertEntry => {}
        }
    }

    pub(super) fn shell(&mut self, ui: &mut egui::Ui) {
        let narrow = ui.available_width() < 780.0;
        if narrow {
            ui.label(egui::RichText::new("K A G I T A B A").color(theme::AQUA).monospace().size(18.0));
        }
        ui.horizontal_wrapped(|ui| {
            if !narrow { ui.heading(
                egui::RichText::new("K A G I T A B A")
                    .color(theme::AQUA)
                    .monospace()
                    .size(18.0),
            ); }
            if !narrow && let Some(path) = &self.wallet {
                ui.add_sized(
                    [180.0, 36.0],
                    egui::Label::new(egui::RichText::new(wallet_name(path)).size(19.0).strong()).truncate(),
                )
                .on_hover_text(path.display().to_string());
            }
            if !narrow {
                self.remote_ui(ui);
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if self.screen != Screen::Home
                    && ui
                        .add_enabled(
                            !self.busy,
                            egui::Button::new(egui::RichText::new("×").color(theme::ERROR)),
                        )
                        .on_hover_text("Close wallet")
                        .clicked()
                {
                    self.navigate(Leave::Close);
                }
                if let Some(path) = self.wallet.clone() {
                    let favorite = self.preferences.favorites.contains(&path);
                    if ui
                        .button(
                            egui::RichText::new(if favorite { "★" } else { "☆" })
                                .color(theme::AQUA),
                        )
                        .on_hover_text(if favorite {
                            "Remove from favorites"
                        } else {
                            "Add to favorites"
                        })
                        .clicked()
                    {
                        self.preferences.toggle_favorite(&path);
                        self.save_preferences();
                    }
                }
                ui.menu_button("Tools", |ui| {
                    if ui.add_enabled(self.unlocked.is_some(), egui::Button::new("Manage access…")).clicked() {
                        self.navigate(Leave::Screen(Screen::Access));
                        ui.close();
                    }
                    if ui.add_enabled(self.unlocked.is_some(), egui::Button::new("Copy to wallet…")).clicked() {
                        self.copy_selection = self.selected.into_iter().collect();
                        self.navigate(Leave::Screen(Screen::Copy));
                        ui.close();
                    }
                    if ui.add_enabled(self.unlocked.is_some(), egui::Button::new("Delete duplicates…")).clicked() {
                        self.navigate(Leave::Screen(Screen::Duplicates));
                        ui.close();
                    }
                    if ui.button("Password generator").clicked() {
                        self.tools.open_generator(None);
                        ui.close();
                    }
                });
                if (self.unlocked.is_some() || self.copy_active)
                    && ui
                        .add_enabled(!self.locking, egui::Button::new("Lock"))
                        .clicked()
                {
                    self.request_lock();
                }
                if !matches!(self.screen, Screen::Home | Screen::Wallet | Screen::Unlock)
                    && self.wallet.is_some()
                    && ui
                        .add_enabled(!self.busy, egui::Button::new("Back"))
                        .clicked()
                {
                    self.navigate(Leave::Screen(Screen::Wallet));
                }
            });
        });
        if narrow && self.wallet.is_some() {
            ui.horizontal_wrapped(|ui| {
                if let Some(path) = &self.wallet {
                    ui.add_sized(
                        [120.0, 36.0],
                        egui::Label::new(egui::RichText::new(wallet_name(path)).size(19.0).strong()).truncate(),
                    )
                    .on_hover_text(path.display().to_string());
                }
                self.remote_ui(ui);
            });
        }
        ui.separator();
        self.progress_ui(ui);
        if let Some(error) = &self.preference_error {
            ui.colored_label(theme::ERROR, error);
        }
        ui.add_enabled_ui(
            !self.busy && self.leave_action.is_none() && self.trust.is_none(),
            |ui| match self.screen {
                Screen::Home => self.home(ui),
                Screen::Wallet => self.workspace(ui),
                screen => {
                    let scroll = egui::ScrollArea::vertical()
                        .scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::VisibleWhenNeeded)
                        .id_salt("workflow");
                    #[cfg(feature = "smoke")]
                    let scroll = if std::env::var("KAGITABA_SMOKE_SCENE").as_deref() == Ok("import-item-history") {
                        scroll.vertical_scroll_offset(850.0)
                    } else { scroll };
                    scroll.show(ui, |ui| {
                            ui.set_max_width(ui.available_width().min(720.0));
                            theme::surface().show(ui, |ui| match screen {
                                Screen::Create => self.create(ui),
                                Screen::Enrollment => self.enrollment(ui),
                                Screen::Unlock => {
                                    ui.heading("Unlock your wallet");
                                    self.hardware_ui(ui);
                                }
                                Screen::Import => {
                                    if self.unlocked.is_some() {
                                        self.import_ui(ui);
                                    } else {
                                        self.unlock_prompt(ui);
                                    }
                                }
                                Screen::Keys => self.keys_ui(ui),
                                Screen::Transfer => self.transfer_ui(ui),
                                Screen::Duplicates => self.duplicates_ui(ui),
                                Screen::Access => self.access_ui(ui),
                                Screen::Copy => self.copy_ui(ui),
                                _ => {}
                            });
                        });
                }
            },
        );
        self.trust_modal(ui.ctx());
        if self.screen == Screen::Wallet
            && !self.tools.generator
            && !self.tools.totp
            && ui.available_width() < 1100.0
            && self.selected.is_some()
            && self.leave_action.is_none()
        {
            self.entry_modal(ui.ctx());
        }
        if let Some(action) = self.leave_action {
            egui::Modal::new(egui::Id::new("discard-edits"))
                .frame(theme::surface())
                .show(ui.ctx(), |ui| {
                    ui.set_max_width((ui.ctx().content_rect().width() - 80.0).min(420.0));
                    ui.heading("Discard unsaved changes?");
                    theme::caption(ui, "Your edits have not been saved to the wallet.");
                    if ui.button("Keep editing").clicked() {
                        self.leave_action = None;
                    }
                    if ui.button("Discard changes & continue").clicked() {
                        self.leave(action);
                    }
                    if self.unlocked.is_some() && ui.button("Lock & clear secrets").clicked() {
                        self.request_lock();
                    }
                });
        }
    }

    fn home(&mut self, ui: &mut egui::Ui) {
        let margin = ((ui.available_width() - 600.0) / 2.0).max(0.0);
        ui.add_space((ui.available_height() * 0.08).min(48.0));
        let height = ui.available_height();
        let width = ui.available_width().min(600.0);
        ui.horizontal(|ui| {
            ui.add_space(margin);
            ui.allocate_ui_with_layout(
                egui::vec2(width, height),
                egui::Layout::top_down(egui::Align::Min),
                |ui| {
                    ui.set_width(width);
                    ui.heading("Wallets");
                    ui.add_space(14.0);
                    ui.horizontal_wrapped(|ui| {
                        if theme::primary(ui, "Open wallet…").clicked() {
                            self.pick(Pick::Open);
                        }
                        if ui.button("Create wallet…").clicked() {
                            self.screen = Screen::Create;
                            self.send(Command::Scan);
                        }
                        if ui.button("Create enrollment bundle…").clicked() {
                            self.screen = Screen::Enrollment;
                            self.send(Command::Scan);
                        }
                    });
                    ui.add_space(12.0);
                    let mut remember = self.preferences.remember;
                    if ui
                        .checkbox(&mut remember, "Remember opened wallets")
                        .changed()
                    {
                        self.preferences.set_remember(remember);
                        self.save_preferences();
                    }
                    egui::ScrollArea::vertical()
                            .scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::VisibleWhenNeeded)
                        .id_salt("saved-wallets")
                        .show(ui, |ui| {
                            if !self.preferences.favorites.is_empty() {
                                ui.add_space(12.0);
                                ui.heading(egui::RichText::new("Favorites").size(20.0));
                                for path in self.preferences.favorites.clone() {
                                    self.wallet_row(ui, path, true);
                                }
                            }
                            if self.preferences.remember {
                                ui.add_space(12.0);
                                ui.heading(egui::RichText::new("Recent wallets").size(20.0));
                                if self.preferences.recent.is_empty() {
                                    ui.colored_label(
                                        theme::MUTED,
                                        "Wallets you open will appear here.",
                                    );
                                }
                                for path in self.preferences.recent.clone() {
                                    self.wallet_row(ui, path, false);
                                }
                            }
                        });
                },
            );
        });
    }

    fn wallet_row(&mut self, ui: &mut egui::Ui, path: PathBuf, favorite: bool) {
        ui.push_id(&path, |ui| {
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 0.0;
                let width = (ui.available_width() - 88.0).max(60.0);
                let mut label = egui::text::LayoutJob::default();
                label.append(&wallet_name(&path), 0.0, egui::TextFormat {
                    font_id: egui::FontId::proportional(16.0), color: theme::INK,
                    ..Default::default()
                });
                label.append(&format!("\n{}", path.display()), 0.0, egui::TextFormat {
                    font_id: egui::FontId::monospace(12.0), color: theme::MUTED,
                    ..Default::default()
                });
                label.wrap.max_width = (width - 28.0).max(1.0);
                label.wrap.max_rows = 2;
                let label = ui.fonts_mut(|fonts| fonts.layout_job(label));
                if ui
                    .add_sized([width, 60.0], egui::Button::new("").left_text(label))
                    .on_hover_text(path.display().to_string())
                    .clicked()
                {
                    self.send(Command::Open(path.clone(), None));
                }
                if ui
                    .add_sized(
                        [44.0, 60.0],
                        egui::Button::new(
                            egui::RichText::new(if favorite { "★" } else { "☆" })
                                .color(theme::AQUA),
                        ),
                    )
                    .on_hover_text(if favorite {
                        "Remove from favorites"
                    } else {
                        "Add to favorites"
                    })
                    .clicked()
                {
                    self.preferences.toggle_favorite(&path);
                    self.save_preferences();
                }
                if ui
                    .add_sized(
                        [44.0, 60.0],
                        egui::Button::new(egui::RichText::new("×").color(theme::ERROR)),
                    )
                    .on_hover_text("Remove saved location; keep wallet files")
                    .clicked()
                {
                    self.preferences.remove(&path);
                    self.save_preferences();
                }
            });
        });
    }

    fn create(&mut self, ui: &mut egui::Ui) {
        ui.heading("Create wallet");
        theme::caption(ui, "Location");
        let mut location = self
            .create_path
            .as_ref()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 0.0;
            let width = (ui.available_width() - 48.0).max(100.0);
            if ui
                .add_sized([width, 36.0], egui::TextEdit::singleline(&mut location))
                .changed()
            {
                self.create_path = (!location.is_empty()).then(|| PathBuf::from(&location));
            }
            if ui
                .add_sized([48.0, 36.0], egui::Button::new("📁"))
                .on_hover_text("Choose wallet location")
                .clicked()
            {
                self.pick(Pick::Create);
            }
        });
        self.hardware_ui(ui);
        ui.add_enabled_ui(self.key_ready() && self.create_path.is_some(), |ui| {
            if theme::primary(ui, "Create wallet").clicked()
                && let Some(path) = self.create_path.clone()
            {
                if self.unlocked.is_some() {
                    self.send(Command::Create(path));
                } else {
                    self.prepare_selected_key();
                }
            }
        });
    }

    fn enrollment(&mut self, ui: &mut egui::Ui) {
        ui.heading("Create enrollment bundle");
        self.hardware_ui(ui);
        ui.add_enabled_ui(self.key_ready(), |ui| {
            if theme::primary(ui, "Export enrollment bundle…").clicked() {
                if self.unlocked.is_some() {
                    self.pick(Pick::ExportParticipant);
                } else {
                    self.prepare_selected_key();
                }
            }
        });
    }

    pub(super) fn key_ready(&self) -> bool {
        self.unlocked.is_some()
            || (!self.provision
                && self.inspected_slots.as_ref().is_some_and(|slots| {
                    slots.contains(&self.encryption_slot) && slots.contains(&self.signing_slot)
                })
                && self.encryption_slot != self.signing_slot)
    }

    pub(super) fn prepare_selected_key(&mut self) {
        if let Ok(slots) = kagitaba_device::Slots::new(self.encryption_slot, self.signing_slot) {
            self.use_prepared = true;
            self.send(Command::UsePreparedKey(slots));
        }
    }

    fn unlock_prompt(&mut self, ui: &mut egui::Ui) {
        ui.heading("Wallet locked");
        theme::caption(ui, "Unlock your key to view credentials and make changes.");
        if theme::primary(ui, "Unlock…").clicked() {
            self.screen = Screen::Unlock;
            self.send(Command::Scan);
        }
    }

    fn workspace(&mut self, ui: &mut egui::Ui) {
        ui.horizontal_wrapped(|ui| {
            if ui
                .add_enabled(self.unlocked.is_some(), egui::Button::new("Import…"))
                .clicked()
            {
                self.navigate(Leave::Screen(Screen::Import));
            }
            if ui.button("Keys & access").clicked() {
                self.navigate(Leave::Screen(Screen::Keys));
            }
            if ui.button("Backups & updates").clicked() {
                self.navigate(Leave::Screen(Screen::Transfer));
            }
        });
        if self.unlocked.is_none() {
            self.unlock_prompt(ui);
        }
        ui.separator();
        let width = ui.available_width();
        if width >= 680.0 {
            let height = ui.available_height();
            ui.horizontal_top(|ui| {
                ui.allocate_ui_with_layout(egui::vec2(190.0, height), egui::Layout::top_down(egui::Align::Min), |ui| self.collection_tree(ui));
                ui.separator();
                let list_width = if width >= 1100.0 { 300.0 } else { ui.available_width() };
                ui.allocate_ui_with_layout(egui::vec2(list_width, height), egui::Layout::top_down(egui::Align::Min), |ui| self.entry_list(ui));
                if width >= 1100.0 {
                    ui.separator();
                    ui.allocate_ui_with_layout(egui::vec2(ui.available_width(), height), egui::Layout::top_down(egui::Align::Min), |ui| {
                        egui::ScrollArea::vertical().id_salt("entry-detail").show(ui, |ui| {
                            ui.set_min_width((ui.available_width() - 1.0).max(0.0));
                            theme::surface().show(ui, |ui| { ui.set_min_width(ui.available_width()); self.entry_ui(ui); });
                        });
                    });
                }
            });
        } else {
            egui::CollapsingHeader::new("Collections").default_open(true).show(ui, |ui| {
                ui.scope(|ui| { ui.set_max_height(180.0); self.collection_tree(ui); });
            });
            ui.separator();
            self.entry_list(ui);
        }
    }

    fn progress_ui(&self, ui: &mut egui::Ui) {
        const MESSAGES: [&str; 4] = [
            "Waiting for YubiKey confirmation — touch the key when it flashes.",
            "YubiKey operation pending — touch if it flashes; a recent touch may still be cached.",
            "Waiting for the YubiKey — no touch required by this slot.",
            "YubiKey operation pending — touch the key if it flashes (policy unavailable).",
        ];
        if self.busy || self.private_operation.is_some() {
            let message = match self.private_operation {
                Some(Some(TouchPolicy::Always)) => MESSAGES[0],
                Some(Some(TouchPolicy::Cached)) => MESSAGES[1],
                Some(Some(TouchPolicy::Never)) => MESSAGES[2],
                Some(_) => MESSAGES[3],
                None => &self.status,
            };
            // Private commands can start/finish repeatedly during one worker job.
            // Reserve the same space for every policy, including wrapped text,
            // so those notifications don't move the controls below the banner.
            let text_width =
                (ui.available_width() - 20.0 - ui.spacing().item_spacing.x).max(1.0);
            let font = egui::TextStyle::Body.resolve(ui.style());
            let height = MESSAGES.iter().chain(std::iter::once(&message)).fold(
                36.0_f32,
                |height, text| {
                    height.max(
                        ui.painter()
                            .layout((*text).into(), font.clone(), theme::INK, text_width)
                            .size()
                            .y,
                    )
                },
            );
            ui.allocate_ui_with_layout(
                egui::vec2(ui.available_width(), height),
                egui::Layout::left_to_right(egui::Align::Center),
                |ui| {
                    ui.add(egui::Spinner::new().size(20.0));
                    let color = if self.private_operation.is_some() {
                        theme::AQUA
                    } else {
                        theme::INK
                    };
                    ui.add(egui::Label::new(egui::RichText::new(message).color(color)).wrap());
                },
            );
        } else if !self.status.is_empty() {
            ui.label(&self.status);
        }
    }
    fn entry_modal(&mut self, ctx: &egui::Context) {
        let id = egui::Id::new("entry-detail-modal");
        let size = egui::vec2(
            (ctx.content_rect().width() - 64.0).clamp(240.0, 640.0),
            (ctx.content_rect().height() - 80.0).max(250.0),
        );
        let modal = egui::Modal::new(id)
            .area(egui::Modal::default_area(id).default_size(size))
            .frame(theme::surface())
            .show(ctx, |ui| {
                ui.set_width((ctx.content_rect().width() - 64.0).clamp(240.0, 640.0));
                ui.set_height(size.y - 38.0);
                // Lock remains available even while this modal owns input.
                ui.horizontal(|ui| {
                    if ui
                        .add_enabled(!self.busy, egui::Button::new("Close details"))
                        .clicked()
                    {
                        self.navigate(Leave::DismissEntry);
                    }
                    if self.unlocked.is_some() && ui.button("Lock").clicked() {
                        self.request_lock();
                    }
                });
                self.progress_ui(ui);
                egui::ScrollArea::vertical()
                            .scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::VisibleWhenNeeded)
                    .id_salt("modal-details")
                    .auto_shrink([false, false])
                    .max_height(ui.available_height().max(100.0))
                    .show(ui, |ui| {
                        ui.add_enabled_ui(!self.busy, |ui| self.entry_ui(ui));
                    });
            });
        if modal.should_close() && !self.busy {
            self.navigate(Leave::DismissEntry);
        }
    }

    fn trust_modal(&mut self, ctx: &egui::Context) {
        if let Some((path, fingerprint)) = self.trust.clone() {
            egui::Modal::new(egui::Id::new("wallet-trust")).frame(theme::surface()).show(ctx, |ui| {
                ui.set_max_width((ctx.content_rect().width() - 80.0).min(520.0));
                ui.heading("Verify this wallet");
                ui.label(path.display().to_string());
                theme::caption(ui, "First open: compare this signing fingerprint with a trusted device or backup record.");
                ui.monospace(&fingerprint);
                ui.add_enabled_ui(!self.busy, |ui| {
                    if theme::primary(ui, "Trust signer & open wallet").clicked() {
                        self.trust = None;
                        self.send(Command::Open(path, Some(fingerprint)));
                    }
                    if ui.button("Cancel").clicked() { self.trust = None; }
                });
            });
        }
    }
}

fn wallet_name(path: &std::path::Path) -> String {
    path.file_name()
        .unwrap_or(path.as_os_str())
        .to_string_lossy()
        .into_owned()
}

#[cfg(test)]
mod progress_tests {
    use super::*;

    #[test]
    fn progress_has_one_message_and_stable_geometry_across_private_commands() {
        for width in [440.0, 855.0, 1400.0] {
            let (tx, _) = mpsc::channel();
            let (_, rx) = mpsc::channel();
            let ctx = egui::Context::default();
            theme::install(&ctx);
            let mut app = App::state(ctx.clone(), tx, rx);
            app.busy = true;
            app.status = "Working…".into();
            let mut baseline = None;
            for policy in [None, Some(Some(TouchPolicy::Cached)), Some(Some(TouchPolicy::Always)), Some(Some(TouchPolicy::Never)), Some(None), None] {
                app.private_operation = policy;
                for frame in 0..4 {
                    let mut next_control = egui::Rect::NOTHING;
                    let mut output = ctx.run_ui(egui::RawInput {
                        screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(width, 780.0))),
                        time: Some(frame as f64 * 0.1),
                        ..Default::default()
                    }, |ui| {
                        app.progress_ui(ui);
                        next_control = ui.button("Import…").rect;
                    });
                    output.textures_delta.clear();
                    if let Some(expected) = baseline {
                        assert_eq!(next_control, expected, "width {width}, policy {policy:?}");
                    } else {
                        baseline = Some(next_control);
                    }
                    let texts: Vec<_> = output.shapes.iter().filter_map(|shape| match &shape.shape {
                        egui::epaint::Shape::Text(text) => Some(text.galley.text()),
                        _ => None,
                    }).collect();
                    assert_eq!(texts.len(), 2, "one progress label and one button: {texts:?}");
                    assert_eq!(texts.contains(&"Working…"), policy.is_none());
                }
            }
            app.busy = false;
            app.status = "Completed".into();
            let mut output = ctx.run_ui(Default::default(), |ui| app.progress_ui(ui));
            output.textures_delta.clear();
            assert!(output.shapes.iter().any(|shape| matches!(&shape.shape,
                egui::epaint::Shape::Text(text) if text.galley.text() == "Completed")));
        }
    }
}
