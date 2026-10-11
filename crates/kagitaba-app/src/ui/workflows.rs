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
        app.participant_names.insert(participant, "Everyday YubiKey".into());
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
            relation: kagitaba_store::HistoryRelation { ahead: 1, behind: 2 },
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
            "import" => app.screen = Screen::Import,
            "review" => {
                app.screen = Screen::Import;
                app.preview = Some("3 entries · 1 collection\nNo unresolved references or unsupported credentials.".into());
            }
            "keys" => app.screen = Screen::Keys,
            "transfer" => app.screen = Screen::Transfer,
            "unlock" => {
                app.clear_secrets();
                app.screen = Screen::Unlock;
            }
            "create" => {
                app.clear_secrets();
                app.wallet = None;
                app.create_path = Some("/home/example/Wallets/New wallet".into());
                app.screen = Screen::Create;
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
        self.name_edit.is_some() || self.selected.is_some()
            && (!self.json.is_empty() && self.json != *self.entry_original
                || self.recipients != self.original_recipients)
    }

    pub(super) fn navigate(&mut self, action: Leave) {
        if self.dirty() {
            self.leave_action = Some(action);
        } else {
            self.leave(action);
        }
    }

    fn leave(&mut self, action: Leave) {
        self.name_edit = None;
        self.reset_entry();
        self.leave_action = None;
        match action {
            Leave::Select(id) => {
                self.select_entry(id);
                if self.unlocked.is_some() {
                    self.send(Command::Read(id));
                }
            }
            Leave::New(collection) => self.new_entry(collection),
            Leave::Screen(screen) => {
                if self.screen == Screen::Import {
                    self.send(Command::DiscardImport);
                }
                self.screen = screen;
                self.consent = false;
                self.revoke_confirm = false;
                self.provision = false;
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
            Leave::DismissEntry => {}
        }
    }

    pub(super) fn shell(&mut self, ui: &mut egui::Ui) {
        let narrow = ui.available_width() < 780.0;
        ui.horizontal_wrapped(|ui| {
            ui.heading(
                egui::RichText::new("K A G I T A B A")
                    .color(theme::AQUA)
                    .monospace()
                    .size(18.0),
            );
            if self.screen != Screen::Home {
                if !narrow && let Some(path) = &self.wallet {
                    ui.add_sized(
                        [180.0, 24.0],
                        egui::Label::new(wallet_name(path)).truncate(),
                    )
                    .on_hover_text(path.display().to_string());
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if self.unlocked.is_some()
                        && ui
                            .add_enabled(!self.locking, egui::Button::new("Lock"))
                            .clicked()
                    {
                        self.request_lock();
                    }
                    if ui
                        .add_enabled(
                            !self.busy,
                            egui::Button::new(if self.screen == Screen::Wallet {
                                "Close wallet"
                            } else {
                                "Back"
                            }),
                        )
                        .clicked()
                    {
                        if matches!(self.screen, Screen::Home | Screen::Create | Screen::Wallet)
                            || self.wallet.is_none()
                        {
                            self.navigate(Leave::Close);
                        } else {
                            self.navigate(Leave::Screen(Screen::Wallet));
                        }
                    }
                });
            }
        });
        if narrow && let Some(path) = &self.wallet {
            ui.add(egui::Label::new(wallet_name(path)).truncate())
                .on_hover_text(path.display().to_string());
        }
        ui.separator();
        self.remote_ui(ui);
        if self.busy || !self.status.is_empty() {
            ui.horizontal_wrapped(|ui| {
                if self.busy {
                    ui.spinner();
                }
                ui.label(&self.status);
            });
        }
        if let Some(error) = &self.preference_error {
            ui.colored_label(theme::ERROR, error);
        }
        ui.add_enabled_ui(!self.busy && self.leave_action.is_none() && self.trust.is_none(), |ui| {
            match self.screen {
                Screen::Home => self.home(ui),
                Screen::Wallet => self.workspace(ui),
                screen => {
                    egui::ScrollArea::vertical().id_salt("workflow").show(ui, |ui| {
                        ui.set_max_width(ui.available_width().min(720.0));
                        theme::surface().show(ui, |ui| {
                            match screen {
                                Screen::Create => self.create(ui),
                                Screen::Unlock => {
                                    ui.heading("Unlock your wallet");
                                    self.hardware_ui(ui);
                                    if ui.button("Browse encrypted entries without unlocking").clicked() { self.screen = Screen::Wallet; }
                                }
                                Screen::Import => {
                                    if self.unlocked.is_some() { self.import_ui(ui); }
                                    else { self.unlock_prompt(ui); }
                                }
                                Screen::Keys => self.keys_ui(ui),
                                Screen::Transfer => self.transfer_ui(ui),
                                _ => {}
                            }
                        });
                    });
                }
            }
        });
        self.trust_modal(ui.ctx());
        if self.screen == Screen::Wallet
            && ui.available_width() < 780.0
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
                    ui.label("Your edits have not been saved to the wallet.");
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
                            self.pick(Pick::Create);
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
                        .id_salt("saved-wallets")
                        .show(ui, |ui| {
                            if !self.preferences.favorites.is_empty() {
                                ui.add_space(12.0);
                                ui.strong("Favorites");
                                for path in self.preferences.favorites.clone() {
                                    self.wallet_row(ui, path, true);
                                }
                            }
                            if self.preferences.remember {
                                ui.add_space(12.0);
                                ui.strong("Recent wallets");
                                if self.preferences.recent.is_empty() {
                                    ui.label("Wallets you open will appear here.");
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
            egui::Frame::new()
                .fill(theme::SURFACE)
                .stroke(egui::Stroke::new(1.0, theme::LINE))
                .inner_margin(8)
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        let width = (ui.available_width() - 100.0).max(60.0);
                        if ui
                            .add_sized(
                                [width, 48.0],
                                egui::Button::new(format!(
                                    "{}\n{}",
                                    wallet_name(&path),
                                    path.display()
                                ))
                                .wrap(),
                            )
                            .clicked()
                        {
                            self.send(Command::Open(path.clone(), None));
                        }
                        if ui
                            .button(if favorite { "★" } else { "☆" })
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
                            .button("×")
                            .on_hover_text("Remove from this list. The wallet folder is kept.")
                            .clicked()
                        {
                            self.preferences.remove(&path);
                            self.save_preferences();
                        }
                    });
                });
        });
    }

    fn create(&mut self, ui: &mut egui::Ui) {
        ui.heading("Create wallet");
        ui.label("1 · Location     2 · Key     3 · Create");
        if let Some(path) = &self.create_path {
            ui.label(format!("Wallet folder: {}", path.display()));
        }
        if self.unlocked.is_none() {
            ui.label("Unlock an existing Kagitaba key, or set up two unused PIV slots.");
            self.hardware_ui(ui);
        } else {
            ui.colored_label(theme::AQUA, "Your key is ready");
            ui.label("Touch your key to sign the new wallet.");
            if theme::primary(ui, "Create wallet").clicked()
                && let Some(path) = self.create_path.clone()
            {
                self.send(Command::Create(path));
            }
        }
        if ui.button("Choose a different folder…").clicked() {
            self.pick(Pick::Create);
        }
    }

    fn unlock_prompt(&mut self, ui: &mut egui::Ui) {
        ui.heading("Wallet locked");
        ui.label("Unlock your key to view credentials and make changes.");
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
            if let Some(path) = self.wallet.clone() {
                let favorite = self.preferences.favorites.contains(&path);
                if ui
                    .button(if favorite {
                        "★ Favorite"
                    } else {
                        "☆ Favorite"
                    })
                    .clicked()
                {
                    self.preferences.toggle_favorite(&path);
                    self.save_preferences();
                }
            }
        });
        if self.unlocked.is_none() {
            self.unlock_prompt(ui);
        }
        ui.separator();
        if ui.available_width() >= 780.0 {
            let height = ui.available_height();
            let detail_width = ui.available_width() - 320.0;
            ui.horizontal_top(|ui| {
                ui.allocate_ui_with_layout(
                    egui::vec2(290.0, height),
                    egui::Layout::top_down(egui::Align::Min),
                    |ui| {
                        self.entry_list(ui);
                    },
                );
                ui.separator();
                ui.allocate_ui_with_layout(
                    egui::vec2(detail_width, height),
                    egui::Layout::top_down(egui::Align::Min),
                    |ui| {
                        egui::ScrollArea::vertical()
                            .id_salt("entry-detail")
                            .show(ui, |ui| {
                                ui.set_min_width((ui.available_width() - 1.0).max(0.0));
                                theme::surface().show(ui, |ui| self.entry_ui(ui));
                            });
                    },
                );
            });
        } else {
            self.entry_list(ui);
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
                egui::ScrollArea::vertical()
                    .id_salt("modal-details")
                    .auto_shrink([false, false])
                    .max_height((ctx.content_rect().height() - 150.0).max(100.0))
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
                ui.label("First open: compare this signing fingerprint with a trusted device or backup record.");
                ui.label(&fingerprint);
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
