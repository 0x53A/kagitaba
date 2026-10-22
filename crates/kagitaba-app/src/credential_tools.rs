use crate::theme;
use eframe::egui;
use kagitaba_cxf::{otp, password::Rules};
use std::{
    io::Read,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    time::Duration,
};
use zeroize::{Zeroize, Zeroizing};

type ScanResult = Result<Vec<Zeroizing<String>>, &'static str>;

#[derive(Default)]
pub struct Tools {
    pub generator: bool,
    pub target: Option<usize>,
    rules: Rules,
    generated: Zeroizing<String>,
    revealed: bool,
    pub totp: bool,
    uri: Zeroizing<String>,
    candidates: Vec<Zeroizing<String>>,
    preview: Option<crate::editor::SecretValue>,
    status: String,
    dialog: egui_file_dialog::FileDialog,
    camera: String,
    camera_frame: Arc<Mutex<Option<Zeroizing<Vec<u8>>>>>,
    camera_texture: Option<egui::TextureHandle>,
    receiver: Option<mpsc::Receiver<ScanResult>>,
    cancel: Option<Arc<AtomicBool>>,
}
impl Drop for Tools {
    fn drop(&mut self) {
        if let Some(cancel) = &self.cancel {
            cancel.store(true, Ordering::Relaxed);
        }
    }
}
impl Tools {
    pub fn open_generator(&mut self, target: Option<usize>) {
        self.generated.zeroize();
        self.status.clear();
        self.target = target;
        self.generator = true;
    }
    pub fn show(
        &mut self,
        ctx: &egui::Context,
        json: &mut String,
        clip: &mut crate::editor::Clipboard,
    ) {
        if self.generator {
            let mut open = true;
            let mut apply = false;
            egui::Window::new("Password generator")
                .open(&mut open)
                .resizable(true)
                .vscroll(true)
                .scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::VisibleWhenNeeded)
                .default_width(340.0)
                .max_width((ctx.content_rect().width() - 32.0).max(240.0))
                .max_height(ctx.content_rect().height() - 80.0)
                .show(ctx, |ui| {
                    let before = self.rules.clone();
                    ui.horizontal(|ui| {
                        theme::caption(ui, "Length");
                        ui.add(egui::DragValue::new(&mut self.rules.length).range(1..=1024));
                    });
                    ui.checkbox(&mut self.rules.lowercase, "Lowercase");
                    ui.checkbox(&mut self.rules.uppercase, "Uppercase");
                    ui.checkbox(&mut self.rules.digits, "Digits");
                    ui.checkbox(&mut self.rules.symbols, "Symbols");
                    ui.checkbox(&mut self.rules.lookalikes, "Exclude lookalikes");
                    ui.checkbox(&mut self.rules.require_each, "Require every enabled class");
                    theme::caption(ui, "Allowed symbols");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.rules.symbol_set)
                            .font(egui::TextStyle::Monospace),
                    );
                    theme::caption(ui, "Additional exclusions");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.rules.exclusions)
                            .font(egui::TextStyle::Monospace),
                    );
                    if self.rules != before {
                        self.generated.zeroize();
                    }
                    match self.rules.alphabet() {
                        Ok(alphabet) => {
                            theme::caption(ui, format!("Alphabet: {alphabet}"));
                        }
                        Err(e) => {
                            ui.colored_label(theme::ERROR, e);
                        }
                    }
                    if ui.button("Generate").clicked() {
                        match self.rules.generate(&mut rand::rngs::SysRng) {
                            Ok(v) => self.generated = v,
                            Err(e) => {
                                self.generated.zeroize();
                                self.status = e.into();
                            }
                        }
                    }
                    ui.add(
                        egui::TextEdit::singleline(&mut *self.generated)
                            .font(egui::TextStyle::Monospace)
                            .password(!self.revealed)
                            .interactive(false),
                    );
                    ui.checkbox(&mut self.revealed, "Show password");
                    ui.horizontal(|ui| {
                        if ui
                            .add_enabled(!self.generated.is_empty(), egui::Button::new("Copy"))
                            .clicked()
                        {
                            clip.copy(&self.generated);
                        }
                        if self.target.is_some()
                            && ui
                                .add_enabled(
                                    !self.generated.is_empty(),
                                    egui::Button::new("Use password"),
                                )
                                .clicked()
                        {
                            apply = true;
                        }
                    });
                    ui.label(&self.status);
                });
            if apply {
                if let (Some(index), Ok(value)) =
                    (self.target, serde_json::from_str::<serde_json::Value>(json))
                {
                    let mut value = crate::editor::SecretValue(value);
                    if let Some(c) = value.0["entity"]["credentials"]
                        .get_mut(index)
                        .filter(|c| c["type"] == "basic-auth")
                    {
                        if c.get("password").is_none_or(serde_json::Value::is_null) {
                            c["password"] = serde_json::json!({"fieldType":"concealed-string"});
                        }
                        c["password"]["value"] = self.generated.as_str().into();
                        json.zeroize();
                        *json = value.0.to_string();
                    }
                }
                open = false;
            }
            if !open {
                self.generator = false;
                self.generated.zeroize();
                self.revealed = false;
            }
        }
        if !self.totp {
            return;
        }
        self.dialog.update(ctx);
        if let Some(path) = self.dialog.take_picked() {
            self.start(ctx.clone(), move |_| {
                let mut data = Zeroizing::new(Vec::new());
                std::fs::File::open(path)
                    .map_err(|_| "Cannot read image")?
                    .take(16 * 1024 * 1024 + 1)
                    .read_to_end(&mut data)
                    .map_err(|_| "Cannot read image")?;
                if data.len() > 16 * 1024 * 1024 {
                    return Err("Image exceeds 16 MiB");
                }
                scan_image(&data)
            });
        }
        if let Some(result) = self.receiver.as_ref().and_then(|r| r.try_recv().ok()) {
            self.receiver = None;
            self.cancel = None;
            match result {
                Ok(values) => {
                    self.candidates = values;
                    self.status = "Choose a TOTP code to review".into();
                }
                Err(e) => self.status = e.into(),
            }
        }
        if let Some(frame) = self.camera_frame.lock().expect("camera frame").take() {
            let image = egui::ColorImage::from_gray([640, 480], &frame);
            if let Some(texture) = &mut self.camera_texture {
                texture.set(image, egui::TextureOptions::LINEAR);
            } else {
                self.camera_texture =
                    Some(ctx.load_texture("TOTP camera", image, egui::TextureOptions::LINEAR));
            }
        }
        let mut open = true;
        let mut add = false;
        let mut image = false;
        let mut camera = false;
        let mut stop = false;
        egui::Window::new("Import TOTP")
            .open(&mut open)
            .vscroll(true)
            .scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::VisibleWhenNeeded)
            .default_width(340.0)
            .max_width((ctx.content_rect().width() - 32.0).max(240.0))
            .max_height(ctx.content_rect().height() - 80.0)
            .show(ctx, |ui| {
                theme::caption(ui, "otpauth URI");
                ui.add(
                    egui::TextEdit::singleline(&mut *self.uri)
                        .font(egui::TextStyle::Monospace)
                        .password(true),
                );
                if ui.button("Review URI").clicked() {
                    self.review();
                }
                for i in 0..self.candidates.len() {
                    if ui.button(format!("Review TOTP {}", i + 1)).clicked() {
                        self.uri = self.candidates[i].clone();
                        self.review();
                    }
                }
                if self.camera.is_empty() {
                    self.camera = "/dev/video0".into();
                }
                if let Some(texture) = &self.camera_texture {
                    ui.add(egui::Image::new(texture).max_width(400.0));
                }
                theme::caption(ui, "Camera device");
                ui.add(
                    egui::TextEdit::singleline(&mut self.camera).font(egui::TextStyle::Monospace),
                );
                ui.horizontal_wrapped(|ui| {
                    image = ui
                        .add_enabled(
                            self.receiver.is_none(),
                            egui::Button::new("Import picture (PNG / JPEG)"),
                        )
                        .clicked();
                    camera = ui
                        .add_enabled(self.receiver.is_none(), egui::Button::new("Scan camera"))
                        .clicked();
                    stop = ui.button("Stop camera").clicked();
                });
                if let Some(value) = &self.preview {
                    let c = &value.0;
                    ui.label(format!(
                        "{} · {}",
                        c["issuer"].as_str().unwrap_or(""),
                        c["username"].as_str().unwrap_or("")
                    ));
                    theme::caption(
                        ui,
                        format!(
                            "{} · {} digits · {} seconds",
                            c["algorithm"].as_str().unwrap_or(""),
                            c["digits"],
                            c["period"]
                        ),
                    );
                    add = ui.button("Add to entry draft").clicked();
                }
                ui.label(&self.status);
            });
        if image {
            self.dialog.pick_file();
        }
        if camera {
            let device = self.camera.clone();
            self.status = "Point the camera at a TOTP QR code (60 second scan)".into();
            let frame = self.camera_frame.clone();
            let repaint = ctx.clone();
            self.start(ctx.clone(), move |cancel| {
                scan_camera(&device, &cancel, &frame, &repaint)
            });
        }
        if stop {
            self.camera_texture = None;
            self.camera_frame.lock().expect("camera frame").take();
            if let Some(cancel) = &self.cancel {
                cancel.store(true, Ordering::Relaxed);
            }
            self.receiver = None;
        }
        if add {
            if let (Some(c), Ok(value)) = (
                self.preview.take(),
                serde_json::from_str::<serde_json::Value>(json),
            ) {
                let mut value = crate::editor::SecretValue(value);
                if let Some(credentials) = value.0["entity"]["credentials"].as_array_mut() {
                    credentials.push(c.0.clone());
                    json.zeroize();
                    *json = value.0.to_string();
                }
            }
            open = false;
        }
        if !open {
            self.camera_texture = None;
            self.camera_frame.lock().expect("camera frame").take();
            self.totp = false;
            self.uri.zeroize();
            self.candidates.clear();
            self.preview = None;
            self.receiver = None;
            if let Some(c) = self.cancel.take() {
                c.store(true, Ordering::Relaxed);
            }
            self.dialog = egui_file_dialog::FileDialog::new();
        }
    }
    fn review(&mut self) {
        match otp::parse(&self.uri) {
            Ok(c) => {
                self.preview = Some(crate::editor::SecretValue(c));
                self.status.clear();
            }
            Err(e) => {
                self.preview = None;
                self.status = e.into();
            }
        }
    }
    fn start(
        &mut self,
        ctx: egui::Context,
        job: impl FnOnce(Arc<AtomicBool>) -> Result<Vec<Zeroizing<String>>, &'static str>
        + Send
        + 'static,
    ) {
        if let Some(cancel) = self.cancel.take() {
            cancel.store(true, Ordering::Relaxed);
        }
        self.preview = None;
        self.candidates.clear();
        let cancel = Arc::new(AtomicBool::new(false));
        self.cancel = Some(cancel.clone());
        let (tx, rx) = mpsc::channel();
        self.receiver = Some(rx);
        std::thread::spawn(move || {
            let result = job(cancel.clone());
            if !cancel.load(Ordering::Relaxed) {
                let _ = tx.send(result);
                ctx.request_repaint();
            }
        });
    }
}
fn scan_image(data: &[u8]) -> Result<Vec<Zeroizing<String>>, &'static str> {
    let mut reader = image::ImageReader::new(std::io::Cursor::new(data))
        .with_guessed_format()
        .map_err(|_| "Invalid image")?;
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(8192);
    limits.max_image_height = Some(8192);
    limits.max_alloc = Some(128 * 1024 * 1024);
    reader.limits(limits);
    let image = reader
        .decode()
        .map_err(|_| "Unsupported or oversized image")?
        .thumbnail(2048, 2048)
        .to_luma8();
    let (width, height) = image.dimensions();
    let pixels = Zeroizing::new(image.into_raw());
    otp::scan(width as usize, height as usize, &pixels)
}
fn scan_camera(
    device: &str,
    cancel: &AtomicBool,
    frame: &Mutex<Option<Zeroizing<Vec<u8>>>>,
    ctx: &egui::Context,
) -> Result<Vec<Zeroizing<String>>, &'static str> {
    use std::process::{Command, Stdio};
    if !device.starts_with("/dev/video") || !device[10..].chars().all(|c| c.is_ascii_digit()) {
        return Err("Choose a /dev/video camera device");
    }
    // A bounded stream, no temporary photos, no shell and no network input.
    let mut child=Command::new("ffmpeg").args(["-nostdin","-loglevel","quiet","-f","video4linux2","-i",device,"-t","60","-vf","scale=640:480:force_original_aspect_ratio=decrease,pad=640:480:(ow-iw)/2:(oh-ih)/2,fps=3","-pix_fmt","gray","-f","rawvideo","pipe:1"]).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().map_err(|_|"Camera requires ffmpeg on PATH")?;
    let mut stdout = child.stdout.take().ok_or("Camera unavailable")?;
    let (tx, rx) = mpsc::sync_channel(1);
    let reading = std::thread::spawn(move || {
        loop {
            let mut pixels = Zeroizing::new(vec![0u8; 640 * 480]);
            if stdout.read_exact(&mut pixels).is_err() {
                break;
            }
            if tx.send(pixels).is_err() {
                break;
            }
        }
    });
    let deadline = std::time::Instant::now() + Duration::from_secs(65);
    let result = loop {
        if cancel.load(Ordering::Relaxed) {
            break Err("Camera scan cancelled");
        }
        if std::time::Instant::now() > deadline {
            break Err("No supported TOTP QR code found");
        }
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(pixels) => {
                let result = otp::scan(640, 480, &pixels);
                *frame.lock().expect("camera frame") = Some(pixels);
                ctx.request_repaint();
                if let Ok(values) = result {
                    break Ok(values);
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                break Err("Camera unavailable or no supported TOTP QR code found");
            }
            Err(_) => (),
        }
    };
    let _ = child.kill();
    drop(rx);
    let _ = child.wait();
    let _ = reading.join();
    result
}

#[cfg(test)]
mod tests {
    #[test]
    fn image_import_uses_the_shared_decoder_and_rejects_corrupt_input() {
        let values =
            super::scan_image(include_bytes!("../../../tests/fixtures/totp-qr.png")).unwrap();
        assert_eq!(values.len(), 1);
        assert_eq!(kagitaba_cxf::otp::parse(&values[0]).unwrap()["period"], 300);
        assert!(super::scan_image(b"not an image").is_err());
    }
}
