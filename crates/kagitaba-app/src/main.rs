#![forbid(unsafe_code)]
mod backend;
mod editor;
mod ui;
fn main() -> eframe::Result {
    let _lock = match backend::instance_lock() {
        Ok(lock) => lock,
        Err(e) => {
            eprintln!("{e}");
            return Ok(());
        }
    };
    eframe::run_native(
        "Kagitaba",
        eframe::NativeOptions {
            viewport: eframe::egui::ViewportBuilder::default().with_inner_size([1180.0, 820.0]),
            ..Default::default()
        },
        Box::new(|cc| Ok(Box::new(ui::App::new(cc)))),
    )
}
