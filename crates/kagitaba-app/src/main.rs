#![forbid(unsafe_code)]
mod backend;
mod editor;
mod preferences;
mod remote;
mod theme;
mod ui;
fn main() -> eframe::Result {
    let window_size = [1180.0, 820.0];
    #[cfg(feature = "smoke")]
    let window_size = if std::env::var_os("KAGITABA_SMOKE_NARROW").is_some() {
        [440.0, 780.0]
    } else {
        window_size
    };
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
            viewport: eframe::egui::ViewportBuilder::default()
                .with_inner_size(window_size)
                .with_min_inner_size([360.0, 480.0]),
            ..Default::default()
        },
        Box::new(|cc| Ok(Box::new(ui::App::new(cc)))),
    )
}
