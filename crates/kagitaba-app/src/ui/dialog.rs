use super::*;

/// Native portal dialogs run off the UI thread. Dropping the receiver on lock
/// ignores late selections; the system chooser never receives credential data.
pub(super) struct Dialog {
    #[cfg(feature = "native-dialog")]
    result: Option<mpsc::Receiver<Option<PathBuf>>>,
    #[cfg(not(feature = "native-dialog"))]
    inner: egui_file_dialog::FileDialog,
    picked: Option<PathBuf>,
    finished_empty: bool,
}
impl Dialog {
    pub fn new() -> Self {
        Self {
            #[cfg(feature = "native-dialog")]
            result: None,
            #[cfg(not(feature = "native-dialog"))]
            inner: egui_file_dialog::FileDialog::new(),
            picked: None,
            finished_empty: false,
        }
    }
    pub fn open(&mut self, pick: Pick, ctx: egui::Context) {
        self.finished_empty = false;
        #[cfg(feature = "native-dialog")]
        {
            let (tx, rx) = mpsc::channel();
            self.result = Some(rx);
            std::thread::spawn(move || {
                let dialog = rfd::FileDialog::new();
                let path = match pick {
                    Pick::Create | Pick::Open | Pick::Pull | Pick::Merge | Pick::Backup | Pick::CopyDestination => {
                        dialog.pick_folder()
                    }
                    Pick::ExportParticipant | Pick::ExportFile { .. } => dialog.save_file(),
                    _ => dialog.pick_file(),
                };
                let _ = tx.send(path);
                ctx.request_repaint();
            });
        }
        #[cfg(not(feature = "native-dialog"))]
        {
            let _ = ctx;
            match pick {
                Pick::Create | Pick::Open | Pick::Pull | Pick::Merge | Pick::Backup | Pick::CopyDestination => {
                    self.inner.pick_directory()
                }
                Pick::ExportParticipant | Pick::ExportFile { .. } => self.inner.save_file(),
                _ => self.inner.pick_file(),
            }
        }
    }
    pub fn update(&mut self, ctx: &egui::Context) {
        #[cfg(feature = "native-dialog")]
        {
            let _ = ctx;
            if let Some(receiver) = &self.result {
                match receiver.try_recv() {
                    Ok(path) => {
                        self.finished_empty = path.is_none();
                        self.picked = path;
                        self.result = None;
                    }
                    Err(mpsc::TryRecvError::Disconnected) => {
                        self.finished_empty = true;
                        self.result = None;
                    }
                    Err(mpsc::TryRecvError::Empty) => {}
                }
            }
        }
        #[cfg(not(feature = "native-dialog"))]
        {
            self.inner.update(ctx);
            self.picked = self.inner.take_picked();
        }
    }
    pub fn take_finished_empty(&mut self) -> bool {
        std::mem::take(&mut self.finished_empty)
    }
    pub fn take_picked(&mut self) -> Option<PathBuf> {
        self.picked.take()
    }
}

#[cfg(all(test, feature = "native-dialog"))]
mod tests {
    use super::*;
    #[test]
    fn cancelled_and_disconnected_choosers_finish_without_stale_selections() {
        let ctx = egui::Context::default();
        for disconnected in [false, true] {
            let mut dialog = Dialog::new();
            let (tx, rx) = mpsc::channel();
            dialog.result = Some(rx);
            if !disconnected { tx.send(None).unwrap(); }
            drop(tx);
            dialog.update(&ctx);
            assert!(dialog.result.is_none());
            assert!(dialog.take_finished_empty());
            assert!(!dialog.take_finished_empty());
            assert!(dialog.take_picked().is_none());
        }
    }
}
