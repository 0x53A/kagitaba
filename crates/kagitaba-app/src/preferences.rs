//! Local navigation preferences only; never credential titles or trust decisions.
use std::{
    fs, io,
    os::unix::{
        ffi::{OsStrExt, OsStringExt},
        fs::{DirBuilderExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
};

#[derive(Default)]
pub struct Preferences {
    pub remember: bool,
    pub recent: Vec<PathBuf>,
    pub favorites: Vec<PathBuf>,
}

impl Preferences {
    pub fn path() -> Option<PathBuf> {
        std::env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|p| PathBuf::from(p).join(".local/share")))
            .map(|p| p.join("kagitaba/navigation.json"))
    }

    pub fn load(path: &Path) -> io::Result<Self> {
        use io::Read;
        let file = match fs::File::open(path) {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(e) => return Err(e),
        };
        let mut bytes = Vec::new();
        file.take(1024 * 1024 + 1).read_to_end(&mut bytes)?;
        if bytes.len() > 1024 * 1024 {
            return Err(io::Error::other("Navigation preferences exceed size limit"));
        }
        let v: serde_json::Value = serde_json::from_slice(&bytes)?;
        if v["version"] != 1 {
            return Err(io::Error::other("Unsupported navigation preferences"));
        }
        let paths = |name: &str| -> io::Result<Vec<PathBuf>> {
            let values = v[name]
                .as_array()
                .ok_or_else(|| io::Error::other("Invalid saved wallets"))?;
            let mut result = Vec::new();
            for value in values {
                let bytes = hex::decode(
                    value
                        .as_str()
                        .ok_or_else(|| io::Error::other("Invalid saved path"))?,
                )
                .map_err(|_| io::Error::other("Invalid saved path"))?;
                let path = PathBuf::from(std::ffi::OsString::from_vec(bytes));
                if path.is_absolute() && !result.contains(&path) {
                    result.push(path);
                }
            }
            Ok(result)
        };
        let remember = v["remember"]
            .as_bool()
            .ok_or_else(|| io::Error::other("Invalid history preference"))?;
        let favorites = paths("favorites")?;
        let mut recent = if remember { paths("recent")? } else { vec![] };
        recent.retain(|p| !favorites.contains(p));
        recent.truncate(20);
        Ok(Self {
            remember,
            recent,
            favorites,
        })
    }

    pub fn save(&self, path: &Path) -> io::Result<()> {
        use io::Write;
        let parent = path
            .parent()
            .ok_or_else(|| io::Error::other("Missing preferences directory"))?;
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)?;
        let encode = |paths: &[PathBuf]| {
            paths
                .iter()
                .map(|p| hex::encode(p.as_os_str().as_bytes()))
                .collect::<Vec<_>>()
        };
        let v = serde_json::json!({"version":1,"remember":self.remember,"recent":encode(&self.recent),"favorites":encode(&self.favorites)});
        // A unique sibling avoids following an existing temporary symlink.
        let tmp = parent.join(format!(
            "navigation-{}.tmp",
            kagitaba_core::EntryId::generate(&mut rand::rngs::SysRng).map_err(io::Error::other)?
        ));
        let result = (|| {
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp)?;
            file.write_all(&serde_json::to_vec(&v)?)?;
            file.sync_all()?;
            fs::rename(&tmp, path)?;
            fs::File::open(parent)?.sync_all()
        })();
        if result.is_err() {
            let _ = fs::remove_file(tmp);
        }
        result
    }

    pub fn opened(&mut self, path: &Path) {
        if !self.remember || self.favorites.iter().any(|p| p == path) {
            return;
        }
        self.recent.retain(|p| p != path);
        self.recent.insert(0, path.to_owned());
        self.recent.truncate(20);
    }

    pub fn set_remember(&mut self, remember: bool) {
        self.remember = remember;
        if !remember {
            self.recent.clear();
        }
    }

    pub fn toggle_favorite(&mut self, path: &Path) {
        if self.favorites.iter().any(|p| p == path) {
            self.favorites.retain(|p| p != path);
            self.opened(path);
        } else {
            self.recent.retain(|p| p != path);
            self.favorites.push(path.to_owned());
        }
    }

    pub fn remove(&mut self, path: &Path) {
        self.recent.retain(|p| p != path);
        self.favorites.retain(|p| p != path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn history_opt_out_and_favorites_survive_restart() {
        let dir = std::env::temp_dir().join(format!(
            "kagitaba-nav-{}",
            kagitaba_core::EntryId::generate(&mut rand::rngs::SysRng).unwrap()
        ));
        let file = dir.join("navigation.json");
        let mut prefs = Preferences::default();
        prefs.opened(Path::new("/one"));
        assert!(prefs.recent.is_empty());
        prefs.set_remember(true);
        for p in ["/one", "/two", "/one"] {
            prefs.opened(Path::new(p));
        }
        assert_eq!(
            prefs.recent,
            vec![PathBuf::from("/one"), PathBuf::from("/two")]
        );
        prefs.toggle_favorite(Path::new("/one"));
        prefs.set_remember(false);
        prefs.save(&file).unwrap();
        let mut loaded = Preferences::load(&file).unwrap();
        assert!(!loaded.remember && loaded.recent.is_empty());
        assert_eq!(loaded.favorites, vec![PathBuf::from("/one")]);
        loaded.remove(Path::new("/one"));
        loaded.save(&file).unwrap();
        assert!(Preferences::load(&file).unwrap().favorites.is_empty());
        fs::remove_dir_all(dir).unwrap();
    }
}
