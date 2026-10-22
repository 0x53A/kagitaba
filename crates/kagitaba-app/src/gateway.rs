//! Local, approval-gated browser gateway. No wallet operations run on this thread.
use std::{
    fs::{self, DirBuilder, Permissions},
    io::{self, Read, Write},
    os::unix::{
        fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

const LIMIT: usize = 64 * 1024;
const LIFETIME: Duration = Duration::from_secs(90);
pub struct Request {
    pub id: u64,
    pub origin: String,
    pub passkey: Option<crate::gateway_passkey::Request>,
    pub deadline: Instant,
    pub cancelled: Arc<AtomicBool>,
    pub reply: mpsc::SyncSender<Zeroizing<String>>,
}
impl Request {
    pub fn live(&self) -> bool {
        !self.cancelled.load(Ordering::Acquire) && Instant::now() < self.deadline
    }
}
impl Drop for Request {
    fn drop(&mut self) {
        self.cancelled.store(true, Ordering::Release);
    }
}
#[derive(Clone)]
pub struct Permit {
    pub cancelled: Arc<AtomicBool>,
    pub deadline: Instant,
}
impl Permit {
    pub fn check(&self) -> Result<(), &'static str> {
        if self.cancelled.load(Ordering::Acquire) || Instant::now() >= self.deadline {
            Err("Request cancelled or expired")
        } else {
            Ok(())
        }
    }
}
impl Request {
    pub fn permit(&self) -> Permit {
        Permit {
            cancelled: self.cancelled.clone(),
            deadline: self.deadline,
        }
    }
}
pub struct Server {
    stop: Arc<AtomicBool>,
    pub requests: mpsc::Receiver<Request>,
}
impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
    }
}
fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "Invalid gateway data")
}
fn private_directory(path: &Path) -> io::Result<()> {
    let m = fs::symlink_metadata(path)?;
    if !m.is_dir() || m.uid() != rustix::process::geteuid().as_raw() || m.mode() & 0o077 != 0 {
        return Err(invalid());
    }
    Ok(())
}
fn socket_path() -> io::Result<PathBuf> {
    let runtime = PathBuf::from(std::env::var_os("XDG_RUNTIME_DIR").ok_or_else(invalid)?);
    if !runtime.is_absolute() {
        return Err(invalid());
    }
    private_directory(&runtime)?;
    let dir = runtime.join("kagitaba");
    match DirBuilder::new().mode(0o700).create(&dir) {
        Ok(()) => (),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => (),
        Err(e) => return Err(e),
    }
    private_directory(&dir)?;
    Ok(dir.join("browser.sock"))
}
fn check_socket(path: &Path) -> io::Result<()> {
    let m = fs::symlink_metadata(path)?;
    if !m.file_type().is_socket()
        || m.uid() != rustix::process::geteuid().as_raw()
        || m.mode() & 0o077 != 0
    {
        return Err(invalid());
    }
    Ok(())
}
pub fn read_frame(reader: &mut impl Read) -> io::Result<Zeroizing<Vec<u8>>> {
    let mut header = [0; 4];
    reader.read_exact(&mut header)?;
    let size = u32::from_ne_bytes(header) as usize;
    if size == 0 || size > LIMIT {
        return Err(invalid());
    }
    let mut bytes = Zeroizing::new(vec![0; size]);
    reader.read_exact(&mut bytes)?;
    Ok(bytes)
}
pub fn write_frame(writer: &mut impl Write, bytes: &[u8]) -> io::Result<()> {
    if bytes.is_empty() || bytes.len() > LIMIT {
        return Err(invalid());
    }
    writer.write_all(&(bytes.len() as u32).to_ne_bytes())?;
    writer.write_all(bytes)?;
    writer.flush()
}
pub fn origin(value: &str) -> Option<String> {
    let url = url::Url::parse(value).ok()?;
    (url.scheme() == "https"
        && url.has_host()
        && url.username().is_empty()
        && url.password().is_none())
    .then(|| url.origin().ascii_serialization())
}
fn parse_request(bytes: &[u8]) -> io::Result<(String, Option<crate::gateway_passkey::Request>)> {
    let v: serde_json::Value = serde_json::from_slice(bytes).map_err(|_| invalid())?;
    let passkey = v["operation"] == "passkey";
    if v["version"] != 1
        || (!passkey && v["operation"] != "login")
        || v.as_object()
            .is_none_or(|o| o.len() != if passkey { 5 } else { 3 })
    {
        return Err(invalid());
    }
    let supplied = v["origin"].as_str().ok_or_else(invalid)?;
    if supplied.len() > 2048 {
        return Err(invalid());
    }
    let canonical = origin(supplied).ok_or_else(invalid)?;
    if supplied != canonical {
        return Err(invalid());
    }
    let request = if passkey {
        Some(
            crate::gateway_passkey::Request::parse(
                &canonical,
                v["kind"].as_str().ok_or_else(invalid)?,
                &v["input"],
            )
            .map_err(|_| invalid())?,
        )
    } else {
        None
    };
    Ok((canonical, request))
}
pub fn denied() -> Zeroizing<String> {
    Zeroizing::new("{\"version\":1,\"error\":\"Request denied or unavailable\"}".into())
}

pub fn start(ctx: eframe::egui::Context) -> io::Result<Server> {
    start_at(socket_path()?, ctx)
}
fn start_at(path: PathBuf, ctx: eframe::egui::Context) -> io::Result<Server> {
    let directory = path.parent().ok_or_else(invalid)?;
    private_directory(directory)?;
    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(directory.join("browser.lock"))?;
    let metadata = lock.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o077 != 0
    {
        return Err(invalid());
    }
    lock.try_lock()
        .map_err(|_| io::Error::new(io::ErrorKind::AddrInUse, "Gateway already running"))?;
    if path.try_exists()? {
        check_socket(&path)?;
        match UnixStream::connect(&path) {
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    "Gateway already running",
                ));
            }
            Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => fs::remove_file(&path)?,
            Err(e) => return Err(e),
        }
    }
    let listener = UnixListener::bind(&path)?;
    fs::set_permissions(&path, Permissions::from_mode(0o600))?;
    listener.set_nonblocking(true)?;
    let (tx, requests) = mpsc::sync_channel(1);
    let stop = Arc::new(AtomicBool::new(false));
    let stopped = stop.clone();
    std::thread::spawn(move || {
        let _lock = lock;
        let mut id = 0;
        while !stopped.load(Ordering::Acquire) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    id += 1;
                    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                    let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
                    let result = read_frame(&mut stream).and_then(|b| parse_request(&b));
                    if let Ok((origin, passkey)) = result {
                        let (reply, rx) = mpsc::sync_channel(1);
                        let cancelled = Arc::new(AtomicBool::new(false));
                        let deadline = Instant::now() + LIFETIME;
                        let request = Request {
                            id,
                            origin,
                            passkey,
                            deadline,
                            cancelled: cancelled.clone(),
                            reply,
                        };
                        if tx.try_send(request).is_ok() {
                            ctx.request_repaint();
                            let _ = stream.set_read_timeout(Some(Duration::from_millis(100)));
                            while Instant::now() < deadline && !stopped.load(Ordering::Acquire) {
                                match rx.try_recv() {
                                    Ok(response) => {
                                        let _ = write_frame(&mut stream, response.as_bytes());
                                        break;
                                    }
                                    Err(mpsc::TryRecvError::Disconnected) => {
                                        let _ = write_frame(&mut stream, denied().as_bytes());
                                        break;
                                    }
                                    Err(mpsc::TryRecvError::Empty) => (),
                                }
                                let mut byte = [0];
                                match stream.read(&mut byte) {
                                    Err(e)
                                        if matches!(
                                            e.kind(),
                                            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                                        ) => {}
                                    _ => break, // EOF or unexpected extra input cancels this one-shot request.
                                }
                            }
                            cancelled.store(true, Ordering::Release);
                            ctx.request_repaint();
                        } else {
                            let _ = write_frame(&mut stream, denied().as_bytes());
                        }
                    } else {
                        let _ = write_frame(&mut stream, denied().as_bytes());
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(50))
                }
                Err(_) => break,
            }
        }
        let _ = fs::remove_file(path);
    });
    Ok(Server { stop, requests })
}

/// Firefox starts this same executable in bridge mode; stdout is protocol only.
pub fn bridge() -> io::Result<()> {
    // Firefox supplies the host manifest path and the calling extension ID.
    if std::env::args().next_back().as_deref() != Some("firefox@kagitaba.local") {
        return Err(invalid());
    }
    let input = read_frame(&mut io::stdin().lock())?;
    // The bridge is transport only. The native endpoint interprets requests.
    let path = socket_path()?;
    check_socket(&path)?;
    let mut socket = UnixStream::connect(path)?;
    socket.set_read_timeout(Some(LIFETIME + Duration::from_secs(5)))?;
    socket.set_write_timeout(Some(Duration::from_secs(2)))?;
    write_frame(&mut socket, &input)?;
    // A closed native port closes stdin. Propagate that immediately to the app.
    let cancellation = socket.try_clone()?;
    std::thread::spawn(move || {
        let mut b = [0];
        let _ = io::stdin().read(&mut b);
        let _ = cancellation.shutdown(std::net::Shutdown::Both);
    });
    let response = read_frame(&mut socket)?;
    write_frame(&mut io::stdout().lock(), &response)
}

/// Extract only a basic login whose explicit scope matches the browser origin.
pub fn login(json: &str, requested: &str) -> Option<Zeroizing<String>> {
    let mut value: serde_json::Value = serde_json::from_str(json).ok()?;
    let result = (|| {
        if value["kind"] != "item" {
            return None;
        }
        let entity = &value["entity"];
        if !entity["scope"]["urls"]
            .as_array()?
            .iter()
            .any(|v| v.as_str().and_then(origin).as_deref() == Some(requested))
        {
            return None;
        }
        let c = entity["credentials"]
            .as_array()?
            .iter()
            .find(|c| c["type"] == "basic-auth")?;
        let username = c["username"]["value"].as_str().unwrap_or("");
        let password = c["password"]["value"].as_str().unwrap_or("");
        let mut output = serde_json::json!({"version":1,"username":username,"password":password});
        let encoded = Zeroizing::new(serde_json::to_string(&output).ok()?);
        wipe(&mut output);
        (encoded.len() <= LIMIT).then_some(encoded)
    })();
    wipe(&mut value);
    result
}
pub(crate) fn wipe(value: &mut serde_json::Value) {
    use zeroize::Zeroize;
    match value {
        serde_json::Value::String(s) => s.zeroize(),
        serde_json::Value::Array(a) => a.iter_mut().for_each(wipe),
        serde_json::Value::Object(o) => o.values_mut().for_each(wipe),
        _ => (),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn socket_roundtrip_cancellation_and_exclusive_listener() {
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), Permissions::from_mode(0o700)).unwrap();
        let path = temp.path().join("browser.sock");
        let server = start_at(path.clone(), Default::default()).unwrap();
        assert!(start_at(path.clone(), Default::default()).is_err());
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
        let connect = || {
            let mut client = UnixStream::connect(&path).unwrap();
            client
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            write_frame(
                &mut client,
                br#"{"version":1,"operation":"login","origin":"https://example.com"}"#,
            )
            .unwrap();
            client
        };
        let mut client = connect();
        let request = server
            .requests
            .recv_timeout(Duration::from_secs(3))
            .unwrap();
        assert!(request.live());
        assert_eq!(request.origin, "https://example.com");
        request
            .reply
            .send(Zeroizing::new("{\"version\":1}".into()))
            .unwrap();
        assert_eq!(&**read_frame(&mut client).unwrap(), br#"{"version":1}"#);
        drop(request);
        let client = connect();
        let request = server
            .requests
            .recv_timeout(Duration::from_secs(3))
            .unwrap();
        drop(client);
        let limit = Instant::now() + Duration::from_secs(3);
        while request.live() && Instant::now() < limit {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(!request.live());
        drop(request);
        let mut client = connect();
        let request = server
            .requests
            .recv_timeout(Duration::from_secs(3))
            .unwrap();
        drop(request);
        assert_eq!(&**read_frame(&mut client).unwrap(), denied().as_bytes());
        drop(server);
    }
    #[test]
    fn framing_bounds_and_truncation() {
        for size in [0u32, (LIMIT + 1) as u32] {
            assert!(read_frame(&mut &size.to_ne_bytes()[..]).is_err());
        }
        assert!(read_frame(&mut &[5, 0, 0, 0, 1][..]).is_err());
        let mut wire = vec![];
        write_frame(&mut wire, b"example").unwrap();
        assert_eq!(&**read_frame(&mut &wire[..]).unwrap(), b"example");
    }
    #[test]
    fn requests_require_canonical_https_origins() {
        for origin in [
            "http://example.com",
            "https://example.com/path",
            "https://u@example.com",
            "https://example.com:443",
            "https://example.com\n",
        ] {
            let wire =
                serde_json::json!({"version":1,"operation":"login","origin":origin}).to_string();
            assert!(parse_request(wire.as_bytes()).is_err());
        }
        assert!(
            parse_request(br#"{"version":1,"operation":"login","origin":"https://example.com"}"#)
                .is_ok()
        );
    }
    #[test]
    fn credentials_require_exact_scope() {
        let fixture = r#"{"kind":"item","entity":{"scope":{"urls":["https://example.com/login"]},"credentials":[{"type":"basic-auth","username":{"value":"synthetic"},"password":{"value":"test"}}]}}"#;
        assert!(login(fixture, "https://example.com").is_some());
        for site in [
            "https://evil.example.com",
            "https://example.com:444",
            "http://example.com",
        ] {
            assert!(login(fixture, site).is_none());
        }
    }
    #[test]
    fn private_directories_reject_symlinks_and_public_access() {
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), Permissions::from_mode(0o700)).unwrap();
        assert!(private_directory(temp.path()).is_ok());
        let link = temp.path().join("link");
        std::os::unix::fs::symlink(temp.path(), &link).unwrap();
        assert!(private_directory(&link).is_err());
        fs::set_permissions(temp.path(), Permissions::from_mode(0o755)).unwrap();
        assert!(private_directory(temp.path()).is_err());
    }
}
