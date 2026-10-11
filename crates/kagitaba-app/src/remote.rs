//! Application-owned transport. Git handles configured origin authentication;
//! Store independently verifies fetched bytes before offering any acceptance.
use crate::backend::Event;
use kagitaba_core::crypto::PublicKey;
use kagitaba_store::{HistoryRelation, Store};
use std::{
    path::PathBuf,
    process::{Command, Stdio},
    sync::mpsc,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Fetch,
    Push,
}
pub struct Request {
    pub path: PathBuf,
    pub root: PublicKey,
    pub checkpoint: String,
    pub action: Action,
}
#[derive(Clone, Debug)]
pub struct Status {
    pub head: String,
    pub relation: HistoryRelation,
}
pub struct Report {
    pub path: PathBuf,
    pub checkpoint: String,
    pub action: Action,
    pub result: Result<Option<Status>, String>,
}

pub fn start(ctx: eframe::egui::Context, events: mpsc::Sender<Event>) -> mpsc::Sender<Request> {
    let (tx, rx) = mpsc::channel::<Request>();
    std::thread::spawn(move || {
        while let Ok(request) = rx.recv() {
            let result = run(&request);
            let _ = events.send(Event::Remote(Report {
                path: request.path,
                checkpoint: request.checkpoint,
                action: request.action,
                result,
            }));
            ctx.request_repaint();
        }
    });
    tx
}

fn git(request: &Request, args: &[&str]) -> Result<bool, String> {
    // A separate process group managed by timeout bounds transport/helpers too.
    // No shell, terminal prompts, hooks, raw output, or credential-bearing URLs
    // enter the UI. Configured credential helpers/SSH agent remain available.
    let status = Command::new("timeout")
        .args(["--kill-after=5s", "30s", "git", "--no-pager", "-C"])
        .arg(&request.path)
        .args([
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "credential.interactive=false",
            "-c",
            "protocol.ext.allow=never",
        ])
        .args(args)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GCM_INTERACTIVE", "never")
        .env("GIT_SSH_COMMAND", "ssh -o BatchMode=yes")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|_| {
            "Cannot start Git transport; install git, openssh and coreutils (timeout).".to_owned()
        })?;
    if matches!(status.code(), Some(124 | 137)) {
        return Err("Git transport timed out after 30 seconds.".into());
    }
    if status.code() == Some(127) {
        return Err("Git transport executable is unavailable.".into());
    }
    Ok(status.success())
}

fn run(request: &Request) -> Result<Option<Status>, String> {
    let checkpoint = kagitaba_store::parse_oid(&request.checkpoint).map_err(|e| e.to_string())?;
    let store = Store::open(&request.path, request.root.clone(), Some(checkpoint))
        .map_err(|e| e.to_string())?;
    if store.head != checkpoint {
        return Err("Wallet changed; fetch again before synchronizing.".into());
    }
    if !git(request, &["config", "--get", "remote.origin.url"])? {
        return Ok(None);
    }
    if !git(
        request,
        &[
            "fetch",
            "--no-tags",
            "--no-write-fetch-head",
            "--no-recurse-submodules",
            "origin",
            "+refs/heads/wallet:refs/remotes/origin/wallet",
        ],
    )? {
        return Err("Fetch failed. Check origin, network access and noninteractive Git authentication; the remote must have a wallet branch.".into());
    }
    let candidate = store.origin_head().map_err(|e| e.to_string())?;
    let relation = store
        .relation(candidate)
        .map_err(|e| format!("Fetched history was rejected: {e}"))?;
    if request.action == Action::Fetch {
        return Ok(Some(Status {
            head: candidate.to_string(),
            relation,
        }));
    }
    if relation.behind != 0 {
        return Err("Push stopped: remote changes need Pull or Merge. Fetch to refresh the available action.".into());
    }
    if relation.ahead != 0
        && !git(
            request,
            &[
                "push",
                "--no-verify",
                "--recurse-submodules=no",
                "origin",
                &format!("{}:refs/heads/wallet", request.checkpoint),
            ],
        )?
    {
        return Err("Push failed or was rejected. Local commits are retained; fetch to check for new remote changes, or check Git authentication.".into());
    }
    Ok(Some(Status {
        head: request.checkpoint.clone(),
        relation: HistoryRelation {
            ahead: 0,
            behind: 0,
        },
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use kagitaba_core::crypto::SoftwareIdentity;
    use kagitaba_store::{Signer, Snapshot};
    use p256::{
        ecdsa::{Signature, SigningKey, signature::Signer as _},
        pkcs8::EncodePublicKey,
    };
    use std::path::Path;

    struct Key {
        private: SigningKey,
        public: PublicKey,
    }
    impl Signer for Key {
        fn public_key(&self) -> &PublicKey {
            &self.public
        }
        fn sign(&self, bytes: &[u8]) -> kagitaba_store::Result<Vec<u8>> {
            let signature: Signature = self.private.sign(bytes);
            Ok(signature.to_der().as_bytes().to_vec())
        }
    }
    fn git_at(path: &Path, args: &[&str]) -> String {
        let output = Command::new("git")
            .arg("-C")
            .arg(path)
            .args(args)
            .output()
            .unwrap();
        assert!(output.status.success(), "synthetic Git setup failed");
        String::from_utf8(output.stdout).unwrap().trim().into()
    }
    fn fixture() -> (tempfile::TempDir, Key, Store, Store) {
        let dir = tempfile::tempdir().unwrap();
        let private = SigningKey::from_slice(&[12; 32]).unwrap();
        let public = PublicKey::from_der(
            private
                .verifying_key()
                .to_public_key_der()
                .unwrap()
                .as_bytes(),
        )
        .unwrap();
        let key = Key { private, public };
        let local = Store::create(
            &dir.path().join("local"),
            Snapshot::empty(
                SoftwareIdentity::from_bytes(&[8; 32]).unwrap().public_key(),
                key.public.clone(),
            )
            .unwrap(),
            &key,
        )
        .unwrap();
        let remote_path = dir.path().join("remote.git");
        git_at(
            dir.path(),
            &[
                "clone",
                "--bare",
                local.path.to_str().unwrap(),
                remote_path.to_str().unwrap(),
            ],
        );
        git_at(
            &local.path,
            &["remote", "add", "origin", remote_path.to_str().unwrap()],
        );
        let remote = Store::open(&remote_path, key.public.clone(), Some(local.head)).unwrap();
        (dir, key, local, remote)
    }
    fn request(store: &Store, action: Action) -> Request {
        Request {
            path: store.path.clone(),
            root: store.root_signer.clone(),
            checkpoint: store.head.to_string(),
            action,
        }
    }

    #[test]
    fn fetch_reports_verified_changes_without_accepting_and_push_is_explicit() {
        let (_dir, key, mut local, mut remote) = fixture();
        assert_eq!(
            run(&request(&local, Action::Fetch))
                .unwrap()
                .unwrap()
                .relation,
            HistoryRelation {
                ahead: 0,
                behind: 0
            }
        );
        remote
            .save(remote.snapshot.clone(), &key, "Remote update")
            .unwrap();
        let accepted = local.head;
        let index = std::fs::read(local.path.join(".git/index")).unwrap();
        // Fetch must not care about or overwrite working-copy edits.
        std::fs::write(local.path.join("kagitaba-format"), b"dirty").unwrap();
        let status = run(&request(&local, Action::Fetch)).unwrap().unwrap();
        assert_eq!(
            status.relation,
            HistoryRelation {
                ahead: 0,
                behind: 1
            }
        );
        assert_eq!(status.head, remote.head.to_string());
        assert_eq!(
            git_at(&local.path, &["rev-parse", "HEAD"]),
            accepted.to_string()
        );
        assert_eq!(std::fs::read(local.path.join(".git/index")).unwrap(), index);
        assert_eq!(
            std::fs::read(local.path.join("kagitaba-format")).unwrap(),
            b"dirty"
        );
        std::fs::write(local.path.join("kagitaba-format"), b"1\n").unwrap();
        local.accept(remote.head).unwrap();
        local
            .save(local.snapshot.clone(), &key, "Local update")
            .unwrap();
        assert_eq!(
            run(&request(&local, Action::Fetch))
                .unwrap()
                .unwrap()
                .relation,
            HistoryRelation {
                ahead: 1,
                behind: 0
            }
        );
        assert_ne!(
            git_at(&remote.path, &["rev-parse", "HEAD"]),
            local.head.to_string()
        );
        assert_eq!(
            run(&request(&local, Action::Push))
                .unwrap()
                .unwrap()
                .relation,
            HistoryRelation {
                ahead: 0,
                behind: 0
            }
        );
        assert_eq!(
            Store::open(&remote.path, key.public, Some(remote.head))
                .unwrap()
                .head,
            local.head
        );
    }

    #[test]
    fn divergence_requires_merge_and_push_never_discards_either_branch() {
        let (_dir, key, mut local, mut remote) = fixture();
        local.save(local.snapshot.clone(), &key, "Local").unwrap();
        remote
            .save(remote.snapshot.clone(), &key, "Remote")
            .unwrap();
        let before = (local.head, remote.head);
        assert_eq!(
            run(&request(&local, Action::Fetch))
                .unwrap()
                .unwrap()
                .relation,
            HistoryRelation {
                ahead: 1,
                behind: 1
            }
        );
        assert!(
            run(&request(&local, Action::Push))
                .unwrap_err()
                .contains("need Pull or Merge")
        );
        assert_eq!(
            git_at(&local.path, &["rev-parse", "HEAD"]),
            before.0.to_string()
        );
        assert_eq!(
            git_at(&remote.path, &["rev-parse", "HEAD"]),
            before.1.to_string()
        );
        local.merge_origin(&key).unwrap();
        run(&request(&local, Action::Push)).unwrap();
        assert!(Store::open(&remote.path, key.public, Some(before.1)).is_ok());
    }

    #[test]
    fn unsigned_remote_and_failed_transport_are_visible_without_exposing_output() {
        let (dir, key, local, remote) = fixture();
        let unsigned = git_at(
            &remote.path,
            &[
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@localhost",
                "commit-tree",
                "HEAD^{tree}",
                "-p",
                "HEAD",
                "-m",
                "Unsigned",
            ],
        );
        git_at(
            &remote.path,
            &["update-ref", "refs/heads/wallet", &unsigned],
        );
        let error = run(&request(&local, Action::Fetch)).unwrap_err();
        assert!(error.contains("Fetched history was rejected"));
        assert_eq!(
            Store::open(&local.path, key.public, Some(local.head))
                .unwrap()
                .head,
            local.head
        );
        git_at(
            &local.path,
            &[
                "remote",
                "set-url",
                "origin",
                dir.path().join("secret-token-value").to_str().unwrap(),
            ],
        );
        let error = run(&request(&local, Action::Fetch)).unwrap_err();
        assert!(error.contains("Fetch failed"));
        assert!(!error.contains("secret-token-value"));
        git_at(&local.path, &["remote", "remove", "origin"]);
        assert!(run(&request(&local, Action::Fetch)).unwrap().is_none());
    }

    #[test]
    fn rejected_push_reports_failure_and_preserves_signed_local_changes() {
        let (dir, key, mut local, _) = fixture();
        let normal = dir.path().join("normal-remote");
        local.backup_to(&normal).unwrap();
        git_at(&normal, &["config", "receive.denyCurrentBranch", "refuse"]);
        git_at(
            &local.path,
            &["remote", "set-url", "origin", normal.to_str().unwrap()],
        );
        let old = local.head;
        local
            .save(local.snapshot.clone(), &key, "Local pending")
            .unwrap();
        assert!(
            run(&request(&local, Action::Push))
                .unwrap_err()
                .contains("Push failed or was rejected")
        );
        assert_eq!(git_at(&normal, &["rev-parse", "HEAD"]), old.to_string());
        assert_eq!(
            git_at(&local.path, &["rev-parse", "HEAD"]),
            local.head.to_string()
        );
    }
}
