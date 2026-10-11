//! Explicit offline transfer with a caller-provided trusted signing key.
use kagitaba_core::crypto::PublicKey;
use kagitaba_store::{Store, parse_oid};
use std::{
    fs,
    io::{Read, Write},
    path::Path,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 7 || !matches!(args[1].as_str(), "export" | "import") {
        return Err("usage: browser_transfer export|import WALLET TRUSTED_ROOT_PEM CHECKPOINT TRANSFER_JSON --confirmed-trust".into());
    }
    if args[6] != "--confirmed-trust" {
        return Err("Confirm the independently checked trust root and checkpoint".into());
    }
    let root = PublicKey::from_pem(&fs::read_to_string(&args[3])?)?;
    let checkpoint = parse_oid(&args[4])?;
    let mut store = Store::open(Path::new(&args[2]), root, Some(checkpoint))?;
    match args[1].as_str() {
        "export" => {
            let data = store.export_transfer()?;
            let mut options = fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut f = options.open(&args[5])?;
            f.write_all(&data)?;
            f.sync_all()?;
        }
        "import" => {
            let mut data = Vec::new();
            fs::File::open(&args[5])?
                .take(768 * 1024 * 1024 + 1)
                .read_to_end(&mut data)?;
            store.import_transfer(&data)?;
        }
        _ => unreachable!(),
    }
    println!("Accepted checkpoint: {}", store.head);
    Ok(())
}
