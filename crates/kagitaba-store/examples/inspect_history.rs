//! Read-only topology/signature diagnostic. Does not decrypt or print entries.
//! Genesis inspection is not an independent trust decision or freshness proof.
use kagitaba_store::Store;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = PathBuf::from(std::env::args().nth(1).ok_or("provide a wallet path")?);
    let root = Store::inspect_root(&path)?;
    let store = Store::open(&path, root, None)?;
    println!("History signatures and merge policy verified against the genesis signing key.");
    println!("This does not establish independent trust or freshness.");
    println!("Head: {}", store.head);
    println!(
        "Participants: {}; entries: {}",
        store.snapshot.wallet.participants().len(),
        store.snapshot.wallet.entries().len()
    );
    Ok(())
}
