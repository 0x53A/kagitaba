//! Read-only plaintext CXF inspection. Prints counts, never credentials.
use std::{fs::File, process::ExitCode};

use kagitaba_cxf::Document;

fn main() -> ExitCode {
    let mut args = std::env::args_os().skip(1);
    let Some(path) = args.next().filter(|_| args.next().is_none()) else {
        eprintln!("usage: inspect_cxf <plaintext-cxf.json>");
        return ExitCode::FAILURE;
    };
    let input = match File::open(path) {
        Ok(input) => input,
        Err(_) => {
            eprintln!("could not open input file");
            return ExitCode::FAILURE;
        }
    };
    match Document::from_reader(input) {
        Ok(document) => {
            let accounts = document.as_json()["accounts"].as_array().unwrap();
            let items: usize = accounts
                .iter()
                .map(|a| a["items"].as_array().unwrap().len())
                .sum();
            let roots: usize = accounts
                .iter()
                .map(|a| a["collections"].as_array().unwrap().len())
                .sum();
            println!(
                "{} accounts, {items} items, {roots} root collections",
                accounts.len()
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
