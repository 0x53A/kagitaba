//! Read-only Bitwarden inspection. Prints counts and warning categories only.
use std::{fs::File, process::ExitCode};

fn main() -> ExitCode {
    let mut args = std::env::args_os().skip(1);
    let Some(path) = args.next().filter(|_| args.next().is_none()) else {
        eprintln!("usage: inspect_bitwarden <unencrypted-bitwarden.json>");
        return ExitCode::FAILURE;
    };
    let input = match File::open(path) {
        Ok(input) => input,
        Err(_) => {
            eprintln!("could not open input file");
            return ExitCode::FAILURE;
        }
    };
    match kagitaba_cxf::bitwarden::from_reader(input) {
        Ok(converted) => {
            let report = converted.report();
            println!(
                "{} items, {} root collections",
                report.items, report.root_collections
            );
            for warning in &report.warnings {
                println!("source item {:?}: {:?}", warning.item_index, warning.kind);
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
