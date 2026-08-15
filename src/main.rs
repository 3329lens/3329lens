//! 3329lens — cryptographic inventory scanner.
//!
//! Thin entry point: parse arguments, dispatch, map errors to an exit code.
//! Exit codes: 0 success, 1 operational error, 2 vulnerability gate failure
//! (see `--fail-on`, raised from within the scan handler).

use clap::Parser;

use lens3329::cli::{run, Cli};

fn main() {
    let cli = Cli::parse();

    if let Err(e) = run(cli.command) {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}
