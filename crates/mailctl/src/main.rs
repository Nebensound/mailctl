//! Binary entry point; all logic lives in the library.

use std::process::ExitCode;

use clap::Parser as _;
use mailctl::adapters::system::SystemBackend;
use mailctl::cli::{Cli, run};

fn main() -> ExitCode {
    let mut stdout = std::io::stdout().lock();
    ExitCode::from(run(&Cli::parse(), &SystemBackend, &mut stdout))
}
