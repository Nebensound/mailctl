//! Binary entry point; all logic lives in the library.

#![cfg_attr(coverage_nightly, feature(coverage_attribute))]
#![cfg_attr(
    coverage_nightly,
    allow(stable_features, reason = "the attribute may be stable by now")
)]

use std::process::ExitCode;

use clap::Parser as _;
use mailctl::adapters::system::SystemBackend;
use mailctl::cli::{Cli, run};

// Coverage: process entry point; the release job runs the binary as a smoke test.
#[cfg_attr(coverage_nightly, coverage(off))]
fn main() -> ExitCode {
    let mut stdout = std::io::stdout().lock();
    ExitCode::from(run(&Cli::parse(), &SystemBackend, &mut stdout))
}
