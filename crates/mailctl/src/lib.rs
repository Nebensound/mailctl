//! `mailctl`: an agent-friendly IMAP/SMTP tool for sorting mailboxes.
//!
//! It lists, shows, moves, marks read, creates folders and forwards to an allow
//! list. Every change addresses a mail by UID **and** checks its `Message-ID`
//! (or the stable [`types::MailRef`]) first, and is read back from the server
//! afterwards. There is deliberately no way to delete mail.

// The coverage job runs on nightly with `--cfg coverage_nightly` and leaves
// out the few I/O wrappers marked `coverage(off)`, each with its reason.
#![cfg_attr(coverage_nightly, feature(coverage_attribute))]
#![cfg_attr(
    coverage_nightly,
    allow(stable_features, reason = "the attribute may be stable by now")
)]

pub mod account;
pub mod adapters;
pub mod cache;
pub mod cli;
pub mod config;
pub mod discover;
pub mod error;
pub mod forward;
pub mod guard;
pub mod imap_wire;
pub mod model;
pub mod plan;
pub mod probe;
pub mod service;
pub mod setup;
pub mod store;
pub mod types;
pub mod utf7;

#[cfg(test)]
mod testing;
