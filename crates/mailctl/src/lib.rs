//! `mailctl`: an agent-friendly IMAP/SMTP tool for sorting mailboxes.
//!
//! It lists, shows, moves, marks read, creates folders and forwards to an allow
//! list. Every change addresses a mail by UID **and** checks its `Message-ID`
//! (or the stable [`types::MailRef`]) first, and is read back from the server
//! afterwards. There is deliberately no way to delete mail.

pub mod account;
pub mod adapters;
pub mod cache;
pub mod cli;
pub mod config;
pub mod discover;
pub mod error;
pub mod forward;
pub mod guard;
pub mod model;
pub mod plan;
pub mod service;
pub mod setup;
pub mod store;
pub mod types;
pub mod utf7;

#[cfg(test)]
mod testing;
