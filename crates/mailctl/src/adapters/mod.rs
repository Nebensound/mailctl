//! Thin adapters to the real network and operating system.
//!
//! They contain no decisions and are excluded from the coverage gate; see the
//! README section "Coverage deviation".

pub mod imap;
pub mod net;
pub mod smtp;
pub mod system;
