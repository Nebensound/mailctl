//! Thin adapters to the real network and operating system.
//!
//! They contain no decisions. The IMAP and SMTP adapters are tested end to
//! end against scripted servers; the parts that need the real network, a
//! terminal or the keychain are marked `coverage(off)` with their reason
//! (see the README section "Coverage").

pub mod imap;
pub mod net;
pub mod smtp;
pub mod system;
