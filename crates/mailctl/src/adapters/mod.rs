//! Thin adapters to the real network and operating system.
//!
//! They contain no decisions; the parts that need a live server, the network,
//! a terminal or the keychain are marked `coverage(off)` with their reason
//! (see the README section "Coverage").

pub mod imap;
pub mod net;
pub mod smtp;
pub mod system;
