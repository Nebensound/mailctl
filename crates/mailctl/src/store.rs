//! Abstractions over the mail server (IMAP) and the outgoing transport (SMTP).
//!
//! All decisions live in [`crate::service`] and work against these traits, so
//! they are tested against an in-memory mailbox. The real adapters in
//! [`crate::adapters`] stay thin.

use crate::error::Error;
use crate::types::{EmailAddress, MailboxName, MessageId, Uid};

/// IMAP system flag for read mail.
pub const FLAG_SEEN: &str = "\\Seen";
/// IMAP system flag for flagged mail.
pub const FLAG_FLAGGED: &str = "\\Flagged";
/// Keyword Apple Mail and others set on forwarded mail.
pub const FLAG_FORWARDED: &str = "$Forwarded";

/// Whether `flags` contains `flag`; IMAP flags compare case-insensitively.
#[must_use]
pub fn has_flag(flags: &[String], flag: &str) -> bool {
    flags.iter().any(|f| f.eq_ignore_ascii_case(flag))
}

/// A folder as listed by the server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FolderInfo {
    /// Decoded folder name.
    pub name: MailboxName,
    /// Hierarchy delimiter, if the server reports one.
    pub delimiter: Option<String>,
    /// Whether the folder can hold mail (`\Noselect` is not set).
    pub selectable: bool,
    /// RFC 6154 special use in lowercase (`sent`, `drafts`, `junk`, `trash`,
    /// `archive`, `all`, `flagged`), if the server reports one.
    pub special_use: Option<String>,
}

/// Header data of one mail as fetched from the server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawHeader {
    /// UID in the selected folder.
    pub uid: Uid,
    /// Flags, e.g. `\Seen`.
    pub flags: Vec<String>,
    /// Size of the full message in bytes.
    pub size: u32,
    /// Raw header block.
    pub header: Vec<u8>,
}

/// One complete mail as fetched from the server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawMessage {
    /// UID in the selected folder.
    pub uid: Uid,
    /// Flags, e.g. `\Seen`.
    pub flags: Vec<String>,
    /// Size as reported by the server (`RFC822.SIZE`), the same value as in
    /// [`RawHeader::size`], so both give the same [`crate::types::MailRef`].
    pub size: u32,
    /// The full RFC 5322 message.
    pub body: Vec<u8>,
}

/// Operations on one IMAP account. There is deliberately no delete operation.
pub trait MailStore {
    /// Lists all folders.
    ///
    /// # Errors
    /// Server errors.
    fn folders(&mut self) -> Result<Vec<FolderInfo>, Error>;
    /// Selects a folder for the following calls.
    ///
    /// # Errors
    /// Server errors, e.g. a missing folder.
    fn select(&mut self, folder: &MailboxName) -> Result<(), Error>;
    /// Opens a folder read-only (`EXAMINE`); the server rejects any change.
    ///
    /// # Errors
    /// Server errors, e.g. a missing folder.
    fn select_read_only(&mut self, folder: &MailboxName) -> Result<(), Error>;
    /// All UIDs in the selected folder, in any order.
    ///
    /// # Errors
    /// Server errors.
    fn uids(&mut self) -> Result<Vec<Uid>, Error>;
    /// Headers of the given UIDs; missing UIDs are left out.
    ///
    /// # Errors
    /// Server errors.
    fn headers(&mut self, uids: &[Uid]) -> Result<Vec<RawHeader>, Error>;
    /// The complete mail, without setting `\Seen`.
    ///
    /// # Errors
    /// Server errors.
    fn message(&mut self, uid: Uid) -> Result<Option<RawMessage>, Error>;
    /// Adds flags to a mail.
    ///
    /// # Errors
    /// Server errors.
    fn add_flags(&mut self, uid: Uid, flags: &[&str]) -> Result<(), Error>;
    /// Whether the server supports the `MOVE` extension.
    ///
    /// # Errors
    /// Server errors.
    fn supports_move(&mut self) -> Result<bool, Error>;
    /// Moves a mail from the selected folder to `target`.
    ///
    /// # Errors
    /// Server errors.
    fn move_to(&mut self, uid: Uid, target: &MailboxName) -> Result<(), Error>;
    /// UIDs in the selected folder whose `Message-ID` header matches.
    ///
    /// # Errors
    /// Server errors.
    fn find_message_id(&mut self, id: &MessageId) -> Result<Vec<Uid>, Error>;
    /// Creates a folder.
    ///
    /// # Errors
    /// Server errors.
    fn create_folder(&mut self, name: &MailboxName) -> Result<(), Error>;
    /// Stores a message in a folder with the given flags.
    ///
    /// # Errors
    /// Server errors.
    fn append(&mut self, folder: &MailboxName, message: &[u8], flags: &[&str])
    -> Result<(), Error>;
}

/// Outgoing mail transport.
pub trait MailSender {
    /// Sends a finished message.
    ///
    /// # Errors
    /// Transport errors.
    fn send(&mut self, from: &EmailAddress, to: &EmailAddress, message: &[u8])
    -> Result<(), Error>;
}
