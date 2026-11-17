//! Typed errors of the library.

/// All errors the library reports.
#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    /// A value from the command line, a plan or the config is invalid.
    #[error("invalid input: {0}")]
    InvalidInput(String),
    /// The configuration could not be read or parsed.
    #[error("configuration: {0}")]
    Config(String),
    /// No password could be obtained for an account.
    #[error("no password for account {account}: {reason}")]
    Secret {
        /// Account name.
        account: String,
        /// Why the lookup failed.
        reason: String,
    },
    /// The mail server reported an error.
    #[error("mail server: {0}")]
    Store(String),
    /// Sending via SMTP failed.
    #[error("sending failed: {0}")]
    Send(String),
    /// The requested account is not configured.
    #[error("unknown account: {0}")]
    UnknownAccount(String),
    /// No mail with this UID exists in the selected folder.
    #[error("no mail with UID {0} in this folder")]
    NotFound(u32),
    /// The mail at the UID is not the expected one.
    #[error("Message-ID mismatch at UID {uid}: expected {expected}, found {found}")]
    MessageIdMismatch {
        /// The UID that was checked.
        uid: u32,
        /// The expected `Message-ID` or mail reference.
        expected: String,
        /// The same kind of value for the mail found on the server: its
        /// `Message-ID` (or "no Message-ID"), or its mail reference.
        found: String,
    },
    /// The forward recipient is not on the allow list.
    #[error("forwarding to {0} is not allowed by the configuration")]
    ForwardNotAllowed(String),
    /// The mail already carries the `$Forwarded` flag.
    #[error("mail at UID {0} was already forwarded")]
    AlreadyForwarded(u32),
    /// The server lacks the IMAP `MOVE` extension and the mail has no
    /// `Message-ID`, so a copy could not be confirmed before the original is
    /// removed.
    #[error(
        "server does not support MOVE and the mail has no Message-ID; refusing to copy and remove it, the copy could not be confirmed"
    )]
    MoveUnsupported,
    /// The server has neither `MOVE` nor `UIDPLUS`, and other mails in the
    /// folder are already marked `\Deleted`: a plain `EXPUNGE` would remove
    /// them too.
    #[error(
        "server supports neither MOVE nor UIDPLUS and {count} other mail(s) in {folder} are marked deleted; refusing to expunge, it would remove them too"
    )]
    OthersMarkedDeleted {
        /// Source folder.
        folder: String,
        /// Number of other mails marked `\Deleted`.
        count: usize,
    },
    /// The folder does not exist.
    #[error("folder does not exist: {0}")]
    FolderMissing(String),
    /// The folder already exists.
    #[error("folder already exists: {0}")]
    FolderExists(String),
    /// Server discovery found nothing usable; the message lists what was tried.
    #[error("{0}")]
    NoServerFound(String),
    /// The account's access level does not allow this operation.
    #[error("account {account} is set to `{granted}`; this needs `{needed}`")]
    AccessDenied {
        /// Account name.
        account: String,
        /// Required level.
        needed: &'static str,
        /// Configured level.
        granted: &'static str,
    },
    /// A change was made but could not be confirmed afterwards.
    #[error("change not confirmed: {0}")]
    NotConfirmed(String),
    /// The main step succeeded, a following one failed; repeating the command
    /// is not the fix.
    #[error("partly done: {0}")]
    Partial(String),
    /// The server forgets custom keywords in this folder, so `$Forwarded`
    /// cannot protect against forwarding a mail twice.
    #[error(
        "the server does not keep $Forwarded in {0}; refusing to forward, a repeat could not be detected"
    )]
    KeywordsUnsupported(String),
}
