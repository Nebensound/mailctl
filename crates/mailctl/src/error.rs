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
    /// The mail at the UID has a different `Message-ID` than expected.
    #[error("Message-ID mismatch at UID {uid}: expected {expected}, found {found}")]
    MessageIdMismatch {
        /// The UID that was checked.
        uid: u32,
        /// The expected `Message-ID`.
        expected: String,
        /// The `Message-ID` found on the server.
        found: String,
    },
    /// The forward recipient is not on the allow list.
    #[error("forwarding to {0} is not allowed by the configuration")]
    ForwardNotAllowed(String),
    /// The mail already carries the `$Forwarded` flag.
    #[error("mail at UID {0} was already forwarded")]
    AlreadyForwarded(u32),
    /// The server lacks the IMAP `MOVE` extension; copying and expunging is refused.
    #[error("server does not support MOVE; refusing to copy and expunge")]
    MoveUnsupported,
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
}
