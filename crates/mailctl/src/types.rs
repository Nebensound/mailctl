//! Validated domain values used throughout the crate.

use std::fmt::{self, Write as _};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::Error;

/// IMAP with implicit TLS.
pub const IMAPS_PORT: u16 = 993;
/// SMTP submission with STARTTLS.
pub const SUBMISSION_PORT: u16 = 587;
/// SMTP submission with implicit TLS.
pub const SUBMISSIONS_PORT: u16 = 465;

/// Whether SMTP on `port` speaks TLS from the first byte (465) instead of
/// upgrading with STARTTLS, when nothing else is known.
#[must_use]
pub fn smtp_implicit_tls(port: u16) -> bool {
    port == SUBMISSIONS_PORT
}

/// Transport security of a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Security {
    /// TLS from the first byte (IMAP 993, SMTP 465).
    Tls,
    /// Plain connection upgraded with `STARTTLS` (SMTP 587).
    StartTls,
}

impl Security {
    /// The usual security for SMTP on `port`: implicit TLS on 465, else STARTTLS.
    #[must_use]
    pub fn for_smtp_port(port: u16) -> Self {
        if smtp_implicit_tls(port) {
            Self::Tls
        } else {
            Self::StartTls
        }
    }

    /// The name used in the configuration file.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tls => "tls",
            Self::StartTls => "starttls",
        }
    }
}

/// An IMAP UID within one mailbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Uid(u32);

impl Uid {
    /// Creates a UID; IMAP UIDs are never zero.
    ///
    /// # Errors
    /// Returns [`Error::InvalidInput`] for zero.
    pub fn new(value: u32) -> Result<Self, Error> {
        if value == 0 {
            return Err(Error::InvalidInput("UID must not be zero".into()));
        }
        Ok(Self(value))
    }

    /// The numeric value.
    #[must_use]
    pub fn get(self) -> u32 {
        self.0
    }
}

impl fmt::Display for Uid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A normalized `Message-ID` header value without angle brackets.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct MessageId(String);

impl MessageId {
    /// Parses a header value, accepting it with or without angle brackets.
    ///
    /// # Errors
    /// Returns [`Error::InvalidInput`] for empty values or values with whitespace.
    pub fn parse(raw: &str) -> Result<Self, Error> {
        let trimmed = raw.trim();
        let inner = trimmed
            .strip_prefix('<')
            .and_then(|s| s.strip_suffix('>'))
            .unwrap_or(trimmed);
        if inner.is_empty() || inner.chars().any(char::is_whitespace) {
            return Err(Error::InvalidInput(format!("invalid Message-ID: {raw:?}")));
        }
        Ok(Self(inner.to_owned()))
    }

    /// A new `Message-ID` for a message sent from `from`:
    /// `mailctl-<time>-<random>-<counter>@<domain>`. `random` keeps two
    /// forwards in the same second, or from two processes, apart. Valid by
    /// construction, because an [`EmailAddress`] contains no whitespace.
    #[must_use]
    pub fn generated(time: u64, random: u64, counter: u32, from: &EmailAddress) -> Self {
        Self(format!(
            "mailctl-{time}-{random:016x}-{counter}@{}",
            from.domain()
        ))
    }

    /// The value without angle brackets.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for MessageId {
    type Error = Error;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<MessageId> for String {
    fn from(value: MessageId) -> Self {
        value.0
    }
}

impl fmt::Display for MessageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A mailbox (folder) name as shown to users, already decoded from modified UTF-7.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct MailboxName(String);

impl MailboxName {
    /// Creates a mailbox name.
    ///
    /// # Errors
    /// Returns [`Error::InvalidInput`] for empty names or names with control characters.
    pub fn new(raw: &str) -> Result<Self, Error> {
        if raw.is_empty() || raw.chars().any(char::is_control) {
            return Err(Error::InvalidInput(format!(
                "invalid mailbox name: {raw:?}"
            )));
        }
        Ok(Self(raw.to_owned()))
    }

    /// The standard inbox, valid by construction.
    #[must_use]
    pub fn inbox() -> Self {
        Self("INBOX".to_owned())
    }

    /// The decoded name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for MailboxName {
    type Error = Error;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(&value)
    }
}

impl From<MailboxName> for String {
    fn from(value: MailboxName) -> Self {
        value.0
    }
}

impl fmt::Display for MailboxName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A plain e-mail address such as `accounting@example.com`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct EmailAddress(String);

impl EmailAddress {
    /// Parses an address; comparison is case-insensitive, so it is stored lowercased.
    ///
    /// # Errors
    /// Returns [`Error::InvalidInput`] unless the value has exactly one `@` with
    /// non-empty parts and no whitespace or angle brackets.
    pub fn parse(raw: &str) -> Result<Self, Error> {
        let value = raw.trim();
        let valid = match value.split_once('@') {
            Some((local, domain)) => {
                !local.is_empty()
                    && domain.contains('.')
                    && !domain.contains('@')
                    && !value
                        .chars()
                        .any(|c| c.is_whitespace() || c == '<' || c == '>')
            }
            None => false,
        };
        if !valid {
            return Err(Error::InvalidInput(format!(
                "invalid e-mail address: {raw:?}"
            )));
        }
        Ok(Self(value.to_lowercase()))
    }

    /// The address.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The part after `@`.
    #[must_use]
    pub fn domain(&self) -> &str {
        self.0.rsplit('@').next().unwrap_or_default()
    }
}

impl TryFrom<String> for EmailAddress {
    type Error = Error;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<EmailAddress> for String {
    fn from(value: EmailAddress) -> Self {
        value.0
    }
}

impl fmt::Display for EmailAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A stable short reference for one mail, derived from a SHA-256 hash.
///
/// The same mail always gets the same reference, in every run and every
/// account, so people and agents can talk about it without a counter.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct MailRef(String);

/// Number of hex characters in a [`MailRef`] (40 bits).
const MAIL_REF_LEN: usize = 10;

impl MailRef {
    /// Derives the reference from the `Message-ID`.
    #[must_use]
    pub fn from_message_id(id: &MessageId) -> Self {
        Self::hash(&["mid", id.as_str()])
    }

    /// Fallback for mails without `Message-ID`: date, sender, subject and size.
    #[must_use]
    pub fn from_fallback(date: &str, from: &str, subject: &str, size: u32) -> Self {
        Self::hash(&["fallback", date, from, subject, &size.to_string()])
    }

    fn hash(parts: &[&str]) -> Self {
        let mut hasher = Sha256::new();
        for part in parts {
            hasher.update(part.as_bytes());
            hasher.update([0_u8]);
        }
        let hex = hasher
            .finalize()
            .iter()
            .fold(String::new(), |mut acc, byte| {
                let _ = write!(acc, "{byte:02x}");
                acc
            });
        Self(hex.chars().take(MAIL_REF_LEN).collect())
    }

    /// Parses a reference given by a user or agent.
    ///
    /// # Errors
    /// Returns [`Error::InvalidInput`] unless it is exactly ten lowercase hex digits.
    pub fn parse(raw: &str) -> Result<Self, Error> {
        let value = raw.trim();
        if value.len() == MAIL_REF_LEN
            && value
                .chars()
                .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
        {
            Ok(Self(value.to_owned()))
        } else {
            Err(Error::InvalidInput(format!(
                "invalid mail reference: {raw:?}"
            )))
        }
    }

    /// The reference string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// What a changing command expects to find at a UID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expect {
    /// The exact `Message-ID`.
    MessageId(MessageId),
    /// The stable short reference.
    Ref(MailRef),
}

impl Expect {
    /// Ten lowercase hex digits are a reference, anything else a `Message-ID`.
    ///
    /// # Errors
    /// Returns [`Error::InvalidInput`] if it is neither.
    pub fn parse(raw: &str) -> Result<Self, Error> {
        MailRef::parse(raw)
            .map(Self::Ref)
            .or_else(|_| MessageId::parse(raw).map(Self::MessageId))
    }
}

impl fmt::Display for MailRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
#[path = "tests/types.rs"]
mod tests;
