//! Configuration file: accounts and the forward allow list. Passwords never live here.

use std::fmt;

use serde::Deserialize;

use crate::error::Error;
use crate::types::{EmailAddress, MailboxName};

use crate::types::{
    IMAPS_PORT as DEFAULT_IMAP_PORT, SUBMISSION_PORT as DEFAULT_SMTP_PORT, Security,
};

/// The whole configuration file.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Recipients that `forward` may send to. Anything else is refused.
    #[serde(default)]
    pub forward_allowlist: Vec<EmailAddress>,
    /// Configured accounts.
    pub accounts: Vec<AccountConfig>,
}

/// One mail account.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountConfig {
    /// Short name used on the command line, e.g. `icloud`.
    pub name: String,
    /// Login name for IMAP (and SMTP unless `smtp_user` is set).
    pub user: String,
    /// Sender address used when forwarding.
    pub address: EmailAddress,
    /// IMAP host.
    pub imap_host: String,
    /// IMAP port with implicit TLS.
    #[serde(default = "default_imap_port")]
    pub imap_port: u16,
    /// SMTP host for forwarding.
    pub smtp_host: String,
    /// SMTP port (STARTTLS).
    #[serde(default = "default_smtp_port")]
    pub smtp_port: u16,
    /// SMTP security as discovered: `tls` or `starttls`. Without it, implicit
    /// TLS on port 465 and STARTTLS on any other port.
    #[serde(default)]
    pub smtp_security: Option<Security>,
    /// Separate SMTP login, if it differs from `user`.
    #[serde(default)]
    pub smtp_user: Option<String>,
    /// Folder for sent mail; forwarded copies are stored there.
    pub sent_folder: MailboxName,
    /// Where the password comes from.
    pub password: PasswordSource,
    /// What mailctl may do in this account; defaults to read-only.
    #[serde(default)]
    pub access: Access,
}

/// What mailctl may do in an account. Each level includes the ones below it.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Default,
    Deserialize,
    serde::Serialize,
    clap::ValueEnum,
)]
#[serde(rename_all = "lowercase")]
pub enum Access {
    /// List and read only; folders are opened with `EXAMINE`, no flag changes at all.
    #[default]
    Read,
    /// Also mark mail as read.
    Flag,
    /// Also move mail and create folders.
    Organize,
    /// Also forward mail to addresses on the allow list.
    Send,
}

impl Access {
    /// The name used in the configuration.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Flag => "flag",
            Self::Organize => "organize",
            Self::Send => "send",
        }
    }

    /// Fails unless this level includes `needed`.
    ///
    /// # Errors
    /// [`Error::AccessDenied`].
    pub fn require(self, account: &str, needed: Self) -> Result<(), Error> {
        if self >= needed {
            Ok(())
        } else {
            Err(Error::AccessDenied {
                account: account.to_owned(),
                needed: needed.as_str(),
                granted: self.as_str(),
            })
        }
    }
}

fn default_imap_port() -> u16 {
    DEFAULT_IMAP_PORT
}

fn default_smtp_port() -> u16 {
    DEFAULT_SMTP_PORT
}

impl AccountConfig {
    /// The SMTP login name.
    #[must_use]
    pub fn smtp_login(&self) -> &str {
        self.smtp_user.as_deref().unwrap_or(&self.user)
    }

    /// The SMTP security to use: as configured, else derived from the port.
    #[must_use]
    pub fn smtp_tls(&self) -> Security {
        self.smtp_security
            .unwrap_or_else(|| Security::for_smtp_port(self.smtp_port))
    }
}

/// Source of an account password.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum PasswordSource {
    /// macOS keychain item with this service name; the account is the login name.
    Keychain(String),
    /// Environment variable with this name (for cloud agents and CI).
    Env(String),
}

/// A password that never shows up in debug output.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(String);

impl Secret {
    /// Wraps a password.
    #[must_use]
    pub fn new(value: String) -> Self {
        Self(value)
    }

    /// A password typed or piped in by the user, without the trailing line
    /// break.
    ///
    /// # Errors
    /// [`Error::InvalidInput`] for an empty password or one with control
    /// characters such as an inner line break: those cannot be stored safely
    /// in the keychain and are almost always a paste mistake.
    pub fn entered(raw: &str) -> Result<Self, Error> {
        let value = raw.trim_end_matches(['\r', '\n']);
        if value.is_empty() {
            return Err(Error::InvalidInput("empty password".into()));
        }
        if value.chars().any(char::is_control) {
            return Err(Error::InvalidInput(
                "password contains control characters such as a line break".into(),
            ));
        }
        Ok(Self(value.to_owned()))
    }

    /// Reads the output of `security find-generic-password -w`. `security`
    /// prints passwords with non-ASCII bytes as hex digits, so a hex string
    /// that decodes to UTF-8 with a non-ASCII character is decoded; any other
    /// value is taken as it is.
    #[must_use]
    pub fn from_keychain_output(raw: &str) -> Self {
        let value = raw.trim_end_matches('\n');
        Self(decode_hex_password(value).unwrap_or_else(|| value.to_owned()))
    }

    /// Exposes the password for login.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

fn decode_hex_password(value: &str) -> Option<String> {
    let hex = !value.is_empty()
        && value.len().is_multiple_of(2)
        && value.bytes().all(|b| b.is_ascii_hexdigit());
    if !hex {
        return None;
    }
    let bytes: Vec<u8> = value
        .as_bytes()
        .chunks_exact(2)
        .filter_map(|pair| {
            std::str::from_utf8(pair)
                .ok()
                .and_then(|h| u8::from_str_radix(h, 16).ok())
        })
        .collect();
    // `security` switches to hex only for non-ASCII bytes; an all-ASCII
    // result (`123456` → 0x12 0x34 0x56) was printed as it is.
    if bytes.is_ascii() {
        return None;
    }
    String::from_utf8(bytes).ok()
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(***)")
    }
}

/// Looks up secrets; implemented by the binary for the real keychain and environment.
pub trait SecretLookup {
    /// Reads an environment variable.
    fn env(&self, name: &str) -> Option<String>;
    /// Reads a keychain item.
    ///
    /// # Errors
    /// Returns a human-readable reason when the item cannot be read.
    fn keychain(&self, service: &str, account: &str) -> Result<String, String>;
}

impl Config {
    /// Parses the TOML configuration and checks it for consistency.
    ///
    /// # Errors
    /// Returns [`Error::Config`] for syntax errors, empty or duplicate account names
    /// and an empty account list.
    pub fn parse(text: &str) -> Result<Self, Error> {
        let config: Self = toml::from_str(text).map_err(|e| Error::Config(e.to_string()))?;
        if config.accounts.is_empty() {
            return Err(Error::Config("no accounts configured".into()));
        }
        let mut seen = std::collections::HashSet::new();
        for account in &config.accounts {
            if account.name.trim().is_empty() {
                return Err(Error::Config("account name must not be empty".into()));
            }
            if !seen.insert(account.name.as_str()) {
                return Err(Error::Config(format!(
                    "duplicate account: {}",
                    account.name
                )));
            }
        }
        Ok(config)
    }

    /// Finds an account by name.
    ///
    /// # Errors
    /// Returns [`Error::UnknownAccount`] if no account has this name.
    pub fn account(&self, name: &str) -> Result<&AccountConfig, Error> {
        self.accounts
            .iter()
            .find(|a| a.name == name)
            .ok_or_else(|| Error::UnknownAccount(name.to_owned()))
    }

    /// Whether `forward` may send to this address.
    #[must_use]
    pub fn forward_allowed(&self, to: &EmailAddress) -> bool {
        self.forward_allowlist.contains(to)
    }
}

/// Resolves the password of an account.
///
/// # Errors
/// Returns [`Error::Secret`] if the source yields nothing.
pub fn resolve_password(
    account: &AccountConfig,
    lookup: &dyn SecretLookup,
) -> Result<Secret, Error> {
    let fail = |reason: String| Error::Secret {
        account: account.name.clone(),
        reason,
    };
    match &account.password {
        PasswordSource::Env(var) => lookup
            .env(var)
            .filter(|v| !v.is_empty())
            .map(Secret::new)
            .ok_or_else(|| fail(format!("environment variable {var} is not set"))),
        PasswordSource::Keychain(service) => lookup
            .keychain(service, &account.user)
            .map(Secret::new)
            .map_err(fail),
    }
}

#[cfg(test)]
#[path = "tests/config.rs"]
mod tests;
