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
    /// Configured accounts; may be empty, e.g. before the first `account add`.
    #[serde(default)]
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
    /// Store a copy of forwarded mail in `sent_folder`. `false` for servers
    /// that file mail sent through their SMTP server themselves (Gmail,
    /// Microsoft 365), which would otherwise end up with two copies.
    #[serde(default = "default_true")]
    pub save_sent_copy: bool,
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

fn default_true() -> bool {
    true
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

    /// The keychain item's account attribute: the account's own name, so two
    /// accounts with the same login on different servers never share (and
    /// overwrite) a stored password.
    #[must_use]
    pub fn keychain_account(&self) -> &str {
        &self.name
    }

    /// The folder to store forwarded copies in, if mailctl stores them itself.
    #[must_use]
    pub fn sent_copy_folder(&self) -> Option<&MailboxName> {
        self.save_sent_copy.then_some(&self.sent_folder)
    }

    /// The SMTP security to use: as configured, else derived from the port.
    #[must_use]
    pub fn smtp_tls(&self) -> Security {
        self.smtp_security
            .unwrap_or_else(|| Security::for_smtp_port(self.smtp_port))
    }
}

/// Checks an account name: not blank and without control characters, since it
/// is also the keychain item's account and is typed on the command line.
///
/// # Errors
/// [`Error::Config`] naming the problem.
pub fn validate_account_name(name: &str) -> Result<(), Error> {
    if name.trim().is_empty() {
        return Err(Error::Config("account name must not be empty".into()));
    }
    if name.chars().any(char::is_control) {
        return Err(Error::Config(format!(
            "account name {name:?} contains control characters"
        )));
    }
    Ok(())
}

/// Source of an account password.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum PasswordSource {
    /// macOS keychain item with this service name; the item's account is the
    /// mailctl account name (see [`AccountConfig::keychain_account`]).
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

    /// Exposes the password for login.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

/// The `security -i` command that stores `secret` as a generic password.
///
/// # Errors
/// [`Error::Secret`] if any value contains a control character: `security -i`
/// reads commands line by line, so one could end the command early or start
/// another.
pub fn keychain_store_command(
    service: &str,
    account: &str,
    secret: &Secret,
) -> Result<String, Error> {
    if [service, account, secret.expose()]
        .iter()
        .any(|value| value.chars().any(char::is_control))
    {
        return Err(Error::Secret {
            account: account.to_owned(),
            reason: "control characters cannot be stored in the keychain".into(),
        });
    }
    let quote = |s: &str| format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""));
    Ok(format!(
        "add-generic-password -U -s {} -a {} -w {}\n",
        quote(service),
        quote(account),
        quote(secret.expose())
    ))
}

/// The password from `security find-generic-password -g`, which prints it on
/// standard error as `password: "text"`, or as `password: 0x<hex>  "..."` when
/// it is not printable ASCII. Unlike `-w`, the two forms cannot be confused:
/// a printable password that happens to look like hex stays as it is.
///
/// # Errors
/// A reason, if there is no `password:` line or the hex is not UTF-8.
pub fn keychain_password(security_stderr: &str) -> Result<String, String> {
    let line = security_stderr
        .lines()
        .find_map(|l| l.strip_prefix("password: "))
        .ok_or("`security` printed no password")?;
    if let Some(hex) = line.strip_prefix("0x") {
        let digits = hex.split_whitespace().next().unwrap_or_default();
        let bytes: Vec<u8> = digits
            .as_bytes()
            .chunks(2)
            .map(|pair| {
                std::str::from_utf8(pair)
                    .ok()
                    .and_then(|h| u8::from_str_radix(h, 16).ok())
            })
            .collect::<Option<_>>()
            .ok_or("`security` printed invalid hex")?;
        return String::from_utf8(bytes).map_err(|_| "password is not UTF-8".to_owned());
    }
    Ok(line
        .strip_prefix('"')
        .and_then(|rest| rest.strip_suffix('"'))
        .unwrap_or(line)
        .to_owned())
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
    /// Returns [`Error::Config`] for syntax errors and invalid or duplicate
    /// account names. No accounts at all is valid (a fresh setup, or after
    /// removing the last one); commands that need one report it as unknown.
    pub fn parse(text: &str) -> Result<Self, Error> {
        let config: Self = toml::from_str(text).map_err(|e| Error::Config(e.to_string()))?;
        let mut seen = std::collections::HashSet::new();
        for account in &config.accounts {
            validate_account_name(&account.name)?;
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
            .keychain(service, account.keychain_account())
            .map(Secret::new)
            .map_err(fail),
    }
}

#[cfg(test)]
#[path = "tests/config.rs"]
mod tests;
