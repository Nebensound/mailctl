//! Configuration file: accounts and the forward allow list. Passwords never live here.

use std::fmt;

use serde::Deserialize;

use crate::error::Error;
use crate::types::{EmailAddress, MailboxName};

/// Default IMAP port (implicit TLS).
const DEFAULT_IMAP_PORT: u16 = 993;
/// Default SMTP submission port (STARTTLS).
const DEFAULT_SMTP_PORT: u16 = 587;

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

    /// Exposes the password for login.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
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
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
forward_allowlist = ["accounting@example.com"]

[[accounts]]
name = "icloud"
user = "alice@example.com"
address = "alice@example.com"
imap_host = "imap.mail.me.com"
smtp_host = "smtp.mail.me.com"
sent_folder = "Sent Messages"
password = { keychain = "mailctl" }

[[accounts]]
name = "work"
user = "alice@example.com"
address = "alice@example.com"
imap_host = "mail.example"
imap_port = 1993
smtp_host = "mail.example"
smtp_port = 465
smtp_user = "submit"
sent_folder = "INBOX.Sent"
password = { env = "MAILCTL_PW_WORK" }
access = "organize"
"#;

    struct Fake {
        env: Option<String>,
        keychain: Result<String, String>,
    }

    impl SecretLookup for Fake {
        fn env(&self, _name: &str) -> Option<String> {
            self.env.clone()
        }
        fn keychain(&self, _service: &str, _account: &str) -> Result<String, String> {
            self.keychain.clone()
        }
    }

    #[test]
    fn parses_sample_with_defaults() -> Result<(), Error> {
        let config = Config::parse(SAMPLE)?;
        let icloud = config.account("icloud")?;
        assert_eq!(icloud.imap_port, 993);
        assert_eq!(icloud.smtp_port, 587);
        assert_eq!(icloud.smtp_login(), "alice@example.com");
        let ns = config.account("work")?;
        assert_eq!(ns.imap_port, 1993);
        assert_eq!(ns.smtp_login(), "submit");
        assert!(config.forward_allowed(&EmailAddress::parse("Accounting@example.com")?));
        assert!(!config.forward_allowed(&EmailAddress::parse("x@y.de")?));
        assert_eq!(
            config.account("nope"),
            Err(Error::UnknownAccount("nope".into()))
        );
        Ok(())
    }

    #[test]
    fn rejects_bad_configs() {
        assert!(matches!(Config::parse("nonsense ="), Err(Error::Config(_))));
        assert!(matches!(
            Config::parse("accounts = []"),
            Err(Error::Config(_))
        ));
        let dup = format!(
            "{SAMPLE}\n{}",
            SAMPLE
                .split("[[accounts]]")
                .nth(1)
                .map(|s| format!("[[accounts]]{s}"))
                .unwrap_or_default()
        );
        assert!(matches!(Config::parse(&dup), Err(Error::Config(m)) if m.contains("duplicate")));
        let empty = SAMPLE.replace("name = \"icloud\"", "name = \" \"");
        assert!(matches!(Config::parse(&empty), Err(Error::Config(m)) if m.contains("empty")));
    }

    #[test]
    fn access_levels_are_ordered() {
        assert!(
            Access::Read < Access::Flag
                && Access::Flag < Access::Organize
                && Access::Organize < Access::Send
        );
        assert!(Access::Send.require("a", Access::Read).is_ok());
        assert_eq!(
            Access::Flag.require("a", Access::Organize),
            Err(Error::AccessDenied {
                account: "a".into(),
                needed: "organize",
                granted: "flag"
            })
        );
        let names: Vec<&str> = [Access::Read, Access::Flag, Access::Organize, Access::Send]
            .iter()
            .map(|a| a.as_str())
            .collect();
        assert_eq!(names, ["read", "flag", "organize", "send"]);
    }

    #[test]
    fn resolves_passwords() -> Result<(), Error> {
        let config = Config::parse(SAMPLE)?;
        let icloud = config.account("icloud")?;
        let ns = config.account("work")?;
        let ok = Fake {
            env: Some("e".into()),
            keychain: Ok("k".into()),
        };
        assert_eq!(resolve_password(icloud, &ok)?.expose(), "k");
        assert_eq!(resolve_password(ns, &ok)?.expose(), "e");
        let bad = Fake {
            env: Some(String::new()),
            keychain: Err("locked".into()),
        };
        assert!(
            matches!(resolve_password(icloud, &bad), Err(Error::Secret { reason, .. }) if reason == "locked")
        );
        assert!(matches!(
            resolve_password(ns, &bad),
            Err(Error::Secret { .. })
        ));
        assert_eq!(format!("{:?}", Secret::new("pw".into())), "Secret(***)");
        Ok(())
    }
}
