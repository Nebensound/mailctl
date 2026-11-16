//! Editing the configuration file while keeping comments and formatting.
//!
//! Every edit is validated by parsing the result with [`Config::parse`] before
//! it is handed back, so an edit can never leave a broken file.

use toml_edit::{Array, ArrayOfTables, DocumentMut, InlineTable, Item, Table, value};

use crate::config::{Access, Config, PasswordSource};
use crate::error::Error;
use crate::types::{EmailAddress, MailboxName};

/// A new account entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewAccount {
    /// Short name.
    pub name: String,
    /// Login name.
    pub user: String,
    /// Sender address.
    pub address: EmailAddress,
    /// IMAP host (implicit TLS).
    pub imap_host: String,
    /// IMAP port.
    pub imap_port: u16,
    /// SMTP host.
    pub smtp_host: String,
    /// SMTP port.
    pub smtp_port: u16,
    /// SMTP login, if different from `user`.
    pub smtp_user: Option<String>,
    /// Sent folder.
    pub sent_folder: MailboxName,
    /// Password source.
    pub password: PasswordSource,
    /// Access level.
    pub access: Access,
}

fn parse_doc(text: &str) -> Result<DocumentMut, Error> {
    text.parse::<DocumentMut>()
        .map_err(|e| Error::Config(e.to_string()))
}

fn finish(doc: &DocumentMut) -> Result<String, Error> {
    let text = doc.to_string();
    Config::parse(&text)?;
    Ok(text)
}

fn accounts_mut(doc: &mut DocumentMut) -> Result<&mut ArrayOfTables, Error> {
    if !doc.contains_key("accounts") {
        doc.insert("accounts", Item::ArrayOfTables(ArrayOfTables::new()));
    }
    doc.get_mut("accounts")
        .and_then(Item::as_array_of_tables_mut)
        .ok_or_else(|| Error::Config("`accounts` must be an array of tables".into()))
}

fn port_value(port: u16) -> Item {
    value(i64::from(port))
}

/// Adds an account to the configuration text (which may be empty).
///
/// # Errors
/// [`Error::Config`] if the text is not valid TOML, the name is taken, or the
/// result would not be a valid configuration.
pub fn add_account(text: &str, account: &NewAccount) -> Result<String, Error> {
    let mut doc = parse_doc(text)?;
    let accounts = accounts_mut(&mut doc)?;
    let taken = accounts
        .iter()
        .any(|t| t.get("name").and_then(Item::as_str) == Some(account.name.as_str()));
    if taken {
        return Err(Error::Config(format!(
            "account {} already exists",
            account.name
        )));
    }
    let mut table = Table::new();
    table.insert("name", value(account.name.as_str()));
    table.insert("user", value(account.user.as_str()));
    table.insert("address", value(account.address.as_str()));
    table.insert("imap_host", value(account.imap_host.as_str()));
    table.insert("imap_port", port_value(account.imap_port));
    table.insert("smtp_host", value(account.smtp_host.as_str()));
    table.insert("smtp_port", port_value(account.smtp_port));
    if let Some(user) = &account.smtp_user {
        table.insert("smtp_user", value(user.as_str()));
    }
    table.insert("sent_folder", value(account.sent_folder.as_str()));
    let mut password = InlineTable::new();
    match &account.password {
        PasswordSource::Keychain(service) => password.insert("keychain", service.as_str().into()),
        PasswordSource::Env(var) => password.insert("env", var.as_str().into()),
    };
    table.insert("password", value(password));
    table.insert("access", value(account.access.as_str()));
    accounts.push(table);
    finish(&doc)
}

/// Removes an account from the configuration text.
///
/// # Errors
/// [`Error::UnknownAccount`] if it does not exist; [`Error::Config`] if the
/// result would be invalid, for example because it was the last account.
pub fn remove_account(text: &str, name: &str) -> Result<String, Error> {
    let mut doc = parse_doc(text)?;
    let accounts = accounts_mut(&mut doc)?;
    let index = accounts
        .iter()
        .position(|t| t.get("name").and_then(Item::as_str) == Some(name))
        .ok_or_else(|| Error::UnknownAccount(name.to_owned()))?;
    accounts.remove(index);
    finish(&doc)
}

/// Sets the access level of an account.
///
/// # Errors
/// [`Error::UnknownAccount`] if it does not exist; [`Error::Config`] for
/// invalid TOML or an invalid result.
pub fn set_access(text: &str, name: &str, access: Access) -> Result<String, Error> {
    let mut doc = parse_doc(text)?;
    let table = accounts_mut(&mut doc)?
        .iter_mut()
        .find(|t| t.get("name").and_then(Item::as_str) == Some(name))
        .ok_or_else(|| Error::UnknownAccount(name.to_owned()))?;
    table.insert("access", value(access.as_str()));
    finish(&doc)
}

fn allowlist_mut(doc: &mut DocumentMut) -> Result<&mut Array, Error> {
    if !doc.contains_key("forward_allowlist") {
        doc.insert("forward_allowlist", value(Array::new()));
    }
    doc.get_mut("forward_allowlist")
        .and_then(Item::as_array_mut)
        .ok_or_else(|| Error::Config("`forward_allowlist` must be an array".into()))
}

/// Adds an address to the forward allow list; adding an existing one is a no-op.
///
/// # Errors
/// [`Error::Config`] for invalid TOML or an invalid result.
pub fn allowlist_add(text: &str, address: &EmailAddress) -> Result<String, Error> {
    let mut doc = parse_doc(text)?;
    let list = allowlist_mut(&mut doc)?;
    let present = list.iter().any(|v| {
        v.as_str()
            .is_some_and(|s| s.eq_ignore_ascii_case(address.as_str()))
    });
    if !present {
        list.push(address.as_str());
    }
    finish(&doc)
}

/// Removes an address from the forward allow list.
///
/// # Errors
/// [`Error::InvalidInput`] if it is not on the list; [`Error::Config`] for
/// invalid TOML or an invalid result.
pub fn allowlist_remove(text: &str, address: &EmailAddress) -> Result<String, Error> {
    let mut doc = parse_doc(text)?;
    let list = allowlist_mut(&mut doc)?;
    let before = list.len();
    list.retain(|v| {
        !v.as_str()
            .is_some_and(|s| s.eq_ignore_ascii_case(address.as_str()))
    });
    if list.len() == before {
        return Err(Error::InvalidInput(format!(
            "{address} is not on the allow list"
        )));
    }
    finish(&doc)
}

/// Picks the sent folder: the one flagged `\Sent`, else a common name.
#[must_use]
pub fn pick_sent_folder(folders: &[crate::store::FolderInfo]) -> Option<MailboxName> {
    const NAMES: &[&str] = &[
        "Sent Messages",
        "Sent",
        "INBOX.Sent",
        "INBOX/Sent",
        "Gesendet",
        "Gesendete Objekte",
        "Sent Items",
    ];
    folders
        .iter()
        .find(|f| f.selectable && f.special_use.as_deref() == Some("sent"))
        .or_else(|| {
            NAMES.iter().find_map(|name| {
                folders
                    .iter()
                    .find(|f| f.selectable && f.name.as_str() == *name)
            })
        })
        .map(|f| f.name.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::FolderInfo;

    fn account(name: &str) -> Result<NewAccount, Error> {
        Ok(NewAccount {
            name: name.to_owned(),
            user: "alice".to_owned(),
            address: EmailAddress::parse("alice@example.com")?,
            imap_host: "mail.example.net".to_owned(),
            imap_port: 993,
            smtp_host: "mail.example.net".to_owned(),
            smtp_port: 587,
            smtp_user: None,
            sent_folder: MailboxName::new("INBOX.Sent")?,
            password: PasswordSource::Keychain("mailctl".to_owned()),
            access: Access::Organize,
        })
    }

    #[test]
    fn adds_accounts_and_keeps_comments() -> Result<(), Error> {
        let first = add_account("", &account("work")?)?;
        let config = Config::parse(&first)?;
        assert_eq!(config.account("work")?.imap_port, 993);
        let commented = format!("# my mail accounts\n{first}");
        let mut second = account("home")?;
        second.smtp_user = Some("submit".into());
        second.password = PasswordSource::Env("PW".into());
        let both = add_account(&commented, &second)?;
        assert!(both.starts_with("# my mail accounts"));
        let config = Config::parse(&both)?;
        assert_eq!(config.account("home")?.smtp_login(), "submit");
        assert_eq!(
            config.account("home")?.password,
            PasswordSource::Env("PW".into())
        );
        assert!(
            matches!(add_account(&both, &account("work")?), Err(Error::Config(m)) if m.contains("already exists"))
        );
        assert!(matches!(
            add_account("x = [", &account("a")?),
            Err(Error::Config(_))
        ));
        assert!(matches!(
            add_account("accounts = 1", &account("a")?),
            Err(Error::Config(_))
        ));
        let mut bad = account("bad")?;
        bad.name = " ".into();
        assert!(add_account("", &bad).is_err());
        Ok(())
    }

    #[test]
    fn sets_access() -> Result<(), Error> {
        let text = add_account("", &account("a")?)?;
        assert_eq!(Config::parse(&text)?.account("a")?.access, Access::Organize);
        let read = set_access(&text, "a", Access::Read)?;
        assert_eq!(Config::parse(&read)?.account("a")?.access, Access::Read);
        assert_eq!(
            set_access(&text, "b", Access::Read),
            Err(Error::UnknownAccount("b".into()))
        );
        Ok(())
    }

    #[test]
    fn removes_accounts() -> Result<(), Error> {
        let one = add_account("", &account("a")?)?;
        let two = add_account(&one, &account("b")?)?;
        let left = remove_account(&two, "a")?;
        assert!(Config::parse(&left)?.account("a").is_err());
        assert_eq!(
            remove_account(&left, "zzz"),
            Err(Error::UnknownAccount("zzz".into()))
        );
        assert!(
            matches!(remove_account(&left, "b"), Err(Error::Config(m)) if m.contains("accounts"))
        );
        Ok(())
    }

    #[test]
    fn edits_the_allowlist() -> Result<(), Error> {
        let base = add_account("", &account("a")?)?;
        let addr = EmailAddress::parse("accounting@example.com")?;
        let with = allowlist_add(&base, &addr)?;
        assert_eq!(allowlist_add(&with, &addr)?, with);
        assert!(Config::parse(&with)?.forward_allowed(&addr));
        let without = allowlist_remove(&with, &addr)?;
        assert!(!Config::parse(&without)?.forward_allowed(&addr));
        assert!(matches!(
            allowlist_remove(&without, &addr),
            Err(Error::InvalidInput(_))
        ));
        assert!(matches!(
            allowlist_add("forward_allowlist = 1", &addr),
            Err(Error::Config(_))
        ));
        assert!(matches!(
            allowlist_add("x = [", &addr),
            Err(Error::Config(_))
        ));
        Ok(())
    }

    #[test]
    fn picks_sent_folder() -> Result<(), Error> {
        let f = |name: &str, special: Option<&str>, selectable| -> Result<FolderInfo, Error> {
            Ok(FolderInfo {
                name: MailboxName::new(name)?,
                delimiter: None,
                selectable,
                special_use: special.map(str::to_owned),
            })
        };
        let flagged = [
            f("Gesendet", None, true)?,
            f("Postausgang", Some("sent"), true)?,
        ];
        assert_eq!(
            pick_sent_folder(&flagged).map(|n| n.to_string()),
            Some("Postausgang".into())
        );
        let named = [
            f("INBOX", None, true)?,
            f("Sent", None, false)?,
            f("INBOX.Sent", None, true)?,
        ];
        assert_eq!(
            pick_sent_folder(&named).map(|n| n.to_string()),
            Some("INBOX.Sent".into())
        );
        assert_eq!(pick_sent_folder(&[f("INBOX", None, true)?]), None);
        Ok(())
    }
}
