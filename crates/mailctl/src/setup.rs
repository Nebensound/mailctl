//! Editing the configuration file while keeping comments and formatting.
//!
//! Every edit is validated by parsing the result with [`Config::parse`] before
//! it is handed back, so an edit can never leave a broken file.

use toml_edit::{Array, ArrayOfTables, DocumentMut, InlineTable, Item, Table, value};

use crate::config::Access;
use crate::config::{AccountConfig, Config, PasswordSource};
use crate::error::Error;
use crate::types::{EmailAddress, MailboxName};

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

/// Adds an account to the configuration text (which may be empty). Every
/// field of `account` is written, so it parses back as the same value.
///
/// # Errors
/// [`Error::Config`] if the text is not valid TOML, the name is taken, or the
/// result would not be a valid configuration.
pub fn add_account(text: &str, account: &AccountConfig) -> Result<String, Error> {
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
    if let Some(security) = account.smtp_security {
        table.insert("smtp_security", value(security.as_str()));
    }
    if let Some(user) = &account.smtp_user {
        table.insert("smtp_user", value(user.as_str()));
    }
    table.insert("sent_folder", value(account.sent_folder.as_str()));
    if !account.save_sent_copy {
        table.insert("save_sent_copy", value(false));
    }
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
/// [`Error::UnknownAccount`] if it does not exist; [`Error::Config`] for
/// invalid TOML. Removing the last account leaves a valid, empty setup.
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
#[path = "tests/setup.rs"]
mod tests;
