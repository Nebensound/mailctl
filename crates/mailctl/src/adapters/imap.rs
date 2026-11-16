//! [`MailStore`] over IMAP with implicit TLS.

use std::borrow::Cow;

use ::imap::types::Flag;
use imap_proto::NameAttribute;

use crate::config::{AccountConfig, Secret};
use crate::error::Error;
use crate::store::{FolderInfo, MailStore, RawHeader, RawMessage};
use crate::types::{MailboxName, MessageId, Uid};
use crate::utf7;

/// An authenticated IMAP session.
pub struct ImapStore {
    session: ::imap::Session<::imap::Connection>,
}

fn store_err(e: impl std::fmt::Display) -> Error {
    Error::Store(e.to_string())
}

fn flag_of(name: &str) -> Flag<'static> {
    match name {
        "\\Seen" => Flag::Seen,
        "\\Answered" => Flag::Answered,
        "\\Flagged" => Flag::Flagged,
        "\\Draft" => Flag::Draft,
        other => Flag::Custom(Cow::Owned(other.to_owned())),
    }
}

fn special_use(attribute: &NameAttribute<'_>) -> Option<String> {
    let name = match attribute {
        NameAttribute::Sent => "sent",
        NameAttribute::Drafts => "drafts",
        NameAttribute::Junk => "junk",
        NameAttribute::Trash => "trash",
        NameAttribute::Archive => "archive",
        NameAttribute::All => "all",
        NameAttribute::Flagged => "flagged",
        _ => return None,
    };
    Some(name.to_owned())
}

fn uid_set(uids: &[Uid]) -> String {
    uids.iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

impl ImapStore {
    /// Connects and logs in.
    ///
    /// # Errors
    /// Connection, TLS or login errors.
    pub fn connect(account: &AccountConfig, secret: &Secret) -> Result<Self, Error> {
        let client = ::imap::ClientBuilder::new(account.imap_host.as_str(), account.imap_port)
            .connect()
            .map_err(store_err)?;
        let session = client
            .login(&account.user, secret.expose())
            .map_err(|(e, _)| store_err(e))?;
        Ok(Self { session })
    }
}

impl Drop for ImapStore {
    fn drop(&mut self) {
        let _ = self.session.logout();
    }
}

impl MailStore for ImapStore {
    fn folders(&mut self) -> Result<Vec<FolderInfo>, Error> {
        let names = self.session.list(Some(""), Some("*")).map_err(store_err)?;
        names
            .iter()
            .map(|n| {
                Ok(FolderInfo {
                    name: MailboxName::new(&utf7::decode(n.name())?)?,
                    delimiter: n.delimiter().map(str::to_owned),
                    selectable: !n.attributes().contains(&NameAttribute::NoSelect),
                    special_use: n.attributes().iter().find_map(special_use),
                })
            })
            .collect()
    }

    fn select(&mut self, folder: &MailboxName) -> Result<(), Error> {
        self.session
            .select(utf7::encode(folder.as_str()))
            .map(|_| ())
            .map_err(store_err)
    }

    fn select_read_only(&mut self, folder: &MailboxName) -> Result<(), Error> {
        self.session
            .examine(utf7::encode(folder.as_str()))
            .map(|_| ())
            .map_err(store_err)
    }

    fn uids(&mut self) -> Result<Vec<Uid>, Error> {
        self.session
            .uid_search("ALL")
            .map_err(store_err)?
            .into_iter()
            .map(Uid::new)
            .collect()
    }

    fn headers(&mut self, uids: &[Uid]) -> Result<Vec<RawHeader>, Error> {
        if uids.is_empty() {
            return Ok(Vec::new());
        }
        let fetches = self
            .session
            .uid_fetch(uid_set(uids), "(UID FLAGS RFC822.SIZE BODY.PEEK[HEADER])")
            .map_err(store_err)?;
        fetches
            .iter()
            .filter_map(|f| {
                let uid = Uid::new(f.uid?).ok()?;
                Some(Ok(RawHeader {
                    uid,
                    flags: f.flags().iter().map(ToString::to_string).collect(),
                    size: f.size.unwrap_or(0),
                    header: f.header().unwrap_or_default().to_vec(),
                }))
            })
            .collect()
    }

    fn message(&mut self, uid: Uid) -> Result<Option<RawMessage>, Error> {
        let fetches = self
            .session
            .uid_fetch(uid.to_string(), "(UID FLAGS RFC822.SIZE BODY.PEEK[])")
            .map_err(store_err)?;
        Ok(fetches.iter().find(|f| f.uid == Some(uid.get())).map(|f| {
            let body = f.body().unwrap_or_default().to_vec();
            RawMessage {
                uid,
                flags: f.flags().iter().map(ToString::to_string).collect(),
                size: f
                    .size
                    .unwrap_or_else(|| u32::try_from(body.len()).unwrap_or(u32::MAX)),
                body,
            }
        }))
    }

    fn add_flags(&mut self, uid: Uid, flags: &[&str]) -> Result<(), Error> {
        self.session
            .uid_store(
                uid.to_string(),
                format!("+FLAGS.SILENT ({})", flags.join(" ")),
            )
            .map(|_| ())
            .map_err(store_err)
    }

    fn supports_move(&mut self) -> Result<bool, Error> {
        Ok(self
            .session
            .capabilities()
            .map_err(store_err)?
            .has_str("MOVE"))
    }

    fn move_to(&mut self, uid: Uid, target: &MailboxName) -> Result<(), Error> {
        self.session
            .uid_mv(uid.to_string(), utf7::encode(target.as_str()))
            .map_err(store_err)
    }

    fn find_message_id(&mut self, id: &MessageId) -> Result<Vec<Uid>, Error> {
        let quoted = id.as_str().replace('\\', "\\\\").replace('"', "\\\"");
        self.session
            .uid_search(format!("HEADER Message-ID \"{quoted}\""))
            .map_err(store_err)?
            .into_iter()
            .map(Uid::new)
            .collect()
    }

    fn create_folder(&mut self, name: &MailboxName) -> Result<(), Error> {
        self.session
            .create(utf7::encode(name.as_str()))
            .map_err(store_err)
    }

    fn append(
        &mut self,
        folder: &MailboxName,
        message: &[u8],
        flags: &[&str],
    ) -> Result<(), Error> {
        let mailbox = utf7::encode(folder.as_str());
        self.session
            .append(&mailbox, message)
            .flags(flags.iter().map(|f| flag_of(f)))
            .finish()
            .map(|_| ())
            .map_err(store_err)
    }
}
