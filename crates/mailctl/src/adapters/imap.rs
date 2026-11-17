//! [`MailStore`] over IMAP with implicit TLS.

use std::time::Duration;

use imap_proto::NameAttribute;

use crate::adapters::net::connect_any;
use crate::config::{AccountConfig, Secret};
use crate::error::Error;
use crate::imap_wire::{append_mailbox, flag_of, keywords_allowed, special_use, uid_set};
use crate::store::{FolderInfo, MailStore, MoveSupport, RawHeader, RawMessage};
use crate::types::{MailboxName, MessageId, Uid};
use crate::utf7;

/// Timeout for connecting.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// Timeout for each read or write, so a stalled server cannot hang a command.
const IO_TIMEOUT: Duration = Duration::from_mins(2);

/// An authenticated IMAP session.
pub struct ImapStore {
    session: ::imap::Session<::imap::Connection>,
    /// Whether the selected folder keeps custom keywords (`PERMANENTFLAGS`).
    keywords: bool,
}

// Coverage: only reached when a live IMAP server fails.
#[cfg_attr(coverage_nightly, coverage(off))]
fn store_err(e: impl std::fmt::Display) -> Error {
    Error::Store(e.to_string())
}

// Coverage: needs a live IMAP server; the decisions it uses are in `imap_wire`.
#[cfg_attr(coverage_nightly, coverage(off))]
impl ImapStore {
    /// Connects and logs in.
    ///
    /// # Errors
    /// Connection, TLS or login errors.
    pub fn connect(account: &AccountConfig, secret: &Secret) -> Result<Self, Error> {
        // Always implicit TLS, whatever the port: the imap crate's default
        // would only use it on 993 and expect a plain greeting elsewhere.
        let tcp = connect_any(&account.imap_host, account.imap_port, CONNECT_TIMEOUT)
            .map_err(store_err)?;
        tcp.set_read_timeout(Some(IO_TIMEOUT)).map_err(store_err)?;
        tcp.set_write_timeout(Some(IO_TIMEOUT)).map_err(store_err)?;
        let tls = native_tls::TlsConnector::new()
            .map_err(store_err)?
            .connect(&account.imap_host, tcp)
            .map_err(store_err)?;
        let connection: ::imap::Connection = Box::new(tls);
        let mut client = ::imap::Client::new(connection);
        client.read_greeting().map_err(store_err)?;
        let session = client
            .login(&account.user, secret.expose())
            .map_err(|(e, _)| store_err(e))?;
        Ok(Self {
            session,
            keywords: false,
        })
    }
}

// Coverage: needs a live IMAP server.
#[cfg_attr(coverage_nightly, coverage(off))]
impl Drop for ImapStore {
    fn drop(&mut self) {
        let _ = self.session.logout();
    }
}

// Coverage: needs a live IMAP server; the decisions it uses are in `imap_wire`.
#[cfg_attr(coverage_nightly, coverage(off))]
impl MailStore for ImapStore {
    fn folders(&mut self) -> Result<Vec<FolderInfo>, Error> {
        let names = self.session.list(Some(""), Some("*")).map_err(store_err)?;
        // A name that is not valid modified UTF-7 (written by another client)
        // is skipped instead of failing the whole listing.
        Ok(names
            .iter()
            .filter_map(|n| {
                let name = utf7::decode(n.name())
                    .and_then(|decoded| MailboxName::new(&decoded))
                    .ok()?;
                Some(FolderInfo {
                    name,
                    delimiter: n.delimiter().map(str::to_owned),
                    selectable: !n.attributes().contains(&NameAttribute::NoSelect),
                    special_use: n.attributes().iter().find_map(special_use),
                })
            })
            .collect())
    }

    fn select(&mut self, folder: &MailboxName) -> Result<(), Error> {
        // Raw SELECT: the parsed response cannot tell an absent PERMANENTFLAGS
        // code from an empty one, and that decides `keywords_allowed`.
        let (response, _) = self
            .session
            .run(format!("SELECT \"{}\"", append_mailbox(folder)))
            .map_err(store_err)?;
        self.keywords = keywords_allowed(&response);
        Ok(())
    }

    fn select_read_only(&mut self, folder: &MailboxName) -> Result<(), Error> {
        self.keywords = false;
        self.session
            .examine(utf7::encode(folder.as_str()))
            .map(|_| ())
            .map_err(store_err)
    }

    fn keywords_allowed(&mut self) -> Result<bool, Error> {
        Ok(self.keywords)
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

    fn remove_flags(&mut self, uid: Uid, flags: &[&str]) -> Result<(), Error> {
        self.session
            .uid_store(
                uid.to_string(),
                format!("-FLAGS.SILENT ({})", flags.join(" ")),
            )
            .map(|_| ())
            .map_err(store_err)
    }

    fn move_support(&mut self) -> Result<MoveSupport, Error> {
        let caps = self.session.capabilities().map_err(store_err)?;
        Ok(if caps.has_str("MOVE") {
            MoveSupport::Move
        } else if caps.has_str("UIDPLUS") {
            MoveSupport::CopyUidExpunge
        } else {
            MoveSupport::CopyExpunge
        })
    }

    fn copy_to(&mut self, uid: Uid, target: &MailboxName) -> Result<(), Error> {
        self.session
            .uid_copy(uid.to_string(), utf7::encode(target.as_str()))
            .map_err(store_err)
    }

    fn deleted_uids(&mut self) -> Result<Vec<Uid>, Error> {
        self.session
            .uid_search("DELETED")
            .map_err(store_err)?
            .into_iter()
            .map(Uid::new)
            .collect()
    }

    fn expunge_uid(&mut self, uid: Uid) -> Result<(), Error> {
        self.session
            .uid_expunge(uid.to_string())
            .map(|_| ())
            .map_err(store_err)
    }

    fn expunge_all_deleted(&mut self) -> Result<(), Error> {
        self.session.expunge().map(|_| ()).map_err(store_err)
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
        // The imap crate puts this between quotes without escaping it.
        let mailbox = append_mailbox(folder);
        self.session
            .append(&mailbox, message)
            .flags(flags.iter().map(|f| flag_of(f)))
            .finish()
            .map(|_| ())
            .map_err(store_err)
    }
}
