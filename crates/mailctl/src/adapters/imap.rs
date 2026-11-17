//! [`MailStore`] over IMAP with implicit TLS.
//!
//! The IMAP client is async; the adapter drives it on its own
//! single-threaded tokio runtime, so the rest of mailctl stays synchronous.

use std::future::Future;
use std::time::Duration;

use async_imap::types::{Fetch, Name, NameAttribute};
use futures_util::TryStreamExt as _;
use tokio::net::TcpStream;
use tokio::runtime::Runtime;
use tokio_native_tls::TlsStream;

use crate::adapters::net::connect_any;
use crate::config::{AccountConfig, Secret};
use crate::error::Error;
use crate::imap_wire::{SelectReader, flag_list, flag_name, quoted_mailbox, special_use, uid_set};
use crate::store::{FolderInfo, MailStore, MoveSupport, RawHeader, RawMessage};
use crate::types::{MailboxName, MessageId, Uid};
use crate::utf7;

/// Timeout for connecting.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// Timeout for each command (and for TLS, greeting and login together), so a
/// stalled server cannot hang mailctl.
const IO_TIMEOUT: Duration = Duration::from_mins(2);

/// An IMAP session over implicit TLS.
type Session = async_imap::Session<TlsStream<TcpStream>>;

/// An authenticated IMAP session.
pub struct ImapStore {
    /// Drives the async IMAP client.
    runtime: Runtime,
    session: Session,
    /// Whether the selected folder keeps custom keywords (`PERMANENTFLAGS`).
    keywords: bool,
}

// Coverage: only reached when a live IMAP server fails.
#[cfg_attr(coverage_nightly, coverage(off))]
fn store_err(e: impl std::fmt::Display) -> Error {
    Error::Store(e.to_string())
}

/// Runs one IMAP step on `runtime` and gives up after [`IO_TIMEOUT`].
// Coverage: needs a live IMAP server.
#[cfg_attr(coverage_nightly, coverage(off))]
fn block_on<T>(
    runtime: &Runtime,
    step: impl Future<Output = Result<T, Error>>,
) -> Result<T, Error> {
    // The timer must be created inside the runtime, hence the async block.
    runtime
        .block_on(async { tokio::time::timeout(IO_TIMEOUT, step).await })
        .map_err(|_| store_err("the IMAP server did not answer in time"))?
}

// Coverage: needs a live IMAP server; the decisions it uses are in `imap_wire`.
#[cfg_attr(coverage_nightly, coverage(off))]
impl ImapStore {
    /// Connects and logs in.
    ///
    /// # Errors
    /// Connection, TLS or login errors.
    pub fn connect(account: &AccountConfig, secret: &Secret) -> Result<Self, Error> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .map_err(store_err)?;
        // Always implicit TLS, whatever the port: IMAP's default would only
        // use it on 993 and expect a plain greeting elsewhere.
        let tcp = connect_any(&account.imap_host, account.imap_port, CONNECT_TIMEOUT)
            .map_err(store_err)?;
        tcp.set_nonblocking(true).map_err(store_err)?;
        let tls = tokio_native_tls::TlsConnector::from(
            native_tls::TlsConnector::new().map_err(store_err)?,
        );
        let session = block_on(&runtime, async {
            let tcp = TcpStream::from_std(tcp).map_err(store_err)?;
            let stream = tls
                .connect(&account.imap_host, tcp)
                .await
                .map_err(store_err)?;
            let mut client = async_imap::Client::new(stream);
            client
                .read_response()
                .await
                .map_err(store_err)?
                .ok_or_else(|| store_err("connection closed before the greeting"))?;
            client
                .login(&account.user, secret.expose())
                .await
                .map_err(|(e, _)| store_err(e))
        })?;
        Ok(Self {
            runtime,
            session,
            keywords: false,
        })
    }

    /// Changes the flags of one mail with `UID STORE`; `operation` is
    /// `+FLAGS.SILENT` or `-FLAGS.SILENT`.
    fn store_flags(&mut self, uid: Uid, operation: &str, flags: &[&str]) -> Result<(), Error> {
        let Self {
            runtime, session, ..
        } = self;
        block_on(runtime, async {
            session
                .uid_store(uid.to_string(), format!("{operation} {}", flag_list(flags)))
                .await
                .map_err(store_err)?
                .try_collect::<Vec<Fetch>>()
                .await
                .map(|_| ())
                .map_err(store_err)
        })
    }
}

// Coverage: needs a live IMAP server.
#[cfg_attr(coverage_nightly, coverage(off))]
impl Drop for ImapStore {
    fn drop(&mut self) {
        let Self {
            runtime, session, ..
        } = self;
        let _ = block_on(runtime, async { session.logout().await.map_err(store_err) });
    }
}

// Coverage: needs a live IMAP server; the decisions it uses are in `imap_wire`.
#[cfg_attr(coverage_nightly, coverage(off))]
impl MailStore for ImapStore {
    fn folders(&mut self) -> Result<Vec<FolderInfo>, Error> {
        let Self {
            runtime, session, ..
        } = self;
        let names: Vec<Name> = block_on(runtime, async {
            session
                .list(Some(""), Some("*"))
                .await
                .map_err(store_err)?
                .try_collect()
                .await
                .map_err(store_err)
        })?;
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
        let Self {
            runtime,
            session,
            keywords,
        } = self;
        // Raw SELECT: the parsed mailbox cannot tell an absent PERMANENTFLAGS
        // code from an empty one, and that decides whether keywords stick.
        *keywords = block_on(runtime, async {
            let tag = session
                .run_command(format!("SELECT {}", quoted_mailbox(folder)))
                .await
                .map_err(store_err)?;
            let mut reader = SelectReader::new(tag);
            loop {
                let response = session
                    .read_response()
                    .await
                    .map_err(store_err)?
                    .ok_or_else(|| store_err("connection closed during SELECT"))?;
                if let Some(done) = reader.feed(response.parsed()) {
                    return done.map_err(store_err);
                }
            }
        })?;
        Ok(())
    }

    fn select_read_only(&mut self, folder: &MailboxName) -> Result<(), Error> {
        let Self {
            runtime,
            session,
            keywords,
        } = self;
        *keywords = false;
        block_on(runtime, async {
            session
                .examine(utf7::encode(folder.as_str()))
                .await
                .map(|_| ())
                .map_err(store_err)
        })
    }

    fn keywords_allowed(&mut self) -> Result<bool, Error> {
        Ok(self.keywords)
    }

    fn uids(&mut self) -> Result<Vec<Uid>, Error> {
        let Self {
            runtime, session, ..
        } = self;
        block_on(runtime, async {
            session.uid_search("ALL").await.map_err(store_err)
        })?
        .into_iter()
        .map(Uid::new)
        .collect()
    }

    fn headers(&mut self, uids: &[Uid]) -> Result<Vec<RawHeader>, Error> {
        if uids.is_empty() {
            return Ok(Vec::new());
        }
        let Self {
            runtime, session, ..
        } = self;
        let fetches: Vec<Fetch> = block_on(runtime, async {
            session
                .uid_fetch(uid_set(uids), "(UID FLAGS RFC822.SIZE BODY.PEEK[HEADER])")
                .await
                .map_err(store_err)?
                .try_collect()
                .await
                .map_err(store_err)
        })?;
        fetches
            .iter()
            .filter_map(|f| {
                let uid = Uid::new(f.uid?).ok()?;
                Some(Ok(RawHeader {
                    uid,
                    flags: f.flags().map(|flag| flag_name(&flag)).collect(),
                    size: f.size.unwrap_or(0),
                    header: f.header().unwrap_or_default().to_vec(),
                }))
            })
            .collect()
    }

    fn message(&mut self, uid: Uid) -> Result<Option<RawMessage>, Error> {
        let Self {
            runtime, session, ..
        } = self;
        let fetches: Vec<Fetch> = block_on(runtime, async {
            session
                .uid_fetch(uid.to_string(), "(UID FLAGS RFC822.SIZE BODY.PEEK[])")
                .await
                .map_err(store_err)?
                .try_collect()
                .await
                .map_err(store_err)
        })?;
        Ok(fetches.iter().find(|f| f.uid == Some(uid.get())).map(|f| {
            let body = f.body().unwrap_or_default().to_vec();
            RawMessage {
                uid,
                flags: f.flags().map(|flag| flag_name(&flag)).collect(),
                size: f
                    .size
                    .unwrap_or_else(|| u32::try_from(body.len()).unwrap_or(u32::MAX)),
                body,
            }
        }))
    }

    fn add_flags(&mut self, uid: Uid, flags: &[&str]) -> Result<(), Error> {
        self.store_flags(uid, "+FLAGS.SILENT", flags)
    }

    fn remove_flags(&mut self, uid: Uid, flags: &[&str]) -> Result<(), Error> {
        self.store_flags(uid, "-FLAGS.SILENT", flags)
    }

    fn move_support(&mut self) -> Result<MoveSupport, Error> {
        let Self {
            runtime, session, ..
        } = self;
        let caps = block_on(runtime, async {
            session.capabilities().await.map_err(store_err)
        })?;
        Ok(if caps.has_str("MOVE") {
            MoveSupport::Move
        } else if caps.has_str("UIDPLUS") {
            MoveSupport::CopyUidExpunge
        } else {
            MoveSupport::CopyExpunge
        })
    }

    fn copy_to(&mut self, uid: Uid, target: &MailboxName) -> Result<(), Error> {
        let Self {
            runtime, session, ..
        } = self;
        block_on(runtime, async {
            session
                .uid_copy(uid.to_string(), utf7::encode(target.as_str()))
                .await
                .map_err(store_err)
        })
    }

    fn deleted_uids(&mut self) -> Result<Vec<Uid>, Error> {
        let Self {
            runtime, session, ..
        } = self;
        block_on(runtime, async {
            session.uid_search("DELETED").await.map_err(store_err)
        })?
        .into_iter()
        .map(Uid::new)
        .collect()
    }

    fn expunge_uid(&mut self, uid: Uid) -> Result<(), Error> {
        let Self {
            runtime, session, ..
        } = self;
        block_on(runtime, async {
            session
                .uid_expunge(uid.to_string())
                .await
                .map_err(store_err)?
                .try_collect::<Vec<_>>()
                .await
                .map(|_| ())
                .map_err(store_err)
        })
    }

    fn expunge_all_deleted(&mut self) -> Result<(), Error> {
        let Self {
            runtime, session, ..
        } = self;
        block_on(runtime, async {
            session
                .expunge()
                .await
                .map_err(store_err)?
                .try_collect::<Vec<_>>()
                .await
                .map(|_| ())
                .map_err(store_err)
        })
    }

    fn move_to(&mut self, uid: Uid, target: &MailboxName) -> Result<(), Error> {
        let Self {
            runtime, session, ..
        } = self;
        block_on(runtime, async {
            session
                .uid_mv(uid.to_string(), utf7::encode(target.as_str()))
                .await
                .map_err(store_err)
        })
    }

    fn find_message_id(&mut self, id: &MessageId) -> Result<Vec<Uid>, Error> {
        let quoted = id.as_str().replace('\\', "\\\\").replace('"', "\\\"");
        let Self {
            runtime, session, ..
        } = self;
        block_on(runtime, async {
            session
                .uid_search(format!("HEADER Message-ID \"{quoted}\""))
                .await
                .map_err(store_err)
        })?
        .into_iter()
        .map(Uid::new)
        .collect()
    }

    fn create_folder(&mut self, name: &MailboxName) -> Result<(), Error> {
        let Self {
            runtime, session, ..
        } = self;
        block_on(runtime, async {
            session
                .create(utf7::encode(name.as_str()))
                .await
                .map_err(store_err)
        })
    }

    fn append(
        &mut self,
        folder: &MailboxName,
        message: &[u8],
        flags: &[&str],
    ) -> Result<(), Error> {
        let Self {
            runtime, session, ..
        } = self;
        // The IMAP client quotes and escapes the mailbox name itself.
        let flags = (!flags.is_empty()).then(|| flag_list(flags));
        block_on(runtime, async {
            session
                .append(
                    utf7::encode(folder.as_str()),
                    flags.as_deref(),
                    None,
                    message,
                )
                .await
                .map_err(store_err)
        })
    }
}
