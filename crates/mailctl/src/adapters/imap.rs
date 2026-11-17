//! [`MailStore`] over IMAP with implicit TLS.
//!
//! The IMAP client is async; the adapter drives it on its own
//! single-threaded tokio runtime, so the rest of mailctl stays synchronous.
//!
//! Commands whose answer `async-imap` streams (LIST, FETCH, STORE, SEARCH,
//! EXPUNGE, CAPABILITY) go through [`command`] instead: those streams end at
//! the tagged status without looking at it, so a refused command would pass
//! as an empty success. Sending a command and reading its answer share one
//! error path: a command fails alike whether the connection breaks while it
//! is written or while its answer is read.

use std::future::Future;
use std::time::Duration;

use async_imap::imap_proto::{RequestId, Response};
use futures_util::{TryFutureExt as _, future};
use tokio::net::TcpStream;
use tokio::runtime::Runtime;
use tokio_native_tls::TlsStream;

use crate::adapters::net::{Trust, connect_any};
use crate::config::{AccountConfig, Secret};
use crate::error::Error;
use crate::imap_wire::{
    SelectKeywords, command_done, fetched, flag_list, has_capability, listed_folder,
    quoted_mailbox, received, searched, uid_set,
};
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

/// Drives the async IMAP client and stops using the connection after a
/// timeout.
struct Driver {
    runtime: Runtime,
    /// Time limit of each step.
    timeout: Duration,
    /// A command timed out: its remaining response lines are still unread
    /// and would be taken as the answer to the next command.
    broken: bool,
}

/// An authenticated IMAP session.
pub struct ImapStore {
    driver: Driver,
    session: Session,
    /// Whether the selected folder keeps custom keywords (`PERMANENTFLAGS`).
    keywords: bool,
}

fn store_err(e: impl std::fmt::Display) -> Error {
    Error::Store(e.to_string())
}

impl Driver {
    /// Runs one IMAP step and gives up after the timeout. After a timeout
    /// every later step fails without touching the connection.
    fn run<T>(&mut self, step: impl Future<Output = Result<T, Error>>) -> Result<T, Error> {
        if self.broken {
            return Err(store_err(
                "the IMAP connection timed out earlier and is not used again",
            ));
        }
        // The timer must be created inside the runtime, hence the async block.
        let timeout = self.timeout;
        let result = self
            .runtime
            .block_on(async { tokio::time::timeout(timeout, step).await });
        result.unwrap_or_else(|_| {
            self.broken = true;
            Err(store_err("the IMAP server did not answer in time"))
        })
    }
}

/// A TLS connector that trusts the certificates `trust` names.
fn tls_connector(trust: &Trust) -> Result<native_tls::TlsConnector, Error> {
    let mut builder = native_tls::TlsConnector::builder();
    if let Trust::Only(pem) = trust {
        builder
            .disable_built_in_roots(true)
            .add_root_certificate(native_tls::Certificate::from_pem(pem).map_err(store_err)?);
    }
    builder.build().map_err(store_err)
}

/// Sends `text` and hands each response, the tagged completion included, to
/// `each`; fails unless the server completes the command with OK.
async fn command(
    session: &mut Session,
    text: &str,
    each: impl FnMut(&Response<'_>),
) -> Result<(), Error> {
    let sent = session.run_command(text).await.map_err(store_err);
    future::ready(sent)
        .and_then(|tag| answer(session, tag, each))
        .await
}

/// Reads the answer to the command tagged `tag`.
async fn answer(
    session: &mut Session,
    tag: RequestId,
    mut each: impl FnMut(&Response<'_>),
) -> Result<(), Error> {
    loop {
        let response = received(session.read_response().await).map_err(store_err)?;
        let parsed = response.parsed();
        each(parsed);
        if let Some(done) = command_done(parsed, &tag) {
            return done.map_err(store_err);
        }
    }
}

/// UIDs of a `UID SEARCH`.
async fn search(session: &mut Session, criteria: &str) -> Result<Vec<Uid>, Error> {
    let mut found = Vec::new();
    command(session, &format!("UID SEARCH {criteria}"), |r| {
        found.extend(searched(r));
    })
    .await?;
    found.into_iter().map(Uid::new).collect()
}

impl ImapStore {
    /// Connects and logs in.
    ///
    /// # Errors
    /// Connection, TLS or login errors.
    pub fn connect(account: &AccountConfig, secret: &Secret) -> Result<Self, Error> {
        Self::connect_with(account, secret, &Trust::System, IO_TIMEOUT)
    }

    /// Connects and logs in, trusting the certificates `trust` names and
    /// giving each step `timeout`.
    ///
    /// # Errors
    /// Connection, TLS or login errors.
    pub(crate) fn connect_with(
        account: &AccountConfig,
        secret: &Secret,
        trust: &Trust,
        timeout: Duration,
    ) -> Result<Self, Error> {
        let tls = tokio_native_tls::TlsConnector::from(tls_connector(trust)?);
        // Always implicit TLS, whatever the port: IMAP's default would only
        // use it on 993 and expect a plain greeting elsewhere.
        let (runtime, tcp) = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .and_then(|runtime| {
                connect_any(&account.imap_host, account.imap_port, CONNECT_TIMEOUT)
                    .and_then(|tcp| tcp.set_nonblocking(true).map(|()| tcp))
                    .and_then(|tcp| {
                        // Registering with the reactor needs the runtime.
                        let _context = runtime.enter();
                        TcpStream::from_std(tcp)
                    })
                    .map(|tcp| (runtime, tcp))
            })
            .map_err(store_err)?;
        let mut driver = Driver {
            runtime,
            timeout,
            broken: false,
        };
        let session = driver.run(async {
            let stream = tls
                .connect(&account.imap_host, tcp)
                .await
                .map_err(store_err)?;
            let mut client = async_imap::Client::new(stream);
            received(client.read_response().await)
                .map_err(|e| store_err(format!("before the greeting: {e}")))?;
            client
                .login(&account.user, secret.expose())
                .await
                .map_err(|(e, _)| store_err(e))
        })?;
        Ok(Self {
            driver,
            session,
            keywords: false,
        })
    }

    /// Changes the flags of one mail with `UID STORE`; `operation` is
    /// `+FLAGS.SILENT` or `-FLAGS.SILENT`.
    fn store_flags(&mut self, uid: Uid, operation: &str, flags: &[&str]) -> Result<(), Error> {
        let Self {
            driver, session, ..
        } = self;
        let text = format!("UID STORE {uid} {operation} {}", flag_list(flags));
        driver.run(command(session, &text, |_| ()))
    }
}

impl Drop for ImapStore {
    fn drop(&mut self) {
        let Self {
            driver, session, ..
        } = self;
        let _ = driver.run(async { session.logout().await.map_err(store_err) });
    }
}

impl MailStore for ImapStore {
    fn folders(&mut self) -> Result<Vec<FolderInfo>, Error> {
        let Self {
            driver, session, ..
        } = self;
        let mut folders = Vec::new();
        driver.run(command(session, "LIST \"\" *", |r| {
            folders.extend(listed_folder(r));
        }))?;
        Ok(folders)
    }

    fn select(&mut self, folder: &MailboxName) -> Result<(), Error> {
        let Self {
            driver,
            session,
            keywords,
        } = self;
        // Raw SELECT: the parsed mailbox cannot tell an absent PERMANENTFLAGS
        // code from an empty one, and that decides whether keywords stick.
        let mut select = SelectKeywords::default();
        let text = format!("SELECT {}", quoted_mailbox(folder));
        driver.run(command(session, &text, |r| select.see(r)))?;
        *keywords = select.allowed();
        Ok(())
    }

    fn select_read_only(&mut self, folder: &MailboxName) -> Result<(), Error> {
        let Self {
            driver,
            session,
            keywords,
        } = self;
        *keywords = false;
        driver.run(async {
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
            driver, session, ..
        } = self;
        driver.run(search(session, "ALL"))
    }

    fn headers(&mut self, uids: &[Uid]) -> Result<Vec<RawHeader>, Error> {
        if uids.is_empty() {
            return Ok(Vec::new());
        }
        let Self {
            driver, session, ..
        } = self;
        let mut fetches = Vec::new();
        let text = format!(
            "UID FETCH {} (UID FLAGS RFC822.SIZE BODY.PEEK[HEADER])",
            uid_set(uids)
        );
        driver.run(command(session, &text, |r| fetches.extend(fetched(r))))?;
        // A FETCH without a UID is a flag change another client made, sent
        // along unasked; it is not one of the requested mails.
        Ok(fetches
            .into_iter()
            .filter_map(|f| {
                let uid = f.uid.and_then(|uid| Uid::new(uid).ok())?;
                Some(RawHeader {
                    uid,
                    flags: f.flags,
                    size: f.size.unwrap_or(0),
                    header: f.header.unwrap_or_default(),
                })
            })
            .collect())
    }

    fn message(&mut self, uid: Uid) -> Result<Option<RawMessage>, Error> {
        let Self {
            driver, session, ..
        } = self;
        let mut fetches = Vec::new();
        let text = format!("UID FETCH {uid} (UID FLAGS RFC822.SIZE BODY.PEEK[])");
        driver.run(command(session, &text, |r| fetches.extend(fetched(r))))?;
        Ok(fetches
            .into_iter()
            .find(|f| f.uid == Some(uid.get()))
            .map(|f| {
                let body = f.body.unwrap_or_default();
                let length = u32::try_from(body.len()).unwrap_or(u32::MAX);
                RawMessage {
                    uid,
                    flags: f.flags,
                    size: f.size.unwrap_or(length),
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
            driver, session, ..
        } = self;
        let (mut moves, mut uidplus) = (false, false);
        driver.run(command(session, "CAPABILITY", |r| {
            moves |= has_capability(r, "MOVE");
            uidplus |= has_capability(r, "UIDPLUS");
        }))?;
        Ok(if moves {
            MoveSupport::Move
        } else if uidplus {
            MoveSupport::CopyUidExpunge
        } else {
            MoveSupport::CopyExpunge
        })
    }

    fn copy_to(&mut self, uid: Uid, target: &MailboxName) -> Result<(), Error> {
        let Self {
            driver, session, ..
        } = self;
        driver.run(async {
            session
                .uid_copy(uid.to_string(), utf7::encode(target.as_str()))
                .await
                .map_err(store_err)
        })
    }

    fn deleted_uids(&mut self) -> Result<Vec<Uid>, Error> {
        let Self {
            driver, session, ..
        } = self;
        driver.run(search(session, "DELETED"))
    }

    fn expunge_uid(&mut self, uid: Uid) -> Result<(), Error> {
        let Self {
            driver, session, ..
        } = self;
        driver.run(command(session, &format!("UID EXPUNGE {uid}"), |_| ()))
    }

    fn expunge_all_deleted(&mut self) -> Result<(), Error> {
        let Self {
            driver, session, ..
        } = self;
        driver.run(command(session, "EXPUNGE", |_| ()))
    }

    fn move_to(&mut self, uid: Uid, target: &MailboxName) -> Result<(), Error> {
        let Self {
            driver, session, ..
        } = self;
        driver.run(async {
            session
                .uid_mv(uid.to_string(), utf7::encode(target.as_str()))
                .await
                .map_err(store_err)
        })
    }

    fn find_message_id(&mut self, id: &MessageId) -> Result<Vec<Uid>, Error> {
        let quoted = id.as_str().replace('\\', "\\\\").replace('"', "\\\"");
        let Self {
            driver, session, ..
        } = self;
        driver.run(search(session, &format!("HEADER Message-ID \"{quoted}\"")))
    }

    fn create_folder(&mut self, name: &MailboxName) -> Result<(), Error> {
        let Self {
            driver, session, ..
        } = self;
        driver.run(async {
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
            driver, session, ..
        } = self;
        // The IMAP client quotes and escapes the mailbox name itself.
        let flags = (!flags.is_empty()).then(|| flag_list(flags));
        driver.run(async {
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
