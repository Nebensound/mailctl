//! Command line definition and dispatch. Output is always JSON on stdout.

use std::io::Write;
use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};
use serde::Serialize;

use crate::config::{Access, AccountConfig, Config, Secret, SecretLookup, resolve_password};
use crate::discover::Net;
use crate::error::Error;
use crate::guard::GuardedStore;
use crate::model::MailSummary;
use crate::plan::{self, Plan};
use crate::service::{self, ForwardJob};
use crate::store::{MailSender, MailStore};
use crate::types::{EmailAddress, Expect, MailRef, MailboxName, MessageId, Uid};

/// Agent-friendly mailbox tool: list, show, move, mark read, create folders and
/// forward to allowed recipients. It never deletes mail.
#[derive(Debug, Parser)]
#[command(name = "mailctl", version)]
pub struct Cli {
    /// Configuration file (default: `$MAILCTL_CONFIG` or `~/.config/mailctl/config.toml`).
    #[arg(long, global = true, env = "MAILCTL_CONFIG")]
    pub config: Option<PathBuf>,
    /// The command.
    #[command(subcommand)]
    pub command: Command,
}

/// Account and folder of a mail.
#[derive(Debug, Clone, clap::Args)]
pub struct Location {
    /// Account name from the configuration.
    #[arg(short, long)]
    pub account: String,
    /// Folder; defaults to the inbox.
    #[arg(short, long, default_value = "INBOX")]
    pub folder: String,
}

/// A single mail that will be changed.
#[derive(Debug, Clone, clap::Args)]
pub struct Target {
    /// Account and folder.
    #[command(flatten)]
    pub location: Location,
    /// UID of the mail in the folder.
    #[arg(long)]
    pub uid: u32,
    /// `Message-ID` or ten-digit mail reference the mail must have.
    #[arg(long)]
    pub expect: String,
    /// Only check, change nothing.
    #[arg(long)]
    pub dry_run: bool,
}

/// All commands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// List configured accounts.
    Accounts,
    /// List the folders of an account.
    Folders {
        /// Account name.
        #[arg(short, long)]
        account: String,
    },
    /// List mails, newest first.
    List {
        /// Account and folder.
        #[command(flatten)]
        location: Location,
        /// Maximum number of mails.
        #[arg(short = 'n', long, default_value_t = 50)]
        limit: usize,
        /// Only mails with a UID below this one (paging). UIDs are per folder,
        /// so this cannot be combined with `--all-folders`.
        #[arg(long, conflicts_with = "all_folders")]
        before: Option<u32>,
        /// One JSON object per line, written as soon as each chunk arrives.
        #[arg(long)]
        ndjson: bool,
        /// List every selectable folder of the account (`--limit` applies per folder).
        #[arg(long)]
        all_folders: bool,
    },
    /// Show one mail with text and attachments.
    Show {
        /// Account and folder.
        #[command(flatten)]
        location: Location,
        /// UID of the mail.
        #[arg(long)]
        uid: u32,
        /// Optional identity check.
        #[arg(long)]
        expect: Option<String>,
        /// Maximum length of the text.
        #[arg(long, default_value_t = 4000)]
        max_chars: usize,
    },
    /// Mark one mail as read.
    MarkRead {
        /// The mail.
        #[command(flatten)]
        target: Target,
    },
    /// Move one mail to another folder of the same account.
    Move {
        /// The mail.
        #[command(flatten)]
        target: Target,
        /// Target folder.
        #[arg(long)]
        to: String,
        /// Mark as read before moving.
        #[arg(long)]
        mark_read: bool,
    },
    /// Create a folder.
    CreateFolder {
        /// Account name.
        #[arg(short, long)]
        account: String,
        /// Folder name as listed by `folders`.
        name: String,
        /// Only check, change nothing.
        #[arg(long)]
        dry_run: bool,
    },
    /// Forward one mail with its attachments to a recipient on the allow list.
    Forward {
        /// The mail.
        #[command(flatten)]
        target: Target,
        /// Recipient.
        #[arg(long)]
        to: String,
        /// Note above the forwarded text.
        #[arg(long)]
        note: Option<String>,
    },
    /// Run a JSON plan with many changes over one connection.
    Apply {
        /// Plan file, or `-` for standard input.
        plan: PathBuf,
    },
    /// Set up, test and remove accounts.
    Account {
        /// What to do.
        #[command(subcommand)]
        command: crate::account::AccountCommand,
    },
    /// Manage the forward allow list.
    Allowlist {
        /// What to do.
        #[command(subcommand)]
        command: crate::account::AllowlistCommand,
    },
    /// Print the stable reference for a `Message-ID` (offline).
    Ref {
        /// The `Message-ID`.
        message_id: String,
    },
}

/// Connections and system access, provided by the binary.
pub trait Backend {
    /// Reads the configuration text.
    ///
    /// # Errors
    /// [`Error::Config`] if it cannot be read.
    fn read_config(&self, path: Option<&PathBuf>) -> Result<String, Error>;
    /// Reads a plan file; `-` means standard input.
    ///
    /// # Errors
    /// [`Error::InvalidInput`] if it cannot be read.
    fn read_plan(&self, path: &Path) -> Result<String, Error>;
    /// Password sources.
    fn secrets(&self) -> &dyn SecretLookup;
    /// Opens an IMAP session.
    ///
    /// # Errors
    /// Connection or login errors.
    fn connect(
        &self,
        account: &AccountConfig,
        secret: &Secret,
    ) -> Result<Box<dyn MailStore>, Error>;
    /// Opens an SMTP transport.
    ///
    /// # Errors
    /// Connection errors.
    fn sender(
        &self,
        account: &AccountConfig,
        secret: &Secret,
    ) -> Result<Box<dyn MailSender>, Error>;
    /// Seconds since the Unix epoch, used for new `Message-ID`s.
    fn unix_time(&self) -> u64;
    /// A random number, different on every call, for unique `Message-ID`s.
    fn random(&self) -> u64;
    /// Path of the configuration file.
    ///
    /// # Errors
    /// [`Error::Config`] if no path can be determined.
    fn config_path(&self, explicit: Option<&PathBuf>) -> Result<PathBuf, Error>;
    /// Reads a file; `None` if it does not exist.
    ///
    /// # Errors
    /// Any other read error.
    fn read_optional(&self, path: &Path) -> Result<Option<String>, Error>;
    /// Writes a file atomically, creating parent directories.
    ///
    /// # Errors
    /// Write errors.
    fn write_file(&self, path: &Path, text: &str) -> Result<(), Error>;
    /// Asks a question on the terminal; `None` without a terminal.
    ///
    /// # Errors
    /// Terminal errors.
    fn prompt_line(&self, question: &str, default: Option<&str>) -> Result<Option<String>, Error>;
    /// Asks for a password without echo; `None` without a terminal.
    ///
    /// # Errors
    /// Terminal errors.
    fn prompt_password(&self, prompt: &str) -> Result<Option<Secret>, Error>;
    /// Reads all of standard input.
    ///
    /// # Errors
    /// Read errors.
    fn read_stdin(&self) -> Result<String, Error>;
    /// Stores or replaces a keychain item.
    ///
    /// # Errors
    /// Keychain errors.
    fn keychain_store(&self, service: &str, account: &str, secret: &Secret) -> Result<(), Error>;
    /// Deletes a keychain item.
    ///
    /// # Errors
    /// Keychain errors.
    fn keychain_delete(&self, service: &str, account: &str) -> Result<(), Error>;
    /// Network access for server discovery.
    fn net(&self) -> Box<dyn Net>;
    /// Logs in to SMTP without sending anything.
    ///
    /// # Errors
    /// Connection or login errors.
    fn check_smtp(&self, account: &AccountConfig, secret: &Secret) -> Result<(), Error>;
}

#[expect(
    clippy::needless_pass_by_value,
    reason = "signature required by Result::map_err"
)]
fn output_error(e: serde_json::Error) -> Error {
    Error::InvalidInput(format!("output: {e}"))
}

/// Writes `value` as pretty-printed JSON followed by a newline.
///
/// # Errors
/// [`Error::InvalidInput`] if `out` fails.
fn write_json<T: Serialize>(out: &mut dyn Write, value: &T) -> Result<(), Error> {
    serde_json::to_writer_pretty(&mut *out, value)
        .and_then(|()| writeln!(out).map_err(serde_json::Error::io))
        .map_err(output_error)
}

/// Writes `value` as one line of JSON (for ndjson).
fn write_json_line<T: Serialize>(out: &mut dyn Write, value: &T) -> Result<(), Error> {
    serde_json::to_writer(&mut *out, value)
        .and_then(|()| writeln!(out).map_err(serde_json::Error::io))
        .map_err(output_error)
}

#[derive(Serialize)]
struct ErrorOutput<'a> {
    error: &'a str,
}

#[derive(Serialize)]
struct AccountOutput<'a> {
    name: &'a str,
    address: &'a EmailAddress,
    imap_host: &'a str,
}

#[derive(Serialize)]
struct FolderOutput {
    name: MailboxName,
    delimiter: Option<String>,
    selectable: bool,
    special_use: Option<String>,
}

#[derive(Serialize)]
struct Listed<'a> {
    folder: &'a MailboxName,
    #[serde(flatten)]
    mail: MailSummary,
}

#[derive(Serialize)]
struct RefOutput {
    message_id: MessageId,
    mail_ref: MailRef,
}

/// Runs a parsed command line and writes JSON to `out`. Never panics; errors
/// become a one-line JSON object with an `error` field.
///
/// Returns the process exit code: 0 success, 1 some plan operations failed,
/// 2 error.
pub fn run(cli: &Cli, backend: &dyn Backend, out: &mut dyn Write) -> u8 {
    match dispatch(cli, backend, out) {
        Ok(code) => code,
        Err(e) => {
            // One line, so ndjson readers can parse it too. Nothing more can
            // be done if even the error cannot be written.
            let _ = write_json_line(
                out,
                &ErrorOutput {
                    error: &e.to_string(),
                },
            );
            2
        }
    }
}

/// Writes `value` as the command's JSON result; exit code 0.
///
/// # Errors
/// [`Error::InvalidInput`] if `out` fails.
pub(crate) fn emit<T: Serialize>(out: &mut dyn Write, value: &T) -> Result<u8, Error> {
    write_json(out, value).map(|()| 0)
}

struct Session<'a> {
    config: Config,
    account: AccountConfig,
    backend: &'a dyn Backend,
    secret: Secret,
}

impl<'a> Session<'a> {
    fn open(cli: &Cli, backend: &'a dyn Backend, account: &str) -> Result<Self, Error> {
        let config = Config::parse(&backend.read_config(cli.config.as_ref())?)?;
        let account = config.account(account)?.clone();
        let secret = resolve_password(&account, backend.secrets())?;
        Ok(Self {
            config,
            account,
            backend,
            secret,
        })
    }

    fn require(&self, needed: Access) -> Result<(), Error> {
        self.account.access.require(&self.account.name, needed)
    }

    fn store(&self) -> Result<Box<dyn MailStore>, Error> {
        let inner = self.backend.connect(&self.account, &self.secret)?;
        Ok(Box::new(GuardedStore::new(
            inner,
            &self.account.name,
            self.account.access,
        )))
    }

    /// The SMTP connection, or [`NoSender`] (which refuses every message)
    /// below [`Access::Send`]: no SMTP connection is made without send access.
    fn sender(&self) -> Result<Box<dyn MailSender>, Error> {
        if self.account.access < Access::Send {
            return Ok(Box::new(NoSender));
        }
        self.backend.sender(&self.account, &self.secret)
    }

    fn new_message_id(&self, counter: u32) -> MessageId {
        MessageId::generated(
            self.backend.unix_time(),
            self.backend.random(),
            counter,
            &self.account.address,
        )
    }
}

fn dispatch(cli: &Cli, backend: &dyn Backend, out: &mut dyn Write) -> Result<u8, Error> {
    match &cli.command {
        Command::Ref { message_id } => {
            let message_id = MessageId::parse(message_id)?;
            let mail_ref = MailRef::from_message_id(&message_id);
            emit(
                out,
                &RefOutput {
                    message_id,
                    mail_ref,
                },
            )
        }
        Command::Accounts => accounts(cli, backend, out),
        Command::Account { command } => crate::account::run_account(cli, backend, out, command),
        Command::Allowlist { command } => crate::account::run_allowlist(cli, backend, out, command),
        Command::Folders { account } => folders(cli, backend, out, account),
        Command::List {
            location,
            limit,
            before,
            ndjson,
            all_folders,
        } => {
            let request = ListRequest {
                limit: *limit,
                before: *before,
                ndjson: *ndjson,
                all_folders: *all_folders,
            };
            list(cli, backend, out, location, &request)
        }
        Command::Show {
            location,
            uid,
            expect,
            max_chars,
        } => show(
            cli,
            backend,
            out,
            location,
            *uid,
            expect.as_deref(),
            *max_chars,
        ),
        Command::MarkRead { target } => {
            let (session, folder, uid, expect) = open_target(cli, backend, target, Access::Flag)?;
            emit(
                out,
                &service::mark_read(
                    session.store()?.as_mut(),
                    &folder,
                    uid,
                    &expect,
                    target.dry_run,
                )?,
            )
        }
        Command::Move {
            target,
            to,
            mark_read,
        } => {
            let (session, folder, uid, expect) =
                open_target(cli, backend, target, Access::Organize)?;
            let to = MailboxName::new(to)?;
            let mut store = session.store()?;
            emit(
                out,
                &service::move_mail(
                    store.as_mut(),
                    &folder,
                    uid,
                    &expect,
                    &to,
                    *mark_read,
                    target.dry_run,
                )?,
            )
        }
        Command::CreateFolder {
            account,
            name,
            dry_run,
        } => {
            let session = Session::open(cli, backend, account)?;
            session.require(Access::Organize)?;
            let name = MailboxName::new(name)?;
            emit(
                out,
                &service::create_folder(session.store()?.as_mut(), &name, *dry_run)?,
            )
        }
        Command::Forward { target, to, note } => {
            forward(cli, backend, out, target, to, note.as_deref())
        }
        Command::Apply { plan } => apply(cli, backend, out, plan),
    }
}

fn folders(
    cli: &Cli,
    backend: &dyn Backend,
    out: &mut dyn Write,
    account: &str,
) -> Result<u8, Error> {
    let session = Session::open(cli, backend, account)?;
    let folders: Vec<FolderOutput> = service::folders(session.store()?.as_mut())?
        .into_iter()
        .map(|f| FolderOutput {
            name: f.name,
            delimiter: f.delimiter,
            selectable: f.selectable,
            special_use: f.special_use,
        })
        .collect();
    emit(out, &folders)
}

fn show(
    cli: &Cli,
    backend: &dyn Backend,
    out: &mut dyn Write,
    location: &Location,
    uid: u32,
    expect: Option<&str>,
    max_chars: usize,
) -> Result<u8, Error> {
    let session = Session::open(cli, backend, &location.account)?;
    let expect = expect.map(Expect::parse).transpose()?;
    let folder = MailboxName::new(&location.folder)?;
    let uid = Uid::new(uid)?;
    emit(
        out,
        &service::show(
            session.store()?.as_mut(),
            &folder,
            uid,
            expect.as_ref(),
            max_chars,
        )?,
    )
}

struct ListRequest {
    limit: usize,
    before: Option<u32>,
    ndjson: bool,
    all_folders: bool,
}

fn list(
    cli: &Cli,
    backend: &dyn Backend,
    out: &mut dyn Write,
    location: &Location,
    request: &ListRequest,
) -> Result<u8, Error> {
    let session = Session::open(cli, backend, &location.account)?;
    let before = request.before.map(Uid::new).transpose()?;
    let mut store = session.store()?;
    let folder = MailboxName::new(&location.folder)?;
    let folders: Vec<MailboxName> = if request.all_folders {
        service::folders(store.as_mut())?
            .into_iter()
            .filter(|f| f.selectable)
            .map(|f| f.name)
            .collect()
    } else {
        vec![folder.clone()]
    };
    if request.ndjson {
        for folder in &folders {
            service::list_each(
                store.as_mut(),
                folder,
                request.limit,
                before,
                service::FETCH_CHUNK,
                &mut |mail| write_json_line(out, &Listed { folder, mail }),
            )?;
        }
        return Ok(0);
    }
    if request.all_folders {
        let mut listed = Vec::new();
        for folder in &folders {
            for mail in service::list(store.as_mut(), folder, request.limit, before)? {
                listed.push(Listed { folder, mail });
            }
        }
        return emit(out, &listed);
    }
    emit(
        out,
        &service::list(store.as_mut(), &folder, request.limit, before)?,
    )
}

fn accounts(cli: &Cli, backend: &dyn Backend, out: &mut dyn Write) -> Result<u8, Error> {
    let config = Config::parse(&backend.read_config(cli.config.as_ref())?)?;
    let list: Vec<AccountOutput<'_>> = config
        .accounts
        .iter()
        .map(|a| AccountOutput {
            name: &a.name,
            address: &a.address,
            imap_host: &a.imap_host,
        })
        .collect();
    emit(out, &list)
}

fn open_target<'a>(
    cli: &Cli,
    backend: &'a dyn Backend,
    target: &Target,
    needed: Access,
) -> Result<(Session<'a>, MailboxName, Uid, Expect), Error> {
    let session = Session::open(cli, backend, &target.location.account)?;
    session.require(needed)?;
    let folder = MailboxName::new(&target.location.folder)?;
    Ok((
        session,
        folder,
        Uid::new(target.uid)?,
        Expect::parse(&target.expect)?,
    ))
}

fn forward(
    cli: &Cli,
    backend: &dyn Backend,
    out: &mut dyn Write,
    target: &Target,
    to: &str,
    note: Option<&str>,
) -> Result<u8, Error> {
    let (session, folder, uid, expect) = open_target(cli, backend, target, Access::Send)?;
    let to = EmailAddress::parse(to)?;
    let id = session.new_message_id(1);
    let job = ForwardJob {
        folder: &folder,
        uid,
        expect: &expect,
        to: &to,
        from: &session.account.address,
        sent_folder: session.account.sent_copy_folder(),
        new_message_id: &id,
        note,
        dry_run: target.dry_run,
    };
    let mut store = session.store()?;
    let mut sender = session.sender()?;
    emit(
        out,
        &service::forward(store.as_mut(), sender.as_mut(), &session.config, &job)?,
    )
}

fn apply(cli: &Cli, backend: &dyn Backend, out: &mut dyn Write, plan: &Path) -> Result<u8, Error> {
    let plan = Plan::parse(&backend.read_plan(plan)?)?;
    let session = Session::open(cli, backend, &plan.account)?;
    let mut store = session.store()?;
    let needs_sender = plan
        .ops
        .iter()
        .any(|op| matches!(op, plan::PlanOp::Forward { .. }));
    let mut sender: Box<dyn MailSender> = if needs_sender {
        session.sender()?
    } else {
        Box::new(NoSender)
    };
    let mut counter = 0_u32;
    let mut ids = || {
        counter = counter.saturating_add(1);
        Ok(session.new_message_id(counter))
    };
    let result = plan::run(
        &plan,
        &session.account,
        &session.config,
        store.as_mut(),
        sender.as_mut(),
        &mut ids,
    );
    write_json(out, &result)?;
    Ok(u8::from(result.failed > 0))
}

/// Placeholder transport for plans without forwards; it refuses to send.
struct NoSender;

impl MailSender for NoSender {
    fn send(
        &mut self,
        _from: &EmailAddress,
        _to: &EmailAddress,
        _message: &[u8],
    ) -> Result<(), Error> {
        Err(Error::Send(
            "no SMTP connection opened for this plan".into(),
        ))
    }
}

#[cfg(test)]
#[path = "tests/cli.rs"]
mod tests;
