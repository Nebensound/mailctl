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
        /// Only mails with a UID below this one (paging).
        #[arg(long)]
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

fn to_json<T: Serialize>(value: &T) -> Result<String, Error> {
    serde_json::to_string_pretty(value).map_err(|e| Error::InvalidInput(format!("output: {e}")))
}

fn write_line(out: &mut dyn Write, text: &str) -> Result<(), Error> {
    writeln!(out, "{text}").map_err(|e| Error::InvalidInput(format!("output: {e}")))
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
/// become a JSON object with an `error` field.
///
/// Returns the process exit code: 0 success, 1 some plan operations failed,
/// 2 error.
pub fn run(cli: &Cli, backend: &dyn Backend, out: &mut dyn Write) -> u8 {
    match dispatch(cli, backend, out) {
        Ok(code) => code,
        Err(e) => {
            let json = to_json(&ErrorOutput {
                error: &e.to_string(),
            })
            .unwrap_or_else(|_| "{\"error\":\"unprintable error\"}".to_owned());
            let _ = write_line(out, &json);
            2
        }
    }
}

fn emit<T: Serialize>(out: &mut dyn Write, value: &T) -> Result<u8, Error> {
    write_line(out, &to_json(value)?)?;
    Ok(0)
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

    fn sender(&self) -> Result<Box<dyn MailSender>, Error> {
        self.require(Access::Send)?;
        self.backend.sender(&self.account, &self.secret)
    }

    fn new_message_id(&self, counter: u32) -> Result<MessageId, Error> {
        let time = self.backend.unix_time();
        let domain = self.account.address.domain();
        MessageId::parse(&format!("mailctl-{time}-{counter}@{domain}"))
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
    let folders: Vec<MailboxName> = if request.all_folders {
        service::folders(store.as_mut())?
            .into_iter()
            .filter(|f| f.selectable)
            .map(|f| f.name)
            .collect()
    } else {
        vec![MailboxName::new(&location.folder)?]
    };
    if request.ndjson {
        for folder in &folders {
            service::list_each(
                store.as_mut(),
                folder,
                request.limit,
                before,
                service::FETCH_CHUNK,
                &mut |mail| {
                    let line = serde_json::to_string(&Listed { folder, mail })
                        .map_err(|e| Error::InvalidInput(format!("output: {e}")))?;
                    write_line(out, &line)
                },
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
    let mut mails = Vec::new();
    for folder in &folders {
        mails.extend(service::list(
            store.as_mut(),
            folder,
            request.limit,
            before,
        )?);
    }
    emit(out, &mails)
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
    let id = session.new_message_id(1)?;
    let job = ForwardJob {
        folder: &folder,
        uid,
        expect: &expect,
        to: &to,
        from: &session.account.address,
        sent_folder: &session.account.sent_folder,
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
    let mut sender: Box<dyn MailSender> = if needs_sender && session.account.access >= Access::Send
    {
        session.sender()?
    } else {
        Box::new(NoSender)
    };
    let mut counter = 0_u32;
    let mut ids = || {
        counter = counter.saturating_add(1);
        session.new_message_id(counter)
    };
    let result = plan::run(
        &plan,
        &session.account,
        &session.config,
        store.as_mut(),
        sender.as_mut(),
        &mut ids,
    );
    write_line(out, &to_json(&result)?)?;
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
mod tests {
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;

    use super::*;
    use crate::testing::{FakeSender, FakeStore, Shared, mail};

    const CONFIG: &str = r#"
forward_allowlist = ["accounting@example.com"]
[[accounts]]
name = "test"
user = "alice@example.com"
address = "alice@example.com"
imap_host = "imap.test"
smtp_host = "smtp.test"
sent_folder = "Sent"
password = { env = "PW" }
access = "send"
"#;

    struct Env {
        password: Option<String>,
    }

    impl SecretLookup for Env {
        fn env(&self, _name: &str) -> Option<String> {
            self.password.clone()
        }
        fn keychain(&self, _service: &str, _account: &str) -> Result<String, String> {
            Err("no keychain in tests".into())
        }
    }

    struct TestBackend {
        config: Result<String, Error>,
        plan: String,
        env: Env,
        store: Rc<RefCell<FakeStore>>,
        sent: Cell<usize>,
        fail_connect: bool,
    }

    impl TestBackend {
        fn new() -> Self {
            Self {
                config: Ok(CONFIG.to_owned()),
                plan: String::new(),
                env: Env {
                    password: Some("pw".into()),
                },
                store: Rc::new(RefCell::new(FakeStore::with_inbox(vec![
                    mail(2, "a@x", "Invoice", &[]),
                    mail(3, "b@x", "News", &[]),
                ]))),
                sent: Cell::new(0),
                fail_connect: false,
            }
        }
    }

    impl Backend for TestBackend {
        fn read_config(&self, _path: Option<&PathBuf>) -> Result<String, Error> {
            self.config.clone()
        }
        fn read_plan(&self, _path: &Path) -> Result<String, Error> {
            Ok(self.plan.clone())
        }
        fn secrets(&self) -> &dyn SecretLookup {
            &self.env
        }
        fn connect(&self, _a: &AccountConfig, _s: &Secret) -> Result<Box<dyn MailStore>, Error> {
            if self.fail_connect {
                return Err(Error::Store("connection refused".into()));
            }
            Ok(Box::new(Shared(Rc::clone(&self.store))))
        }
        fn sender(&self, _a: &AccountConfig, _s: &Secret) -> Result<Box<dyn MailSender>, Error> {
            self.sent.set(self.sent.get().saturating_add(1));
            Ok(Box::new(FakeSender::default()))
        }
        fn unix_time(&self) -> u64 {
            1_700_000_000
        }
        fn config_path(&self, _explicit: Option<&PathBuf>) -> Result<PathBuf, Error> {
            Ok(PathBuf::from("/unused"))
        }
        fn read_optional(&self, _path: &Path) -> Result<Option<String>, Error> {
            Ok(None)
        }
        fn write_file(&self, _path: &Path, _text: &str) -> Result<(), Error> {
            Ok(())
        }
        fn prompt_line(&self, _q: &str, _d: Option<&str>) -> Result<Option<String>, Error> {
            Ok(None)
        }
        fn prompt_password(&self, _p: &str) -> Result<Option<Secret>, Error> {
            Ok(None)
        }
        fn read_stdin(&self) -> Result<String, Error> {
            Ok(String::new())
        }
        fn keychain_store(&self, _s: &str, _a: &str, _p: &Secret) -> Result<(), Error> {
            Ok(())
        }
        fn keychain_delete(&self, _s: &str, _a: &str) -> Result<(), Error> {
            Ok(())
        }
        fn net(&self) -> Box<dyn Net> {
            Box::new(crate::discover::tests::FakeNet::default())
        }
        fn check_smtp(&self, _a: &AccountConfig, _s: &Secret) -> Result<(), Error> {
            Ok(())
        }
    }

    fn at<'a>(v: &'a serde_json::Value, pointer: &str) -> &'a serde_json::Value {
        v.pointer(pointer).unwrap_or(&serde_json::Value::Null)
    }

    fn exec(backend: &TestBackend, args: &[&str]) -> Result<(serde_json::Value, u8), Error> {
        let cli = Cli::try_parse_from(std::iter::once("mailctl").chain(args.iter().copied()))
            .map_err(|e| Error::InvalidInput(e.to_string()))?;
        let mut out = Vec::new();
        let code = run(&cli, backend, &mut out);
        let first_line = String::from_utf8_lossy(&out);
        let text = if args.contains(&"--ndjson") {
            first_line.lines().next().unwrap_or_default().to_owned()
        } else {
            first_line.into_owned()
        };
        let value = serde_json::from_str(&text).map_err(|e| Error::InvalidInput(e.to_string()))?;
        Ok((value, code))
    }

    #[test]
    fn offline_and_listing_commands() -> Result<(), Error> {
        let b = TestBackend::new();
        let (v, code) = exec(&b, &["ref", "<m2@test>"])?;
        assert_eq!(code, 0);
        assert_eq!(
            at(&v, "/mail_ref"),
            MailRef::from_message_id(&MessageId::parse("m2@test")?).as_str()
        );
        let (v, _) = exec(&b, &["accounts"])?;
        assert_eq!(at(&v, "/0/name"), "test");
        let (v, _) = exec(&b, &["folders", "-a", "test"])?;
        assert_eq!(v.as_array().map(Vec::len), Some(4));
        let (v, _) = exec(&b, &["list", "-a", "test", "-n", "1"])?;
        assert_eq!(at(&v, "/0/uid"), 3);
        let (v, _) = exec(&b, &["list", "-a", "test", "--before", "3"])?;
        assert_eq!(at(&v, "/0/uid"), 2);
        let (v, _) = exec(
            &b,
            &["show", "-a", "test", "--uid", "2", "--expect", "m2@test"],
        )?;
        assert_eq!(at(&v, "/subject"), "Invoice");
        let (v, _) = exec(&b, &["show", "-a", "test", "--uid", "2"])?;
        assert_eq!(at(&v, "/uid"), 2);
        Ok(())
    }

    #[test]
    fn ndjson_and_all_folders() -> Result<(), Error> {
        let b = TestBackend::new();
        let cli =
            Cli::try_parse_from(["mailctl", "list", "-a", "test", "--ndjson", "--all-folders"])
                .map_err(|e| Error::InvalidInput(e.to_string()))?;
        let mut out = Vec::new();
        assert_eq!(run(&cli, &b, &mut out), 0);
        let lines: Vec<serde_json::Value> = String::from_utf8_lossy(&out)
            .lines()
            .map(serde_json::from_str)
            .collect::<Result<_, _>>()
            .map_err(|e| Error::InvalidInput(e.to_string()))?;
        assert_eq!(lines.len(), 2);
        assert_eq!(
            at(lines.first().unwrap_or(&serde_json::Value::Null), "/folder"),
            "INBOX"
        );
        let (v, _) = exec(&b, &["list", "-a", "test", "--all-folders"])?;
        assert_eq!(at(&v, "/1/uid"), 2);
        let (v, code) = exec(&b, &["list", "-a", "test", "--ndjson", "-n", "1"])?;
        assert_eq!((code, at(&v, "/uid")), (0, &serde_json::Value::from(3)));
        Ok(())
    }

    #[test]
    fn write_errors_are_reported() -> Result<(), Error> {
        struct Broken;
        impl Write for Broken {
            fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("closed"))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let b = TestBackend::new();
        let cli = Cli::try_parse_from(["mailctl", "list", "-a", "test", "--ndjson"])
            .map_err(|e| Error::InvalidInput(e.to_string()))?;
        assert_eq!(run(&cli, &b, &mut Broken), 2);
        Ok(())
    }

    fn with_access(access: &str) -> TestBackend {
        let mut b = TestBackend::new();
        b.config = Ok(CONFIG.replace("access = \"send\"", &format!("access = \"{access}\"")));
        b
    }

    /// Every changing command, live and as dry run, as plain commands and as plans.
    const CHANGES: &[&[&str]] = &[
        &[
            "mark-read",
            "-a",
            "test",
            "--uid",
            "2",
            "--expect",
            "m2@test",
        ],
        &[
            "mark-read",
            "-a",
            "test",
            "--uid",
            "2",
            "--expect",
            "m2@test",
            "--dry-run",
        ],
        &[
            "move",
            "-a",
            "test",
            "--uid",
            "2",
            "--expect",
            "m2@test",
            "--to",
            "Work/GitHub",
        ],
        &[
            "move",
            "-a",
            "test",
            "--uid",
            "2",
            "--expect",
            "m2@test",
            "--to",
            "Work/GitHub",
            "--dry-run",
        ],
        &[
            "move",
            "-a",
            "test",
            "--uid",
            "2",
            "--expect",
            "m2@test",
            "--to",
            "Work/GitHub",
            "--mark-read",
        ],
        &["create-folder", "-a", "test", "New"],
        &["create-folder", "-a", "test", "New", "--dry-run"],
        &[
            "forward",
            "-a",
            "test",
            "--uid",
            "2",
            "--expect",
            "m2@test",
            "--to",
            "accounting@example.com",
        ],
        &[
            "forward",
            "-a",
            "test",
            "--uid",
            "2",
            "--expect",
            "m2@test",
            "--to",
            "accounting@example.com",
            "--dry-run",
        ],
    ];

    const PLAN_ALL: &str = r#"{"account":"test","dry_run":DRY,"ops":[
        {"op":"mark_read","uid":2,"expect":"m2@test"},
        {"op":"move","uid":2,"expect":"m2@test","to":"Work/GitHub","mark_read":true},
        {"op":"create_folder","name":"New"},
        {"op":"forward","uid":2,"expect":"m2@test","to":"accounting@example.com"}]}"#;

    #[test]
    fn read_only_account_cannot_change_anything() -> Result<(), Error> {
        let mut b = with_access("read");
        let before = b.store.borrow().snapshot();
        for args in CHANGES {
            let (v, code) = exec(&b, args)?;
            assert_eq!(code, 2, "{args:?} must be refused: {v}");
            assert!(
                at(&v, "/error")
                    .as_str()
                    .is_some_and(|e| e.contains("is set to `read`")),
                "{args:?}: {v}"
            );
        }
        for dry in ["false", "true"] {
            b.plan = PLAN_ALL.replace("DRY", dry);
            let (v, code) = exec(&b, &["apply", "plan.json"])?;
            assert_eq!(
                (code, at(&v, "/failed")),
                (1, &serde_json::Value::from(4)),
                "{v}"
            );
        }
        assert_eq!(
            b.store.borrow().snapshot(),
            before,
            "mailbox must be unchanged"
        );
        assert_eq!(
            b.store.borrow().mutations,
            0,
            "no changing call may reach the server"
        );
        assert_eq!(b.sent.get(), 0, "no SMTP connection may be opened");
        let (v, code) = exec(&b, &["list", "-a", "test"])?;
        assert_eq!((code, at(&v, "/0/uid")), (0, &serde_json::Value::from(3)));
        assert!(
            b.store.borrow().read_only,
            "read accounts must open folders with EXAMINE"
        );
        let (_, code) = exec(&b, &["show", "-a", "test", "--uid", "2"])?;
        assert_eq!(code, 0);
        assert_eq!(
            b.store.borrow().snapshot(),
            before,
            "reading must not set \\Seen"
        );
        Ok(())
    }

    #[test]
    fn access_matrix() -> Result<(), Error> {
        // Dry runs of: mark-read (flag), move (organize), create-folder (organize), forward (send).
        let commands: [(&[&str], Access); 4] = [
            (CHANGES.get(1).copied().unwrap_or_default(), Access::Flag),
            (
                CHANGES.get(3).copied().unwrap_or_default(),
                Access::Organize,
            ),
            (
                CHANGES.get(6).copied().unwrap_or_default(),
                Access::Organize,
            ),
            (CHANGES.get(8).copied().unwrap_or_default(), Access::Send),
        ];
        for level in [Access::Read, Access::Flag, Access::Organize, Access::Send] {
            for (args, needed) in &commands {
                let b = with_access(level.as_str());
                let (v, code) = exec(&b, args)?;
                let expected = if level >= *needed { 0 } else { 2 };
                assert_eq!(code, expected, "{level:?} {args:?}: {v}");
            }
        }
        Ok(())
    }

    #[test]
    fn changing_commands() -> Result<(), Error> {
        let b = TestBackend::new();
        let (v, code) = exec(
            &b,
            &[
                "mark-read",
                "-a",
                "test",
                "--uid",
                "2",
                "--expect",
                "m2@test",
            ],
        )?;
        assert_eq!((code, at(&v, "/confirmed").as_bool()), (0, Some(true)));
        let (v, _) = exec(
            &b,
            &[
                "move",
                "-a",
                "test",
                "--uid",
                "3",
                "--expect",
                "m3@test",
                "--to",
                "Work/GitHub",
                "--mark-read",
                "--dry-run",
            ],
        )?;
        assert_eq!(at(&v, "/dry_run"), true);
        let (v, _) = exec(&b, &["create-folder", "-a", "test", "New", "--dry-run"])?;
        assert_eq!(at(&v, "/target"), "New");
        let (v, _) = exec(
            &b,
            &[
                "forward",
                "-a",
                "test",
                "--uid",
                "2",
                "--expect",
                "m2@test",
                "--to",
                "accounting@example.com",
                "--note",
                "Please",
                "--dry-run",
            ],
        )?;
        assert_eq!(at(&v, "/op"), "forward");
        assert_eq!(b.sent.get(), 1);
        Ok(())
    }

    #[test]
    fn apply_plans() -> Result<(), Error> {
        let mut b = TestBackend::new();
        b.plan = r#"{"account":"test","ops":[{"op":"move","uid":3,"expect":"m3@test","to":"Work/GitHub"}]}"#.into();
        let (v, code) = exec(&b, &["apply", "plan.json"])?;
        assert_eq!((code, at(&v, "/failed").as_u64()), (0, Some(0)));
        assert_eq!(b.sent.get(), 0);
        b.plan = r#"{"account":"test","ops":[
            {"op":"forward","uid":2,"expect":"m2@test","to":"accounting@example.com"},
            {"op":"move","uid":99,"expect":"m99@test","to":"Work/GitHub"}]}"#
            .into();
        let (v, code) = exec(&b, &["apply", "-"])?;
        assert_eq!((code, at(&v, "/failed").as_u64()), (1, Some(1)));
        assert_eq!(b.sent.get(), 1);
        Ok(())
    }

    #[test]
    fn errors_become_json() -> Result<(), Error> {
        let mut b = TestBackend::new();
        let (v, code) = exec(&b, &["list", "-a", "nope"])?;
        assert_eq!(code, 2);
        assert!(
            at(&v, "/error")
                .as_str()
                .is_some_and(|e| e.contains("unknown account"))
        );
        b.fail_connect = true;
        let (_, code) = exec(&b, &["folders", "-a", "test"])?;
        assert_eq!(code, 2);
        b.env.password = None;
        let (v, _) = exec(&b, &["folders", "-a", "test"])?;
        assert!(
            at(&v, "/error")
                .as_str()
                .is_some_and(|e| e.contains("no password"))
        );
        b.config = Err(Error::Config("missing".into()));
        let (_, code) = exec(&b, &["accounts"])?;
        assert_eq!(code, 2);
        Ok(())
    }

    #[test]
    fn no_sender_refuses() -> Result<(), Error> {
        let addr = EmailAddress::parse("a@b.de")?;
        assert!(NoSender.send(&addr, &addr, b"x").is_err());
        Ok(())
    }
}
