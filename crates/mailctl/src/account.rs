//! `mailctl account …` and `mailctl allowlist …`: setting up accounts with
//! automatic server discovery and a manual fallback.

use std::io::Write;
use std::path::PathBuf;

use clap::{Args, Subcommand};
use serde::Serialize;

use crate::cli::{Backend, Cli};
use crate::config::{Access, AccountConfig, Config, PasswordSource, Secret, resolve_password};
use crate::discover::{self, Discovery, Endpoint, Security, ServerSettings};
use crate::error::Error;
use crate::guard::GuardedStore;
use crate::service;
use crate::setup::{self, NewAccount};
use crate::types::{EmailAddress, MailboxName};

/// Default keychain service name.
pub const DEFAULT_KEYCHAIN_SERVICE: &str = "mailctl";
/// IMAP port with implicit TLS.
const IMAPS: u16 = 993;
/// SMTP submission with STARTTLS.
const SUBMISSION: u16 = 587;
/// SMTP submission with implicit TLS.
const SUBMISSIONS: u16 = 465;

/// Account commands.
#[derive(Debug, Subcommand)]
pub enum AccountCommand {
    /// Find the mail servers for an address (does not change anything).
    Discover {
        /// E-mail address.
        address: String,
    },
    /// Add an account: discover servers, check the login, store the password.
    Add(AddArgs),
    /// Log in and check folders, sent folder and optionally SMTP.
    Test {
        /// Account name.
        #[arg(short, long)]
        account: String,
        /// Also log in to SMTP (sends nothing).
        #[arg(long)]
        smtp: bool,
    },
    /// Replace the password in the keychain after checking it.
    SetPassword {
        /// Account name.
        #[arg(short, long)]
        account: String,
        /// Read the password from standard input instead of the terminal.
        #[arg(long)]
        password_stdin: bool,
    },
    /// Change what mailctl may do in an account.
    SetAccess {
        /// Account name.
        #[arg(short, long)]
        account: String,
        /// New level: read, flag, organize or send.
        #[arg(value_enum)]
        access: Access,
    },
    /// Remove an account from the configuration.
    Remove {
        /// Account name.
        #[arg(short, long)]
        account: String,
        /// Also delete the password from the keychain.
        #[arg(long)]
        delete_password: bool,
    },
}

/// Options of `account add`. Every server option overrides discovery.
#[derive(Debug, Clone, Args)]
pub struct AddArgs {
    /// Short name, e.g. `icloud`.
    #[arg(long)]
    pub name: String,
    /// E-mail address.
    #[arg(long)]
    pub address: String,
    /// Login name (default: from discovery, else the address).
    #[arg(long)]
    pub user: Option<String>,
    /// IMAP host (implicit TLS).
    #[arg(long)]
    pub imap_host: Option<String>,
    /// IMAP port.
    #[arg(long)]
    pub imap_port: Option<u16>,
    /// SMTP host.
    #[arg(long)]
    pub smtp_host: Option<String>,
    /// SMTP port; 465 means implicit TLS, anything else STARTTLS.
    #[arg(long)]
    pub smtp_port: Option<u16>,
    /// SMTP login, if different from the IMAP login.
    #[arg(long)]
    pub smtp_user: Option<String>,
    /// Sent folder (default: detected after login).
    #[arg(long)]
    pub sent_folder: Option<String>,
    /// `keychain`, `keychain:<service>` or `env:<VARIABLE>`.
    #[arg(long, default_value = "keychain")]
    pub password_source: String,
    /// Read the password from standard input instead of the terminal.
    #[arg(long)]
    pub password_stdin: bool,
    /// What mailctl may do: read (default), flag, organize or send.
    #[arg(long, value_enum, default_value_t = Access::Read)]
    pub access: Access,
    /// Skip the login check (then `--sent-folder` is required).
    #[arg(long)]
    pub no_verify: bool,
    /// Show what would be written, change nothing.
    #[arg(long)]
    pub dry_run: bool,
}

/// Allow-list commands.
#[derive(Debug, Subcommand)]
pub enum AllowlistCommand {
    /// Allow forwarding to an address.
    Add {
        /// E-mail address.
        address: String,
    },
    /// Stop allowing forwarding to an address.
    Remove {
        /// E-mail address.
        address: String,
    },
}

fn emit<T: Serialize>(out: &mut dyn Write, value: &T) -> Result<u8, Error> {
    let json = serde_json::to_string_pretty(value)
        .map_err(|e| Error::InvalidInput(format!("output: {e}")))?;
    writeln!(out, "{json}").map_err(|e| Error::InvalidInput(format!("output: {e}")))?;
    Ok(0)
}

/// Parses `keychain`, `keychain:<service>` or `env:<VARIABLE>`.
///
/// # Errors
/// [`Error::InvalidInput`] for anything else.
pub fn parse_password_source(raw: &str) -> Result<PasswordSource, Error> {
    match raw.split_once(':') {
        None if raw == "keychain" => Ok(PasswordSource::Keychain(
            DEFAULT_KEYCHAIN_SERVICE.to_owned(),
        )),
        Some(("keychain", service)) if !service.is_empty() => {
            Ok(PasswordSource::Keychain(service.to_owned()))
        }
        Some(("env", var)) if !var.is_empty() => Ok(PasswordSource::Env(var.to_owned())),
        _ => Err(Error::InvalidInput(format!(
            "password source must be `keychain`, `keychain:<service>` or `env:<VARIABLE>`, got {raw:?}"
        ))),
    }
}

fn config_text(cli: &Cli, backend: &dyn Backend) -> Result<(PathBuf, String), Error> {
    let path = backend.config_path(cli.config.as_ref())?;
    let text = backend.read_optional(&path)?.unwrap_or_default();
    Ok((path, text))
}

/// Connections made by account setup only ever read.
fn read_only(
    backend: &dyn Backend,
    account: &AccountConfig,
    secret: &Secret,
) -> Result<GuardedStore, Error> {
    Ok(GuardedStore::new(
        backend.connect(account, secret)?,
        &account.name,
        Access::Read,
    ))
}

fn smtp_endpoint(host: &str, port: u16) -> Endpoint {
    let security = if port == SUBMISSIONS {
        Security::Tls
    } else {
        Security::StartTls
    };
    Endpoint {
        host: host.to_owned(),
        port,
        security,
    }
}

/// Runs an `account` command.
///
/// # Errors
/// Errors of the individual steps.
pub fn run_account(
    cli: &Cli,
    backend: &dyn Backend,
    out: &mut dyn Write,
    command: &AccountCommand,
) -> Result<u8, Error> {
    match command {
        AccountCommand::Discover { address } => {
            let address = EmailAddress::parse(address)?;
            emit(out, &discover::discover(&address, backend.net().as_mut())?)
        }
        AccountCommand::Add(args) => add(cli, backend, out, args),
        AccountCommand::Test { account, smtp } => test(cli, backend, out, account, *smtp),
        AccountCommand::SetPassword {
            account,
            password_stdin,
        } => set_password(cli, backend, out, account, *password_stdin),
        AccountCommand::SetAccess { account, access } => {
            let (path, text, _) = load(cli, backend, account)?;
            backend.write_file(&path, &setup::set_access(&text, account, *access)?)?;
            emit(
                out,
                &AccessReport {
                    account: account.clone(),
                    access: *access,
                },
            )
        }
        AccountCommand::Remove {
            account,
            delete_password,
        } => remove(cli, backend, out, account, *delete_password),
    }
}

/// Runs an `allowlist` command.
///
/// # Errors
/// Invalid address, configuration or write errors.
pub fn run_allowlist(
    cli: &Cli,
    backend: &dyn Backend,
    out: &mut dyn Write,
    command: &AllowlistCommand,
) -> Result<u8, Error> {
    let (path, text) = config_text(cli, backend)?;
    let (address, new_text, op) = match command {
        AllowlistCommand::Add { address } => {
            let address = EmailAddress::parse(address)?;
            let new_text = setup::allowlist_add(&text, &address)?;
            (address, new_text, "allowlist_add")
        }
        AllowlistCommand::Remove { address } => {
            let address = EmailAddress::parse(address)?;
            let new_text = setup::allowlist_remove(&text, &address)?;
            (address, new_text, "allowlist_remove")
        }
    };
    backend.write_file(&path, &new_text)?;
    emit(
        out,
        &AllowlistReport {
            op,
            address,
            config: path,
        },
    )
}

#[derive(Serialize)]
struct AllowlistReport {
    op: &'static str,
    address: EmailAddress,
    config: PathBuf,
}

#[derive(Debug, Serialize)]
struct AddReport {
    account: String,
    access: Access,
    settings: ServerSettings,
    source: String,
    discovery_trace: Vec<String>,
    sent_folder: MailboxName,
    verified: bool,
    password_stored: bool,
    dry_run: bool,
    config: PathBuf,
}

/// Where the server settings came from.
struct Resolved {
    settings: ServerSettings,
    source: String,
    trace: Vec<String>,
}

fn apply_overrides(mut settings: ServerSettings, args: &AddArgs) -> ServerSettings {
    if let Some(host) = &args.imap_host {
        settings.imap.host.clone_from(host);
    }
    if let Some(port) = args.imap_port {
        settings.imap.port = port;
    }
    if args.smtp_host.is_some() || args.smtp_port.is_some() {
        let host = args
            .smtp_host
            .clone()
            .unwrap_or_else(|| settings.smtp.host.clone());
        let port = args.smtp_port.unwrap_or(settings.smtp.port);
        settings.smtp = smtp_endpoint(&host, port);
    }
    if let Some(user) = &args.user {
        settings.username.clone_from(user);
    }
    settings
}

fn ask(
    backend: &dyn Backend,
    question: &str,
    default: Option<&str>,
    hint: &str,
) -> Result<String, Error> {
    backend
        .prompt_line(question, default)?
        .map(|answer| answer.trim().to_owned())
        .map(|answer| {
            if answer.is_empty() {
                default.unwrap_or_default().to_owned()
            } else {
                answer
            }
        })
        .filter(|answer| !answer.is_empty())
        .ok_or_else(|| Error::InvalidInput(hint.to_owned()))
}

fn ask_port(backend: &dyn Backend, question: &str, default: u16, hint: &str) -> Result<u16, Error> {
    ask(backend, question, Some(&default.to_string()), hint)?
        .parse()
        .map_err(|_| Error::InvalidInput(format!("{question}: not a port number")))
}

/// Manual fallback: asks for every value that was not given on the command line.
fn manual(
    backend: &dyn Backend,
    args: &AddArgs,
    address: &EmailAddress,
    reason: &str,
) -> Result<Resolved, Error> {
    let hint = format!(
        "{reason}. Set the servers manually with --imap-host and --smtp-host \
         (optional --imap-port, --smtp-port, --user), or run in a terminal to be asked."
    );
    let imap_host = match &args.imap_host {
        Some(host) => host.clone(),
        None => ask(backend, "IMAP server (TLS)", None, &hint)?,
    };
    let imap_port = match args.imap_port {
        Some(port) => port,
        None => ask_port(backend, "IMAP port", IMAPS, &hint)?,
    };
    let smtp_host = match &args.smtp_host {
        Some(host) => host.clone(),
        None => ask(backend, "SMTP server", Some(&imap_host), &hint)?,
    };
    let smtp_port = match args.smtp_port {
        Some(port) => port,
        None => ask_port(
            backend,
            "SMTP port (587 STARTTLS, 465 TLS)",
            SUBMISSION,
            &hint,
        )?,
    };
    let username = match &args.user {
        Some(user) => user.clone(),
        None => ask(backend, "Login name", Some(address.as_str()), &hint)?,
    };
    Ok(Resolved {
        settings: ServerSettings {
            imap: Endpoint {
                host: imap_host,
                port: imap_port,
                security: Security::Tls,
            },
            smtp: smtp_endpoint(&smtp_host, smtp_port),
            username,
        },
        source: "manual".to_owned(),
        trace: vec![reason.to_owned()],
    })
}

fn resolve_servers(
    backend: &dyn Backend,
    args: &AddArgs,
    address: &EmailAddress,
) -> Result<Resolved, Error> {
    if args.imap_host.is_some() && args.smtp_host.is_some() {
        return manual(backend, args, address, "servers given on the command line");
    }
    match discover::discover(address, backend.net().as_mut()) {
        Ok(Discovery {
            settings,
            source,
            trace,
        }) => Ok(Resolved {
            settings: apply_overrides(settings, args),
            source,
            trace,
        }),
        Err(e) => manual(backend, args, address, &e.to_string()),
    }
}

fn obtain_password(
    backend: &dyn Backend,
    source: &PasswordSource,
    probe: &AccountConfig,
    from_stdin: bool,
) -> Result<Secret, Error> {
    match source {
        PasswordSource::Env(_) => resolve_password(probe, backend.secrets()),
        PasswordSource::Keychain(_) if from_stdin => {
            let text = backend.read_stdin()?;
            let password = text.trim_end_matches(['\r', '\n']);
            if password.is_empty() {
                return Err(Error::InvalidInput(
                    "empty password on standard input".into(),
                ));
            }
            Ok(Secret::new(password.to_owned()))
        }
        PasswordSource::Keychain(_) => backend
            .prompt_password(&format!("Password for {}: ", probe.user))?
            .ok_or_else(|| {
                Error::InvalidInput(
                    "no terminal for the password prompt; use --password-stdin".into(),
                )
            }),
    }
}

/// Logs in (unless `--no-verify`), detects the sent folder and checks SMTP.
fn verify_new_account(
    backend: &dyn Backend,
    args: &AddArgs,
    password: &PasswordSource,
    probe: &mut AccountConfig,
) -> Result<(Option<Secret>, MailboxName), Error> {
    let explicit_sent = args
        .sent_folder
        .as_deref()
        .map(MailboxName::new)
        .transpose()?;
    if args.no_verify {
        let sent = explicit_sent
            .ok_or_else(|| Error::InvalidInput("--no-verify needs --sent-folder".into()))?;
        let secret = match password {
            PasswordSource::Keychain(_) => Some(obtain_password(
                backend,
                password,
                probe,
                args.password_stdin,
            )?),
            PasswordSource::Env(_) => None,
        };
        return Ok((secret, sent));
    }
    let secret = obtain_password(backend, password, probe, args.password_stdin)?;
    let folders = service::folders(&mut read_only(backend, probe, &secret)?)?;
    let sent = match explicit_sent {
        Some(name) if folders.iter().any(|f| f.name == name) => name,
        Some(name) => return Err(Error::FolderMissing(name.to_string())),
        None => setup::pick_sent_folder(&folders).ok_or_else(|| {
            Error::InvalidInput("no sent folder detected; pass --sent-folder".into())
        })?,
    };
    probe.sent_folder = sent.clone();
    backend.check_smtp(probe, &secret)?;
    Ok((Some(secret), sent))
}

fn add(cli: &Cli, backend: &dyn Backend, out: &mut dyn Write, args: &AddArgs) -> Result<u8, Error> {
    let address = EmailAddress::parse(&args.address)?;
    let password = parse_password_source(&args.password_source)?;
    let (path, text) = config_text(cli, backend)?;
    if let Ok(existing) = Config::parse(&text)
        && existing.account(&args.name).is_ok()
    {
        return Err(Error::Config(format!(
            "account {} already exists",
            args.name
        )));
    }
    let Resolved {
        settings,
        source,
        trace,
    } = resolve_servers(backend, args, &address)?;
    let placeholder_sent = MailboxName::inbox();
    let mut probe = AccountConfig {
        name: args.name.clone(),
        user: settings.username.clone(),
        address: address.clone(),
        imap_host: settings.imap.host.clone(),
        imap_port: settings.imap.port,
        smtp_host: settings.smtp.host.clone(),
        smtp_port: settings.smtp.port,
        smtp_user: args.smtp_user.clone(),
        sent_folder: placeholder_sent,
        password: password.clone(),
        access: Access::Read,
    };
    let (secret, sent_folder) = verify_new_account(backend, args, &password, &mut probe)?;
    let new_text = setup::add_account(
        &text,
        &NewAccount {
            name: args.name.clone(),
            user: probe.user.clone(),
            address,
            imap_host: probe.imap_host.clone(),
            imap_port: probe.imap_port,
            smtp_host: probe.smtp_host.clone(),
            smtp_port: probe.smtp_port,
            smtp_user: args.smtp_user.clone(),
            sent_folder: sent_folder.clone(),
            password: password.clone(),
            access: args.access,
        },
    )?;
    let mut password_stored = false;
    if !args.dry_run {
        if let (PasswordSource::Keychain(service), Some(secret)) = (&password, &secret) {
            backend.keychain_store(service, &probe.user, secret)?;
            password_stored = true;
        }
        backend.write_file(&path, &new_text)?;
    }
    emit(
        out,
        &AddReport {
            account: args.name.clone(),
            access: args.access,
            settings,
            source,
            discovery_trace: trace,
            sent_folder,
            verified: !args.no_verify,
            password_stored,
            dry_run: args.dry_run,
            config: path,
        },
    )
}

#[derive(Serialize)]
struct TestReport {
    account: String,
    access: Access,
    imap_login: bool,
    folders: usize,
    sent_folder: MailboxName,
    sent_folder_exists: bool,
    suggested_sent_folder: Option<MailboxName>,
    smtp_login: Option<bool>,
}

fn load(
    cli: &Cli,
    backend: &dyn Backend,
    name: &str,
) -> Result<(PathBuf, String, AccountConfig), Error> {
    let (path, text) = config_text(cli, backend)?;
    let account = Config::parse(&text)?.account(name)?.clone();
    Ok((path, text, account))
}

fn test(
    cli: &Cli,
    backend: &dyn Backend,
    out: &mut dyn Write,
    name: &str,
    smtp: bool,
) -> Result<u8, Error> {
    let (_, _, account) = load(cli, backend, name)?;
    let secret = resolve_password(&account, backend.secrets())?;
    let folders = service::folders(&mut read_only(backend, &account, &secret)?)?;
    let sent_folder_exists = folders.iter().any(|f| f.name == account.sent_folder);
    let smtp_login = if smtp {
        backend.check_smtp(&account, &secret)?;
        Some(true)
    } else {
        None
    };
    emit(
        out,
        &TestReport {
            account: account.name.clone(),
            access: account.access,
            imap_login: true,
            folders: folders.len(),
            sent_folder: account.sent_folder.clone(),
            sent_folder_exists,
            suggested_sent_folder: (!sent_folder_exists)
                .then(|| setup::pick_sent_folder(&folders))
                .flatten(),
            smtp_login,
        },
    )
}

#[derive(Serialize)]
struct AccessReport {
    account: String,
    access: Access,
}

#[derive(Serialize)]
struct PasswordReport {
    account: String,
    password_stored: bool,
}

fn set_password(
    cli: &Cli,
    backend: &dyn Backend,
    out: &mut dyn Write,
    name: &str,
    from_stdin: bool,
) -> Result<u8, Error> {
    let (_, _, account) = load(cli, backend, name)?;
    let PasswordSource::Keychain(service) = &account.password else {
        return Err(Error::InvalidInput(format!(
            "account {name} reads its password from the environment; change the variable instead"
        )));
    };
    let secret = obtain_password(backend, &account.password, &account, from_stdin)?;
    service::folders(&mut read_only(backend, &account, &secret)?)?;
    backend.keychain_store(service, &account.user, &secret)?;
    emit(
        out,
        &PasswordReport {
            account: account.name.clone(),
            password_stored: true,
        },
    )
}

#[derive(Serialize)]
struct RemoveReport {
    account: String,
    password_deleted: bool,
    config: PathBuf,
}

fn remove(
    cli: &Cli,
    backend: &dyn Backend,
    out: &mut dyn Write,
    name: &str,
    delete_password: bool,
) -> Result<u8, Error> {
    let (path, text, account) = load(cli, backend, name)?;
    let new_text = setup::remove_account(&text, name)?;
    backend.write_file(&path, &new_text)?;
    let mut password_deleted = false;
    if let (true, PasswordSource::Keychain(service)) = (delete_password, &account.password) {
        backend.keychain_delete(service, &account.user)?;
        password_deleted = true;
    }
    emit(
        out,
        &RemoveReport {
            account: name.to_owned(),
            password_deleted,
            config: path,
        },
    )
}

#[cfg(test)]
mod tests {
    use clap::Parser as _;

    use super::*;
    use crate::cli::run;
    use crate::discover::tests::{AUTOCONFIG, FakeNet};
    use crate::testing::FakeBackend;

    fn exec(b: &FakeBackend, args: &[&str]) -> Result<(serde_json::Value, u8), Error> {
        let cli = Cli::try_parse_from(std::iter::once("mailctl").chain(args.iter().copied()))
            .map_err(|e| Error::InvalidInput(e.to_string()))?;
        let mut out = Vec::new();
        let code = run(&cli, b, &mut out);
        let v = serde_json::from_slice(&out).map_err(|e| Error::InvalidInput(e.to_string()))?;
        Ok((v, code))
    }

    fn at<'a>(v: &'a serde_json::Value, p: &str) -> &'a serde_json::Value {
        v.pointer(p).unwrap_or(&serde_json::Value::Null)
    }

    fn plesk_net() -> FakeNet {
        let mut net = FakeNet {
            ok: vec![
                ("mail.example.net".into(), 993),
                ("mail.example.net".into(), 587),
            ],
            ..FakeNet::default()
        };
        net.pages.insert(
            "https://example.com/.well-known/autoconfig/mail/config-v1.1.xml".into(),
            AUTOCONFIG.into(),
        );
        net
    }

    #[test]
    fn password_sources() {
        assert_eq!(
            parse_password_source("keychain"),
            Ok(PasswordSource::Keychain("mailctl".into()))
        );
        assert_eq!(
            parse_password_source("keychain:x"),
            Ok(PasswordSource::Keychain("x".into()))
        );
        assert_eq!(
            parse_password_source("env:PW"),
            Ok(PasswordSource::Env("PW".into()))
        );
        for bad in ["", "env:", "keychain:", "file:x", "plain"] {
            assert!(parse_password_source(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn discover_command() -> Result<(), Error> {
        let b = FakeBackend::new(plesk_net());
        let (v, code) = exec(&b, &["account", "discover", "alice@example.com"])?;
        assert_eq!(
            (code, at(&v, "/settings/imap/host")),
            (0, &serde_json::Value::from("mail.example.net"))
        );
        Ok(())
    }

    #[test]
    fn add_with_discovery_verifies_and_stores() -> Result<(), Error> {
        let b = FakeBackend::new(plesk_net());
        b.passwords.borrow_mut().push("geheim".into());
        let (v, code) = exec(
            &b,
            &[
                "account",
                "add",
                "--name",
                "work",
                "--address",
                "alice@example.com",
            ],
        )?;
        assert_eq!(code, 0, "{v}");
        assert_eq!(at(&v, "/sent_folder"), "Sent");
        assert_eq!(at(&v, "/password_stored"), true);
        assert_eq!(
            b.keychain
                .borrow()
                .get(&("mailctl".to_owned(), "alice".to_owned()))
                .map(String::as_str),
            Some("geheim")
        );
        let config = Config::parse(&b.file_text())?;
        assert_eq!(config.account("work")?.imap_host, "mail.example.net");
        assert_eq!(b.smtp_checks.get(), 1);
        assert_eq!(config.account("work")?.access, Access::Read);
        let (v, _) = exec(&b, &["account", "set-access", "-a", "work", "organize"])?;
        assert_eq!(at(&v, "/access"), "organize");
        assert_eq!(
            Config::parse(&b.file_text())?.account("work")?.access,
            Access::Organize
        );
        let (v, code) = exec(
            &b,
            &[
                "account",
                "add",
                "--name",
                "work",
                "--address",
                "alice@example.com",
            ],
        )?;
        assert_eq!(code, 2);
        assert!(
            at(&v, "/error")
                .as_str()
                .is_some_and(|e| e.contains("already exists"))
        );
        Ok(())
    }

    #[test]
    fn add_overrides_and_dry_run() -> Result<(), Error> {
        let b = FakeBackend::new(plesk_net());
        b.stdin.borrow_mut().push_str("pw\n");
        let (v, _) = exec(
            &b,
            &[
                "account",
                "add",
                "--name",
                "n",
                "--address",
                "alice@example.com",
                "--password-stdin",
                "--imap-port",
                "1993",
                "--smtp-port",
                "465",
                "--user",
                "j",
                "--sent-folder",
                "Sent",
                "--dry-run",
            ],
        )?;
        assert_eq!(at(&v, "/settings/imap/port"), 1993);
        assert_eq!(at(&v, "/settings/smtp/security"), "tls");
        assert_eq!(at(&v, "/settings/username"), "j");
        assert_eq!(at(&v, "/dry_run"), true);
        assert!(b.file_text().is_empty() && b.keychain.borrow().is_empty());
        let (v, code) = exec(
            &b,
            &[
                "account",
                "add",
                "--name",
                "n",
                "--address",
                "alice@example.com",
                "--sent-folder",
                "Nope",
            ],
        )?;
        assert_eq!(code, 2, "{v}");
        Ok(())
    }

    #[test]
    fn imap_override_and_env_password_with_verification() -> Result<(), Error> {
        let mut net = plesk_net();
        net.ok.push(("imap.other".into(), 993));
        let b = FakeBackend::new(net);
        let (v, code) = exec(
            &b,
            &[
                "account",
                "add",
                "--name",
                "n",
                "--address",
                "alice@example.com",
                "--imap-host",
                "imap.other",
                "--password-source",
                "env:PW",
            ],
        )?;
        assert_eq!(code, 0, "{v}");
        assert_eq!(at(&v, "/settings/imap/host"), "imap.other");
        assert_eq!(at(&v, "/settings/smtp/host"), "mail.example.net");
        assert_eq!(at(&v, "/password_stored"), false);
        b.env_password.replace(None);
        let (v, code) = exec(
            &b,
            &[
                "account",
                "add",
                "--name",
                "m",
                "--address",
                "alice@example.com",
                "--password-source",
                "env:PW",
            ],
        )?;
        assert_eq!(code, 2);
        assert!(
            at(&v, "/error")
                .as_str()
                .is_some_and(|e| e.contains("not set")),
            "{v}"
        );
        Ok(())
    }

    #[test]
    fn manual_fallback_asks_or_explains() -> Result<(), Error> {
        let b = FakeBackend::new(FakeNet::default());
        b.answers.borrow_mut().extend([
            "mail.example.org".to_owned(),
            String::new(),
            String::new(),
            "465".into(),
            String::new(),
        ]);
        b.passwords.borrow_mut().push("pw".into());
        let (v, code) = exec(
            &b,
            &[
                "account",
                "add",
                "--name",
                "x",
                "--address",
                "a@example.org",
            ],
        )?;
        assert_eq!(code, 0, "{v}");
        assert_eq!(at(&v, "/source"), "manual");
        assert_eq!(at(&v, "/settings/smtp/host"), "mail.example.org");
        assert_eq!(at(&v, "/settings/smtp/port"), 465);
        assert_eq!(at(&v, "/settings/username"), "a@example.org");

        let headless = FakeBackend {
            terminal: false,
            ..FakeBackend::new(FakeNet::default())
        };
        let (v, code) = exec(
            &headless,
            &[
                "account",
                "add",
                "--name",
                "x",
                "--address",
                "a@example.org",
            ],
        )?;
        assert_eq!(code, 2);
        assert!(
            at(&v, "/error")
                .as_str()
                .is_some_and(|e| e.contains("--imap-host and --smtp-host"))
        );

        let bad_port = FakeBackend::new(FakeNet::default());
        bad_port
            .answers
            .borrow_mut()
            .extend(["mail.example.org".to_owned(), "abc".into()]);
        let (v, _) = exec(
            &bad_port,
            &[
                "account",
                "add",
                "--name",
                "x",
                "--address",
                "a@example.org",
            ],
        )?;
        assert!(
            at(&v, "/error")
                .as_str()
                .is_some_and(|e| e.contains("not a port"))
        );
        Ok(())
    }

    #[test]
    fn manual_flags_and_no_verify() -> Result<(), Error> {
        let b = FakeBackend::new(FakeNet::default());
        b.stdin.borrow_mut().push_str("pw");
        let (v, code) = exec(
            &b,
            &[
                "account",
                "add",
                "--name",
                "w",
                "--address",
                "alice@example.org",
                "--imap-host",
                "imap.w",
                "--smtp-host",
                "smtp.w",
                "--imap-port",
                "993",
                "--smtp-port",
                "587",
                "--user",
                "u",
                "--no-verify",
                "--sent-folder",
                "INBOX.Sent",
                "--password-stdin",
            ],
        )?;
        assert_eq!(code, 0, "{v}");
        assert_eq!(
            (at(&v, "/source"), at(&v, "/verified")),
            (
                &serde_json::Value::from("manual"),
                &serde_json::Value::from(false)
            )
        );
        let env = FakeBackend::new(FakeNet::default());
        let (v, code) = exec(
            &env,
            &[
                "account",
                "add",
                "--name",
                "e",
                "--address",
                "a@b.de",
                "--imap-host",
                "i",
                "--smtp-host",
                "s",
                "--no-verify",
                "--sent-folder",
                "Sent",
                "--password-source",
                "env:PW",
            ],
        )?;
        assert_eq!(
            (code, at(&v, "/password_stored")),
            (0, &serde_json::Value::from(false))
        );
        let (v, _) = exec(
            &env,
            &[
                "account",
                "add",
                "--name",
                "f",
                "--address",
                "a@b.de",
                "--imap-host",
                "i",
                "--smtp-host",
                "s",
                "--no-verify",
            ],
        )?;
        assert!(
            at(&v, "/error")
                .as_str()
                .is_some_and(|e| e.contains("--sent-folder"))
        );
        Ok(())
    }

    #[test]
    fn password_input_errors() -> Result<(), Error> {
        let b = FakeBackend {
            terminal: false,
            ..FakeBackend::new(plesk_net())
        };
        let (v, _) = exec(
            &b,
            &[
                "account",
                "add",
                "--name",
                "n",
                "--address",
                "alice@example.com",
            ],
        )?;
        assert!(
            at(&v, "/error")
                .as_str()
                .is_some_and(|e| e.contains("--password-stdin"))
        );
        let (v, _) = exec(
            &b,
            &[
                "account",
                "add",
                "--name",
                "n",
                "--address",
                "alice@example.com",
                "--password-stdin",
            ],
        )?;
        assert!(
            at(&v, "/error")
                .as_str()
                .is_some_and(|e| e.contains("empty password"))
        );
        let none = FakeBackend {
            sent_folder_flag: false,
            ..FakeBackend::new(plesk_net())
        };
        none.passwords.borrow_mut().push("pw".into());
        let (v, _) = exec(
            &none,
            &[
                "account",
                "add",
                "--name",
                "n",
                "--address",
                "alice@example.com",
            ],
        )?;
        assert!(
            at(&v, "/error")
                .as_str()
                .is_some_and(|e| e.contains("no sent folder")),
            "{v}"
        );
        Ok(())
    }

    #[test]
    fn test_set_password_remove_and_allowlist() -> Result<(), Error> {
        let b = FakeBackend::new(plesk_net());
        b.passwords.borrow_mut().push("pw".into());
        exec(
            &b,
            &[
                "account",
                "add",
                "--name",
                "work",
                "--address",
                "alice@example.com",
            ],
        )?;
        let (v, _) = exec(&b, &["account", "test", "-a", "work", "--smtp"])?;
        assert_eq!(
            (at(&v, "/sent_folder_exists"), at(&v, "/smtp_login")),
            (
                &serde_json::Value::from(true),
                &serde_json::Value::from(true)
            )
        );
        let (v, _) = exec(&b, &["account", "test", "-a", "work"])?;
        assert_eq!(at(&v, "/smtp_login"), &serde_json::Value::Null);
        b.passwords.borrow_mut().push("neu".into());
        let (v, _) = exec(&b, &["account", "set-password", "-a", "work"])?;
        assert_eq!(at(&v, "/password_stored"), true);
        let (v, _) = exec(&b, &["allowlist", "add", "Accounting@example.com"])?;
        assert_eq!(at(&v, "/address"), "accounting@example.com");
        exec(&b, &["allowlist", "remove", "accounting@example.com"])?;
        let (v, code) = exec(&b, &["allowlist", "remove", "accounting@example.com"])?;
        assert_eq!(code, 2, "{v}");

        b.stdin.borrow_mut().push_str("pw\n");
        exec(
            &b,
            &[
                "account",
                "add",
                "--name",
                "env",
                "--address",
                "a@b.de",
                "--imap-host",
                "i",
                "--smtp-host",
                "s",
                "--no-verify",
                "--sent-folder",
                "Sent",
                "--password-source",
                "env:PW",
            ],
        )?;
        let (v, _) = exec(&b, &["account", "set-password", "-a", "env"])?;
        assert!(
            at(&v, "/error")
                .as_str()
                .is_some_and(|e| e.contains("environment"))
        );
        let (v, _) = exec(&b, &["account", "remove", "-a", "env", "--delete-password"])?;
        assert_eq!(at(&v, "/password_deleted"), false);
        let (v, _) = exec(
            &b,
            &["account", "remove", "-a", "work", "--delete-password"],
        )?;
        assert!(
            at(&v, "/error")
                .as_str()
                .is_some_and(|e| e.contains("accounts")),
            "{v}"
        );
        Ok(())
    }

    #[test]
    fn remove_deletes_keychain_item_and_reports_missing_sent() -> Result<(), Error> {
        let b = FakeBackend::new(plesk_net());
        b.passwords
            .borrow_mut()
            .extend(["a".to_owned(), "b".to_owned()]);
        exec(
            &b,
            &[
                "account",
                "add",
                "--name",
                "one",
                "--address",
                "alice@example.com",
            ],
        )?;
        exec(
            &b,
            &[
                "account",
                "add",
                "--name",
                "two",
                "--address",
                "alice@example.com",
                "--sent-folder",
                "INBOX",
            ],
        )?;
        let (v, _) = exec(&b, &["account", "remove", "-a", "one", "--delete-password"])?;
        assert_eq!(at(&v, "/password_deleted"), true);
        assert!(b.keychain.borrow().is_empty());
        b.env_password.replace(Some("x".into()));
        let text = b
            .file_text()
            .replace("sent_folder = \"INBOX\"", "sent_folder = \"Gone\"");
        b.files
            .borrow_mut()
            .insert(PathBuf::from("/cfg.toml"), text);
        b.keychain
            .borrow_mut()
            .insert(("mailctl".into(), "alice".into()), "b".into());
        let (v, _) = exec(&b, &["account", "test", "-a", "two"])?;
        assert_eq!(
            (
                at(&v, "/sent_folder_exists"),
                at(&v, "/suggested_sent_folder")
            ),
            (
                &serde_json::Value::from(false),
                &serde_json::Value::from("Sent")
            )
        );
        Ok(())
    }
}
