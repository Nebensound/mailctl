//! `mailctl account …` and `mailctl allowlist …`: setting up accounts with
//! automatic server discovery and a manual fallback.

use std::io::Write;
use std::path::PathBuf;

use clap::{Args, Subcommand};
use serde::Serialize;

use crate::cli::{Backend, Cli};
use crate::config::{Access, AccountConfig, Config, PasswordSource, Secret, resolve_password};
use crate::discover::{self, Discovery, Endpoint, Security, ServerSettings, smtp_endpoint};
use crate::error::Error;
use crate::guard::GuardedStore;
use crate::service;
use crate::setup::{self, NewAccount};
use crate::types::{EmailAddress, IMAPS_PORT as IMAPS, MailboxName, SUBMISSION_PORT as SUBMISSION};

/// Default keychain service name.
pub const DEFAULT_KEYCHAIN_SERVICE: &str = "mailctl";

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
        /// Also delete the password from the keychain, unless another account
        /// uses the same keychain item.
        #[arg(long)]
        delete_password: bool,
    },
}

/// Options of `account add`. Every server option overrides discovery.
#[derive(Debug, Clone, Args)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "independent command-line switches"
)]
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
    /// Accept servers outside the address's domain that DNS pointed to,
    /// without asking.
    #[arg(long)]
    pub yes: bool,
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
    crate::cli::write_json(out, value).map(|()| 0)
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
            let (path, text) = config_text(cli, backend)?;
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
    /// Servers from unauthenticated DNS outside the address's domain.
    unconfirmed_hosts: Vec<String>,
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
        unconfirmed_hosts: Vec::new(),
    })
}

/// Asks before the password is sent to servers outside the address's domain
/// that only unauthenticated DNS pointed to.
fn confirm_hosts(
    backend: &dyn Backend,
    hosts: &[String],
    address: &EmailAddress,
) -> Result<(), Error> {
    if hosts.is_empty() {
        return Ok(());
    }
    let list = hosts.join(", ");
    let domain = address.domain();
    let question =
        format!("DNS points to {list}, outside {domain}. Send the password there? [y/N]");
    let answer = backend.prompt_line(&question, None)?.ok_or_else(|| {
        Error::InvalidInput(format!(
            "DNS points to {list}, outside {domain}; confirm with --yes or set \
             --imap-host and --smtp-host"
        ))
    })?;
    if matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
        Ok(())
    } else {
        Err(Error::InvalidInput(format!("servers {list} not confirmed")))
    }
}

fn resolve_servers(
    backend: &dyn Backend,
    args: &AddArgs,
    address: &EmailAddress,
) -> Result<Resolved, Error> {
    // Both servers given: nothing to discover or ask; ports and login default.
    if let (Some(imap_host), Some(smtp_host)) = (&args.imap_host, &args.smtp_host) {
        return Ok(Resolved {
            settings: ServerSettings {
                imap: Endpoint {
                    host: imap_host.clone(),
                    port: args.imap_port.unwrap_or(IMAPS),
                    security: Security::Tls,
                },
                smtp: smtp_endpoint(smtp_host, args.smtp_port.unwrap_or(SUBMISSION)),
                username: args.user.clone().unwrap_or_else(|| address.to_string()),
            },
            source: "command line".to_owned(),
            trace: Vec::new(),
            unconfirmed_hosts: Vec::new(),
        });
    }
    match discover::discover(address, backend.net().as_mut()) {
        Ok(Discovery {
            settings,
            source,
            trace,
            unconfirmed_hosts,
        }) => {
            let settings = apply_overrides(settings, args);
            // Hosts the user gave on the command line need no confirmation.
            let unconfirmed_hosts = unconfirmed_hosts
                .into_iter()
                .filter(|h| *h == settings.imap.host || *h == settings.smtp.host)
                .collect();
            Ok(Resolved {
                settings,
                source,
                trace,
                unconfirmed_hosts,
            })
        }
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
        PasswordSource::Keychain(_) if from_stdin => Secret::entered(&backend.read_stdin()?),
        PasswordSource::Keychain(_) => {
            let typed = backend
                .prompt_password(&format!("Password for {}: ", probe.user))?
                .ok_or_else(|| {
                    Error::InvalidInput(
                        "no terminal for the password prompt; use --password-stdin".into(),
                    )
                })?;
            Secret::entered(typed.expose())
        }
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
        unconfirmed_hosts,
    } = resolve_servers(backend, args, &address)?;
    if !args.yes {
        confirm_hosts(backend, &unconfirmed_hosts, &address)?;
    }
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
        // Config first: storing the password with `-U` would overwrite an item
        // another account shares, and that must not happen for a failed add.
        backend.write_file(&path, &new_text)?;
        if let (PasswordSource::Keychain(service), Some(secret)) = (&password, &secret) {
            backend
                .keychain_store(service, &probe.user, secret)
                .map_err(|e| {
                    Error::Partial(format!(
                        "account {} was added, but storing its password failed ({e}); \
                         run `mailctl account set-password -a {}`",
                        args.name, args.name
                    ))
                })?;
            password_stored = true;
        }
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
) -> Result<(PathBuf, String, Config, AccountConfig), Error> {
    let (path, text) = config_text(cli, backend)?;
    let config = Config::parse(&text)?;
    let account = config.account(name)?.clone();
    Ok((path, text, config, account))
}

fn test(
    cli: &Cli,
    backend: &dyn Backend,
    out: &mut dyn Write,
    name: &str,
    smtp: bool,
) -> Result<u8, Error> {
    let (_, _, _, account) = load(cli, backend, name)?;
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
    let (_, _, _, account) = load(cli, backend, name)?;
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
    let (path, text, config, account) = load(cli, backend, name)?;
    let new_text = setup::remove_account(&text, name)?;
    // Another account may log in with the same keychain item; keep it then.
    let shared = config.accounts.iter().any(|other| {
        other.name != account.name
            && other.password == account.password
            && other.user == account.user
    });
    // Config first: a leftover keychain item is harmless, a configured account
    // whose item is gone is not.
    backend.write_file(&path, &new_text)?;
    let mut password_deleted = false;
    if let (true, false, PasswordSource::Keychain(service)) =
        (delete_password, shared, &account.password)
    {
        backend
            .keychain_delete(service, &account.user)
            .map_err(|e| {
                Error::Partial(format!(
                    "account {name} was removed, but deleting its keychain item failed ({e})"
                ))
            })?;
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
#[path = "tests/account.rs"]
mod tests;
