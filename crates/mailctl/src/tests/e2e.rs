//! End-to-end tests: the command line through the real IMAP and SMTP
//! adapters and TLS against the scripted servers in `tests/server`, one
//! provider profile each.

use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::Parser as _;
use serde_json::Value;

use crate::adapters::imap::ImapStore;
use crate::adapters::net::Trust;
use crate::adapters::smtp::SmtpSender;
use crate::adapters::system::SystemBackend;
use crate::cli::{Backend, Cli, run};
use crate::config::{AccountConfig, Config, Secret, SecretLookup};
use crate::discover::Net;
use crate::error::Error;
use crate::store::{MailSender, MailStore};
use crate::test_server::TestCa;
use crate::test_server::imap::{
    DOVECOT, Fault, ICLOUD, ImapServer, PASSWORD, Profile, RFC3501, USER,
};
use crate::test_server::smtp::{Accepted, Mode, SmtpServer};

/// The only recipient on the forward allow list.
const ACCOUNTING: &str = "accounting@example.com";

/// The command line's view of one account on scripted servers.
struct E2e {
    ca: TestCa,
    server: ImapServer,
    smtp: Option<(SmtpServer, Mode)>,
    /// The account's sent folder.
    sent: String,
    plan: String,
    /// Connect as in production, trusting the system roots instead of the
    /// servers' CA.
    system_trust: bool,
    /// Time limit of each IMAP step.
    io_timeout: Duration,
    /// The password mailctl finds for the account.
    password: String,
}

impl E2e {
    fn new(profile: Profile, folders: &[(&str, &str)], sent: &str) -> Result<Self, String> {
        let ca = TestCa::new()?;
        let server = ImapServer::start(&ca, profile, folders)?;
        Ok(Self {
            ca,
            server,
            smtp: None,
            sent: sent.to_owned(),
            plan: String::new(),
            system_trust: false,
            io_timeout: Duration::from_secs(5),
            password: PASSWORD.to_owned(),
        })
    }

    /// Adds an SMTP server; with `files_sent` it files each message in the
    /// sent folder itself.
    fn with_smtp(mut self, mode: Mode, files_sent: bool) -> Result<Self, String> {
        let filing = files_sent.then(|| (self.server.clone(), self.sent.clone()));
        self.smtp = Some((SmtpServer::start(&self.ca, mode, filing)?, mode));
        Ok(self)
    }

    fn config(&self) -> String {
        let (smtp_port, security) = match &self.smtp {
            Some((server, Mode::StartTls)) => (server.port, "starttls"),
            Some((server, Mode::Tls)) => (server.port, "tls"),
            None => (1, "tls"),
        };
        format!(
            r#"
forward_allowlist = ["{ACCOUNTING}"]

[[accounts]]
name = "mail"
user = "{USER}"
address = "{USER}"
imap_host = "localhost"
imap_port = {imap_port}
smtp_host = "localhost"
smtp_port = {smtp_port}
smtp_security = "{security}"
sent_folder = "{sent}"
password = {{ env = "PW" }}
access = "send"
"#,
            imap_port = self.server.port,
            sent = self.sent,
        )
    }

    fn trust(&self) -> Trust {
        Trust::Only(self.ca.pem.clone())
    }

    /// The account as mailctl reads it from the configuration.
    fn account(&self) -> Result<AccountConfig, String> {
        Config::parse(&self.config())
            .and_then(|config| config.account("mail").cloned())
            .map_err(|e| e.to_string())
    }

    fn smtp_sender(&self, account: &AccountConfig, secret: &Secret) -> Result<SmtpSender, Error> {
        if self.system_trust {
            SmtpSender::new(account, secret)
        } else {
            SmtpSender::new_with(account, secret, &self.trust())
        }
    }

    /// The messages the SMTP server accepted.
    fn accepted(&self) -> Result<Vec<Accepted>, String> {
        self.smtp.as_ref().ok_or("no SMTP server")?.0.accepted()
    }

    fn dovecot() -> Result<Self, String> {
        Self::new(
            DOVECOT,
            &[
                ("INBOX", r"\HasChildren"),
                ("INBOX.Archive", r"\HasNoChildren"),
                ("INBOX.Beh&APY-rden", r"\HasNoChildren"),
                ("INBOX.Sent", r"\HasNoChildren \Sent"),
                ("INBOX.Trash", r"\HasNoChildren \Trash"),
            ],
            "INBOX.Sent",
        )
    }

    fn icloud() -> Result<Self, String> {
        Self::new(
            ICLOUD,
            &[
                ("INBOX", r"\Noinferiors"),
                ("Archive", ""),
                ("Deleted Messages", r"\Trash"),
                ("Sent Messages", r"\Sent"),
            ],
            "Sent Messages",
        )
    }

    fn rfc3501() -> Result<Self, String> {
        Self::new(
            RFC3501,
            &[("INBOX", ""), ("Archive", ""), ("Sent", "")],
            "Sent",
        )
    }

    /// Runs the command line and returns its JSON output and exit code.
    fn run(&self, args: &[&str]) -> Result<(Value, u8), String> {
        let cli = Cli::try_parse_from(std::iter::once("mailctl").chain(args.iter().copied()))
            .map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        let code = run(&cli, self, &mut out);
        let value = serde_json::from_slice(&out)
            .map_err(|e| format!("{e}: {}", String::from_utf8_lossy(&out)))?;
        Ok((value, code))
    }

    /// Stores a plain text mail with this `Message-ID` and subject.
    fn add(&self, folder: &str, id: &str, subject: &str, flags: &[&str]) -> Result<u32, String> {
        self.server.add(
            folder,
            &[
                "From: Bob <bob@example.com>",
                &format!("To: {USER}"),
                &format!("Subject: {subject}"),
                "Date: Mon, 16 Nov 2026 10:00:00 +0000",
                &format!("Message-ID: <{id}>"),
                "MIME-Version: 1.0",
                "Content-Type: text/plain; charset=utf-8",
                "",
                &format!("Text of {subject}."),
            ],
            flags,
        )
    }

    /// The `Message-ID`s in a folder.
    fn ids(&self, folder: &str) -> Result<Vec<String>, String> {
        Ok(self
            .server
            .messages(folder)?
            .iter()
            .filter_map(|m| m.header("Message-ID"))
            .collect())
    }

    /// The flags of the mail with this `Message-ID`.
    fn flags(&self, folder: &str, id: &str) -> Result<Vec<String>, String> {
        self.server
            .messages(folder)?
            .into_iter()
            .find(|m| m.header("Message-ID").as_deref() == Some(&format!("<{id}>")))
            .map(|m| m.flags.into_iter().collect())
            .ok_or_else(|| format!("{id} not in {folder}"))
    }

    fn count(&self, command: &str) -> Result<usize, String> {
        Ok(self
            .server
            .commands()?
            .iter()
            .filter(|c| *c == command)
            .count())
    }
}

impl SecretLookup for E2e {
    fn env(&self, _name: &str) -> Option<String> {
        Some(self.password.clone())
    }
    fn keychain(&self, _service: &str, _account: &str) -> Result<String, String> {
        Err("no keychain in end-to-end tests".into())
    }
}

impl Backend for E2e {
    fn read_config(&self, _path: Option<&PathBuf>) -> Result<String, Error> {
        Ok(self.config())
    }
    fn read_plan(&self, _path: &Path) -> Result<String, Error> {
        Ok(self.plan.clone())
    }
    fn secrets(&self) -> &dyn SecretLookup {
        self
    }
    fn connect(
        &self,
        account: &AccountConfig,
        secret: &Secret,
    ) -> Result<Box<dyn MailStore>, Error> {
        Ok(Box::new(if self.system_trust {
            ImapStore::connect(account, secret)?
        } else {
            ImapStore::connect_with(account, secret, &self.trust(), self.io_timeout)?
        }))
    }
    fn sender(
        &self,
        account: &AccountConfig,
        secret: &Secret,
    ) -> Result<Box<dyn MailSender>, Error> {
        Ok(Box::new(SmtpSender::new_with(
            account,
            secret,
            &self.trust(),
        )?))
    }
    fn unix_time(&self) -> u64 {
        1_700_000_000
    }
    fn random(&self) -> u64 {
        7
    }
    fn config_path(&self, _explicit: Option<&PathBuf>) -> Result<PathBuf, Error> {
        Ok(PathBuf::from("/unused"))
    }
    fn read_optional(&self, _path: &Path) -> Result<Option<String>, Error> {
        Ok(Some(self.config()))
    }
    fn write_file(&self, _path: &Path, _text: &str) -> Result<(), Error> {
        Err(Error::Config("read-only in end-to-end tests".into()))
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
    fn check_smtp(&self, account: &AccountConfig, secret: &Secret) -> Result<(), Error> {
        self.smtp_sender(account, secret)?.check()
    }
}

fn at<'a>(value: &'a Value, pointer: &str) -> &'a Value {
    value.pointer(pointer).unwrap_or(&Value::Null)
}

#[test]
fn reading_decodes_folder_names_and_marks_nothing_read() -> Result<(), String> {
    let e2e = E2e::dovecot()?;
    e2e.add("INBOX", "a@example.com", "Invoice", &[])?;
    e2e.add("INBOX", "b@example.com", "News", &[r"\Seen"])?;

    let (folders, code) = e2e.run(&["folders", "-a", "mail"])?;
    assert_eq!(code, 0, "{folders}");
    assert_eq!(at(&folders, "/2/name"), "INBOX.Behörden");
    assert_eq!(at(&folders, "/2/delimiter"), ".");
    assert_eq!(at(&folders, "/3/special_use"), "sent");
    assert_eq!(at(&folders, "/4/special_use"), "trash");

    let (list, code) = e2e.run(&["list", "-a", "mail"])?;
    assert_eq!(code, 0, "{list}");
    assert_eq!(at(&list, "/0/message_id"), "b@example.com");
    assert_eq!(at(&list, "/0/flags/seen"), true);
    assert_eq!(at(&list, "/1/subject"), "Invoice");
    assert_eq!(at(&list, "/1/flags/seen"), false);

    let (shown, code) = e2e.run(&["show", "-a", "mail", "--uid", "1"])?;
    assert_eq!(code, 0, "{shown}");
    assert_eq!(at(&shown, "/text"), "Text of Invoice.\r\n");
    assert_eq!(at(&shown, "/to/0"), USER);

    assert_eq!(e2e.flags("INBOX", "a@example.com")?, Vec::<String>::new());
    assert_eq!(e2e.count("SELECT")?, 0, "reading only examines");
    assert_eq!(e2e.count("UID STORE")?, 0);
    Ok(())
}

#[test]
fn icloud_names_special_folders_without_the_capability() -> Result<(), String> {
    let (folders, code) = E2e::icloud()?.run(&["folders", "-a", "mail"])?;
    assert_eq!(code, 0, "{folders}");
    assert_eq!(at(&folders, "/0/name"), "Archive");
    assert_eq!(at(&folders, "/0/delimiter"), "/");
    assert_eq!(at(&folders, "/1/special_use"), "trash");
    assert_eq!(at(&folders, "/3/name"), "Sent Messages");
    assert_eq!(at(&folders, "/3/special_use"), "sent");
    Ok(())
}

#[test]
fn mark_read_sets_seen_on_the_server() -> Result<(), String> {
    let e2e = E2e::dovecot()?;
    e2e.add("INBOX", "a@example.com", "Invoice", &[])?;
    let (out, code) = e2e.run(&[
        "mark-read",
        "-a",
        "mail",
        "--uid",
        "1",
        "--expect",
        "a@example.com",
    ])?;
    assert_eq!(code, 0, "{out}");
    assert_eq!(e2e.flags("INBOX", "a@example.com")?, [r"\Seen"]);
    Ok(())
}

#[test]
fn a_mail_with_another_message_id_is_left_alone() -> Result<(), String> {
    let e2e = E2e::dovecot()?;
    e2e.add("INBOX", "a@example.com", "Invoice", &[])?;
    let (out, code) = e2e.run(&[
        "move",
        "-a",
        "mail",
        "--uid",
        "1",
        "--expect",
        "other@example.com",
        "--to",
        "INBOX.Archive",
    ])?;
    assert_ne!(code, 0, "{out}");
    assert_eq!(e2e.ids("INBOX")?, ["<a@example.com>"]);
    assert_eq!(e2e.count("UID MOVE")?, 0);
    Ok(())
}

#[test]
fn move_uses_move_where_the_server_offers_it() -> Result<(), String> {
    let e2e = E2e::dovecot()?;
    e2e.add("INBOX", "a@example.com", "Invoice", &[])?;
    e2e.add("INBOX", "b@example.com", "News", &[])?;
    let (out, code) = e2e.run(&[
        "move",
        "-a",
        "mail",
        "--uid",
        "1",
        "--expect",
        "a@example.com",
        "--to",
        "INBOX.Beh\u{f6}rden",
    ])?;
    assert_eq!(code, 0, "{out}");
    assert_eq!(e2e.ids("INBOX")?, ["<b@example.com>"]);
    assert_eq!(e2e.ids("INBOX.Beh&APY-rden")?, ["<a@example.com>"]);
    assert_eq!(e2e.count("UID MOVE")?, 1);
    assert_eq!(e2e.count("UID COPY")?, 0);
    Ok(())
}

#[test]
fn move_on_icloud_copies_and_expunges_only_its_own_mail() -> Result<(), String> {
    let e2e = E2e::icloud()?;
    e2e.add("INBOX", "a@example.com", "Invoice", &[])?;
    // Marked deleted by another client; UID EXPUNGE must leave it.
    e2e.add("INBOX", "c@example.com", "Old", &[r"\Deleted"])?;
    let (out, code) = e2e.run(&[
        "move",
        "-a",
        "mail",
        "--uid",
        "1",
        "--expect",
        "a@example.com",
        "--to",
        "Archive",
        "--mark-read",
    ])?;
    assert_eq!(code, 0, "{out}");
    assert_eq!(e2e.ids("INBOX")?, ["<c@example.com>"]);
    assert_eq!(e2e.ids("Archive")?, ["<a@example.com>"]);
    assert_eq!(e2e.flags("Archive", "a@example.com")?, [r"\Seen"]);
    assert_eq!(e2e.count("UID MOVE")?, 0);
    assert_eq!(e2e.count("UID COPY")?, 1);
    assert_eq!(e2e.count("UID EXPUNGE")?, 1);
    assert_eq!(e2e.count("EXPUNGE")?, 0);
    Ok(())
}

#[test]
fn move_without_uidplus_expunges_when_nothing_else_is_deleted() -> Result<(), String> {
    let e2e = E2e::rfc3501()?;
    e2e.add("INBOX", "a@example.com", "Invoice", &[])?;
    e2e.add("INBOX", "b@example.com", "News", &[])?;
    let (out, code) = e2e.run(&[
        "move",
        "-a",
        "mail",
        "--uid",
        "1",
        "--expect",
        "a@example.com",
        "--to",
        "Archive",
    ])?;
    assert_eq!(code, 0, "{out}");
    assert_eq!(e2e.ids("INBOX")?, ["<b@example.com>"]);
    assert_eq!(e2e.ids("Archive")?, ["<a@example.com>"]);
    assert_eq!(e2e.count("EXPUNGE")?, 1);
    Ok(())
}

#[test]
fn move_without_uidplus_refuses_beside_another_deleted_mail() -> Result<(), String> {
    let e2e = E2e::rfc3501()?;
    e2e.add("INBOX", "a@example.com", "Invoice", &[])?;
    e2e.add("INBOX", "c@example.com", "Old", &[r"\Deleted"])?;
    let (out, code) = e2e.run(&[
        "move",
        "-a",
        "mail",
        "--uid",
        "1",
        "--expect",
        "a@example.com",
        "--to",
        "Archive",
    ])?;
    assert_ne!(code, 0, "{out}");
    assert_eq!(e2e.ids("INBOX")?, ["<a@example.com>", "<c@example.com>"]);
    assert_eq!(e2e.flags("INBOX", "a@example.com")?, Vec::<String>::new());
    assert_eq!(e2e.count("EXPUNGE")?, 0);
    Ok(())
}

#[test]
fn create_folder_encodes_the_name_for_the_server() -> Result<(), String> {
    let e2e = E2e::dovecot()?;
    let (out, code) = e2e.run(&["create-folder", "-a", "mail", "INBOX.Belege f\u{fc}r 2026"])?;
    assert_eq!(code, 0, "{out}");
    assert!(
        e2e.server
            .folders()?
            .contains(&"INBOX.Belege f&APw-r 2026".to_owned()),
        "{:?}",
        e2e.server.folders()?
    );
    let (again, code) = e2e.run(&["create-folder", "-a", "mail", "INBOX.Belege f\u{fc}r 2026"])?;
    assert_ne!(code, 0, "{again}");
    Ok(())
}

#[test]
fn apply_runs_a_plan_over_one_connection() -> Result<(), String> {
    let mut e2e = E2e::icloud()?;
    e2e.add("INBOX", "a@example.com", "Invoice", &[])?;
    e2e.add("INBOX", "b@example.com", "News", &[])?;
    e2e.plan = r#"{"account": "mail", "ops": [
        {"op": "mark_read", "uid": 1, "expect": "a@example.com"},
        {"op": "move", "uid": 2, "expect": "b@example.com", "to": "Archive"}
    ]}"#
    .to_owned();
    let (out, code) = e2e.run(&["apply", "plan.json"])?;
    assert_eq!(code, 0, "{out}");
    assert_eq!(e2e.flags("INBOX", "a@example.com")?, [r"\Seen"]);
    assert_eq!(e2e.ids("Archive")?, ["<b@example.com>"]);
    assert_eq!(e2e.count("LOGIN")?, 1);
    Ok(())
}

#[test]
fn a_certificate_outside_the_trust_is_refused() -> Result<(), String> {
    // Production connects with the system roots, which do not hold the
    // test CA.
    let mut e2e = E2e::dovecot()?.with_smtp(Mode::Tls, false)?;
    e2e.system_trust = true;
    let (out, code) = e2e.run(&["folders", "-a", "mail"])?;
    assert_ne!(code, 0, "{out}");
    assert_eq!(e2e.count("LOGIN")?, 0);
    // The production backend does the same.
    let (account, secret) = (e2e.account()?, Secret::new(PASSWORD.to_owned()));
    let system = SystemBackend;
    assert!(matches!(
        system.connect(&account, &secret),
        Err(Error::Store(_))
    ));
    let sender = system.sender(&account, &secret);
    assert!(sender.is_ok(), "the transport connects only on send");
    assert!(matches!(
        system.check_smtp(&account, &secret),
        Err(Error::Send(_))
    ));
    Ok(())
}

#[test]
fn a_wrong_password_is_reported() -> Result<(), String> {
    let mut e2e = E2e::dovecot()?;
    e2e.password = "wrong".to_owned();
    let (out, code) = e2e.run(&["folders", "-a", "mail"])?;
    assert_ne!(code, 0, "{out}");
    assert!(out.to_string().contains("Authentication failed"), "{out}");
    Ok(())
}

/// Forwards mail 1 of the inbox, expected as `a@example.com`, to `to`.
fn forward(e2e: &E2e, to: &str) -> Result<(Value, u8), String> {
    e2e.run(&[
        "forward",
        "-a",
        "mail",
        "--uid",
        "1",
        "--expect",
        "a@example.com",
        "--to",
        to,
        "--note",
        "For the books.",
    ])
}

#[test]
fn forward_over_starttls_sends_files_and_flags() -> Result<(), String> {
    let e2e = E2e::dovecot()?.with_smtp(Mode::StartTls, false)?;
    e2e.add("INBOX", "a@example.com", "Invoice", &[])?;
    let (out, code) = forward(&e2e, ACCOUNTING)?;
    assert_eq!(code, 0, "{out}");

    let accepted = e2e.accepted()?;
    let [sent] = accepted.as_slice() else {
        return Err(format!("{} messages accepted", accepted.len()));
    };
    assert_eq!(sent.from, USER);
    assert_eq!(sent.to, [ACCOUNTING]);
    let data = String::from_utf8_lossy(&sent.data);
    assert!(data.contains("For the books."), "{data}");
    assert!(data.contains("Text of Invoice."), "{data}");

    let copies = e2e.server.messages("INBOX.Sent")?;
    let [copy] = copies.as_slice() else {
        return Err(format!("{} copies filed", copies.len()));
    };
    // lettre ends DATA with a CRLF of its own after the message.
    assert_eq!(
        sent.data.strip_suffix(b"\r\n"),
        Some(copy.body.as_slice()),
        "the copy is what was sent"
    );
    assert_eq!(e2e.flags("INBOX", "a@example.com")?, ["$Forwarded"]);
    assert_eq!(e2e.count("APPEND")?, 1);
    Ok(())
}

#[test]
fn forward_on_icloud_confirms_the_copy_without_the_header_search() -> Result<(), String> {
    let e2e = E2e::icloud()?.with_smtp(Mode::Tls, false)?;
    e2e.add("INBOX", "a@example.com", "Invoice", &[])?;
    let (out, code) = forward(&e2e, ACCOUNTING)?;
    assert_eq!(code, 0, "{out}");
    assert_eq!(e2e.accepted()?.len(), 1);
    assert_eq!(e2e.server.messages("Sent Messages")?.len(), 1);
    assert_eq!(e2e.flags("INBOX", "a@example.com")?, ["$Forwarded"]);
    Ok(())
}

#[test]
fn forward_stores_no_second_copy_where_the_server_files_one() -> Result<(), String> {
    // Gmail and Microsoft 365 file what they send themselves.
    let e2e = E2e::dovecot()?.with_smtp(Mode::StartTls, true)?;
    e2e.add("INBOX", "a@example.com", "Invoice", &[])?;
    let (out, code) = forward(&e2e, ACCOUNTING)?;
    assert_eq!(code, 0, "{out}");
    assert_eq!(e2e.server.messages("INBOX.Sent")?.len(), 1);
    assert_eq!(e2e.count("APPEND")?, 0);
    Ok(())
}

#[test]
fn forward_refuses_a_recipient_off_the_allow_list() -> Result<(), String> {
    let e2e = E2e::dovecot()?.with_smtp(Mode::StartTls, false)?;
    e2e.add("INBOX", "a@example.com", "Invoice", &[])?;
    let (out, code) = forward(&e2e, "someone@example.com")?;
    assert_ne!(code, 0, "{out}");
    assert!(e2e.accepted()?.is_empty());
    assert_eq!(e2e.flags("INBOX", "a@example.com")?, Vec::<String>::new());
    Ok(())
}

#[test]
fn a_failed_smtp_login_sends_nothing_and_changes_nothing() -> Result<(), String> {
    let mut e2e = E2e::dovecot()?.with_smtp(Mode::Tls, false)?;
    e2e.add("INBOX", "a@example.com", "Invoice", &[])?;
    e2e.password = "wrong".to_owned();
    // IMAP takes the same password; let it in so that SMTP fails alone.
    e2e.server.accept_any_password()?;
    let (out, code) = forward(&e2e, ACCOUNTING)?;
    assert_ne!(code, 0, "{out}");
    assert!(e2e.accepted()?.is_empty());
    assert!(e2e.server.messages("INBOX.Sent")?.is_empty());
    assert_eq!(e2e.flags("INBOX", "a@example.com")?, Vec::<String>::new());
    Ok(())
}

#[test]
fn account_test_logs_in_to_imap_and_smtp() -> Result<(), String> {
    for mode in [Mode::StartTls, Mode::Tls] {
        let e2e = E2e::dovecot()?.with_smtp(mode, false)?;
        let (out, code) = e2e.run(&["account", "test", "-a", "mail", "--smtp"])?;
        assert_eq!(code, 0, "{mode:?}: {out}");
        assert!(e2e.accepted()?.is_empty());
    }
    Ok(())
}

/// A mailbox with two mails in the inbox and an SMTP server.
fn with_mail(e2e: E2e, mode: Mode) -> Result<E2e, String> {
    let e2e = e2e.with_smtp(mode, false)?;
    e2e.add("INBOX", "a@example.com", "Invoice", &[])?;
    e2e.add("INBOX", "b@example.com", "News", &[])?;
    Ok(e2e)
}

fn dovecot_mail() -> Result<E2e, String> {
    with_mail(E2e::dovecot()?, Mode::StartTls)
}

fn icloud_mail() -> Result<E2e, String> {
    with_mail(E2e::icloud()?, Mode::Tls)
}

fn rfc3501_mail() -> Result<E2e, String> {
    with_mail(E2e::rfc3501()?, Mode::StartTls)
}

/// A command line run on a fresh set of servers.
struct Scenario {
    setup: fn() -> Result<E2e, String>,
    args: &'static [&'static str],
}

const UID_1: [&str; 6] = ["-a", "mail", "--uid", "1", "--expect", "a@example.com"];

const SCENARIOS: &[Scenario] = &[
    Scenario {
        setup: dovecot_mail,
        args: &["folders", "-a", "mail"],
    },
    Scenario {
        setup: dovecot_mail,
        args: &["list", "-a", "mail"],
    },
    Scenario {
        setup: dovecot_mail,
        args: &["show", "-a", "mail", "--uid", "1"],
    },
    Scenario {
        setup: dovecot_mail,
        args: &[
            "mark-read",
            UID_1[0],
            UID_1[1],
            UID_1[2],
            UID_1[3],
            UID_1[4],
            UID_1[5],
        ],
    },
    Scenario {
        setup: dovecot_mail,
        args: &[
            "move",
            UID_1[0],
            UID_1[1],
            UID_1[2],
            UID_1[3],
            UID_1[4],
            UID_1[5],
            "--to",
            "INBOX.Archive",
        ],
    },
    Scenario {
        setup: dovecot_mail,
        args: &["create-folder", "-a", "mail", "INBOX.New"],
    },
    Scenario {
        setup: dovecot_mail,
        args: &[
            "forward", UID_1[0], UID_1[1], UID_1[2], UID_1[3], UID_1[4], UID_1[5], "--to",
            ACCOUNTING,
        ],
    },
    Scenario {
        setup: icloud_mail,
        args: &[
            "move", UID_1[0], UID_1[1], UID_1[2], UID_1[3], UID_1[4], UID_1[5], "--to", "Archive",
        ],
    },
    Scenario {
        setup: icloud_mail,
        args: &[
            "forward", UID_1[0], UID_1[1], UID_1[2], UID_1[3], UID_1[4], UID_1[5], "--to",
            ACCOUNTING,
        ],
    },
    Scenario {
        setup: rfc3501_mail,
        args: &[
            "move", UID_1[0], UID_1[1], UID_1[2], UID_1[3], UID_1[4], UID_1[5], "--to", "Archive",
        ],
    },
];

#[test]
fn every_failed_imap_command_fails_the_command_line() -> Result<(), String> {
    for scenario in SCENARIOS {
        let baseline = (scenario.setup)()?;
        let (out, code) = baseline.run(scenario.args)?;
        assert_eq!(code, 0, "{:?}: {out}", scenario.args);
        for (index, command) in baseline.server.commands()?.iter().enumerate() {
            if command == "LOGOUT" {
                continue;
            }
            for fault in [Fault::No, Fault::Close] {
                let e2e = (scenario.setup)()?;
                e2e.server.fail_at(index, fault)?;
                let (out, code) = e2e.run(scenario.args)?;
                assert_ne!(
                    code, 0,
                    "{:?} with {fault:?} at {command} ({index}): {out}",
                    scenario.args
                );
                // Whatever failed, the mail is still there, not marked
                // deleted: in its folder or in the target.
                let mut kept = 0_usize;
                for folder in e2e.server.folders()? {
                    kept = kept.saturating_add(
                        e2e.server
                            .messages(&folder)?
                            .iter()
                            .filter(|m| {
                                m.header("Message-ID").as_deref() == Some("<a@example.com>")
                                    && !m.flags.contains(r"\Deleted")
                            })
                            .count(),
                    );
                }
                assert!(
                    kept >= 1,
                    "{:?} with {fault:?} at {command} ({index}) lost the mail",
                    scenario.args
                );
            }
        }
    }
    Ok(())
}

#[test]
fn a_stalled_server_times_out_and_the_connection_is_given_up() -> Result<(), String> {
    let baseline = dovecot_mail()?;
    baseline.run(&["list", "-a", "mail"])?;
    let fetch = baseline
        .server
        .commands()?
        .iter()
        .position(|c| c == "UID FETCH")
        .ok_or("no UID FETCH")?;

    let mut e2e = dovecot_mail()?;
    e2e.io_timeout = Duration::from_millis(300);
    e2e.server.fail_at(fetch, Fault::Stall)?;
    let (out, code) = e2e.run(&["list", "-a", "mail"])?;
    assert_ne!(code, 0, "{out}");
    assert!(out.to_string().contains("did not answer in time"), "{out}");
    // The answer may still arrive, so not even LOGOUT is sent any more.
    assert_eq!(e2e.count("LOGOUT")?, 0);
    Ok(())
}

#[test]
fn a_connection_closed_before_the_greeting_is_reported() -> Result<(), String> {
    let e2e = E2e::dovecot()?;
    e2e.server.close_before_greeting()?;
    let (out, code) = e2e.run(&["folders", "-a", "mail"])?;
    assert_ne!(code, 0, "{out}");
    assert!(out.to_string().contains("before the greeting"), "{out}");
    Ok(())
}

#[test]
fn a_refused_connection_is_reported() -> Result<(), String> {
    let e2e = E2e::dovecot()?;
    let mut account = e2e.account()?;
    // A port that was free a moment ago and has no listener now.
    account.imap_port = std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .map_err(|e| e.to_string())?
        .port();
    let secret = Secret::new(PASSWORD.to_owned());
    let result = ImapStore::connect_with(&account, &secret, &e2e.trust(), e2e.io_timeout);
    assert!(matches!(result, Err(Error::Store(_))));
    Ok(())
}

#[test]
fn an_unreadable_certificate_authority_is_refused() -> Result<(), String> {
    let e2e = E2e::dovecot()?;
    let account = e2e.account()?;
    let secret = Secret::new(PASSWORD.to_owned());
    let garbage = Trust::Only(b"not a certificate".to_vec());
    let imap = ImapStore::connect_with(&account, &secret, &garbage, e2e.io_timeout);
    assert!(matches!(imap, Err(Error::Store(_))));
    let smtp = SmtpSender::new_with(&account, &secret, &garbage);
    assert!(matches!(smtp, Err(Error::Send(_))));
    Ok(())
}

#[test]
fn a_flag_change_sent_along_with_a_fetch_is_not_taken_for_a_mail() -> Result<(), String> {
    let e2e = dovecot_mail()?;
    e2e.server
        .send_unsolicited_fetch(r"* 1 FETCH (FLAGS (\Seen))")?;
    let (list, code) = e2e.run(&["list", "-a", "mail"])?;
    assert_eq!(code, 0, "{list}");
    assert_eq!(list.as_array().map(Vec::len), Some(2), "{list}");
    let (shown, code) = e2e.run(&["show", "-a", "mail", "--uid", "2"])?;
    assert_eq!(code, 0, "{shown}");
    assert_eq!(at(&shown, "/subject"), "News");
    Ok(())
}

#[test]
fn a_flag_change_with_a_uid_sent_along_is_not_taken_for_a_mail() -> Result<(), String> {
    // Servers send the UID along once QRESYNC is on, some after any UID
    // command. The change comes first, so a reader that takes the first
    // FETCH of a UID gets a mail without header or body.
    let e2e = dovecot_mail()?;
    e2e.server
        .send_unsolicited_fetch(r"* 1 FETCH (UID 1 FLAGS (\Seen))")?;
    let (list, code) = e2e.run(&["list", "-a", "mail"])?;
    assert_eq!(code, 0, "{list}");
    assert_eq!(list.as_array().map(Vec::len), Some(2), "{list}");
    let (shown, code) = e2e.run(&["show", "-a", "mail", "--uid", "1"])?;
    assert_eq!(code, 0, "{shown}");
    assert_eq!(at(&shown, "/message_id"), "a@example.com");

    // A move is confirmed by fetching the header of the moved mail alone;
    // a change to another mail sent along is not one of the requested UIDs.
    e2e.server
        .send_unsolicited_fetch(r"* 2 FETCH (UID 2 FLAGS (\Seen))")?;
    let mut args = vec!["move"];
    args.extend(UID_1);
    args.extend(["--to", "INBOX.Archive"]);
    let (moved, code) = e2e.run(&args)?;
    assert_eq!(code, 0, "{moved}");
    assert_eq!(e2e.ids("INBOX.Archive")?, ["<a@example.com>"]);
    Ok(())
}

#[test]
fn a_folder_name_that_is_not_modified_utf7_is_skipped() -> Result<(), String> {
    let e2e = E2e::new(
        RFC3501,
        &[("INBOX", ""), ("Bad&Name", ""), ("Sent", "")],
        "Sent",
    )?;
    let (folders, code) = e2e.run(&["folders", "-a", "mail"])?;
    assert_eq!(code, 0, "{folders}");
    let names: Vec<&Value> = folders
        .as_array()
        .map(|list| list.iter().map(|f| at(f, "/name")).collect())
        .unwrap_or_default();
    assert_eq!(names, ["INBOX", "Sent"]);
    Ok(())
}

#[test]
fn a_failed_smtp_connection_test_is_reported() -> Result<(), String> {
    let e2e = E2e::dovecot()?.with_smtp(Mode::StartTls, false)?;
    e2e.smtp.as_ref().ok_or("no SMTP server")?.0.refuse_noop();
    let (out, code) = e2e.run(&["account", "test", "-a", "mail", "--smtp"])?;
    assert_ne!(code, 0, "{out}");
    assert!(out.to_string().contains("connection test failed"), "{out}");
    Ok(())
}

#[test]
fn move_without_uidplus_keeps_the_original_when_another_mail_is_deleted_meanwhile()
-> Result<(), String> {
    let args = [
        "move",
        "-a",
        "mail",
        "--uid",
        "1",
        "--expect",
        "a@example.com",
        "--to",
        "Archive",
    ];
    let baseline = rfc3501_mail()?;
    baseline.run(&args)?;
    // Another client marks mail 2 deleted right after mailctl marked its own.
    let store = baseline
        .server
        .commands()?
        .iter()
        .position(|c| c == "UID STORE")
        .ok_or("no UID STORE")?;

    let e2e = rfc3501_mail()?;
    e2e.server
        .delete_meanwhile(store.saturating_add(1), "INBOX", 2)?;
    let (out, code) = e2e.run(&args)?;
    assert_ne!(code, 0, "{out}");
    assert!(
        out.to_string().contains("marked deleted meanwhile"),
        "{out}"
    );
    assert_eq!(e2e.flags("INBOX", "a@example.com")?, Vec::<String>::new());
    assert_eq!(e2e.flags("INBOX", "b@example.com")?, [r"\Deleted"]);
    assert_eq!(e2e.ids("Archive")?, ["<a@example.com>"]);
    assert_eq!(e2e.count("EXPUNGE")?, 0);
    Ok(())
}
