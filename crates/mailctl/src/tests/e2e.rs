//! End-to-end tests: the command line through the real IMAP adapter and TLS
//! against the scripted server in `tests/server`, one provider profile each.

use std::path::{Path, PathBuf};

use clap::Parser as _;
use serde_json::Value;

use crate::adapters::imap::ImapStore;
use crate::adapters::net::Trust;
use crate::cli::{Backend, Cli, run};
use crate::config::{AccountConfig, Secret, SecretLookup};
use crate::discover::Net;
use crate::error::Error;
use crate::store::{MailSender, MailStore};
use crate::test_server::imap::{DOVECOT, ICLOUD, ImapServer, PASSWORD, Profile, RFC3501, USER};

/// The command line's view of one account on a scripted server.
struct E2e {
    server: ImapServer,
    config: String,
    plan: String,
    /// Trust the system roots instead of the server's CA.
    system_trust: bool,
    /// The password mailctl finds for the account.
    password: String,
}

impl E2e {
    fn new(profile: Profile, folders: &[(&str, &str)], sent: &str) -> Result<Self, String> {
        let server = ImapServer::start(profile, folders)?;
        let config = format!(
            r#"
[[accounts]]
name = "mail"
user = "{USER}"
address = "{USER}"
imap_host = "localhost"
imap_port = {port}
smtp_host = "localhost"
sent_folder = "{sent}"
password = {{ env = "PW" }}
access = "organize"
"#,
            port = server.port
        );
        Ok(Self {
            server,
            config,
            plan: String::new(),
            system_trust: false,
            password: PASSWORD.to_owned(),
        })
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
        Ok(self.config.clone())
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
        let trust = if self.system_trust {
            Trust::System
        } else {
            Trust::Only(self.server.ca_pem.clone())
        };
        Ok(Box::new(ImapStore::connect_with(account, secret, &trust)?))
    }
    fn sender(&self, _a: &AccountConfig, _s: &Secret) -> Result<Box<dyn MailSender>, Error> {
        Err(Error::Send("no SMTP server in this test".into()))
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
        Ok(None)
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
    fn check_smtp(&self, _a: &AccountConfig, _s: &Secret) -> Result<(), Error> {
        Ok(())
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
    let mut e2e = E2e::dovecot()?;
    e2e.system_trust = true;
    let (out, code) = e2e.run(&["folders", "-a", "mail"])?;
    assert_ne!(code, 0, "{out}");
    assert_eq!(e2e.count("LOGIN")?, 0);
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
