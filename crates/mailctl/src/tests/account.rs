//! Tests for `account`.

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
