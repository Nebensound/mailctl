//! Tests for `account`.

use clap::Parser as _;

use super::*;
use crate::cli::run;
use crate::discover::tests::{AUTOCONFIG, FakeNet, srv_net};
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
            &serde_json::Value::from("command line"),
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
    // `two` logs in with the same keychain item, so it stays.
    let (v, _) = exec(&b, &["account", "remove", "-a", "one", "--delete-password"])?;
    assert_eq!(at(&v, "/password_deleted"), false);
    assert_eq!(b.keychain.borrow().len(), 1);
    b.env_password.replace(Some("x".into()));
    let text = b
        .file_text()
        .replace("sent_folder = \"INBOX\"", "sent_folder = \"Gone\"");
    b.files
        .borrow_mut()
        .insert(PathBuf::from("/cfg.toml"), text);
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

/// A backend with two configured accounts, `work` (keychain) and `other`.
fn configured() -> Result<FakeBackend, Error> {
    let b = FakeBackend::new(plesk_net());
    b.passwords
        .borrow_mut()
        .extend(["pw".to_owned(), "pw".to_owned()]);
    for (name, user) in [("work", "alice"), ("other", "bob")] {
        let (v, code) = exec(
            &b,
            &[
                "account",
                "add",
                "--name",
                name,
                "--address",
                "alice@example.com",
                "--user",
                user,
            ],
        )?;
        assert_eq!(code, 0, "{v}");
    }
    exec(&b, &["allowlist", "add", "accounting@example.com"])?;
    b.calls.set(0);
    b.passwords.borrow_mut().push("new".into());
    b.answers.borrow_mut().extend([
        "mail.example.org".to_owned(),
        String::new(),
        String::new(),
        "465".into(),
        String::new(),
    ]);
    b.stdin.borrow_mut().push_str("pw\n");
    Ok(b)
}

/// Every account command that reads or writes something outside the process.
const ACCOUNT_COMMANDS: &[&[&str]] = &[
    &["account", "discover", "alice@example.com"],
    &[
        "account",
        "add",
        "--name",
        "new",
        "--address",
        "alice@example.com",
    ],
    &[
        "account",
        "add",
        "--name",
        "man",
        "--address",
        "a@example.org",
    ],
    &[
        "account",
        "add",
        "--name",
        "piped",
        "--address",
        "alice@example.com",
        "--password-stdin",
    ],
    &["account", "test", "-a", "work", "--smtp"],
    &["account", "set-password", "-a", "work"],
    &["account", "set-access", "-a", "work", "organize"],
    &["account", "remove", "-a", "other", "--delete-password"],
    &["allowlist", "add", "x@example.de"],
    &["allowlist", "remove", "accounting@example.com"],
];

/// Runs `args` on fresh backends with the n-th failure injected, for
/// n = 0, 1, … until it succeeds; every run before must report an error
/// and leave the configuration file unchanged.
fn fails_cleanly(args: &[&str], inject: &dyn Fn(&mut FakeBackend, usize)) -> Result<usize, Error> {
    for n in 0..64 {
        let mut b = configured()?;
        let before = b.file_text();
        inject(&mut b, n);
        let (v, code) = exec(&b, args)?;
        if code == 0 {
            return Ok(n);
        }
        let error = at(&v, "/error").as_str().unwrap_or_default();
        assert!(!error.is_empty(), "{args:?} at {n}: {v}");
        // Only a keychain step after the file was written may leave it changed,
        // and it must say so.
        if !error.starts_with("partly done") {
            assert_eq!(b.file_text(), before, "{args:?} at {n}");
        }
    }
    Err(Error::Store(format!("{args:?} never succeeded")))
}

#[test]
fn every_backend_and_server_failure_is_reported() -> Result<(), Error> {
    for args in ACCOUNT_COMMANDS {
        fails_cleanly(args, &|b, n| b.fail_at = Some(n))?;
        fails_cleanly(args, &|b, n| b.store_fail_at = Some(n))?;
    }
    Ok(())
}

#[test]
fn invalid_addresses_are_refused() -> Result<(), Error> {
    for args in [
        &["account", "discover", "nobody"][..],
        &["account", "add", "--name", "n", "--address", "nobody"],
        &["allowlist", "add", "nobody"],
        &["allowlist", "remove", "nobody"],
    ] {
        let b = configured()?;
        let before = b.file_text();
        let (v, code) = exec(&b, args)?;
        assert_eq!(code, 2, "{args:?}");
        assert!(
            at(&v, "/error")
                .as_str()
                .is_some_and(|e| e.contains("invalid e-mail address")),
            "{args:?}: {v}"
        );
        assert_eq!(b.file_text(), before);
    }
    Ok(())
}

#[test]
fn output_errors_are_reported() -> Result<(), Error> {
    struct Broken;
    impl std::io::Write for Broken {
        fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("closed"))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let b = configured()?;
    let cli = Cli::try_parse_from(["mailctl", "account", "discover", "alice@example.com"])
        .map_err(|e| Error::InvalidInput(e.to_string()))?;
    assert_eq!(run(&cli, &b, &mut Broken), 2);
    Ok(())
}

#[test]
fn remove_deletes_an_unshared_keychain_item() -> Result<(), Error> {
    let b = configured()?;
    let (v, code) = exec(
        &b,
        &["account", "remove", "-a", "other", "--delete-password"],
    )?;
    assert_eq!(
        (code, at(&v, "/password_deleted")),
        (0, &serde_json::Value::from(true))
    );
    let keys: Vec<(String, String)> = b.keychain.borrow().keys().cloned().collect();
    assert_eq!(keys, vec![("mailctl".to_owned(), "alice".to_owned())]);
    Ok(())
}

/// Runs `args` and returns the error text; the command must fail.
fn error_of(b: &FakeBackend, args: &[&str]) -> Result<String, Error> {
    let (v, code) = exec(b, args)?;
    assert_eq!(code, 2, "{args:?}: {v}");
    Ok(at(&v, "/error").as_str().unwrap_or_default().to_owned())
}

#[test]
fn refuses_bad_input_and_broken_configuration() -> Result<(), Error> {
    let b = configured()?;
    let before = b.file_text();
    let add = [
        "account",
        "add",
        "--name",
        "n",
        "--address",
        "alice@example.com",
    ];
    let cases: &[(&[&str], &str)] = &[
        (&["account", "test", "-a", "nope"], "unknown account"),
        (
            &["account", "set-access", "-a", "nope", "read"],
            "unknown account",
        ),
        (
            &[&add[..], &["--password-source", "plain"]].concat(),
            "password source",
        ),
        (
            &[&add[..], &["--sent-folder", ""]].concat(),
            "invalid mailbox name",
        ),
    ];
    for (args, expected) in cases {
        let error = error_of(&b, args)?;
        assert!(error.contains(expected), "{args:?}: {error}");
    }
    assert_eq!(b.file_text(), before);

    let nothing = FakeBackend::new(FakeNet::default());
    let error = error_of(&nothing, &["account", "discover", "alice@example.com"])?;
    assert!(error.contains("no IMAP host"), "{error}");

    let broken = FakeBackend::new(plesk_net());
    broken
        .files
        .borrow_mut()
        .insert(PathBuf::from("/cfg.toml"), "x = [".into());
    for args in [
        &["account", "test", "-a", "work"][..],
        &["allowlist", "add", "x@example.de"],
        &[
            "account",
            "add",
            "--name",
            "n",
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
    ] {
        let error = error_of(&broken, args)?;
        assert!(error.contains("config"), "{args:?}: {error}");
    }
    assert_eq!(broken.file_text(), "x = [");
    Ok(())
}

#[test]
fn missing_passwords_are_reported() -> Result<(), Error> {
    let headless = FakeBackend {
        terminal: false,
        ..FakeBackend::new(FakeNet::default())
    };
    let error = error_of(
        &headless,
        &[
            "account",
            "add",
            "--name",
            "n",
            "--address",
            "a@b.de",
            "--imap-host",
            "i",
            "--smtp-host",
            "s",
            "--no-verify",
            "--sent-folder",
            "Sent",
        ],
    )?;
    assert!(error.contains("--password-stdin"), "{error}");
    assert!(headless.file_text().is_empty());

    let b = FakeBackend::new(FakeNet::default());
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
    b.env_password.replace(None);
    let error = error_of(&b, &["account", "test", "-a", "env"])?;
    assert!(error.contains("no password"), "{error}");
    Ok(())
}

#[test]
fn manual_fallback_asks_only_for_missing_values() -> Result<(), Error> {
    // Only the IMAP host given: the rest is asked, with defaults.
    let b = FakeBackend::new(FakeNet::default());
    b.answers.borrow_mut().extend(vec![String::new(); 4]);
    b.passwords.borrow_mut().push("pw".into());
    let (v, code) = exec(
        &b,
        &[
            "account",
            "add",
            "--name",
            "a",
            "--address",
            "a@example.org",
            "--imap-host",
            "imap.example.org",
        ],
    )?;
    assert_eq!(code, 0, "{v}");
    assert_eq!(at(&v, "/source"), "manual");
    assert_eq!(at(&v, "/settings/smtp/host"), "imap.example.org");
    assert_eq!(at(&v, "/settings/username"), "a@example.org");

    // Everything but the IMAP host given: exactly one question.
    let b = FakeBackend::new(FakeNet::default());
    b.answers.borrow_mut().push("in.example.org".into());
    b.passwords.borrow_mut().push("pw".into());
    let (v, code) = exec(
        &b,
        &[
            "account",
            "add",
            "--name",
            "b",
            "--address",
            "a@example.org",
            "--imap-port",
            "1993",
            "--smtp-host",
            "out.example.org",
            "--smtp-port",
            "465",
            "--user",
            "login",
        ],
    )?;
    assert_eq!(code, 0, "{v}");
    assert_eq!(
        (
            at(&v, "/settings/imap/host"),
            at(&v, "/settings/imap/port"),
            at(&v, "/settings/smtp/host"),
            at(&v, "/settings/username"),
        ),
        (
            &serde_json::Value::from("in.example.org"),
            &serde_json::Value::from(1993),
            &serde_json::Value::from("out.example.org"),
            &serde_json::Value::from("login"),
        )
    );
    assert!(b.answers.borrow().is_empty());
    Ok(())
}

const ADD_ATTACKER: &[&str] = &[
    "account",
    "add",
    "--name",
    "n",
    "--address",
    "alice@example.com",
];

#[test]
fn foreign_servers_from_dns_need_confirmation() -> Result<(), Error> {
    let net = || srv_net("imap.attacker.net", "smtp.attacker.net");

    // No terminal: refused before any login, with the way out.
    let headless = FakeBackend {
        terminal: false,
        ..FakeBackend::new(net())
    };
    let error = error_of(&headless, ADD_ATTACKER)?;
    assert!(
        error.contains("imap.attacker.net, smtp.attacker.net") && error.contains("--yes"),
        "{error}"
    );
    assert_eq!(headless.smtp_checks.get(), 0);
    assert!(headless.file_text().is_empty());

    // Declined in the terminal.
    let declined = FakeBackend::new(net());
    declined.answers.borrow_mut().push("n".into());
    let error = error_of(&declined, ADD_ATTACKER)?;
    assert!(error.contains("not confirmed"), "{error}");
    assert_eq!(declined.smtp_checks.get(), 0);

    // Confirmed in the terminal, or with --yes.
    let confirmed = FakeBackend::new(net());
    confirmed.answers.borrow_mut().push("Yes".into());
    confirmed.passwords.borrow_mut().push("pw".into());
    let (v, code) = exec(&confirmed, ADD_ATTACKER)?;
    assert_eq!(code, 0, "{v}");
    let flagged = FakeBackend {
        terminal: false,
        ..FakeBackend::new(net())
    };
    flagged.stdin.borrow_mut().push_str("pw");
    let (v, code) = exec(
        &flagged,
        &[ADD_ATTACKER, &["--yes", "--password-stdin"]].concat(),
    )?;
    assert_eq!(code, 0, "{v}");

    // Servers given on the command line replace the foreign ones: no question.
    let mut own_imap = srv_net("imap.attacker.net", "mail.example.com");
    own_imap.ok.push(("mail.example.com".into(), 993));
    let overridden = FakeBackend::new(own_imap);
    overridden.passwords.borrow_mut().push("pw".into());
    let (v, code) = exec(
        &overridden,
        &[ADD_ATTACKER, &["--imap-host", "mail.example.com"]].concat(),
    )?;
    assert_eq!(code, 0, "{v}");
    assert!(overridden.answers.borrow().is_empty());
    Ok(())
}

#[test]
fn multi_line_passwords_are_refused() -> Result<(), Error> {
    let b = FakeBackend::new(plesk_net());
    b.stdin.borrow_mut().push_str("first\nsecond\n");
    let error = error_of(
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
    assert!(error.contains("control characters"), "{error}");
    assert!(b.keychain.borrow().is_empty());
    assert!(b.file_text().is_empty());

    let typed = FakeBackend::new(plesk_net());
    typed.passwords.borrow_mut().push("a\u{7}b".into());
    let error = error_of(
        &typed,
        &[
            "account",
            "add",
            "--name",
            "n",
            "--address",
            "alice@example.com",
        ],
    )?;
    assert!(error.contains("control characters"), "{error}");
    Ok(())
}

#[test]
fn failures_while_confirming_foreign_servers_are_reported() -> Result<(), Error> {
    for n in 0..64 {
        let mut b = FakeBackend::new(srv_net("imap.attacker.net", "smtp.attacker.net"));
        b.answers.borrow_mut().push("y".into());
        b.passwords.borrow_mut().push("pw".into());
        b.fail_at = Some(n);
        let (v, code) = exec(&b, ADD_ATTACKER)?;
        if code == 0 {
            assert!(
                n >= 3,
                "config path, config file and the question come first"
            );
            return Ok(());
        }
        assert!(at(&v, "/error").is_string(), "{n}: {v}");
        if n <= 2 {
            // Up to the question nothing has logged in anywhere.
            assert_eq!(b.smtp_checks.get(), 0, "{n}");
        }
    }
    Err(Error::Store("never succeeded".into()))
}

#[test]
fn unverified_passwords_do_not_replace_a_shared_keychain_item() -> Result<(), Error> {
    let b = configured()?;
    let before = b.keychain.borrow().clone();
    let file = b.file_text();
    b.stdin.borrow_mut().clear();
    b.stdin.borrow_mut().push_str("typo");
    let add = |name: &'static str, user: &'static str| -> Vec<&'static str> {
        vec![
            "account",
            "add",
            "--name",
            name,
            "--address",
            "alice@example.com",
            "--user",
            user,
            "--imap-host",
            "mail.example.net",
            "--smtp-host",
            "mail.example.net",
            "--no-verify",
            "--sent-folder",
            "Sent",
            "--password-stdin",
        ]
    };
    let error = error_of(&b, &add("work2", "alice"))?;
    assert!(
        error.contains("account work uses the same keychain item"),
        "{error}"
    );
    assert_eq!(*b.keychain.borrow(), before);
    assert_eq!(b.file_text(), file);

    // A login of its own is fine.
    let (v, code) = exec(&b, &add("carol", "carol"))?;
    assert_eq!(code, 0, "{v}");
    Ok(())
}

#[test]
fn discovered_smtp_security_is_stored() -> Result<(), Error> {
    // Implicit TLS on a port other than 465, as an SRV record can announce.
    let mut net = srv_net("mail.example.com", "smtp.example.com");
    net.srv.insert(
        "_submissions._tcp.example.com".into(),
        vec![crate::discover::SrvRecord {
            target: "smtp.example.com".into(),
            port: 2465,
            priority: 0,
            weight: 0,
        }],
    );
    net.ok.push(("smtp.example.com".into(), 2465));
    let b = FakeBackend::new(net);
    b.passwords.borrow_mut().push("pw".into());
    let (v, code) = exec(&b, ADD_ATTACKER)?;
    assert_eq!(code, 0, "{v}");
    let config = Config::parse(&b.file_text())?;
    let account = config.account("n")?;
    assert_eq!(
        (account.smtp_port, account.smtp_tls()),
        (2465, Security::Tls)
    );
    Ok(())
}
