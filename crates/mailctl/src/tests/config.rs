//! Tests for `config`.

use super::*;

const SAMPLE: &str = r#"
forward_allowlist = ["accounting@example.com"]

[[accounts]]
name = "icloud"
user = "alice@example.com"
address = "alice@example.com"
imap_host = "imap.mail.me.com"
smtp_host = "smtp.mail.me.com"
sent_folder = "Sent Messages"
password = { keychain = "mailctl" }

[[accounts]]
name = "work"
user = "alice@example.com"
address = "alice@example.com"
imap_host = "mail.example"
imap_port = 1993
smtp_host = "mail.example"
smtp_port = 465
smtp_user = "submit"
sent_folder = "INBOX.Sent"
password = { env = "MAILCTL_PW_WORK" }
access = "organize"
"#;

struct Fake {
    env: Option<String>,
    keychain: Result<String, String>,
}

impl SecretLookup for Fake {
    fn env(&self, _name: &str) -> Option<String> {
        self.env.clone()
    }
    fn keychain(&self, _service: &str, _account: &str) -> Result<String, String> {
        self.keychain.clone()
    }
}

#[test]
fn parses_sample_with_defaults() -> Result<(), Error> {
    let config = Config::parse(SAMPLE)?;
    let icloud = config.account("icloud")?;
    assert_eq!(icloud.imap_port, 993);
    assert_eq!(icloud.smtp_port, 587);
    assert_eq!(icloud.smtp_login(), "alice@example.com");
    let ns = config.account("work")?;
    assert_eq!(ns.imap_port, 1993);
    assert_eq!(ns.smtp_login(), "submit");
    assert!(config.forward_allowed(&EmailAddress::parse("Accounting@example.com")?));
    assert!(!config.forward_allowed(&EmailAddress::parse("x@y.de")?));
    assert_eq!(
        config.account("nope"),
        Err(Error::UnknownAccount("nope".into()))
    );
    Ok(())
}

#[test]
fn rejects_bad_configs() {
    assert!(matches!(Config::parse("nonsense ="), Err(Error::Config(_))));
    assert!(matches!(
        Config::parse("accounts = []"),
        Err(Error::Config(_))
    ));
    let dup = format!(
        "{SAMPLE}\n{}",
        SAMPLE
            .split("[[accounts]]")
            .nth(1)
            .map(|s| format!("[[accounts]]{s}"))
            .unwrap_or_default()
    );
    assert!(matches!(Config::parse(&dup), Err(Error::Config(m)) if m.contains("duplicate")));
    let empty = SAMPLE.replace("name = \"icloud\"", "name = \" \"");
    assert!(matches!(Config::parse(&empty), Err(Error::Config(m)) if m.contains("empty")));
}

#[test]
fn access_levels_are_ordered() {
    assert!(
        Access::Read < Access::Flag
            && Access::Flag < Access::Organize
            && Access::Organize < Access::Send
    );
    assert!(Access::Send.require("a", Access::Read).is_ok());
    assert_eq!(
        Access::Flag.require("a", Access::Organize),
        Err(Error::AccessDenied {
            account: "a".into(),
            needed: "organize",
            granted: "flag"
        })
    );
    let names: Vec<&str> = [Access::Read, Access::Flag, Access::Organize, Access::Send]
        .iter()
        .map(|a| a.as_str())
        .collect();
    assert_eq!(names, ["read", "flag", "organize", "send"]);
}

#[test]
fn resolves_passwords() -> Result<(), Error> {
    let config = Config::parse(SAMPLE)?;
    let icloud = config.account("icloud")?;
    let ns = config.account("work")?;
    let ok = Fake {
        env: Some("e".into()),
        keychain: Ok("k".into()),
    };
    assert_eq!(resolve_password(icloud, &ok)?.expose(), "k");
    assert_eq!(resolve_password(ns, &ok)?.expose(), "e");
    let bad = Fake {
        env: Some(String::new()),
        keychain: Err("locked".into()),
    };
    assert!(
        matches!(resolve_password(icloud, &bad), Err(Error::Secret { reason, .. }) if reason == "locked")
    );
    assert!(matches!(
        resolve_password(ns, &bad),
        Err(Error::Secret { .. })
    ));
    assert_eq!(format!("{:?}", Secret::new("pw".into())), "Secret(***)");
    Ok(())
}

#[test]
fn entered_passwords_are_checked() -> Result<(), Error> {
    assert_eq!(Secret::entered("geheim\r\n")?.expose(), "geheim");
    assert_eq!(Secret::entered("über alles")?.expose(), "über alles");
    for bad in ["", "\n", "first\nsecond", "tab\there"] {
        assert!(
            matches!(Secret::entered(bad), Err(Error::InvalidInput(_))),
            "{bad:?}"
        );
    }
    Ok(())
}

#[test]
fn keychain_output_is_decoded_like_security_prints_it() {
    let read = |raw: &str| Secret::from_keychain_output(raw).expose().to_owned();
    // Printable ASCII comes back as it is, even when it looks like hex.
    assert_eq!(read("geheim\n"), "geheim");
    assert_eq!(read("deadbeef\n"), "deadbeef");
    assert_eq!(read("6162"), "6162");
    // Anything else is printed as hex: "grün" in UTF-8.
    assert_eq!(read("6772c3bc6e\n"), "grün");
    // Odd length, non-hex characters or invalid UTF-8 are not hex output.
    assert_eq!(read("abc"), "abc");
    assert_eq!(read("+f"), "+f");
    assert_eq!(read("ff"), "ff");
    assert_eq!(read(""), "");
}
