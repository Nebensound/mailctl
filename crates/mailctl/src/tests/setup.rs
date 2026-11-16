//! Tests for `setup`.

use super::*;
use crate::store::FolderInfo;

fn account(name: &str) -> Result<NewAccount, Error> {
    Ok(NewAccount {
        name: name.to_owned(),
        user: "alice".to_owned(),
        address: EmailAddress::parse("alice@example.com")?,
        imap_host: "mail.example.net".to_owned(),
        imap_port: 993,
        smtp_host: "mail.example.net".to_owned(),
        smtp_port: 587,
        smtp_security: Security::StartTls,
        smtp_user: None,
        sent_folder: MailboxName::new("INBOX.Sent")?,
        save_sent_copy: true,
        password: PasswordSource::Keychain("mailctl".to_owned()),
        access: Access::Organize,
    })
}

#[test]
fn adds_accounts_and_keeps_comments() -> Result<(), Error> {
    let first = add_account("", &account("work")?)?;
    let config = Config::parse(&first)?;
    assert_eq!(config.account("work")?.imap_port, 993);
    let commented = format!("# my mail accounts\n{first}");
    let mut second = account("home")?;
    second.smtp_user = Some("submit".into());
    second.password = PasswordSource::Env("PW".into());
    let both = add_account(&commented, &second)?;
    assert!(both.starts_with("# my mail accounts"));
    let config = Config::parse(&both)?;
    assert_eq!(config.account("home")?.smtp_login(), "submit");
    assert_eq!(
        config.account("home")?.password,
        PasswordSource::Env("PW".into())
    );
    assert!(
        matches!(add_account(&both, &account("work")?), Err(Error::Config(m)) if m.contains("already exists"))
    );
    assert!(matches!(
        add_account("x = [", &account("a")?),
        Err(Error::Config(_))
    ));
    assert!(matches!(
        add_account("accounts = 1", &account("a")?),
        Err(Error::Config(_))
    ));
    let mut bad = account("bad")?;
    bad.name = " ".into();
    assert!(add_account("", &bad).is_err());
    Ok(())
}

#[test]
fn sets_access() -> Result<(), Error> {
    let text = add_account("", &account("a")?)?;
    assert_eq!(Config::parse(&text)?.account("a")?.access, Access::Organize);
    let read = set_access(&text, "a", Access::Read)?;
    assert_eq!(Config::parse(&read)?.account("a")?.access, Access::Read);
    assert_eq!(
        set_access(&text, "b", Access::Read),
        Err(Error::UnknownAccount("b".into()))
    );
    Ok(())
}

#[test]
fn removes_accounts() -> Result<(), Error> {
    let one = add_account("", &account("a")?)?;
    let two = add_account(&one, &account("b")?)?;
    let left = remove_account(&two, "a")?;
    assert!(Config::parse(&left)?.account("a").is_err());
    assert_eq!(
        remove_account(&left, "zzz"),
        Err(Error::UnknownAccount("zzz".into()))
    );
    assert!(matches!(remove_account(&left, "b"), Err(Error::Config(m)) if m.contains("accounts")));
    Ok(())
}

#[test]
fn edits_the_allowlist() -> Result<(), Error> {
    let base = add_account("", &account("a")?)?;
    let addr = EmailAddress::parse("accounting@example.com")?;
    let with = allowlist_add(&base, &addr)?;
    assert_eq!(allowlist_add(&with, &addr)?, with);
    assert!(Config::parse(&with)?.forward_allowed(&addr));
    let without = allowlist_remove(&with, &addr)?;
    assert!(!Config::parse(&without)?.forward_allowed(&addr));
    assert!(matches!(
        allowlist_remove(&without, &addr),
        Err(Error::InvalidInput(_))
    ));
    assert!(matches!(
        allowlist_add("forward_allowlist = 1", &addr),
        Err(Error::Config(_))
    ));
    assert!(matches!(
        allowlist_add("x = [", &addr),
        Err(Error::Config(_))
    ));
    Ok(())
}

#[test]
fn picks_sent_folder() -> Result<(), Error> {
    let f = |name: &str, special: Option<&str>, selectable| -> Result<FolderInfo, Error> {
        Ok(FolderInfo {
            name: MailboxName::new(name)?,
            delimiter: None,
            selectable,
            special_use: special.map(str::to_owned),
        })
    };
    let flagged = [
        f("Gesendet", None, true)?,
        f("Postausgang", Some("sent"), true)?,
    ];
    assert_eq!(
        pick_sent_folder(&flagged).map(|n| n.to_string()),
        Some("Postausgang".into())
    );
    let named = [
        f("INBOX", None, true)?,
        f("Sent", None, false)?,
        f("INBOX.Sent", None, true)?,
    ];
    assert_eq!(
        pick_sent_folder(&named).map(|n| n.to_string()),
        Some("INBOX.Sent".into())
    );
    assert_eq!(pick_sent_folder(&[f("INBOX", None, true)?]), None);
    Ok(())
}

#[test]
fn edits_refuse_broken_files() -> Result<(), Error> {
    let address = EmailAddress::parse("accounting@example.com")?;
    for broken in ["x = [", "accounts = 1"] {
        assert!(
            matches!(remove_account(broken, "a"), Err(Error::Config(_))),
            "{broken}"
        );
        assert!(
            matches!(set_access(broken, "a", Access::Read), Err(Error::Config(_))),
            "{broken}"
        );
    }
    for broken in ["x = [", "forward_allowlist = \"accounting@example.com\""] {
        assert!(
            matches!(allowlist_add(broken, &address), Err(Error::Config(_))),
            "{broken}"
        );
        assert!(
            matches!(allowlist_remove(broken, &address), Err(Error::Config(_))),
            "{broken}"
        );
    }
    Ok(())
}
