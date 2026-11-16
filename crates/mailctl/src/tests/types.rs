//! Tests for `types`.

use super::*;

#[test]
fn uid_rejects_zero_and_keeps_value() -> Result<(), Error> {
    assert!(Uid::new(0).is_err());
    let uid = Uid::new(42)?;
    assert_eq!(uid.get(), 42);
    assert_eq!(uid.to_string(), "42");
    Ok(())
}

#[test]
fn message_id_strips_brackets_and_validates() -> Result<(), Error> {
    let id = MessageId::parse(" <abc@example.com> ")?;
    assert_eq!(id.as_str(), "abc@example.com");
    assert_eq!(id.to_string(), "abc@example.com");
    assert_eq!(MessageId::parse("abc@example.com")?, id);
    assert!(MessageId::parse("<>").is_err());
    assert!(MessageId::parse("a b").is_err());
    let back: String = id.clone().into();
    assert_eq!(MessageId::try_from(back)?, id);
    Ok(())
}

#[test]
fn mailbox_name_validates() -> Result<(), Error> {
    let name = MailboxName::new("Work/GitHub")?;
    assert_eq!(name.as_str(), "Work/GitHub");
    assert_eq!(name.to_string(), "Work/GitHub");
    assert!(MailboxName::new("").is_err());
    assert!(MailboxName::new("a\nb").is_err());
    let back: String = name.clone().into();
    assert_eq!(MailboxName::try_from(back)?, name);
    Ok(())
}

#[test]
fn email_address_validates_and_lowercases() -> Result<(), Error> {
    let addr = EmailAddress::parse(" Accounting@Example.COM ")?;
    assert_eq!(addr.as_str(), "accounting@example.com");
    assert_eq!(addr.to_string(), "accounting@example.com");
    assert_eq!(addr.domain(), "example.com");
    for bad in [
        "", "nobody", "@x.de", "a@b", "a@@b.de", "a b@c.de", "<a@b.de>",
    ] {
        assert!(EmailAddress::parse(bad).is_err(), "{bad} should fail");
    }
    let back: String = addr.clone().into();
    assert_eq!(EmailAddress::try_from(back)?, addr);
    Ok(())
}

#[test]
fn mail_ref_is_stable_and_short() -> Result<(), Error> {
    let a = MailRef::from_message_id(&MessageId::parse("<x@y.z>")?);
    let b = MailRef::from_message_id(&MessageId::parse("x@y.z")?);
    assert_eq!(a, b);
    assert_eq!(a.as_str().len(), MAIL_REF_LEN);
    assert_eq!(a.to_string(), a.as_str());
    let c = MailRef::from_fallback("2026-11-16", "a@b.de", "Hi", 10);
    let d = MailRef::from_fallback("2026-11-16", "a@b.de", "Hi", 11);
    assert_ne!(c, d);
    assert_ne!(a, c);
    assert_eq!(MailRef::parse(a.as_str())?, a);
    assert!(MailRef::parse("ABCDEF0123").is_err());
    assert!(MailRef::parse("abc").is_err());
    Ok(())
}

#[test]
fn expect_distinguishes_refs_and_ids() -> Result<(), Error> {
    assert!(matches!(Expect::parse("0123456789")?, Expect::Ref(_)));
    assert!(matches!(Expect::parse("<a@b>")?, Expect::MessageId(_)));
    assert!(Expect::parse(" ").is_err());
    Ok(())
}

#[test]
fn generated_message_ids_use_the_sender_domain() -> Result<(), Error> {
    let from = EmailAddress::parse("Alice@Example.com")?;
    let id = MessageId::generated(1_700_000_000, 0xbeef, 3, &from);
    assert_eq!(
        id.as_str(),
        "mailctl-1700000000-000000000000beef-3@example.com"
    );
    assert_ne!(
        MessageId::generated(1_700_000_000, 0xbeef, 3, &from),
        MessageId::generated(1_700_000_000, 0xbeee, 3, &from)
    );
    assert_eq!(MessageId::parse(id.as_str())?, id);
    Ok(())
}

#[test]
fn only_port_465_uses_implicit_tls_for_smtp() {
    assert!(smtp_implicit_tls(SUBMISSIONS_PORT));
    assert!(!smtp_implicit_tls(SUBMISSION_PORT));
    assert!(!smtp_implicit_tls(25));
}
