//! Tests for `forward`.

use super::*;
use crate::model::tests::INVOICE;

#[test]
fn subject_prefix() {
    assert_eq!(subject_for("Invoice"), "Fwd: Invoice");
    assert_eq!(subject_for("WG: Invoice"), "WG: Invoice");
    assert_eq!(subject_for("fwd: x"), "fwd: x");
}

#[test]
fn builds_forward_with_attachments() -> Result<(), Error> {
    let from = EmailAddress::parse("alice@example.com")?;
    let to = EmailAddress::parse("accounting@example.com")?;
    let id = MessageId::parse("fwd-1@mailctl")?;
    let bytes = build(&ForwardRequest {
        from: &from,
        to: &to,
        message_id: &id,
        note: Some("Please book."),
        original: INVOICE.as_bytes(),
    })?;
    let parsed = MessageParser::default()
        .parse(&bytes)
        .ok_or_else(|| Error::InvalidInput("unparseable".into()))?;
    assert_eq!(parsed.subject(), Some("Fwd: Invoice 4711"));
    assert_eq!(parsed.message_id(), Some("fwd-1@mailctl"));
    let text = parsed.body_text(0).unwrap_or_default();
    assert!(text.starts_with("Please book."));
    assert!(text.contains("From: billing@shop.example"));
    let names: Vec<_> = parsed
        .attachments()
        .map(|a| a.attachment_name().map(str::to_owned))
        .collect();
    assert_eq!(
        names,
        vec![
            Some("invoice.pdf".to_owned()),
            Some("attachment".to_owned())
        ]
    );
    Ok(())
}

#[test]
fn rejects_unparseable_original() -> Result<(), Error> {
    let addr = EmailAddress::parse("a@b.de")?;
    let id = MessageId::parse("x@y")?;
    let request = ForwardRequest {
        from: &addr,
        to: &addr,
        message_id: &id,
        note: None,
        original: b"",
    };
    assert!(build(&request).is_err());
    let plain = ForwardRequest {
        original: b"Subject: hi\r\n\r\nbody",
        ..request
    };
    let bytes = build(&plain)?;
    assert!(String::from_utf8_lossy(&bytes).contains("Fwd: hi"));
    Ok(())
}
