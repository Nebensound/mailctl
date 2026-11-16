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

const ODD_ATTACHMENT: &str = "Subject: odd\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\nsee attachment\r\n--b\r\nContent-Type: application/pdf@x\r\nContent-Disposition: attachment; filename=a.pdf\r\n\r\nxx\r\n--b--\r\n";

#[test]
fn rejects_attachment_types_the_transport_cannot_carry() -> Result<(), Error> {
    let addr = EmailAddress::parse("a@b.de")?;
    let id = MessageId::parse("x@y")?;
    let result = build(&ForwardRequest {
        from: &addr,
        to: &addr,
        message_id: &id,
        note: None,
        original: ODD_ATTACHMENT.as_bytes(),
    });
    assert!(
        matches!(&result, Err(Error::InvalidInput(m)) if m.starts_with("attachment type")),
        "{result:?}"
    );
    Ok(())
}

#[test]
fn rejects_addresses_the_transport_cannot_carry() -> Result<(), Error> {
    let good = EmailAddress::parse("a@b.de")?;
    let odd = EmailAddress::parse("a(b@x.de")?;
    let id = MessageId::parse("x@y")?;
    let request = ForwardRequest {
        from: &odd,
        to: &good,
        message_id: &id,
        note: None,
        original: b"Subject: hi\r\n\r\nbody",
    };
    let as_sender = build(&request);
    assert!(
        matches!(&as_sender, Err(Error::InvalidInput(m)) if m.starts_with("address a(b@x.de")),
        "{as_sender:?}"
    );
    let as_recipient = build(&ForwardRequest {
        from: &good,
        to: &odd,
        ..request
    });
    assert!(
        matches!(&as_recipient, Err(Error::InvalidInput(m)) if m.starts_with("address a(b@x.de")),
        "{as_recipient:?}"
    );
    Ok(())
}
