//! Tests for `model`.

use super::*;
use crate::error::Error;

pub(crate) const INVOICE: &str = "Message-ID: <inv-1@shop.example>\r\n\
Date: Wed, 11 Nov 2026 10:00:00 +0100\r\n\
From: Shop Ltd <billing@shop.example>\r\n\
To: Example Ltd <alice@example.com>, info@example.com\r\n\
Cc: Accounting <accounting@example.com>\r\n\
Subject: Invoice 4711\r\n\
MIME-Version: 1.0\r\n\
Content-Type: multipart/mixed; boundary=\"b\"\r\n\
\r\n\
--b\r\n\
Content-Type: text/plain; charset=utf-8\r\n\
\r\n\
Invoice attached.\r\n\
--b\r\n\
Content-Type: application/pdf; name=\"invoice.pdf\"\r\n\
Content-Disposition: attachment; filename=\"invoice.pdf\"\r\n\
Content-Transfer-Encoding: base64\r\n\
\r\n\
JVBERi0=\r\n\
--b\r\n\
Content-Type: application/x-unknown\r\n\
Content-Disposition: attachment\r\n\
\r\n\
x\r\n\
--b--\r\n";

#[test]
fn summarizes_headers_with_flags() -> Result<(), Error> {
    let raw = RawHeader {
        uid: Uid::new(7)?,
        flags: vec!["\\SEEN".into(), "\\Flagged".into(), "$Forwarded".into()],
        size: 1234,
        header: INVOICE.as_bytes().to_vec(),
    };
    let s = summary_from_header(&raw);
    assert_eq!(s.message_id, Some(MessageId::parse("inv-1@shop.example")?));
    assert_eq!(
        s.mail_ref,
        MailRef::from_message_id(&MessageId::parse("inv-1@shop.example")?)
    );
    assert_eq!(s.from, "Shop Ltd <billing@shop.example>");
    assert_eq!(s.subject, "Invoice 4711");
    assert_eq!(s.date.as_deref(), Some("2026-11-11T10:00:00+01:00"));
    assert!(s.flags.seen && s.flags.flagged && s.flags.forwarded && s.likely_attachments);
    Ok(())
}

#[test]
fn falls_back_without_message_id() -> Result<(), Error> {
    let raw = RawHeader {
        uid: Uid::new(1)?,
        flags: vec![],
        size: 5,
        header: b"From: a@b.de\r\nContent-Type: text/plain\r\n\r\n".to_vec(),
    };
    let s = summary_from_header(&raw);
    assert!(s.message_id.is_none() && s.date.is_none() && !s.flags.seen && !s.likely_attachments);
    assert_eq!(s.from, "a@b.de");
    assert_eq!(s.mail_ref, MailRef::from_fallback("", "a@b.de", "", 5));
    let empty = RawHeader {
        header: Vec::new(),
        ..raw
    };
    assert_eq!(summary_from_header(&empty).from, "");
    Ok(())
}

#[test]
fn details_include_text_recipients_and_attachments() -> Result<(), Error> {
    let raw = RawMessage {
        uid: Uid::new(7)?,
        flags: vec![],
        size: 4711,
        body: INVOICE.as_bytes().to_vec(),
    };
    let d = detail_from_message(&raw, 5);
    assert_eq!(d.text, "Invoi");
    assert!(d.text_truncated);
    assert_eq!(
        d.to,
        vec!["Example Ltd <alice@example.com>", "info@example.com"]
    );
    assert_eq!(d.cc, vec!["Accounting <accounting@example.com>"]);
    assert_eq!(d.attachments.len(), 2);
    let pdf = d
        .attachments
        .first()
        .ok_or_else(|| Error::InvalidInput("missing".into()))?;
    assert_eq!(pdf.name.as_deref(), Some("invoice.pdf"));
    assert_eq!(pdf.mime, "application/pdf");
    let full = detail_from_message(&raw, 1000);
    assert!(!full.text_truncated);
    let empty = detail_from_message(
        &RawMessage {
            body: Vec::new(),
            ..raw
        },
        10,
    );
    assert!(empty.text.is_empty() && empty.attachments.is_empty() && empty.to.is_empty());
    Ok(())
}

#[test]
fn mime_fallbacks() -> Result<(), Error> {
    let body = b"Content-Type: multipart/mixed; boundary=\"b\"\r\n\r\n--b\r\n\
Content-Type: text/plain\r\n\r\nHi\r\n--b\r\n\
Content-Type: application\r\nContent-Disposition: attachment; filename=\"a.bin\"\r\n\r\nx\r\n--b\r\n\
Content-Disposition: attachment; filename=\"b.bin\"\r\n\r\ny\r\n--b--\r\n";
    let raw = RawMessage {
        uid: Uid::new(1)?,
        flags: vec![],
        size: 300,
        body: body.to_vec(),
    };
    let d = detail_from_message(&raw, 10);
    let mimes: Vec<&str> = d.attachments.iter().map(|a| a.mime.as_str()).collect();
    assert!(
        mimes.iter().all(|m| *m == OCTET_STREAM || m.contains('/')),
        "{mimes:?}"
    );
    assert!(mimes.contains(&OCTET_STREAM));
    assert_eq!(mime_of(None), OCTET_STREAM);
    Ok(())
}

#[test]
fn address_variants() {
    let msg = MessageParser::default().parse_headers(b"To: \"Only Name\" <>, plain@x.de\r\n\r\n");
    let list = addresses(msg.as_ref().and_then(mail_parser::Message::to));
    assert!(list.contains(&"plain@x.de".to_owned()));
}

#[test]
fn show_and_list_agree_on_the_reference() -> Result<(), Error> {
    // Without a Message-ID the reference hashes the size; the server's
    // RFC822.SIZE may differ from the bytes received (line endings).
    let mail = b"From: a@example.com\r\nSubject: no id\r\n\r\nbody\r\n".to_vec();
    let size = 999;
    let listed = summary_from_header(&RawHeader {
        uid: Uid::new(3)?,
        flags: vec![],
        size,
        header: mail.clone(),
    });
    let shown = detail_from_message(
        &RawMessage {
            uid: Uid::new(3)?,
            flags: vec![],
            size,
            body: mail,
        },
        10,
    );
    assert_eq!(shown.summary.mail_ref, listed.mail_ref);
    assert_eq!(shown.summary.size, 999);
    Ok(())
}
