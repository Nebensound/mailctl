//! Building the forward message: the original text plus all original attachments.

use std::fmt::Write as _;

use lettre::Message;
use lettre::message::header::ContentType;
use lettre::message::{Attachment, Mailbox, MultiPart, SinglePart};
use mail_parser::{MessageParser, MimeHeaders};

use crate::error::Error;
use crate::model::mime_of;
use crate::types::{EmailAddress, MessageId};

/// Input for [`build`].
#[derive(Debug, Clone)]
pub struct ForwardRequest<'a> {
    /// Sender of the forward.
    pub from: &'a EmailAddress,
    /// Recipient of the forward.
    pub to: &'a EmailAddress,
    /// `Message-ID` for the new message.
    pub message_id: &'a MessageId,
    /// Optional note placed above the forwarded text.
    pub note: Option<&'a str>,
    /// The complete original message.
    pub original: &'a [u8],
}

fn subject_for(original: &str) -> String {
    let lower = original.to_lowercase();
    if ["fwd:", "fw:", "wg:"].iter().any(|p| lower.starts_with(p)) {
        original.to_owned()
    } else {
        format!("Fwd: {original}")
    }
}

fn mailbox(address: &EmailAddress) -> Result<Mailbox, Error> {
    address
        .as_str()
        .parse()
        .map_err(|e| Error::InvalidInput(format!("address {address}: {e}")))
}

/// Builds the forward as raw RFC 5322 bytes.
///
/// # Errors
/// Returns [`Error::InvalidInput`] if the original cannot be parsed or the
/// message cannot be assembled.
pub fn build(request: &ForwardRequest<'_>) -> Result<Vec<u8>, Error> {
    let parsed = MessageParser::default()
        .parse(request.original)
        .ok_or_else(|| Error::InvalidInput("original message cannot be parsed".into()))?;
    let subject = parsed.subject().unwrap_or_default();
    let from = parsed
        .from()
        .and_then(|a| a.first())
        .and_then(mail_parser::Addr::address)
        .unwrap_or_default();
    let date = parsed
        .date()
        .map(mail_parser::DateTime::to_rfc3339)
        .unwrap_or_default();
    let text = parsed.body_text(0).unwrap_or_default();
    let mut body = String::new();
    if let Some(note) = request.note {
        body.push_str(note);
        body.push_str("\n\n");
    }
    body.push_str("---------- Forwarded message ----------\n");
    let _ = write!(
        body,
        "From: {from}
Date: {date}
Subject: {subject}

{text}"
    );

    let mut parts = MultiPart::mixed().singlepart(SinglePart::plain(body));
    for part in parsed.attachments() {
        let name = part.attachment_name().unwrap_or("attachment").to_owned();
        let content_type = ContentType::parse(&mime_of(part.content_type()))
            .map_err(|e| Error::InvalidInput(format!("attachment type: {e}")))?;
        parts =
            parts.singlepart(Attachment::new(name).body(part.contents().to_vec(), content_type));
    }

    let message = Message::builder()
        .from(mailbox(request.from)?)
        .to(mailbox(request.to)?)
        .subject(subject_for(subject))
        .message_id(Some(format!("<{}>", request.message_id)))
        .multipart(parts)
        .map_err(|e| Error::InvalidInput(format!("cannot build forward: {e}")))?;
    Ok(message.formatted())
}

#[cfg(test)]
mod tests {
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
}
