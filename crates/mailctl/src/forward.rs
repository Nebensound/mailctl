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

/// Maps a transport error to [`Error::InvalidInput`] with `context` in front.
fn invalid<E: std::fmt::Display>(context: String) -> impl FnOnce(E) -> Error {
    move |e| Error::InvalidInput(format!("{context}: {e}"))
}

fn mailbox(address: &EmailAddress) -> Result<Mailbox, Error> {
    address
        .as_str()
        .parse()
        .map_err(invalid(format!("address {address}")))
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
        // mail_parser has decoded text parts to UTF-8 already; say so, or the
        // recipient reads them in the default US-ASCII.
        let mime = mime_of(part.content_type());
        let mime = if part.is_text() {
            format!("{mime}; charset=utf-8")
        } else {
            mime
        };
        let content_type =
            ContentType::parse(&mime).map_err(invalid("attachment type".to_owned()))?;
        parts =
            parts.singlepart(Attachment::new(name).body(part.contents().to_vec(), content_type));
    }

    // Sender and recipient are always set, so assembling cannot fail in
    // practice; it is still checked instead of unwrapped.
    Message::builder()
        .from(mailbox(request.from)?)
        .to(mailbox(request.to)?)
        .subject(subject_for(subject))
        .message_id(Some(format!("<{}>", request.message_id)))
        .multipart(parts)
        .ok()
        .map(|message| message.formatted())
        .ok_or(Error::InvalidInput("cannot build forward".into()))
}

#[cfg(test)]
#[path = "tests/forward.rs"]
mod tests;
