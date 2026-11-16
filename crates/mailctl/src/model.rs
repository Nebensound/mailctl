//! Output types and parsing of raw mail data into them.

use mail_parser::{Address, MessageParser, MimeHeaders};
use serde::Serialize;

use crate::store::{FLAG_FLAGGED, FLAG_FORWARDED, FLAG_SEEN, RawHeader, RawMessage};
use crate::types::{MailRef, MessageId, Uid};

/// One mail in a listing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MailSummary {
    /// Stable short reference (hash of the `Message-ID`).
    pub mail_ref: MailRef,
    /// UID in the listed folder.
    pub uid: Uid,
    /// `Message-ID` without angle brackets, if present.
    pub message_id: Option<MessageId>,
    /// `Date` header in RFC 3339, if parseable.
    pub date: Option<String>,
    /// Sender as `Name <address>` or just the address.
    pub from: String,
    /// Subject.
    pub subject: String,
    /// Server flags of interest.
    pub flags: MailFlags,
    /// The top-level content type is `multipart/mixed`, which usually means attachments.
    pub likely_attachments: bool,
    /// Size in bytes.
    pub size: u32,
}

/// Flags of a mail that matter for sorting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct MailFlags {
    /// `\Seen` is set.
    pub seen: bool,
    /// `\Flagged` is set.
    pub flagged: bool,
    /// `$Forwarded` is set.
    pub forwarded: bool,
}

/// An attachment of a mail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AttachmentInfo {
    /// File name, if given.
    pub name: Option<String>,
    /// MIME type such as `application/pdf`.
    pub mime: String,
    /// Size of the decoded content in bytes.
    pub size: usize,
}

/// One mail with content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MailDetail {
    /// Header data.
    #[serde(flatten)]
    pub summary: MailSummary,
    /// `To` recipients.
    pub to: Vec<String>,
    /// `Cc` recipients.
    pub cc: Vec<String>,
    /// Plain text body, cut to the requested length.
    pub text: String,
    /// The text was cut.
    pub text_truncated: bool,
    /// Attachments.
    pub attachments: Vec<AttachmentInfo>,
}

/// Fallback MIME type for parts without a usable `Content-Type`.
pub(crate) const OCTET_STREAM: &str = "application/octet-stream";

/// `type/subtype` of a part; parts without a full content type are treated as
/// [`OCTET_STREAM`].
pub(crate) fn mime_of(content_type: Option<&mail_parser::ContentType<'_>>) -> String {
    content_type
        .and_then(|ct| ct.subtype().map(|sub| format!("{}/{sub}", ct.ctype())))
        .unwrap_or_else(|| OCTET_STREAM.to_owned())
}

fn has_flag(flags: &[String], flag: &str) -> bool {
    flags.iter().any(|f| f.eq_ignore_ascii_case(flag))
}

fn addresses(address: Option<&Address<'_>>) -> Vec<String> {
    address
        .map(|a| {
            a.iter()
                .filter_map(|addr| {
                    let mail = addr.address().filter(|m| !m.is_empty())?;
                    Some(match addr.name() {
                        Some(name) => format!("{name} <{mail}>"),
                        None => mail.to_owned(),
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

fn summarize(
    uid: Uid,
    flags: &[String],
    size: u32,
    message: Option<&mail_parser::Message<'_>>,
) -> MailSummary {
    let message_id = message
        .and_then(mail_parser::Message::message_id)
        .and_then(|raw| MessageId::parse(raw).ok());
    let date = message
        .and_then(mail_parser::Message::date)
        .map(mail_parser::DateTime::to_rfc3339);
    let from = addresses(message.and_then(mail_parser::Message::from))
        .into_iter()
        .next()
        .unwrap_or_default();
    let subject = message
        .and_then(mail_parser::Message::subject)
        .unwrap_or_default()
        .to_owned();
    let likely_attachments = message.and_then(|m| m.content_type()).is_some_and(|ct| {
        ct.ctype().eq_ignore_ascii_case("multipart")
            && ct
                .subtype()
                .is_some_and(|s| s.eq_ignore_ascii_case("mixed"))
    });
    let mail_ref = message_id.as_ref().map_or_else(
        || MailRef::from_fallback(date.as_deref().unwrap_or_default(), &from, &subject, size),
        MailRef::from_message_id,
    );
    MailSummary {
        mail_ref,
        uid,
        message_id,
        date,
        from,
        subject,
        flags: MailFlags {
            seen: has_flag(flags, FLAG_SEEN),
            flagged: has_flag(flags, FLAG_FLAGGED),
            forwarded: has_flag(flags, FLAG_FORWARDED),
        },
        likely_attachments,
        size,
    }
}

/// Builds a summary from fetched headers.
#[must_use]
pub fn summary_from_header(raw: &RawHeader) -> MailSummary {
    let parsed = MessageParser::default().parse_headers(&raw.header);
    summarize(raw.uid, &raw.flags, raw.size, parsed.as_ref())
}

/// Builds the detail view from a complete mail, cutting the text to `max_chars`.
#[must_use]
pub fn detail_from_message(raw: &RawMessage, max_chars: usize) -> MailDetail {
    let parser = MessageParser::default();
    let parsed = parser.parse(&raw.body);
    let size = u32::try_from(raw.body.len()).unwrap_or(u32::MAX);
    let summary = summarize(raw.uid, &raw.flags, size, parsed.as_ref());
    let full_text = parsed
        .as_ref()
        .and_then(|m| m.body_text(0))
        .map(std::borrow::Cow::into_owned)
        .unwrap_or_default();
    let text_truncated = full_text.chars().count() > max_chars;
    let text = full_text.chars().take(max_chars).collect();
    let attachments = parsed
        .as_ref()
        .map(|m| {
            m.attachments()
                .map(|part| AttachmentInfo {
                    name: part.attachment_name().map(str::to_owned),
                    mime: mime_of(part.content_type()),
                    size: part.len(),
                })
                .collect()
        })
        .unwrap_or_default();
    MailDetail {
        to: addresses(parsed.as_ref().and_then(mail_parser::Message::to)),
        cc: addresses(parsed.as_ref().and_then(mail_parser::Message::cc)),
        summary,
        text,
        text_truncated,
        attachments,
    }
}

#[cfg(test)]
pub(crate) mod tests {
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
        assert!(
            s.message_id.is_none() && s.date.is_none() && !s.flags.seen && !s.likely_attachments
        );
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
        let msg =
            MessageParser::default().parse_headers(b"To: \"Only Name\" <>, plain@x.de\r\n\r\n");
        let list = addresses(msg.as_ref().and_then(mail_parser::Message::to));
        assert!(list.contains(&"plain@x.de".to_owned()));
    }
}
