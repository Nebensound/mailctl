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
#[path = "tests/model.rs"]
pub(crate) mod tests;
