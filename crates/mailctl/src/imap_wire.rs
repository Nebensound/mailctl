//! Pure IMAP wire helpers used by the IMAP adapter: flag and folder
//! attribute mapping, UID sets, keyword support, SELECT completion and
//! mailbox quoting.

use async_imap::imap_proto::{RequestId, Response, ResponseCode, Status};
use async_imap::types::{Flag, NameAttribute};

use crate::store::FLAG_FORWARDED;
use crate::types::{MailboxName, Uid};
use crate::utf7;

/// The IMAP name of a flag as the server sent it, e.g. `\Seen` or
/// `$Forwarded`.
#[must_use]
pub fn flag_name(flag: &Flag<'_>) -> String {
    match flag {
        Flag::Seen => "\\Seen".to_owned(),
        Flag::Answered => "\\Answered".to_owned(),
        Flag::Flagged => "\\Flagged".to_owned(),
        Flag::Deleted => "\\Deleted".to_owned(),
        Flag::Draft => "\\Draft".to_owned(),
        Flag::Recent => "\\Recent".to_owned(),
        Flag::MayCreate => "\\*".to_owned(),
        Flag::Custom(name) => name.to_string(),
    }
}

/// A parenthesized flag list for STORE and APPEND: `(\Seen $Forwarded)`.
#[must_use]
pub fn flag_list(flags: &[&str]) -> String {
    format!("({})", flags.join(" "))
}

/// The RFC 6154 special-use name of a folder attribute, if it is one.
#[must_use]
pub fn special_use(attribute: &NameAttribute<'_>) -> Option<String> {
    let name = match attribute {
        NameAttribute::Sent => "sent",
        NameAttribute::Drafts => "drafts",
        NameAttribute::Junk => "junk",
        NameAttribute::Trash => "trash",
        NameAttribute::Archive => "archive",
        NameAttribute::All => "all",
        NameAttribute::Flagged => "flagged",
        _ => return None,
    };
    Some(name.to_owned())
}

/// A UID set for FETCH/STORE: `1,5,9`.
#[must_use]
pub fn uid_set(uids: &[Uid]) -> String {
    uids.iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

/// Follows the responses to a raw SELECT up to its tagged completion and
/// judges from them whether the folder keeps custom keywords.
#[derive(Debug)]
pub struct SelectReader {
    /// The tag of the SELECT command.
    tag: RequestId,
    /// The last `PERMANENTFLAGS` code seen, if any.
    permanent: Option<Vec<String>>,
}

impl SelectReader {
    /// Starts following the SELECT command tagged `tag`.
    #[must_use]
    pub fn new(tag: RequestId) -> Self {
        Self {
            tag,
            permanent: None,
        }
    }

    /// Takes the next server response: `None` while SELECT is still running,
    /// then whether the folder keeps keywords, or why SELECT failed.
    pub fn feed(&mut self, response: &Response<'_>) -> Option<Result<bool, String>> {
        if let Some(flags) = permanent_flags(response) {
            self.permanent = Some(flags);
        }
        command_done(response, &self.tag)
            .map(|done| done.map(|()| keywords_allowed(self.permanent.as_deref())))
    }
}

/// The flags of a `PERMANENTFLAGS` response code, if `response` carries one.
fn permanent_flags(response: &Response<'_>) -> Option<Vec<String>> {
    let (Response::Data { outcome, .. } | Response::Done { outcome, .. }) = response else {
        return None;
    };
    match &outcome.code {
        Some(ResponseCode::PermanentFlags(flags)) => {
            Some(flags.iter().map(ToString::to_string).collect())
        }
        _ => None,
    }
}

/// Whether a folder keeps custom keywords such as `$Forwarded`, judged from
/// the `PERMANENTFLAGS` code of its SELECT response. Without the code
/// (`None`) RFC 3501 says all flags are permanent; an explicit empty list
/// means none is. (The parsed mailbox of `async-imap` reports both as an
/// empty list, hence the adapter reads the responses itself.) Keywords
/// compare case-insensitively.
fn keywords_allowed(permanent: Option<&[String]>) -> bool {
    permanent.is_none_or(|flags| {
        flags
            .iter()
            .any(|f| f == "\\*" || f.eq_ignore_ascii_case(FLAG_FORWARDED))
    })
}

/// How a response ends the command tagged `tag`: `None` while the command
/// is still running, `Some(Ok(()))` when it completed, `Some(Err(reason))`
/// when the server refused it or closed the connection.
fn command_done(response: &Response<'_>, tag: &RequestId) -> Option<Result<(), String>> {
    match response {
        Response::Done {
            tag: done,
            status,
            outcome,
        } if done == tag => Some(match status {
            Status::Ok => Ok(()),
            _ => Err(format!(
                "{status:?}: {}",
                outcome.information.as_deref().unwrap_or_default()
            )),
        }),
        Response::Data {
            status: Status::Bye,
            outcome,
        } => Some(Err(format!(
            "server closed the connection: {}",
            outcome.information.as_deref().unwrap_or_default()
        ))),
        _ => None,
    }
}

/// A mailbox name as an IMAP quoted string: modified UTF-7 between quotes,
/// with `\` and `"` escaped. Needed for the raw SELECT command.
#[must_use]
pub fn quoted_mailbox(folder: &MailboxName) -> String {
    let encoded = utf7::encode(folder.as_str())
        .replace('\\', "\\\\")
        .replace('"', "\\\"");
    format!("\"{encoded}\"")
}

#[cfg(test)]
#[path = "tests/imap_wire.rs"]
mod tests;
