//! Pure IMAP wire helpers used by the IMAP adapter: flag and folder
//! attribute mapping, UID sets, keyword support and APPEND quoting.

use std::borrow::Cow;

use ::imap::types::Flag;
use imap_proto::NameAttribute;

use crate::store::FLAG_FORWARDED;
use crate::types::{MailboxName, Uid};
use crate::utf7;

/// The imap crate's flag for a flag name; anything not a system flag is a
/// keyword.
#[must_use]
pub fn flag_of(name: &str) -> Flag<'static> {
    match name {
        "\\Seen" => Flag::Seen,
        "\\Answered" => Flag::Answered,
        "\\Flagged" => Flag::Flagged,
        "\\Draft" => Flag::Draft,
        other => Flag::Custom(Cow::Owned(other.to_owned())),
    }
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

/// Whether a folder keeps custom keywords such as `$Forwarded`, judged from
/// the raw SELECT response. Without a `PERMANENTFLAGS` code RFC 3501 says
/// all flags are permanent; an explicit `PERMANENTFLAGS ()` means none is.
/// (The imap crate reports both as an empty list, hence the raw response.)
/// Keywords compare case-insensitively.
#[must_use]
pub fn keywords_allowed(select_response: &[u8]) -> bool {
    let text = String::from_utf8_lossy(select_response);
    let upper = text.to_ascii_uppercase();
    let Some(start) = upper.find("[PERMANENTFLAGS (") else {
        return true;
    };
    let list = text
        .get(start.saturating_add("[PERMANENTFLAGS (".len())..)
        .and_then(|rest| rest.split(')').next())
        .unwrap_or_default();
    list.split_whitespace()
        .any(|f| f == "\\*" || f.eq_ignore_ascii_case(FLAG_FORWARDED))
}

/// A mailbox name as an IMAP quoted string's content: modified UTF-7, with
/// `\\` and `"` escaped. The imap crate writes APPEND's mailbox between
/// quotes as it is, and the raw SELECT needs the same.
#[must_use]
pub fn append_mailbox(folder: &MailboxName) -> String {
    utf7::encode(folder.as_str())
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
}

#[cfg(test)]
#[path = "tests/imap_wire.rs"]
mod tests;
