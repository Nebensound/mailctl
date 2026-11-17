//! Pure IMAP wire helpers used by the IMAP adapter: reading the responses
//! it gets (LIST, FETCH, SEARCH, CAPABILITY, SELECT, command completion),
//! flag lists, UID sets and mailbox quoting.

use async_imap::imap_proto::{
    AttributeValue, Capability, MailboxDatum, MailboxListData, MessageSection, NameAttribute,
    RequestId, Response, ResponseCode, SectionPath, Status,
};

use crate::store::{FLAG_FORWARDED, FolderInfo};
use crate::types::{MailboxName, Uid};
use crate::utf7;

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

/// Collects what the answer to a SELECT says about custom keywords.
#[derive(Debug, Default)]
pub struct SelectKeywords {
    /// The last `PERMANENTFLAGS` code seen, if any.
    permanent: Option<Vec<String>>,
}

impl SelectKeywords {
    /// Takes one response to the SELECT, the tagged completion included.
    pub fn see(&mut self, response: &Response<'_>) {
        if let Some(flags) = permanent_flags(response) {
            self.permanent = Some(flags);
        }
    }

    /// Whether the selected folder keeps custom keywords such as
    /// `$Forwarded`.
    #[must_use]
    pub fn allowed(&self) -> bool {
        keywords_allowed(self.permanent.as_deref())
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
#[must_use]
pub fn command_done(response: &Response<'_>, tag: &RequestId) -> Option<Result<(), String>> {
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

/// The next response. The end of the connection counts as an error, since
/// a server never ends a command that way; depending on the TLS library a
/// cleanly closed connection arrives as no response or as a read error.
///
/// # Errors
/// Why there is no response.
pub fn received<T>(response: std::io::Result<Option<T>>) -> Result<T, String> {
    response
        .and_then(|r| r.ok_or(std::io::Error::from(std::io::ErrorKind::UnexpectedEof)))
        .map_err(|e| read_error(&e))
}

/// Describes a failed read; the end of the connection in plain words.
fn read_error(e: &std::io::Error) -> String {
    if e.kind() == std::io::ErrorKind::UnexpectedEof {
        "the server closed the connection".to_owned()
    } else {
        e.to_string()
    }
}

/// A folder of a LIST response; `None` for any other response, and for a
/// name that is not valid modified UTF-7 (written by another client), which
/// is skipped instead of failing the whole listing.
#[must_use]
pub fn listed_folder(response: &Response<'_>) -> Option<FolderInfo> {
    let Response::MailboxData(MailboxDatum::List(MailboxListData {
        name_attributes,
        delimiter,
        name,
    })) = response
    else {
        return None;
    };
    let name = utf7::decode(name)
        .and_then(|decoded| MailboxName::new(&decoded))
        .ok()?;
    Some(FolderInfo {
        name,
        delimiter: delimiter.as_deref().map(str::to_owned),
        selectable: !name_attributes.contains(&NameAttribute::NoSelect),
        special_use: name_attributes.iter().find_map(special_use),
    })
}

/// The attributes mailctl asks for, as one FETCH response carries them.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Fetched {
    /// `UID`; missing on a flag change another client made, which the server
    /// sends along unasked.
    pub uid: Option<u32>,
    /// `FLAGS` as the server sent them, e.g. `\Seen` or `$Forwarded`.
    pub flags: Vec<String>,
    /// `RFC822.SIZE`.
    pub size: Option<u32>,
    /// `BODY[HEADER]`.
    pub header: Option<Vec<u8>>,
    /// `BODY[]`.
    pub body: Option<Vec<u8>>,
}

/// The attributes of a FETCH response; `None` for any other response.
#[must_use]
pub fn fetched(response: &Response<'_>) -> Option<Fetched> {
    let Response::Fetch(_, attributes) = response else {
        return None;
    };
    let mut fetched = Fetched::default();
    for attribute in attributes {
        match attribute {
            AttributeValue::Uid(uid) => fetched.uid = Some(*uid),
            AttributeValue::Flags(flags) => {
                fetched.flags = flags.iter().map(ToString::to_string).collect();
            }
            AttributeValue::Rfc822Size(size) => fetched.size = Some(*size),
            AttributeValue::BodySection {
                section: Some(SectionPath::Full(MessageSection::Header)),
                data,
                ..
            } => fetched.header = data.as_deref().map(<[u8]>::to_vec),
            AttributeValue::BodySection {
                section: None,
                data,
                ..
            } => fetched.body = data.as_deref().map(<[u8]>::to_vec),
            // An open set: servers may add attributes nobody asked for.
            _ => {}
        }
    }
    Some(fetched)
}

/// The numbers of a SEARCH response; none for any other response.
#[must_use]
pub fn searched(response: &Response<'_>) -> Vec<u32> {
    match response {
        Response::MailboxData(MailboxDatum::Search(numbers)) => numbers.clone(),
        _ => Vec::new(),
    }
}

/// Whether a CAPABILITY response lists `name`, e.g. `MOVE`.
#[must_use]
pub fn has_capability(response: &Response<'_>, name: &str) -> bool {
    let Response::Capabilities(capabilities) = response else {
        return false;
    };
    capabilities
        .iter()
        .any(|c| matches!(c, Capability::Atom(atom) if atom.eq_ignore_ascii_case(name)))
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
