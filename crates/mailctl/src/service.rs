//! All decisions: listing, verifying and changing mail. Works on the traits from
//! [`crate::store`] only.

use serde::Serialize;

use crate::config::Config;
use crate::error::Error;
use crate::forward::{self, ForwardRequest};
use crate::model::{self, MailDetail, MailSummary};
use crate::store::{
    FLAG_FORWARDED, FLAG_SEEN, FolderInfo, MailSender, MailStore, RawHeader, has_flag,
};
use crate::types::{EmailAddress, Expect, MailboxName, MessageId, Uid};

/// Result of a changing command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ActionReport {
    /// What was done: `mark_read`, `move`, `forward` or `create_folder`.
    pub op: &'static str,
    /// The mail concerned, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mail: Option<MailSummary>,
    /// Target folder or recipient.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// Nothing was changed because of `--dry-run`.
    pub dry_run: bool,
    /// The change was made and confirmed by reading it back from the server.
    /// `false` after a live move of a mail without `Message-ID`: it left the
    /// source folder, but cannot be identified in the target.
    pub confirmed: bool,
}

/// Lists folders.
///
/// # Errors
/// Server errors.
pub fn folders(store: &mut dyn MailStore) -> Result<Vec<FolderInfo>, Error> {
    store.folders()
}

/// Number of mails whose headers are fetched per IMAP request.
pub const FETCH_CHUNK: usize = 500;

/// Lists up to `limit` mails of a folder, newest (highest UID) first,
/// optionally only below the UID `before` for paging.
///
/// # Errors
/// Server errors.
pub fn list(
    store: &mut dyn MailStore,
    folder: &MailboxName,
    limit: usize,
    before: Option<Uid>,
) -> Result<Vec<MailSummary>, Error> {
    let mut all = Vec::new();
    list_each(store, folder, limit, before, FETCH_CHUNK, &mut |mail| {
        all.push(mail);
        Ok(())
    })?;
    Ok(all)
}

/// Like [`list`], but fetches headers in chunks of `chunk` mails and hands each
/// mail to `on_mail` as soon as its chunk arrived, newest first. Returns the
/// number of mails delivered.
///
/// # Errors
/// Server errors and errors returned by `on_mail`.
pub fn list_each(
    store: &mut dyn MailStore,
    folder: &MailboxName,
    limit: usize,
    before: Option<Uid>,
    chunk: usize,
    on_mail: &mut dyn FnMut(MailSummary) -> Result<(), Error>,
) -> Result<usize, Error> {
    // EXAMINE: reading must not clear `\Recent` for other clients.
    store.select_read_only(folder)?;
    let mut uids: Vec<Uid> = store
        .uids()?
        .into_iter()
        .filter(|uid| before.is_none_or(|b| *uid < b))
        .collect();
    uids.sort_unstable_by_key(|u| std::cmp::Reverse(*u));
    uids.truncate(limit);
    let mut delivered = 0_usize;
    for part in uids.chunks(chunk.max(1)) {
        let mut summaries: Vec<MailSummary> = store
            .headers(part)?
            .iter()
            .map(model::summary_from_header)
            .collect();
        summaries.sort_unstable_by_key(|s| std::cmp::Reverse(s.uid));
        for mail in summaries {
            on_mail(mail)?;
            delivered = delivered.saturating_add(1);
        }
    }
    Ok(delivered)
}

fn header_of(store: &mut dyn MailStore, uid: Uid) -> Result<RawHeader, Error> {
    store
        .headers(&[uid])?
        .into_iter()
        .find(|h| h.uid == uid)
        .ok_or(Error::NotFound(uid.get()))
}

/// Checks that the mail at `uid` in the selected folder is the expected one.
fn verify(store: &mut dyn MailStore, uid: Uid, expect: &Expect) -> Result<MailSummary, Error> {
    let summary = model::summary_from_header(&header_of(store, uid)?);
    let matches = match expect {
        Expect::MessageId(id) => summary.message_id.as_ref() == Some(id),
        Expect::Ref(r) => &summary.mail_ref == r,
    };
    if matches {
        Ok(summary)
    } else {
        Err(Error::MessageIdMismatch {
            uid: uid.get(),
            expected: match expect {
                Expect::MessageId(id) => id.to_string(),
                Expect::Ref(r) => r.to_string(),
            },
            found: summary
                .message_id
                .as_ref()
                .map_or_else(|| summary.mail_ref.to_string(), ToString::to_string),
        })
    }
}

/// Shows one mail, optionally checking its identity first.
///
/// # Errors
/// [`Error::NotFound`], [`Error::MessageIdMismatch`] or server errors.
pub fn show(
    store: &mut dyn MailStore,
    folder: &MailboxName,
    uid: Uid,
    expect: Option<&Expect>,
    max_chars: usize,
) -> Result<MailDetail, Error> {
    store.select_read_only(folder)?;
    if let Some(expect) = expect {
        verify(store, uid, expect)?;
    }
    let raw = store.message(uid)?.ok_or(Error::NotFound(uid.get()))?;
    Ok(model::detail_from_message(&raw, max_chars))
}

/// Marks a mail as read.
///
/// # Errors
/// [`Error::NotFound`], [`Error::MessageIdMismatch`], [`Error::NotConfirmed`] or server errors.
pub fn mark_read(
    store: &mut dyn MailStore,
    folder: &MailboxName,
    uid: Uid,
    expect: &Expect,
    dry_run: bool,
) -> Result<ActionReport, Error> {
    store.select(folder)?;
    let mail = verify(store, uid, expect)?;
    let mut confirmed = false;
    if !dry_run {
        store.add_flags(uid, &[FLAG_SEEN])?;
        if !has_flag(&header_of(store, uid)?.flags, FLAG_SEEN) {
            return Err(Error::NotConfirmed(format!("\\Seen not set on UID {uid}")));
        }
        confirmed = true;
    }
    Ok(ActionReport {
        op: "mark_read",
        mail: Some(mail),
        target: None,
        dry_run,
        confirmed,
    })
}

fn require_folder(store: &mut dyn MailStore, name: &MailboxName) -> Result<(), Error> {
    let exists = store
        .folders()?
        .iter()
        .any(|f| &f.name == name && f.selectable);
    if exists {
        Ok(())
    } else {
        Err(Error::FolderMissing(name.to_string()))
    }
}

/// Checks that `folder` holds a mail whose `Message-ID` is exactly `id` (the
/// server's header search only matches substrings), with `required_flag` set
/// on the newest such mail.
fn confirm_in_folder(
    store: &mut dyn MailStore,
    folder: &MailboxName,
    id: &MessageId,
    required_flag: Option<&str>,
) -> Result<(), Error> {
    store.select(folder)?;
    let candidates = store.find_message_id(id)?;
    let newest = store
        .headers(&candidates)?
        .into_iter()
        .filter(|h| model::summary_from_header(h).message_id.as_ref() == Some(id))
        .max_by_key(|h| h.uid);
    let Some(header) = newest else {
        return Err(Error::NotConfirmed(format!("{id} not found in {folder}")));
    };
    if let Some(flag) = required_flag
        && !has_flag(&header.flags, flag)
    {
        return Err(Error::NotConfirmed(format!(
            "{flag} not set on {id} in {folder}"
        )));
    }
    Ok(())
}

/// Moves a mail to another folder of the same account, optionally marking it read first.
///
/// # Errors
/// [`Error::FolderMissing`], [`Error::MoveUnsupported`], [`Error::NotFound`],
/// [`Error::MessageIdMismatch`], [`Error::NotConfirmed`] or server errors.
pub fn move_mail(
    store: &mut dyn MailStore,
    folder: &MailboxName,
    uid: Uid,
    expect: &Expect,
    target: &MailboxName,
    mark_read_first: bool,
    dry_run: bool,
) -> Result<ActionReport, Error> {
    require_folder(store, target)?;
    if !store.supports_move()? {
        return Err(Error::MoveUnsupported);
    }
    store.select(folder)?;
    let mail = verify(store, uid, expect)?;
    let mut confirmed = false;
    if !dry_run {
        if mark_read_first {
            store.add_flags(uid, &[FLAG_SEEN])?;
        }
        store.move_to(uid, target)?;
        store.select(folder)?;
        if !store.headers(&[uid])?.is_empty() {
            return Err(Error::NotConfirmed(format!("UID {uid} still in {folder}")));
        }
        // Without a Message-ID the mail cannot be found again in the target:
        // it left the source, but that is not confirmed as filed.
        if let Some(id) = &mail.message_id {
            let flag = mark_read_first.then_some(FLAG_SEEN);
            confirm_in_folder(store, target, id, flag)?;
            confirmed = true;
        }
    }
    Ok(ActionReport {
        op: "move",
        mail: Some(mail),
        target: Some(target.to_string()),
        dry_run,
        confirmed,
    })
}

/// Creates a folder if it does not exist yet.
///
/// # Errors
/// [`Error::FolderExists`], [`Error::NotConfirmed`] or server errors.
pub fn create_folder(
    store: &mut dyn MailStore,
    name: &MailboxName,
    dry_run: bool,
) -> Result<ActionReport, Error> {
    if store.folders()?.iter().any(|f| &f.name == name) {
        return Err(Error::FolderExists(name.to_string()));
    }
    let mut confirmed = false;
    if !dry_run {
        store.create_folder(name)?;
        if !store.folders()?.iter().any(|f| &f.name == name) {
            return Err(Error::NotConfirmed(format!(
                "folder {name} not listed after creation"
            )));
        }
        confirmed = true;
    }
    Ok(ActionReport {
        op: "create_folder",
        mail: None,
        target: Some(name.to_string()),
        dry_run,
        confirmed,
    })
}

/// After sending: flags the original as `$Forwarded` and stores the copy in
/// the sent folder, and confirms both. The copy does not depend on the flag:
/// both steps run, and every failure is reported.
fn record_forward(
    store: &mut dyn MailStore,
    job: &ForwardJob<'_>,
    bytes: &[u8],
) -> Result<(), Error> {
    let flagged = flag_forwarded(store, job);
    let copied = match job.sent_folder {
        Some(sent) => store
            .append(sent, bytes, &[FLAG_SEEN])
            .and_then(|()| confirm_in_folder(store, sent, job.new_message_id, None)),
        None => Ok(()),
    };
    match (flagged, copied) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(e), Ok(())) | (Ok(()), Err(e)) => Err(e),
        (Err(flag), Err(copy)) => Err(Error::NotConfirmed(format!("{flag}; {copy}"))),
    }
}

fn flag_forwarded(store: &mut dyn MailStore, job: &ForwardJob<'_>) -> Result<(), Error> {
    store.add_flags(job.uid, &[FLAG_FORWARDED])?;
    if has_flag(&header_of(store, job.uid)?.flags, FLAG_FORWARDED) {
        Ok(())
    } else {
        Err(Error::NotConfirmed(format!(
            "{FLAG_FORWARDED} not set on UID {}",
            job.uid
        )))
    }
}

/// Everything [`forward`] needs besides the connections.
#[derive(Debug, Clone)]
pub struct ForwardJob<'a> {
    /// Folder of the original.
    pub folder: &'a MailboxName,
    /// UID of the original.
    pub uid: Uid,
    /// Identity check for the original.
    pub expect: &'a Expect,
    /// Recipient; must be on the allow list.
    pub to: &'a EmailAddress,
    /// Sender address of the account.
    pub from: &'a EmailAddress,
    /// Sent folder for the copy; `None` where the server files sent mail
    /// itself (Gmail, Microsoft 365), so a second copy is not stored.
    pub sent_folder: Option<&'a MailboxName>,
    /// `Message-ID` for the new message.
    pub new_message_id: &'a MessageId,
    /// Optional note.
    pub note: Option<&'a str>,
    /// Only check, change nothing.
    pub dry_run: bool,
}

/// Forwards a mail with its attachments, stores a copy in the sent folder and
/// flags the original as `$Forwarded`. Refuses recipients outside the allow
/// list and mails that were already forwarded.
///
/// # Errors
/// [`Error::ForwardNotAllowed`], [`Error::AlreadyForwarded`], [`Error::NotFound`],
/// [`Error::MessageIdMismatch`], [`Error::NotConfirmed`], send or server errors.
pub fn forward(
    store: &mut dyn MailStore,
    sender: &mut dyn MailSender,
    config: &Config,
    job: &ForwardJob<'_>,
) -> Result<ActionReport, Error> {
    if !config.forward_allowed(job.to) {
        return Err(Error::ForwardNotAllowed(job.to.to_string()));
    }
    store.select(job.folder)?;
    let mail = verify(store, job.uid, job.expect)?;
    if mail.flags.forwarded {
        return Err(Error::AlreadyForwarded(job.uid.get()));
    }
    if !store.keywords_allowed()? {
        return Err(Error::KeywordsUnsupported(job.folder.to_string()));
    }
    let original = store
        .message(job.uid)?
        .ok_or(Error::NotFound(job.uid.get()))?;
    let bytes = forward::build(&ForwardRequest {
        from: job.from,
        to: job.to,
        message_id: job.new_message_id,
        note: job.note,
        original: &original.body,
    })?;
    // Before anything is sent, also in a dry run: the copy must have a place.
    if let Some(sent) = job.sent_folder {
        require_folder(store, sent)?;
    }
    let mut confirmed = false;
    if !job.dry_run {
        sender.send(job.from, job.to, &bytes)?;
        // The mail is out. Flag the original first, so a retry is refused as
        // `AlreadyForwarded` even if storing the copy fails; report anything
        // that fails from here on as partly done instead of as a plain error.
        record_forward(store, job, &bytes).map_err(|e| {
            Error::Partial(format!(
                "UID {} was forwarded to {}, but {e}",
                job.uid, job.to
            ))
        })?;
        confirmed = true;
    }
    Ok(ActionReport {
        op: "forward",
        mail: Some(mail),
        target: Some(job.to.to_string()),
        dry_run: job.dry_run,
        confirmed,
    })
}

#[cfg(test)]
#[path = "tests/service.rs"]
mod tests;
