//! All decisions: listing, verifying and changing mail. Works on the traits from
//! [`crate::store`] only.

use serde::Serialize;

use crate::config::Config;
use crate::error::Error;
use crate::forward::{self, ForwardRequest};
use crate::model::{self, MailDetail, MailSummary};
use crate::store::{
    FLAG_DELETED, FLAG_FORWARDED, FLAG_SEEN, FolderInfo, MailSender, MailStore, MoveSupport,
    RawHeader, has_flag,
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

/// Opens `folder` for a change: read-write, or with EXAMINE for a dry run, so
/// a preview does not clear `\Recent` for other clients.
fn open(store: &mut dyn MailStore, folder: &MailboxName, dry_run: bool) -> Result<(), Error> {
    if dry_run {
        store.select_read_only(folder)
    } else {
        store.select(folder)
    }
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
        // `found` is the same kind of value as `expected`, so a wrong UID and
        // a stale reference can be told apart without another lookup.
        let (expected, found) = match expect {
            Expect::MessageId(id) => (
                id.to_string(),
                summary
                    .message_id
                    .as_ref()
                    .map_or_else(|| "no Message-ID".to_owned(), ToString::to_string),
            ),
            Expect::Ref(r) => (r.to_string(), summary.mail_ref.to_string()),
        };
        Err(Error::MessageIdMismatch {
            uid: uid.get(),
            expected,
            found,
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
    open(store, folder, dry_run)?;
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
    let Some(header) = newest_with_id(store, folder, id)? else {
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

/// Selects `folder` and returns the newest mail whose `Message-ID` is exactly
/// `id` (the server's header search only matches substrings).
fn newest_with_id(
    store: &mut dyn MailStore,
    folder: &MailboxName,
    id: &MessageId,
) -> Result<Option<RawHeader>, Error> {
    store.select(folder)?;
    let candidates = store.find_message_id(id)?;
    Ok(store
        .headers(&candidates)?
        .into_iter()
        .filter(|h| model::summary_from_header(h).message_id.as_ref() == Some(id))
        .max_by_key(|h| h.uid))
}

/// Moves a mail to another folder of the same account, optionally marking it read first.
///
/// Servers without `MOVE` get a copy, which is confirmed in the target before
/// the original is marked `\Deleted` and removed: with `UIDPLUS` exactly this
/// mail (`UID EXPUNGE`), otherwise with a plain `EXPUNGE` only when no other
/// mail in the folder is marked.
///
/// # Errors
/// [`Error::FolderMissing`], [`Error::MoveUnsupported`],
/// [`Error::OthersMarkedDeleted`], [`Error::NotFound`],
/// [`Error::MessageIdMismatch`], [`Error::NotConfirmed`], [`Error::Partial`]
/// or server errors.
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
    let support = store.move_support()?;
    open(store, folder, dry_run)?;
    let mail = verify(store, uid, expect)?;
    // Without MOVE the copy is identified by Message-ID.
    let copy_id = match support {
        MoveSupport::Move => None,
        _ => Some(check_copy_fallback(
            store,
            folder,
            uid,
            mail.message_id.as_ref(),
            support,
        )?),
    };
    let mut confirmed = false;
    if !dry_run {
        if mark_read_first {
            store.add_flags(uid, &[FLAG_SEEN])?;
        }
        match copy_id {
            None => store.move_to(uid, target)?,
            Some(id) => {
                let flag = mark_read_first.then_some(FLAG_SEEN);
                move_by_copy(store, folder, uid, id, target, flag, support)?;
            }
        }
        // The source folder is selected again after the move.
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

/// Whether a mail can be moved without `MOVE`: its copy must be identifiable
/// by `Message-ID`, and without `UIDPLUS` no other mail in the folder may be
/// marked `\Deleted`, because a plain `EXPUNGE` would remove it too. The
/// mail's own mark, left by an interrupted attempt, does not count.
fn check_copy_fallback<'a>(
    store: &mut dyn MailStore,
    folder: &MailboxName,
    uid: Uid,
    id: Option<&'a MessageId>,
    support: MoveSupport,
) -> Result<&'a MessageId, Error> {
    let id = id.ok_or(Error::MoveUnsupported)?;
    if support == MoveSupport::CopyExpunge {
        let count = store
            .deleted_uids()?
            .into_iter()
            .filter(|&d| d != uid)
            .count();
        if count > 0 {
            return Err(Error::OthersMarkedDeleted {
                folder: folder.to_string(),
                count,
            });
        }
    }
    Ok(id)
}

/// Moves a mail on a server without `MOVE`. The original is only removed once
/// its own copy is confirmed in the target: a mail with this `Message-ID` that
/// was not there before the copy. An existing one is never taken as the copy,
/// because two different mails can share a `Message-ID` (a CC to oneself and
/// the list copy); a retry after an interruption leaves a duplicate instead.
fn move_by_copy(
    store: &mut dyn MailStore,
    folder: &MailboxName,
    uid: Uid,
    id: &MessageId,
    target: &MailboxName,
    flag: Option<&str>,
    support: MoveSupport,
) -> Result<(), Error> {
    // UIDs only grow within a folder, so the copy is newer than anything before.
    let before = newest_with_id(store, target, id)?.map(|h| h.uid);
    store.select(folder)?;
    store.copy_to(uid, target)?;
    let Some(copy) = newest_with_id(store, target, id)?.filter(|h| Some(h.uid) > before) else {
        return Err(Error::NotConfirmed(format!(
            "no new copy of {id} in {target}"
        )));
    };
    if let Some(flag) = flag
        && !has_flag(&copy.flags, flag)
    {
        return Err(Error::NotConfirmed(format!(
            "{flag} not set on the copy of {id} in {target}"
        )));
    }
    store.select(folder)?;
    store.add_flags(uid, &[FLAG_DELETED])?;
    if support == MoveSupport::CopyUidExpunge {
        return store.expunge_uid(uid);
    }
    // Checked before the copy; checked again right before EXPUNGE in case
    // another client marked a mail in between.
    let deleted = store.deleted_uids()?;
    if deleted != [uid] {
        store.remove_flags(uid, &[FLAG_DELETED])?;
        return Err(Error::Partial(format!(
            "copied to {target}, but the original stays in {folder}: another mail there was marked deleted meanwhile, so EXPUNGE would remove it too"
        )));
    }
    store.expunge_all_deleted()
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
        Some(sent) => copy_unless_filed(store, sent, job.new_message_id, bytes),
        None => Ok(()),
    };
    match (flagged, copied) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(e), Ok(())) | (Ok(()), Err(e)) => Err(e),
        (Err(flag), Err(copy)) => Err(Error::NotConfirmed(format!("{flag}; {copy}"))),
    }
}

/// Stores the copy in the sent folder, unless the SMTP server has filed one
/// there itself (as Gmail and Microsoft 365 do), and confirms it.
fn copy_unless_filed(
    store: &mut dyn MailStore,
    sent: &MailboxName,
    id: &MessageId,
    bytes: &[u8],
) -> Result<(), Error> {
    if newest_with_id(store, sent, id)?.is_some() {
        return Ok(());
    }
    store.append(sent, bytes, &[FLAG_SEEN])?;
    confirm_in_folder(store, sent, id, None)
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
    // SELECT even in a dry run: EXAMINE reports no permanent flags, and the
    // keyword check below must see the real ones.
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
