//! All decisions: listing, verifying and changing mail. Works on the traits from
//! [`crate::store`] only.

use serde::Serialize;

use crate::config::Config;
use crate::error::Error;
use crate::forward::{self, ForwardRequest};
use crate::model::{self, MailDetail, MailSummary};
use crate::store::{FLAG_FORWARDED, FLAG_SEEN, FolderInfo, MailSender, MailStore, RawHeader};
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
    store.select(folder)?;
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

fn has_flag(header: &RawHeader, flag: &str) -> bool {
    header.flags.iter().any(|f| f.eq_ignore_ascii_case(flag))
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
    store.select(folder)?;
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
        if !has_flag(&header_of(store, uid)?, FLAG_SEEN) {
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

fn confirm_in_folder(
    store: &mut dyn MailStore,
    folder: &MailboxName,
    id: &MessageId,
    required_flag: Option<&str>,
) -> Result<(), Error> {
    store.select(folder)?;
    let found = store.find_message_id(id)?;
    let Some(uid) = found.iter().max().copied() else {
        return Err(Error::NotConfirmed(format!("{id} not found in {folder}")));
    };
    if let Some(flag) = required_flag
        && !has_flag(&header_of(store, uid)?, flag)
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
        if let Some(id) = &mail.message_id {
            let flag = mark_read_first.then_some(FLAG_SEEN);
            confirm_in_folder(store, target, id, flag)?;
        } else {
            store.select(folder)?;
            if store.uids()?.contains(&uid) {
                return Err(Error::NotConfirmed(format!("UID {uid} still in {folder}")));
            }
        }
        confirmed = true;
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
    /// Sent folder for the copy.
    pub sent_folder: &'a MailboxName,
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
    let mut confirmed = false;
    if !job.dry_run {
        sender.send(job.from, job.to, &bytes)?;
        store.append(job.sent_folder, &bytes, &[FLAG_SEEN])?;
        store.add_flags(job.uid, &[FLAG_FORWARDED])?;
        if !has_flag(&header_of(store, job.uid)?, FLAG_FORWARDED) {
            return Err(Error::NotConfirmed(format!(
                "{FLAG_FORWARDED} not set on UID {}",
                job.uid
            )));
        }
        confirm_in_folder(store, job.sent_folder, job.new_message_id, None)?;
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
mod tests {
    use super::*;
    use crate::testing::{FakeSender, FakeStore, folder, mail, uid};
    use crate::types::MailRef;

    fn expect(id: &str) -> Result<Expect, Error> {
        Expect::parse(id)
    }

    #[test]
    fn lists_newest_first_with_paging() -> Result<(), Error> {
        let mut store = FakeStore::with_inbox(vec![
            mail(1, "a@x", "A", &[]),
            mail(5, "b@x", "B", &[]),
            mail(3, "c@x", "C", &[]),
        ]);
        let inbox = folder("INBOX")?;
        let all = list(&mut store, &inbox, 10, None)?;
        assert_eq!(
            all.iter().map(|m| m.uid.get()).collect::<Vec<_>>(),
            vec![5, 3, 1]
        );
        let page = list(&mut store, &inbox, 1, Some(uid(5)?))?;
        assert_eq!(
            page.iter().map(|m| m.uid.get()).collect::<Vec<_>>(),
            vec![3]
        );
        assert!(list(&mut store, &inbox, 10, Some(uid(1)?))?.is_empty());
        let mut seen = Vec::new();
        let n = list_each(&mut store, &inbox, 10, None, 0, &mut |m| {
            seen.push(m.uid.get());
            Ok(())
        })?;
        assert_eq!((n, seen), (3, vec![5, 3, 1]));
        let stop = list_each(&mut store, &inbox, 10, None, 2, &mut |_| {
            Err(Error::Store("stop".into()))
        });
        assert_eq!(stop, Err(Error::Store("stop".into())));
        assert!(list(&mut store, &folder("Missing")?, 10, None).is_err());
        assert_eq!(folders(&mut store)?.len(), 4);
        Ok(())
    }

    #[test]
    fn show_verifies_identity() -> Result<(), Error> {
        let mut store = FakeStore::with_inbox(vec![mail(2, "a@x", "Hello", &[])]);
        let inbox = folder("INBOX")?;
        let d = show(
            &mut store,
            &inbox,
            uid(2)?,
            Some(&expect("<m2@test>")?),
            100,
        )?;
        assert_eq!(d.summary.subject, "Hello");
        assert!(show(&mut store, &inbox, uid(2)?, None, 100).is_ok());
        assert!(matches!(
            show(
                &mut store,
                &inbox,
                uid(2)?,
                Some(&expect("other@test")?),
                100
            ),
            Err(Error::MessageIdMismatch { .. })
        ));
        assert_eq!(
            show(&mut store, &inbox, uid(9)?, None, 1),
            Err(Error::NotFound(9))
        );
        assert_eq!(
            show(&mut store, &inbox, uid(9)?, Some(&expect("m9@test")?), 1),
            Err(Error::NotFound(9))
        );
        Ok(())
    }

    #[test]
    fn mark_read_sets_and_confirms() -> Result<(), Error> {
        let mut store = FakeStore::with_inbox(vec![mail(2, "a@x", "S", &[])]);
        let inbox = folder("INBOX")?;
        let dry = mark_read(&mut store, &inbox, uid(2)?, &expect("m2@test")?, true)?;
        assert!(dry.dry_run && !dry.confirmed);
        assert!(!store.flags("INBOX", 2).contains(&FLAG_SEEN.to_owned()));
        let r = mark_read(&mut store, &inbox, uid(2)?, &expect("m2@test")?, false)?;
        assert!(r.confirmed);
        assert!(store.flags("INBOX", 2).contains(&FLAG_SEEN.to_owned()));
        store.ignore_flags = true;
        assert!(matches!(
            mark_read(
                &mut FakeStore {
                    ignore_flags: true,
                    ..FakeStore::with_inbox(vec![mail(2, "a@x", "S", &[])])
                },
                &inbox,
                uid(2)?,
                &expect("m2@test")?,
                false
            ),
            Err(Error::NotConfirmed(_))
        ));
        Ok(())
    }

    #[test]
    fn move_checks_everything() -> Result<(), Error> {
        let inbox = folder("INBOX")?;
        let target = folder("Work/GitHub")?;
        let mut store =
            FakeStore::with_inbox(vec![mail(2, "a@x", "S", &[]), mail(3, "b@x", "T", &[])]);
        let r = move_mail(
            &mut store,
            &inbox,
            uid(2)?,
            &expect("m2@test")?,
            &target,
            true,
            false,
        )?;
        assert!(r.confirmed);
        assert!(store.uids_of("INBOX").iter().all(|u| u.get() != 2));
        assert_eq!(store.uids_of("Work/GitHub").len(), 1);
        let dry = move_mail(
            &mut store,
            &inbox,
            uid(3)?,
            &expect("m3@test")?,
            &target,
            false,
            true,
        )?;
        assert!(dry.dry_run && !dry.confirmed && store.uids_of("INBOX").len() == 1);
        let plain = move_mail(
            &mut store,
            &inbox,
            uid(3)?,
            &expect("m3@test")?,
            &target,
            false,
            false,
        )?;
        assert!(plain.confirmed);
        assert_eq!(
            move_mail(
                &mut store,
                &inbox,
                uid(2)?,
                &expect("m2@test")?,
                &folder("Nope")?,
                false,
                false
            ),
            Err(Error::FolderMissing("Nope".into()))
        );
        assert_eq!(
            move_mail(
                &mut store,
                &inbox,
                uid(2)?,
                &expect("m2@test")?,
                &folder("Noselect")?,
                false,
                false
            ),
            Err(Error::FolderMissing("Noselect".into()))
        );
        let mut no_move = FakeStore {
            move_supported: false,
            ..FakeStore::with_inbox(vec![mail(2, "a@x", "S", &[])])
        };
        assert_eq!(
            move_mail(
                &mut no_move,
                &inbox,
                uid(2)?,
                &expect("m2@test")?,
                &target,
                false,
                false
            ),
            Err(Error::MoveUnsupported)
        );
        Ok(())
    }

    #[test]
    fn move_confirmation_failures() -> Result<(), Error> {
        let inbox = folder("INBOX")?;
        let target = folder("Work/GitHub")?;
        let mut lost = FakeStore {
            lose_moves: true,
            ..FakeStore::with_inbox(vec![mail(2, "a@x", "S", &[])])
        };
        assert!(matches!(
            move_mail(
                &mut lost,
                &inbox,
                uid(2)?,
                &expect("m2@test")?,
                &target,
                false,
                false
            ),
            Err(Error::NotConfirmed(_))
        ));
        let mut unflagged = FakeStore {
            ignore_flags: true,
            ..FakeStore::with_inbox(vec![mail(2, "a@x", "S", &[])])
        };
        assert!(matches!(
            move_mail(
                &mut unflagged,
                &inbox,
                uid(2)?,
                &expect("m2@test")?,
                &target,
                true,
                false
            ),
            Err(Error::NotConfirmed(_))
        ));
        // Mails without Message-ID are confirmed by their absence from the source folder.
        let no_id =
            FakeStore::raw_mail(4, b"From: z@x.de\r\nSubject: no id\r\n\r\nx".to_vec(), &[]);
        let r = MailRef::from_fallback("", "z@x.de", "no id", 33);
        let mut store = FakeStore::with_inbox(vec![no_id.clone()]);
        let ok = move_mail(
            &mut store,
            &inbox,
            uid(4)?,
            &Expect::Ref(r.clone()),
            &target,
            false,
            false,
        )?;
        assert!(ok.confirmed);
        let mut stuck = FakeStore {
            stuck_moves: true,
            ..FakeStore::with_inbox(vec![no_id])
        };
        assert!(matches!(
            move_mail(
                &mut stuck,
                &inbox,
                uid(4)?,
                &Expect::Ref(r),
                &target,
                false,
                false
            ),
            Err(Error::NotConfirmed(_))
        ));
        Ok(())
    }

    #[test]
    fn create_folder_paths() -> Result<(), Error> {
        let mut store = FakeStore::with_inbox(vec![]);
        let name = folder("Newsletters/New")?;
        assert!(create_folder(&mut store, &name, true)?.dry_run);
        assert!(create_folder(&mut store, &name, false)?.confirmed);
        assert_eq!(
            create_folder(&mut store, &name, false),
            Err(Error::FolderExists(name.to_string()))
        );
        let mut broken = FakeStore {
            ignore_creates: true,
            ..FakeStore::with_inbox(vec![])
        };
        assert!(matches!(
            create_folder(&mut broken, &name, false),
            Err(Error::NotConfirmed(_))
        ));
        Ok(())
    }

    #[test]
    fn forward_paths() -> Result<(), Error> {
        let config = crate::testing::config()?;
        let inbox = folder("INBOX")?;
        let sent = folder("Sent")?;
        let from = EmailAddress::parse("alice@example.com")?;
        let to = EmailAddress::parse("accounting@example.com")?;
        let new_id = MessageId::parse("fwd@mailctl")?;
        let exp = expect("m2@test")?;
        let job = ForwardJob {
            folder: &inbox,
            uid: uid(2)?,
            expect: &exp,
            to: &to,
            from: &from,
            sent_folder: &sent,
            new_message_id: &new_id,
            note: None,
            dry_run: true,
        };
        let mut store = FakeStore::with_inbox(vec![mail(2, "a@x", "Invoice", &[])]);
        let mut sender = FakeSender::default();
        assert!(forward(&mut store, &mut sender, &config, &job)?.dry_run);
        assert!(sender.sent.is_empty());
        let live = ForwardJob {
            dry_run: false,
            ..job.clone()
        };
        assert!(forward(&mut store, &mut sender, &config, &live)?.confirmed);
        assert_eq!(sender.sent.len(), 1);
        assert_eq!(store.uids_of("Sent").len(), 1);
        assert_eq!(
            forward(&mut store, &mut sender, &config, &live),
            Err(Error::AlreadyForwarded(2))
        );
        let stranger = EmailAddress::parse("x@y.de")?;
        let bad = ForwardJob {
            to: &stranger,
            ..live.clone()
        };
        assert_eq!(
            forward(&mut store, &mut sender, &config, &bad),
            Err(Error::ForwardNotAllowed("x@y.de".into()))
        );

        let mut no_body = FakeStore {
            hide_bodies: true,
            ..FakeStore::with_inbox(vec![mail(2, "a@x", "R", &[])])
        };
        assert_eq!(
            forward(&mut no_body, &mut sender, &config, &live),
            Err(Error::NotFound(2))
        );
        let mut unflagged = FakeStore {
            ignore_flags: true,
            ..FakeStore::with_inbox(vec![mail(2, "a@x", "R", &[])])
        };
        assert!(matches!(
            forward(&mut unflagged, &mut sender, &config, &live),
            Err(Error::NotConfirmed(_))
        ));
        let mut no_copy = FakeStore {
            lose_appends: true,
            ..FakeStore::with_inbox(vec![mail(2, "a@x", "R", &[])])
        };
        assert!(matches!(
            forward(&mut no_copy, &mut sender, &config, &live),
            Err(Error::NotConfirmed(_))
        ));
        let mut failing = FakeSender {
            fail: true,
            ..FakeSender::default()
        };
        let mut fresh = FakeStore::with_inbox(vec![mail(2, "a@x", "R", &[])]);
        assert!(matches!(
            forward(&mut fresh, &mut failing, &config, &live),
            Err(Error::Send(_))
        ));
        Ok(())
    }

    #[test]
    fn mismatch_reports_ref_for_mails_without_id() -> Result<(), Error> {
        let no_id = FakeStore::raw_mail(4, b"From: z@x.de\r\n\r\nx".to_vec(), &[]);
        let mut store = FakeStore::with_inbox(vec![no_id]);
        let err = mark_read(
            &mut store,
            &folder("INBOX")?,
            uid(4)?,
            &Expect::Ref(MailRef::parse("0000000000")?),
            false,
        );
        assert!(
            matches!(err, Err(Error::MessageIdMismatch { expected, .. }) if expected == "0000000000")
        );
        Ok(())
    }
}
