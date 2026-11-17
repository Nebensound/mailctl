//! Tests for `service`.

use super::*;
use std::cell::RefCell;
use std::rc::Rc;

use crate::testing::{FakeSender, FakeStore, Shared, folder, mail, uid};
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
    let mut store = FakeStore::with_inbox(vec![mail(2, "a@x", "S", &[]), mail(3, "b@x", "T", &[])]);
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
    // Mails without Message-ID leave the source folder, but cannot be found
    // again in the target: the move is done, not confirmed.
    let no_id = FakeStore::raw_mail(4, b"From: z@x.de\r\nSubject: no id\r\n\r\nx".to_vec(), &[]);
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
    assert!(!ok.confirmed);
    assert_eq!(store.uids_of("Work/GitHub").len(), 1);
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
        sent_folder: Some(&sent),
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
        Err(Error::Partial(m)) if m.contains("not confirmed")
    ));
    let mut no_copy = FakeStore {
        lose_appends: true,
        ..FakeStore::with_inbox(vec![mail(2, "a@x", "R", &[])])
    };
    assert!(matches!(
        forward(&mut no_copy, &mut sender, &config, &live),
        Err(Error::Partial(m)) if m.contains("not confirmed")
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

/// Runs `operation` against a fresh store whose n-th server call fails, for
/// n = 0, 1, … until the operation needs fewer calls than that. Every run
/// before must end in exactly that server error, and must not report success.
fn fails_cleanly_at_every_call(
    fresh: &dyn Fn() -> FakeStore,
    operation: &dyn Fn(&mut FakeStore) -> Result<(), Error>,
) -> Result<usize, Error> {
    for call in 0..64 {
        let mut store = fresh();
        store.fail_at_call = Some(call);
        match operation(&mut store) {
            Ok(()) => return Ok(call),
            Err(Error::Store(message)) if message == "simulated failure" => {}
            // After a forward went out, failures are reported as partly done.
            Err(Error::Partial(message)) if message.ends_with("mail server: simulated failure") => {
            }
            Err(other) => return Err(other),
        }
    }
    Err(Error::Store("operation never finished".into()))
}

#[test]
fn every_server_failure_aborts_the_operation() -> Result<(), Error> {
    let config = crate::testing::config()?;
    let inbox = folder("INBOX")?;
    let target = folder("Work/GitHub")?;
    let sent = folder("Sent")?;
    let new = folder("New")?;
    let from = EmailAddress::parse("alice@example.com")?;
    let to = EmailAddress::parse("accounting@example.com")?;
    let new_id = MessageId::parse("fwd@mailctl")?;
    let by_id = expect("m2@test")?;
    let fresh = || FakeStore::with_inbox(vec![mail(2, "a@x", "Invoice", &[])]);
    let no_id = FakeStore::raw_mail(4, b"From: z@x.de\r\nSubject: s\r\n\r\nx".to_vec(), &[]);
    let without_id = || FakeStore::with_inbox(vec![no_id.clone()]);
    let by_ref = Expect::Ref(
        list(&mut without_id(), &inbox, 1, None)?
            .first()
            .ok_or(Error::NotFound(4))?
            .mail_ref
            .clone(),
    );

    let calls = [
        fails_cleanly_at_every_call(&fresh, &|s| list(s, &inbox, 10, None).map(drop))?,
        fails_cleanly_at_every_call(&fresh, &|s| {
            show(s, &inbox, uid(2)?, Some(&by_id), 100).map(drop)
        })?,
        fails_cleanly_at_every_call(&fresh, &|s| {
            mark_read(s, &inbox, uid(2)?, &by_id, false).map(drop)
        })?,
        fails_cleanly_at_every_call(&fresh, &|s| {
            move_mail(s, &inbox, uid(2)?, &by_id, &target, true, false).map(drop)
        })?,
        fails_cleanly_at_every_call(&without_id, &|s| {
            move_mail(s, &inbox, uid(4)?, &by_ref, &target, false, false).map(drop)
        })?,
        fails_cleanly_at_every_call(&fresh, &|s| create_folder(s, &new, false).map(drop))?,
        fails_cleanly_at_every_call(&fresh, &|s| {
            let job = ForwardJob {
                folder: &inbox,
                uid: uid(2)?,
                expect: &by_id,
                to: &to,
                from: &from,
                sent_folder: Some(&sent),
                new_message_id: &new_id,
                note: None,
                dry_run: false,
            };
            forward(s, &mut FakeSender::default(), &config, &job).map(drop)
        })?,
    ];
    // list: select, uids, headers; show: select, headers, message; mark_read:
    // select, headers, flag, headers; move: folders, capability, select,
    // headers, (flag,) move, headers of the UID, and with a Message-ID
    // select, search, headers; create: folders, create, folders; forward: select,
    // headers, keywords, message, folders, the newest UID in Sent (select,
    // uids) and select again, flag, headers, then in Sent the newer mails
    // (select, uids, headers) and the search (select, search, headers) for a
    // copy filed by the server, append, and the newer mails again.
    assert_eq!(calls, [3, 3, 4, 10, 6, 3, 20]);
    Ok(())
}

#[test]
fn forward_refuses_originals_it_cannot_rebuild() -> Result<(), Error> {
    let config = crate::testing::config()?;
    let inbox = folder("INBOX")?;
    let sent = folder("Sent")?;
    let from = EmailAddress::parse("alice@example.com")?;
    let to = EmailAddress::parse("accounting@example.com")?;
    let new_id = MessageId::parse("fwd@mailctl")?;
    let by_id = expect("m3@test")?;
    let odd = FakeStore::raw_mail(
        3,
        b"Message-ID: <m3@test>\r\nSubject: odd\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: application/pdf@x\r\nContent-Disposition: attachment; filename=a.pdf\r\n\r\nxx\r\n--b--\r\n".to_vec(),
        &[],
    );
    let mut store = FakeStore::with_inbox(vec![odd]);
    let before = store.snapshot();
    let mut sender = FakeSender::default();
    let job = ForwardJob {
        folder: &inbox,
        uid: uid(3)?,
        expect: &by_id,
        to: &to,
        from: &from,
        sent_folder: Some(&sent),
        new_message_id: &new_id,
        note: None,
        dry_run: false,
    };
    assert!(matches!(
        forward(&mut store, &mut sender, &config, &job),
        Err(Error::InvalidInput(_))
    ));
    assert!(sender.sent.is_empty());
    assert_eq!(store.snapshot(), before);
    Ok(())
}

#[test]
fn failed_sent_copy_does_not_allow_a_second_forward() -> Result<(), Error> {
    let config = crate::testing::config()?;
    let inbox = folder("INBOX")?;
    let sent = folder("Sent")?;
    let from = EmailAddress::parse("alice@example.com")?;
    let to = EmailAddress::parse("accounting@example.com")?;
    let new_id = MessageId::parse("fwd@mailctl")?;
    let by_id = expect("m2@test")?;
    let job = ForwardJob {
        folder: &inbox,
        uid: uid(2)?,
        expect: &by_id,
        to: &to,
        from: &from,
        sent_folder: Some(&sent),
        new_message_id: &new_id,
        note: None,
        dry_run: false,
    };
    // Calls: select, headers, keywords, message, folders, then the sent
    // folder's newest UID (select, uids) and select again; after sending:
    // flag, headers, then the copy check (select, uids, headers, select,
    // search, headers) and append (fails).
    let mut store = FakeStore {
        fail_at_call: Some(16),
        ..FakeStore::with_inbox(vec![mail(2, "a@x", "Invoice", &[])])
    };
    let mut sender = FakeSender::default();
    let first = forward(&mut store, &mut sender, &config, &job);
    assert!(
        matches!(&first, Err(Error::Partial(m)) if m.contains("was forwarded")),
        "{first:?}"
    );
    assert_eq!(store.flags("INBOX", 2), vec![FLAG_FORWARDED.to_owned()]);
    assert_eq!(
        forward(&mut store, &mut sender, &config, &job),
        Err(Error::AlreadyForwarded(2))
    );
    assert_eq!(sender.sent.len(), 1);
    Ok(())
}

#[test]
fn confirmation_compares_the_message_id_exactly() -> Result<(), Error> {
    // `1m2@test` contains `m2@test`: a header search finds it, but it is not
    // the moved mail. The move is lost, so it must not be confirmed.
    let lookalike = FakeStore::raw_mail(
        50,
        b"Message-ID: <1m2@test>\r\nSubject: other\r\n\r\nx".to_vec(),
        &[],
    );
    let mut store = FakeStore {
        lose_moves: true,
        ..FakeStore::with_inbox(vec![mail(2, "a@x", "Invoice", &[])])
    };
    store
        .folders
        .get_mut("Work/GitHub")
        .ok_or(Error::NotFound(0))?
        .push(lookalike);
    let result = move_mail(
        &mut store,
        &folder("INBOX")?,
        uid(2)?,
        &expect("m2@test")?,
        &folder("Work/GitHub")?,
        false,
        false,
    );
    assert!(
        matches!(&result, Err(Error::NotConfirmed(m)) if m.contains("not found")),
        "{result:?}"
    );
    Ok(())
}

fn forward_job_parts() -> Result<
    (
        MailboxName,
        MailboxName,
        EmailAddress,
        EmailAddress,
        MessageId,
        Expect,
    ),
    Error,
> {
    Ok((
        folder("INBOX")?,
        folder("Sent")?,
        EmailAddress::parse("alice@example.com")?,
        EmailAddress::parse("accounting@example.com")?,
        MessageId::parse("fwd@mailctl")?,
        expect("m2@test")?,
    ))
}

#[test]
fn forward_checks_before_sending() -> Result<(), Error> {
    let config = crate::testing::config()?;
    let (inbox, sent, from, to, new_id, by_id) = forward_job_parts()?;
    let missing = folder("Sent Messages")?;
    for dry_run in [true, false] {
        let job = ForwardJob {
            folder: &inbox,
            uid: uid(2)?,
            expect: &by_id,
            to: &to,
            from: &from,
            sent_folder: Some(&missing),
            new_message_id: &new_id,
            note: None,
            dry_run,
        };
        let mut store = FakeStore::with_inbox(vec![mail(2, "a@x", "Invoice", &[])]);
        let mut sender = FakeSender::default();
        assert_eq!(
            forward(&mut store, &mut sender, &config, &job),
            Err(Error::FolderMissing("Sent Messages".into())),
            "dry run: {dry_run}"
        );
        assert!(sender.sent.is_empty());

        // A server that forgets $Forwarded could not stop a second forward.
        let job = ForwardJob {
            sent_folder: Some(&sent),
            ..job
        };
        let mut forgetful = FakeStore {
            no_keywords: true,
            ..FakeStore::with_inbox(vec![mail(2, "a@x", "Invoice", &[])])
        };
        assert_eq!(
            forward(&mut forgetful, &mut sender, &config, &job),
            Err(Error::KeywordsUnsupported("INBOX".into()))
        );
        assert!(sender.sent.is_empty());
        assert_eq!(forgetful.mutations, 0);
    }
    Ok(())
}

#[test]
fn the_sent_copy_does_not_depend_on_the_flag() -> Result<(), Error> {
    let config = crate::testing::config()?;
    let (inbox, sent, from, to, new_id, by_id) = forward_job_parts()?;
    let job = ForwardJob {
        folder: &inbox,
        uid: uid(2)?,
        expect: &by_id,
        to: &to,
        from: &from,
        sent_folder: Some(&sent),
        new_message_id: &new_id,
        note: None,
        dry_run: false,
    };
    // The flag is accepted but not kept; the copy is still stored.
    let mut unflagged = FakeStore {
        ignore_flags: true,
        ..FakeStore::with_inbox(vec![mail(2, "a@x", "R", &[])])
    };
    let result = forward(&mut unflagged, &mut FakeSender::default(), &config, &job);
    assert!(
        matches!(&result, Err(Error::Partial(m)) if m.contains("$Forwarded not set")),
        "{result:?}"
    );
    assert_eq!(unflagged.uids_of("Sent").len(), 1);

    // Both steps fail: both are reported.
    let mut neither = FakeStore {
        ignore_flags: true,
        lose_appends: true,
        ..FakeStore::with_inbox(vec![mail(2, "a@x", "R", &[])])
    };
    let result = forward(&mut neither, &mut FakeSender::default(), &config, &job);
    assert!(
        matches!(&result, Err(Error::Partial(m)) if m.contains("$Forwarded not set") && m.contains("not found in Sent")),
        "{result:?}"
    );
    Ok(())
}

#[test]
fn no_own_copy_where_the_server_files_sent_mail() -> Result<(), Error> {
    let config = crate::testing::config()?;
    let (inbox, _, from, to, new_id, by_id) = forward_job_parts()?;
    let job = ForwardJob {
        folder: &inbox,
        uid: uid(2)?,
        expect: &by_id,
        to: &to,
        from: &from,
        sent_folder: None,
        new_message_id: &new_id,
        note: None,
        dry_run: false,
    };
    let mut store = FakeStore::with_inbox(vec![mail(2, "a@x", "Invoice", &[])]);
    store.folders.remove("Sent");
    let mut sender = FakeSender::default();
    assert!(forward(&mut store, &mut sender, &config, &job)?.confirmed);
    assert_eq!(sender.sent.len(), 1);
    assert_eq!(store.flags("INBOX", 2), vec![FLAG_FORWARDED.to_owned()]);
    Ok(())
}

#[test]
fn reading_examines_instead_of_selecting() -> Result<(), Error> {
    let mut store = FakeStore::with_inbox(vec![mail(2, "a@x", "Invoice", &[])]);
    let inbox = folder("INBOX")?;
    list(&mut store, &inbox, 10, None)?;
    assert!(store.read_only, "list must not open the folder read-write");
    store.read_only = false;
    show(&mut store, &inbox, uid(2)?, None, 10)?;
    assert!(store.read_only, "show must not open the folder read-write");
    Ok(())
}

#[test]
fn mismatches_report_the_same_kind_of_value() -> Result<(), Error> {
    let inbox = folder("INBOX")?;
    let mut store = FakeStore::with_inbox(vec![
        mail(2, "a@x", "Invoice", &[]),
        FakeStore::raw_mail(3, b"From: z@x.de\r\nSubject: s\r\n\r\nx".to_vec(), &[]),
    ]);
    let listed = list(&mut store, &inbox, 10, None)?;
    let ref_of = |n: u32| {
        listed
            .iter()
            .find(|m| m.uid.get() == n)
            .map(|m| m.mail_ref.to_string())
            .unwrap_or_default()
    };
    let stale = Expect::parse("0123456789")?;
    assert_eq!(
        mark_read(&mut store, &inbox, uid(2)?, &stale, true),
        Err(Error::MessageIdMismatch {
            uid: 2,
            expected: "0123456789".into(),
            found: ref_of(2),
        })
    );
    assert_eq!(
        mark_read(&mut store, &inbox, uid(3)?, &expect("m2@test")?, true),
        Err(Error::MessageIdMismatch {
            uid: 3,
            expected: "m2@test".into(),
            found: "no Message-ID".into(),
        })
    );
    Ok(())
}

#[test]
fn a_copy_the_server_filed_itself_is_not_stored_again() -> Result<(), Error> {
    let config = crate::testing::config()?;
    let (inbox, sent, from, to, new_id, by_id) = forward_job_parts()?;
    let job = ForwardJob {
        folder: &inbox,
        uid: uid(2)?,
        expect: &by_id,
        to: &to,
        from: &from,
        sent_folder: Some(&sent),
        new_message_id: &new_id,
        note: None,
        dry_run: false,
    };
    let mut store = FakeStore::with_inbox(vec![mail(2, "a@x", "Invoice", &[])]);
    // What a server that files submissions itself leaves in Sent.
    store
        .folders
        .entry("Sent".into())
        .or_default()
        .push(FakeStore::raw_mail(
            90,
            b"Message-ID: <fwd@mailctl>\r\nSubject: Fwd: Invoice\r\n\r\nx".to_vec(),
            &[],
        ));
    let report = forward(&mut store, &mut FakeSender::default(), &config, &job)?;
    assert!(report.confirmed);
    assert_eq!(store.uids_of("Sent").len(), 1);
    Ok(())
}

#[test]
fn forward_confirms_the_sent_copy_where_the_header_search_finds_nothing() -> Result<(), Error> {
    // iCloud: `SEARCH HEADER Message-ID` never matches.
    let config = crate::testing::config()?;
    let (inbox, sent, from, to, new_id, by_id) = forward_job_parts()?;
    let job = ForwardJob {
        folder: &inbox,
        uid: uid(2)?,
        expect: &by_id,
        to: &to,
        from: &from,
        sent_folder: Some(&sent),
        new_message_id: &new_id,
        note: None,
        dry_run: false,
    };
    let mut store = FakeStore {
        no_header_search: true,
        ..FakeStore::with_inbox(vec![mail(2, "a@x", "Invoice", &[])])
    };
    // An older mail in Sent: the copy must be found above it.
    store.append(&sent, b"Message-ID: <old@x>\r\nSubject: old\r\n\r\nx", &[])?;
    let report = forward(&mut store, &mut FakeSender::default(), &config, &job)?;
    assert!(report.confirmed);
    assert_eq!(store.uids_of("Sent").len(), 2);
    assert_eq!(store.flags("INBOX", 2), vec![FLAG_FORWARDED.to_owned()]);
    Ok(())
}

#[test]
fn a_filed_copy_is_found_without_the_header_search() -> Result<(), Error> {
    // The SMTP server files the submission itself, and the IMAP server's
    // header search never matches: the copy is still found by its new UID.
    let config = crate::testing::config()?;
    let (inbox, sent, from, to, new_id, by_id) = forward_job_parts()?;
    let job = ForwardJob {
        folder: &inbox,
        uid: uid(2)?,
        expect: &by_id,
        to: &to,
        from: &from,
        sent_folder: Some(&sent),
        new_message_id: &new_id,
        note: None,
        dry_run: false,
    };
    let shared = Rc::new(RefCell::new(FakeStore {
        no_header_search: true,
        ..FakeStore::with_inbox(vec![mail(2, "a@x", "Invoice", &[])])
    }));
    let mut sender = FakeSender {
        files_into: Some((Rc::clone(&shared), sent.clone())),
        ..FakeSender::default()
    };
    let report = forward(&mut Shared(Rc::clone(&shared)), &mut sender, &config, &job)?;
    assert!(report.confirmed);
    assert_eq!(shared.borrow().uids_of("Sent").len(), 1, "no second copy");
    Ok(())
}

#[test]
fn dry_runs_examine_instead_of_selecting() -> Result<(), Error> {
    let inbox = folder("INBOX")?;
    let mut store = FakeStore::with_inbox(vec![mail(2, "a@x", "Invoice", &[])]);
    mark_read(&mut store, &inbox, uid(2)?, &expect("m2@test")?, true)?;
    assert!(
        store.read_only,
        "mark_read --dry-run must not open read-write"
    );
    store.read_only = false;
    move_mail(
        &mut store,
        &inbox,
        uid(2)?,
        &expect("m2@test")?,
        &folder("Work/GitHub")?,
        true,
        true,
    )?;
    assert!(store.read_only, "move --dry-run must not open read-write");
    store.read_only = false;
    mark_read(&mut store, &inbox, uid(2)?, &expect("m2@test")?, false)?;
    assert!(!store.read_only, "a real change needs SELECT");
    Ok(())
}

#[test]
fn moves_into_the_inbox_however_it_is_spelled() -> Result<(), Error> {
    let mut store = FakeStore::with_inbox(Vec::new());
    store
        .folders
        .entry("Work/GitHub".into())
        .or_default()
        .push(mail(7, "a@x", "Back", &[]));
    let report = move_mail(
        &mut store,
        &folder("Work/GitHub")?,
        uid(7)?,
        &expect("m7@test")?,
        &folder("inbox")?,
        false,
        false,
    )?;
    assert!(report.confirmed);
    assert_eq!(store.uids_of("INBOX").len(), 1);
    assert_eq!(
        create_folder(&mut store, &folder("Inbox")?, true),
        Err(Error::FolderExists("INBOX".into()))
    );
    Ok(())
}

/// INBOX with mail 2 to move and mail 3 already marked `\Deleted` by another client.
fn no_move_store(support: MoveSupport, deleted_neighbour: bool) -> FakeStore {
    let neighbour: &[&str] = if deleted_neighbour {
        &[FLAG_DELETED]
    } else {
        &[]
    };
    FakeStore {
        move_support: support,
        ..FakeStore::with_inbox(vec![
            mail(2, "a@x", "S", &[]),
            mail(3, "b@x", "T", neighbour),
        ])
    }
}

fn move_two(store: &mut FakeStore, mark_read: bool, dry_run: bool) -> Result<ActionReport, Error> {
    move_mail(
        store,
        &folder("INBOX")?,
        uid(2)?,
        &expect("m2@test")?,
        &folder("Work/GitHub")?,
        mark_read,
        dry_run,
    )
}

#[test]
fn uidplus_moves_by_copy_and_removes_only_this_mail() -> Result<(), Error> {
    let mut store = no_move_store(MoveSupport::CopyUidExpunge, true);
    let report = move_two(&mut store, true, false)?;
    assert!(report.confirmed);
    // Mail 3 was marked deleted by someone else and must survive.
    assert_eq!(store.uids_of("INBOX"), vec![uid(3)?]);
    assert_eq!(store.flags("INBOX", 3), vec![FLAG_DELETED.to_owned()]);
    let filed = store.uids_of("Work/GitHub");
    assert_eq!(filed.len(), 1);
    let copy = filed.first().map_or(0, |u| u.get());
    assert_eq!(store.flags("Work/GitHub", copy), vec![FLAG_SEEN.to_owned()]);
    Ok(())
}

#[test]
fn without_uidplus_moves_when_no_other_mail_is_marked() -> Result<(), Error> {
    let mut store = no_move_store(MoveSupport::CopyExpunge, false);
    assert!(move_two(&mut store, false, false)?.confirmed);
    assert_eq!(store.uids_of("INBOX"), vec![uid(3)?]);
    assert_eq!(store.uids_of("Work/GitHub").len(), 1);
    Ok(())
}

#[test]
fn moves_without_move_where_the_header_search_finds_nothing() -> Result<(), Error> {
    // iCloud: no MOVE, and `SEARCH HEADER Message-ID` never matches.
    for support in [MoveSupport::CopyUidExpunge, MoveSupport::CopyExpunge] {
        let mut store = FakeStore {
            no_header_search: true,
            ..no_move_store(support, false)
        };
        assert!(move_two(&mut store, true, false)?.confirmed, "{support:?}");
        assert_eq!(store.uids_of("INBOX"), vec![uid(3)?]);
        let filed = store.uids_of("Work/GitHub");
        assert_eq!(filed.len(), 1);
        let copy = filed.first().map_or(0, |u| u.get());
        assert_eq!(store.flags("Work/GitHub", copy), vec![FLAG_SEEN.to_owned()]);
    }
    Ok(())
}

#[test]
fn without_uidplus_refuses_when_other_mails_are_marked() {
    for dry_run in [true, false] {
        let mut store = no_move_store(MoveSupport::CopyExpunge, true);
        let before = store.snapshot();
        assert_eq!(
            move_two(&mut store, false, dry_run),
            Err(Error::OthersMarkedDeleted {
                folder: "INBOX".into(),
                count: 1
            })
        );
        assert_eq!(store.snapshot(), before, "nothing may change");
    }
}

#[test]
fn without_uidplus_a_mark_set_meanwhile_keeps_the_original() -> Result<(), Error> {
    let mut store = FakeStore {
        race_deleted: Some(3),
        ..no_move_store(MoveSupport::CopyExpunge, false)
    };
    let result = move_two(&mut store, false, false);
    assert!(matches!(result, Err(Error::Partial(m)) if m.contains("another mail")));
    // Both mails are still in INBOX; our own \Deleted mark is taken back.
    assert_eq!(store.uids_of("INBOX"), vec![uid(2)?, uid(3)?]);
    assert!(store.flags("INBOX", 2).is_empty());
    assert_eq!(store.uids_of("Work/GitHub").len(), 1);
    Ok(())
}

#[test]
fn an_unconfirmed_copy_leaves_the_original_untouched() {
    for support in [MoveSupport::CopyUidExpunge, MoveSupport::CopyExpunge] {
        let mut store = FakeStore {
            lose_copies: true,
            ..no_move_store(support, false)
        };
        let before = store.snapshot();
        assert!(matches!(
            move_two(&mut store, false, false),
            Err(Error::NotConfirmed(_))
        ));
        assert_eq!(store.snapshot(), before);
    }
}

#[test]
fn a_retry_after_an_interruption_copies_again_and_finishes() -> Result<(), Error> {
    // The earlier attempt copied and marked the original, then the connection
    // dropped before EXPUNGE. Its own mark must not block the retry.
    let mut store = FakeStore {
        move_support: MoveSupport::CopyExpunge,
        ..FakeStore::with_inbox(vec![
            mail(2, "a@x", "S", &[FLAG_DELETED]),
            mail(3, "b@x", "T", &[]),
        ])
    };
    store.select(&folder("INBOX")?)?;
    store.copy_to(uid(2)?, &folder("Work/GitHub")?)?;
    assert!(move_two(&mut store, false, false)?.confirmed);
    assert_eq!(store.uids_of("INBOX"), vec![uid(3)?]);
    // A duplicate is harmless; a lost mail would not be.
    assert_eq!(store.uids_of("Work/GitHub").len(), 2);
    Ok(())
}

#[test]
fn two_mails_with_the_same_message_id_both_keep_a_copy() -> Result<(), Error> {
    // A CC to oneself and the mailing-list copy share one Message-ID.
    let cc = FakeStore::raw_mail(
        2,
        b"Message-ID: <same@x>\r\nFrom: a@x\r\nSubject: S\r\n\r\ndirect".to_vec(),
        &[],
    );
    let list = FakeStore::raw_mail(
        3,
        b"Message-ID: <same@x>\r\nFrom: a@x\r\nSubject: [list] S\r\n\r\nlist footer".to_vec(),
        &[],
    );
    for support in [MoveSupport::CopyUidExpunge, MoveSupport::CopyExpunge] {
        let mut store = FakeStore {
            move_support: support,
            ..FakeStore::with_inbox(vec![cc.clone(), list.clone()])
        };
        for n in [2, 3] {
            move_mail(
                &mut store,
                &folder("INBOX")?,
                uid(n)?,
                &expect("same@x")?,
                &folder("Work/GitHub")?,
                false,
                false,
            )?;
        }
        assert!(store.uids_of("INBOX").is_empty());
        let bodies: Vec<String> = store
            .snapshot()
            .into_iter()
            .filter(|(name, _)| name == "Work/GitHub")
            .flat_map(|(_, mails)| mails)
            .map(|(_, _, body)| String::from_utf8_lossy(&body).into_owned())
            .collect();
        assert_eq!(bodies.len(), 2, "{support:?}");
        assert!(bodies.iter().any(|b| b.ends_with("direct")));
        assert!(bodies.iter().any(|b| b.ends_with("list footer")));
    }
    Ok(())
}

#[test]
fn a_copy_without_the_read_mark_keeps_the_original() -> Result<(), Error> {
    let mut store = FakeStore {
        ignore_flags: true,
        ..no_move_store(MoveSupport::CopyUidExpunge, false)
    };
    let result = move_two(&mut store, true, false);
    assert!(matches!(result, Err(Error::NotConfirmed(m)) if m.contains("not set on the copy")));
    assert_eq!(store.uids_of("INBOX"), vec![uid(2)?, uid(3)?]);
    Ok(())
}

#[test]
fn without_move_a_mail_without_message_id_is_refused() -> Result<(), Error> {
    let no_id = FakeStore::raw_mail(4, b"From: z@x.de\r\nSubject: no id\r\n\r\nx".to_vec(), &[]);
    let r = MailRef::from_fallback("", "z@x.de", "no id", 33);
    for dry_run in [true, false] {
        let mut store = FakeStore {
            move_support: MoveSupport::CopyUidExpunge,
            ..FakeStore::with_inbox(vec![no_id.clone()])
        };
        let before = store.snapshot();
        assert_eq!(
            move_mail(
                &mut store,
                &folder("INBOX")?,
                uid(4)?,
                &Expect::Ref(r.clone()),
                &folder("Work/GitHub")?,
                false,
                dry_run,
            ),
            Err(Error::MoveUnsupported)
        );
        assert_eq!(store.snapshot(), before);
    }
    Ok(())
}

#[test]
fn every_server_failure_aborts_a_move_without_move() -> Result<(), Error> {
    for support in [MoveSupport::CopyUidExpunge, MoveSupport::CopyExpunge] {
        let calls = fails_cleanly_at_every_call(&|| no_move_store(support, false), &|store| {
            move_two(store, true, false).map(|_| ())
        })?;
        assert!(calls > 10, "{support:?}: {calls}");
    }
    // The race path, too: removing our own mark again can fail.
    let calls = fails_cleanly_at_every_call(
        &|| FakeStore {
            race_deleted: Some(3),
            ..no_move_store(MoveSupport::CopyExpunge, false)
        },
        &|store| match move_two(store, false, false) {
            Err(Error::Partial(m)) if m.contains("another mail") => Ok(()),
            other => other.map(|_| ()),
        },
    )?;
    assert!(calls > 10);
    Ok(())
}
