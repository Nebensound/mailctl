//! Tests for `service`.

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
