//! Tests for `cache`.

use std::cell::RefCell;
use std::rc::Rc;

use super::*;
use crate::store::FLAG_DELETED;
use crate::testing::{FakeStore, Shared, folder, mail, uid};

#[test]
fn lists_folders_and_capabilities_once_per_connection() -> Result<(), Error> {
    let fake = Rc::new(RefCell::new(FakeStore::with_inbox(vec![
        mail(2, "a@x", "A", &[]),
        mail(3, "b@x", "B", &[]),
    ])));
    let mut shared = Shared(Rc::clone(&fake));
    let mut store = CachedStore::new(&mut shared);
    let target = folder("Work/GitHub")?;
    for n in [2, 3] {
        let expect = crate::types::Expect::parse(&format!("m{n}@test"))?;
        crate::service::move_mail(
            &mut store,
            &folder("INBOX")?,
            uid(n)?,
            &expect,
            &target,
            false,
            false,
        )?;
    }
    let calls_for_two = fake.borrow().calls.get();
    // A third move needs no LIST and no CAPABILITY.
    fake.borrow_mut()
        .folders
        .entry("INBOX".into())
        .or_default()
        .push(mail(4, "c@x", "C", &[]));
    let before = fake.borrow().calls.get();
    crate::service::move_mail(
        &mut store,
        &folder("INBOX")?,
        uid(4)?,
        &crate::types::Expect::parse("m4@test")?,
        &target,
        false,
        false,
    )?;
    let per_move = fake.borrow().calls.get().saturating_sub(before);
    assert_eq!(
        calls_for_two,
        2 * per_move + 2,
        "LIST and CAPABILITY only once"
    );
    Ok(())
}

#[test]
fn a_new_folder_is_seen_at_once() -> Result<(), Error> {
    let mut inner = FakeStore::with_inbox(Vec::new());
    let mut store = CachedStore::new(&mut inner);
    let new = folder("New")?;
    assert!(!store.folders()?.iter().any(|f| f.name == new));
    store.create_folder(&new)?;
    assert!(store.folders()?.iter().any(|f| f.name == new));
    Ok(())
}

#[test]
fn passes_everything_else_through() -> Result<(), Error> {
    let mut inner = FakeStore::with_inbox(vec![mail(2, "a@x", "A", &[])]);
    let mut store = CachedStore::new(&mut inner);
    let inbox = folder("INBOX")?;
    store.select_read_only(&inbox)?;
    store.select(&inbox)?;
    assert!(store.keywords_allowed()?);
    assert_eq!(store.uids()?, vec![uid(2)?]);
    assert_eq!(store.headers(&[uid(2)?])?.len(), 1);
    assert!(store.message(uid(2)?)?.is_some());
    store.add_flags(uid(2)?, &["\\Seen"])?;
    assert_eq!(
        store.find_message_id(&MessageId::parse("m2@test")?)?,
        vec![uid(2)?]
    );
    store.append(&folder("Sent")?, b"Message-ID: <x@y>\r\n\r\nx", &[])?;
    assert_eq!(store.move_support()?, MoveSupport::Move);
    // Second call comes from the cache: a failing inner store is not asked.
    assert_eq!(store.move_support()?, MoveSupport::Move);
    store.remove_flags(uid(2)?, &["\\Seen"])?;
    store.copy_to(uid(2)?, &folder("Sent")?)?;
    store.add_flags(uid(2)?, &[FLAG_DELETED])?;
    assert_eq!(store.deleted_uids()?, vec![uid(2)?]);
    store.expunge_uid(uid(2)?)?;
    store.expunge_all_deleted()?;
    assert!(store.uids()?.is_empty());
    assert_eq!(
        store.move_to(uid(2)?, &folder("Sent")?),
        Err(Error::NotFound(2))
    );
    Ok(())
}

#[test]
fn assumed_folders_are_listed_until_the_end() -> Result<(), Error> {
    let mut inner = FakeStore::with_inbox(Vec::new());
    let mut store = CachedStore::new(&mut inner);
    let planned = folder("Invoices")?;
    store.assume_folder(&planned);
    assert!(store.folders()?.iter().any(|f| f.name == planned));
    // Also after the real list was reloaded.
    store.create_folder(&folder("Other")?)?;
    let names: Vec<String> = store
        .folders()?
        .iter()
        .map(|f| f.name.to_string())
        .collect();
    assert!(names.contains(&"Invoices".to_owned()) && names.contains(&"Other".to_owned()));
    Ok(())
}
