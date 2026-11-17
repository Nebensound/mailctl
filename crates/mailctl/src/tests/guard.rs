//! Tests for `guard`.

use std::cell::RefCell;
use std::rc::Rc;

use super::*;
use crate::testing::{FakeStore, Shared, folder, mail, uid};

fn guarded(access: Access) -> (GuardedStore, Rc<RefCell<FakeStore>>) {
    let fake = Rc::new(RefCell::new(FakeStore::with_inbox(vec![mail(
        2,
        "a@example.com",
        "S",
        &[],
    )])));
    (
        GuardedStore::new(Box::new(Shared(Rc::clone(&fake))), "acct", access),
        fake,
    )
}

/// Calls every changing operation once and reports which ones were let through.
fn try_all(store: &mut GuardedStore) -> Result<[bool; 8], Error> {
    store.select(&folder("INBOX")?)?;
    let flag = store.add_flags(uid(2)?, &["\\Seen"]).is_ok();
    let unflag = store.remove_flags(uid(2)?, &["\\Seen"]).is_ok();
    let create = store.create_folder(&folder("New")?).is_ok();
    let append = store
        .append(&folder("Sent")?, b"Subject: x\r\n\r\n", &[])
        .is_ok();
    store.select(&folder("INBOX")?)?;
    let copy = store.copy_to(uid(2)?, &folder("Work/GitHub")?).is_ok();
    let expunge_one = store.expunge_uid(uid(9)?).is_ok();
    let expunge_all = store.expunge_all_deleted().is_ok();
    let moved = store.move_to(uid(2)?, &folder("Work/GitHub")?).is_ok();
    Ok([
        flag,
        unflag,
        create,
        append,
        copy,
        expunge_one,
        expunge_all,
        moved,
    ])
}

#[test]
fn read_only_lets_nothing_through_and_examines() -> Result<(), Error> {
    let (mut store, fake) = guarded(Access::Read);
    let before = fake.borrow().snapshot();
    assert_eq!(try_all(&mut store)?, [false; 8]);
    assert_eq!(fake.borrow().snapshot(), before);
    assert_eq!(fake.borrow().mutations, 0);
    assert!(fake.borrow().read_only, "read accounts must use EXAMINE");
    assert!(store.folders()?.len() > 1);
    assert_eq!(store.move_support()?, MoveSupport::Move);
    assert!(store.deleted_uids()?.is_empty());
    assert_eq!(store.uids()?.len(), 1);
    assert_eq!(store.headers(&[uid(2)?])?.len(), 1);
    assert!(store.message(uid(2)?)?.is_some());
    assert_eq!(
        store.find_message_id(&MessageId::parse("m2@test")?)?.len(),
        1
    );
    store.select_read_only(&folder("INBOX")?)?;
    Ok(())
}

#[test]
fn each_level_unlocks_exactly_its_operations() -> Result<(), Error> {
    // [flag, unflag, create folder, append, copy, expunge one, expunge all, move]
    let expected = [
        (
            Access::Flag,
            [true, true, false, false, false, false, false, false],
        ),
        (
            Access::Organize,
            [true, true, true, false, true, true, true, true],
        ),
        (Access::Send, [true; 8]),
    ];
    for (access, allowed) in expected {
        let (mut store, fake) = guarded(access);
        assert_eq!(try_all(&mut store)?, allowed, "{access:?}");
        assert!(!fake.borrow().read_only);
    }
    let (mut store, _) = guarded(Access::Flag);
    assert!(matches!(
        store.move_to(uid(2)?, &folder("Work/GitHub")?),
        Err(Error::AccessDenied {
            needed: "organize",
            granted: "flag",
            ..
        })
    ));
    Ok(())
}
