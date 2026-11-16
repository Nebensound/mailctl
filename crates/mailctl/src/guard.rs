//! Enforces an account's [`Access`] level on every mail-server operation.
//!
//! This is the second line of defence after the per-command checks: even if a
//! code path forgot its check, a change above the account's level never reaches
//! the server. For `read` accounts folders are opened with `EXAMINE`, so the
//! server itself refuses changes as well.

use crate::config::Access;
use crate::error::Error;
use crate::store::{FolderInfo, MailStore, RawHeader, RawMessage};
use crate::types::{MailboxName, MessageId, Uid};

/// A [`MailStore`] that only lets through what the access level allows.
pub struct GuardedStore {
    inner: Box<dyn MailStore>,
    account: String,
    access: Access,
}

impl GuardedStore {
    /// Wraps a store for an account with the given access level.
    #[must_use]
    pub fn new(inner: Box<dyn MailStore>, account: &str, access: Access) -> Self {
        Self {
            inner,
            account: account.to_owned(),
            access,
        }
    }

    fn require(&self, needed: Access) -> Result<(), Error> {
        self.access.require(&self.account, needed)
    }
}

impl MailStore for GuardedStore {
    fn folders(&mut self) -> Result<Vec<FolderInfo>, Error> {
        self.inner.folders()
    }

    fn select(&mut self, folder: &MailboxName) -> Result<(), Error> {
        if self.access == Access::Read {
            self.inner.select_read_only(folder)
        } else {
            self.inner.select(folder)
        }
    }

    fn select_read_only(&mut self, folder: &MailboxName) -> Result<(), Error> {
        self.inner.select_read_only(folder)
    }

    fn uids(&mut self) -> Result<Vec<Uid>, Error> {
        self.inner.uids()
    }

    fn headers(&mut self, uids: &[Uid]) -> Result<Vec<RawHeader>, Error> {
        self.inner.headers(uids)
    }

    fn message(&mut self, uid: Uid) -> Result<Option<RawMessage>, Error> {
        self.inner.message(uid)
    }

    fn add_flags(&mut self, uid: Uid, flags: &[&str]) -> Result<(), Error> {
        self.require(Access::Flag)?;
        self.inner.add_flags(uid, flags)
    }

    fn supports_move(&mut self) -> Result<bool, Error> {
        self.inner.supports_move()
    }

    fn move_to(&mut self, uid: Uid, target: &MailboxName) -> Result<(), Error> {
        self.require(Access::Organize)?;
        self.inner.move_to(uid, target)
    }

    fn find_message_id(&mut self, id: &MessageId) -> Result<Vec<Uid>, Error> {
        self.inner.find_message_id(id)
    }

    fn create_folder(&mut self, name: &MailboxName) -> Result<(), Error> {
        self.require(Access::Organize)?;
        self.inner.create_folder(name)
    }

    fn append(
        &mut self,
        folder: &MailboxName,
        message: &[u8],
        flags: &[&str],
    ) -> Result<(), Error> {
        self.require(Access::Send)?;
        self.inner.append(folder, message, flags)
    }
}

#[cfg(test)]
mod tests {
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
    fn try_all(store: &mut GuardedStore) -> Result<[bool; 4], Error> {
        store.select(&folder("INBOX")?)?;
        let flag = store.add_flags(uid(2)?, &["\\Seen"]).is_ok();
        let create = store.create_folder(&folder("New")?).is_ok();
        let append = store
            .append(&folder("Sent")?, b"Subject: x\r\n\r\n", &[])
            .is_ok();
        store.select(&folder("INBOX")?)?;
        let moved = store.move_to(uid(2)?, &folder("Work/GitHub")?).is_ok();
        Ok([flag, create, append, moved])
    }

    #[test]
    fn read_only_lets_nothing_through_and_examines() -> Result<(), Error> {
        let (mut store, fake) = guarded(Access::Read);
        let before = fake.borrow().snapshot();
        assert_eq!(try_all(&mut store)?, [false, false, false, false]);
        assert_eq!(fake.borrow().snapshot(), before);
        assert_eq!(fake.borrow().mutations, 0);
        assert!(fake.borrow().read_only, "read accounts must use EXAMINE");
        assert!(store.folders()?.len() > 1 && store.supports_move()?);
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
        // [flag, create folder, append, move]
        let expected = [
            (Access::Flag, [true, false, false, false]),
            (Access::Organize, [true, true, false, true]),
            (Access::Send, [true, true, true, true]),
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
}
