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
#[path = "tests/guard.rs"]
mod tests;
