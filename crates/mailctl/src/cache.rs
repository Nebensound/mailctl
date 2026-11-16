//! A [`MailStore`] wrapper for plans: it remembers the folder list and MOVE
//! support, so a long plan does not list all folders for every move, and it
//! knows the folders a dry run of the plan would have created.

use crate::error::Error;
use crate::store::{FolderInfo, MailStore, RawHeader, RawMessage};
use crate::types::{MailboxName, MessageId, Uid};

/// Caches `folders` and `supports_move`; creating a folder clears the folder
/// list, so the next call sees the new folder.
pub struct CachedStore<'a> {
    inner: &'a mut dyn MailStore,
    folders: Option<Vec<FolderInfo>>,
    supports_move: Option<bool>,
    /// Folders a dry run "created"; listed as if they existed.
    assumed: Vec<FolderInfo>,
}

impl<'a> CachedStore<'a> {
    /// Wraps a store.
    #[must_use]
    pub fn new(inner: &'a mut dyn MailStore) -> Self {
        Self {
            inner,
            folders: None,
            supports_move: None,
            assumed: Vec::new(),
        }
    }

    /// Lists `name` from now on as if it existed: a dry run creates nothing,
    /// but later operations of the same plan may use the folder.
    pub fn assume_folder(&mut self, name: &MailboxName) {
        self.assumed.push(FolderInfo {
            name: name.clone(),
            delimiter: None,
            selectable: true,
            special_use: None,
        });
    }
}

impl MailStore for CachedStore<'_> {
    fn folders(&mut self) -> Result<Vec<FolderInfo>, Error> {
        if self.folders.is_none() {
            self.folders = Some(self.inner.folders()?);
        }
        let mut folders = self.folders.clone().unwrap_or_default();
        folders.extend(self.assumed.iter().cloned());
        Ok(folders)
    }

    fn select(&mut self, folder: &MailboxName) -> Result<(), Error> {
        self.inner.select(folder)
    }

    fn select_read_only(&mut self, folder: &MailboxName) -> Result<(), Error> {
        self.inner.select_read_only(folder)
    }

    fn keywords_allowed(&mut self) -> Result<bool, Error> {
        self.inner.keywords_allowed()
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
        self.inner.add_flags(uid, flags)
    }

    fn supports_move(&mut self) -> Result<bool, Error> {
        if let Some(supported) = self.supports_move {
            return Ok(supported);
        }
        let supported = self.inner.supports_move()?;
        self.supports_move = Some(supported);
        Ok(supported)
    }

    fn move_to(&mut self, uid: Uid, target: &MailboxName) -> Result<(), Error> {
        self.inner.move_to(uid, target)
    }

    fn find_message_id(&mut self, id: &MessageId) -> Result<Vec<Uid>, Error> {
        self.inner.find_message_id(id)
    }

    fn create_folder(&mut self, name: &MailboxName) -> Result<(), Error> {
        self.folders = None;
        self.inner.create_folder(name)
    }

    fn append(
        &mut self,
        folder: &MailboxName,
        message: &[u8],
        flags: &[&str],
    ) -> Result<(), Error> {
        self.inner.append(folder, message, flags)
    }
}

#[cfg(test)]
#[path = "tests/cache.rs"]
mod tests;
