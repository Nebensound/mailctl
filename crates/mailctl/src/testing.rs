//! In-memory mailbox and transport for tests.

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::rc::Rc;

use crate::cli::Backend;
use crate::config::{AccountConfig, Config, Secret, SecretLookup};
use crate::discover::Net;
use crate::discover::tests::FakeNet;
use crate::error::Error;
use crate::store::{
    FLAG_DELETED, FolderInfo, MailSender, MailStore, MoveSupport, RawHeader, RawMessage,
};
use crate::types::{EmailAddress, MailboxName, MessageId, Uid};

/// One stored mail.
#[derive(Debug, Clone)]
pub(crate) struct FakeMail {
    uid: u32,
    flags: Vec<String>,
    body: Vec<u8>,
}

/// UID, flags and bytes of one stored mail.
pub(crate) type MailState = (u32, Vec<String>, Vec<u8>);

/// In-memory IMAP account with switches to simulate server misbehaviour.
#[derive(Debug, Clone)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "independent switches to simulate server faults"
)]
pub(crate) struct FakeStore {
    pub(crate) folders: BTreeMap<String, Vec<FakeMail>>,
    pub(crate) noselect: Vec<String>,
    pub(crate) selected: Option<String>,
    pub(crate) next_uid: u32,
    pub(crate) move_support: MoveSupport,
    pub(crate) ignore_flags: bool,
    pub(crate) lose_moves: bool,
    /// `COPY` succeeds but no copy arrives.
    pub(crate) lose_copies: bool,
    /// When a mail gets `\Deleted`, another client marks this UID too.
    pub(crate) race_deleted: Option<u32>,
    pub(crate) stuck_moves: bool,
    pub(crate) ignore_creates: bool,
    pub(crate) hide_bodies: bool,
    pub(crate) lose_appends: bool,
    pub(crate) fail_all: bool,
    /// The server forgets custom keywords such as `$Forwarded`.
    pub(crate) no_keywords: bool,
    /// Fail the store call with this zero-based number (and only that one).
    pub(crate) fail_at_call: Option<usize>,
    /// Number of store calls so far.
    pub(crate) calls: Cell<usize>,
    /// The selected folder was opened with `EXAMINE`.
    pub(crate) read_only: bool,
    /// Number of changing calls that reached the store.
    pub(crate) mutations: usize,
}

pub(crate) fn uid(value: u32) -> Result<Uid, Error> {
    Uid::new(value)
}

pub(crate) fn folder(name: &str) -> Result<MailboxName, Error> {
    MailboxName::new(name)
}

/// A mail with `Message-ID: <m{uid}@test>`.
pub(crate) fn mail(uid: u32, from: &str, subject: &str, flags: &[&str]) -> FakeMail {
    let body = format!(
        "Message-ID: <m{uid}@test>\r\nDate: Wed, 11 Nov 2026 10:00:00 +0100\r\nFrom: {from}\r\nSubject: {subject}\r\n\r\nText {uid}\r\n"
    );
    FakeStore::raw_mail(uid, body.into_bytes(), flags)
}

pub(crate) fn config() -> Result<Config, Error> {
    Config::parse(
        r#"
forward_allowlist = ["accounting@example.com"]
[[accounts]]
name = "test"
user = "alice@example.com"
address = "alice@example.com"
imap_host = "imap.test"
smtp_host = "smtp.test"
sent_folder = "Sent"
password = { env = "MAILCTL_TEST_PW" }
access = "send"
"#,
    )
}

impl FakeStore {
    pub(crate) fn raw_mail(uid: u32, body: Vec<u8>, flags: &[&str]) -> FakeMail {
        FakeMail {
            uid,
            flags: flags.iter().map(|f| (*f).to_owned()).collect(),
            body,
        }
    }

    /// INBOX with the given mails plus `Work/GitHub`, `Sent` and a non-selectable `Noselect`.
    pub(crate) fn with_inbox(mails: Vec<FakeMail>) -> Self {
        let next_uid = mails
            .iter()
            .map(|m| m.uid)
            .max()
            .unwrap_or(0)
            .saturating_add(100);
        let mut folders = BTreeMap::new();
        folders.insert("INBOX".to_owned(), mails);
        folders.insert("Work/GitHub".to_owned(), Vec::new());
        folders.insert("Sent".to_owned(), Vec::new());
        folders.insert("Noselect".to_owned(), Vec::new());
        Self {
            folders,
            noselect: vec!["Noselect".to_owned()],
            selected: None,
            next_uid,
            move_support: MoveSupport::Move,
            ignore_flags: false,
            lose_moves: false,
            lose_copies: false,
            race_deleted: None,
            stuck_moves: false,
            ignore_creates: false,
            hide_bodies: false,
            lose_appends: false,
            fail_all: false,
            no_keywords: false,
            fail_at_call: None,
            calls: Cell::new(0),
            read_only: false,
            mutations: 0,
        }
    }

    /// Every folder with every mail's UID, flags and bytes, for equality checks.
    pub(crate) fn snapshot(&self) -> Vec<(String, Vec<MailState>)> {
        self.folders
            .iter()
            .map(|(name, mails)| {
                (
                    name.clone(),
                    mails
                        .iter()
                        .map(|m| (m.uid, m.flags.clone(), m.body.clone()))
                        .collect(),
                )
            })
            .collect()
    }

    fn mutate(&mut self) -> Result<(), Error> {
        if self.read_only {
            return Err(Error::Store("mailbox is read-only (EXAMINE)".into()));
        }
        self.mutations = self.mutations.saturating_add(1);
        Ok(())
    }

    pub(crate) fn flags(&self, folder: &str, uid: u32) -> Vec<String> {
        self.folders
            .get(folder)
            .and_then(|m| m.iter().find(|x| x.uid == uid))
            .map(|m| m.flags.clone())
            .unwrap_or_default()
    }

    pub(crate) fn uids_of(&self, folder: &str) -> Vec<Uid> {
        self.folders
            .get(folder)
            .map(|m| m.iter().filter_map(|x| Uid::new(x.uid).ok()).collect())
            .unwrap_or_default()
    }

    fn check(&self) -> Result<(), Error> {
        let call = self.calls.get();
        self.calls.set(call.saturating_add(1));
        if self.fail_all || self.fail_at_call == Some(call) {
            Err(Error::Store("simulated failure".into()))
        } else {
            Ok(())
        }
    }

    fn current(&mut self) -> Result<&mut Vec<FakeMail>, Error> {
        let name = self
            .selected
            .clone()
            .ok_or_else(|| Error::Store("no folder selected".into()))?;
        self.folders
            .get_mut(&name)
            .ok_or_else(|| Error::Store("selected folder vanished".into()))
    }

    fn next(&mut self) -> u32 {
        self.next_uid = self.next_uid.saturating_add(1);
        self.next_uid
    }
}

impl MailStore for FakeStore {
    fn folders(&mut self) -> Result<Vec<FolderInfo>, Error> {
        self.check()?;
        self.folders
            .keys()
            .map(|name| {
                Ok(FolderInfo {
                    name: MailboxName::new(name)?,
                    delimiter: Some("/".to_owned()),
                    selectable: !self.noselect.contains(name),
                    special_use: (name == "Sent").then(|| "sent".to_owned()),
                })
            })
            .collect()
    }

    fn select(&mut self, folder: &MailboxName) -> Result<(), Error> {
        self.check()?;
        if !self.folders.contains_key(folder.as_str()) {
            return Err(Error::Store(format!("no such folder {folder}")));
        }
        self.selected = Some(folder.to_string());
        self.read_only = false;
        Ok(())
    }

    fn select_read_only(&mut self, folder: &MailboxName) -> Result<(), Error> {
        self.select(folder)?;
        self.read_only = true;
        Ok(())
    }

    fn keywords_allowed(&mut self) -> Result<bool, Error> {
        self.check()?;
        Ok(!self.no_keywords)
    }

    fn uids(&mut self) -> Result<Vec<Uid>, Error> {
        self.check()?;
        Ok(self
            .current()?
            .iter()
            .filter_map(|m| Uid::new(m.uid).ok())
            .collect())
    }

    fn headers(&mut self, uids: &[Uid]) -> Result<Vec<RawHeader>, Error> {
        self.check()?;
        Ok(self
            .current()?
            .iter()
            .filter(|m| uids.iter().any(|u| u.get() == m.uid))
            .filter_map(|m| {
                Some(RawHeader {
                    uid: Uid::new(m.uid).ok()?,
                    flags: m.flags.clone(),
                    size: u32::try_from(m.body.len()).ok()?,
                    header: m.body.clone(),
                })
            })
            .collect())
    }

    fn message(&mut self, uid: Uid) -> Result<Option<RawMessage>, Error> {
        self.check()?;
        if self.hide_bodies {
            return Ok(None);
        }
        Ok(self
            .current()?
            .iter()
            .find(|m| m.uid == uid.get())
            .map(|m| RawMessage {
                uid,
                flags: m.flags.clone(),
                size: u32::try_from(m.body.len()).unwrap_or(u32::MAX),
                body: m.body.clone(),
            }))
    }

    fn add_flags(&mut self, uid: Uid, flags: &[&str]) -> Result<(), Error> {
        self.check()?;
        self.mutate()?;
        if self.ignore_flags {
            return Ok(());
        }
        let keep_keywords = !self.no_keywords;
        let race = self.race_deleted.filter(|_| flags.contains(&FLAG_DELETED));
        if let Some(other) = race
            && let Some(m) = self.current()?.iter_mut().find(|m| m.uid == other)
        {
            m.flags.push(FLAG_DELETED.to_owned());
        }
        if let Some(m) = self.current()?.iter_mut().find(|m| m.uid == uid.get()) {
            for flag in flags
                .iter()
                .filter(|f| keep_keywords || f.starts_with('\\'))
            {
                if !m.flags.iter().any(|f| f == flag) {
                    m.flags.push((*flag).to_owned());
                }
            }
        }
        Ok(())
    }

    fn remove_flags(&mut self, uid: Uid, flags: &[&str]) -> Result<(), Error> {
        self.check()?;
        self.mutate()?;
        if let Some(m) = self.current()?.iter_mut().find(|m| m.uid == uid.get()) {
            m.flags.retain(|f| !flags.contains(&f.as_str()));
        }
        Ok(())
    }

    fn move_support(&mut self) -> Result<MoveSupport, Error> {
        self.check()?;
        Ok(self.move_support)
    }

    fn copy_to(&mut self, uid: Uid, target: &MailboxName) -> Result<(), Error> {
        self.check()?;
        self.mutate()?;
        let Some(mut copy) = self.current()?.iter().find(|m| m.uid == uid.get()).cloned() else {
            return Err(Error::NotFound(uid.get()));
        };
        if self.lose_copies {
            return Ok(());
        }
        copy.uid = self.next();
        self.folders
            .get_mut(target.as_str())
            .ok_or_else(|| Error::Store(format!("no such folder {target}")))?
            .push(copy);
        Ok(())
    }

    fn deleted_uids(&mut self) -> Result<Vec<Uid>, Error> {
        self.check()?;
        Ok(self
            .current()?
            .iter()
            .filter(|m| m.flags.iter().any(|f| f == FLAG_DELETED))
            .filter_map(|m| Uid::new(m.uid).ok())
            .collect())
    }

    fn expunge_uid(&mut self, uid: Uid) -> Result<(), Error> {
        self.check()?;
        self.mutate()?;
        self.current()?
            .retain(|m| m.uid != uid.get() || !m.flags.iter().any(|f| f == FLAG_DELETED));
        Ok(())
    }

    fn expunge_all_deleted(&mut self) -> Result<(), Error> {
        self.check()?;
        self.mutate()?;
        self.current()?
            .retain(|m| !m.flags.iter().any(|f| f == FLAG_DELETED));
        Ok(())
    }

    fn move_to(&mut self, uid: Uid, target: &MailboxName) -> Result<(), Error> {
        self.check()?;
        self.mutate()?;
        if self.stuck_moves {
            return Ok(());
        }
        let source = self.current()?;
        let Some(pos) = source.iter().position(|m| m.uid == uid.get()) else {
            return Err(Error::NotFound(uid.get()));
        };
        let mut moved = source.remove(pos);
        if self.lose_moves {
            return Ok(());
        }
        moved.uid = self.next();
        self.folders
            .get_mut(target.as_str())
            .ok_or_else(|| Error::Store(format!("no such folder {target}")))?
            .push(moved);
        Ok(())
    }

    fn find_message_id(&mut self, id: &MessageId) -> Result<Vec<Uid>, Error> {
        self.check()?;
        let needle = format!("<{id}>");
        Ok(self
            .current()?
            .iter()
            .filter(|m| String::from_utf8_lossy(&m.body).contains(&needle))
            .filter_map(|m| Uid::new(m.uid).ok())
            .collect())
    }

    fn create_folder(&mut self, name: &MailboxName) -> Result<(), Error> {
        self.check()?;
        self.mutations = self.mutations.saturating_add(1);
        if !self.ignore_creates {
            self.folders.insert(name.to_string(), Vec::new());
        }
        Ok(())
    }

    fn append(
        &mut self,
        folder: &MailboxName,
        message: &[u8],
        flags: &[&str],
    ) -> Result<(), Error> {
        self.check()?;
        self.mutations = self.mutations.saturating_add(1);
        if self.lose_appends {
            return Ok(());
        }
        let uid = self.next();
        self.folders
            .get_mut(folder.as_str())
            .ok_or_else(|| Error::Store(format!("no such folder {folder}")))?
            .push(Self::raw_mail(uid, message.to_vec(), flags));
        Ok(())
    }
}

/// A handle to a shared [`FakeStore`], so tests can inspect it after the code under test used it.
pub(crate) struct Shared(pub(crate) Rc<RefCell<FakeStore>>);

impl MailStore for Shared {
    fn folders(&mut self) -> Result<Vec<FolderInfo>, Error> {
        self.0.borrow_mut().folders()
    }
    fn select(&mut self, folder: &MailboxName) -> Result<(), Error> {
        self.0.borrow_mut().select(folder)
    }
    fn select_read_only(&mut self, folder: &MailboxName) -> Result<(), Error> {
        self.0.borrow_mut().select_read_only(folder)
    }
    fn keywords_allowed(&mut self) -> Result<bool, Error> {
        self.0.borrow_mut().keywords_allowed()
    }
    fn uids(&mut self) -> Result<Vec<Uid>, Error> {
        self.0.borrow_mut().uids()
    }
    fn headers(&mut self, uids: &[Uid]) -> Result<Vec<RawHeader>, Error> {
        self.0.borrow_mut().headers(uids)
    }
    fn message(&mut self, uid: Uid) -> Result<Option<RawMessage>, Error> {
        self.0.borrow_mut().message(uid)
    }
    fn add_flags(&mut self, uid: Uid, flags: &[&str]) -> Result<(), Error> {
        self.0.borrow_mut().add_flags(uid, flags)
    }
    fn remove_flags(&mut self, uid: Uid, flags: &[&str]) -> Result<(), Error> {
        self.0.borrow_mut().remove_flags(uid, flags)
    }
    fn move_support(&mut self) -> Result<MoveSupport, Error> {
        self.0.borrow_mut().move_support()
    }
    fn copy_to(&mut self, uid: Uid, target: &MailboxName) -> Result<(), Error> {
        self.0.borrow_mut().copy_to(uid, target)
    }
    fn deleted_uids(&mut self) -> Result<Vec<Uid>, Error> {
        self.0.borrow_mut().deleted_uids()
    }
    fn expunge_uid(&mut self, uid: Uid) -> Result<(), Error> {
        self.0.borrow_mut().expunge_uid(uid)
    }
    fn expunge_all_deleted(&mut self) -> Result<(), Error> {
        self.0.borrow_mut().expunge_all_deleted()
    }
    fn move_to(&mut self, uid: Uid, target: &MailboxName) -> Result<(), Error> {
        self.0.borrow_mut().move_to(uid, target)
    }
    fn find_message_id(&mut self, id: &MessageId) -> Result<Vec<Uid>, Error> {
        self.0.borrow_mut().find_message_id(id)
    }
    fn create_folder(&mut self, name: &MailboxName) -> Result<(), Error> {
        self.0.borrow_mut().create_folder(name)
    }
    fn append(
        &mut self,
        folder: &MailboxName,
        message: &[u8],
        flags: &[&str],
    ) -> Result<(), Error> {
        self.0.borrow_mut().append(folder, message, flags)
    }
}

/// Records sent messages.
#[derive(Debug, Default)]
pub(crate) struct FakeSender {
    pub(crate) sent: Vec<(EmailAddress, Vec<u8>)>,
    pub(crate) fail: bool,
}

impl MailSender for FakeSender {
    fn send(
        &mut self,
        _from: &EmailAddress,
        to: &EmailAddress,
        message: &[u8],
    ) -> Result<(), Error> {
        if self.fail {
            return Err(Error::Send("simulated failure".into()));
        }
        self.sent.push((to.clone(), message.to_vec()));
        Ok(())
    }
}

/// Complete fake backend for account setup tests: files, terminal, keychain, network.
pub(crate) struct FakeBackend {
    pub(crate) net: FakeNet,
    pub(crate) files: RefCell<HashMap<PathBuf, String>>,
    pub(crate) answers: RefCell<Vec<String>>,
    pub(crate) passwords: RefCell<Vec<String>>,
    pub(crate) stdin: RefCell<String>,
    pub(crate) keychain: RefCell<HashMap<(String, String), String>>,
    pub(crate) env_password: RefCell<Option<String>>,
    pub(crate) terminal: bool,
    pub(crate) sent_folder_flag: bool,
    pub(crate) smtp_checks: Cell<usize>,
    /// Fail the backend call with this zero-based number.
    pub(crate) fail_at: Option<usize>,
    /// Number of backend calls so far.
    pub(crate) calls: Cell<usize>,
    /// Passed on to every connected [`FakeStore`] as `fail_at_call`.
    pub(crate) store_fail_at: Option<usize>,
    /// Written to the configuration file while the password prompt is open,
    /// as another shell editing it at that moment would.
    pub(crate) edit_during_prompt: RefCell<Option<String>>,
}

const CONFIG_PATH: &str = "/cfg.toml";

impl FakeBackend {
    pub(crate) fn new(net: FakeNet) -> Self {
        Self {
            net,
            files: RefCell::new(HashMap::new()),
            answers: RefCell::new(Vec::new()),
            passwords: RefCell::new(Vec::new()),
            stdin: RefCell::new(String::new()),
            keychain: RefCell::new(HashMap::new()),
            env_password: RefCell::new(Some("env-pw".into())),
            terminal: true,
            sent_folder_flag: true,
            smtp_checks: Cell::new(0),
            fail_at: None,
            calls: Cell::new(0),
            store_fail_at: None,
            edit_during_prompt: RefCell::new(None),
        }
    }

    fn step(&self) -> Result<(), Error> {
        let call = self.calls.get();
        self.calls.set(call.saturating_add(1));
        if self.fail_at == Some(call) {
            Err(Error::Store("simulated backend failure".into()))
        } else {
            Ok(())
        }
    }

    pub(crate) fn file_text(&self) -> String {
        self.files
            .borrow()
            .get(Path::new(CONFIG_PATH))
            .cloned()
            .unwrap_or_default()
    }

    fn pop(list: &RefCell<Vec<String>>) -> Option<String> {
        let mut list = list.borrow_mut();
        (!list.is_empty()).then(|| list.remove(0))
    }
}

impl SecretLookup for FakeBackend {
    fn env(&self, _name: &str) -> Option<String> {
        self.env_password.borrow().clone()
    }
    fn keychain(&self, service: &str, account: &str) -> Result<String, String> {
        self.keychain
            .borrow()
            .get(&(service.to_owned(), account.to_owned()))
            .cloned()
            .ok_or_else(|| "not found".to_owned())
    }
}

impl Backend for FakeBackend {
    fn read_config(&self, _path: Option<&PathBuf>) -> Result<String, Error> {
        self.step()?;
        Ok(self.file_text())
    }
    fn read_plan(&self, _path: &Path) -> Result<String, Error> {
        Err(Error::InvalidInput("no plans here".into()))
    }
    fn secrets(&self) -> &dyn SecretLookup {
        self
    }
    fn connect(&self, _a: &AccountConfig, _s: &Secret) -> Result<Box<dyn MailStore>, Error> {
        self.step()?;
        let mut store = FakeStore::with_inbox(Vec::new());
        store.fail_at_call = self.store_fail_at;
        if !self.sent_folder_flag {
            store.folders.remove("Sent");
        }
        Ok(Box::new(store))
    }
    fn sender(&self, _a: &AccountConfig, _s: &Secret) -> Result<Box<dyn MailSender>, Error> {
        self.step()?;
        Ok(Box::new(FakeSender::default()))
    }
    fn unix_time(&self) -> u64 {
        1
    }
    fn random(&self) -> u64 {
        0xfeed
    }
    fn config_path(&self, _explicit: Option<&PathBuf>) -> Result<PathBuf, Error> {
        self.step()?;
        Ok(PathBuf::from(CONFIG_PATH))
    }
    fn read_optional(&self, path: &Path) -> Result<Option<String>, Error> {
        self.step()?;
        Ok(self.files.borrow().get(path).cloned())
    }
    fn write_file(&self, path: &Path, text: &str) -> Result<(), Error> {
        self.step()?;
        self.files
            .borrow_mut()
            .insert(path.to_path_buf(), text.to_owned());
        Ok(())
    }
    fn prompt_line(
        &self,
        _question: &str,
        _default: Option<&str>,
    ) -> Result<Option<String>, Error> {
        self.step()?;
        Ok(self
            .terminal
            .then(|| Self::pop(&self.answers).unwrap_or_default()))
    }
    fn prompt_password(&self, _prompt: &str) -> Result<Option<Secret>, Error> {
        self.step()?;
        if let Some(text) = self.edit_during_prompt.borrow_mut().take() {
            self.files
                .borrow_mut()
                .insert(PathBuf::from(CONFIG_PATH), text);
        }
        Ok(self
            .terminal
            .then(|| Secret::new(Self::pop(&self.passwords).unwrap_or_else(|| "pw".into()))))
    }
    fn read_stdin(&self) -> Result<String, Error> {
        self.step()?;
        Ok(std::mem::take(&mut *self.stdin.borrow_mut()))
    }
    fn keychain_store(&self, service: &str, account: &str, secret: &Secret) -> Result<(), Error> {
        self.step()?;
        self.keychain.borrow_mut().insert(
            (service.to_owned(), account.to_owned()),
            secret.expose().to_owned(),
        );
        Ok(())
    }
    fn keychain_delete(&self, service: &str, account: &str) -> Result<(), Error> {
        self.step()?;
        self.keychain
            .borrow_mut()
            .remove(&(service.to_owned(), account.to_owned()));
        Ok(())
    }
    fn net(&self) -> Box<dyn Net> {
        Box::new(self.net.clone())
    }
    fn check_smtp(&self, _account: &AccountConfig, _secret: &Secret) -> Result<(), Error> {
        self.step()?;
        self.smtp_checks
            .set(self.smtp_checks.get().saturating_add(1));
        Ok(())
    }
}
