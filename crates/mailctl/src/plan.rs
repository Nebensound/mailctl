//! Batch plans: many changes over one connection, each reported on its own.

use serde::{Deserialize, Serialize};

use crate::cache::CachedStore;
use crate::config::{Access, AccountConfig, Config};
use crate::error::Error;
use crate::service::{self, ActionReport, ForwardJob};
use crate::store::{MailSender, MailStore};
use crate::types::{EmailAddress, Expect, MailboxName, MessageId, Uid};

/// A batch of changes for one account.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    /// Account name from the configuration.
    pub account: String,
    /// Default folder of the mails in this plan.
    #[serde(default = "default_folder")]
    pub folder: MailboxName,
    /// Only check, change nothing.
    #[serde(default)]
    pub dry_run: bool,
    /// The changes, executed in order.
    pub ops: Vec<PlanOp>,
}

fn default_folder() -> MailboxName {
    MailboxName::inbox()
}

/// One change in a [`Plan`].
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum PlanOp {
    /// Move a mail, optionally marking it read first.
    Move {
        /// UID in the folder.
        uid: Uid,
        /// `Message-ID` or mail reference.
        expect: String,
        /// Target folder.
        to: MailboxName,
        /// Mark as read before moving.
        #[serde(default)]
        mark_read: bool,
        /// Folder of the mail, if not the plan default.
        #[serde(default)]
        folder: Option<MailboxName>,
    },
    /// Mark a mail as read.
    MarkRead {
        /// UID in the folder.
        uid: Uid,
        /// `Message-ID` or mail reference.
        expect: String,
        /// Folder of the mail, if not the plan default.
        #[serde(default)]
        folder: Option<MailboxName>,
    },
    /// Forward a mail to an allowed recipient.
    Forward {
        /// UID in the folder.
        uid: Uid,
        /// `Message-ID` or mail reference.
        expect: String,
        /// Recipient.
        to: EmailAddress,
        /// Optional note.
        #[serde(default)]
        note: Option<String>,
        /// Folder of the mail, if not the plan default.
        #[serde(default)]
        folder: Option<MailboxName>,
    },
    /// Create a folder.
    CreateFolder {
        /// Folder name.
        name: MailboxName,
    },
}

/// Result of one operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OpResult {
    /// Position in the plan, starting at 0.
    pub index: usize,
    /// The operation succeeded.
    pub ok: bool,
    /// Report on success.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub report: Option<ActionReport>,
    /// Error message on failure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Result of a whole plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PlanResult {
    /// Per-operation results.
    pub results: Vec<OpResult>,
    /// Number of failed operations.
    pub failed: usize,
}

impl PlanOp {
    /// The access level this operation needs.
    #[must_use]
    pub fn required_access(&self) -> Access {
        match self {
            Self::MarkRead { .. } => Access::Flag,
            Self::Move { .. } | Self::CreateFolder { .. } => Access::Organize,
            Self::Forward { .. } => Access::Send,
        }
    }
}

impl Plan {
    /// Parses a plan from JSON.
    ///
    /// # Errors
    /// Returns [`Error::InvalidInput`] for malformed JSON.
    pub fn parse(json: &str) -> Result<Self, Error> {
        serde_json::from_str(json).map_err(|e| Error::InvalidInput(format!("plan: {e}")))
    }
}

/// Runs a plan. Each operation is independent; a failure does not stop the rest.
pub fn run(
    plan: &Plan,
    account: &AccountConfig,
    config: &Config,
    store: &mut dyn MailStore,
    sender: &mut dyn MailSender,
    new_message_id: &mut dyn FnMut() -> Result<MessageId, Error>,
) -> PlanResult {
    // One folder listing and capability check for the whole plan.
    let mut store = CachedStore::new(store);
    let results: Vec<OpResult> = plan
        .ops
        .iter()
        .enumerate()
        .map(|(index, op)| {
            let outcome = run_op(
                plan,
                op,
                account,
                config,
                &mut store,
                sender,
                new_message_id,
            );
            // A dry run creates nothing, but later operations of the same plan
            // may use the folder (`create_folder X`, then `move` into X).
            if let (true, Ok(_), PlanOp::CreateFolder { name }) = (plan.dry_run, &outcome, op) {
                store.assume_folder(name);
            }
            match outcome {
                Ok(report) => OpResult {
                    index,
                    ok: true,
                    report: Some(report),
                    error: None,
                },
                Err(e) => OpResult {
                    index,
                    ok: false,
                    report: None,
                    error: Some(e.to_string()),
                },
            }
        })
        .collect();
    let failed = results.iter().filter(|r| !r.ok).count();
    PlanResult { results, failed }
}

fn run_op(
    plan: &Plan,
    op: &PlanOp,
    account: &AccountConfig,
    config: &Config,
    store: &mut dyn MailStore,
    sender: &mut dyn MailSender,
    new_message_id: &mut dyn FnMut() -> Result<MessageId, Error>,
) -> Result<ActionReport, Error> {
    account
        .access
        .require(&account.name, op.required_access())?;
    match op {
        PlanOp::Move {
            uid,
            expect,
            to,
            mark_read,
            folder,
        } => service::move_mail(
            store,
            folder.as_ref().unwrap_or(&plan.folder),
            *uid,
            &Expect::parse(expect)?,
            to,
            *mark_read,
            plan.dry_run,
        ),
        PlanOp::MarkRead {
            uid,
            expect,
            folder,
        } => service::mark_read(
            store,
            folder.as_ref().unwrap_or(&plan.folder),
            *uid,
            &Expect::parse(expect)?,
            plan.dry_run,
        ),
        PlanOp::Forward {
            uid,
            expect,
            to,
            note,
            folder,
        } => {
            let expect = Expect::parse(expect)?;
            let id = new_message_id()?;
            service::forward(
                store,
                sender,
                config,
                &ForwardJob {
                    folder: folder.as_ref().unwrap_or(&plan.folder),
                    uid: *uid,
                    expect: &expect,
                    to,
                    from: &account.address,
                    sent_folder: account.sent_copy_folder(),
                    new_message_id: &id,
                    note: note.as_deref(),
                    dry_run: plan.dry_run,
                },
            )
        }
        PlanOp::CreateFolder { name } => service::create_folder(store, name, plan.dry_run),
    }
}

#[cfg(test)]
#[path = "tests/plan.rs"]
mod tests;
