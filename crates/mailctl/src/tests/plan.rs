//! Tests for `plan`.

use super::*;
use crate::testing::{FakeSender, FakeStore, config, mail};

#[test]
fn runs_all_ops_and_reports_failures() -> Result<(), Error> {
    let config = config()?;
    let account = config.account("test")?.clone();
    let plan = Plan::parse(
        r#"{"account":"test","ops":[
            {"op":"create_folder","name":"Newsletter"},
            {"op":"move","uid":2,"expect":"m2@test","to":"Newsletter","mark_read":true},
            {"op":"mark_read","uid":3,"expect":"<m3@test>"},
            {"op":"forward","uid":3,"expect":"m3@test","to":"accounting@example.com","note":"Please book"},
            {"op":"move","uid":9,"expect":"m9@test","to":"Newsletter","folder":"INBOX"},
            {"op":"mark_read","uid":3,"expect":" "},
            {"op":"forward","uid":3,"expect":" ","to":"accounting@example.com"}
        ]}"#,
    )?;
    assert_eq!(plan.folder.as_str(), "INBOX");
    let mut store = FakeStore::with_inbox(vec![mail(2, "a@x", "N", &[]), mail(3, "b@x", "R", &[])]);
    let mut sender = FakeSender::default();
    let mut counter = 0_u32;
    let mut ids = || {
        counter = counter.saturating_add(1);
        MessageId::parse(&format!("fwd{counter}@mailctl"))
    };
    let result = run(&plan, &account, &config, &mut store, &mut sender, &mut ids);
    let oks: Vec<bool> = result.results.iter().map(|r| r.ok).collect();
    assert_eq!(oks, vec![true, true, true, true, false, false, false]);
    assert_eq!(result.failed, 3);
    assert_eq!(sender.sent.len(), 1);
    Ok(())
}

#[test]
fn rejects_bad_plans() {
    assert!(Plan::parse("{").is_err());
    assert!(Plan::parse(r#"{"account":"a","ops":[{"op":"delete","uid":1}]}"#).is_err());
}

#[test]
fn default_folder_is_inbox() {
    assert_eq!(default_folder().as_str(), "INBOX");
}

#[test]
fn op_level_failures_do_not_stop_the_plan() -> Result<(), Error> {
    let config = config()?;
    let account = config.account("test")?.clone();
    let plan = Plan::parse(
        r#"{"account":"test","ops":[
            {"op":"move","uid":2,"expect":" ","to":"Sent"},
            {"op":"forward","uid":2,"expect":"m2@test","to":"accounting@example.com"},
            {"op":"mark_read","uid":2,"expect":"m2@test"}
        ]}"#,
    )?;
    let mut store = FakeStore::with_inbox(vec![mail(2, "a@x", "N", &[])]);
    let mut sender = FakeSender::default();
    let mut no_ids = || Err(Error::InvalidInput("no message id".into()));
    let result = run(
        &plan,
        &account,
        &config,
        &mut store,
        &mut sender,
        &mut no_ids,
    );
    let oks: Vec<bool> = result.results.iter().map(|r| r.ok).collect();
    assert_eq!(oks, vec![false, false, true]);
    assert_eq!(result.failed, 2);
    assert!(sender.sent.is_empty());
    assert_eq!(store.uids_of("INBOX").len(), 1);
    Ok(())
}

#[test]
fn uid_zero_is_refused_when_the_plan_is_read() {
    let parsed = Plan::parse(
        r#"{"account":"test","ops":[{"op":"move","uid":0,"expect":"m2@test","to":"Sent"}]}"#,
    );
    assert!(
        matches!(&parsed, Err(Error::InvalidInput(m)) if m.contains("UID must not be zero")),
        "{parsed:?}"
    );
}

#[test]
fn dry_runs_know_folders_created_earlier_in_the_plan() -> Result<(), Error> {
    let config = config()?;
    let account = config.account("test")?.clone();
    let plan = Plan::parse(
        r#"{"account":"test","dry_run":true,"ops":[
            {"op":"create_folder","name":"Invoices"},
            {"op":"move","uid":2,"expect":"m2@test","to":"Invoices"}
        ]}"#,
    )?;
    let mut store = FakeStore::with_inbox(vec![mail(2, "a@x", "Invoice", &[])]);
    let before = store.snapshot();
    let mut no_ids = || Err(Error::InvalidInput("no message id".into()));
    let result = run(
        &plan,
        &account,
        &config,
        &mut store,
        &mut FakeSender::default(),
        &mut no_ids,
    );
    assert_eq!(result.failed, 0, "{result:?}");
    assert_eq!(store.snapshot(), before);
    assert!(!store.folders.contains_key("Invoices"));
    Ok(())
}

#[test]
fn the_plan_store_passes_everything_through() -> Result<(), Error> {
    let mut inner = FakeStore::with_inbox(vec![mail(2, "a@x", "A", &[])]);
    let mut store = PlannedFolders {
        inner: &mut inner,
        planned: Vec::new(),
    };
    let inbox = MailboxName::inbox();
    let uid = Uid::new(2)?;
    store.select_read_only(&inbox)?;
    store.select(&inbox)?;
    assert!(store.keywords_allowed()?);
    assert_eq!(store.uids()?, vec![uid]);
    assert!(store.message(uid)?.is_some());
    assert_eq!(
        store.find_message_id(&MessageId::parse("m2@test")?)?,
        vec![uid]
    );
    let sent = MailboxName::new("Sent")?;
    store.append(&sent, b"Message-ID: <x@y>\r\n\r\nx", &[])?;
    let new = MailboxName::new("New")?;
    store.create_folder(&new)?;
    assert!(store.folders()?.iter().any(|f| f.name == new));
    Ok(())
}
