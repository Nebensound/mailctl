//! Tests for `cli`.

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use super::*;
use crate::testing::{FakeSender, FakeStore, Shared, mail};

const CONFIG: &str = r#"
forward_allowlist = ["accounting@example.com"]
[[accounts]]
name = "test"
user = "alice@example.com"
address = "alice@example.com"
imap_host = "imap.test"
smtp_host = "smtp.test"
sent_folder = "Sent"
password = { env = "PW" }
access = "send"
"#;

struct Env {
    password: Option<String>,
}

impl SecretLookup for Env {
    fn env(&self, _name: &str) -> Option<String> {
        self.password.clone()
    }
    fn keychain(&self, _service: &str, _account: &str) -> Result<String, String> {
        Err("no keychain in tests".into())
    }
}

struct TestBackend {
    config: Result<String, Error>,
    plan: String,
    env: Env,
    store: Rc<RefCell<FakeStore>>,
    sent: Cell<usize>,
    fail_connect: bool,
    /// Fail the backend call with this zero-based number.
    fail_at: Option<usize>,
    calls: Cell<usize>,
}

impl TestBackend {
    fn new() -> Self {
        Self {
            config: Ok(CONFIG.to_owned()),
            plan: String::new(),
            env: Env {
                password: Some("pw".into()),
            },
            store: Rc::new(RefCell::new(FakeStore::with_inbox(vec![
                mail(2, "a@x", "Invoice", &[]),
                mail(3, "b@x", "News", &[]),
            ]))),
            sent: Cell::new(0),
            fail_connect: false,
            fail_at: None,
            calls: Cell::new(0),
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
}

impl Backend for TestBackend {
    fn read_config(&self, _path: Option<&PathBuf>) -> Result<String, Error> {
        self.step()?;
        self.config.clone()
    }
    fn read_plan(&self, _path: &Path) -> Result<String, Error> {
        self.step()?;
        Ok(self.plan.clone())
    }
    fn secrets(&self) -> &dyn SecretLookup {
        &self.env
    }
    fn connect(&self, _a: &AccountConfig, _s: &Secret) -> Result<Box<dyn MailStore>, Error> {
        self.step()?;
        if self.fail_connect {
            return Err(Error::Store("connection refused".into()));
        }
        Ok(Box::new(Shared(Rc::clone(&self.store))))
    }
    fn sender(&self, _a: &AccountConfig, _s: &Secret) -> Result<Box<dyn MailSender>, Error> {
        self.step()?;
        self.sent.set(self.sent.get().saturating_add(1));
        Ok(Box::new(FakeSender::default()))
    }
    fn unix_time(&self) -> u64 {
        1_700_000_000
    }
    fn random(&self) -> u64 {
        u64::try_from(self.calls.get()).unwrap_or_default()
    }
    fn config_path(&self, _explicit: Option<&PathBuf>) -> Result<PathBuf, Error> {
        Ok(PathBuf::from("/unused"))
    }
    fn read_optional(&self, _path: &Path) -> Result<Option<String>, Error> {
        Ok(None)
    }
    fn write_file(&self, _path: &Path, _text: &str) -> Result<(), Error> {
        Ok(())
    }
    fn prompt_line(&self, _q: &str, _d: Option<&str>) -> Result<Option<String>, Error> {
        Ok(None)
    }
    fn prompt_password(&self, _p: &str) -> Result<Option<Secret>, Error> {
        Ok(None)
    }
    fn read_stdin(&self) -> Result<String, Error> {
        Ok(String::new())
    }
    fn keychain_store(&self, _s: &str, _a: &str, _p: &Secret) -> Result<(), Error> {
        Ok(())
    }
    fn keychain_delete(&self, _s: &str, _a: &str) -> Result<(), Error> {
        Ok(())
    }
    fn net(&self) -> Box<dyn Net> {
        Box::new(crate::discover::tests::FakeNet::default())
    }
    fn check_smtp(&self, _a: &AccountConfig, _s: &Secret) -> Result<(), Error> {
        Ok(())
    }
}

fn at<'a>(v: &'a serde_json::Value, pointer: &str) -> &'a serde_json::Value {
    v.pointer(pointer).unwrap_or(&serde_json::Value::Null)
}

fn exec(backend: &TestBackend, args: &[&str]) -> Result<(serde_json::Value, u8), Error> {
    let cli = Cli::try_parse_from(std::iter::once("mailctl").chain(args.iter().copied()))
        .map_err(|e| Error::InvalidInput(e.to_string()))?;
    let mut out = Vec::new();
    let code = run(&cli, backend, &mut out);
    let first_line = String::from_utf8_lossy(&out);
    let text = if args.contains(&"--ndjson") {
        first_line.lines().next().unwrap_or_default().to_owned()
    } else {
        first_line.into_owned()
    };
    let value = serde_json::from_str(&text).map_err(|e| Error::InvalidInput(e.to_string()))?;
    Ok((value, code))
}

#[test]
fn offline_and_listing_commands() -> Result<(), Error> {
    let b = TestBackend::new();
    let (v, code) = exec(&b, &["ref", "<m2@test>"])?;
    assert_eq!(code, 0);
    assert_eq!(
        at(&v, "/mail_ref"),
        MailRef::from_message_id(&MessageId::parse("m2@test")?).as_str()
    );
    let (v, _) = exec(&b, &["accounts"])?;
    assert_eq!(at(&v, "/0/name"), "test");
    let (v, _) = exec(&b, &["folders", "-a", "test"])?;
    assert_eq!(v.as_array().map(Vec::len), Some(4));
    let (v, _) = exec(&b, &["list", "-a", "test", "-n", "1"])?;
    assert_eq!(at(&v, "/0/uid"), 3);
    let (v, _) = exec(&b, &["list", "-a", "test", "--before", "3"])?;
    assert_eq!(at(&v, "/0/uid"), 2);
    let (v, _) = exec(
        &b,
        &["show", "-a", "test", "--uid", "2", "--expect", "m2@test"],
    )?;
    assert_eq!(at(&v, "/subject"), "Invoice");
    let (v, _) = exec(&b, &["show", "-a", "test", "--uid", "2"])?;
    assert_eq!(at(&v, "/uid"), 2);
    Ok(())
}

#[test]
fn ndjson_and_all_folders() -> Result<(), Error> {
    let b = TestBackend::new();
    let cli = Cli::try_parse_from(["mailctl", "list", "-a", "test", "--ndjson", "--all-folders"])
        .map_err(|e| Error::InvalidInput(e.to_string()))?;
    let mut out = Vec::new();
    assert_eq!(run(&cli, &b, &mut out), 0);
    let lines: Vec<serde_json::Value> = String::from_utf8_lossy(&out)
        .lines()
        .map(serde_json::from_str)
        .collect::<Result<_, _>>()
        .map_err(|e| Error::InvalidInput(e.to_string()))?;
    assert_eq!(lines.len(), 2);
    assert_eq!(
        at(lines.first().unwrap_or(&serde_json::Value::Null), "/folder"),
        "INBOX"
    );
    let (v, _) = exec(&b, &["list", "-a", "test", "--all-folders"])?;
    assert_eq!(at(&v, "/1/uid"), 2);
    let (v, code) = exec(&b, &["list", "-a", "test", "--ndjson", "-n", "1"])?;
    assert_eq!((code, at(&v, "/uid")), (0, &serde_json::Value::from(3)));
    Ok(())
}

#[test]
fn write_errors_are_reported() -> Result<(), Error> {
    struct Broken;
    impl Write for Broken {
        fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("closed"))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    for args in [
        &["list", "-a", "test", "--ndjson"][..],
        &["list", "-a", "test"],
        &["apply", "plan.json"],
    ] {
        let b = server_backend();
        let cli = Cli::try_parse_from(std::iter::once("mailctl").chain(args.iter().copied()))
            .map_err(|e| Error::InvalidInput(e.to_string()))?;
        assert_eq!(run(&cli, &b, &mut Broken), 2, "{args:?}");
    }
    Ok(())
}

fn with_access(access: &str) -> TestBackend {
    let mut b = TestBackend::new();
    b.config = Ok(CONFIG.replace("access = \"send\"", &format!("access = \"{access}\"")));
    b
}

/// Every changing command, live and as dry run, as plain commands and as plans.
const CHANGES: &[&[&str]] = &[
    &[
        "mark-read",
        "-a",
        "test",
        "--uid",
        "2",
        "--expect",
        "m2@test",
    ],
    &[
        "mark-read",
        "-a",
        "test",
        "--uid",
        "2",
        "--expect",
        "m2@test",
        "--dry-run",
    ],
    &[
        "move",
        "-a",
        "test",
        "--uid",
        "2",
        "--expect",
        "m2@test",
        "--to",
        "Work/GitHub",
    ],
    &[
        "move",
        "-a",
        "test",
        "--uid",
        "2",
        "--expect",
        "m2@test",
        "--to",
        "Work/GitHub",
        "--dry-run",
    ],
    &[
        "move",
        "-a",
        "test",
        "--uid",
        "2",
        "--expect",
        "m2@test",
        "--to",
        "Work/GitHub",
        "--mark-read",
    ],
    &["create-folder", "-a", "test", "New"],
    &["create-folder", "-a", "test", "New", "--dry-run"],
    &[
        "forward",
        "-a",
        "test",
        "--uid",
        "2",
        "--expect",
        "m2@test",
        "--to",
        "accounting@example.com",
    ],
    &[
        "forward",
        "-a",
        "test",
        "--uid",
        "2",
        "--expect",
        "m2@test",
        "--to",
        "accounting@example.com",
        "--dry-run",
    ],
];

const PLAN_ALL: &str = r#"{"account":"test","dry_run":DRY,"ops":[
    {"op":"mark_read","uid":2,"expect":"m2@test"},
    {"op":"move","uid":2,"expect":"m2@test","to":"Work/GitHub","mark_read":true},
    {"op":"create_folder","name":"New"},
    {"op":"forward","uid":2,"expect":"m2@test","to":"accounting@example.com"}]}"#;

#[test]
fn read_only_account_cannot_change_anything() -> Result<(), Error> {
    let mut b = with_access("read");
    let before = b.store.borrow().snapshot();
    for args in CHANGES {
        let (v, code) = exec(&b, args)?;
        assert_eq!(code, 2, "{args:?} must be refused: {v}");
        assert!(
            at(&v, "/error")
                .as_str()
                .is_some_and(|e| e.contains("is set to `read`")),
            "{args:?}: {v}"
        );
    }
    for dry in ["false", "true"] {
        b.plan = PLAN_ALL.replace("DRY", dry);
        let (v, code) = exec(&b, &["apply", "plan.json"])?;
        assert_eq!(
            (code, at(&v, "/failed")),
            (1, &serde_json::Value::from(4)),
            "{v}"
        );
    }
    assert_eq!(
        b.store.borrow().snapshot(),
        before,
        "mailbox must be unchanged"
    );
    assert_eq!(
        b.store.borrow().mutations,
        0,
        "no changing call may reach the server"
    );
    assert_eq!(b.sent.get(), 0, "no SMTP connection may be opened");
    let (v, code) = exec(&b, &["list", "-a", "test"])?;
    assert_eq!((code, at(&v, "/0/uid")), (0, &serde_json::Value::from(3)));
    assert!(
        b.store.borrow().read_only,
        "read accounts must open folders with EXAMINE"
    );
    let (_, code) = exec(&b, &["show", "-a", "test", "--uid", "2"])?;
    assert_eq!(code, 0);
    assert_eq!(
        b.store.borrow().snapshot(),
        before,
        "reading must not set \\Seen"
    );
    Ok(())
}

#[test]
fn access_matrix() -> Result<(), Error> {
    // Dry runs of: mark-read (flag), move (organize), create-folder (organize), forward (send).
    let commands: [(&[&str], Access); 4] = [
        (CHANGES.get(1).copied().unwrap_or_default(), Access::Flag),
        (
            CHANGES.get(3).copied().unwrap_or_default(),
            Access::Organize,
        ),
        (
            CHANGES.get(6).copied().unwrap_or_default(),
            Access::Organize,
        ),
        (CHANGES.get(8).copied().unwrap_or_default(), Access::Send),
    ];
    for level in [Access::Read, Access::Flag, Access::Organize, Access::Send] {
        for (args, needed) in &commands {
            let b = with_access(level.as_str());
            let (v, code) = exec(&b, args)?;
            let expected = if level >= *needed { 0 } else { 2 };
            assert_eq!(code, expected, "{level:?} {args:?}: {v}");
        }
    }
    Ok(())
}

#[test]
fn changing_commands() -> Result<(), Error> {
    let b = TestBackend::new();
    let (v, code) = exec(
        &b,
        &[
            "mark-read",
            "-a",
            "test",
            "--uid",
            "2",
            "--expect",
            "m2@test",
        ],
    )?;
    assert_eq!((code, at(&v, "/confirmed").as_bool()), (0, Some(true)));
    let (v, _) = exec(
        &b,
        &[
            "move",
            "-a",
            "test",
            "--uid",
            "3",
            "--expect",
            "m3@test",
            "--to",
            "Work/GitHub",
            "--mark-read",
            "--dry-run",
        ],
    )?;
    assert_eq!(at(&v, "/dry_run"), true);
    let (v, _) = exec(&b, &["create-folder", "-a", "test", "New", "--dry-run"])?;
    assert_eq!(at(&v, "/target"), "New");
    let (v, _) = exec(
        &b,
        &[
            "forward",
            "-a",
            "test",
            "--uid",
            "2",
            "--expect",
            "m2@test",
            "--to",
            "accounting@example.com",
            "--note",
            "Please",
            "--dry-run",
        ],
    )?;
    assert_eq!(at(&v, "/op"), "forward");
    assert_eq!(b.sent.get(), 1);
    Ok(())
}

#[test]
fn apply_plans() -> Result<(), Error> {
    let mut b = TestBackend::new();
    b.plan =
        r#"{"account":"test","ops":[{"op":"move","uid":3,"expect":"m3@test","to":"Work/GitHub"}]}"#
            .into();
    let (v, code) = exec(&b, &["apply", "plan.json"])?;
    assert_eq!((code, at(&v, "/failed").as_u64()), (0, Some(0)));
    assert_eq!(b.sent.get(), 0);
    b.plan = r#"{"account":"test","ops":[
        {"op":"forward","uid":2,"expect":"m2@test","to":"accounting@example.com"},
        {"op":"move","uid":99,"expect":"m99@test","to":"Work/GitHub"}]}"#
        .into();
    let (v, code) = exec(&b, &["apply", "-"])?;
    assert_eq!((code, at(&v, "/failed").as_u64()), (1, Some(1)));
    assert_eq!(b.sent.get(), 1);
    Ok(())
}

#[test]
fn errors_become_json() -> Result<(), Error> {
    let mut b = TestBackend::new();
    let (v, code) = exec(&b, &["list", "-a", "nope"])?;
    assert_eq!(code, 2);
    assert!(
        at(&v, "/error")
            .as_str()
            .is_some_and(|e| e.contains("unknown account"))
    );
    b.fail_connect = true;
    let (_, code) = exec(&b, &["folders", "-a", "test"])?;
    assert_eq!(code, 2);
    b.env.password = None;
    let (v, _) = exec(&b, &["folders", "-a", "test"])?;
    assert!(
        at(&v, "/error")
            .as_str()
            .is_some_and(|e| e.contains("no password"))
    );
    b.config = Err(Error::Config("missing".into()));
    let (_, code) = exec(&b, &["accounts"])?;
    assert_eq!(code, 2);
    Ok(())
}

#[test]
fn no_sender_refuses() -> Result<(), Error> {
    let addr = EmailAddress::parse("a@b.de")?;
    assert!(NoSender.send(&addr, &addr, b"x").is_err());
    Ok(())
}

/// Commands that talk to the server, with a plan for `apply`.
const SERVER_COMMANDS: &[&[&str]] = &[
    &["folders", "-a", "test"],
    &["list", "-a", "test"],
    &["list", "-a", "test", "--all-folders"],
    &["list", "-a", "test", "--ndjson", "--all-folders"],
    &["show", "-a", "test", "--uid", "2"],
    &["show", "-a", "test", "--uid", "2", "--expect", "m2@test"],
    &["apply", "plan.json"],
];

fn server_backend() -> TestBackend {
    let mut b = TestBackend::new();
    b.plan = r#"{"account":"test","ops":[
        {"op":"create_folder","name":"New"},
        {"op":"mark_read","uid":2,"expect":"m2@test"},
        {"op":"forward","uid":2,"expect":"m2@test","to":"accounting@example.com"},
        {"op":"move","uid":3,"expect":"m3@test","to":"Work/GitHub","mark_read":true}]}"#
        .into();
    b
}

/// Runs `args` with the n-th failure injected by `inject`, for n = 0, 1, …
/// until the command succeeds. Every run before must fail with a non-zero
/// exit code; returns how many failure points there were.
fn fails_at_every_step(
    args: &[&str],
    inject: &dyn Fn(&mut TestBackend, usize),
) -> Result<usize, Error> {
    for n in 0..64 {
        let mut b = server_backend();
        inject(&mut b, n);
        let cli = Cli::try_parse_from(std::iter::once("mailctl").chain(args.iter().copied()))
            .map_err(|e| Error::InvalidInput(e.to_string()))?;
        let mut out = Vec::new();
        let code = run(&cli, &b, &mut out);
        if code == 0 {
            return Ok(n);
        }
        // An ndjson listing may have printed mails before the error line.
        let text = String::from_utf8_lossy(&out);
        let last = if args.contains(&"--ndjson") {
            text.lines().last().unwrap_or_default().to_owned()
        } else {
            text.into_owned()
        };
        let v: serde_json::Value =
            serde_json::from_str(&last).map_err(|e| Error::InvalidInput(e.to_string()))?;
        let reported = at(&v, "/error").is_string() || at(&v, "/failed").as_u64() > Some(0);
        assert!(reported, "{args:?} at {n}: {v}");
    }
    Err(Error::Store(format!("{args:?} never succeeded")))
}

#[test]
fn every_backend_and_server_failure_is_reported() -> Result<(), Error> {
    for args in SERVER_COMMANDS.iter().chain(CHANGES.iter()) {
        let backend_steps = fails_at_every_step(args, &|b, n| b.fail_at = Some(n))?;
        let server_steps =
            fails_at_every_step(args, &|b, n| b.store.borrow_mut().fail_at_call = Some(n))?;
        assert!(backend_steps >= 2, "{args:?}: config and connection");
        assert!(server_steps >= 1, "{args:?}");
    }
    Ok(())
}

#[test]
fn invalid_arguments_are_refused_before_connecting() -> Result<(), Error> {
    let invalid: &[&[&str]] = &[
        &["ref", " "],
        &["list", "-a", "test", "--folder", ""],
        &["list", "-a", "test", "--before", "0"],
        &["show", "-a", "test", "--uid", "0"],
        &["show", "-a", "test", "--uid", "2", "--folder", ""],
        &["show", "-a", "test", "--uid", "2", "--expect", " "],
        &[
            "mark-read",
            "-a",
            "test",
            "--uid",
            "0",
            "--expect",
            "m2@test",
        ],
        &["mark-read", "-a", "test", "--uid", "2", "--expect", " "],
        &[
            "mark-read",
            "-a",
            "test",
            "--uid",
            "2",
            "--expect",
            "m2@test",
            "--folder",
            "",
        ],
        &[
            "move", "-a", "test", "--uid", "2", "--expect", "m2@test", "--to", "",
        ],
        &["create-folder", "-a", "test", ""],
        &[
            "forward", "-a", "test", "--uid", "2", "--expect", "m2@test", "--to", "nobody",
        ],
    ];
    for args in invalid {
        let b = TestBackend::new();
        let (v, code) = exec(&b, args)?;
        assert_eq!(code, 2, "{args:?}");
        assert!(
            at(&v, "/error")
                .as_str()
                .is_some_and(|e| e.starts_with("invalid input")),
            "{args:?}: {v}"
        );
        assert_eq!(b.store.borrow().mutations, 0, "{args:?}");
        assert_eq!(b.sent.get(), 0, "{args:?}");
    }
    let mut b = TestBackend::new();
    b.plan = "{".into();
    let (v, code) = exec(&b, &["apply", "plan.json"])?;
    assert_eq!(code, 2);
    assert!(at(&v, "/error").is_string());
    Ok(())
}

#[test]
fn broken_configuration_is_reported() -> Result<(), Error> {
    let mut b = TestBackend::new();
    b.config = Ok("x = [".into());
    for args in [&["accounts"][..], &["folders", "-a", "test"]] {
        let (v, code) = exec(&b, args)?;
        assert_eq!(code, 2, "{args:?}");
        assert!(
            at(&v, "/error")
                .as_str()
                .is_some_and(|e| e.contains("config")),
            "{args:?}: {v}"
        );
    }
    assert_eq!(b.store.borrow().calls.get(), 0);
    Ok(())
}

#[test]
fn uid_paging_is_per_folder() {
    let parsed = Cli::try_parse_from([
        "mailctl",
        "list",
        "-a",
        "test",
        "--all-folders",
        "--before",
        "5",
    ]);
    assert!(
        parsed.is_err_and(|e| e.to_string().contains("cannot be used with")),
        "UIDs of one folder must not bound the others"
    );
}
