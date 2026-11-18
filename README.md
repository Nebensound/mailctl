# mailctl

Safe, agent-friendly IMAP/SMTP command line tool for sorting mailboxes. It
lists, shows, moves, marks read, creates folders and forwards to an allow
list. Every command prints JSON on stdout, so scripts and AI agents can drive
it reliably.

**It never deletes mail.** There is no delete command. On servers without the
IMAP `MOVE` extension (iCloud, for example) a move copies the mail and removes
the original only after its copy is confirmed in the target folder, and,
without `UIDPLUS`, only when no other mail in the folder is marked for
deletion (checked right before `EXPUNGE`; see below).

## Installation

With [Rust](https://rustup.rs) installed:

```sh
cargo install mailctl --locked
```

On Linux the build links the system OpenSSL and needs its headers and
`pkg-config` (`libssl-dev pkg-config` on Debian and Ubuntu). Without them,
compile OpenSSL in instead:

```sh
cargo install mailctl --locked --features vendored-openssl
```

There are no prebuilt binaries before 1.0.

## Safety model

- Each account has an **access level**, enforced by mailctl itself (see
  below). A `read` account cannot be changed in any way.

- Every change addresses a mail by UID **and** `--expect`, which is either the
  `Message-ID` or the ten-digit mail reference. If the mail at that UID is a
  different one, nothing happens.
- Every change is read back from the server afterwards (`"confirmed": true`).
  A move of a mail without `Message-ID` is checked only in the source folder
  (the mail is gone there) and reports `"confirmed": false`: it cannot be
  identified in the target.
- Servers without `MOVE`: the mail is copied, the copy is confirmed in the
  target by `Message-ID`, and only then is the original marked `\Deleted` and
  removed. With `UIDPLUS` exactly this mail is removed (`UID EXPUNGE`). Without
  `UIDPLUS` a plain `EXPUNGE` would remove every marked mail in the folder, so
  mailctl refuses the move while any other mail there is marked `\Deleted`,
  and checks again right before `EXPUNGE`; if another client marked one in
  between, it takes its own mark back and reports `partly done` (the copy is
  in the target, the original still in the source). One server round trip
  remains between that check and `EXPUNGE`. Mails without `Message-ID` cannot
  be moved this way, because their copy cannot be confirmed. The copy must be
  a new mail in the target: an existing mail with the same `Message-ID` (a CC
  to yourself and the list copy share one) is never taken as the copy, so a
  retry after an interruption leaves a duplicate rather than losing a mail.
- `--dry-run` checks everything and changes nothing; plans support
  `"dry_run": true`.
- `forward` only sends to addresses in `forward_allowlist`, refuses mails that
  already carry `$Forwarded`, stores a copy in the sent folder and sets
  `$Forwarded` on the original. It refuses folders whose `PERMANENTFLAGS` do
  not allow keywords; a server that sends no `PERMANENTFLAGS` at all counts as
  allowing them (RFC 3501). If the flag still does not stick, the forward is
  reported as `partly done`: do not repeat it.

## Access levels

Each level includes everything below it. New accounts start at `read`.

| Level | Allows |
|---|---|
| `read` | `folders`, `list`, `show`. Folders are opened with `EXAMINE`, so the server itself rejects changes; reading never sets `\Seen`. |
| `flag` | + `mark-read` |
| `organize` | + `move`, `create-folder` |
| `send` | + `forward` (to the allow list only), including the copy in the sent folder |

Forwarding has its own top level because it is the only action with an
effect outside the mailbox and cannot be undone.

The level is enforced in three places: every command and plan operation
checks it first (also with `--dry-run`); a guard around the IMAP connection
refuses every change above the level even if a code path forgot its check;
and below `send` no SMTP connection is opened at all. A test runs every
changing command, live and as dry run, and every plan operation against a
`read` account and asserts that the mailbox is byte-for-byte unchanged and
that no changing call reached the server.

```sh
mailctl account set-access -a work organize
```

## Mail reference

Each mail gets a stable short reference: the first ten hex digits of a SHA-256
hash of its `Message-ID` (for mails without one: date, sender, subject and
size). The same mail has the same reference in every run, report and account.

```sh
mailctl ref '<abc@example.com>'
```

## Configuration

`~/.config/mailctl/config.toml`, or `--config`, or `$MAILCTL_CONFIG`.
Passwords are never stored in this file.

```toml
forward_allowlist = ["accounting@example.com"]

[[accounts]]
name = "icloud"
access = "read"
user = "alice@icloud.com"
address = "alice@icloud.com"
imap_host = "imap.mail.me.com"
smtp_host = "smtp.mail.me.com"
sent_folder = "Sent Messages"
password = { keychain = "mailctl" }

[[accounts]]
name = "work"
access = "send"
user = "alice@example.com"
address = "alice@example.com"
imap_host = "mail.example.net"
smtp_host = "mail.example.net"
sent_folder = "INBOX.Sent"
password = { keychain = "mailctl" }

[[accounts]]
name = "home"
user = "alice@example.org"
address = "alice@example.org"
imap_host = "mail.example.net"
smtp_host = "mail.example.net"
sent_folder = "INBOX.Sent"
password = { env = "MAILCTL_PASSWORD_HOME" }
```

Host names and sent folders above are examples; check them with
`mailctl folders -a <name>`. IMAP always uses TLS from the first byte, on
`imap_port` (default 993). SMTP uses `smtp_port` (default 587) with
`smtp_security = "starttls"` or `"tls"`; `account add` stores what discovery
found, and without the key port 465 means TLS and any other port STARTTLS.
Folder names that are not valid IMAP modified UTF-7 are left out of listings.
Before storing its copy of a forward in the sent folder, mailctl looks for one
the SMTP server filed itself. Because such a copy can appear with a delay,
`save_sent_copy = false` turns the own copy off completely; `account add` sets
it for Gmail and Microsoft 365, which always file sent mail.

Passwords come from the macOS keychain (`password = { keychain = "<service>" }`;
the item's account is the mailctl account name, so two accounts with the same
login on different servers never share a password) or from an environment variable (`password = { env = "VAR" }`)
for cloud agents and CI. iCloud needs an app-specific password. Items are
keyed by service and account name, so several configuration files that use the
same account names need a keychain service each
(`account add --password-source keychain:<service>`).

```sh
security add-generic-password -s mailctl -a icloud -w
```

## Setting up accounts

```sh
mailctl account add --name icloud --address alice@icloud.com
mailctl account add --name work --address alice@example.com --access organize
mailctl allowlist add accounting@example.com
mailctl account test -a work --smtp
```

`account add` finds the servers automatically, asks for the password without
echo (or reads it with `--password-stdin`), logs in, detects the sent folder
(RFC 6154 `\Sent`, else common names), checks the SMTP login (only for
`--access send`; after raising an account to `send` later, run `account test
--smtp`), stores the password in the keychain and adds the account to the
configuration, keeping comments. `--dry-run` shows the result without writing anything.

Discovery order (like Thunderbird): built-in presets (iCloud, Gmail,
Outlook.com, GMX, WEB.DE, Posteo) → the provider's autoconfig
(`autoconfig.<domain>`, `/.well-known/autoconfig`) → Mozilla ISPDB → DNS SRV
(`_imaps._tcp`, `_submissions._tcp`, `_submission._tcp`) → MX record (ISPDB for
the MX domain, then `<mx>`, `imap.<domain>`, `mail.<domain>`). A candidate is
used only if the TLS handshake succeeds and the certificate is valid for the
host name. `mailctl account discover <address>` shows the result and a trace
of everything that was tried.

DNS answers are not authenticated. If SRV or MX records point to servers
outside the address's domain, `account add` shows them and asks before sending
the password there (RFC 6186 §6); without a terminal it needs `--yes`.
`account discover` lists such servers under `unconfirmed_hosts`.

If nothing usable is found, `account add` falls back to manual entry: in a
terminal it asks for the missing values; without a terminal it fails with the
options to pass (`--imap-host`, `--smtp-host`, `--imap-port`, `--smtp-port`,
`--user`). Values given on the command line always override discovery; with
both `--imap-host` and `--smtp-host` nothing is discovered or asked, and the
ports default to 993 and 587 and the login to the address.

Other account commands: `account test -a NAME [--smtp]`,
`account set-access -a NAME read|flag|organize|send`,
`account set-password -a NAME [--password-stdin]` (checks the login before
storing), `account remove -a NAME [--delete-password]`, and
`allowlist add|remove ADDRESS`.

## Commands

| Command | Purpose |
|---|---|
| `accounts` | Configured accounts |
| `folders -a A` | Folders with delimiter and selectability |
| `list -a A [-f F] [-n 50] [--before UID] [--ndjson] [--all-folders]` | Mails newest first, paged by UID |
| `show -a A [-f F] --uid U [--expect X] [--max-chars 4000]` | Text, recipients, attachments |
| `mark-read -a A [-f F] --uid U --expect X [--dry-run]` | Set `\Seen` |
| `move -a A [-f F] --uid U --expect X --to F2 [--mark-read] [--dry-run]` | Move within the account |
| `create-folder -a A NAME [--dry-run]` | Create a folder |
| `forward -a A [-f F] --uid U --expect X --to ADDR [--note T] [--dry-run]` | Forward with attachments |
| `apply PLAN.json` (or `-`) | Many changes over one connection |
| `ref MESSAGE-ID` | Mail reference, offline |
| `account discover\|add\|test\|set-access\|set-password\|remove` | Account setup, see above |
| `allowlist add\|remove ADDRESS` | Forward allow list |

`list` fetches headers in chunks of 500 mails. With `--ndjson` it writes one
JSON object per line (including `folder`) as soon as each chunk arrives, so a
complete listing of a large mailbox can be piped into a file. `--all-folders`
walks every selectable folder; `-n` then applies per folder. UIDs belong to
one folder, so `--before` cannot be combined with `--all-folders`.

```sh
mailctl list -a icloud --all-folders --ndjson -n 1000000 > icloud.ndjson
```

Exit codes: `0` success, `1` some plan operations failed, `2` error (the JSON
then has an `error` field).

### Plan format

```json
{
  "account": "icloud",
  "folder": "INBOX",
  "dry_run": false,
  "ops": [
    {"op": "create_folder", "name": "Newsletters/New"},
    {"op": "move", "uid": 1234, "expect": "3f9a1c07b2", "to": "Work/GitHub", "mark_read": true},
    {"op": "mark_read", "uid": 1235, "expect": "<id@host>"},
    {"op": "forward", "uid": 1236, "expect": "a1b2c3d4e5", "to": "accounting@example.com", "note": "Please book"}
  ]
}
```

Each operation is independent; failures are reported per operation and do not
stop the rest.

## Development

CI (`.github/workflows/ci.yml`) is self-contained so that anyone can reproduce
it: fmt, clippy with warnings denied, tests on Linux and macOS, `cargo
llvm-cov` with a 100% gate (see Coverage below), `cargo deny` for
licenses and advisories, and a release build with a smoke test outside the
source tree.

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --locked --all-features
cargo +nightly-2026-11-14 llvm-cov --workspace --ignore-filename-regex '(testing\.rs|src/tests/)' \
  --fail-under-lines 100 --fail-under-regions 100 --fail-under-functions 100
cargo build --release
```

Architecture: all decisions live in `service`, `plan` and `cli` and work
against the `MailStore` and `MailSender` traits; tests run them against an
in-memory mailbox (`testing.rs`). The adapters in `src/adapters/` only
translate to IMAP, SMTP, files, environment and keychain.

End-to-end tests (`src/tests/e2e.rs`) run the command line through the real
IMAP and SMTP adapters and TLS against scripted servers on local ports
(`src/tests/server/`), with a certificate authority made for each test run.
The IMAP server plays Dovecot, iCloud Mail and a server with nothing beyond
RFC 3501; each profile repeats what the real server answered to the same
commands (capabilities, `LIST` attributes, `PERMANENTFLAGS`, iCloud's header
search that never matches). The SMTP server takes STARTTLS or implicit TLS
and can file what it sends in the sent folder itself, as Gmail and
Microsoft 365 do.

## Coverage

This project requires 100% test coverage of its production code (regions,
lines and functions), measured with `cargo llvm-cov` on a pinned nightly
(only the coverage job; everything else builds on stable). Unit tests
live in `src/tests/` and the fakes in `src/testing.rs`; both are test code and
are not counted.

All decisions live in tested modules, including those the adapters need:
`imap_wire` (reading LIST, FETCH, SEARCH, CAPABILITY and SELECT responses,
command completion, flag lists, UID sets, keyword support, mailbox quoting),
`probe` (the SMTP dialog before STARTTLS, handshake classification),
`config::keychain_store_command` and `Secret::from_keychain_output`. The file
handling of the system backend is tested against a temporary directory.

The IMAP and SMTP adapters are covered by the end-to-end tests (see
Development), failure paths included: the scripted IMAP server refuses,
closes or stalls any command on request, and a test checks for every
command of each operation that a refusal or a closed connection there fails
the command line and loses no mail.

Error paths that are handled the same way are written as one `and_then`
chain, not as a row of `?`, so that one tested failure covers all of them.
Failures only the operating system can cause, such as a runtime that cannot
start, are not simulated one by one. Rewriting such a chain with `?` leaves
uncovered regions behind.

What remains are thin wrappers that need the real network (server
discovery), a terminal or the macOS `security` tool. Each is marked
`#[cfg_attr(coverage_nightly, coverage(off))]` directly, with a
`// Coverage:` comment giving the reason, and `main` is exercised by the
release smoke test.

- **Risk:** a provider that behaves unlike the scripted profiles. Changes to
  the adapters get a live check against a real account before they are
  merged (see `CONTRIBUTING.md`).

## Versioning

The version describes the command line: its commands, options, configuration
and JSON output. The Rust library in this crate is the implementation of the
command line, not a stable API; it can change in any release.

## Releasing

Every merge into `main` that changes the shipped program publishes a release;
nobody sets versions or pushes tags by hand.

- The version is derived from [Conventional
  Commits](https://www.conventionalcommits.org/) with
  [semantic-version](https://github.com/PaulHatch/semantic-version), tags
  `vX.Y.Z`: `feat:` releases a minor version, `!` after the type (`feat!:`,
  `refactor(store)!:`) or a `BREAKING CHANGE:` footer a major version, `fix:`,
  `perf:`, `deps:` (dependency updates change what `cargo install --locked`
  builds) and any other type a patch version. `build:`, `ci:`, `docs:`,
  `test:`, `chore:`, `style:` and `refactor:` release nothing on their own, as
  usual for Conventional Commits; they go out with the next release. While the
  major version is 0, everything moves one place, as Cargo treats `0.x`: `!`
  releases a minor version (`0.1.0` → `0.2.0`), `feat:` and `fix:` a patch
  version (`0.1.0` → `0.1.1`). The pull request title becomes the squash
  commit on `main`, so it must carry the type; on the pull request the version
  is derived from the branch commits, so at least one of them carries it too.
- On a pull request, CI commits the derived version to `Cargo.toml` and
  `Cargo.lock` on the branch and starts the checks again for that commit. A
  version raised by hand is kept if it is higher; a version this job set
  earlier is derived again and can go down. On `main`, CI only verifies
  that the tree carries the derived version.
- After all checks pass on `main`, CI publishes the crate to crates.io and
  then creates the tag and the GitHub release on that commit. Both publishing
  steps skip what already exists, so a failed release run is finished by
  re-running it. It needs the secret `CARGO_REGISTRY_TOKEN` (a crates.io API
  token with the `publish-update` and, for the first release, `publish-new`
  scope, whose crate scope includes `mailctl`).
- Pull requests from forks fail the version job: their version cannot be
  committed. A maintainer brings such a change in through a branch of this
  repository.

Repository settings this relies on:

- The ruleset on `main` requires the CI checks, at least `version`, with
  "Require branches to be up to date before merging". A pull request opened
  before another one was released then has to update its branch, which derives
  its version again. Merge the next pull request only after the previous
  release run has created its tag; until then the tag the derivation starts
  from does not exist yet.
- Optionally, the token lives in an environment limited to `main`, so branch
  workflows cannot read it.

## Status

Early prototype, not yet tested against real mailboxes at scale.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in this work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.
