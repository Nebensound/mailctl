# mailctl

Safe, agent-friendly IMAP/SMTP command line tool for sorting mailboxes. It
lists, shows, moves, marks read, creates folders and forwards to an allow
list. Every command prints JSON on stdout, so scripts and AI agents can drive
it reliably.

**It never deletes mail.** There is no delete command, and moving refuses to
fall back to copy-and-expunge on servers without the IMAP `MOVE` extension.

## Installation

Binaries for macOS (Apple Silicon and Intel) and Linux (x86_64) are attached
to each [GitHub release](https://github.com/Nebensound/mailctl/releases);
unpack one and put `mailctl` on your `PATH`. The Linux binary is statically
linked (musl, OpenSSL compiled in), so it needs no particular glibc or
OpenSSL and runs in slim container images. With Rust installed:

```sh
cargo install mailctl --locked
```

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

## Coverage

This project requires 100% test coverage of its production code (regions,
lines and functions), measured with `cargo llvm-cov` on a pinned nightly
(only the coverage job; everything else builds on stable). Unit tests
live in `src/tests/` and the fakes in `src/testing.rs`; both are test code and
are not counted.

All decisions live in tested modules, including those the adapters need:
`imap_wire` (flags, UID sets, keyword support, APPEND quoting), `probe` (the
SMTP dialog before STARTTLS, handshake classification),
`config::keychain_store_command` and `Secret::from_keychain_output`. The file
handling of the system backend is tested against a temporary directory.

What remains are thin I/O wrappers that need a live IMAP or SMTP server, the
real network, a terminal or the macOS `security` tool. Each is marked
`#[cfg_attr(coverage_nightly, coverage(off))]` directly, with a
`// Coverage:` comment giving the reason, and `main` is exercised by the
release smoke test.

- **Risk:** mistakes in those wrappers (for example calling the wrong IMAP
  command) are not caught by unit tests.
- **Next step:** integration tests against a disposable IMAP/SMTP server (for
  example GreenMail or Dovecot in a container) in CI, then remove the marks
  from the IMAP and SMTP adapters.

## Releasing

1. Set `version` in `crates/mailctl/Cargo.toml`, merge that to `main`.
2. Tag the merge commit and push the tag: `git tag v0.1.0 && git push origin v0.1.0`.

The release workflow then checks that the tag matches the version and is on
`main`, runs the full CI, builds the binaries, creates the GitHub release with
them and finally publishes the crate to crates.io (a crates.io version can
never be replaced, so that comes last). It needs the secret
`CARGO_REGISTRY_TOKEN` (a crates.io API token with the `publish-update` and,
for the first release, `publish-new` scope) in the `crates-io` environment.

Repository settings that keep the release path as protected as `main`:

- Environment `crates-io`: deployment refs limited to tags matching `v*`, so
  the token is not available to branch workflows.
- A tag ruleset for `v*` that only maintainers may create, update or delete.
- After the first release, crates.io Trusted Publishing
  (`rust-lang/crates-io-auth-action`) can replace the long-lived token; the
  first publish of a new crate still needs one.

## Status

Early prototype, not yet tested against real mailboxes at scale.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in this work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.
