# mailctl

Safe, agent-friendly IMAP/SMTP command line tool for sorting mailboxes. It
lists, shows, moves, marks read, creates folders and forwards to an allow
list. Every command prints JSON on stdout, so scripts and AI agents can drive
it reliably.

**It never deletes mail.** There is no delete command, and moving refuses to
fall back to copy-and-expunge on servers without the IMAP `MOVE` extension.

## Safety model

- Each account has an **access level**, enforced by mailctl itself (see
  below). A `read` account cannot be changed in any way.

- Every change addresses a mail by UID **and** `--expect`, which is either the
  `Message-ID` or the ten-digit mail reference. If the mail at that UID is a
  different one, nothing happens.
- Every change is read back from the server afterwards (`"confirmed": true`).
- `--dry-run` checks everything and changes nothing; plans support
  `"dry_run": true`.
- `forward` only sends to addresses in `forward_allowlist`, refuses mails that
  already carry `$Forwarded`, stores a copy in the sent folder and sets
  `$Forwarded` on the original.

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
`mailctl folders -a <name>`. Defaults: IMAP port 993 (TLS), SMTP port 587
(STARTTLS; port 465 uses implicit TLS).

Passwords come from the macOS keychain (`password = { keychain = "<service>" }`,
account = `user`) or from an environment variable (`password = { env = "VAR" }`)
for cloud agents and CI. iCloud needs an app-specific password.

```sh
security add-generic-password -s mailctl -a alice@icloud.com -w
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
(RFC 6154 `\Sent`, else common names), checks the SMTP login, stores the
password in the keychain and adds the account to the configuration, keeping
comments. `--dry-run` shows the result without writing anything.

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
storing), `account remove -a NAME [--delete-password]` (keeps a keychain item
that another account still uses), and `allowlist add|remove ADDRESS`.

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
llvm-cov` with a 100% gate (see the deviation below), `cargo deny` for
licenses and advisories, and a release build with a smoke test outside the
source tree.

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --locked --all-features
cargo llvm-cov --workspace --ignore-filename-regex '(adapters/|main\.rs|testing\.rs|src/tests/)' \
  --fail-under-lines 100 --fail-under-regions 100 --fail-under-functions 100
cargo build --release
```

Architecture: all decisions live in `service`, `plan` and `cli` and work
against the `MailStore` and `MailSender` traits; tests run them against an
in-memory mailbox (`testing.rs`). The adapters in `src/adapters/` only
translate to IMAP, SMTP, files, environment and keychain.

## Coverage deviation

This project requires 100% test coverage of its production code (regions,
lines and functions). It excludes `src/adapters/` (IMAP, SMTP, HTTPS/DNS/TLS probes,
keychain, terminal, files) and `src/main.rs` from the gate. Unit tests live in
`src/tests/` and the fakes in `src/testing.rs`; both are test code and are not
counted as production coverage.

- **Risk:** errors in the translation to IMAP/SMTP (command syntax, folder
  encoding, flag names) are not caught by unit tests.
- **Rationale:** they need a real mail server; they contain no decisions,
  which all live in tested modules. Folder-name encoding (`utf7`) is
  separately tested.
- **Migration target:** integration tests against a disposable IMAP/SMTP
  server (for example GreenMail or Dovecot in a container) in CI, then remove
  the exclusion.

Measured locally with `cargo tarpaulin` (LLVM tools matching rustc were not
available in the build environment): 99.7% of lines, the only reported gaps
being four lines (struct-literal fields, a multi-line call and a method-chain
line) that every test executes — a known
line-attribution artefact of tarpaulin. CI must run `cargo llvm-cov` as
listed above.

`src/testing.rs` is test-only code (`#[cfg(test)]`) and not production code.

## Status

0.0.3, early prototype. Not yet published on crates.io.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in this work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.
