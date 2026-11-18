# Contributing

The checks, the architecture and the coverage rules are described in the
README sections Development and Coverage; run all checks locally before you
push. Commit messages and pull request titles follow Conventional Commits,
which decide the next version (README section Versioning).

## Live check against a real account

The end-to-end tests run against scripted servers that repeat what real
providers answered. A provider can still behave differently, so a change to
the IMAP or SMTP adapters gets a live check before it is merged (every merge
into `main` is released).

Use an account you can afford to touch, with `access = "organize"` (`"send"`
for the forward step), and a mail you may move. mailctl cannot delete
anything: remove the test folder and the forwarded copy by hand afterwards.

```sh
mailctl account test -a NAME --smtp
mailctl folders -a NAME
mailctl list -a NAME --limit 5
mailctl show -a NAME --uid UID
mailctl create-folder -a NAME mailctl-test
mailctl move -a NAME --uid UID --expect REF --to mailctl-test
mailctl list -a NAME -f mailctl-test --limit 1        # the mail's new UID
mailctl move -a NAME -f mailctl-test --uid NEW --expect REF --to INBOX
mailctl mark-read -a NAME --uid UID --expect REF
mailctl forward -a NAME --uid UID --expect REF --to ADDRESS_ON_THE_ALLOW_LIST
```

`REF` is the mail's `mail_ref` from `list`. Every command must exit with 0
and report the change as confirmed. Note the provider in the pull request.

If a provider behaves in a way no profile in `src/tests/server/imap.rs`
covers, add a profile built from that server's actual responses and a test
for the behaviour.
