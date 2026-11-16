//! Tests for `imap_wire`.

use super::*;

#[test]
fn maps_flags_and_attributes() {
    assert_eq!(flag_of("\\Seen"), Flag::Seen);
    assert_eq!(flag_of("\\Answered"), Flag::Answered);
    assert_eq!(flag_of("\\Flagged"), Flag::Flagged);
    assert_eq!(flag_of("\\Draft"), Flag::Draft);
    assert_eq!(flag_of("$Forwarded"), Flag::Custom("$Forwarded".into()));
    let uses: Vec<Option<String>> = [
        NameAttribute::Sent,
        NameAttribute::Drafts,
        NameAttribute::Junk,
        NameAttribute::Trash,
        NameAttribute::Archive,
        NameAttribute::All,
        NameAttribute::Flagged,
        NameAttribute::NoSelect,
    ]
    .iter()
    .map(special_use)
    .collect();
    assert_eq!(
        uses,
        [
            "sent", "drafts", "junk", "trash", "archive", "all", "flagged"
        ]
        .iter()
        .map(|s| Some((*s).to_owned()))
        .chain([None])
        .collect::<Vec<_>>()
    );
}

#[test]
fn builds_uid_sets() -> Result<(), crate::error::Error> {
    assert_eq!(
        uid_set(&[Uid::new(1)?, Uid::new(5)?, Uid::new(9)?]),
        "1,5,9"
    );
    assert_eq!(uid_set(&[]), "");
    Ok(())
}

#[test]
fn keyword_support_follows_rfc_3501() {
    let names = |list: &[&str]| list.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
    // No PERMANENTFLAGS code: all flags are permanent.
    assert!(keywords_allowed(&[]));
    assert!(keywords_allowed(&names(&["\\Seen", "\\*"])));
    assert!(keywords_allowed(&names(&["\\Seen", "$forwarded"])));
    assert!(!keywords_allowed(&names(&["\\Seen", "\\Flagged"])));
    // What the imap crate prints for the "may create" flag.
    assert_eq!(Flag::MayCreate.to_string(), "\\*");
}

#[test]
fn append_escapes_the_folder_name() -> Result<(), crate::error::Error> {
    assert_eq!(append_mailbox(&MailboxName::new("Sent")?), "Sent");
    assert_eq!(
        append_mailbox(&MailboxName::new(r#"Sent "Mail" \ Ü"#)?),
        r#"Sent \"Mail\" \\ &ANw-"#
    );
    Ok(())
}
