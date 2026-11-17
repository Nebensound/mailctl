//! Tests for `imap_wire`.

use std::borrow::Cow;

use super::*;

/// Parses one complete server response line.
fn parse(line: &str) -> Result<Response<'_>, String> {
    match Response::parse(line.as_bytes()) {
        Ok(([], response)) => Ok(response),
        other => Err(format!("not one complete response: {line:?} -> {other:?}")),
    }
}

#[test]
fn names_every_flag() {
    let names: Vec<String> = [
        Flag::Seen,
        Flag::Answered,
        Flag::Flagged,
        Flag::Deleted,
        Flag::Draft,
        Flag::Recent,
        Flag::MayCreate,
        Flag::Custom(Cow::Borrowed("$Forwarded")),
    ]
    .iter()
    .map(flag_name)
    .collect();
    assert_eq!(
        names,
        [
            "\\Seen",
            "\\Answered",
            "\\Flagged",
            "\\Deleted",
            "\\Draft",
            "\\Recent",
            "\\*",
            "$Forwarded"
        ]
    );
}

#[test]
fn flag_names_round_trip_through_the_parser() {
    for name in [
        "\\Seen",
        "\\Answered",
        "\\Flagged",
        "\\Draft",
        "\\*",
        "$Forwarded",
    ] {
        assert_eq!(flag_name(&Flag::from(name)), name);
    }
}

#[test]
fn builds_flag_lists() {
    assert_eq!(flag_list(&["\\Seen", "$Forwarded"]), "(\\Seen $Forwarded)");
    assert_eq!(flag_list(&["\\Seen"]), "(\\Seen)");
    assert_eq!(flag_list(&[]), "()");
}

#[test]
fn maps_special_use_attributes() {
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
fn reads_permanent_flags_from_responses() -> Result<(), String> {
    assert_eq!(
        permanent_flags(&parse("* OK [PERMANENTFLAGS (\\Seen \\*)] Limited\r\n")?),
        Some(vec!["\\Seen".to_owned(), "\\*".to_owned()])
    );
    assert_eq!(
        permanent_flags(&parse("* OK [PERMANENTFLAGS ()] None\r\n")?),
        Some(Vec::new())
    );
    // Servers may also put the code on the tagged completion.
    assert_eq!(
        permanent_flags(&parse("A1 OK [PERMANENTFLAGS ($Forwarded)] Done\r\n")?),
        Some(vec!["$Forwarded".to_owned()])
    );
    // Other codes, codeless status responses and other data carry none.
    assert_eq!(
        permanent_flags(&parse("* OK [UIDVALIDITY 3857529045] UIDs\r\n")?),
        None
    );
    assert_eq!(permanent_flags(&parse("* OK Ready\r\n")?), None);
    assert_eq!(permanent_flags(&parse("* 3 EXISTS\r\n")?), None);
    Ok(())
}

#[test]
fn keyword_support_follows_rfc_3501() {
    let flags = |list: &[&str]| list.iter().map(|f| (*f).to_owned()).collect::<Vec<_>>();
    // No PERMANENTFLAGS code: all flags are permanent.
    assert!(keywords_allowed(None));
    // An explicit empty list: nothing is permanent.
    assert!(!keywords_allowed(Some(&[])));
    assert!(keywords_allowed(Some(&flags(&["\\Seen", "\\*"]))));
    assert!(keywords_allowed(Some(&flags(&["\\Seen", "$forwarded"]))));
    assert!(!keywords_allowed(Some(&flags(&["\\Seen", "\\Flagged"]))));
}

#[test]
fn keyword_support_from_a_parsed_select() -> Result<(), String> {
    let judge = |line: &str| -> Result<bool, String> {
        Ok(keywords_allowed(permanent_flags(&parse(line)?).as_deref()))
    };
    assert!(!judge("* OK [PERMANENTFLAGS ()] No permanent flags\r\n")?);
    assert!(judge("* OK [PERMANENTFLAGS (\\Seen \\*)] Limited\r\n")?);
    assert!(judge("* ok [permanentflags (\\Seen $forwarded)] x\r\n")?);
    assert!(!judge("* OK [PERMANENTFLAGS (\\Seen \\Flagged)] x\r\n")?);
    Ok(())
}

#[test]
fn recognizes_the_end_of_a_command() -> Result<(), String> {
    let tag = RequestId("A7".to_owned());
    assert_eq!(
        command_done(&parse("A7 OK [READ-WRITE] SELECT completed\r\n")?, &tag),
        Some(Ok(()))
    );
    assert_eq!(
        command_done(&parse("A7 NO Mailbox does not exist\r\n")?, &tag),
        Some(Err("No: Mailbox does not exist".to_owned()))
    );
    assert_eq!(
        command_done(&parse("A7 BAD\r\n")?, &tag),
        Some(Err("Bad: ".to_owned()))
    );
    assert_eq!(
        command_done(&parse("* BYE Shutting down\r\n")?, &tag),
        Some(Err("server closed the connection: Shutting down".to_owned()))
    );
    // Another command's completion and untagged data keep it running.
    assert_eq!(command_done(&parse("A6 OK Done\r\n")?, &tag), None);
    assert_eq!(command_done(&parse("* 3 EXISTS\r\n")?, &tag), None);
    assert_eq!(command_done(&parse("* OK Still here\r\n")?, &tag), None);
    Ok(())
}

#[test]
fn quotes_mailbox_names() -> Result<(), crate::error::Error> {
    assert_eq!(quoted_mailbox(&MailboxName::new("Sent")?), "\"Sent\"");
    assert_eq!(
        quoted_mailbox(&MailboxName::new(r#"Sent "Mail" \ Ü"#)?),
        r#""Sent \"Mail\" \\ &ANw-""#
    );
    Ok(())
}

#[test]
fn select_reader_follows_a_select() -> Result<(), String> {
    let run = |lines: &[&str]| -> Result<Vec<Option<Result<bool, String>>>, String> {
        let mut reader = SelectReader::new(RequestId("A3".to_owned()));
        lines
            .iter()
            .map(|line| Ok(reader.feed(&parse(line)?)))
            .collect()
    };
    // Without PERMANENTFLAGS every flag is permanent.
    assert_eq!(
        run(&[
            "* FLAGS (\\Seen \\Flagged)\r\n",
            "* 3 EXISTS\r\n",
            "A3 OK [READ-WRITE] SELECT completed\r\n",
        ])?,
        [None, None, Some(Ok(true))]
    );
    // An explicit empty list on an untagged response counts at completion.
    assert_eq!(
        run(&[
            "* OK [PERMANENTFLAGS ()] No permanent flags\r\n",
            "A3 OK [READ-WRITE] SELECT completed\r\n",
        ])?,
        [None, Some(Ok(false))]
    );
    // A code on the tagged completion itself counts too.
    assert_eq!(
        run(&["A3 OK [PERMANENTFLAGS (\\Seen \\*)] SELECT completed\r\n"])?,
        [Some(Ok(true))]
    );
    // A refused SELECT reports the server's reason.
    assert_eq!(
        run(&["A3 NO No such mailbox\r\n"])?,
        [Some(Err("No: No such mailbox".to_owned()))]
    );
    Ok(())
}
