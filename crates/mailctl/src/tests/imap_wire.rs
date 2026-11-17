//! Tests for `imap_wire`.

use super::*;

/// Parses one complete server response line.
fn parse(line: &str) -> Result<Response<'_>, String> {
    match Response::parse(line.as_bytes()) {
        Ok(([], response)) => Ok(response),
        other => Err(format!("not one complete response: {line:?} -> {other:?}")),
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
fn select_keywords_follow_the_permanent_flags() -> Result<(), String> {
    let allowed = |lines: &[&str]| -> Result<bool, String> {
        let mut select = SelectKeywords::default();
        for line in lines {
            select.see(&parse(line)?);
        }
        Ok(select.allowed())
    };
    // Without PERMANENTFLAGS every flag is permanent.
    assert!(allowed(&[
        "* FLAGS (\\Seen \\Flagged)\r\n",
        "* 3 EXISTS\r\n",
        "A3 OK [READ-WRITE] SELECT completed\r\n",
    ])?);
    // An explicit empty list means none is.
    assert!(!allowed(&[
        "* OK [PERMANENTFLAGS ()] No permanent flags\r\n",
        "A3 OK [READ-WRITE] SELECT completed\r\n",
    ])?);
    // A code on the tagged completion itself counts too.
    assert!(allowed(&[
        "A3 OK [PERMANENTFLAGS (\\Seen \\*)] SELECT completed\r\n"
    ])?);
    Ok(())
}

#[test]
fn a_missing_response_is_an_error() {
    assert_eq!(received(Ok(Some(7))), Ok(7));
    assert_eq!(
        received::<u8>(Ok(None)),
        Err("the server closed the connection".to_owned())
    );
    let eof = std::io::Error::from(std::io::ErrorKind::UnexpectedEof);
    assert_eq!(
        received::<u8>(Err(eof)),
        Err("the server closed the connection".to_owned())
    );
    let closed = std::io::Error::other("connection closed gracefully");
    assert_eq!(
        received::<u8>(Err(closed)),
        Err("connection closed gracefully".to_owned())
    );
}

#[test]
fn reads_folders_from_list_responses() -> Result<(), String> {
    let folder = listed_folder(&parse(
        "* LIST (\\HasNoChildren \\Sent) \".\" \"INBOX.Beh&APY-rden\"\r\n",
    )?)
    .ok_or("no folder")?;
    assert_eq!(folder.name.as_str(), "INBOX.Behörden");
    assert_eq!(folder.delimiter.as_deref(), Some("."));
    assert!(folder.selectable);
    assert_eq!(folder.special_use.as_deref(), Some("sent"));

    let parent =
        listed_folder(&parse("* LIST (\\Noselect) NIL \"Archive\"\r\n")?).ok_or("no folder")?;
    assert!(!parent.selectable);
    assert_eq!(parent.delimiter, None);
    assert_eq!(parent.special_use, None);

    // Not modified UTF-7: skipped.
    assert!(listed_folder(&parse("* LIST () \"/\" \"Bad&Name\"\r\n")?).is_none());
    assert!(listed_folder(&parse("* 3 EXISTS\r\n")?).is_none());
    Ok(())
}

#[test]
fn reads_the_requested_attributes_of_a_fetch() -> Result<(), String> {
    let header = fetched(&parse(
        "* 2 FETCH (UID 7 FLAGS (\\Seen $Forwarded) RFC822.SIZE 42 BODY[HEADER] {13}\r\nSubject: Hi\r\n)\r\n",
    )?);
    assert_eq!(
        header,
        Some(Fetched {
            uid: Some(7),
            flags: vec!["\\Seen".to_owned(), "$Forwarded".to_owned()],
            size: Some(42),
            header: Some(b"Subject: Hi\r\n".to_vec()),
            body: None,
        })
    );
    let body = fetched(&parse(
        "* 2 FETCH (UID 7 BODY[] {5}\r\nHello INTERNALDATE \"17-Nov-2026 10:00:00 +0000\")\r\n",
    )?)
    .ok_or("no fetch")?;
    assert_eq!(body.body.as_deref(), Some(&b"Hello"[..]));
    // A flag change another client made comes without UID.
    let unasked = fetched(&parse("* 1 FETCH (FLAGS (\\Seen))\r\n")?).ok_or("no fetch")?;
    assert_eq!(unasked.uid, None);
    assert_eq!(fetched(&parse("* SEARCH 1 2\r\n")?), None);
    Ok(())
}

#[test]
fn reads_search_results() -> Result<(), String> {
    assert_eq!(searched(&parse("* SEARCH 2 84 882\r\n")?), [2, 84, 882]);
    assert_eq!(searched(&parse("* SEARCH\r\n")?), Vec::<u32>::new());
    assert_eq!(searched(&parse("* 3 EXISTS\r\n")?), Vec::<u32>::new());
    Ok(())
}

#[test]
fn finds_capabilities() -> Result<(), String> {
    let capabilities = parse("* CAPABILITY IMAP4rev1 UIDPLUS move AUTH=PLAIN\r\n")?;
    assert!(has_capability(&capabilities, "UIDPLUS"));
    assert!(has_capability(&capabilities, "MOVE"));
    assert!(!has_capability(&capabilities, "PLAIN"));
    assert!(!has_capability(&parse("* 3 EXISTS\r\n")?, "MOVE"));
    Ok(())
}
