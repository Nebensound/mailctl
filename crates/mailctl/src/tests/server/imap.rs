//! A scripted `IMAP4rev1` server over implicit TLS. It knows the commands
//! mailctl sends and answers them the way the [`Profile`] it plays does.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead as _, BufReader, Read as _, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex, MutexGuard};

use rustls::{ServerConfig, ServerConnection, StreamOwned};

use super::{TestCa, limit_silence};

/// The login the server accepts.
pub(crate) const USER: &str = "alice@example.com";
/// The password the server accepts.
pub(crate) const PASSWORD: &str = "pw";

/// How a server answers. The values are taken from what the real servers
/// sent to the same commands.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Profile {
    /// Capabilities after login.
    capabilities: &'static str,
    /// Hierarchy delimiter in `LIST`.
    pub(crate) delimiter: char,
    /// `UID SEARCH HEADER` finds mail.
    header_search: bool,
    /// An empty search result still sends an untagged `SEARCH` line.
    empty_search_line: bool,
    /// The `PERMANENTFLAGS` code after `SELECT`; `None` leaves it out.
    select_permanent: Option<&'static str>,
    /// The `PERMANENTFLAGS` code after `EXAMINE`; `None` leaves it out.
    examine_permanent: Option<&'static str>,
}

impl Profile {
    fn has(&self, capability: &str) -> bool {
        self.capabilities.split(' ').any(|c| c == capability)
    }
}

/// Dovecot at a hosting provider: `MOVE`, `UIDPLUS`, `SPECIAL-USE`, folders
/// below `INBOX` with `.` as delimiter, and an empty `PERMANENTFLAGS` after
/// `EXAMINE`.
pub(crate) const DOVECOT: Profile = Profile {
    capabilities: "IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE SORT UNSELECT CHILDREN \
        NAMESPACE UIDPLUS LIST-EXTENDED CONDSTORE QRESYNC ESEARCH LIST-STATUS BINARY MOVE \
        SPECIAL-USE LITERAL+ QUOTA",
    delimiter: '.',
    header_search: true,
    empty_search_line: true,
    select_permanent: Some(r"\Answered \Flagged \Deleted \Seen \Draft $Forwarded $NotJunk \*"),
    examine_permanent: Some(""),
};

/// iCloud Mail: no `MOVE` but `UIDPLUS`, special-use attributes without the
/// `SPECIAL-USE` capability, `/` as delimiter, and a header search that never
/// finds anything and then sends no untagged `SEARCH` line at all.
pub(crate) const ICLOUD: Profile = Profile {
    capabilities: "XAPPLEPUSHSERVICE IMAP4 IMAP4rev1 CONDSTORE ENABLE QRESYNC QUOTA \
        XAPPLELITERAL NAMESPACE UIDPLUS UNSELECT SORT ESEARCH ESORT CONTEXT=SORT WITHIN SASL-IR \
        ID IDLE X-APPLE-REMOTE-LINKS LIST-STATUS",
    delimiter: '/',
    header_search: false,
    empty_search_line: false,
    select_permanent: Some(
        r"\Answered \Flagged \Draft \Deleted \Seen \Recent $MailFlagBit0 $MailFlagBit1 $MailFlagBit2 $Forwarded Redirected $NotJunk NotJunk $iCloudCleanup \*",
    ),
    examine_permanent: Some(
        r"\Answered \Flagged \Draft \Deleted \Seen \Recent $MailFlagBit0 $MailFlagBit1 $MailFlagBit2 $Forwarded Redirected $NotJunk NotJunk $iCloudCleanup \*",
    ),
};

/// Nothing beyond RFC 3501: no `MOVE`, no `UIDPLUS`, no `PERMANENTFLAGS` code.
pub(crate) const RFC3501: Profile = Profile {
    capabilities: "IMAP4rev1",
    delimiter: '/',
    header_search: true,
    empty_search_line: true,
    select_permanent: None,
    examine_permanent: None,
};

/// A failure the server plays instead of answering a command.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Fault {
    /// Answer `NO`.
    No,
    /// Never answer, as a stalled server.
    Stall,
    /// Close the connection cleanly (TLS `close_notify`).
    Close,
}

/// One stored mail.
#[derive(Clone, Debug)]
pub(crate) struct Message {
    pub(crate) uid: u32,
    pub(crate) flags: BTreeSet<String>,
    pub(crate) body: Vec<u8>,
}

impl Message {
    /// The value of a header field, unfolded headers only.
    pub(crate) fn header(&self, name: &str) -> Option<String> {
        String::from_utf8_lossy(header_part(&self.body))
            .split("\r\n")
            .find_map(|line| {
                let (key, value) = line.split_once(':')?;
                key.eq_ignore_ascii_case(name)
                    .then(|| value.trim().to_owned())
            })
    }
}

#[derive(Debug, Default)]
struct Folder {
    /// `LIST` attributes, e.g. `\Sent`.
    attributes: String,
    messages: Vec<Message>,
    next_uid: u32,
}

impl Folder {
    fn add(&mut self, body: Vec<u8>, flags: BTreeSet<String>) -> u32 {
        let uid = self.next_uid.max(1);
        self.next_uid = uid.saturating_add(1);
        self.messages.push(Message { uid, flags, body });
        uid
    }
}

#[derive(Debug, Default)]
struct State {
    /// By the name on the wire (modified UTF-7).
    folders: BTreeMap<String, Folder>,
    /// Every command received, as its name (`LOGIN`, `UID MOVE`, …).
    commands: Vec<String>,
    /// `LOGIN` takes any password for [`USER`].
    any_password: bool,
    /// The fault played at the command with this index in `commands`.
    fault: Option<(usize, Fault)>,
    /// Close each connection before the greeting.
    close_before_greeting: bool,
    /// Before the command with this index, mark this mail deleted, as
    /// another client would meanwhile: folder and UID.
    delete_meanwhile: Option<(usize, String, u32)>,
    /// An untagged FETCH line (a flag change, with or without UID) to send
    /// along with every `UID FETCH`, as a server does when another client
    /// changed a flag meanwhile.
    unsolicited_fetch: Option<String>,
}

fn lock(state: &Mutex<State>) -> Result<MutexGuard<'_, State>, String> {
    state.lock().map_err(|e| e.to_string())
}

/// A running server; its threads end with the test process.
#[derive(Clone)]
pub(crate) struct ImapServer {
    pub(crate) port: u16,
    state: Arc<Mutex<State>>,
}

impl ImapServer {
    /// Starts a server with these folders (wire name, `LIST` attributes).
    pub(crate) fn start(
        ca: &TestCa,
        profile: Profile,
        folders: &[(&str, &str)],
    ) -> Result<Self, String> {
        let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
        let port = listener.local_addr().map_err(|e| e.to_string())?.port();
        let state = Arc::new(Mutex::new(State {
            folders: folders
                .iter()
                .map(|(name, attributes)| {
                    let folder = Folder {
                        attributes: (*attributes).to_owned(),
                        ..Folder::default()
                    };
                    ((*name).to_owned(), folder)
                })
                .collect(),
            commands: Vec::new(),
            any_password: false,
            fault: None,
            close_before_greeting: false,
            delete_meanwhile: None,
            unsolicited_fetch: None,
        }));
        let shared = Arc::clone(&state);
        let config = Arc::clone(&ca.config);
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                limit_silence(&stream);
                let (config, state) = (Arc::clone(&config), Arc::clone(&shared));
                std::thread::spawn(move || serve(stream, config, profile, &state));
            }
        });
        Ok(Self { port, state })
    }

    /// Stores a mail (lines joined with CRLF) and returns its UID.
    pub(crate) fn add(&self, folder: &str, lines: &[&str], flags: &[&str]) -> Result<u32, String> {
        let body = format!("{}\r\n", lines.join("\r\n")).into_bytes();
        self.put(
            folder,
            body,
            flags.iter().map(|f| (*f).to_owned()).collect(),
        )
    }

    /// Stores a mail as it is and returns its UID.
    pub(crate) fn put(
        &self,
        folder: &str,
        body: Vec<u8>,
        flags: BTreeSet<String>,
    ) -> Result<u32, String> {
        let mut state = lock(&self.state)?;
        let folder = state
            .folders
            .get_mut(folder)
            .ok_or_else(|| format!("no folder {folder}"))?;
        Ok(folder.add(body, flags))
    }

    /// The mails of a folder.
    pub(crate) fn messages(&self, folder: &str) -> Result<Vec<Message>, String> {
        lock(&self.state)?
            .folders
            .get(folder)
            .map(|f| f.messages.clone())
            .ok_or_else(|| format!("no folder {folder}"))
    }

    /// The folder names on the wire.
    pub(crate) fn folders(&self) -> Result<Vec<String>, String> {
        Ok(lock(&self.state)?.folders.keys().cloned().collect())
    }

    /// Lets `LOGIN` take any password, so that a test can fail SMTP alone.
    pub(crate) fn accept_any_password(&self) -> Result<(), String> {
        lock(&self.state)?.any_password = true;
        Ok(())
    }

    /// Plays `fault` at the command with this index (counted over all
    /// connections, as in [`Self::commands`]).
    pub(crate) fn fail_at(&self, index: usize, fault: Fault) -> Result<(), String> {
        lock(&self.state)?.fault = Some((index, fault));
        Ok(())
    }

    /// Marks a mail deleted right before the command with this index, as
    /// another client would meanwhile.
    pub(crate) fn delete_meanwhile(
        &self,
        index: usize,
        folder: &str,
        uid: u32,
    ) -> Result<(), String> {
        lock(&self.state)?.delete_meanwhile = Some((index, folder.to_owned(), uid));
        Ok(())
    }

    /// Closes each connection right after the TLS handshake.
    pub(crate) fn close_before_greeting(&self) -> Result<(), String> {
        lock(&self.state)?.close_before_greeting = true;
        Ok(())
    }

    /// Sends `line`, an untagged FETCH such as a flag change with or without
    /// UID, along with every `UID FETCH`.
    pub(crate) fn send_unsolicited_fetch(&self, line: &str) -> Result<(), String> {
        lock(&self.state)?.unsolicited_fetch = Some(line.to_owned());
        Ok(())
    }

    /// The commands received so far.
    pub(crate) fn commands(&self) -> Result<Vec<String>, String> {
        Ok(lock(&self.state)?.commands.clone())
    }
}

/// A token of a command line.
#[derive(Clone, Debug, PartialEq)]
enum Token {
    Atom(String),
    Quoted(String),
    List(Vec<Token>),
    Literal(Vec<u8>),
}

impl Token {
    fn text(&self) -> Option<&str> {
        match self {
            Self::Atom(s) | Self::Quoted(s) => Some(s),
            Self::List(_) | Self::Literal(_) => None,
        }
    }
}

/// Splits a command line (without a trailing literal) into tokens.
fn tokens(line: &str) -> Result<Vec<Token>, String> {
    tokens_until(&mut line.chars().peekable(), None)
}

fn tokens_until(
    chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
    end: Option<char>,
) -> Result<Vec<Token>, String> {
    let mut out = Vec::new();
    loop {
        match chars.next() {
            None if end.is_none() => return Ok(out),
            None => return Err("unterminated list".into()),
            Some(c) if Some(c) == end => return Ok(out),
            Some(' ') => {}
            Some('(') => out.push(Token::List(tokens_until(chars, Some(')'))?)),
            Some('"') => {
                let mut text = String::new();
                loop {
                    match chars.next() {
                        None => return Err("unterminated string".into()),
                        Some('"') => break,
                        Some('\\') => text.extend(chars.next()),
                        Some(c) => text.push(c),
                    }
                }
                out.push(Token::Quoted(text));
            }
            Some(c) => {
                let mut atom = String::from(c);
                while let Some(&next) = chars.peek() {
                    if next == ' ' || next == '(' || next == ')' || next == '"' {
                        break;
                    }
                    atom.push(next);
                    chars.next();
                }
                out.push(Token::Atom(atom));
            }
        }
    }
}

/// The header block of a mail, including the blank line after it.
fn header_part(body: &[u8]) -> &[u8] {
    body.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .and_then(|at| body.get(..at.saturating_add(4)))
        .unwrap_or(body)
}

/// Whether `uid` is in an IMAP UID set such as `1,3:5,7:*`.
fn in_set(uid: u32, set: &str) -> bool {
    set.split(',').any(|range| {
        let (low, high) = range.split_once(':').unwrap_or((range, range));
        let bound = |s: &str| {
            if s == "*" {
                Some(u32::MAX)
            } else {
                s.parse().ok()
            }
        };
        match (bound(low), bound(high)) {
            (Some(a), Some(b)) => (a.min(b)..=a.max(b)).contains(&uid),
            _ => false,
        }
    })
}

fn flag_list(flags: &BTreeSet<String>) -> String {
    flags.iter().cloned().collect::<Vec<_>>().join(" ")
}

fn flag_set(token: Option<&Token>) -> BTreeSet<String> {
    match token {
        Some(Token::List(items)) => items
            .iter()
            .filter_map(Token::text)
            .map(str::to_owned)
            .collect(),
        Some(token) => token.text().map(str::to_owned).into_iter().collect(),
        None => BTreeSet::new(),
    }
}

type Stream = BufReader<StreamOwned<ServerConnection, TcpStream>>;

/// One client connection; a broken connection just ends it.
fn serve(stream: TcpStream, config: Arc<ServerConfig>, profile: Profile, state: &Mutex<State>) {
    let Ok(connection) = ServerConnection::new(config) else {
        return;
    };
    let mut stream = BufReader::new(StreamOwned::new(connection, stream));
    let mut session = Session {
        profile,
        state,
        logged_in: false,
        selected: None,
        read_only: false,
    };
    let _ = session.run(&mut stream);
}

struct Session<'a> {
    profile: Profile,
    state: &'a Mutex<State>,
    logged_in: bool,
    selected: Option<String>,
    read_only: bool,
}

/// The answer to one command: untagged lines and the tagged status.
struct Reply {
    untagged: Vec<Vec<u8>>,
    status: String,
}

impl Reply {
    fn ok(text: &str) -> Self {
        Self {
            untagged: Vec::new(),
            status: format!("OK {text}"),
        }
    }
    fn no(text: &str) -> Self {
        Self {
            untagged: Vec::new(),
            status: format!("NO {text}"),
        }
    }
    fn bad(text: &str) -> Self {
        Self {
            untagged: Vec::new(),
            status: format!("BAD {text}"),
        }
    }
    fn with(mut self, line: impl Into<Vec<u8>>) -> Self {
        self.untagged.push(line.into());
        self
    }
}

fn send(stream: &mut Stream, line: &[u8]) -> Result<(), String> {
    let out = stream.get_mut();
    out.write_all(line)
        .and_then(|()| out.write_all(b"\r\n"))
        .and_then(|()| out.flush())
        .map_err(|e| e.to_string())
}

/// Ends the connection cleanly, after completing the TLS handshake if no
/// byte was exchanged yet.
fn close(stream: &mut Stream) -> Result<(), String> {
    let out = stream.get_mut();
    while out.conn.is_handshaking() {
        out.conn
            .complete_io(&mut out.sock)
            .map_err(|e| e.to_string())?;
    }
    out.conn.send_close_notify();
    out.flush().map_err(|e| e.to_string())
}

/// Reads one line without CRLF; `None` at the end of the connection.
fn read_line(stream: &mut Stream) -> Result<Option<String>, String> {
    let mut line = Vec::new();
    let n = stream
        .read_until(b'\n', &mut line)
        .map_err(|e| e.to_string())?;
    if n == 0 {
        return Ok(None);
    }
    while line.last().is_some_and(|b| *b == b'\n' || *b == b'\r') {
        line.pop();
    }
    String::from_utf8(line).map(Some).map_err(|e| e.to_string())
}

/// Takes the command name (two words for `UID …`) off the arguments.
fn command_name(args: &mut Vec<Token>) -> String {
    let mut words = Vec::new();
    while let Some(word) = args.first().and_then(Token::text).map(str::to_uppercase) {
        args.remove(0);
        let more = word == "UID";
        words.push(word);
        if !more {
            break;
        }
    }
    words.join(" ")
}

/// A trailing `{n}` announcing a literal: the line before it and `n`.
fn literal_size(line: &str) -> Option<(&str, usize)> {
    let open = line.strip_suffix('}')?.rfind('{')?;
    let size = line.get(open.saturating_add(1)..line.len().saturating_sub(1))?;
    Some((line.get(..open)?, size.parse().ok()?))
}

/// The FETCH items this server answers.
const FETCH_ITEMS: [&str; 7] = [
    "UID",
    "FLAGS",
    "RFC822.SIZE",
    "BODY.PEEK[HEADER]",
    "BODY[HEADER]",
    "BODY.PEEK[]",
    "BODY[]",
];

impl Session<'_> {
    fn run(&mut self, stream: &mut Stream) -> Result<(), String> {
        if lock(self.state)?.close_before_greeting {
            return close(stream);
        }
        send(stream, b"* OK [CAPABILITY IMAP4rev1] scripted server ready")?;
        while let Some(line) = read_line(stream)? {
            let (tag, rest) = line.split_once(' ').unwrap_or((line.as_str(), ""));
            let mut args = match literal_size(rest) {
                Some((before, size)) => {
                    send(stream, b"+ Ready for literal data")?;
                    let mut literal = vec![0; size];
                    stream.read_exact(&mut literal).map_err(|e| e.to_string())?;
                    let tail = read_line(stream)?.unwrap_or_default();
                    let mut args = tokens(before)?;
                    args.push(Token::Literal(literal));
                    args.extend(tokens(&tail)?);
                    args
                }
                None => tokens(rest)?,
            };
            let name = command_name(&mut args);
            let fault = {
                let mut state = lock(self.state)?;
                state.commands.push(name.clone());
                let index = state.commands.len().saturating_sub(1);
                if let Some((at, folder, uid)) = state.delete_meanwhile.clone()
                    && at == index
                    && let Some(message) = state
                        .folders
                        .get_mut(&folder)
                        .and_then(|f| f.messages.iter_mut().find(|m| m.uid == uid))
                {
                    message.flags.insert(r"\Deleted".to_owned());
                }
                state
                    .fault
                    .and_then(|(at, fault)| (at == index).then_some(fault))
            };
            let reply = match fault {
                None => self.handle(&name, &args)?,
                Some(Fault::No) => Reply::no("[UNAVAILABLE] scripted failure"),
                Some(Fault::Stall) => {
                    while read_line(stream)?.is_some() {}
                    return Ok(());
                }
                Some(Fault::Close) => return close(stream),
            };
            for line in &reply.untagged {
                send(stream, line)?;
            }
            send(stream, format!("{tag} {}", reply.status).as_bytes())?;
            if name == "LOGOUT" {
                return Ok(());
            }
        }
        Ok(())
    }

    fn handle(&mut self, name: &str, args: &[Token]) -> Result<Reply, String> {
        let text = |i: usize| args.get(i).and_then(Token::text).unwrap_or_default();
        if !self.logged_in && !matches!(name, "CAPABILITY" | "LOGIN" | "LOGOUT") {
            return Ok(Reply::bad("log in first"));
        }
        let needs_folder = name.starts_with("UID ") || name == "EXPUNGE";
        if needs_folder && self.selected.is_none() {
            return Ok(Reply::bad("no mailbox selected"));
        }
        Ok(match name {
            "CAPABILITY" => Reply::ok("CAPABILITY completed").with(if self.logged_in {
                format!("* CAPABILITY {}", self.profile.capabilities)
            } else {
                "* CAPABILITY IMAP4rev1 AUTH=PLAIN".to_owned()
            }),
            "LOGIN"
                if text(0) == USER && (text(1) == PASSWORD || lock(self.state)?.any_password) =>
            {
                self.logged_in = true;
                Reply::ok("Logged in")
            }
            "LOGIN" => Reply::no("[AUTHENTICATIONFAILED] Authentication failed."),
            "LOGOUT" => Reply::ok("Logout completed").with("* BYE Logging out"),
            "NOOP" => Reply::ok("NOOP completed"),
            "LIST" => self.list()?,
            "SELECT" | "EXAMINE" => self.select(text(0), name == "EXAMINE")?,
            "CREATE" => self.create(text(0))?,
            "APPEND" => self.append(args)?,
            "EXPUNGE" => self.expunge(None)?,
            "UID SEARCH" => self.search(args)?,
            "UID FETCH" => self.fetch(text(0), args.get(1))?,
            "UID STORE" => self.store(text(0), text(1), args.get(2))?,
            "UID COPY" => self.copy(text(0), text(1), false)?,
            // MOVE expunges from the source, which a read-only mailbox refuses.
            "UID MOVE" if self.profile.has("MOVE") && self.read_only => {
                Reply::no("Mailbox is read-only")
            }
            "UID MOVE" if self.profile.has("MOVE") => self.copy(text(0), text(1), true)?,
            "UID EXPUNGE" if self.profile.has("UIDPLUS") => self.expunge(Some(text(0)))?,
            _ => Reply::bad("unknown command"),
        })
    }

    fn list(&self) -> Result<Reply, String> {
        let state = lock(self.state)?;
        Ok(state
            .folders
            .iter()
            .fold(Reply::ok("LIST completed"), |reply, (name, folder)| {
                reply.with(format!(
                    "* LIST ({}) \"{}\" \"{name}\"",
                    folder.attributes, self.profile.delimiter
                ))
            }))
    }

    fn select(&mut self, folder: &str, read_only: bool) -> Result<Reply, String> {
        let state = lock(self.state)?;
        let Some(found) = state.folders.get(folder) else {
            self.selected = None;
            return Ok(Reply::no("Mailbox doesn't exist"));
        };
        self.selected = Some(folder.to_owned());
        self.read_only = read_only;
        let permanent = if read_only {
            self.profile.examine_permanent
        } else {
            self.profile.select_permanent
        };
        let mut reply = Reply::ok(if read_only {
            "[READ-ONLY] EXAMINE completed"
        } else {
            "[READ-WRITE] SELECT completed"
        })
        .with(r"* FLAGS (\Answered \Flagged \Deleted \Seen \Draft)");
        if let Some(flags) = permanent {
            reply = reply.with(format!("* OK [PERMANENTFLAGS ({flags})] Flags permitted."));
        }
        Ok(reply
            .with(format!("* {} EXISTS", found.messages.len()))
            .with("* 0 RECENT")
            .with("* OK [UIDVALIDITY 1] UIDs valid")
            .with(format!(
                "* OK [UIDNEXT {}] Predicted next UID",
                found.next_uid.max(1)
            )))
    }

    fn create(&self, folder: &str) -> Result<Reply, String> {
        let mut state = lock(self.state)?;
        if state.folders.contains_key(folder) {
            return Ok(Reply::no("[ALREADYEXISTS] Mailbox already exists"));
        }
        state.folders.insert(folder.to_owned(), Folder::default());
        Ok(Reply::ok("Create completed"))
    }

    fn append(&self, args: &[Token]) -> Result<Reply, String> {
        let folder = args.first().and_then(Token::text).unwrap_or_default();
        let flags = flag_set(args.get(1).filter(|t| matches!(t, Token::List(_))));
        let Some(Token::Literal(body)) = args.iter().find(|t| matches!(t, Token::Literal(_)))
        else {
            return Ok(Reply::bad("APPEND without a message"));
        };
        let mut state = lock(self.state)?;
        let Some(target) = state.folders.get_mut(folder) else {
            return Ok(Reply::no("[TRYCREATE] Mailbox doesn't exist"));
        };
        let uid = target.add(body.clone(), flags);
        Ok(if self.profile.has("UIDPLUS") {
            Reply::ok(&format!("[APPENDUID 1 {uid}] Append completed"))
        } else {
            Reply::ok("Append completed")
        })
    }

    /// Runs `f` on the selected folder.
    fn with_folder<T>(&self, f: impl FnOnce(&mut Folder) -> T) -> Result<T, String> {
        let mut state = lock(self.state)?;
        let name = self.selected.as_deref().unwrap_or_default();
        state
            .folders
            .get_mut(name)
            .map(f)
            .ok_or_else(|| format!("selected folder {name} is gone"))
    }

    fn search(&self, args: &[Token]) -> Result<Reply, String> {
        let key = args
            .first()
            .and_then(Token::text)
            .unwrap_or_default()
            .to_uppercase();
        let field = args.get(1).and_then(Token::text).unwrap_or_default();
        let value = args
            .get(2)
            .and_then(Token::text)
            .unwrap_or_default()
            .to_lowercase();
        // A real server answers BAD to criteria it cannot parse; an empty
        // result here would hide a search this server does not know.
        if !matches!(key.as_str(), "ALL" | "DELETED" | "HEADER") {
            return Ok(Reply::bad("unsupported search key"));
        }
        let profile = self.profile;
        let found = self.with_folder(|folder| {
            folder
                .messages
                .iter()
                .filter(|m| match key.as_str() {
                    "ALL" => true,
                    "DELETED" => m.flags.contains(r"\Deleted"),
                    "HEADER" => {
                        profile.header_search
                            && m.header(field)
                                .is_some_and(|v| v.to_lowercase().contains(&value))
                    }
                    _ => false,
                })
                .map(|m| m.uid.to_string())
                .collect::<Vec<_>>()
        })?;
        let reply = Reply::ok("SEARCH completed");
        Ok(if found.is_empty() && !self.profile.empty_search_line {
            reply
        } else if found.is_empty() {
            reply.with("* SEARCH")
        } else {
            reply.with(format!("* SEARCH {}", found.join(" ")))
        })
    }

    fn fetch(&self, set: &str, items: Option<&Token>) -> Result<Reply, String> {
        let items: Vec<String> = match items {
            Some(Token::List(list)) => list
                .iter()
                .filter_map(Token::text)
                .map(str::to_uppercase)
                .collect(),
            Some(item) => item.text().map(str::to_uppercase).into_iter().collect(),
            None => Vec::new(),
        };
        // As with SEARCH: BAD instead of silently leaving an item out.
        if !items.iter().all(|i| FETCH_ITEMS.contains(&i.as_str())) {
            return Ok(Reply::bad("unsupported fetch item"));
        }
        let read_only = self.read_only;
        let unsolicited = lock(self.state)?.unsolicited_fetch.clone();
        let lines = self.with_folder(|folder| {
            let mut lines = Vec::new();
            if let Some(line) = unsolicited.filter(|_| !folder.messages.is_empty()) {
                lines.push(line.into_bytes());
            }
            for (index, message) in folder.messages.iter_mut().enumerate() {
                if !in_set(message.uid, set) {
                    continue;
                }
                if !read_only && items.iter().any(|i| i.starts_with("BODY[")) {
                    message.flags.insert(r"\Seen".to_owned());
                }
                let mut line = format!("* {} FETCH (UID {}", index.saturating_add(1), message.uid)
                    .into_bytes();
                for item in &items {
                    match item.as_str() {
                        "FLAGS" => {
                            line.extend(format!(" FLAGS ({})", flag_list(&message.flags)).bytes());
                        }
                        "RFC822.SIZE" => {
                            line.extend(format!(" RFC822.SIZE {}", message.body.len()).bytes());
                        }
                        "BODY.PEEK[HEADER]" | "BODY[HEADER]" => {
                            let header = header_part(&message.body);
                            line.extend(format!(" BODY[HEADER] {{{}}}\r\n", header.len()).bytes());
                            line.extend_from_slice(header);
                        }
                        "BODY.PEEK[]" | "BODY[]" => {
                            line.extend(format!(" BODY[] {{{}}}\r\n", message.body.len()).bytes());
                            line.extend_from_slice(&message.body);
                        }
                        // `UID` is already in the line; the rest are refused above.
                        _ => {}
                    }
                }
                line.push(b')');
                lines.push(line);
            }
            lines
        })?;
        Ok(lines
            .into_iter()
            .fold(Reply::ok("FETCH completed"), Reply::with))
    }

    fn store(&self, set: &str, operation: &str, flags: Option<&Token>) -> Result<Reply, String> {
        if self.read_only {
            return Ok(Reply::no("Mailbox is read-only"));
        }
        let flags = flag_set(flags);
        let operation = operation.to_uppercase();
        let lines = self.with_folder(|folder| {
            let mut lines = Vec::new();
            for (index, message) in folder.messages.iter_mut().enumerate() {
                if !in_set(message.uid, set) {
                    continue;
                }
                match operation.trim_end_matches(".SILENT") {
                    "+FLAGS" => message.flags.extend(flags.iter().cloned()),
                    "-FLAGS" => message.flags.retain(|f| !flags.contains(f)),
                    _ => message.flags.clone_from(&flags),
                }
                if !operation.ends_with(".SILENT") {
                    lines.push(format!(
                        "* {} FETCH (UID {} FLAGS ({}))",
                        index.saturating_add(1),
                        message.uid,
                        flag_list(&message.flags)
                    ));
                }
            }
            lines
        })?;
        Ok(lines
            .into_iter()
            .fold(Reply::ok("STORE completed"), Reply::with))
    }

    /// `UID COPY`, or `UID MOVE` with `remove`.
    fn copy(&self, set: &str, target: &str, remove: bool) -> Result<Reply, String> {
        let source = self.selected.clone().unwrap_or_default();
        let mut state = lock(self.state)?;
        if !state.folders.contains_key(target) {
            return Ok(Reply::no("[TRYCREATE] Mailbox doesn't exist"));
        }
        let picked: Vec<Message> = state
            .folders
            .get(&source)
            .map(|f| {
                f.messages
                    .iter()
                    .filter(|m| in_set(m.uid, set))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();
        let mut mapping = Vec::new();
        if let Some(folder) = state.folders.get_mut(target) {
            for message in &picked {
                let uid = folder.add(message.body.clone(), message.flags.clone());
                mapping.push((message.uid, uid));
            }
        }
        let mut reply = Reply::ok(&if self.profile.has("UIDPLUS") && !mapping.is_empty() {
            let (from, to): (Vec<String>, Vec<String>) = mapping
                .iter()
                .map(|(a, b)| (a.to_string(), b.to_string()))
                .unzip();
            format!("[COPYUID 1 {} {}] completed", from.join(","), to.join(","))
        } else {
            "completed".to_owned()
        });
        if remove && let Some(folder) = state.folders.get_mut(&source) {
            for line in remove_where(folder, |m| in_set(m.uid, set)) {
                reply = reply.with(line);
            }
        }
        Ok(reply)
    }

    /// `EXPUNGE`, or `UID EXPUNGE` with a set.
    fn expunge(&self, set: Option<&str>) -> Result<Reply, String> {
        if self.read_only {
            return Ok(Reply::no("Mailbox is read-only"));
        }
        let lines = self.with_folder(|folder| {
            remove_where(folder, |m| {
                m.flags.contains(r"\Deleted") && set.is_none_or(|s| in_set(m.uid, s))
            })
        })?;
        Ok(lines
            .into_iter()
            .fold(Reply::ok("EXPUNGE completed"), Reply::with))
    }
}

/// Removes the matching mails and returns the `EXPUNGE` lines, each with the
/// sequence number at the time it is sent.
fn remove_where(folder: &mut Folder, matches: impl Fn(&Message) -> bool) -> Vec<String> {
    let mut lines = Vec::new();
    let mut index = 0_usize;
    while let Some(message) = folder.messages.get(index) {
        if matches(message) {
            folder.messages.remove(index);
            lines.push(format!("* {} EXPUNGE", index.saturating_add(1)));
        } else {
            index = index.saturating_add(1);
        }
    }
    lines
}
