//! A scripted SMTP submission server: STARTTLS or implicit TLS, `AUTH PLAIN`,
//! and optionally a copy of each message filed in an IMAP folder, as Gmail and
//! Microsoft 365 do with the mail they send.

use std::collections::BTreeSet;
use std::io::{BufRead as _, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use base64::Engine as _;
use rustls::{ServerConfig, ServerConnection, StreamOwned};

use super::imap::{ImapServer, PASSWORD, USER};
use super::{TestCa, limit_silence};

/// How the client secures the connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Mode {
    /// Plain greeting, then `STARTTLS` (port 587).
    StartTls,
    /// TLS from the first byte (port 465).
    Tls,
}

/// One accepted message.
#[derive(Clone, Debug)]
pub(crate) struct Accepted {
    pub(crate) from: String,
    pub(crate) to: Vec<String>,
    pub(crate) data: Vec<u8>,
}

/// The IMAP folder the server files a copy of each message in.
pub(crate) type Filing = Option<(ImapServer, String)>;

/// A running server; its threads end with the test process.
pub(crate) struct SmtpServer {
    pub(crate) port: u16,
    accepted: Arc<Mutex<Vec<Accepted>>>,
    refuse_noop: Arc<AtomicBool>,
}

impl SmtpServer {
    pub(crate) fn start(ca: &TestCa, mode: Mode, filing: Filing) -> Result<Self, String> {
        let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
        let port = listener.local_addr().map_err(|e| e.to_string())?.port();
        let accepted = Arc::new(Mutex::new(Vec::new()));
        let shared = Arc::clone(&accepted);
        let config = Arc::clone(&ca.config);
        let filing = Arc::new(filing);
        let refuse_noop = Arc::new(AtomicBool::new(false));
        let refuse = Arc::clone(&refuse_noop);
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                limit_silence(&stream);
                let context = Context {
                    accepted: Arc::clone(&shared),
                    filing: Arc::clone(&filing),
                    refuse_noop: Arc::clone(&refuse),
                };
                let config = Arc::clone(&config);
                std::thread::spawn(move || serve(stream, config, mode, &context));
            }
        });
        Ok(Self {
            port,
            accepted,
            refuse_noop,
        })
    }

    /// Answers `NOOP` with an error, which fails a connection test.
    pub(crate) fn refuse_noop(&self) {
        self.refuse_noop.store(true, Ordering::Relaxed);
    }

    /// The messages accepted so far.
    pub(crate) fn accepted(&self) -> Result<Vec<Accepted>, String> {
        self.accepted
            .lock()
            .map(|list| list.clone())
            .map_err(|e| e.to_string())
    }
}

struct Context {
    accepted: Arc<Mutex<Vec<Accepted>>>,
    filing: Arc<Filing>,
    refuse_noop: Arc<AtomicBool>,
}

impl Context {
    fn accept(&self, message: Accepted) -> Result<(), String> {
        if let Some((imap, folder)) = self.filing.as_ref() {
            imap.put(
                folder,
                message.data.clone(),
                BTreeSet::from([r"\Seen".to_owned()]),
            )?;
        }
        self.accepted
            .lock()
            .map_err(|e| e.to_string())?
            .push(message);
        Ok(())
    }
}

/// One client connection; a broken connection just ends it.
fn serve(stream: TcpStream, config: Arc<ServerConfig>, mode: Mode, context: &Context) {
    let _ = match mode {
        Mode::Tls => ServerConnection::new(config)
            .map_err(|e| e.to_string())
            .and_then(|connection| {
                let mut reader = BufReader::new(StreamOwned::new(connection, stream));
                dialog(&mut reader, true, true, context)
            }),
        Mode::StartTls => {
            let mut reader = BufReader::new(stream);
            dialog(&mut reader, true, false, context).and_then(|upgrade| {
                if !upgrade {
                    return Ok(false);
                }
                let connection = ServerConnection::new(config).map_err(|e| e.to_string())?;
                let mut reader = BufReader::new(StreamOwned::new(connection, reader.into_inner()));
                dialog(&mut reader, false, true, context)
            })
        }
    };
}

fn reply<S: Write>(reader: &mut BufReader<S>, text: &str) -> Result<(), String> {
    let out = reader.get_mut();
    out.write_all(text.as_bytes())
        .and_then(|()| out.write_all(b"\r\n"))
        .and_then(|()| out.flush())
        .map_err(|e| e.to_string())
}

/// Reads one line without CRLF; `None` at the end of the connection.
fn read_line<S: Read>(reader: &mut BufReader<S>) -> Result<Option<Vec<u8>>, String> {
    let mut line = Vec::new();
    if reader
        .read_until(b'\n', &mut line)
        .map_err(|e| e.to_string())?
        == 0
    {
        return Ok(None);
    }
    while line.last().is_some_and(|b| *b == b'\n' || *b == b'\r') {
        line.pop();
    }
    Ok(Some(line))
}

/// The address between `<` and `>`.
fn address(line: &str) -> Option<String> {
    let (_, rest) = line.split_once('<')?;
    let (address, _) = rest.split_once('>')?;
    Some(address.to_owned())
}

/// Whether an `AUTH PLAIN` line carries the expected login.
fn plain_login(line: &str) -> bool {
    let expected = format!("\0{USER}\0{PASSWORD}");
    line.split(' ')
        .nth(2)
        .and_then(|encoded| {
            base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .ok()
        })
        .is_some_and(|decoded| decoded == expected.as_bytes())
}

/// The message after `DATA`, up to the line with a single dot.
fn read_data<S: Read>(reader: &mut BufReader<S>) -> Result<Vec<u8>, String> {
    let mut data = Vec::new();
    while let Some(line) = read_line(reader)? {
        if line == b"." {
            return Ok(data);
        }
        data.extend_from_slice(line.strip_prefix(b".").unwrap_or(&line));
        data.extend_from_slice(b"\r\n");
    }
    Err("connection closed during DATA".into())
}

/// Runs the dialog; `Ok(true)` when the client asked for `STARTTLS`. A new
/// connection starts with the greeting (`greet`); after `STARTTLS` the client
/// speaks first.
fn dialog<S: Read + Write>(
    reader: &mut BufReader<S>,
    greet: bool,
    secure: bool,
    context: &Context,
) -> Result<bool, String> {
    if greet {
        reply(reader, "220 localhost ESMTP scripted server")?;
    }
    let mut authenticated = false;
    let mut from = String::new();
    let mut to = Vec::new();
    while let Some(line) = read_line(reader)? {
        let line = String::from_utf8_lossy(&line).into_owned();
        let verb = line.split(' ').next().unwrap_or_default().to_uppercase();
        match verb.as_str() {
            "EHLO" | "HELO" if secure => reply(reader, "250-localhost\r\n250 AUTH PLAIN")?,
            "EHLO" | "HELO" => reply(reader, "250-localhost\r\n250 STARTTLS")?,
            "STARTTLS" if !secure => {
                reply(reader, "220 2.0.0 Ready to start TLS")?;
                return Ok(true);
            }
            "AUTH" if !secure => reply(reader, "530 5.7.0 Must issue a STARTTLS command first")?,
            "AUTH" if plain_login(&line) => {
                authenticated = true;
                reply(reader, "235 2.7.0 Authentication successful")?;
            }
            "AUTH" => reply(reader, "535 5.7.8 Authentication credentials invalid")?,
            "MAIL" | "RCPT" | "DATA" if !authenticated => {
                reply(reader, "530 5.7.0 Authentication required")?;
            }
            "MAIL" => {
                from = address(&line).unwrap_or_default();
                to.clear();
                reply(reader, "250 2.1.0 Ok")?;
            }
            "RCPT" => {
                to.extend(address(&line));
                reply(reader, "250 2.1.5 Ok")?;
            }
            "DATA" => {
                reply(reader, "354 End data with <CR><LF>.<CR><LF>")?;
                let data = read_data(reader)?;
                context.accept(Accepted {
                    from: std::mem::take(&mut from),
                    to: std::mem::take(&mut to),
                    data,
                })?;
                reply(reader, "250 2.0.0 Ok: queued")?;
            }
            "RSET" => {
                from.clear();
                to.clear();
                reply(reader, "250 2.0.0 Ok")?;
            }
            "NOOP" if context.refuse_noop.load(Ordering::Relaxed) => {
                reply(reader, "554 5.0.0 scripted failure")?;
            }
            "NOOP" => reply(reader, "250 2.0.0 Ok")?,
            "QUIT" => {
                reply(reader, "221 2.0.0 Bye")?;
                return Ok(false);
            }
            _ => reply(reader, "502 5.5.2 Command not recognized")?,
        }
    }
    Ok(false)
}
