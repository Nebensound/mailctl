//! The decisions of a TLS probe, kept apart from the sockets: the SMTP
//! dialog before STARTTLS and how a failed handshake is classified.

use std::io::{BufRead, Write};

use crate::discover::Probe;

/// Reads one SMTP reply, following `250-` continuation lines.
fn read_reply(reader: &mut dyn BufRead) -> Option<String> {
    let mut reply = String::new();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).ok()? == 0 {
            return None;
        }
        reply.push_str(&line);
        if line.as_bytes().get(3) != Some(&b'-') {
            return Some(reply);
        }
    }
}

/// The SMTP dialog up to the TLS handshake: banner, `EHLO`, `STARTTLS`.
///
/// # Errors
/// What went wrong, for the discovery trace.
pub fn starttls_dialog(reader: &mut dyn BufRead, writer: &mut dyn Write) -> Result<(), String> {
    let banner = read_reply(reader).ok_or("no SMTP banner")?;
    if !banner.starts_with("220") {
        return Err(format!("unexpected banner {}", banner.trim()));
    }
    writer
        .write_all(b"EHLO mailctl\r\n")
        .map_err(|e| e.to_string())?;
    let ehlo = read_reply(reader).ok_or("no EHLO reply")?;
    if !ehlo.to_uppercase().contains("STARTTLS") {
        return Err("server does not offer STARTTLS".into());
    }
    writer
        .write_all(b"STARTTLS\r\n")
        .map_err(|e| e.to_string())?;
    let ready = read_reply(reader).ok_or("no STARTTLS reply")?;
    if ready.starts_with("220") {
        Ok(())
    } else {
        Err(format!("STARTTLS refused: {}", ready.trim()))
    }
}

/// A failed TLS handshake: a certificate problem means the host is the wrong
/// name for this server (common on shared hosting); anything else means it
/// is not reachable.
#[must_use]
pub fn handshake_failure(text: String) -> Probe {
    let lower = text.to_lowercase();
    if lower.contains("certificate") || lower.contains("hostname") || lower.contains("not trusted")
    {
        Probe::CertificateMismatch(text)
    } else {
        Probe::Unreachable(text)
    }
}

#[cfg(test)]
#[path = "tests/probe.rs"]
mod tests;
