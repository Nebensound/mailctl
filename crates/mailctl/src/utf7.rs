//! Modified UTF-7 for IMAP mailbox names (RFC 3501, section 5.1.3).

use crate::error::Error;

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+,";

/// Encodes a mailbox name for the wire.
#[must_use]
pub fn encode(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut pending: Vec<u16> = Vec::new();
    for ch in name.chars() {
        if (' '..='~').contains(&ch) {
            flush(&mut out, &mut pending);
            if ch == '&' {
                out.push_str("&-");
            } else {
                out.push(ch);
            }
        } else {
            let mut buf = [0_u16; 2];
            pending.extend_from_slice(ch.encode_utf16(&mut buf));
        }
    }
    flush(&mut out, &mut pending);
    out
}

fn flush(out: &mut String, pending: &mut Vec<u16>) {
    if pending.is_empty() {
        return;
    }
    let bytes: Vec<u8> = pending.iter().flat_map(|unit| unit.to_be_bytes()).collect();
    out.push('&');
    for chunk in bytes.chunks(3) {
        let b0 = chunk.first().copied().unwrap_or(0);
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        let n = (u32::from(b0) << 16) | (u32::from(b1) << 8) | u32::from(b2);
        let symbols = match chunk.len() {
            1 => 2,
            2 => 3,
            _ => 4,
        };
        for i in 0..symbols {
            let shift = 18_u32.saturating_sub(6_u32.saturating_mul(i));
            let index = usize::try_from((n >> shift) & 0x3f).unwrap_or(0);
            out.push(char::from(*ALPHABET.get(index).unwrap_or(&b'A')));
        }
    }
    out.push('-');
    pending.clear();
}

/// Decodes a mailbox name received from the server.
///
/// # Errors
/// Returns [`Error::InvalidInput`] for malformed shift sequences.
pub fn decode(wire: &str) -> Result<String, Error> {
    let mut out = String::with_capacity(wire.len());
    let mut rest = wire;
    while let Some(start) = rest.find('&') {
        out.push_str(rest.get(..start).unwrap_or_default());
        let after = rest.get(start.saturating_add(1)..).unwrap_or_default();
        let end = after
            .find('-')
            .ok_or_else(|| Error::InvalidInput(format!("unterminated UTF-7 in {wire:?}")))?;
        let encoded = after.get(..end).unwrap_or_default();
        if encoded.is_empty() {
            out.push('&');
        } else {
            out.push_str(&decode_chunk(encoded, wire)?);
        }
        rest = after.get(end.saturating_add(1)..).unwrap_or_default();
    }
    out.push_str(rest);
    Ok(out)
}

fn decode_chunk(encoded: &str, wire: &str) -> Result<String, Error> {
    let bad = || Error::InvalidInput(format!("invalid UTF-7 in {wire:?}"));
    let mut bits: u32 = 0;
    let mut bit_count: u32 = 0;
    let mut bytes = Vec::new();
    for symbol in encoded.bytes() {
        let value = ALPHABET.iter().position(|&a| a == symbol).ok_or_else(bad)?;
        bits = (bits << 6) | u32::try_from(value).map_err(|_| bad())?;
        bit_count = bit_count.saturating_add(6);
        if bit_count >= 8 {
            bit_count = bit_count.saturating_sub(8);
            bytes.push(u8::try_from((bits >> bit_count) & 0xff).map_err(|_| bad())?);
        }
    }
    let units: Vec<u16> = bytes
        .chunks(2)
        .map(|pair| match pair {
            [hi, lo] => Ok(u16::from_be_bytes([*hi, *lo])),
            _ => Err(bad()),
        })
        .collect::<Result<_, _>>()?;
    String::from_utf16(&units).map_err(|_| bad())
}

#[cfg(test)]
#[path = "tests/utf7.rs"]
mod tests;
