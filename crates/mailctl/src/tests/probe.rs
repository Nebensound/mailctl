//! Tests for `probe`.

use super::*;

/// A writer that fails, as a closed connection does.
struct Closed;

impl Write for Closed {
    fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
        Err(std::io::Error::other("closed"))
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn dialog(server: &str) -> (Result<(), String>, String) {
    let mut written = Vec::new();
    let result = starttls_dialog(&mut server.as_bytes(), &mut written);
    (result, String::from_utf8_lossy(&written).into_owned())
}

#[test]
fn speaks_smtp_up_to_starttls() {
    let (result, sent) = dialog(
        "220 mail.example.net ESMTP\r\n250-mail.example.net\r\n250-SIZE 1000\r\n250 STARTTLS\r\n220 go ahead\r\n",
    );
    assert_eq!(result, Ok(()));
    assert_eq!(sent, "EHLO mailctl\r\nSTARTTLS\r\n");
}

#[test]
fn reports_every_way_the_dialog_can_fail() {
    for (server, expected) in [
        ("", "no SMTP banner"),
        ("554 go away\r\n", "unexpected banner 554 go away"),
        ("220 hi\r\n", "no EHLO reply"),
        ("220 hi\r\n250 SIZE\r\n", "server does not offer STARTTLS"),
        ("220 hi\r\n250 STARTTLS\r\n", "no STARTTLS reply"),
        (
            "220 hi\r\n250 STARTTLS\r\n454 not now\r\n",
            "STARTTLS refused: 454 not now",
        ),
    ] {
        assert_eq!(dialog(server).0, Err(expected.to_owned()), "{server:?}");
    }
    // Not valid UTF-8: read_line fails.
    let mut invalid: &[u8] = b"\xff\xfe\r\n";
    assert_eq!(
        starttls_dialog(&mut invalid, &mut Vec::new()),
        Err("no SMTP banner".to_owned())
    );
    for server in ["220 hi\r\n", "220 hi\r\n250 STARTTLS\r\n"] {
        let mut reader = server.as_bytes();
        // EHLO or STARTTLS cannot be written.
        let mut writer: Box<dyn Write> = if server.contains("STARTTLS") {
            Box::new(FailSecond::default())
        } else {
            Box::new(Closed)
        };
        assert_eq!(
            starttls_dialog(&mut reader, writer.as_mut()),
            Err("closed".to_owned()),
            "{server:?}"
        );
    }
}

/// Accepts the first write and fails the second.
#[derive(Default)]
struct FailSecond {
    writes: usize,
}

impl Write for FailSecond {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.writes = self.writes.saturating_add(1);
        if self.writes > 1 {
            Err(std::io::Error::other("closed"))
        } else {
            Ok(buf.len())
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn classifies_handshake_failures() {
    for text in [
        "certificate verify failed",
        "Hostname mismatch",
        "The certificate is not trusted",
    ] {
        assert!(
            matches!(
                handshake_failure(text.into()),
                Probe::CertificateMismatch(_)
            ),
            "{text}"
        );
    }
    assert_eq!(
        handshake_failure("connection reset".into()),
        Probe::Unreachable("connection reset".into())
    );
}
