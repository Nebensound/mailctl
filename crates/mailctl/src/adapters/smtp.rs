//! [`MailSender`] over SMTP: STARTTLS, or implicit TLS on port 465.

use lettre::address::Envelope;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{SmtpTransport, Transport};

use crate::config::{AccountConfig, Secret};
use crate::error::Error;
use crate::store::MailSender;
use crate::types::EmailAddress;

/// An SMTP transport for one account.
pub struct SmtpSender {
    transport: SmtpTransport,
}

// Coverage: only reached when a live SMTP server fails.
#[cfg_attr(coverage_nightly, coverage(off))]
fn send_err(e: impl std::fmt::Display) -> Error {
    Error::Send(e.to_string())
}

// Coverage: builds a lettre transport; the security mode is decided by `AccountConfig::smtp_tls`.
#[cfg_attr(coverage_nightly, coverage(off))]
impl SmtpSender {
    /// Prepares the transport; the connection is opened on send.
    ///
    /// # Errors
    /// Invalid host configuration.
    pub fn new(account: &AccountConfig, secret: &Secret) -> Result<Self, Error> {
        let builder = if account.smtp_tls() == crate::types::Security::Tls {
            SmtpTransport::relay(&account.smtp_host)
        } else {
            SmtpTransport::starttls_relay(&account.smtp_host)
        }
        .map_err(send_err)?;
        let transport = builder
            .port(account.smtp_port)
            .credentials(Credentials::new(
                account.smtp_login().to_owned(),
                secret.expose().to_owned(),
            ))
            .build();
        Ok(Self { transport })
    }
}

// Coverage: needs a live SMTP server.
#[cfg_attr(coverage_nightly, coverage(off))]
impl SmtpSender {
    /// Connects and logs in without sending anything.
    ///
    /// # Errors
    /// Connection or login errors.
    pub fn check(&self) -> Result<(), Error> {
        match self.transport.test_connection() {
            Ok(true) => Ok(()),
            Ok(false) => Err(Error::Send("SMTP connection test failed".into())),
            Err(e) => Err(send_err(e)),
        }
    }
}

// Coverage: needs a live SMTP server.
#[cfg_attr(coverage_nightly, coverage(off))]
impl MailSender for SmtpSender {
    fn send(
        &mut self,
        from: &EmailAddress,
        to: &EmailAddress,
        message: &[u8],
    ) -> Result<(), Error> {
        let envelope = Envelope::new(
            Some(from.as_str().parse().map_err(send_err)?),
            vec![to.as_str().parse().map_err(send_err)?],
        )
        .map_err(send_err)?;
        self.transport
            .send_raw(&envelope, message)
            .map(|_| ())
            .map_err(send_err)
    }
}
