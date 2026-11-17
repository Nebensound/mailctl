//! [`MailSender`] over SMTP: STARTTLS, or implicit TLS on port 465.

use lettre::address::{Address, Envelope};
use lettre::transport::smtp::authentication::Credentials;
use lettre::transport::smtp::client::{Certificate, CertificateStore, Tls, TlsParameters};
use lettre::{SmtpTransport, Transport};

use crate::adapters::net::Trust;
use crate::config::{AccountConfig, Secret};
use crate::error::Error;
use crate::store::MailSender;
use crate::types::{EmailAddress, Security};

/// An SMTP transport for one account.
pub struct SmtpSender {
    transport: SmtpTransport,
}

fn send_err(e: impl std::fmt::Display) -> Error {
    Error::Send(e.to_string())
}

impl SmtpSender {
    /// Prepares the transport; the connection is opened on send.
    ///
    /// # Errors
    /// Invalid host configuration.
    pub fn new(account: &AccountConfig, secret: &Secret) -> Result<Self, Error> {
        Self::new_with(account, secret, &Trust::System)
    }

    /// Prepares the transport, trusting the certificates `trust` names.
    ///
    /// # Errors
    /// Invalid host configuration or certificate.
    pub(crate) fn new_with(
        account: &AccountConfig,
        secret: &Secret,
        trust: &Trust,
    ) -> Result<Self, Error> {
        let mut parameters = TlsParameters::builder(account.smtp_host.clone());
        if let Trust::Only(pem) = trust {
            parameters = parameters
                .certificate_store(CertificateStore::None)
                .add_root_certificate(Certificate::from_pem(pem).map_err(send_err)?);
        }
        parameters
            .build()
            .map(|parameters| {
                let tls = match account.smtp_tls() {
                    Security::Tls => Tls::Wrapper(parameters),
                    Security::StartTls => Tls::Required(parameters),
                };
                // `builder_dangerous` only means "no TLS unless set"; it is
                // always set here, as `relay` and `starttls_relay` would.
                let transport = SmtpTransport::builder_dangerous(&account.smtp_host)
                    .port(account.smtp_port)
                    .tls(tls)
                    .credentials(Credentials::new(
                        account.smtp_login().to_owned(),
                        secret.expose().to_owned(),
                    ))
                    .build();
                Self { transport }
            })
            .map_err(send_err)
    }

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

impl MailSender for SmtpSender {
    fn send(
        &mut self,
        from: &EmailAddress,
        to: &EmailAddress,
        message: &[u8],
    ) -> Result<(), Error> {
        let address = |a: &EmailAddress| a.as_str().parse::<Address>().map_err(send_err);
        address(from)
            .and_then(|from| address(to).map(|to| (from, to)))
            .and_then(|(from, to)| Envelope::new(Some(from), vec![to]).map_err(send_err))
            .and_then(|envelope| {
                self.transport
                    .send_raw(&envelope, message)
                    .map(|_| ())
                    .map_err(send_err)
            })
    }
}
