//! [`Net`] over the real network: HTTPS, DNS and TLS probes.

use std::io::{BufReader, Read};
use std::net::{TcpStream, ToSocketAddrs as _};
use std::time::Duration;

use hickory_resolver::TokioResolver;
use hickory_resolver::proto::rr::RData;

use crate::discover::{Endpoint, Net, Probe, Security, SrvRecord};
use crate::probe::{handshake_failure, starttls_dialog};

/// Timeout for every network step.
const TIMEOUT: Duration = Duration::from_secs(8);

/// The certificates the IMAP and SMTP adapters trust.
#[derive(Debug)]
pub(crate) enum Trust {
    /// The operating system's root certificates, as in production.
    System,
    /// Only this certificate authority (PEM), for tests against a local
    /// server.
    #[cfg_attr(not(test), expect(dead_code, reason = "only tests use their own CA"))]
    Only(Vec<u8>),
}

/// Connects to the first address of `host` that accepts a connection within
/// `timeout` each. Trying all of them matters where the resolver returns an
/// IPv6 address first on a network without IPv6.
///
/// # Errors
/// The error of the last address tried, or of the name lookup.
pub(crate) fn connect_any(host: &str, port: u16, timeout: Duration) -> std::io::Result<TcpStream> {
    let mut last = std::io::Error::new(std::io::ErrorKind::NotFound, "no address");
    for address in (host, port).to_socket_addrs()? {
        match TcpStream::connect_timeout(&address, timeout) {
            Ok(stream) => return Ok(stream),
            Err(e) => last = e,
        }
    }
    Err(last)
}

/// Network access for discovery.
pub struct SystemNet {
    agent: ureq::Agent,
    dns: Option<(tokio::runtime::Runtime, TokioResolver)>,
}

// Coverage: builds the HTTP agent and DNS resolver for the real network.
#[cfg_attr(coverage_nightly, coverage(off))]
impl Default for SystemNet {
    fn default() -> Self {
        let agent = ureq::Agent::config_builder()
            .timeout_global(Some(TIMEOUT))
            .tls_config(
                ureq::tls::TlsConfig::builder()
                    .provider(ureq::tls::TlsProvider::NativeTls)
                    .build(),
            )
            .build()
            .new_agent();
        let dns = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .ok()
            .and_then(|rt| {
                let resolver = TokioResolver::builder_tokio().ok()?.build().ok()?;
                Some((rt, resolver))
            });
        Self { agent, dns }
    }
}

// Coverage: socket wrapper; the dialog itself is `probe::starttls_dialog`.
#[cfg_attr(coverage_nightly, coverage(off))]
fn starttls_upgrade(stream: &TcpStream) -> Result<(), String> {
    starttls_dialog(&mut BufReader::new(stream), &mut &*stream)
}

// Coverage: needs the real network; the decisions are in `discover` and `probe`.
#[cfg_attr(coverage_nightly, coverage(off))]
impl Net for SystemNet {
    fn http_get(&mut self, url: &str) -> Option<String> {
        let mut response = self.agent.get(url).call().ok()?;
        let mut body = String::new();
        response
            .body_mut()
            .as_reader()
            .take(1 << 20)
            .read_to_string(&mut body)
            .ok()?;
        Some(body)
    }

    fn srv(&mut self, name: &str) -> Vec<SrvRecord> {
        let Some((rt, resolver)) = &self.dns else {
            return Vec::new();
        };
        rt.block_on(resolver.srv_lookup(name))
            .map(|lookup| {
                lookup
                    .answers()
                    .iter()
                    .filter_map(|record| match &record.data {
                        RData::SRV(srv) => Some(SrvRecord {
                            target: srv.target.to_string(),
                            port: srv.port,
                            priority: srv.priority,
                            weight: srv.weight,
                        }),
                        _ => None,
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    fn mx(&mut self, domain: &str) -> Vec<String> {
        let Some((rt, resolver)) = &self.dns else {
            return Vec::new();
        };
        let mut hosts: Vec<(u16, String)> = rt
            .block_on(resolver.mx_lookup(domain))
            .map(|lookup| {
                lookup
                    .answers()
                    .iter()
                    .filter_map(|record| match &record.data {
                        RData::MX(mx) => Some((mx.preference, mx.exchange.to_string())),
                        _ => None,
                    })
                    .collect()
            })
            .unwrap_or_default();
        hosts.sort();
        hosts
            .into_iter()
            .map(|(_, host)| host.trim_end_matches('.').to_owned())
            .collect()
    }

    fn probe(&mut self, endpoint: &Endpoint) -> Probe {
        let stream = match connect_any(&endpoint.host, endpoint.port, TIMEOUT) {
            Ok(stream) => stream,
            Err(e) => return Probe::Unreachable(e.to_string()),
        };
        let _ = stream.set_read_timeout(Some(TIMEOUT));
        let _ = stream.set_write_timeout(Some(TIMEOUT));
        if endpoint.security == Security::StartTls
            && let Err(reason) = starttls_upgrade(&stream)
        {
            return Probe::Unreachable(reason);
        }
        let connector = match native_tls::TlsConnector::new() {
            Ok(connector) => connector,
            Err(e) => return Probe::Unreachable(e.to_string()),
        };
        match connector.connect(&endpoint.host, stream) {
            Ok(_) => Probe::Ok,
            Err(native_tls::HandshakeError::Failure(e)) => handshake_failure(e.to_string()),
            Err(native_tls::HandshakeError::WouldBlock(_)) => {
                Probe::Unreachable("TLS handshake timed out".into())
            }
        }
    }
}

#[cfg(test)]
#[path = "../tests/net.rs"]
mod tests;
