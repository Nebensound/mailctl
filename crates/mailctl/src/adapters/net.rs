//! [`Net`] over the real network: HTTPS, DNS and TLS probes.

use std::io::{BufRead as _, BufReader, Read, Write as _};
use std::net::{TcpStream, ToSocketAddrs as _};
use std::time::Duration;

use hickory_resolver::TokioResolver;
use hickory_resolver::proto::rr::RData;

use crate::discover::{Endpoint, Net, Probe, Security, SrvRecord};

/// Timeout for every network step.
const TIMEOUT: Duration = Duration::from_secs(8);

/// Network access for discovery.
pub struct SystemNet {
    agent: ureq::Agent,
    dns: Option<(tokio::runtime::Runtime, TokioResolver)>,
}

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

fn read_reply(reader: &mut BufReader<&TcpStream>) -> Option<String> {
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

fn starttls_upgrade(stream: &TcpStream) -> Result<(), String> {
    let mut reader = BufReader::new(stream);
    let banner = read_reply(&mut reader).ok_or("no SMTP banner")?;
    if !banner.starts_with("220") {
        return Err(format!("unexpected banner {}", banner.trim()));
    }
    (&*stream)
        .write_all(b"EHLO mailctl\r\n")
        .map_err(|e| e.to_string())?;
    let ehlo = read_reply(&mut reader).ok_or("no EHLO reply")?;
    if !ehlo.to_uppercase().contains("STARTTLS") {
        return Err("server does not offer STARTTLS".into());
    }
    (&*stream)
        .write_all(b"STARTTLS\r\n")
        .map_err(|e| e.to_string())?;
    let ready = read_reply(&mut reader).ok_or("no STARTTLS reply")?;
    if ready.starts_with("220") {
        Ok(())
    } else {
        Err(format!("STARTTLS refused: {}", ready.trim()))
    }
}

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
        let address = match (endpoint.host.as_str(), endpoint.port).to_socket_addrs() {
            Ok(mut addresses) => match addresses.next() {
                Some(address) => address,
                None => return Probe::Unreachable("no address".into()),
            },
            Err(e) => return Probe::Unreachable(e.to_string()),
        };
        let stream = match TcpStream::connect_timeout(&address, TIMEOUT) {
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
            Err(native_tls::HandshakeError::Failure(e)) => {
                let text = e.to_string();
                let lower = text.to_lowercase();
                if lower.contains("certificate")
                    || lower.contains("hostname")
                    || lower.contains("not trusted")
                {
                    Probe::CertificateMismatch(text)
                } else {
                    Probe::Unreachable(text)
                }
            }
            Err(native_tls::HandshakeError::WouldBlock(_)) => {
                Probe::Unreachable("TLS handshake timed out".into())
            }
        }
    }
}
