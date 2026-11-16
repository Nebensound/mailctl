//! Automatic discovery of IMAP and SMTP servers for an e-mail address.
//!
//! Sources, in this order (the same order Thunderbird uses):
//! 1. built-in presets for large providers,
//! 2. the provider's own autoconfig file,
//! 3. Mozilla's ISP database (ISPDB),
//! 4. DNS SRV records (RFC 6186 / RFC 8314),
//! 5. the MX record: ISPDB for the MX domain, then common host names.
//!
//! Every candidate is accepted only if a TLS handshake succeeds and the
//! certificate is valid for the host name. Plain-text connections are never
//! suggested.

use serde::Serialize;

use crate::error::Error;
use crate::types::EmailAddress;

pub use crate::types::Security;

/// A server endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Endpoint {
    /// Host name.
    pub host: String,
    /// TCP port.
    pub port: u16,
    /// Transport security.
    pub security: Security,
}

impl Endpoint {
    fn new(host: &str, port: u16, security: Security) -> Self {
        Self {
            host: host.trim_end_matches('.').to_lowercase(),
            port,
            security,
        }
    }
}

/// IMAP (TLS) and SMTP settings for one address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ServerSettings {
    /// Incoming server; always implicit TLS, since the IMAP adapter only speaks TLS.
    pub imap: Endpoint,
    /// Outgoing server.
    pub smtp: Endpoint,
    /// Login name.
    pub username: String,
}

/// Result of a successful discovery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Discovery {
    /// The verified settings.
    pub settings: ServerSettings,
    /// Where they came from.
    pub source: String,
    /// What was tried, in order, for diagnostics.
    pub trace: Vec<String>,
    /// Servers outside the address's domain that were found through
    /// unauthenticated DNS (SRV or MX). A spoofed answer could point anywhere,
    /// so the user has to confirm them before the first login (RFC 6186 §6).
    pub unconfirmed_hosts: Vec<String>,
}

/// Outcome of a TLS probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Probe {
    /// Reachable with a valid certificate for the host name.
    Ok,
    /// Reachable, but the certificate is not valid for this host name.
    CertificateMismatch(String),
    /// Not reachable or no TLS.
    Unreachable(String),
}

/// One SRV record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrvRecord {
    /// Target host; `.` means the service is not offered.
    pub target: String,
    /// Port.
    pub port: u16,
    /// Lower is preferred.
    pub priority: u16,
    /// Higher is preferred among equal priorities.
    pub weight: u16,
}

/// Network access needed for discovery.
pub trait Net {
    /// Fetches a URL over HTTPS; `None` on any failure.
    fn http_get(&mut self, url: &str) -> Option<String>;
    /// SRV records for a name.
    fn srv(&mut self, name: &str) -> Vec<SrvRecord>;
    /// MX hosts of a domain, most preferred first.
    fn mx(&mut self, domain: &str) -> Vec<String>;
    /// Connects and checks TLS and the certificate.
    fn probe(&mut self, endpoint: &Endpoint) -> Probe;
}

use crate::types::{
    IMAPS_PORT as IMAPS, SUBMISSION_PORT as SUBMISSION, SUBMISSIONS_PORT as SUBMISSIONS,
};

/// Built-in settings for large providers: domains, IMAP host, SMTP host, SMTP port.
const PRESETS: &[(&str, &[&str], &str, &str, u16)] = &[
    (
        "iCloud",
        &["icloud.com", "me.com", "mac.com"],
        "imap.mail.me.com",
        "smtp.mail.me.com",
        SUBMISSION,
    ),
    (
        "Gmail",
        &["gmail.com", "googlemail.com"],
        "imap.gmail.com",
        "smtp.gmail.com",
        SUBMISSIONS,
    ),
    (
        "Outlook.com",
        &[
            "outlook.com",
            "hotmail.com",
            "live.com",
            "outlook.de",
            "hotmail.de",
        ],
        "outlook.office365.com",
        "smtp.office365.com",
        SUBMISSION,
    ),
    (
        "GMX",
        &["gmx.de", "gmx.net", "gmx.at", "gmx.ch"],
        "imap.gmx.net",
        "mail.gmx.net",
        SUBMISSION,
    ),
    (
        "WEB.DE",
        &["web.de"],
        "imap.web.de",
        "smtp.web.de",
        SUBMISSION,
    ),
    (
        "Posteo",
        &["posteo.de", "posteo.net"],
        "posteo.de",
        "posteo.de",
        SUBMISSION,
    ),
];

/// An SMTP endpoint whose security follows from the port.
pub(crate) fn smtp_endpoint(host: &str, port: u16) -> Endpoint {
    Endpoint {
        host: host.to_owned(),
        port,
        security: Security::for_smtp_port(port),
    }
}

/// Settings from the built-in presets.
#[must_use]
pub fn preset(address: &EmailAddress) -> Option<(&'static str, ServerSettings)> {
    let domain = address.domain();
    PRESETS
        .iter()
        .find(|(_, domains, ..)| domains.contains(&domain))
        .map(|(name, _, imap, smtp, port)| {
            (
                *name,
                ServerSettings {
                    imap: Endpoint::new(imap, IMAPS, Security::Tls),
                    smtp: Endpoint::new(smtp, *port, Security::for_smtp_port(*port)),
                    username: address.to_string(),
                },
            )
        })
}

fn expand(template: &str, address: &EmailAddress) -> String {
    let local = address.as_str().split('@').next().unwrap_or_default();
    template
        .replace("%EMAILADDRESS%", address.as_str())
        .replace("%EMAILLOCALPART%", local)
        .replace("%EMAILDOMAIN%", address.domain())
}

fn child_text<'a>(node: roxmltree::Node<'a, '_>, name: &str) -> Option<&'a str> {
    node.children()
        .find(|c| c.has_tag_name(name))
        .and_then(|c| c.text())
        .map(str::trim)
}

fn server_endpoint(
    node: roxmltree::Node<'_, '_>,
    address: &EmailAddress,
) -> Option<(Endpoint, Option<String>)> {
    let host = expand(child_text(node, "hostname")?, address);
    let port: u16 = child_text(node, "port")?.parse().ok()?;
    let security = match child_text(node, "socketType")? {
        "SSL" => Security::Tls,
        "STARTTLS" => Security::StartTls,
        _ => return None,
    };
    let username = child_text(node, "username").map(|u| expand(u, address));
    Some((Endpoint::new(&host, port, security), username))
}

/// Parses a Thunderbird autoconfig document (`config-v1.1.xml`).
///
/// Takes the first IMAP server with implicit TLS and the first SMTP server with
/// TLS or STARTTLS; plain-text servers are ignored.
#[must_use]
pub fn parse_autoconfig(xml: &str, address: &EmailAddress) -> Option<ServerSettings> {
    let doc = roxmltree::Document::parse(xml).ok()?;
    let provider = doc
        .descendants()
        .find(|n| n.has_tag_name("emailProvider"))?;
    let (imap, imap_user) = provider
        .children()
        .filter(|n| n.has_tag_name("incomingServer") && n.attribute("type") == Some("imap"))
        .filter_map(|n| server_endpoint(n, address))
        .find(|(e, _)| e.security == Security::Tls)?;
    let (smtp, _) = provider
        .children()
        .filter(|n| n.has_tag_name("outgoingServer") && n.attribute("type") == Some("smtp"))
        .find_map(|n| server_endpoint(n, address))?;
    Some(ServerSettings {
        imap,
        smtp,
        username: imap_user.unwrap_or_else(|| address.to_string()),
    })
}

fn best_srv(net: &mut dyn Net, name: &str) -> Option<SrvRecord> {
    let mut records: Vec<SrvRecord> = net
        .srv(name)
        .into_iter()
        .filter(|r| r.target != "." && !r.target.is_empty() && r.port != 0)
        .collect();
    records.sort_by_key(|r| (r.priority, std::cmp::Reverse(r.weight)));
    records.into_iter().next()
}

fn srv_settings(net: &mut dyn Net, address: &EmailAddress) -> Option<ServerSettings> {
    let domain = address.domain();
    let imap = best_srv(net, &format!("_imaps._tcp.{domain}"))?;
    let smtp = best_srv(net, &format!("_submissions._tcp.{domain}"))
        .map(|r| Endpoint::new(&r.target, r.port, Security::Tls))
        .or_else(|| {
            best_srv(net, &format!("_submission._tcp.{domain}"))
                .map(|r| Endpoint::new(&r.target, r.port, Security::StartTls))
        })?;
    Some(ServerSettings {
        imap: Endpoint::new(&imap.target, imap.port, Security::Tls),
        smtp,
        username: address.to_string(),
    })
}

/// The registrable part of a host name, approximated by its last two labels.
fn base_domain(host: &str) -> String {
    let labels: Vec<&str> = host.trim_end_matches('.').split('.').collect();
    labels
        .iter()
        .rev()
        .take(2)
        .rev()
        .copied()
        .collect::<Vec<_>>()
        .join(".")
}

/// Removes repeated host names, keeping the first occurrence of each.
fn dedup(hosts: &mut Vec<String>) {
    let mut seen = std::collections::HashSet::new();
    hosts.retain(|h| seen.insert(h.trim_end_matches('.').to_ascii_lowercase()));
}

/// Whether `host` is `domain` or a subdomain of it.
fn within(host: &str, domain: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let domain = domain.to_ascii_lowercase();
    host == domain
        || host
            .strip_suffix(&domain)
            .is_some_and(|rest| rest.ends_with('.'))
}

/// Marks the servers of a DNS-derived result that lie outside `domain`.
fn from_dns(mut found: Discovery, domain: &str) -> Discovery {
    let mut outside: Vec<String> = [&found.settings.imap.host, &found.settings.smtp.host]
        .into_iter()
        .filter(|host| !within(host, domain))
        .cloned()
        .collect();
    dedup(&mut outside);
    found.unconfirmed_hosts = outside;
    found
}

struct Run<'a> {
    net: &'a mut dyn Net,
    trace: Vec<String>,
}

impl Run<'_> {
    fn check(&mut self, endpoint: &Endpoint) -> bool {
        let label = format!("{}:{}", endpoint.host, endpoint.port);
        match self.net.probe(endpoint) {
            Probe::Ok => true,
            Probe::CertificateMismatch(reason) => {
                self.trace.push(format!(
                    "{label}: certificate not valid for this host ({reason})"
                ));
                false
            }
            Probe::Unreachable(reason) => {
                self.trace
                    .push(format!("{label}: not reachable ({reason})"));
                false
            }
        }
    }

    fn verified(&mut self, source: &str, settings: Option<ServerSettings>) -> Option<Discovery> {
        let Some(settings) = settings else {
            self.trace.push(format!("{source}: nothing found"));
            return None;
        };
        if self.check(&settings.imap) && self.check(&settings.smtp) {
            Some(Discovery {
                settings,
                source: source.to_owned(),
                trace: std::mem::take(&mut self.trace),
                unconfirmed_hosts: Vec::new(),
            })
        } else {
            self.trace.push(format!("{source}: found, but not usable"));
            None
        }
    }

    fn autoconfig(&mut self, url: &str, address: &EmailAddress) -> Option<ServerSettings> {
        self.net
            .http_get(url)
            .and_then(|xml| parse_autoconfig(&xml, address))
    }

    fn guess(&mut self, address: &EmailAddress, mx: &[String]) -> Option<Discovery> {
        let domain = address.domain();
        let mut hosts: Vec<String> = mx.to_vec();
        hosts.push(format!("imap.{domain}"));
        hosts.push(format!("mail.{domain}"));
        dedup(&mut hosts);
        let imap = hosts
            .iter()
            .map(|h| Endpoint::new(h, IMAPS, Security::Tls))
            .find(|e| self.check(e));
        let Some(imap) = imap else {
            self.trace
                .push("guess: no IMAP host with a valid certificate".to_owned());
            return None;
        };
        let mut smtp_hosts = vec![imap.host.clone()];
        smtp_hosts.extend(hosts.iter().cloned());
        dedup(&mut smtp_hosts);
        let smtp = smtp_hosts
            .iter()
            .flat_map(|h| {
                [
                    Endpoint::new(h, SUBMISSION, Security::StartTls),
                    Endpoint::new(h, SUBMISSIONS, Security::Tls),
                ]
            })
            .find(|e| self.check(e));
        let Some(smtp) = smtp else {
            self.trace
                .push("guess: no SMTP host with a valid certificate".to_owned());
            return None;
        };
        Some(Discovery {
            settings: ServerSettings {
                imap,
                smtp,
                username: address.to_string(),
            },
            source: "guess from MX record and common host names".to_owned(),
            trace: std::mem::take(&mut self.trace),
            unconfirmed_hosts: Vec::new(),
        })
    }
}

/// Discovers verified server settings for an address.
///
/// # Errors
/// Returns [`Error::NoServerFound`] with the full trace if no source yields
/// usable settings.
pub fn discover(address: &EmailAddress, net: &mut dyn Net) -> Result<Discovery, Error> {
    let domain = address.domain().to_owned();
    let mut run = Run {
        net,
        trace: Vec::new(),
    };

    let preset = preset(address);
    let preset_name = preset.as_ref().map(|(name, _)| format!("preset {name}"));
    if let Some(found) = run.verified(
        preset_name.as_deref().unwrap_or("preset"),
        preset.map(|(_, s)| s),
    ) {
        return Ok(found);
    }
    let provider_urls = [
        format!("https://autoconfig.{domain}/mail/config-v1.1.xml?emailaddress={address}"),
        format!("https://{domain}/.well-known/autoconfig/mail/config-v1.1.xml"),
    ];
    for url in &provider_urls {
        let settings = run.autoconfig(url, address);
        if let Some(found) = run.verified(&format!("provider autoconfig {url}"), settings) {
            return Ok(found);
        }
    }
    let ispdb = format!("https://autoconfig.thunderbird.net/v1.1/{domain}");
    let settings = run.autoconfig(&ispdb, address);
    if let Some(found) = run.verified(&format!("Mozilla ISPDB {ispdb}"), settings) {
        return Ok(found);
    }
    let settings = srv_settings(run.net, address);
    if let Some(found) = run.verified("DNS SRV records", settings) {
        return Ok(from_dns(found, &domain));
    }
    let mx = run.net.mx(&domain);
    if let Some(first) = mx.first() {
        let mx_domain = base_domain(first);
        if mx_domain != domain {
            let url = format!("https://autoconfig.thunderbird.net/v1.1/{mx_domain}");
            let settings = run.autoconfig(&url, address);
            if let Some(found) = run.verified(
                &format!("Mozilla ISPDB for MX domain {mx_domain}"),
                settings,
            ) {
                return Ok(from_dns(found, &domain));
            }
        }
    } else {
        run.trace.push(format!("{domain}: no MX record"));
    }
    if let Some(found) = run.guess(address, &mx) {
        return Ok(from_dns(found, &domain));
    }
    Err(Error::NoServerFound(format!(
        "no mail server found for {address}; tried: {}",
        run.trace.join("; ")
    )))
}

#[cfg(test)]
#[path = "tests/discover.rs"]
pub(crate) mod tests;
