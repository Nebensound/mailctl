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

/// Transport security of an endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Security {
    /// TLS from the first byte (IMAP 993, SMTP 465).
    Tls,
    /// Plain connection upgraded with `STARTTLS` (SMTP 587).
    StartTls,
}

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

/// IMAP port with implicit TLS.
const IMAPS: u16 = 993;
/// SMTP submission with implicit TLS.
const SUBMISSIONS: u16 = 465;
/// SMTP submission with STARTTLS.
const SUBMISSION: u16 = 587;

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

fn smtp_security(port: u16) -> Security {
    if port == SUBMISSIONS {
        Security::Tls
    } else {
        Security::StartTls
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
                    smtp: Endpoint::new(smtp, *port, smtp_security(*port)),
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
        hosts.dedup();
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
        smtp_hosts.dedup();
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
        return Ok(found);
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
                return Ok(found);
            }
        }
    } else {
        run.trace.push(format!("{domain}: no MX record"));
    }
    if let Some(found) = run.guess(address, &mx) {
        return Ok(found);
    }
    Err(Error::NoServerFound(format!(
        "no mail server found for {address}; tried: {}",
        run.trace.join("; ")
    )))
}

#[cfg(test)]
pub(crate) mod tests {
    use std::collections::HashMap;

    use super::*;

    /// Network fake: URLs, SRV and MX answers, and endpoints that pass the probe.
    #[derive(Default, Clone)]
    pub(crate) struct FakeNet {
        pub(crate) pages: HashMap<String, String>,
        pub(crate) srv: HashMap<String, Vec<SrvRecord>>,
        pub(crate) mx: HashMap<String, Vec<String>>,
        pub(crate) ok: Vec<(String, u16)>,
        pub(crate) mismatch: Vec<(String, u16)>,
    }

    impl Net for FakeNet {
        fn http_get(&mut self, url: &str) -> Option<String> {
            self.pages.get(url).cloned()
        }
        fn srv(&mut self, name: &str) -> Vec<SrvRecord> {
            self.srv.get(name).cloned().unwrap_or_default()
        }
        fn mx(&mut self, domain: &str) -> Vec<String> {
            self.mx.get(domain).cloned().unwrap_or_default()
        }
        fn probe(&mut self, e: &Endpoint) -> Probe {
            let key = (e.host.clone(), e.port);
            if self.ok.contains(&key) {
                Probe::Ok
            } else if self.mismatch.contains(&key) {
                Probe::CertificateMismatch("other host".into())
            } else {
                Probe::Unreachable("refused".into())
            }
        }
    }

    pub(crate) const AUTOCONFIG: &str = r#"<?xml version="1.0"?>
<clientConfig version="1.1">
  <emailProvider id="example.com">
    <domain>example.com</domain>
    <incomingServer type="pop3"><hostname>pop.x</hostname><port>995</port><socketType>SSL</socketType></incomingServer>
    <incomingServer type="imap"><hostname>plain.%EMAILDOMAIN%</hostname><port>143</port><socketType>plain</socketType></incomingServer>
    <incomingServer type="imap"><hostname>mail.%EMAILDOMAIN%</hostname><port>143</port><socketType>STARTTLS</socketType></incomingServer>
    <incomingServer type="imap"><hostname> mail.example.net </hostname><port>993</port><socketType>SSL</socketType><username>%EMAILLOCALPART%</username></incomingServer>
    <outgoingServer type="smtp"><hostname>mail.example.net</hostname><port>587</port><socketType>STARTTLS</socketType><username>%EMAILADDRESS%</username></outgoingServer>
  </emailProvider>
</clientConfig>"#;

    fn ns() -> Result<EmailAddress, Error> {
        EmailAddress::parse("alice@example.com")
    }

    fn ok(hosts: &[(&str, u16)]) -> Vec<(String, u16)> {
        hosts.iter().map(|(h, p)| ((*h).to_owned(), *p)).collect()
    }

    #[test]
    fn presets_cover_icloud_and_ports() -> Result<(), Error> {
        let (name, s) = preset(&EmailAddress::parse("a@me.com")?).ok_or(Error::NotFound(0))?;
        assert_eq!(
            (name, s.imap.host.as_str(), s.smtp.port, s.smtp.security),
            ("iCloud", "imap.mail.me.com", 587, Security::StartTls)
        );
        let (_, g) = preset(&EmailAddress::parse("a@gmail.com")?).ok_or(Error::NotFound(0))?;
        assert_eq!(g.smtp.security, Security::Tls);
        assert!(preset(&ns()?).is_none());
        Ok(())
    }

    #[test]
    fn parses_autoconfig_and_skips_insecure_servers() -> Result<(), Error> {
        let s = parse_autoconfig(AUTOCONFIG, &ns()?).ok_or(Error::NotFound(0))?;
        assert_eq!(
            s.imap,
            Endpoint::new("mail.example.net", 993, Security::Tls)
        );
        assert_eq!(s.smtp.security, Security::StartTls);
        assert_eq!(s.username, "alice");
        assert!(parse_autoconfig("<nope", &ns()?).is_none());
        assert!(parse_autoconfig("<clientConfig/>", &ns()?).is_none());
        let no_user = AUTOCONFIG.replace("<username>%EMAILLOCALPART%</username>", "");
        assert_eq!(
            parse_autoconfig(&no_user, &ns()?).map(|s| s.username),
            Some("alice@example.com".into())
        );
        let no_smtp = AUTOCONFIG.replace("outgoingServer", "ignored");
        assert!(parse_autoconfig(&no_smtp, &ns()?).is_none());
        let bad_port = AUTOCONFIG.replace("<port>993</port>", "<port>x</port>");
        assert!(parse_autoconfig(&bad_port, &ns()?).is_none());
        Ok(())
    }

    #[test]
    fn preset_wins_when_reachable() -> Result<(), Error> {
        let mut net = FakeNet {
            ok: ok(&[("imap.mail.me.com", 993), ("smtp.mail.me.com", 587)]),
            ..FakeNet::default()
        };
        let d = discover(&EmailAddress::parse("alice@icloud.com")?, &mut net)?;
        assert_eq!(d.source, "preset iCloud");
        Ok(())
    }

    #[test]
    fn provider_autoconfig_is_used() -> Result<(), Error> {
        let mut net = FakeNet {
            ok: ok(&[("mail.example.net", 993), ("mail.example.net", 587)]),
            ..FakeNet::default()
        };
        net.pages.insert(
            "https://example.com/.well-known/autoconfig/mail/config-v1.1.xml".into(),
            AUTOCONFIG.into(),
        );
        let d = discover(&ns()?, &mut net)?;
        assert!(
            d.source
                .starts_with("provider autoconfig https://example.com/.well-known")
        );
        assert!(
            d.trace
                .iter()
                .any(|t| t.contains("autoconfig.example.com") && t.contains("nothing found"))
        );
        Ok(())
    }

    #[test]
    fn falls_through_to_ispdb_and_srv() -> Result<(), Error> {
        let mut net = FakeNet {
            ok: ok(&[("mail.example.net", 993), ("mail.example.net", 587)]),
            ..FakeNet::default()
        };
        net.pages.insert(
            "https://autoconfig.thunderbird.net/v1.1/example.com".into(),
            AUTOCONFIG.into(),
        );
        assert!(
            discover(&ns()?, &mut net)?
                .source
                .starts_with("Mozilla ISPDB")
        );

        let mut srv = FakeNet {
            ok: ok(&[("imap.x.de", 993), ("smtp.x.de", 465)]),
            ..FakeNet::default()
        };
        let rec = |t: &str, port, priority, weight| SrvRecord {
            target: t.into(),
            port,
            priority,
            weight,
        };
        srv.srv.insert(
            "_imaps._tcp.example.com".into(),
            vec![
                rec(".", 0, 0, 0),
                rec("backup.x.de", 993, 20, 0),
                rec("imap.x.de.", 993, 10, 5),
            ],
        );
        srv.srv.insert(
            "_submissions._tcp.example.com".into(),
            vec![rec("smtp.x.de", 465, 0, 0)],
        );
        let d = discover(&ns()?, &mut srv)?;
        assert_eq!(
            (d.source.as_str(), d.settings.imap.host.as_str()),
            ("DNS SRV records", "imap.x.de")
        );

        let mut starttls = FakeNet {
            ok: ok(&[("imap.x.de", 993), ("smtp.x.de", 587)]),
            ..FakeNet::default()
        };
        starttls.srv.insert(
            "_imaps._tcp.example.com".into(),
            vec![rec("imap.x.de", 993, 0, 0)],
        );
        starttls.srv.insert(
            "_submission._tcp.example.com".into(),
            vec![rec("smtp.x.de", 587, 0, 0)],
        );
        assert_eq!(
            discover(&ns()?, &mut starttls)?.settings.smtp.security,
            Security::StartTls
        );
        Ok(())
    }

    #[test]
    fn mx_domain_ispdb_and_guessing() -> Result<(), Error> {
        let mut net = FakeNet {
            ok: ok(&[("mail.example.net", 993), ("mail.example.net", 587)]),
            ..FakeNet::default()
        };
        net.mx
            .insert("example.com".into(), vec!["mx.example.net".into()]);
        net.pages.insert(
            "https://autoconfig.thunderbird.net/v1.1/example.net".into(),
            AUTOCONFIG.into(),
        );
        assert!(
            discover(&ns()?, &mut net)?
                .source
                .contains("MX domain example.net")
        );

        // Shared-hosting case: mail.<domain> presents a certificate for the server name only.
        let mut plesk = FakeNet {
            ok: ok(&[("mail.example.net", 993), ("mail.example.net", 465)]),
            mismatch: ok(&[("mail.example.com", 993)]),
            ..FakeNet::default()
        };
        plesk.mx.insert(
            "example.com".into(),
            vec!["mail.example.com".into(), "mail.example.net".into()],
        );
        let d = discover(&ns()?, &mut plesk)?;
        assert_eq!(d.settings.imap.host, "mail.example.net");
        assert_eq!(
            d.settings.smtp,
            Endpoint::new("mail.example.net", 465, Security::Tls)
        );
        assert!(d.trace.iter().any(|t| t.contains("certificate not valid")));
        Ok(())
    }

    #[test]
    fn reports_trace_when_nothing_works() -> Result<(), Error> {
        let mut net = FakeNet::default();
        let err = discover(&ns()?, &mut net);
        assert!(
            matches!(&err, Err(Error::NoServerFound(m)) if m.contains("no MX record") && m.contains("no IMAP host"))
        );
        let mut imap_only = FakeNet {
            ok: ok(&[("imap.example.com", 993)]),
            ..FakeNet::default()
        };
        assert!(
            matches!(discover(&ns()?, &mut imap_only), Err(Error::NoServerFound(m)) if m.contains("no SMTP host"))
        );
        let mut preset_down = FakeNet::default();
        let err = discover(&EmailAddress::parse("a@icloud.com")?, &mut preset_down);
        assert!(
            matches!(err, Err(Error::NoServerFound(m)) if m.contains("preset iCloud: found, but not usable"))
        );
        Ok(())
    }

    #[test]
    fn helpers() {
        assert_eq!(base_domain("mx01.mail.example.co."), "example.co");
        assert_eq!(base_domain("localhost"), "localhost");
        assert_eq!(smtp_security(465), Security::Tls);
    }
}
