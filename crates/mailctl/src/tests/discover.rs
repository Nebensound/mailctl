//! Tests for `discover`.

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
