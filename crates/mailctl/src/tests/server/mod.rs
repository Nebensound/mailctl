//! Scripted mail servers for the end-to-end tests: real TLS on a local port,
//! a certificate authority made for each server, and behaviour modelled on
//! the responses of real providers (see [`imap::Profile`]).

pub(crate) mod imap;

use std::sync::Arc;

use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use rustls::ServerConfig;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

/// A certificate authority and a server certificate for `localhost` it
/// signed, valid from yesterday to tomorrow (macOS refuses server
/// certificates valid for longer than 825 days).
pub(crate) struct TestCa {
    /// The authority's certificate, which the client trusts.
    pub(crate) pem: Vec<u8>,
    /// TLS settings that present the server certificate.
    pub(crate) config: Arc<ServerConfig>,
}

impl TestCa {
    pub(crate) fn new() -> Result<Self, String> {
        let fail = |e: rcgen::Error| e.to_string();
        let now = time::OffsetDateTime::now_utc();
        let validity = |params: &mut CertificateParams| {
            params.not_before = now.saturating_sub(time::Duration::days(1));
            params.not_after = now.saturating_add(time::Duration::days(1));
        };
        let ca_key = KeyPair::generate().map_err(fail)?;
        let mut ca = CertificateParams::new(Vec::<String>::new()).map_err(fail)?;
        ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca.distinguished_name
            .push(DnType::CommonName, "mailctl test CA");
        ca.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        validity(&mut ca);
        let ca_cert = ca.self_signed(&ca_key).map_err(fail)?;
        let issuer = Issuer::new(ca, ca_key);

        let key = KeyPair::generate().map_err(fail)?;
        let mut leaf = CertificateParams::new(vec!["localhost".to_owned()]).map_err(fail)?;
        leaf.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        validity(&mut leaf);
        let cert = leaf.signed_by(&key, &issuer).map_err(fail)?;

        // TLS 1.2 stays enabled: native-tls on macOS speaks nothing newer.
        let config =
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .map_err(|e| e.to_string())?
                .with_no_client_auth()
                .with_single_cert(
                    vec![cert.der().clone()],
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
                )
                .map_err(|e| e.to_string())?;
        Ok(Self {
            pem: ca_cert.pem().into_bytes(),
            config: Arc::new(config),
        })
    }
}
