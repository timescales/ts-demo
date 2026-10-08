//! Mutual TLS 1.3 with pinned peers.
//!
//! Peers are not named by a certificate authority: each side lists the
//! SHA-256 of the SubjectPublicKeyInfo of every certificate it accepts
//! (`peer_spki_sha256`), and checks the certificate's validity period and
//! the TLS 1.3 handshake signature. Names in the certificate are ignored.
//! Only TLS 1.3 is offered, so every session has an ephemeral key exchange
//! (forward secrecy for share deliveries).

use std::path::PathBuf;
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{CertificateError, DigitallySignedStruct, DistinguishedName, SignatureScheme};
use serde::{Deserialize, Deserializer};
use sha2::{Digest, Sha256};

use crate::ClientError;
use crate::keys::read_private;

/// Mutual TLS 1.3 with pinned peers.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    pub cert_file: PathBuf,
    pub key_file: PathBuf,
    /// SHA-256 of each pinned peer's SubjectPublicKeyInfo, written in the
    /// configuration as 64 hex digits each.
    #[serde(default, deserialize_with = "hex32_list")]
    pub peer_spki_sha256: Vec<[u8; 32]>,
}

impl TlsConfig {
    /// Whether a certificate or key is named. Configuration files write the
    /// section out with empty paths where TLS is off (`cert_file = ""`).
    pub fn is_configured(&self) -> bool {
        !self.cert_file.as_os_str().is_empty() || !self.key_file.as_os_str().is_empty()
    }
}

fn hex32_list<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<[u8; 32]>, D::Error> {
    let items = Vec::<String>::deserialize(d)?;
    items
        .iter()
        .map(|s| {
            let mut out = [0u8; 32];
            hex::decode_to_slice(s, &mut out).map_err(|_| {
                serde::de::Error::custom(format!("expected 64 hex digits, got {s:?}"))
            })?;
            Ok(out)
        })
        .collect()
}

/// SHA-256 of a DER certificate's SubjectPublicKeyInfo: the value pinned
/// in `peer_spki_sha256`.
pub fn spki_sha256(cert_der: &[u8]) -> Result<[u8; 32], ClientError> {
    let (_, cert) = x509_parser::parse_x509_certificate(cert_der)
        .map_err(|e| ClientError::Tls(format!("certificate does not parse: {e}")))?;
    Ok(Sha256::digest(cert.tbs_certificate.subject_pki.raw).into())
}

/// The ring provider. The configurations built here carry it explicitly.
pub(crate) fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Makes ring the process-wide rustls provider unless one is installed.
///
/// The workspace builds rustls without a default provider (no aws-lc next
/// to ring), so a library that builds its own TLS client, such as the OTLP
/// exporter's reqwest client, needs this at start.
pub fn install_default_provider() {
    // An error only means a provider is already installed.
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Server side of mutual TLS: presents `cert_file`, demands a client
/// certificate whose key is pinned in `peer_spki_sha256`, TLS 1.3 only.
pub fn server_config(cfg: &TlsConfig) -> Result<rustls::ServerConfig, ClientError> {
    let provider = provider();
    let (certs, key) = load_identity(cfg)?;
    let verifier = Arc::new(Pinned::new(cfg, Arc::clone(&provider))?);
    rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(tls_error)?
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)
        .map_err(tls_error)
}

/// Client side of mutual TLS: presents `cert_file` and accepts only a
/// server whose key is pinned, TLS 1.3 only.
pub(crate) fn client_config(cfg: &TlsConfig) -> Result<rustls::ClientConfig, ClientError> {
    let provider = provider();
    let (certs, key) = load_identity(cfg)?;
    let verifier = Arc::new(Pinned::new(cfg, Arc::clone(&provider))?);
    rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(tls_error)?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(certs, key)
        .map_err(tls_error)
}

/// A client configuration that accepts no server at all: what a client
/// without `[tls]` hands to reqwest, so an `https` URL fails closed.
pub(crate) fn refusing_client_config() -> Result<rustls::ClientConfig, ClientError> {
    let provider = provider();
    let verifier = Arc::new(Pinned {
        pins: Vec::new(),
        provider: Arc::clone(&provider),
    });
    Ok(rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(tls_error)?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth())
}

fn tls_error(e: rustls::Error) -> ClientError {
    ClientError::Tls(e.to_string())
}

fn load_identity(
    cfg: &TlsConfig,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), ClientError> {
    let pem = std::fs::read(&cfg.cert_file)
        .map_err(|e| ClientError::Tls(format!("reading {}: {e}", cfg.cert_file.display())))?;
    let certs = CertificateDer::pem_slice_iter(&pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| ClientError::Tls(format!("{}: {e}", cfg.cert_file.display())))?;
    if certs.is_empty() {
        return Err(ClientError::Tls(format!(
            "{}: no certificate",
            cfg.cert_file.display()
        )));
    }
    let key_pem = read_private(&cfg.key_file).map_err(|e| ClientError::Tls(e.to_string()))?;
    let key = PrivateKeyDer::from_pem_slice(&key_pem)
        .map_err(|e| ClientError::Tls(format!("{}: {e}", cfg.key_file.display())))?;
    Ok((certs, key))
}

/// Accepts exactly the certificates whose SPKI hash is pinned.
#[derive(Debug)]
struct Pinned {
    pins: Vec<[u8; 32]>,
    provider: Arc<CryptoProvider>,
}

impl Pinned {
    fn new(cfg: &TlsConfig, provider: Arc<CryptoProvider>) -> Result<Self, ClientError> {
        if cfg.peer_spki_sha256.is_empty() {
            return Err(ClientError::Tls(
                "no pinned peer (peer_spki_sha256 is empty)".to_owned(),
            ));
        }
        Ok(Self {
            pins: cfg.peer_spki_sha256.clone(),
            provider,
        })
    }

    fn check(&self, end_entity: &CertificateDer<'_>, now: UnixTime) -> Result<(), rustls::Error> {
        let (_, cert) = x509_parser::parse_x509_certificate(end_entity)
            .map_err(|_| rustls::Error::InvalidCertificate(CertificateError::BadEncoding))?;
        let pin: [u8; 32] = Sha256::digest(cert.tbs_certificate.subject_pki.raw).into();
        if !self.pins.contains(&pin) {
            return Err(rustls::Error::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ));
        }
        let now = i64::try_from(now.as_secs()).unwrap_or(i64::MAX);
        let validity = cert.validity();
        if now < validity.not_before.timestamp() {
            return Err(rustls::Error::InvalidCertificate(
                CertificateError::NotValidYet,
            ));
        }
        if now > validity.not_after.timestamp() {
            return Err(rustls::Error::InvalidCertificate(CertificateError::Expired));
        }
        Ok(())
    }
}

impl ServerCertVerifier for Pinned {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        self.check(end_entity, now)?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

impl ClientCertVerifier for Pinned {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        self.check(end_entity, now)?;
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}
