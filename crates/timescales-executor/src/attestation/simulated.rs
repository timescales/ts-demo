//! Simulated attestation (feature `sim-platform`).
//!
//! Structure mirrors hardware attestation closely enough to exercise every
//! policy decision:
//!
//! ```text
//! vendor root (Ed25519) --certifies--> platform key + security version
//! platform key --signs--> report(measurement, debug, report_data)
//! ```
//!
//! The vendor publishes its current security version. Platforms certified
//! at a lower version are `OutOfDate`. Platform keys can be revoked.
//!
//! **No security**: whoever holds the vendor seed or a platform key can sign
//! any measurement. This exists for development, devnet and tests only, and
//! services refuse it under the production profile.

use std::collections::BTreeSet;
use std::sync::RwLock;

use rand_core::{CryptoRng, RngCore};
use timescales_core::crypto::{Hasher, Keypair, Signature, Zeroizing, domain, verify_digest};
use timescales_core::{Decode, Encode, Hash32, Reader, encoding::put_bool, encoding::put_u16};

use crate::attestation::{
    AttestationError, Evidence, Measurement, Platform, QuoteVerifier, TcbStatus, VerifiedReport,
};

const MAGIC: &[u8; 8] = b"TSCLSIMQ";

fn cert_digest(platform_key: &[u8; 32], svn: u16) -> Hash32 {
    Hasher::new(domain::ATTESTATION_REPORT)
        .chain(b"cert")
        .chain(platform_key)
        .chain(&svn.to_le_bytes())
        .finalize()
}

fn report_digest(platform_key: &[u8; 32], m: &Measurement, debug: bool, rd: &[u8; 64]) -> Hash32 {
    Hasher::new(domain::ATTESTATION_REPORT)
        .chain(b"report")
        .chain(platform_key)
        .chain(m.0.as_bytes())
        .chain(&[u8::from(debug)])
        .chain(rd)
        .finalize()
}

/// The simulated hardware vendor.
#[derive(Debug)]
pub struct SimulatedVendor {
    root: Keypair,
    current_svn: u16,
}

impl SimulatedVendor {
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R, current_svn: u16) -> Self {
        Self {
            root: Keypair::generate(rng),
            current_svn,
        }
    }

    /// The vendor whose root key is derived from `seed`: the dev CA a local
    /// or devnet deployment configures (`simulated_vendor_seed`).
    pub fn from_seed(seed: [u8; 32], current_svn: u16) -> Self {
        Self {
            root: Keypair::from_seed(seed),
            current_svn,
        }
    }

    pub fn root_key(&self) -> [u8; 32] {
        self.root.public()
    }

    pub fn current_svn(&self) -> u16 {
        self.current_svn
    }

    /// Certify a platform key at a security version.
    pub fn certify(&self, platform_key: &[u8; 32], svn: u16) -> PlatformCertificate {
        PlatformCertificate {
            platform_key: *platform_key,
            svn,
            signature: self.root.sign_digest(&cert_digest(platform_key, svn)),
        }
    }

    /// Manufacture a platform at a given security version.
    pub fn platform<R: RngCore + CryptoRng>(&self, rng: &mut R, svn: u16) -> SimulatedPlatform {
        let key = Keypair::generate(rng);
        let cert = self.certify(&key.public(), svn);
        SimulatedPlatform { key, cert }
    }

    pub fn verifier(&self) -> SimulatedQuoteVerifier {
        SimulatedQuoteVerifier::from_root(self.root_key(), self.current_svn)
    }
}

/// The vendor's endorsement of one platform key: what a simulated enclave
/// stores next to its keys so that it keeps its identity across restarts.
///
/// Encoded as `platform_key32 || svn u16 || signature64` (98 bytes).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PlatformCertificate {
    pub platform_key: [u8; 32],
    pub svn: u16,
    pub signature: Signature,
}

impl PlatformCertificate {
    pub const ENCODED_LEN: usize = 32 + 2 + 64;

    pub fn to_bytes(&self) -> [u8; Self::ENCODED_LEN] {
        let mut out = Vec::with_capacity(Self::ENCODED_LEN);
        out.extend_from_slice(&self.platform_key);
        put_u16(&mut out, self.svn);
        self.signature.encode(&mut out);
        let mut b = [0u8; Self::ENCODED_LEN];
        b.copy_from_slice(&out);
        b
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, AttestationError> {
        let malformed = |_| AttestationError::Malformed("platform certificate");
        let mut r = Reader::new(bytes);
        let platform_key: [u8; 32] = r.array().map_err(malformed)?;
        let svn = r.u16().map_err(malformed)?;
        let signature = Signature::decode(&mut r).map_err(malformed)?;
        r.finish().map_err(malformed)?;
        Ok(Self {
            platform_key,
            svn,
            signature,
        })
    }

    /// Whether the vendor with root key `root` issued this certificate.
    pub fn verify(&self, root: &[u8; 32]) -> Result<(), AttestationError> {
        verify_digest(
            root,
            &cert_digest(&self.platform_key, self.svn),
            &self.signature,
        )
        .map_err(|_| AttestationError::BadEndorsement)
    }
}

/// One simulated machine.
#[derive(Debug)]
pub struct SimulatedPlatform {
    key: Keypair,
    cert: PlatformCertificate,
}

impl SimulatedPlatform {
    /// A platform restored from its key seed and certificate. The
    /// certificate must name the key. Whether the vendor issued it is up to
    /// the verifier.
    pub fn from_parts(
        key_seed: [u8; 32],
        cert: PlatformCertificate,
    ) -> Result<Self, AttestationError> {
        let key = Keypair::from_seed(key_seed);
        if key.public() != cert.platform_key {
            return Err(AttestationError::Malformed(
                "platform certificate names another key",
            ));
        }
        Ok(Self { key, cert })
    }

    pub fn id(&self) -> Hash32 {
        Hash32(self.key.public())
    }

    pub fn certificate(&self) -> PlatformCertificate {
        self.cert
    }

    /// The platform key's seed, for persisting the platform.
    pub fn key_seed(&self) -> Zeroizing<[u8; 32]> {
        self.key.seed()
    }

    /// Produce evidence. `debug` models a debug-mode enclave, whose memory
    /// the host can read.
    pub fn quote(&self, measurement: Measurement, debug: bool, report_data: [u8; 64]) -> Evidence {
        let pk = self.key.public();
        let sig = self
            .key
            .sign_digest(&report_digest(&pk, &measurement, debug, &report_data));
        let mut q = Vec::with_capacity(8 + 32 + 2 + 64 + 32 + 1 + 64 + 64);
        q.extend_from_slice(MAGIC);
        q.extend_from_slice(&pk);
        put_u16(&mut q, self.cert.svn);
        self.cert.signature.encode(&mut q);
        measurement.0.encode(&mut q);
        put_bool(&mut q, debug);
        q.extend_from_slice(&report_data);
        sig.encode(&mut q);
        Evidence {
            platform: Platform::Simulated,
            quote: q,
        }
    }
}

/// Verifier pinned to a simulated vendor root.
#[derive(Debug)]
pub struct SimulatedQuoteVerifier {
    root: [u8; 32],
    current_svn: u16,
    revoked: RwLock<BTreeSet<[u8; 32]>>,
}

impl SimulatedQuoteVerifier {
    /// A verifier for the vendor with root key `root` whose current security
    /// version is `current_svn` (`simulated_vendor_root` in a member's
    /// policy).
    pub fn from_root(root: [u8; 32], current_svn: u16) -> Self {
        Self {
            root,
            current_svn,
            revoked: RwLock::default(),
        }
    }

    pub fn revoke(&self, platform_id: Hash32) {
        if let Ok(mut r) = self.revoked.write() {
            r.insert(platform_id.0);
        }
    }
}

impl QuoteVerifier for SimulatedQuoteVerifier {
    fn verify(&self, evidence: &Evidence) -> Result<VerifiedReport, AttestationError> {
        if evidence.platform != Platform::Simulated {
            return Err(AttestationError::UnsupportedPlatform(evidence.platform));
        }
        let mut r = Reader::new(&evidence.quote);
        let magic: [u8; 8] = r
            .array()
            .map_err(|_| AttestationError::Malformed("magic"))?;
        if &magic != MAGIC {
            return Err(AttestationError::Malformed("magic"));
        }
        let parse = |_| AttestationError::Malformed("quote body");
        let pk: [u8; 32] = r.array().map_err(parse)?;
        let svn = r.u16().map_err(parse)?;
        let cert = Signature::decode(&mut r).map_err(parse)?;
        let measurement = Measurement(Hash32::decode(&mut r).map_err(parse)?);
        let debug = r.bool().map_err(parse)?;
        let report_data: [u8; 64] = r.array().map_err(parse)?;
        let sig = Signature::decode(&mut r).map_err(parse)?;
        r.finish().map_err(parse)?;

        PlatformCertificate {
            platform_key: pk,
            svn,
            signature: cert,
        }
        .verify(&self.root)?;
        verify_digest(
            &pk,
            &report_digest(&pk, &measurement, debug, &report_data),
            &sig,
        )
        .map_err(|_| AttestationError::BadSignature)?;
        let revoked = self.revoked.read().map(|s| s.contains(&pk)).unwrap_or(true);
        let tcb = if revoked {
            TcbStatus::Revoked
        } else if svn >= self.current_svn {
            TcbStatus::UpToDate
        } else {
            TcbStatus::OutOfDate
        };
        Ok(VerifiedReport {
            platform: Platform::Simulated,
            measurement,
            tcb,
            debug,
            report_data,
            platform_id: Hash32(pk),
            td: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    fn setup() -> (rand_chacha::ChaCha20Rng, SimulatedVendor) {
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(1);
        let v = SimulatedVendor::new(&mut rng, 3);
        (rng, v)
    }

    #[test]
    fn genuine_quote_verifies() {
        let (mut rng, v) = setup();
        let p = v.platform(&mut rng, 3);
        let m = Measurement::of_program("x", "1", b"");
        let rep = v.verifier().verify(&p.quote(m, false, [7; 64])).unwrap();
        assert_eq!(
            (rep.measurement, rep.tcb, rep.debug, rep.report_data),
            (m, TcbStatus::UpToDate, false, [7; 64])
        );
    }

    #[test]
    fn stale_svn_and_revocation() {
        let (mut rng, v) = setup();
        let old = v.platform(&mut rng, 2);
        let ver = v.verifier();
        let m = Measurement::of_program("x", "1", b"");
        assert_eq!(
            ver.verify(&old.quote(m, false, [0; 64])).unwrap().tcb,
            TcbStatus::OutOfDate
        );
        ver.revoke(old.id());
        assert_eq!(
            ver.verify(&old.quote(m, false, [0; 64])).unwrap().tcb,
            TcbStatus::Revoked
        );
    }

    #[test]
    fn foreign_vendor_and_tampering_rejected() {
        let (mut rng, v) = setup();
        let other = SimulatedVendor::new(&mut rng, 3);
        let p = other.platform(&mut rng, 3);
        let m = Measurement::of_program("x", "1", b"");
        assert_eq!(
            v.verifier().verify(&p.quote(m, false, [0; 64])),
            Err(AttestationError::BadEndorsement)
        );

        let p = v.platform(&mut rng, 3);
        let mut e = p.quote(m, false, [0; 64]);
        // Flip the debug flag after signing.
        let debug_at = 8 + 32 + 2 + 64 + 32;
        e.quote[debug_at] = 1;
        assert_eq!(v.verifier().verify(&e), Err(AttestationError::BadSignature));
        e.quote.truncate(10);
        assert!(matches!(
            v.verifier().verify(&e),
            Err(AttestationError::Malformed(_))
        ));
    }

    #[test]
    fn seeded_vendor_and_root_verifier_agree() {
        let vendor = SimulatedVendor::from_seed([5; 32], 4);
        assert_eq!(
            vendor.root_key(),
            SimulatedVendor::from_seed([5; 32], 4).root_key()
        );
        assert_ne!(
            vendor.root_key(),
            SimulatedVendor::from_seed([6; 32], 4).root_key()
        );
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(2);
        let p = vendor.platform(&mut rng, 4);
        let m = Measurement::of_program("x", "1", b"");
        let ev = p.quote(m, false, [1; 64]);
        let ver = SimulatedQuoteVerifier::from_root(vendor.root_key(), 4);
        assert_eq!(ver.verify(&ev).unwrap().tcb, TcbStatus::UpToDate);
        // A verifier that expects a newer security version marks it stale.
        let newer = SimulatedQuoteVerifier::from_root(vendor.root_key(), 5);
        assert_eq!(newer.verify(&ev).unwrap().tcb, TcbStatus::OutOfDate);
        let other = SimulatedQuoteVerifier::from_root([9; 32], 4);
        assert!(other.verify(&ev).is_err());
    }

    #[test]
    fn platform_survives_a_round_trip_through_its_certificate() {
        let (mut rng, vendor) = setup();
        let p = vendor.platform(&mut rng, 3);
        let cert = PlatformCertificate::from_bytes(&p.certificate().to_bytes()).unwrap();
        assert_eq!(cert, p.certificate());
        cert.verify(&vendor.root_key()).unwrap();
        assert_eq!(
            cert.verify(&SimulatedVendor::from_seed([1; 32], 3).root_key()),
            Err(AttestationError::BadEndorsement)
        );
        let restored = SimulatedPlatform::from_parts(*p.key_seed(), cert).unwrap();
        assert_eq!(restored.id(), p.id());
        let m = Measurement::of_program("x", "1", b"");
        let rep = vendor
            .verifier()
            .verify(&restored.quote(m, false, [3; 64]))
            .unwrap();
        assert_eq!(rep.platform_id, p.id());
        assert_eq!(rep.td, None);
    }

    #[test]
    fn certificate_for_another_key_or_of_another_length_is_refused() {
        let (mut rng, vendor) = setup();
        let p = vendor.platform(&mut rng, 3);
        let q = vendor.platform(&mut rng, 3);
        assert!(matches!(
            SimulatedPlatform::from_parts(*p.key_seed(), q.certificate()),
            Err(AttestationError::Malformed(_))
        ));
        let bytes = p.certificate().to_bytes();
        assert_eq!(bytes.len(), PlatformCertificate::ENCODED_LEN);
        assert!(PlatformCertificate::from_bytes(&bytes[..97]).is_err());
        let mut long = bytes.to_vec();
        long.push(0);
        assert!(PlatformCertificate::from_bytes(&long).is_err());
    }

    #[test]
    fn certified_key_matches_what_the_vendor_signed() {
        let vendor = SimulatedVendor::from_seed([5; 32], 4);
        let key = Keypair::from_seed([8; 32]);
        let cert = vendor.certify(&key.public(), 2);
        let p = SimulatedPlatform::from_parts([8; 32], cert).unwrap();
        let m = Measurement::of_program("x", "1", b"");
        let rep = vendor
            .verifier()
            .verify(&p.quote(m, true, [0; 64]))
            .unwrap();
        assert_eq!((rep.tcb, rep.debug), (TcbStatus::OutOfDate, true));
    }
}
