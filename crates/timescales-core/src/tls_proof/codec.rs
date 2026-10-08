//! Canonical encoding of TLS presentations.
//!
//! ```text
//! Presentation      = NotaryAttestation || seq<Disclosure> (<= 64)
//! NotaryAttestation = bytes server_name (UTF-8, <= 255) || time u64 || sent_len u32
//!                     || received_len u32 || root32 || notary32 || sig64
//! Disclosure        = direction u8 || index u32 || salt16 || bytes chunk (<= CHUNK)
//!                     || InclusionProof
//! ```
//!
//! An oracle discloses the few chunks around one price field, so 64
//! disclosures (2 KiB of transcript) leave ample room while keeping a
//! decoded presentation small.

use crate::crypto::Signature;
use crate::merkle::InclusionProof;
use crate::{
    Decode, DecodeError, Encode, Hash32, Reader,
    encoding::{put_bytes, put_seq, put_u8, put_u32},
};

use crate::tls_proof::{CHUNK, Direction, Disclosure, NotaryAttestation, Presentation};

/// Longest server name (a DNS name has at most 253 characters).
pub const MAX_SERVER_NAME_LEN: usize = 255;
/// Most disclosed chunks in one presentation.
pub const MAX_DISCLOSURES: usize = 64;

impl NotaryAttestation {
    /// Empty server name.
    pub const MIN_ENCODED_LEN: usize = 4 + 8 + 4 + 4 + 32 + 32 + 64;
}

impl Disclosure {
    /// Empty chunk and an empty proof path.
    pub const MIN_ENCODED_LEN: usize = 1 + 4 + 16 + 4 + 8 + 8 + 4;
}

impl Presentation {
    /// No disclosures.
    pub const MIN_ENCODED_LEN: usize = NotaryAttestation::MIN_ENCODED_LEN + 4;
}

impl Encode for Direction {
    fn encode(&self, out: &mut Vec<u8>) {
        put_u8(out, *self as u8);
    }
}

impl Decode for Direction {
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        match r.u8()? {
            0 => Ok(Direction::Sent),
            1 => Ok(Direction::Received),
            tag => Err(DecodeError::InvalidTag {
                ty: "Direction",
                tag,
            }),
        }
    }
}

impl Encode for NotaryAttestation {
    fn encode(&self, out: &mut Vec<u8>) {
        let NotaryAttestation {
            server_name,
            time,
            sent_len,
            received_len,
            root,
            notary,
            signature,
        } = self;
        put_bytes(out, server_name.as_bytes());
        time.encode(out);
        put_u32(out, *sent_len);
        put_u32(out, *received_len);
        root.encode(out);
        out.extend_from_slice(notary);
        signature.encode(out);
    }
}

impl Decode for NotaryAttestation {
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let server_name = String::from_utf8(r.bytes(MAX_SERVER_NAME_LEN)?)
            .map_err(|_| DecodeError::InvalidValue("NotaryAttestation.server_name"))?;
        Ok(NotaryAttestation {
            server_name,
            time: r.u64()?,
            sent_len: r.u32()?,
            received_len: r.u32()?,
            root: Hash32::decode(r)?,
            notary: r.array()?,
            signature: Signature::decode(r)?,
        })
    }
}

impl Encode for Disclosure {
    fn encode(&self, out: &mut Vec<u8>) {
        let Disclosure {
            direction,
            index,
            salt,
            bytes,
            proof,
        } = self;
        direction.encode(out);
        put_u32(out, *index);
        out.extend_from_slice(salt);
        put_bytes(out, bytes);
        proof.encode(out);
    }
}

impl Decode for Disclosure {
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(Disclosure {
            direction: Direction::decode(r)?,
            index: r.u32()?,
            salt: r.array()?,
            bytes: r.bytes(CHUNK)?,
            proof: InclusionProof::decode(r)?,
        })
    }
}

impl Encode for Presentation {
    fn encode(&self, out: &mut Vec<u8>) {
        let Presentation {
            attestation,
            disclosures,
        } = self;
        attestation.encode(out);
        put_seq(out, disclosures);
    }
}

impl Decode for Presentation {
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(Presentation {
            attestation: NotaryAttestation::decode(r)?,
            disclosures: r.seq(MAX_DISCLOSURES)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::crypto::Keypair;
    use rand::SeedableRng;

    use super::*;
    use crate::tls_proof::{Notary, Transcript, Trust, verify};

    fn notarised() -> (Presentation, Trust) {
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(5);
        let notary = Notary::new(Keypair::generate(&mut rng));
        let body =
            br#"{"symbol":"SOLUSD","price":"142.37","ts":1700000000,"pad":"................"}"#;
        let (att, open) = notary
            .notarize(
                &mut rng,
                Transcript {
                    server_name: "api.exchange.test".into(),
                    time: 1000,
                    sent: b"GET /ticker HTTP/1.1".to_vec(),
                    received: body.to_vec(),
                },
            )
            .unwrap();
        let trust = Trust {
            notaries: [notary.public_key()].into(),
            servers: ["api.exchange.test".to_string()].into(),
            max_age_secs: 60,
        };
        (open.disclose_received(&att, 10..70), trust)
    }

    #[test]
    fn codec_round_trips_a_verifiable_presentation() {
        let (p, trust) = notarised();
        assert!(p.disclosures.len() >= 2);
        let back = Presentation::decode_exact(&p.to_bytes()).unwrap();
        assert_eq!(back, p);
        assert_eq!(back.digest(), p.digest());
        assert_eq!(verify(&back, &trust, 1010), verify(&p, &trust, 1010));
        assert!(verify(&back, &trust, 1010).is_ok());
    }

    #[test]
    fn codec_min_lengths() {
        let (mut p, _) = notarised();
        p.attestation.server_name.clear();
        p.disclosures.clear();
        assert_eq!(p.to_bytes().len(), Presentation::MIN_ENCODED_LEN);
        assert_eq!(Presentation::decode_exact(&p.to_bytes()).unwrap(), p);
        let d = Disclosure {
            direction: Direction::Sent,
            index: 0,
            salt: [0; 16],
            bytes: Vec::new(),
            proof: InclusionProof {
                index: 0,
                tree_size: 1,
                path: Vec::new(),
            },
        };
        assert_eq!(d.to_bytes().len(), Disclosure::MIN_ENCODED_LEN);
        assert_eq!(Disclosure::decode_exact(&d.to_bytes()).unwrap(), d);
    }

    #[test]
    fn codec_bounds_names_chunks_and_disclosures_before_allocating() {
        let (p, _) = notarised();

        let mut long = p.clone();
        long.attestation.server_name = "a".repeat(MAX_SERVER_NAME_LEN + 1);
        assert!(matches!(
            Presentation::decode_exact(&long.to_bytes()),
            Err(DecodeError::LengthExceeded { .. })
        ));

        let mut big = p.clone();
        big.disclosures[0].bytes = vec![0; CHUNK + 1];
        assert!(matches!(
            Presentation::decode_exact(&big.to_bytes()),
            Err(DecodeError::LengthExceeded { .. })
        ));

        let mut many = p.attestation.to_bytes();
        many.extend_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(
            Presentation::decode_exact(&many),
            Err(DecodeError::LengthExceeded {
                len: u32::MAX as usize,
                max: MAX_DISCLOSURES
            })
        );
    }

    #[test]
    fn codec_rejects_bad_direction_tags_and_non_utf8_names() {
        let (p, _) = notarised();
        let mut bytes = p.to_bytes();
        let first_disclosure = p.attestation.to_bytes().len() + 4;
        bytes[first_disclosure] = 2;
        assert_eq!(
            Presentation::decode_exact(&bytes),
            Err(DecodeError::InvalidTag {
                ty: "Direction",
                tag: 2
            })
        );

        let mut bytes = p.to_bytes();
        bytes[4] = 0xff;
        assert_eq!(
            Presentation::decode_exact(&bytes),
            Err(DecodeError::InvalidValue("NotaryAttestation.server_name"))
        );
    }

    #[test]
    fn codec_rejects_trailing_and_missing_bytes() {
        let (p, _) = notarised();
        let mut bytes = p.to_bytes();
        bytes.push(0);
        assert_eq!(
            Presentation::decode_exact(&bytes),
            Err(DecodeError::TrailingBytes(1))
        );
        bytes.truncate(bytes.len() - 2);
        assert!(matches!(
            Presentation::decode_exact(&bytes),
            Err(DecodeError::UnexpectedEof { .. })
        ));
    }
}
