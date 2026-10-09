//! External-data provenance in the style of TLSNotary.
//!
//! ```text
//! External API -> TLS session -> notary attests to transcript commitments
//!   -> prover discloses selected ranges -> verifier checks -> claim
//! ```
//!
//! The transcript is split into fixed-size chunks. Each chunk gets a salted
//! hash commitment and the commitments form a Merkle tree. The notary signs
//! the server name, session time, transcript lengths and the root. The
//! prover later reveals only the chunks a claim needs (say, the bytes
//! holding a price) with their salts and inclusion proofs. Everything else
//! stays hidden behind the salted hashes.
//!
//! **What this is not.** In TLSNotary the notary jointly runs the TLS
//! client with the prover in MPC and never sees the plaintext. It signs
//! commitments the prover made to data both parties authenticated. Here the
//! [`Notary`] receives the transcript directly. The disclosure format and
//! the verification logic are the parts Timescales depends on and are modelled
//! faithfully. The trust placed in the notary is *stronger* in this model
//! (it sees the data) and the server authentication step is assumed. The
//! actual protocol is TLS 1.2 only at the time of writing and in alpha.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::cast_possible_truncation))]

pub mod codec;

use std::collections::{BTreeMap, BTreeSet};

use crate::Hash32;
use crate::crypto::{Hasher, Keypair, Signature, domain, verify_digest};
use crate::merkle::{InclusionProof, MerkleTree, leaf_hash};
use rand_core::{CryptoRng, RngCore};
use thiserror::Error;

pub const CHUNK: usize = 32;
/// Responses larger than this are refused (bounds tree size and memory).
pub const MAX_TRANSCRIPT: usize = 1 << 20;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum TlsProofError {
    #[error("notary key not trusted")]
    UntrustedNotary,
    #[error("server {0} not allowed")]
    Server(String),
    #[error("attestation signature invalid")]
    BadSignature,
    #[error("attestation too old or from the future")]
    Stale,
    #[error("disclosed chunk does not match the attested transcript")]
    BadDisclosure,
    #[error("transcript too large")]
    TooLarge,
    #[error("no received bytes in the requested range")]
    NothingToDisclose,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Direction {
    Sent = 0,
    Received = 1,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transcript {
    pub server_name: String,
    pub time: u64,
    pub sent: Vec<u8>,
    pub received: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NotaryAttestation {
    pub server_name: String,
    pub time: u64,
    pub sent_len: u32,
    pub received_len: u32,
    pub root: Hash32,
    pub notary: [u8; 32],
    pub signature: Signature,
}

impl NotaryAttestation {
    fn digest(server: &str, time: u64, sent_len: u32, recv_len: u32, root: &Hash32) -> Hash32 {
        Hasher::new(domain::TLS_ATTESTATION)
            .chain(&(server.len() as u64).to_le_bytes())
            .chain(server.as_bytes())
            .chain(&time.to_le_bytes())
            .chain(&sent_len.to_le_bytes())
            .chain(&recv_len.to_le_bytes())
            .chain(root.as_bytes())
            .finalize()
    }

    pub fn digest_self(&self) -> Hash32 {
        Self::digest(
            &self.server_name,
            self.time,
            self.sent_len,
            self.received_len,
            &self.root,
        )
    }
}

/// Chunk commitments are ordered: all sent chunks, then all received.
fn chunk_commitment(dir: Direction, index: u32, salt: &[u8; 16], bytes: &[u8]) -> Hash32 {
    Hasher::new(domain::TLS_CHUNK)
        .chain(&[dir as u8])
        .chain(&index.to_le_bytes())
        .chain(salt)
        .chain(bytes)
        .finalize()
}

fn chunks(data: &[u8]) -> Vec<&[u8]> {
    data.chunks(CHUNK).collect()
}

/// Private openings kept by the prover after notarisation.
#[derive(Clone, Debug)]
pub struct Openings {
    transcript: Transcript,
    salts: Vec<[u8; 16]>,
    tree: MerkleTree,
}

#[derive(Debug)]
pub struct Notary {
    key: Keypair,
}

impl Notary {
    pub fn new(key: Keypair) -> Self {
        Self { key }
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.key.public()
    }

    pub fn notarize<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        t: Transcript,
    ) -> Result<(NotaryAttestation, Openings), TlsProofError> {
        if t.sent.len() > MAX_TRANSCRIPT || t.received.len() > MAX_TRANSCRIPT {
            return Err(TlsProofError::TooLarge);
        }
        let mut salts = Vec::new();
        let mut leaves = Vec::new();
        for (dir, data) in [
            (Direction::Sent, &t.sent),
            (Direction::Received, &t.received),
        ] {
            for (i, c) in chunks(data).iter().enumerate() {
                let mut s = [0u8; 16];
                rng.fill_bytes(&mut s);
                let idx = u32::try_from(i).map_err(|_| TlsProofError::TooLarge)?;
                leaves.push(leaf_hash(chunk_commitment(dir, idx, &s, c).as_bytes()));
                salts.push(s);
            }
        }
        let tree = MerkleTree::from_leaf_hashes(leaves);
        let sent_len = u32::try_from(t.sent.len()).map_err(|_| TlsProofError::TooLarge)?;
        let received_len = u32::try_from(t.received.len()).map_err(|_| TlsProofError::TooLarge)?;
        let d =
            NotaryAttestation::digest(&t.server_name, t.time, sent_len, received_len, &tree.root());
        let att = NotaryAttestation {
            server_name: t.server_name.clone(),
            time: t.time,
            sent_len,
            received_len,
            root: tree.root(),
            notary: self.key.public(),
            signature: self.key.sign_digest(&d),
        };
        Ok((
            att,
            Openings {
                transcript: t,
                salts,
                tree,
            },
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Disclosure {
    pub direction: Direction,
    pub index: u32,
    pub salt: [u8; 16],
    pub bytes: Vec<u8>,
    pub proof: InclusionProof,
}

/// What a prover shows a verifier: the attestation and some chunks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Presentation {
    pub attestation: NotaryAttestation,
    pub disclosures: Vec<Disclosure>,
}

impl Presentation {
    pub fn digest(&self) -> Hash32 {
        let mut h = Hasher::new(domain::TLS_ATTESTATION)
            .chain(b"presentation")
            .chain(self.attestation.digest_self().as_bytes());
        for d in &self.disclosures {
            h.update(&[d.direction as u8]);
            h.update(&d.index.to_le_bytes());
            h.update(&d.salt);
            h.update(&(d.bytes.len() as u64).to_le_bytes());
            h.update(&d.bytes);
        }
        h.finalize()
    }
}

impl Openings {
    /// Disclose the received chunks covering `range` (byte offsets), clipped
    /// to the received transcript. Fails when that leaves nothing to
    /// disclose: an empty response, an empty range or one past its end.
    pub fn try_disclose_received(
        &self,
        att: &NotaryAttestation,
        range: core::ops::Range<usize>,
    ) -> Result<Presentation, TlsProofError> {
        let received = &self.transcript.received;
        let end = range.end.min(received.len());
        if range.start >= end {
            return Err(TlsProofError::NothingToDisclose);
        }
        let sent_chunks = self.transcript.sent.len().div_ceil(CHUNK);
        let chunks = range.start / CHUNK..=(end - 1) / CHUNK;
        // i < received chunks, so every leaf < salts.len.
        let leaves: Vec<usize> = chunks.clone().map(|i| sent_chunks + i).collect();
        let proofs = self
            .tree
            .proofs_for(&leaves)
            .map_err(|_| TlsProofError::BadDisclosure)?;
        let disclosures = chunks
            .zip(proofs)
            .map(|(i, proof)| {
                let at = i * CHUNK;
                Ok(Disclosure {
                    direction: Direction::Received,
                    index: u32::try_from(i).map_err(|_| TlsProofError::TooLarge)?,
                    salt: self.salts[sent_chunks + i],
                    bytes: received[at..received.len().min(at + CHUNK)].to_vec(),
                    proof,
                })
            })
            .collect::<Result<_, TlsProofError>>()?;
        Ok(Presentation {
            attestation: att.clone(),
            disclosures,
        })
    }

    /// [`Self::try_disclose_received`], except that a range with nothing to
    /// disclose yields a presentation without disclosures, from which no
    /// claim can be read.
    pub fn disclose_received(
        &self,
        att: &NotaryAttestation,
        range: core::ops::Range<usize>,
    ) -> Presentation {
        self.try_disclose_received(att, range)
            .unwrap_or_else(|_| Presentation {
                attestation: att.clone(),
                disclosures: Vec::new(),
            })
    }
}

/// Verifier's trust configuration.
#[derive(Clone, Debug, Default)]
pub struct Trust {
    pub notaries: BTreeSet<[u8; 32]>,
    pub servers: BTreeSet<String>,
    pub max_age_secs: u64,
}

/// What a verified presentation establishes: these received bytes, at these
/// offsets, came from `server_name` at `time` (under the trust model above).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Disclosed {
    pub server_name: String,
    pub time: u64,
    /// Offset -> bytes, received direction only.
    pub received: BTreeMap<usize, Vec<u8>>,
}

impl Disclosed {
    /// Longest contiguous disclosed run starting at the lowest offset.
    pub fn contiguous(&self) -> Vec<u8> {
        let mut out = Vec::new();
        let mut next = None;
        for (off, b) in &self.received {
            if next.is_some_and(|n| n != *off) {
                break;
            }
            out.extend_from_slice(b);
            next = Some(off + b.len());
        }
        out
    }
}

pub fn verify(p: &Presentation, trust: &Trust, now: u64) -> Result<Disclosed, TlsProofError> {
    let a = &p.attestation;
    if !trust.notaries.contains(&a.notary) {
        return Err(TlsProofError::UntrustedNotary);
    }
    if !trust.servers.contains(&a.server_name) {
        return Err(TlsProofError::Server(a.server_name.clone()));
    }
    verify_digest(&a.notary, &a.digest_self(), &a.signature)
        .map_err(|_| TlsProofError::BadSignature)?;
    if a.time > now || now - a.time > trust.max_age_secs {
        return Err(TlsProofError::Stale);
    }
    let sent_chunks = (a.sent_len as usize).div_ceil(CHUNK);
    let recv_chunks = (a.received_len as usize).div_ceil(CHUNK);
    let mut received = BTreeMap::new();
    for d in &p.disclosures {
        let (leaf_index, expected_len) = match d.direction {
            Direction::Sent => {
                let i = d.index as usize;
                (
                    i,
                    if i + 1 == sent_chunks {
                        a.sent_len as usize - i * CHUNK
                    } else {
                        CHUNK
                    },
                )
            }
            Direction::Received => {
                let i = d.index as usize;
                if i >= recv_chunks {
                    return Err(TlsProofError::BadDisclosure);
                }
                (
                    sent_chunks + i,
                    if i + 1 == recv_chunks {
                        a.received_len as usize - i * CHUNK
                    } else {
                        CHUNK
                    },
                )
            }
        };
        if d.bytes.len() != expected_len || d.proof.index != leaf_index as u64 {
            return Err(TlsProofError::BadDisclosure);
        }
        let leaf = leaf_hash(chunk_commitment(d.direction, d.index, &d.salt, &d.bytes).as_bytes());
        d.proof
            .verify(&a.root, &leaf)
            .map_err(|_| TlsProofError::BadDisclosure)?;
        if d.direction == Direction::Received {
            received.insert(d.index as usize * CHUNK, d.bytes.clone());
        }
    }
    Ok(Disclosed {
        server_name: a.server_name.clone(),
        time: a.time,
        received,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    fn setup() -> (Notary, Trust, rand_chacha::ChaCha20Rng) {
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(1);
        let n = Notary::new(Keypair::generate(&mut rng));
        let trust = Trust {
            notaries: [n.public_key()].into(),
            servers: ["api.example-exchange.test".to_string()].into(),
            max_age_secs: 60,
        };
        (n, trust, rng)
    }

    fn transcript() -> Transcript {
        let body = br#"{"account":"private-id-12345","balance":"999999","symbol":"SOLUSD","price":"142.37","ts":1700000000}"#;
        Transcript {
            server_name: "api.example-exchange.test".into(),
            time: 1000,
            sent: b"GET /ticker HTTP/1.1".to_vec(),
            received: body.to_vec(),
        }
    }

    #[test]
    fn selective_disclosure_verifies_and_hides_the_rest() {
        let (n, trust, mut rng) = setup();
        let t = transcript();
        let (att, open) = n.notarize(&mut rng, t.clone()).unwrap();
        let at = t
            .received
            .windows(7)
            .position(|w| w == b"\"price\"")
            .unwrap();
        let p = open.disclose_received(&att, at..at + 16);
        let d = verify(&p, &trust, 1010).unwrap();
        let shown: Vec<u8> = d.received.values().flatten().copied().collect();
        assert!(shown.windows(6).any(|w| w == b"142.37"));
        assert!(
            !shown.windows(10).any(|w| w == b"private-id"),
            "unrelated fields must stay hidden"
        );
    }

    #[test]
    fn empty_response_has_nothing_to_disclose() {
        let (n, trust, mut rng) = setup();
        let mut t = transcript();
        t.received.clear();
        let (att, open) = n.notarize(&mut rng, t).unwrap();
        for range in [0..10, 0..0, 5..40, 31..32] {
            assert_eq!(
                open.try_disclose_received(&att, range.clone()).map(|_| ()),
                Err(TlsProofError::NothingToDisclose)
            );
            let p = open.disclose_received(&att, range);
            assert!(p.disclosures.is_empty());
            let d = verify(&p, &trust, 1010).unwrap();
            assert!(d.received.is_empty() && d.contiguous().is_empty());
        }
    }

    #[test]
    fn oversized_transcripts_are_refused() {
        let (n, _, mut rng) = setup();
        let mut t = transcript();
        t.received = vec![b'x'; MAX_TRANSCRIPT + 1];
        assert_eq!(
            n.notarize(&mut rng, t).map(|_| ()),
            Err(TlsProofError::TooLarge)
        );
    }

    #[test]
    fn ranges_are_clipped_to_the_response() {
        let (n, trust, mut rng) = setup();
        let t = transcript();
        let len = t.received.len();
        let (att, open) = n.notarize(&mut rng, t.clone()).unwrap();
        // Empty, and starting at or past the end.
        for range in [10..10, len..len + 5, len + 40..len + 80] {
            assert_eq!(
                open.try_disclose_received(&att, range).map(|_| ()),
                Err(TlsProofError::NothingToDisclose)
            );
        }
        // Running past the end discloses up to the end.
        let p = open.try_disclose_received(&att, 0..len + 1000).unwrap();
        assert_eq!(p.disclosures.len(), len.div_ceil(CHUNK));
        let d = verify(&p, &trust, 1010).unwrap();
        assert_eq!(d.contiguous(), t.received);
        // The last byte alone is the last, short chunk.
        let p = open.try_disclose_received(&att, len - 1..len).unwrap();
        assert_eq!(p.disclosures.len(), 1);
        assert_eq!(
            p.disclosures[0].bytes.len(),
            len - (len - 1) / CHUNK * CHUNK
        );
        assert!(verify(&p, &trust, 1010).is_ok());
        // Both entry points agree wherever there is something to disclose.
        assert_eq!(
            open.disclose_received(&att, 20..50),
            open.try_disclose_received(&att, 20..50).unwrap()
        );
    }

    #[test]
    fn tampering_and_policy_failures() {
        let (n, trust, mut rng) = setup();
        let t = transcript();
        let (att, open) = n.notarize(&mut rng, t.clone()).unwrap();
        let mut p = open.disclose_received(&att, 60..80);
        p.disclosures[0].bytes[0] ^= 1;
        assert_eq!(verify(&p, &trust, 1010), Err(TlsProofError::BadDisclosure));

        let p = open.disclose_received(&att, 60..80);
        assert_eq!(verify(&p, &trust, 2000), Err(TlsProofError::Stale));
        let mut p2 = p.clone();
        p2.attestation.server_name = "evil.test".into();
        assert!(matches!(
            verify(&p2, &trust, 1010),
            Err(TlsProofError::Server(_))
        ));
        let mut t3 = trust.clone();
        t3.servers.insert("evil.test".into());
        assert_eq!(verify(&p2, &t3, 1010), Err(TlsProofError::BadSignature));
        let other = Notary::new(Keypair::generate(&mut rng));
        let (att2, open2) = other.notarize(&mut rng, t).unwrap();
        assert_eq!(
            verify(&open2.disclose_received(&att2, 0..10), &trust, 1010),
            Err(TlsProofError::UntrustedNotary)
        );
    }

    #[test]
    fn every_tls_proof_error_is_produced() {
        // Exhaustive on purpose: a new variant must be produced here.
        fn variant(e: &TlsProofError) -> usize {
            match e {
                TlsProofError::UntrustedNotary => 0,
                TlsProofError::Server(_) => 1,
                TlsProofError::BadSignature => 2,
                TlsProofError::Stale => 3,
                TlsProofError::BadDisclosure => 4,
                TlsProofError::TooLarge => 5,
                TlsProofError::NothingToDisclose => 6,
            }
        }
        let (n, trust, mut rng) = setup();
        let (att, open) = n.notarize(&mut rng, transcript()).unwrap();
        let p = open.disclose_received(&att, 0..40);
        let mut errors = Vec::new();

        let untrusted = Trust {
            notaries: BTreeSet::new(),
            ..trust.clone()
        };
        errors.push(verify(&p, &untrusted, 1010).map(|_| ()));
        let elsewhere = Trust {
            servers: ["other.test".to_string()].into(),
            ..trust.clone()
        };
        errors.push(verify(&p, &elsewhere, 1010).map(|_| ()));
        let mut forged = p.clone();
        forged.attestation.time += 1;
        errors.push(verify(&forged, &trust, 1010).map(|_| ()));
        errors.push(verify(&p, &trust, 999).map(|_| ()));
        let mut moved = p.clone();
        moved.disclosures[0].index += 1;
        errors.push(verify(&moved, &trust, 1010).map(|_| ()));
        let mut huge = transcript();
        huge.sent = vec![0; MAX_TRANSCRIPT + 1];
        errors.push(n.notarize(&mut rng, huge).map(|_| ()));
        errors.push(open.try_disclose_received(&att, 4096..4100).map(|_| ()));

        let seen: Vec<usize> = errors
            .iter()
            .map(|e| variant(e.as_ref().unwrap_err()))
            .collect();
        assert_eq!(seen, [0, 1, 2, 3, 4, 5, 6]);
    }
}
