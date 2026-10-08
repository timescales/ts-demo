//! Domain-separated SHA-256.
//!
//! Every hash in the protocol is `SHA-256(len(tag) || tag || data)` where
//! `tag` names the purpose. Inputs are always canonical encodings, which are
//! self-delimiting, so concatenating them is unambiguous.

use crate::Hash32;
use sha2::{Digest, Sha256};

/// Domain tags. One per distinct use. Never reuse a tag for a new purpose.
pub mod domain {
    pub const ORDER_COMMITMENT: &[u8] = b"timescales/v1/order-commitment";
    pub const ENVELOPE_COMMITMENT: &[u8] = b"timescales/v1/envelope-commitment";
    pub const INTENT_SIGNATURE: &[u8] = b"timescales/v1/intent-signature";
    pub const PRIORITY_KEY: &[u8] = b"timescales/v1/priority-key";
    pub const BATCH_SEED: &[u8] = b"timescales/v1/batch-seed";
    pub const BATCH_HEADER: &[u8] = b"timescales/v1/batch-header";
    pub const MERKLE_LEAF: &[u8] = b"timescales/v1/merkle-leaf";
    pub const MERKLE_NODE: &[u8] = b"timescales/v1/merkle-node";
    pub const RECEIPT: &[u8] = b"timescales/v1/execution-receipt";
    pub const OUTCOME: &[u8] = b"timescales/v1/execution-outcome";
    pub const TRACE: &[u8] = b"timescales/v1/execution-trace";
    pub const SETTLEMENT: &[u8] = b"timescales/v1/settlement";
    pub const ATTESTATION_REPORT: &[u8] = b"timescales/v1/attestation-report";
    pub const REPORT_DATA: &[u8] = b"timescales/v1/report-data";
    pub const KEY_RELEASE: &[u8] = b"timescales/v1/key-release";
    pub const MEASUREMENT: &[u8] = b"timescales/v1/measurement";
    pub const PRICE_COMMITMENT: &[u8] = b"timescales/v1/price-commitment";
    pub const TLS_ATTESTATION: &[u8] = b"timescales/v1/tls-attestation";
    pub const TLS_CHUNK: &[u8] = b"timescales/v1/tls-chunk";
    pub const PROOF: &[u8] = b"timescales/v1/execution-proof";
    pub const RELAY_SUBMISSION: &[u8] = b"timescales/v1/relay-submission";
    pub const SEAL_KDF: &[u8] = b"timescales/v1/seal";
    pub const MARKET_PARAMS: &[u8] = b"timescales/v1/market-params";
    pub const RPC_ENVELOPE: &[u8] = b"timescales/v1/rpc-envelope";
    pub const COMMITTEE: &[u8] = b"timescales/v1/krc-committee";
    pub const EPOCH_KEY: &[u8] = b"timescales/v1/epoch-key";
    pub const KRC_SHARE: &[u8] = b"timescales/v1/krc-share";
    pub const REPORT_DATA_V2: &[u8] = b"timescales/v1/report-data-v2";
    pub const EXECUTOR_REGISTRATION: &[u8] = b"timescales/v1/executor-registration";
    pub const EPOCH_TERMS: &[u8] = b"timescales/v1/epoch-terms";
    pub const EPOCH_ANNOUNCEMENT: &[u8] = b"timescales/v1/epoch-announcement";
    pub const RECEIPT_COSIGN: &[u8] = b"timescales/v1/receipt-cosign";
    pub const SESSION: &[u8] = b"timescales/v1/session";
    pub const EPOCH_SEED: &[u8] = b"timescales/v1/epoch-seed";
    pub const EPOCH_BINDING: &[u8] = b"timescales/v1/epoch-binding";
    pub const MARKET_ID: &[u8] = b"timescales/v1/market-id";
    pub const RELEASE_POLICY: &[u8] = b"timescales/v1/release-policy";
    pub const EPOCH_KEY_ACK: &[u8] = b"timescales/v1/epoch-key-ack";
    pub const RELAY_REFUSAL: &[u8] = b"timescales/v1/relay-refusal";
    pub const SESSION_NONCE: &[u8] = b"timescales/v1/session-nonce";
}

/// Incremental domain-separated hasher.
#[derive(Clone, Debug)]
pub struct Hasher(Sha256);

impl Hasher {
    pub fn new(domain: &[u8]) -> Self {
        let tag_len = u8::try_from(domain.len()).expect("domain tag longer than 255 bytes");
        let mut h = Sha256::new();
        h.update([tag_len]);
        h.update(domain);
        Self(h)
    }

    pub fn update(&mut self, data: &[u8]) -> &mut Self {
        self.0.update(data);
        self
    }

    pub fn chain(mut self, data: &[u8]) -> Self {
        self.0.update(data);
        self
    }

    pub fn finalize(self) -> Hash32 {
        Hash32(self.0.finalize().into())
    }
}

pub fn hash(domain: &[u8], data: &[u8]) -> Hash32 {
    Hasher::new(domain).chain(data).finalize()
}

pub fn hash_parts(domain: &[u8], parts: &[&[u8]]) -> Hash32 {
    let mut h = Hasher::new(domain);
    for p in parts {
        h.update(p);
    }
    h.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domains_separate() {
        assert_ne!(hash(domain::RECEIPT, b"x"), hash(domain::OUTCOME, b"x"));
    }

    #[test]
    fn incremental_matches_oneshot() {
        let a = hash_parts(domain::TRACE, &[b"ab", b"c"]);
        let b = hash(domain::TRACE, b"abc");
        assert_eq!(a, b);
    }

    #[test]
    fn tags_are_unique() {
        use domain::*;
        let all = [
            ORDER_COMMITMENT,
            ENVELOPE_COMMITMENT,
            INTENT_SIGNATURE,
            PRIORITY_KEY,
            BATCH_SEED,
            BATCH_HEADER,
            MERKLE_LEAF,
            MERKLE_NODE,
            RECEIPT,
            OUTCOME,
            TRACE,
            SETTLEMENT,
            ATTESTATION_REPORT,
            REPORT_DATA,
            KEY_RELEASE,
            MEASUREMENT,
            PRICE_COMMITMENT,
            TLS_ATTESTATION,
            TLS_CHUNK,
            PROOF,
            RELAY_SUBMISSION,
            SEAL_KDF,
            MARKET_PARAMS,
            RPC_ENVELOPE,
            COMMITTEE,
            EPOCH_KEY,
            KRC_SHARE,
            REPORT_DATA_V2,
            EXECUTOR_REGISTRATION,
            EPOCH_TERMS,
            EPOCH_ANNOUNCEMENT,
            RECEIPT_COSIGN,
            SESSION,
            EPOCH_SEED,
            EPOCH_BINDING,
            MARKET_ID,
            RELEASE_POLICY,
            EPOCH_KEY_ACK,
            RELAY_REFUSAL,
            SESSION_NONCE,
        ];
        assert_eq!(all.len(), 40);
        let mut sorted = all.to_vec();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), all.len());
        for tag in all {
            assert!(tag.starts_with(b"timescales/v1/"));
            assert!(tag.len() <= 255);
            // H_tag(x) = SHA-256(u8 len(tag) || tag || x).
            let mut framed = vec![u8::try_from(tag.len()).unwrap()];
            framed.extend_from_slice(tag);
            framed.extend_from_slice(b"abc");
            let expected: [u8; 32] = Sha256::digest(&framed).into();
            assert_eq!(hash(tag, b"abc"), Hash32(expected));
        }
    }

    /// The production tags: exact bytes, and `H_tag("abc")` as
    /// computed independently (Python `hashlib`), so neither the strings nor
    /// the framing can drift without failing here.
    #[test]
    fn production_tags_are_pinned() {
        use domain::*;
        let pinned: [(&[u8], &str, &str); 17] = [
            (
                RPC_ENVELOPE,
                "timescales/v1/rpc-envelope",
                "7fbe63c8079e40165a759614eac72ad40609f7dc2001c08f1fbf13804084e068",
            ),
            (
                COMMITTEE,
                "timescales/v1/krc-committee",
                "05c688bd8211ccc63c291570d1ca97d227ba9e7df508e214563fcc7227466ee1",
            ),
            (
                EPOCH_KEY,
                "timescales/v1/epoch-key",
                "d21cf7e1baae06362806f26eb6da21ebab86687ea600e621f9a2c6ed4f58b2e7",
            ),
            (
                KRC_SHARE,
                "timescales/v1/krc-share",
                "9e6e2230b63748d70c926f5e56df368986af356df01f2dcab33fc1aaa9c29cb1",
            ),
            (
                REPORT_DATA_V2,
                "timescales/v1/report-data-v2",
                "9afbd646916d97f2984bed14650651ddd712fc3506b7ff305974552285057bd5",
            ),
            (
                EXECUTOR_REGISTRATION,
                "timescales/v1/executor-registration",
                "a0a3e7e95d3b63057227eb058c96a3cfbcefa7601d3b72ffb55ebcff0c559882",
            ),
            (
                EPOCH_TERMS,
                "timescales/v1/epoch-terms",
                "313b23348d7b9e41a1b9edab815a7aafe4e77fd2c797286b829222c81d103532",
            ),
            (
                EPOCH_ANNOUNCEMENT,
                "timescales/v1/epoch-announcement",
                "f551db8cb8869b7949ee5c15ca81a253289cdcb703b75eb8914ce3279dd31aad",
            ),
            (
                RECEIPT_COSIGN,
                "timescales/v1/receipt-cosign",
                "a85755b33c5272aba31c92bc0aaa12829aba30a6cb871f6d00920a6ca052175d",
            ),
            (
                SESSION,
                "timescales/v1/session",
                "5a238efd487d0e035d4dca9ca38d95243d8cfe1af8991143c62304942b400e5c",
            ),
            (
                EPOCH_SEED,
                "timescales/v1/epoch-seed",
                "0f299cfd83501efeaa028678f02ab4b6022429b6789236bab49cbe53faad3fb9",
            ),
            (
                EPOCH_BINDING,
                "timescales/v1/epoch-binding",
                "4bde9cf9d9d7964239176ba6dc6c008d6884e32fe79925222330a6abf46772f9",
            ),
            (
                MARKET_ID,
                "timescales/v1/market-id",
                "87a25ab290d883312fd1697e4221088e979a102a15325df25e817336f92225a0",
            ),
            (
                RELEASE_POLICY,
                "timescales/v1/release-policy",
                "2929f1e9a856e18d9598661d4e90a968921d1b4ff38a0d5140fb263ad821a49a",
            ),
            (
                EPOCH_KEY_ACK,
                "timescales/v1/epoch-key-ack",
                "b0cceadefd0a205294992c2d82bef6c5d9a8f5b95755641ae2f762786d9386f0",
            ),
            (
                RELAY_REFUSAL,
                "timescales/v1/relay-refusal",
                "1f6c6abc4282694c312c0ba4a1390a6dd1710e3b33e68dbce3a5f4b9f246b528",
            ),
            (
                SESSION_NONCE,
                "timescales/v1/session-nonce",
                "99ed8425a5a43f58072cd21176c5d5ee7a1e172d1f772f0155e20881d47e447d",
            ),
        ];
        for (tag, name, abc) in pinned {
            assert_eq!(tag, name.as_bytes());
            assert_eq!(Some(hash(tag, b"abc")), Hash32::from_hex(abc), "{name}");
        }
    }
}
