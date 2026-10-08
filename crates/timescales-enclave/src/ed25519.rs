//! Strict Ed25519 verification of messages of any length.
//!
//! Wallets sign SIWS grants over the raw UTF-8 text, while
//! the core crypto verifies only 32-byte digests and this crate may not
//! depend on `ed25519-dalek`. The check is assembled from
//! the curve operations it exposes and the SHA-512 below,
//! with the rules of ed25519-dalek's `verify_strict`: canonical `A`, `R`
//! and `S`, neither `A` nor `R` of small order, and the cofactorless
//! equation `[S]B = R + [k]A` with `k = SHA-512(R || A || M) mod L`.

use core::ops::{Add, Mul};

use timescales_core::crypto::threshold::{ScalarShare, decompress_canonical};

/// The Ed25519 base point, compressed.
pub(crate) const BASEPOINT: [u8; 32] = {
    let mut b = [0x66u8; 32];
    b[0] = 0x58;
    b
};

/// `sum bytes[i]*256^i` in the scalar field `witness` belongs to.
pub(crate) fn reduce_le<T>(_witness: &T, bytes: &[u8]) -> T
where
    T: From<u64> + Copy + Add<Output = T> + Mul<Output = T>,
{
    let radix = T::from(256);
    bytes
        .iter()
        .rev()
        .fold(T::from(0), |acc, b| acc * radix + T::from(u64::from(*b)))
}

/// Whether `signature` is `public`'s strict Ed25519 signature of `message`.
pub(crate) fn verify_strict(public: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    let (r_bytes, s_bytes) = signature.split_at(32);
    let (Ok(r_bytes), Ok(s_bytes)) = (<[u8; 32]>::try_from(r_bytes), <[u8; 32]>::try_from(s_bytes))
    else {
        return false;
    };
    let (Some(a), Some(r), Some(b)) = (
        decompress_canonical(public),
        decompress_canonical(&r_bytes),
        decompress_canonical(&BASEPOINT),
    ) else {
        return false;
    };
    if a.is_small_order() || r.is_small_order() {
        return false;
    }
    // `S` must be below the group order.
    let Some(s) = ScalarShare::from_bytes(1, &s_bytes) else {
        return false;
    };
    let s = s.value;
    let mut h = Sha512::new();
    h.update(&r_bytes);
    h.update(public);
    h.update(message);
    let k = reduce_le(&s, &h.finalize());
    b * s == r + a * k
}

/// SHA-512 (FIPS 180-4).
pub(crate) struct Sha512 {
    state: [u64; 8],
    block: [u8; 128],
    filled: usize,
    /// Message length in bytes so far.
    len: u128,
}

const K: [u64; 80] = [
    0x428a2f98d728ae22,
    0x7137449123ef65cd,
    0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc,
    0x3956c25bf348b538,
    0x59f111f1b605d019,
    0x923f82a4af194f9b,
    0xab1c5ed5da6d8118,
    0xd807aa98a3030242,
    0x12835b0145706fbe,
    0x243185be4ee4b28c,
    0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f,
    0x80deb1fe3b1696b1,
    0x9bdc06a725c71235,
    0xc19bf174cf692694,
    0xe49b69c19ef14ad2,
    0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5,
    0x240ca1cc77ac9c65,
    0x2de92c6f592b0275,
    0x4a7484aa6ea6e483,
    0x5cb0a9dcbd41fbd4,
    0x76f988da831153b5,
    0x983e5152ee66dfab,
    0xa831c66d2db43210,
    0xb00327c898fb213f,
    0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2,
    0xd5a79147930aa725,
    0x06ca6351e003826f,
    0x142929670a0e6e70,
    0x27b70a8546d22ffc,
    0x2e1b21385c26c926,
    0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df,
    0x650a73548baf63de,
    0x766a0abb3c77b2a8,
    0x81c2c92e47edaee6,
    0x92722c851482353b,
    0xa2bfe8a14cf10364,
    0xa81a664bbc423001,
    0xc24b8b70d0f89791,
    0xc76c51a30654be30,
    0xd192e819d6ef5218,
    0xd69906245565a910,
    0xf40e35855771202a,
    0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8,
    0x1e376c085141ab53,
    0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63,
    0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc,
    0x78a5636f43172f60,
    0x84c87814a1f0ab72,
    0x8cc702081a6439ec,
    0x90befffa23631e28,
    0xa4506cebde82bde9,
    0xbef9a3f7b2c67915,
    0xc67178f2e372532b,
    0xca273eceea26619c,
    0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e,
    0xf57d4f7fee6ed178,
    0x06f067aa72176fba,
    0x0a637dc5a2c898a6,
    0x113f9804bef90dae,
    0x1b710b35131c471b,
    0x28db77f523047d84,
    0x32caab7b40c72493,
    0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6,
    0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec,
    0x6c44198c4a475817,
];

const INIT: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

impl Sha512 {
    pub(crate) fn new() -> Self {
        Self {
            state: INIT,
            block: [0; 128],
            filled: 0,
            len: 0,
        }
    }

    pub(crate) fn update(&mut self, mut data: &[u8]) {
        self.len = self.len.wrapping_add(data.len() as u128);
        while !data.is_empty() {
            let take = (128 - self.filled).min(data.len());
            self.block[self.filled..self.filled + take].copy_from_slice(&data[..take]);
            self.filled += take;
            data = &data[take..];
            if self.filled == 128 {
                let block = self.block;
                self.compress(&block);
                self.filled = 0;
            }
        }
    }

    pub(crate) fn finalize(mut self) -> [u8; 64] {
        let bits = self.len.wrapping_mul(8);
        let mut tail = [0u8; 256];
        tail[..self.filled].copy_from_slice(&self.block[..self.filled]);
        tail[self.filled] = 0x80;
        // The 16-byte length must fit after the padding byte.
        let blocks = if self.filled < 112 { 1 } else { 2 };
        let end = blocks * 128;
        tail[end - 16..end].copy_from_slice(&bits.to_be_bytes());
        for block in tail[..end].as_chunks::<128>().0 {
            self.compress(block);
        }
        let mut out = [0u8; 64];
        for (o, w) in out.as_chunks_mut::<8>().0.iter_mut().zip(self.state) {
            *o = w.to_be_bytes();
        }
        out
    }

    fn compress(&mut self, block: &[u8; 128]) {
        let mut w = [0u64; 80];
        for (slot, word) in w.iter_mut().zip(block.as_chunks::<8>().0) {
            *slot = u64::from_be_bytes(*word);
        }
        for i in 16..80 {
            let s0 = w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ (w[i - 15] >> 7);
            let s1 = w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ (w[i - 2] >> 6);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state;
        for i in 0..80 {
            let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
            let ch = (e & f) ^ (!e & g);
            let t1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (s, v) in self.state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *s = s.wrapping_add(v);
        }
    }
}

#[cfg(test)]
mod tests {
    use timescales_core::crypto::{Keypair, hash};

    use super::*;

    fn sha512(data: &[u8]) -> String {
        let mut h = Sha512::new();
        h.update(data);
        hex::encode(h.finalize())
    }

    #[test]
    fn sha512_matches_the_fips_examples() {
        assert_eq!(
            sha512(b""),
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce\
             47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        );
        assert_eq!(
            sha512(b"abc"),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
             2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
        // Two blocks. The padding of the first does not fit.
        assert_eq!(
            sha512(
                b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno\
                  ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
            ),
            "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018\
             501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"
        );
        // Fed in pieces across block boundaries.
        let data = vec![0x61u8; 1000];
        let mut h = Sha512::new();
        for piece in data.chunks(7) {
            h.update(piece);
        }
        assert_eq!(hex::encode(h.finalize()), sha512(&data));
    }

    #[test]
    fn rfc8032_test_vectors() {
        // RFC 8032 7.1, TEST 1 (empty message) and TEST 2 (one byte).
        let cases = [
            (
                "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
                "",
                "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155\
                 5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
            ),
            (
                "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
                "72",
                "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da\
                 085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
            ),
        ];
        for (public, message, signature) in cases {
            let public: [u8; 32] = hex::decode(public).unwrap().try_into().unwrap();
            let message = hex::decode(message).unwrap();
            let signature: [u8; 64] = hex::decode(signature).unwrap().try_into().unwrap();
            assert!(verify_strict(&public, &message, &signature));
            let mut other = message.clone();
            other.push(0);
            assert!(!verify_strict(&public, &other, &signature));
            let mut bad = signature;
            bad[63] ^= 0x10;
            assert!(!verify_strict(&public, &message, &bad));
        }
    }

    #[test]
    fn agrees_with_the_core_digest_signatures() {
        for i in 0u8..8 {
            let key = Keypair::from_seed([i; 32]);
            let digest = hash(b"timescales/test/ed25519", &[i]);
            let sig = key.sign_digest(&digest);
            assert!(verify_strict(&key.public(), digest.as_bytes(), &sig.0));
            let other = Keypair::from_seed([i ^ 0xff; 32]);
            assert!(!verify_strict(&other.public(), digest.as_bytes(), &sig.0));
        }
    }

    #[test]
    fn small_order_keys_and_non_canonical_s_are_refused() {
        // The identity point is of small order. Any `R = identity, S = 0`
        // "signature" passes the cofactorless equation for it.
        let mut identity = [0u8; 32];
        identity[0] = 1;
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&identity);
        assert!(!verify_strict(&identity, b"anything", &sig));
        // S = L (not reduced).
        let key = Keypair::from_seed([9; 32]);
        let digest = hash(b"timescales/test/ed25519", &[]);
        let mut sig = key.sign_digest(&digest).0;
        let ell: [u8; 32] =
            hex::decode("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010")
                .unwrap()
                .try_into()
                .unwrap();
        sig[32..].copy_from_slice(&ell);
        assert!(!verify_strict(&key.public(), digest.as_bytes(), &sig));
    }
}
