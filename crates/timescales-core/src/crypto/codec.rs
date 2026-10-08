//! Canonical encodings of the crypto types.
//!
//! `SealedBox` is `ephemeral32 || u32 len || ciphertext`. The ciphertext holds
//! at least the Poly1305 tag and at most [`MAX_SEALED_BOX_CIPHERTEXT`] bytes.
//! The length prefix is checked against that bound before anything is
//! allocated.

use crate::{Decode, DecodeError, Encode, Reader, encoding::put_bytes};

use crate::crypto::{SealedBox, TAG_LEN};

/// Largest ciphertext a [`SealedBox`] may carry on the wire.
pub const MAX_SEALED_BOX_CIPHERTEXT: usize = 4096;

impl SealedBox {
    /// Ephemeral key, length prefix and a bare tag (empty plaintext).
    pub const MIN_ENCODED_LEN: usize = 32 + 4 + TAG_LEN;
}

impl Encode for SealedBox {
    fn encode(&self, out: &mut Vec<u8>) {
        let SealedBox {
            ephemeral,
            ciphertext,
        } = self;
        out.extend_from_slice(ephemeral);
        put_bytes(out, ciphertext);
    }
}

impl Decode for SealedBox {
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let ephemeral = r.array()?;
        let ciphertext = r.bytes(MAX_SEALED_BOX_CIPHERTEXT)?;
        if ciphertext.len() < TAG_LEN {
            return Err(DecodeError::InvalidValue("SealedBox.ciphertext"));
        }
        Ok(SealedBox {
            ephemeral,
            ciphertext,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::encoding::put_u32;
    use rand::SeedableRng;

    use super::*;
    use crate::crypto::{SealSecret, open, seal};

    fn sealed(plaintext: &[u8]) -> (SealSecret, SealedBox) {
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(7);
        let sk = SealSecret::generate(&mut rng);
        let b = seal(&mut rng, &sk.public(), b"info", b"aad", plaintext).unwrap();
        (sk, b)
    }

    #[test]
    fn codec_round_trips_and_still_opens() {
        let (sk, b) = sealed(b"share bytes");
        let bytes = b.to_bytes();
        assert_eq!(bytes.len(), 32 + 4 + 11 + TAG_LEN);
        let back = SealedBox::decode_exact(&bytes).unwrap();
        assert_eq!(back, b);
        let pt = open(&sk, &back.ephemeral, b"info", b"aad", &back.ciphertext).unwrap();
        assert_eq!(pt.as_slice(), b"share bytes");
    }

    #[test]
    fn codec_min_encoded_len_is_an_empty_plaintext() {
        let (_, b) = sealed(b"");
        assert_eq!(b.to_bytes().len(), SealedBox::MIN_ENCODED_LEN);
        assert_eq!(SealedBox::decode_exact(&b.to_bytes()).unwrap(), b);
    }

    #[test]
    fn codec_accepts_the_largest_ciphertext() {
        let b = SealedBox {
            ephemeral: [3; 32],
            ciphertext: vec![5; MAX_SEALED_BOX_CIPHERTEXT],
        };
        assert_eq!(SealedBox::decode_exact(&b.to_bytes()).unwrap(), b);
    }

    #[test]
    fn codec_checks_the_length_bound_before_reading_the_ciphertext() {
        let mut bytes = vec![0u8; 32];
        put_u32(&mut bytes, u32::MAX);
        assert_eq!(
            SealedBox::decode_exact(&bytes),
            Err(DecodeError::LengthExceeded {
                len: u32::MAX as usize,
                max: MAX_SEALED_BOX_CIPHERTEXT
            })
        );
        let mut bytes = vec![0u8; 32];
        put_u32(&mut bytes, MAX_SEALED_BOX_CIPHERTEXT as u32 + 1);
        bytes.resize(bytes.len() + MAX_SEALED_BOX_CIPHERTEXT + 1, 0);
        assert!(matches!(
            SealedBox::decode_exact(&bytes),
            Err(DecodeError::LengthExceeded { .. })
        ));
    }

    #[test]
    fn codec_rejects_a_ciphertext_shorter_than_the_tag() {
        let b = SealedBox {
            ephemeral: [1; 32],
            ciphertext: vec![0; TAG_LEN - 1],
        };
        assert_eq!(
            SealedBox::decode_exact(&b.to_bytes()),
            Err(DecodeError::InvalidValue("SealedBox.ciphertext"))
        );
    }

    #[test]
    fn codec_rejects_trailing_and_missing_bytes() {
        let (_, b) = sealed(b"x");
        let mut bytes = b.to_bytes();
        bytes.push(0);
        assert_eq!(
            SealedBox::decode_exact(&bytes),
            Err(DecodeError::TrailingBytes(1))
        );
        bytes.truncate(bytes.len() - 2);
        assert!(matches!(
            SealedBox::decode_exact(&bytes),
            Err(DecodeError::UnexpectedEof { .. })
        ));
    }
}
