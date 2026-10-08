//! [`FileSigner`]: a Solana keypair held in memory.

use std::fmt;

use solana_keypair::Keypair;
use solana_signer::Signer;
use zeroize::Zeroizing;

use crate::{Address, SignerError, TxSigner};

/// A Solana keypair loaded from a key file:
/// `FileSigner::from_bytes(timescales_service::keys::solana_keypair_bytes(path)?)`.
pub struct FileSigner {
    keypair: Keypair,
    address: Address,
}

impl FileSigner {
    /// `secret || public` as in a Solana JSON key file. The public half must
    /// be the key the secret half derives.
    pub fn from_bytes(bytes: Zeroizing<[u8; 64]>) -> Result<Self, SignerError> {
        let keypair = Keypair::try_from(&bytes[..]).map_err(|_| SignerError::InvalidKeypair)?;
        let address = keypair.pubkey().to_bytes();
        Ok(Self { keypair, address })
    }
}

impl TxSigner for FileSigner {
    fn address(&self) -> Address {
        self.address
    }

    fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.keypair.sign_message(message).into()
    }
}

impl fmt::Debug for FileSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FileSigner")
            .field("address", &bs58::encode(self.address).into_string())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keypair_bytes(seed: u8) -> Zeroizing<[u8; 64]> {
        Zeroizing::new(Keypair::new_from_array([seed; 32]).to_bytes())
    }

    #[test]
    fn signs_as_the_keypair() {
        let signer = FileSigner::from_bytes(keypair_bytes(3)).unwrap();
        let expected = Keypair::new_from_array([3; 32]);
        assert_eq!(signer.address(), expected.pubkey().to_bytes());
        let sig = signer.sign(b"message");
        assert_eq!(sig, <[u8; 64]>::from(expected.sign_message(b"message")));
    }

    #[test]
    fn refuses_a_public_half_that_does_not_match() {
        let mut bytes = keypair_bytes(3);
        bytes[63] ^= 1;
        assert!(matches!(
            FileSigner::from_bytes(bytes),
            Err(SignerError::InvalidKeypair)
        ));
    }

    #[test]
    fn debug_shows_only_the_address() {
        let signer = FileSigner::from_bytes(keypair_bytes(3)).unwrap();
        let shown = format!("{signer:?}");
        let address = bs58::encode(signer.address()).into_string();
        assert!(shown.contains(&address), "{shown}");
        let secret = bs58::encode([3u8; 32]).into_string();
        assert!(!shown.contains(&secret), "{shown}");
    }
}
