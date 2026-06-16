use crate::SecretBytes;
use crate::{CryptoError, CryptoResult};
use x25519_dalek::{PublicKey, StaticSecret};
use xeddsa::Sign;

pub const SIGNAL_PUBLIC_KEY_VERSION: u8 = 5;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyPair {
    pub public: [u8; 32],
    pub private: SecretBytes,
}

#[must_use]
pub fn generate_key_pair() -> KeyPair {
    let private_bytes: [u8; 32] = rand::random();
    let private = StaticSecret::from(private_bytes);
    let public = PublicKey::from(&private);
    KeyPair {
        public: public.to_bytes(),
        private: private.to_bytes().into(),
    }
}

#[must_use]
pub fn shared_key(private_key: &[u8; 32], public_key: &[u8; 32]) -> [u8; 32] {
    let private = StaticSecret::from(*private_key);
    let public = PublicKey::from(*public_key);
    private.diffie_hellman(&public).to_bytes()
}

#[must_use]
pub fn prefixed_signal_public_key(public_key: &[u8; 32]) -> [u8; 33] {
    let mut out = [0u8; 33];
    out[0] = SIGNAL_PUBLIC_KEY_VERSION;
    out[1..].copy_from_slice(public_key);
    out
}

pub fn sign_x25519(private_key: &[u8], message: &[u8]) -> CryptoResult<[u8; 64]> {
    let private_key: &[u8; 32] = private_key
        .try_into()
        .map_err(|_| CryptoError::InvalidKeyLength)?;
    let private_key = xeddsa::xed25519::PrivateKey::from(private_key);
    Ok(private_key.sign(message, rand_xeddsa::rng()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{NoiseCertificateVerifier, XEdDsaNoiseCertificateVerifier};

    #[test]
    fn shared_key_is_symmetric() {
        let alice = generate_key_pair();
        let bob = generate_key_pair();

        let alice_private: [u8; 32] = alice.private.expose().try_into().unwrap();
        let bob_private: [u8; 32] = bob.private.expose().try_into().unwrap();

        let a = shared_key(&alice_private, &bob.public);
        let b = shared_key(&bob_private, &alice.public);

        assert_eq!(a, b);
    }

    #[test]
    fn prefixes_signal_public_key() {
        let public = [7u8; 32];
        let prefixed = prefixed_signal_public_key(&public);
        assert_eq!(prefixed[0], SIGNAL_PUBLIC_KEY_VERSION);
        assert_eq!(&prefixed[1..], &public);
    }

    #[test]
    fn signs_with_x25519_private_key() {
        let identity = generate_key_pair();
        let message = prefixed_signal_public_key(&generate_key_pair().public);
        let signature = sign_x25519(identity.private.expose(), &message).unwrap();

        assert!(XEdDsaNoiseCertificateVerifier.verify_signature(
            &identity.public,
            &message,
            &signature
        ));
    }
}
