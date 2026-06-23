use crate::SecretBytes;
use crate::{CryptoError, CryptoResult};
use curve25519_dalek::montgomery::MontgomeryPoint;
use ed25519_dalek::{Signature, VerifyingKey};
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
    KeyPair {
        public: public_key_from_private(&private_bytes),
        private: private_bytes.into(),
    }
}

#[must_use]
pub fn public_key_from_private(private_key: &[u8; 32]) -> [u8; 32] {
    let private = StaticSecret::from(*private_key);
    PublicKey::from(&private).to_bytes()
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

/// Verify a libsignal Curve25519 signature (the `curve25519_sign` /
/// `Curve.calculateSignature` scheme used by WhatsApp/Baileys for signed
/// pre-keys, sender keys and noise certificates).
///
/// The signer derives an Ed25519 key pair from the Montgomery private key, signs
/// with Ed25519, then stores the Edwards public-key sign bit in the high bit of
/// signature byte 63. Verification (libsignal `curve25519_sign_open`) converts
/// the Montgomery public key to its Edwards form `y = (u-1)/(u+1)`, restores that
/// sign bit, clears it from the signature, and performs a standard Ed25519 verify.
#[must_use]
pub fn verify_curve25519_signature(
    montgomery_public_key: &[u8; 32],
    message: &[u8],
    signature: &[u8; 64],
) -> bool {
    // Restore the Edwards x-coordinate sign bit that the signer embedded in
    // signature[63]'s high bit, then strip it before Ed25519 verification.
    let sign_bit = signature[63] >> 7;
    let Some(edwards) = MontgomeryPoint(*montgomery_public_key).to_edwards(sign_bit) else {
        return false;
    };
    let Ok(verifying_key) = VerifyingKey::from_bytes(&edwards.compress().to_bytes()) else {
        return false;
    };
    let mut sig_bytes = *signature;
    sig_bytes[63] &= 0x7f;
    let candidate = Signature::from_bytes(&sig_bytes);
    verifying_key.verify_strict(message, &candidate).is_ok()
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
    fn derives_public_key_from_private_key() {
        let private = [7u8; 32];
        let expected = PublicKey::from(&StaticSecret::from(private)).to_bytes();
        assert_eq!(public_key_from_private(&private), expected);
    }

    fn hx(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    // libsignal's `curve25519_sign` (curve25519-js / Curve.calculateSignature, used by
    // WhatsApp/Baileys) embeds the Edwards public-key sign bit in signature byte 63's high
    // bit. Verify both a sign-bit-clear and a sign-bit-set real libsignal signature so a
    // regression in the sign-bit handling is caught. Vectors emitted by curve25519-js.
    #[test]
    fn verifies_libsignal_curve25519_signatures_with_either_sign_bit() {
        // sign bit clear (signature byte 63 high bit = 0)
        let pubk = hx("c3b9047dc029e97b25a53b834128d3a6dace3f63b99cd8ad01f3edff8813ec34");
        let msg = hx("68656c6c6f207369676e61747572652074657374");
        let sig = hx(
            "215a9fb24327c35c0110574691c7354898ad2acda1257fc9494f45a019ab44b22c739e805b2e5ea26bbc36d9b881fa692b61ce07f1cb5e19a34dc1c478d11f0c",
        );
        let pubk: [u8; 32] = pubk.try_into().unwrap();
        let sig: [u8; 64] = sig.try_into().unwrap();
        assert!(verify_curve25519_signature(&pubk, &msg, &sig));
        assert!(XEdDsaNoiseCertificateVerifier.verify_signature(&pubk, &msg, &sig));

        // sign bit SET (signature byte 63 high bit = 1) — the case strict-XEdDSA rejects.
        let fpub = hx("d607e6a250dac7355f0c1835863595f68a037c5b9ae48c2eee2315d19571c55b");
        let fmsg = hx("33083010001a10270718f263663120e14ef896e2c7f037");
        let fsig = hx(
            "767c99ef9dfaa4294986945353e02a6cb0733d633ca7989391a74546f27ae2d881c28d55c64400dc6402290cfa90c4ca7cb653491987ca3fa1b9846e23ebf08b",
        );
        let fpub: [u8; 32] = fpub.try_into().unwrap();
        let fsig: [u8; 64] = fsig.try_into().unwrap();
        assert_eq!(
            fsig[63] >> 7,
            1,
            "fixture sig must exercise the set sign bit"
        );
        assert!(verify_curve25519_signature(&fpub, &fmsg, &fsig));
        assert!(XEdDsaNoiseCertificateVerifier.verify_signature(&fpub, &fmsg, &fsig));

        // tampered message must NOT verify
        let mut bad = fmsg.clone();
        bad[0] ^= 0x01;
        assert!(!verify_curve25519_signature(&fpub, &bad, &fsig));
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
