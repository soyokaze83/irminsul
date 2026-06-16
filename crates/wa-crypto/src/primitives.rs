use aes::Aes256;
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use cbc::cipher::block_padding::Pkcs7;
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use ctr::cipher::StreamCipher;
use hmac::{Hmac, Mac};
use md5::{Digest, Md5};
use pbkdf2::pbkdf2_hmac;
use sha2::{Sha256, Sha512};

type Aes256Ctr = ctr::Ctr128BE<Aes256>;
type Aes256CbcEncryptor = cbc::Encryptor<Aes256>;
type Aes256CbcDecryptor = cbc::Decryptor<Aes256>;

pub type CryptoResult<T> = Result<T, CryptoError>;

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum CryptoError {
    #[error("invalid key length")]
    InvalidKeyLength,
    #[error("invalid iv length")]
    InvalidIvLength,
    #[error("invalid input: {0}")]
    InvalidInput(&'static str),
    #[error("ciphertext is too short")]
    CiphertextTooShort,
    #[error("encryption failed")]
    Encrypt,
    #[error("decryption failed")]
    Decrypt,
    #[error("key derivation failed")]
    Kdf,
}

pub fn aes_256_gcm_encrypt(
    plaintext: &[u8],
    key: &[u8],
    iv: &[u8],
    additional_data: &[u8],
) -> CryptoResult<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::InvalidKeyLength)?;
    let nonce = Nonce::from_slice(validate_len::<12>(iv, CryptoError::InvalidIvLength)?);
    cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad: additional_data,
            },
        )
        .map_err(|_| CryptoError::Encrypt)
}

pub fn aes_256_gcm_decrypt(
    ciphertext_and_tag: &[u8],
    key: &[u8],
    iv: &[u8],
    additional_data: &[u8],
) -> CryptoResult<Vec<u8>> {
    if ciphertext_and_tag.len() < 16 {
        return Err(CryptoError::CiphertextTooShort);
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::InvalidKeyLength)?;
    let nonce = Nonce::from_slice(validate_len::<12>(iv, CryptoError::InvalidIvLength)?);
    cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext_and_tag,
                aad: additional_data,
            },
        )
        .map_err(|_| CryptoError::Decrypt)
}

pub fn aes_256_ctr_apply(input: &[u8], key: &[u8], iv: &[u8]) -> CryptoResult<Vec<u8>> {
    let key = validate_len::<32>(key, CryptoError::InvalidKeyLength)?;
    let iv = validate_len::<16>(iv, CryptoError::InvalidIvLength)?;
    let mut cipher = Aes256Ctr::new(key.into(), iv.into());
    let mut out = input.to_vec();
    cipher.apply_keystream(&mut out);
    Ok(out)
}

pub fn aes_256_cbc_encrypt(plaintext: &[u8], key: &[u8], iv: &[u8]) -> CryptoResult<Vec<u8>> {
    let encrypted = aes_256_cbc_encrypt_with_iv(plaintext, key, iv)?;
    let mut out = Vec::with_capacity(iv.len() + encrypted.len());
    out.extend_from_slice(iv);
    out.extend_from_slice(&encrypted);
    Ok(out)
}

pub fn aes_256_cbc_encrypt_with_iv(
    plaintext: &[u8],
    key: &[u8],
    iv: &[u8],
) -> CryptoResult<Vec<u8>> {
    let key = validate_len::<32>(key, CryptoError::InvalidKeyLength)?;
    let iv = validate_len::<16>(iv, CryptoError::InvalidIvLength)?;
    Ok(Aes256CbcEncryptor::new(key.into(), iv.into()).encrypt_padded_vec_mut::<Pkcs7>(plaintext))
}

pub fn aes_256_cbc_decrypt(ciphertext_with_iv: &[u8], key: &[u8]) -> CryptoResult<Vec<u8>> {
    if ciphertext_with_iv.len() < 16 {
        return Err(CryptoError::CiphertextTooShort);
    }
    let (iv, ciphertext) = ciphertext_with_iv.split_at(16);
    aes_256_cbc_decrypt_with_iv(ciphertext, key, iv)
}

pub fn aes_256_cbc_decrypt_with_iv(
    ciphertext: &[u8],
    key: &[u8],
    iv: &[u8],
) -> CryptoResult<Vec<u8>> {
    let key = validate_len::<32>(key, CryptoError::InvalidKeyLength)?;
    let iv = validate_len::<16>(iv, CryptoError::InvalidIvLength)?;
    Aes256CbcDecryptor::new(key.into(), iv.into())
        .decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
        .map_err(|_| CryptoError::Decrypt)
}

#[must_use]
pub fn sha256_hash(input: &[u8]) -> [u8; 32] {
    Sha256::digest(input).into()
}

#[must_use]
pub fn md5_hash(input: &[u8]) -> [u8; 16] {
    Md5::digest(input).into()
}

pub fn hmac_sha256(input: &[u8], key: &[u8]) -> CryptoResult<[u8; 32]> {
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(key).map_err(|_| CryptoError::InvalidKeyLength)?;
    mac.update(input);
    Ok(mac.finalize().into_bytes().into())
}

pub fn verify_hmac_sha256(input: &[u8], key: &[u8], expected: &[u8]) -> CryptoResult<bool> {
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(key).map_err(|_| CryptoError::InvalidKeyLength)?;
    mac.update(input);
    Ok(mac.verify_slice(expected).is_ok())
}

pub fn hmac_sha512(input: &[u8], key: &[u8]) -> CryptoResult<[u8; 64]> {
    let mut mac =
        <Hmac<Sha512> as Mac>::new_from_slice(key).map_err(|_| CryptoError::InvalidKeyLength)?;
    mac.update(input);
    Ok(mac.finalize().into_bytes().into())
}

pub fn hkdf_sha256(
    input_key_material: &[u8],
    len: usize,
    salt: &[u8],
    info: &[u8],
) -> CryptoResult<Vec<u8>> {
    let hk = hkdf::Hkdf::<Sha256>::new(Some(salt), input_key_material);
    let mut out = vec![0u8; len];
    hk.expand(info, &mut out).map_err(|_| CryptoError::Kdf)?;
    Ok(out)
}

#[must_use]
pub fn derive_pairing_code_key(pairing_code: &str, salt: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    pbkdf2_hmac::<Sha256>(pairing_code.as_bytes(), salt, 2 << 16, &mut out);
    out
}

fn validate_len<const N: usize>(input: &[u8], error: CryptoError) -> CryptoResult<&[u8; N]> {
    input.try_into().map_err(|_| error)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_known_values() {
        assert_eq!(
            hex(&sha256_hash(b"hello")),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
        assert_eq!(hex(&md5_hash(b"hello")), "5d41402abc4b2a76b9719d911017c592");
    }

    #[test]
    fn hmac_sha256_known_value() {
        let mac = hmac_sha256(b"The quick brown fox jumps over the lazy dog", b"key").unwrap();
        assert_eq!(
            hex(&mac),
            "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
        );
        assert!(
            verify_hmac_sha256(b"The quick brown fox jumps over the lazy dog", b"key", &mac)
                .unwrap()
        );
        assert!(
            !verify_hmac_sha256(b"The quick brown fox jumps over the lazy dog", b"bad", &mac)
                .unwrap()
        );
    }

    #[test]
    fn hkdf_rfc5869_case_1() {
        let ikm = [0x0b; 22];
        let salt = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ];
        let info = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
        let okm = hkdf_sha256(&ikm, 42, &salt, &info).unwrap();
        assert_eq!(
            hex(&okm),
            "3cb25f25faacd57a90434f64d0362f2a\
             2d2d0a90cf1a5a4c5db02d56ecc4c5bf\
             34007208d5b887185865"
                .replace(' ', "")
        );
    }

    #[test]
    fn aes_gcm_round_trips_with_aad() {
        let key = [7u8; 32];
        let iv = [3u8; 12];
        let aad = b"context";
        let ciphertext = aes_256_gcm_encrypt(b"plaintext", &key, &iv, aad).unwrap();
        assert_ne!(ciphertext, b"plaintext");
        let plaintext = aes_256_gcm_decrypt(&ciphertext, &key, &iv, aad).unwrap();
        assert_eq!(plaintext, b"plaintext");
    }

    #[test]
    fn aes_ctr_round_trips() {
        let key = [1u8; 32];
        let iv = [2u8; 16];
        let ciphertext = aes_256_ctr_apply(b"plaintext", &key, &iv).unwrap();
        let plaintext = aes_256_ctr_apply(&ciphertext, &key, &iv).unwrap();
        assert_eq!(plaintext, b"plaintext");
    }

    #[test]
    fn aes_cbc_round_trips() {
        let key = [1u8; 32];
        let iv = [2u8; 16];
        let ciphertext = aes_256_cbc_encrypt(b"plaintext", &key, &iv).unwrap();
        let plaintext = aes_256_cbc_decrypt(&ciphertext, &key).unwrap();
        assert_eq!(plaintext, b"plaintext");
    }

    fn hex(input: &[u8]) -> String {
        input.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}
