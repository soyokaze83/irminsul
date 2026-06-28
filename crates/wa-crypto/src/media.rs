use crate::{
    CryptoError, CryptoResult, SecretBytes, aes_256_cbc_decrypt_with_iv,
    aes_256_cbc_encrypt_with_iv, aes_256_gcm_decrypt, aes_256_gcm_encrypt, hkdf_sha256,
    hmac_sha256, sha256_hash,
};
use aes::Aes256;
use aes::cipher::{Block, BlockDecrypt, BlockEncrypt, KeyInit};
use bytes::{Bytes, BytesMut};
use hmac::{Hmac, Mac};
use prost::Message as _;
use sha2::{Digest, Sha256};
use wa_proto::proto::media_retry_notification::ResultType as MediaRetryResultType;
use wa_proto::proto::{MediaRetryNotification, ServerErrorReceipt};

const MEDIA_KEY_LEN: usize = 32;
const MEDIA_MAC_LEN: usize = 10;
const MEDIA_RETRY_IV_LEN: usize = 12;
const MEDIA_RETRY_INFO: &[u8] = b"WhatsApp Media Retry Notification";
const AES_BLOCK_LEN: usize = 16;

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MediaKind {
    Audio,
    Document,
    Gif,
    Image,
    ProfilePicture,
    Product,
    PushToTalk,
    Sticker,
    Video,
    ThumbnailDocument,
    ThumbnailImage,
    ThumbnailVideo,
    ThumbnailLink,
    HistorySync,
    AppState,
    ProductCatalogImage,
    PaymentBackgroundImage,
    VideoNote,
    BusinessCoverPhoto,
}

impl MediaKind {
    #[must_use]
    pub fn hkdf_info_key(self) -> &'static str {
        match self {
            Self::Audio | Self::PushToTalk => "WhatsApp Audio Keys",
            Self::Document => "WhatsApp Document Keys",
            Self::Gif | Self::Video | Self::VideoNote => "WhatsApp Video Keys",
            Self::Image | Self::Product | Self::Sticker | Self::BusinessCoverPhoto => {
                "WhatsApp Image Keys"
            }
            Self::ProfilePicture | Self::ProductCatalogImage => "WhatsApp  Keys",
            Self::ThumbnailDocument => "WhatsApp Document Thumbnail Keys",
            Self::ThumbnailImage => "WhatsApp Image Thumbnail Keys",
            Self::ThumbnailVideo => "WhatsApp Video Thumbnail Keys",
            Self::ThumbnailLink => "WhatsApp Link Thumbnail Keys",
            Self::HistorySync => "WhatsApp History Keys",
            Self::AppState => "WhatsApp App State Keys",
            Self::PaymentBackgroundImage => "WhatsApp Payment Background Keys",
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct MediaKeyMaterial {
    iv: [u8; 16],
    cipher_key: SecretBytes,
    mac_key: SecretBytes,
}

impl MediaKeyMaterial {
    #[must_use]
    pub fn iv(&self) -> &[u8; 16] {
        &self.iv
    }

    #[must_use]
    pub fn cipher_key(&self) -> &[u8] {
        self.cipher_key.expose()
    }

    #[must_use]
    pub fn mac_key(&self) -> &[u8] {
        self.mac_key.expose()
    }
}

impl std::fmt::Debug for MediaKeyMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MediaKeyMaterial")
            .field("iv", &self.iv)
            .field("cipher_key", &"[redacted]")
            .field("mac_key", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncryptedMedia {
    pub media_key: SecretBytes,
    pub ciphertext_with_mac: Bytes,
    pub mac: Bytes,
    pub file_sha256: Bytes,
    pub file_enc_sha256: Bytes,
    pub file_length: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MediaEncryptionMetadata {
    pub media_key: SecretBytes,
    pub mac: Bytes,
    pub file_sha256: Bytes,
    pub file_enc_sha256: Bytes,
    pub file_length: u64,
}

impl EncryptedMedia {
    #[must_use]
    pub fn metadata(&self) -> MediaEncryptionMetadata {
        MediaEncryptionMetadata {
            media_key: self.media_key.clone(),
            mac: self.mac.clone(),
            file_sha256: self.file_sha256.clone(),
            file_enc_sha256: self.file_enc_sha256.clone(),
            file_length: self.file_length,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MediaStreamEncryptFinal {
    pub final_bytes: Bytes,
    pub metadata: MediaEncryptionMetadata,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MediaRetryPayload {
    pub ciphertext: Bytes,
    pub iv: Bytes,
}

pub struct MediaStreamEncryptor {
    media_key: SecretBytes,
    cipher: Aes256,
    previous_cipher_block: [u8; AES_BLOCK_LEN],
    pending_plaintext: BytesMut,
    plaintext_hasher: Sha256,
    encrypted_hasher: Sha256,
    mac: HmacSha256,
    file_length: u64,
    finalized: bool,
}

impl MediaStreamEncryptor {
    pub fn new(kind: MediaKind) -> CryptoResult<Self> {
        let media_key = generate_media_key();
        Self::with_key(kind, media_key.expose())
    }

    pub fn with_key(kind: MediaKind, media_key: &[u8]) -> CryptoResult<Self> {
        validate_media_key(media_key)?;
        let keys = derive_media_keys(media_key, kind)?;
        let cipher =
            Aes256::new_from_slice(keys.cipher_key()).map_err(|_| CryptoError::InvalidKeyLength)?;
        let mut mac = <HmacSha256 as Mac>::new_from_slice(keys.mac_key())
            .map_err(|_| CryptoError::InvalidKeyLength)?;
        mac.update(keys.iv());
        Ok(Self {
            media_key: SecretBytes::from(media_key.to_vec()),
            previous_cipher_block: *keys.iv(),
            cipher,
            pending_plaintext: BytesMut::new(),
            plaintext_hasher: Sha256::new(),
            encrypted_hasher: Sha256::new(),
            mac,
            file_length: 0,
            finalized: false,
        })
    }

    pub fn update(&mut self, plaintext: &[u8]) -> CryptoResult<Bytes> {
        self.ensure_not_finalized()?;
        self.file_length = self
            .file_length
            .checked_add(u64::try_from(plaintext.len()).map_err(|_| CryptoError::Encrypt)?)
            .ok_or(CryptoError::Encrypt)?;
        self.plaintext_hasher.update(plaintext);
        self.pending_plaintext.extend_from_slice(plaintext);

        let full_blocks = self.pending_plaintext.len() / AES_BLOCK_LEN;
        if full_blocks == 0 {
            return Ok(Bytes::new());
        }
        let process_len = full_blocks * AES_BLOCK_LEN;
        let plaintext = self.pending_plaintext.split_to(process_len).freeze();
        Ok(Bytes::from(self.encrypt_plaintext_blocks(&plaintext)))
    }

    pub fn finalize(mut self) -> CryptoResult<MediaStreamEncryptFinal> {
        self.ensure_not_finalized()?;
        self.finalized = true;

        let padding = AES_BLOCK_LEN - (self.pending_plaintext.len() % AES_BLOCK_LEN);
        let padding = if padding == 0 { AES_BLOCK_LEN } else { padding };
        let padding_byte = u8::try_from(padding).map_err(|_| CryptoError::Encrypt)?;
        self.pending_plaintext
            .extend(std::iter::repeat_n(padding_byte, padding));
        let pending = self.pending_plaintext.split().freeze();
        let mut final_bytes = self.encrypt_plaintext_blocks(&pending);

        let mac = self.mac.finalize().into_bytes();
        let mac = Bytes::copy_from_slice(&mac[..MEDIA_MAC_LEN]);
        self.encrypted_hasher.update(&mac);
        final_bytes.extend_from_slice(&mac);

        Ok(MediaStreamEncryptFinal {
            final_bytes: Bytes::from(final_bytes),
            metadata: MediaEncryptionMetadata {
                media_key: self.media_key,
                mac,
                file_sha256: Bytes::copy_from_slice(&self.plaintext_hasher.finalize()),
                file_enc_sha256: Bytes::copy_from_slice(&self.encrypted_hasher.finalize()),
                file_length: self.file_length,
            },
        })
    }

    fn encrypt_plaintext_blocks(&mut self, plaintext: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(plaintext.len());
        for block in plaintext.chunks_exact(AES_BLOCK_LEN) {
            let mut encrypted = [0u8; AES_BLOCK_LEN];
            for (out, (plain, previous)) in encrypted
                .iter_mut()
                .zip(block.iter().zip(self.previous_cipher_block.iter()))
            {
                *out = plain ^ previous;
            }
            let mut encrypted_block = Block::<Aes256>::clone_from_slice(&encrypted);
            self.cipher.encrypt_block(&mut encrypted_block);
            let encrypted: [u8; AES_BLOCK_LEN] = encrypted_block.into();
            self.previous_cipher_block = encrypted;
            self.mac.update(&encrypted);
            self.encrypted_hasher.update(encrypted);
            out.extend_from_slice(&encrypted);
        }
        out
    }

    fn ensure_not_finalized(&self) -> CryptoResult<()> {
        if self.finalized {
            return Err(CryptoError::InvalidInput("media stream already finalized"));
        }
        Ok(())
    }
}

pub struct MediaStreamDecryptor {
    cipher: Aes256,
    previous_cipher_block: [u8; AES_BLOCK_LEN],
    pending_ciphertext_with_mac: BytesMut,
    mac: HmacSha256,
    finalized: bool,
}

impl MediaStreamDecryptor {
    pub fn new(kind: MediaKind, media_key: &[u8]) -> CryptoResult<Self> {
        validate_media_key(media_key)?;
        let keys = derive_media_keys(media_key, kind)?;
        let cipher =
            Aes256::new_from_slice(keys.cipher_key()).map_err(|_| CryptoError::InvalidKeyLength)?;
        let mut mac = <HmacSha256 as Mac>::new_from_slice(keys.mac_key())
            .map_err(|_| CryptoError::InvalidKeyLength)?;
        mac.update(keys.iv());
        Ok(Self {
            previous_cipher_block: *keys.iv(),
            cipher,
            pending_ciphertext_with_mac: BytesMut::new(),
            mac,
            finalized: false,
        })
    }

    pub fn update(&mut self, ciphertext_with_mac: &[u8]) -> CryptoResult<Bytes> {
        self.ensure_not_finalized()?;
        self.pending_ciphertext_with_mac
            .extend_from_slice(ciphertext_with_mac);
        if self.pending_ciphertext_with_mac.len() <= MEDIA_MAC_LEN + AES_BLOCK_LEN {
            return Ok(Bytes::new());
        }

        let available_ciphertext = self.pending_ciphertext_with_mac.len() - MEDIA_MAC_LEN;
        let process_len = ((available_ciphertext - AES_BLOCK_LEN) / AES_BLOCK_LEN) * AES_BLOCK_LEN;
        if process_len == 0 {
            return Ok(Bytes::new());
        }
        let ciphertext = self
            .pending_ciphertext_with_mac
            .split_to(process_len)
            .freeze();
        Ok(Bytes::from(self.decrypt_ciphertext_blocks(&ciphertext)))
    }

    pub fn finalize(mut self) -> CryptoResult<Bytes> {
        self.ensure_not_finalized()?;
        self.finalized = true;
        if self.pending_ciphertext_with_mac.len() <= MEDIA_MAC_LEN {
            return Err(CryptoError::CiphertextTooShort);
        }

        let mac_offset = self.pending_ciphertext_with_mac.len() - MEDIA_MAC_LEN;
        if mac_offset == 0 || !mac_offset.is_multiple_of(AES_BLOCK_LEN) {
            return Err(CryptoError::Decrypt);
        }
        let expected_mac = self
            .pending_ciphertext_with_mac
            .split_off(mac_offset)
            .freeze();
        let remaining_ciphertext = self.pending_ciphertext_with_mac.split().freeze();
        self.mac.update(&remaining_ciphertext);
        let actual_mac = self.mac.clone().finalize().into_bytes();
        if !constant_time_eq(&actual_mac[..MEDIA_MAC_LEN], &expected_mac) {
            return Err(CryptoError::Decrypt);
        }

        let mut plaintext = self.decrypt_ciphertext_blocks_without_mac(&remaining_ciphertext);
        strip_pkcs7_padding(&mut plaintext)?;
        Ok(Bytes::from(plaintext))
    }

    fn decrypt_ciphertext_blocks(&mut self, ciphertext: &[u8]) -> Vec<u8> {
        self.mac.update(ciphertext);
        self.decrypt_ciphertext_blocks_without_mac(ciphertext)
    }

    fn decrypt_ciphertext_blocks_without_mac(&mut self, ciphertext: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(ciphertext.len());
        for block in ciphertext.chunks_exact(AES_BLOCK_LEN) {
            let mut cipher_block = [0u8; AES_BLOCK_LEN];
            cipher_block.copy_from_slice(block);
            let mut decrypted_block = Block::<Aes256>::clone_from_slice(block);
            self.cipher.decrypt_block(&mut decrypted_block);
            for (decrypted, previous) in decrypted_block
                .iter()
                .copied()
                .zip(self.previous_cipher_block.iter().copied())
            {
                out.push(decrypted ^ previous);
            }
            self.previous_cipher_block = cipher_block;
        }
        out
    }

    fn ensure_not_finalized(&self) -> CryptoResult<()> {
        if self.finalized {
            return Err(CryptoError::InvalidInput("media stream already finalized"));
        }
        Ok(())
    }
}

pub fn generate_media_key() -> SecretBytes {
    SecretBytes::from(rand::random::<[u8; MEDIA_KEY_LEN]>())
}

pub fn derive_media_keys(media_key: &[u8], kind: MediaKind) -> CryptoResult<MediaKeyMaterial> {
    validate_media_key(media_key)?;
    let expanded = hkdf_sha256(media_key, 112, &[], kind.hkdf_info_key().as_bytes())?;
    let iv = slice_to_array::<16>(&expanded[0..16], CryptoError::InvalidIvLength)?;
    let cipher_key = SecretBytes::from(expanded[16..48].to_vec());
    let mac_key = SecretBytes::from(expanded[48..80].to_vec());
    Ok(MediaKeyMaterial {
        iv,
        cipher_key,
        mac_key,
    })
}

pub fn encrypt_media_bytes(plaintext: &[u8], kind: MediaKind) -> CryptoResult<EncryptedMedia> {
    let media_key = generate_media_key();
    encrypt_media_bytes_with_key(plaintext, kind, media_key.expose())
}

pub fn encrypt_media_bytes_with_key(
    plaintext: &[u8],
    kind: MediaKind,
    media_key: &[u8],
) -> CryptoResult<EncryptedMedia> {
    validate_media_key(media_key)?;
    let keys = derive_media_keys(media_key, kind)?;
    let ciphertext = aes_256_cbc_encrypt_with_iv(plaintext, keys.cipher_key(), keys.iv())?;
    let mac = media_mac(&keys, &ciphertext)?;

    let mut ciphertext_with_mac = Vec::with_capacity(ciphertext.len() + MEDIA_MAC_LEN);
    ciphertext_with_mac.extend_from_slice(&ciphertext);
    ciphertext_with_mac.extend_from_slice(&mac);

    let file_length = u64::try_from(plaintext.len()).map_err(|_| CryptoError::Encrypt)?;
    Ok(EncryptedMedia {
        media_key: SecretBytes::from(media_key.to_vec()),
        ciphertext_with_mac: Bytes::from(ciphertext_with_mac.clone()),
        mac: Bytes::copy_from_slice(&mac),
        file_sha256: Bytes::copy_from_slice(&sha256_hash(plaintext)),
        file_enc_sha256: Bytes::copy_from_slice(&sha256_hash(&ciphertext_with_mac)),
        file_length,
    })
}

pub fn decrypt_media_bytes(
    ciphertext_with_mac: &[u8],
    kind: MediaKind,
    media_key: &[u8],
) -> CryptoResult<Vec<u8>> {
    validate_media_key(media_key)?;
    if ciphertext_with_mac.len() <= MEDIA_MAC_LEN {
        return Err(CryptoError::CiphertextTooShort);
    }
    let ciphertext_len = ciphertext_with_mac.len() - MEDIA_MAC_LEN;
    let (ciphertext, expected_mac) = ciphertext_with_mac.split_at(ciphertext_len);
    let keys = derive_media_keys(media_key, kind)?;
    let actual_mac = media_mac(&keys, ciphertext)?;
    if !constant_time_eq(&actual_mac, expected_mac) {
        return Err(CryptoError::Decrypt);
    }
    aes_256_cbc_decrypt_with_iv(ciphertext, keys.cipher_key(), keys.iv())
}

pub fn derive_media_retry_key(media_key: &[u8]) -> CryptoResult<SecretBytes> {
    validate_media_key(media_key)?;
    Ok(SecretBytes::from(hkdf_sha256(
        media_key,
        MEDIA_KEY_LEN,
        &[],
        MEDIA_RETRY_INFO,
    )?))
}

pub fn encrypt_media_retry_request(
    stanza_id: &str,
    media_key: &[u8],
) -> CryptoResult<MediaRetryPayload> {
    let iv = rand::random::<[u8; MEDIA_RETRY_IV_LEN]>();
    encrypt_media_retry_request_with_iv(stanza_id, media_key, &iv)
}

pub fn encrypt_media_retry_request_with_iv(
    stanza_id: &str,
    media_key: &[u8],
    iv: &[u8],
) -> CryptoResult<MediaRetryPayload> {
    validate_non_empty(stanza_id, "media retry stanza id")?;
    validate_retry_iv(iv)?;
    let retry_key = derive_media_retry_key(media_key)?;
    let receipt = ServerErrorReceipt {
        stanza_id: Some(stanza_id.to_owned()),
    }
    .encode_to_vec();
    let ciphertext = aes_256_gcm_encrypt(&receipt, retry_key.expose(), iv, stanza_id.as_bytes())?;
    Ok(MediaRetryPayload {
        ciphertext: Bytes::from(ciphertext),
        iv: Bytes::copy_from_slice(iv),
    })
}

pub fn encrypt_media_retry_notification_with_iv(
    notification: &MediaRetryNotification,
    media_key: &[u8],
    stanza_id: &str,
    iv: &[u8],
) -> CryptoResult<MediaRetryPayload> {
    validate_non_empty(stanza_id, "media retry stanza id")?;
    validate_retry_iv(iv)?;
    let retry_key = derive_media_retry_key(media_key)?;
    let ciphertext = aes_256_gcm_encrypt(
        &notification.encode_to_vec(),
        retry_key.expose(),
        iv,
        stanza_id.as_bytes(),
    )?;
    Ok(MediaRetryPayload {
        ciphertext: Bytes::from(ciphertext),
        iv: Bytes::copy_from_slice(iv),
    })
}

pub fn decrypt_media_retry_notification(
    payload: &MediaRetryPayload,
    media_key: &[u8],
    stanza_id: &str,
) -> CryptoResult<MediaRetryNotification> {
    validate_non_empty(stanza_id, "media retry stanza id")?;
    validate_retry_iv(&payload.iv)?;
    let retry_key = derive_media_retry_key(media_key)?;
    let plaintext = aes_256_gcm_decrypt(
        &payload.ciphertext,
        retry_key.expose(),
        &payload.iv,
        stanza_id.as_bytes(),
    )?;
    MediaRetryNotification::decode(plaintext.as_slice()).map_err(|_| CryptoError::Decrypt)
}

#[must_use]
pub fn media_retry_status_code(result: MediaRetryResultType) -> u16 {
    match result {
        MediaRetryResultType::Success => 200,
        MediaRetryResultType::DecryptionError => 412,
        MediaRetryResultType::NotFound => 404,
        MediaRetryResultType::GeneralError => 418,
    }
}

fn media_mac(keys: &MediaKeyMaterial, ciphertext: &[u8]) -> CryptoResult<[u8; MEDIA_MAC_LEN]> {
    let mut input = Vec::with_capacity(keys.iv().len() + ciphertext.len());
    input.extend_from_slice(keys.iv());
    input.extend_from_slice(ciphertext);
    let full_mac = hmac_sha256(&input, keys.mac_key())?;
    slice_to_array::<MEDIA_MAC_LEN>(&full_mac[..MEDIA_MAC_LEN], CryptoError::Encrypt)
}

fn validate_media_key(media_key: &[u8]) -> CryptoResult<()> {
    if media_key.len() != MEDIA_KEY_LEN {
        return Err(CryptoError::InvalidKeyLength);
    }
    Ok(())
}

fn validate_retry_iv(iv: &[u8]) -> CryptoResult<()> {
    if iv.len() != MEDIA_RETRY_IV_LEN {
        return Err(CryptoError::InvalidIvLength);
    }
    Ok(())
}

fn validate_non_empty(value: &str, label: &'static str) -> CryptoResult<()> {
    if value.is_empty() {
        return Err(CryptoError::InvalidInput(label));
    }
    Ok(())
}

fn slice_to_array<const N: usize>(input: &[u8], error: CryptoError) -> CryptoResult<[u8; N]> {
    input.try_into().map_err(|_| error)
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right.iter())
        .fold(0u8, |diff, (left, right)| diff | (left ^ right))
        == 0
}

fn strip_pkcs7_padding(input: &mut Vec<u8>) -> CryptoResult<()> {
    let Some(&padding) = input.last() else {
        return Err(CryptoError::Decrypt);
    };
    let padding = usize::from(padding);
    if padding == 0 || padding > AES_BLOCK_LEN || padding > input.len() {
        return Err(CryptoError::Decrypt);
    }
    if !input[input.len() - padding..]
        .iter()
        .all(|byte| usize::from(*byte) == padding)
    {
        return Err(CryptoError::Decrypt);
    }
    input.truncate(input.len() - padding);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn maps_media_kinds_to_hkdf_info_keys() {
        assert_eq!(MediaKind::Image.hkdf_info_key(), "WhatsApp Image Keys");
        assert_eq!(MediaKind::Gif.hkdf_info_key(), "WhatsApp Video Keys");
        assert_eq!(
            MediaKind::ThumbnailDocument.hkdf_info_key(),
            "WhatsApp Document Thumbnail Keys"
        );
        assert_eq!(
            MediaKind::ProductCatalogImage.hkdf_info_key(),
            "WhatsApp  Keys"
        );
    }

    #[test]
    fn derives_media_keys_with_expected_lengths() {
        let material = derive_media_keys(&[7u8; 32], MediaKind::Image).unwrap();
        assert_eq!(material.iv().len(), 16);
        assert_eq!(material.cipher_key().len(), 32);
        assert_eq!(material.mac_key().len(), 32);
    }

    #[test]
    fn encrypts_and_decrypts_media_bytes() {
        let media_key = [9u8; 32];
        let encrypted =
            encrypt_media_bytes_with_key(b"media plaintext", MediaKind::Image, &media_key).unwrap();

        assert_eq!(encrypted.file_length, 15);
        assert_eq!(encrypted.media_key.expose(), &media_key);
        assert_eq!(encrypted.mac.len(), 10);
        assert_eq!(encrypted.file_sha256.len(), 32);
        assert_eq!(encrypted.file_enc_sha256.len(), 32);
        assert_ne!(encrypted.ciphertext_with_mac.as_ref(), b"media plaintext");

        let decrypted = decrypt_media_bytes(
            &encrypted.ciphertext_with_mac,
            MediaKind::Image,
            encrypted.media_key.expose(),
        )
        .unwrap();
        assert_eq!(decrypted, b"media plaintext");
    }

    #[test]
    fn streaming_media_encryption_matches_byte_helper() {
        let media_key = [9u8; 32];
        let plaintext = (0..8197)
            .map(|idx| u8::try_from(idx % 251).unwrap())
            .collect::<Vec<_>>();
        let expected =
            encrypt_media_bytes_with_key(&plaintext, MediaKind::Video, &media_key).unwrap();

        let mut stream = MediaStreamEncryptor::with_key(MediaKind::Video, &media_key).unwrap();
        let mut ciphertext_with_mac = Vec::new();
        for chunk in plaintext.chunks(97) {
            ciphertext_with_mac.extend_from_slice(&stream.update(chunk).unwrap());
        }
        let final_chunk = stream.finalize().unwrap();
        ciphertext_with_mac.extend_from_slice(&final_chunk.final_bytes);

        assert_eq!(ciphertext_with_mac, expected.ciphertext_with_mac);
        assert_eq!(final_chunk.metadata, expected.metadata());
    }

    #[test]
    fn streaming_media_encryption_handles_empty_payload() {
        let media_key = [3u8; 32];
        let expected = encrypt_media_bytes_with_key(b"", MediaKind::Document, &media_key).unwrap();
        let stream = MediaStreamEncryptor::with_key(MediaKind::Document, &media_key).unwrap();
        let final_chunk = stream.finalize().unwrap();

        assert_eq!(final_chunk.final_bytes, expected.ciphertext_with_mac);
        assert_eq!(final_chunk.metadata, expected.metadata());
    }

    #[test]
    fn streaming_media_decryption_matches_byte_helper() {
        let media_key = [7u8; 32];
        let plaintext = (0..10_003)
            .map(|idx| u8::try_from((idx * 17) % 251).unwrap())
            .collect::<Vec<_>>();
        let encrypted =
            encrypt_media_bytes_with_key(&plaintext, MediaKind::Audio, &media_key).unwrap();

        let mut stream = MediaStreamDecryptor::new(MediaKind::Audio, &media_key).unwrap();
        let mut decrypted = Vec::new();
        for chunk in encrypted.ciphertext_with_mac.chunks(113) {
            decrypted.extend_from_slice(&stream.update(chunk).unwrap());
        }
        decrypted.extend_from_slice(&stream.finalize().unwrap());

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn streaming_media_decryption_rejects_bad_mac_at_finalize() {
        let media_key = [7u8; 32];
        let mut encrypted = encrypt_media_bytes_with_key(
            b"media plaintext that spans blocks",
            MediaKind::Image,
            &media_key,
        )
        .unwrap()
        .ciphertext_with_mac
        .to_vec();
        *encrypted.last_mut().unwrap() ^= 1;

        let mut stream = MediaStreamDecryptor::new(MediaKind::Image, &media_key).unwrap();
        for chunk in encrypted.chunks(9) {
            let _ = stream.update(chunk).unwrap();
        }
        assert!(matches!(stream.finalize(), Err(CryptoError::Decrypt)));
    }

    #[test]
    fn rejects_modified_media_mac() {
        let media_key = [9u8; 32];
        let mut encrypted =
            encrypt_media_bytes_with_key(b"media plaintext", MediaKind::Image, &media_key)
                .unwrap()
                .ciphertext_with_mac
                .to_vec();
        let last = encrypted.last_mut().unwrap();
        *last ^= 1;

        assert!(matches!(
            decrypt_media_bytes(&encrypted, MediaKind::Image, &media_key),
            Err(CryptoError::Decrypt)
        ));
    }

    proptest! {
        #[test]
        fn media_byte_encryption_round_trips_for_generated_payloads(
            plaintext in prop::collection::vec(any::<u8>(), 0..=4096),
            media_key in any::<[u8; MEDIA_KEY_LEN]>(),
            kind in media_kind_strategy(),
        ) {
            let encrypted =
                encrypt_media_bytes_with_key(&plaintext, kind, &media_key).unwrap();
            prop_assert_eq!(encrypted.file_length, plaintext.len() as u64);
            prop_assert_eq!(encrypted.media_key.expose(), &media_key);
            prop_assert_eq!(encrypted.mac.len(), MEDIA_MAC_LEN);
            prop_assert_eq!(encrypted.file_sha256, Bytes::copy_from_slice(&sha256_hash(&plaintext)));
            prop_assert_eq!(
                encrypted.file_enc_sha256,
                Bytes::copy_from_slice(&sha256_hash(&encrypted.ciphertext_with_mac))
            );

            let decrypted =
                decrypt_media_bytes(&encrypted.ciphertext_with_mac, kind, &media_key).unwrap();
            prop_assert_eq!(decrypted, plaintext);
        }

        #[test]
        fn media_stream_encryption_matches_byte_helper_for_generated_chunks(
            plaintext in prop::collection::vec(any::<u8>(), 0..=4096),
            media_key in any::<[u8; MEDIA_KEY_LEN]>(),
            kind in media_kind_strategy(),
            chunk_size in 1usize..=257,
        ) {
            let expected =
                encrypt_media_bytes_with_key(&plaintext, kind, &media_key).unwrap();
            let mut stream = MediaStreamEncryptor::with_key(kind, &media_key).unwrap();
            let mut ciphertext_with_mac = Vec::new();
            for chunk in plaintext.chunks(chunk_size) {
                ciphertext_with_mac.extend_from_slice(&stream.update(chunk).unwrap());
            }
            let final_chunk = stream.finalize().unwrap();
            ciphertext_with_mac.extend_from_slice(&final_chunk.final_bytes);

            prop_assert_eq!(&ciphertext_with_mac, &expected.ciphertext_with_mac);
            prop_assert_eq!(&final_chunk.metadata, &expected.metadata());
        }

        #[test]
        fn media_stream_decryption_matches_byte_helper_for_generated_chunks(
            plaintext in prop::collection::vec(any::<u8>(), 0..=4096),
            media_key in any::<[u8; MEDIA_KEY_LEN]>(),
            kind in media_kind_strategy(),
            chunk_size in 1usize..=257,
        ) {
            let encrypted =
                encrypt_media_bytes_with_key(&plaintext, kind, &media_key).unwrap();
            let expected =
                decrypt_media_bytes(&encrypted.ciphertext_with_mac, kind, &media_key).unwrap();
            let mut stream = MediaStreamDecryptor::new(kind, &media_key).unwrap();
            let mut decrypted = Vec::new();
            for chunk in encrypted.ciphertext_with_mac.chunks(chunk_size) {
                decrypted.extend_from_slice(&stream.update(chunk).unwrap());
            }
            decrypted.extend_from_slice(&stream.finalize().unwrap());

            prop_assert_eq!(&decrypted, &expected);
            prop_assert_eq!(&decrypted, &plaintext);
        }

        #[test]
        fn media_decryption_rejects_generated_tampering(
            plaintext in prop::collection::vec(any::<u8>(), 0..=4096),
            media_key in any::<[u8; MEDIA_KEY_LEN]>(),
            kind in media_kind_strategy(),
            tamper_index in any::<usize>(),
        ) {
            let encrypted =
                encrypt_media_bytes_with_key(&plaintext, kind, &media_key).unwrap();
            let mut tampered = encrypted.ciphertext_with_mac.to_vec();
            prop_assume!(!tampered.is_empty());
            let index = tamper_index % tampered.len();
            tampered[index] ^= 1;

            prop_assert!(matches!(
                decrypt_media_bytes(&tampered, kind, &media_key),
                Err(CryptoError::Decrypt)
            ));
        }

        #[test]
        fn media_retry_request_payload_decrypts_for_generated_inputs(
            stanza_id in stanza_id_strategy(),
            media_key in any::<[u8; MEDIA_KEY_LEN]>(),
            iv in any::<[u8; MEDIA_RETRY_IV_LEN]>(),
        ) {
            let payload =
                encrypt_media_retry_request_with_iv(&stanza_id, &media_key, &iv).unwrap();
            prop_assert_eq!(payload.iv.as_ref(), &iv);

            let retry_key = derive_media_retry_key(&media_key).unwrap();
            let plaintext = aes_256_gcm_decrypt(
                &payload.ciphertext,
                retry_key.expose(),
                &payload.iv,
                stanza_id.as_bytes(),
            )
            .unwrap();
            let receipt = ServerErrorReceipt::decode(plaintext.as_slice()).unwrap();
            prop_assert_eq!(receipt.stanza_id.as_deref(), Some(stanza_id.as_str()));

            prop_assert!(matches!(
                aes_256_gcm_decrypt(
                    &payload.ciphertext,
                    retry_key.expose(),
                    &payload.iv,
                    b"wrong-stanza-id",
                ),
                Err(CryptoError::Decrypt)
            ));
        }

        #[test]
        fn media_retry_notification_payload_round_trips_for_generated_inputs(
            stanza_id in stanza_id_strategy(),
            media_key in any::<[u8; MEDIA_KEY_LEN]>(),
            iv in any::<[u8; MEDIA_RETRY_IV_LEN]>(),
            direct_path in prop::option::of(direct_path_strategy()),
            result in prop::option::of(media_retry_result_strategy()),
            message_secret in prop::option::of(prop::collection::vec(any::<u8>(), 0..=64)),
        ) {
            let notification = MediaRetryNotification {
                stanza_id: Some(stanza_id.clone()),
                direct_path,
                result: result.map(|value| value as i32),
                message_secret: message_secret.map(Bytes::from),
            };
            let payload = encrypt_media_retry_notification_with_iv(
                &notification,
                &media_key,
                &stanza_id,
                &iv,
            )
            .unwrap();

            let decoded =
                decrypt_media_retry_notification(&payload, &media_key, &stanza_id).unwrap();
            prop_assert_eq!(decoded, notification);

            prop_assert!(matches!(
                decrypt_media_retry_notification(&payload, &media_key, "wrong-stanza-id"),
                Err(CryptoError::Decrypt)
            ));
        }

        #[test]
        fn media_retry_notification_rejects_generated_tampering(
            stanza_id in stanza_id_strategy(),
            media_key in any::<[u8; MEDIA_KEY_LEN]>(),
            iv in any::<[u8; MEDIA_RETRY_IV_LEN]>(),
            tamper_index in any::<usize>(),
        ) {
            let notification = MediaRetryNotification {
                stanza_id: Some(stanza_id.clone()),
                direct_path: Some("/media/retry/path".to_owned()),
                result: Some(MediaRetryResultType::Success as i32),
                message_secret: Some(Bytes::from_static(b"retry-secret")),
            };
            let payload = encrypt_media_retry_notification_with_iv(
                &notification,
                &media_key,
                &stanza_id,
                &iv,
            )
            .unwrap();
            let mut tampered = payload.ciphertext.to_vec();
            prop_assume!(!tampered.is_empty());
            let index = tamper_index % tampered.len();
            tampered[index] ^= 1;
            let tampered_payload = MediaRetryPayload {
                ciphertext: Bytes::from(tampered),
                iv: payload.iv,
            };

            prop_assert!(matches!(
                decrypt_media_retry_notification(&tampered_payload, &media_key, &stanza_id),
                Err(CryptoError::Decrypt)
            ));
        }
    }

    #[test]
    fn rejects_invalid_media_inputs() {
        assert!(matches!(
            derive_media_keys(&[1u8; 31], MediaKind::Image),
            Err(CryptoError::InvalidKeyLength)
        ));
        assert!(matches!(
            decrypt_media_bytes(&[1u8; MEDIA_MAC_LEN], MediaKind::Image, &[1u8; 32]),
            Err(CryptoError::CiphertextTooShort)
        ));
    }

    #[test]
    fn encrypts_media_retry_request_payload() {
        let media_key = [8u8; 32];
        let iv = [4u8; 12];
        let payload = encrypt_media_retry_request_with_iv("msg-1", &media_key, &iv).unwrap();
        assert_eq!(payload.iv.as_ref(), &iv);

        let retry_key = derive_media_retry_key(&media_key).unwrap();
        let plaintext = aes_256_gcm_decrypt(
            &payload.ciphertext,
            retry_key.expose(),
            &payload.iv,
            b"msg-1",
        )
        .unwrap();
        let receipt = ServerErrorReceipt::decode(plaintext.as_slice()).unwrap();
        assert_eq!(receipt.stanza_id.as_deref(), Some("msg-1"));
    }

    #[test]
    fn decrypts_media_retry_notification_payload() {
        let media_key = [8u8; 32];
        let iv = [4u8; 12];
        let notification = MediaRetryNotification {
            stanza_id: Some("msg-1".to_owned()),
            direct_path: Some("/new/path".to_owned()),
            result: Some(MediaRetryResultType::Success as i32),
            message_secret: Some(Bytes::from_static(b"secret")),
        };
        let payload =
            encrypt_media_retry_notification_with_iv(&notification, &media_key, "msg-1", &iv)
                .unwrap();

        let decoded = decrypt_media_retry_notification(&payload, &media_key, "msg-1").unwrap();
        assert_eq!(decoded.direct_path.as_deref(), Some("/new/path"));
        assert_eq!(decoded.result, Some(MediaRetryResultType::Success as i32));

        assert!(matches!(
            decrypt_media_retry_notification(&payload, &media_key, "wrong-id",),
            Err(CryptoError::Decrypt)
        ));
    }

    #[test]
    fn maps_media_retry_status_codes() {
        assert_eq!(media_retry_status_code(MediaRetryResultType::Success), 200);
        assert_eq!(media_retry_status_code(MediaRetryResultType::NotFound), 404);
        assert_eq!(
            media_retry_status_code(MediaRetryResultType::DecryptionError),
            412
        );
        assert_eq!(
            media_retry_status_code(MediaRetryResultType::GeneralError),
            418
        );
    }

    fn media_kind_strategy() -> impl Strategy<Value = MediaKind> {
        prop::sample::select(vec![
            MediaKind::Audio,
            MediaKind::Document,
            MediaKind::Gif,
            MediaKind::Image,
            MediaKind::ProfilePicture,
            MediaKind::Product,
            MediaKind::PushToTalk,
            MediaKind::Sticker,
            MediaKind::Video,
            MediaKind::ThumbnailDocument,
            MediaKind::ThumbnailImage,
            MediaKind::ThumbnailVideo,
            MediaKind::ThumbnailLink,
            MediaKind::HistorySync,
            MediaKind::AppState,
            MediaKind::ProductCatalogImage,
            MediaKind::PaymentBackgroundImage,
            MediaKind::VideoNote,
            MediaKind::BusinessCoverPhoto,
        ])
    }

    fn media_retry_result_strategy() -> impl Strategy<Value = MediaRetryResultType> {
        prop::sample::select(vec![
            MediaRetryResultType::Success,
            MediaRetryResultType::DecryptionError,
            MediaRetryResultType::NotFound,
            MediaRetryResultType::GeneralError,
        ])
    }

    fn stanza_id_strategy() -> impl Strategy<Value = String> {
        ascii_string(
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-",
            1..=32,
        )
    }

    fn direct_path_strategy() -> impl Strategy<Value = String> {
        ascii_string(
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-/.",
            1..=64,
        )
        .prop_map(|path| format!("/{path}"))
    }

    fn ascii_string(
        alphabet: &'static str,
        len: std::ops::RangeInclusive<usize>,
    ) -> impl Strategy<Value = String> {
        let chars = alphabet.chars().collect::<Vec<_>>();
        prop::collection::vec(prop::sample::select(chars), len)
            .prop_map(|chars| chars.into_iter().collect())
    }
}
