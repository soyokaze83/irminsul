use crate::{
    CryptoError, CryptoResult, SecretBytes, aes_256_cbc_decrypt_with_iv,
    aes_256_cbc_encrypt_with_iv, aes_256_gcm_decrypt, aes_256_gcm_encrypt, hkdf_sha256,
    hmac_sha256, sha256_hash,
};
use bytes::Bytes;
use prost::Message as _;
use wa_proto::proto::media_retry_notification::ResultType as MediaRetryResultType;
use wa_proto::proto::{MediaRetryNotification, ServerErrorReceipt};

const MEDIA_KEY_LEN: usize = 32;
const MEDIA_MAC_LEN: usize = 10;
const MEDIA_RETRY_IV_LEN: usize = 12;
const MEDIA_RETRY_INFO: &[u8] = b"WhatsApp Media Retry Notification";

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
pub struct MediaRetryPayload {
    pub ciphertext: Bytes,
    pub iv: Bytes,
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
