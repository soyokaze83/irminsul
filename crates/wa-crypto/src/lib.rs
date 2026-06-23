#![forbid(unsafe_code)]

pub mod app_state;
pub mod keys;
pub mod media;
pub mod noise;
pub mod primitives;
pub mod secret;

pub use app_state::{
    APP_STATE_LT_HASH_LEN, AppStateKeyMaterial, AppStateMutationOperation, app_state_index_mac,
    app_state_lt_hash_subtract_then_add, app_state_patch_mac, app_state_snapshot_mac,
    app_state_value_mac, decrypt_app_state_value, derive_app_state_keys,
    encrypt_app_state_value_with_iv,
};
pub use keys::{
    KeyPair, SIGNAL_PUBLIC_KEY_VERSION, generate_key_pair, prefixed_signal_public_key,
    public_key_from_private, shared_key, sign_x25519, verify_curve25519_signature,
};
pub use media::{
    EncryptedMedia, MediaEncryptionMetadata, MediaKeyMaterial, MediaKind, MediaRetryPayload,
    MediaStreamDecryptor, MediaStreamEncryptFinal, MediaStreamEncryptor, decrypt_media_bytes,
    decrypt_media_retry_notification, derive_media_keys, derive_media_retry_key,
    encrypt_media_bytes, encrypt_media_bytes_with_key, encrypt_media_retry_notification_with_iv,
    encrypt_media_retry_request, encrypt_media_retry_request_with_iv, generate_media_key,
    media_retry_status_code,
};
pub use noise::{
    DEFAULT_MAX_FRAME_LEN, DEFAULT_NOISE_HEADER, NoiseCertificateVerifier, NoiseFrameCodec,
    NoiseFrameError, NoiseHandshake, NoiseHandshakeError, NoiseTransport, ROOT_CERT_PUBLIC_KEY,
    ROOT_CERT_SERIAL, XEdDsaNoiseCertificateVerifier, validate_noise_certificate_chain,
};
pub use primitives::{
    CryptoError, CryptoResult, aes_256_cbc_decrypt, aes_256_cbc_decrypt_with_iv,
    aes_256_cbc_encrypt, aes_256_cbc_encrypt_with_iv, aes_256_ctr_apply, aes_256_gcm_decrypt,
    aes_256_gcm_encrypt, derive_pairing_code_key, hkdf_sha256, hmac_sha256, hmac_sha512, md5_hash,
    sha256_hash, verify_hmac_sha256,
};
pub use secret::SecretBytes;
