use crate::{
    CryptoError, CryptoResult, SecretBytes, aes_256_cbc_decrypt, aes_256_cbc_encrypt, hkdf_sha256,
    hmac_sha256, hmac_sha512,
};
use bytes::Bytes;

const APP_STATE_KEY_LEN: usize = 32;
const APP_STATE_EXPANDED_KEY_LEN: usize = 160;
pub const APP_STATE_LT_HASH_LEN: usize = 128;
const APP_STATE_MAC_LEN: usize = 32;
const APP_STATE_INFO: &[u8] = b"WhatsApp App State Keys";
const APP_STATE_LT_HASH_INFO: &[u8] = b"WhatsApp Patch Integrity";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AppStateMutationOperation {
    Set,
    Remove,
}

impl AppStateMutationOperation {
    #[must_use]
    pub fn mac_byte(self) -> u8 {
        match self {
            Self::Set => 0x01,
            Self::Remove => 0x02,
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct AppStateKeyMaterial {
    index_key: SecretBytes,
    value_encryption_key: SecretBytes,
    value_mac_key: SecretBytes,
    snapshot_mac_key: SecretBytes,
    patch_mac_key: SecretBytes,
}

impl AppStateKeyMaterial {
    #[must_use]
    pub fn index_key(&self) -> &[u8] {
        self.index_key.expose()
    }

    #[must_use]
    pub fn value_encryption_key(&self) -> &[u8] {
        self.value_encryption_key.expose()
    }

    #[must_use]
    pub fn value_mac_key(&self) -> &[u8] {
        self.value_mac_key.expose()
    }

    #[must_use]
    pub fn snapshot_mac_key(&self) -> &[u8] {
        self.snapshot_mac_key.expose()
    }

    #[must_use]
    pub fn patch_mac_key(&self) -> &[u8] {
        self.patch_mac_key.expose()
    }
}

impl std::fmt::Debug for AppStateKeyMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppStateKeyMaterial")
            .field("index_key", &"[redacted]")
            .field("value_encryption_key", &"[redacted]")
            .field("value_mac_key", &"[redacted]")
            .field("snapshot_mac_key", &"[redacted]")
            .field("patch_mac_key", &"[redacted]")
            .finish()
    }
}

pub fn derive_app_state_keys(key_data: &[u8]) -> CryptoResult<AppStateKeyMaterial> {
    if key_data.len() != APP_STATE_KEY_LEN {
        return Err(CryptoError::InvalidKeyLength);
    }
    let expanded = hkdf_sha256(key_data, APP_STATE_EXPANDED_KEY_LEN, &[], APP_STATE_INFO)?;
    Ok(AppStateKeyMaterial {
        index_key: SecretBytes::from(expanded[0..32].to_vec()),
        value_encryption_key: SecretBytes::from(expanded[32..64].to_vec()),
        value_mac_key: SecretBytes::from(expanded[64..96].to_vec()),
        snapshot_mac_key: SecretBytes::from(expanded[96..128].to_vec()),
        patch_mac_key: SecretBytes::from(expanded[128..160].to_vec()),
    })
}

pub fn encrypt_app_state_value_with_iv(
    plaintext: &[u8],
    keys: &AppStateKeyMaterial,
    iv: &[u8],
) -> CryptoResult<Bytes> {
    Ok(Bytes::from(aes_256_cbc_encrypt(
        plaintext,
        keys.value_encryption_key(),
        iv,
    )?))
}

pub fn decrypt_app_state_value(
    ciphertext_with_iv: &[u8],
    keys: &AppStateKeyMaterial,
) -> CryptoResult<Vec<u8>> {
    aes_256_cbc_decrypt(ciphertext_with_iv, keys.value_encryption_key())
}

pub fn app_state_index_mac(index: &[u8], keys: &AppStateKeyMaterial) -> CryptoResult<[u8; 32]> {
    hmac_sha256(index, keys.index_key())
}

pub fn app_state_value_mac(
    operation: AppStateMutationOperation,
    encrypted_value: &[u8],
    key_id: &[u8],
    keys: &AppStateKeyMaterial,
) -> CryptoResult<[u8; 32]> {
    app_state_mutation_mac(operation, encrypted_value, key_id, keys.value_mac_key())
}

pub fn app_state_snapshot_mac(
    lthash: &[u8],
    version: u64,
    collection_name: &str,
    keys: &AppStateKeyMaterial,
) -> CryptoResult<[u8; 32]> {
    validate_collection_name(collection_name)?;
    let mut total = Vec::with_capacity(lthash.len() + 8 + collection_name.len());
    total.extend_from_slice(lthash);
    total.extend_from_slice(&version.to_be_bytes());
    total.extend_from_slice(collection_name.as_bytes());
    hmac_sha256(&total, keys.snapshot_mac_key())
}

pub fn app_state_patch_mac<I, M>(
    snapshot_mac: &[u8],
    value_macs: I,
    version: u64,
    collection_name: &str,
    keys: &AppStateKeyMaterial,
) -> CryptoResult<[u8; 32]>
where
    I: IntoIterator<Item = M>,
    M: AsRef<[u8]>,
{
    validate_mac(snapshot_mac, "snapshot mac")?;
    validate_collection_name(collection_name)?;
    let value_macs = value_macs.into_iter().collect::<Vec<_>>();
    let mac_len = value_macs
        .iter()
        .map(|mac| mac.as_ref().len())
        .sum::<usize>();
    let mut total = Vec::with_capacity(snapshot_mac.len() + mac_len + 8 + collection_name.len());
    total.extend_from_slice(snapshot_mac);
    for mac in value_macs {
        validate_mac(mac.as_ref(), "value mac")?;
        total.extend_from_slice(mac.as_ref());
    }
    total.extend_from_slice(&version.to_be_bytes());
    total.extend_from_slice(collection_name.as_bytes());
    hmac_sha256(&total, keys.patch_mac_key())
}

pub fn app_state_lt_hash_subtract_then_add<S, A>(
    base: &[u8],
    subtract: S,
    add: A,
) -> CryptoResult<[u8; APP_STATE_LT_HASH_LEN]>
where
    S: IntoIterator,
    S::Item: AsRef<[u8]>,
    A: IntoIterator,
    A::Item: AsRef<[u8]>,
{
    let mut output = *validate_lt_hash(base)?;
    for item in subtract {
        apply_lt_hash_operand(&mut output, item.as_ref(), true)?;
    }
    for item in add {
        apply_lt_hash_operand(&mut output, item.as_ref(), false)?;
    }
    Ok(output)
}

fn app_state_mutation_mac(
    operation: AppStateMutationOperation,
    data: &[u8],
    key_id: &[u8],
    key: &[u8],
) -> CryptoResult<[u8; 32]> {
    if key_id.is_empty() {
        return Err(CryptoError::InvalidInput("app-state key id"));
    }
    let mut key_context = Vec::with_capacity(1 + key_id.len());
    key_context.push(operation.mac_byte());
    key_context.extend_from_slice(key_id);

    let mut total = Vec::with_capacity(key_context.len() + data.len() + 8);
    total.extend_from_slice(&key_context);
    total.extend_from_slice(data);
    total.extend_from_slice(&(key_context.len() as u64).to_be_bytes());

    let mac = hmac_sha512(&total, key)?;
    let mut truncated = [0u8; APP_STATE_MAC_LEN];
    truncated.copy_from_slice(&mac[..APP_STATE_MAC_LEN]);
    Ok(truncated)
}

fn apply_lt_hash_operand(
    base: &mut [u8; APP_STATE_LT_HASH_LEN],
    input: &[u8],
    subtract: bool,
) -> CryptoResult<()> {
    let expanded = hkdf_sha256(input, APP_STATE_LT_HASH_LEN, &[], APP_STATE_LT_HASH_INFO)?;
    for (base_pair, input_pair) in base.chunks_exact_mut(2).zip(expanded.chunks_exact(2)) {
        let x = u16::from_le_bytes([base_pair[0], base_pair[1]]);
        let y = u16::from_le_bytes([input_pair[0], input_pair[1]]);
        let result = if subtract {
            x.wrapping_sub(y)
        } else {
            x.wrapping_add(y)
        };
        base_pair.copy_from_slice(&result.to_le_bytes());
    }
    Ok(())
}

fn validate_lt_hash(hash: &[u8]) -> CryptoResult<&[u8; APP_STATE_LT_HASH_LEN]> {
    hash.try_into()
        .map_err(|_| CryptoError::InvalidInput("app-state lt hash"))
}

fn validate_collection_name(collection_name: &str) -> CryptoResult<()> {
    if collection_name.is_empty() {
        return Err(CryptoError::InvalidInput("app-state collection name"));
    }
    Ok(())
}

fn validate_mac(mac: &[u8], label: &'static str) -> CryptoResult<()> {
    if mac.len() != APP_STATE_MAC_LEN {
        return Err(CryptoError::InvalidInput(label));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_app_state_keys_with_redacted_debug() {
        let keys = derive_app_state_keys(&[7u8; 32]).unwrap();
        assert_eq!(keys.index_key().len(), 32);
        assert_eq!(keys.value_encryption_key().len(), 32);
        assert_eq!(keys.value_mac_key().len(), 32);
        assert_eq!(keys.snapshot_mac_key().len(), 32);
        assert_eq!(keys.patch_mac_key().len(), 32);
        assert_ne!(keys.index_key(), keys.value_encryption_key());
        assert!(format!("{keys:?}").contains("[redacted]"));
        assert!(derive_app_state_keys(&[7u8; 31]).is_err());
    }

    #[test]
    fn encrypts_app_state_values_and_generates_macs() {
        let keys = derive_app_state_keys(&[8u8; 32]).unwrap();
        let iv = [3u8; 16];
        let encrypted = encrypt_app_state_value_with_iv(b"sync-action", &keys, &iv).unwrap();
        assert_eq!(&encrypted[..16], &iv);
        assert_ne!(&encrypted[16..], b"sync-action");
        let decrypted = decrypt_app_state_value(&encrypted, &keys).unwrap();
        assert_eq!(decrypted, b"sync-action");

        let key_id = [4u8; 32];
        let value_mac =
            app_state_value_mac(AppStateMutationOperation::Set, &encrypted, &key_id, &keys)
                .unwrap();
        assert_ne!(
            value_mac,
            app_state_value_mac(
                AppStateMutationOperation::Remove,
                &encrypted,
                &key_id,
                &keys
            )
            .unwrap()
        );
        assert_eq!(
            app_state_index_mac(b"[\"pin_v1\"]", &keys).unwrap().len(),
            32
        );

        let snapshot_mac = app_state_snapshot_mac(&[0u8; 128], 1, "regular_low", &keys).unwrap();
        let patch_mac =
            app_state_patch_mac(&snapshot_mac, [value_mac], 1, "regular_low", &keys).unwrap();
        assert_eq!(snapshot_mac.len(), 32);
        assert_eq!(patch_mac.len(), 32);
        assert!(
            app_state_patch_mac(&snapshot_mac[..31], [value_mac], 1, "regular_low", &keys).is_err()
        );
    }

    #[test]
    fn lt_hash_adds_and_subtracts_value_macs() {
        let base = [0u8; APP_STATE_LT_HASH_LEN];
        let first = [1u8; 32];
        let second = [2u8; 32];

        let after_add =
            app_state_lt_hash_subtract_then_add(&base, [] as [&[u8]; 0], [&first, &second])
                .unwrap();
        assert_ne!(after_add, base);

        let round_trip =
            app_state_lt_hash_subtract_then_add(&after_add, [&second, &first], [] as [&[u8]; 0])
                .unwrap();
        assert_eq!(round_trip, base);
        assert!(app_state_lt_hash_subtract_then_add(&base[..127], [&first], [&second]).is_err());
    }
}
