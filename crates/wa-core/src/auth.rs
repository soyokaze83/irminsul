use crate::{CoreError, CoreResult, RegistrationPayloadKeys};
use bytes::Bytes;
use wa_binary::BinaryNode;
use wa_crypto::{KeyPair, SecretBytes, generate_key_pair, prefixed_signal_public_key, sign_x25519};
use wa_store::{AuthStore, KeyNamespace, StoreError, StoreResult, StoreTransaction};

const SCHEMA_VERSION_KEY: &str = "schema-version";
const SCHEMA_VERSION: &[u8] = &[1];
const NOISE_PUBLIC_KEY: &str = "noise-public";
const NOISE_PRIVATE_KEY: &str = "noise-private";
const PAIRING_PUBLIC_KEY: &str = "pairing-ephemeral-public";
const PAIRING_PRIVATE_KEY: &str = "pairing-ephemeral-private";
const IDENTITY_PUBLIC_KEY: &str = "identity-public";
const IDENTITY_PRIVATE_KEY: &str = "identity-private";
const SIGNED_PRE_KEY_ID: &str = "signed-pre-key-id";
const SIGNED_PRE_KEY_PUBLIC: &str = "signed-pre-key-public";
const SIGNED_PRE_KEY_PRIVATE: &str = "signed-pre-key-private";
const SIGNED_PRE_KEY_SIGNATURE: &str = "signed-pre-key-signature";
const REGISTRATION_ID: &str = "registration-id";
const ADV_SECRET_KEY: &str = "adv-secret-key";
const NEXT_PRE_KEY_ID: &str = "next-pre-key-id";
const FIRST_UNUPLOADED_PRE_KEY_ID: &str = "first-unuploaded-pre-key-id";
const REGISTERED: &str = "registered";
const ACCOUNT_JID: &str = "account-jid";
const ACCOUNT_LID: &str = "account-lid";
const ACCOUNT_NAME: &str = "account-name";
const ACCOUNT_PLATFORM: &str = "account-platform";
const ACCOUNT_SIGNATURE_KEY: &str = "account-signature-key";
const SIGNED_DEVICE_IDENTITY: &str = "signed-device-identity";
const PAIRING_CODE: &str = "pairing-code";
const ROUTING_INFO: &str = "routing-info";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedPreKey {
    pub key_id: u32,
    pub key_pair: KeyPair,
    pub signature: Bytes,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthCredentials {
    pub noise_key: KeyPair,
    pub pairing_ephemeral_key_pair: KeyPair,
    pub signed_identity_key: KeyPair,
    pub signed_pre_key: SignedPreKey,
    pub registration_id: u32,
    pub adv_secret_key: SecretBytes,
    pub next_pre_key_id: u32,
    pub first_unuploaded_pre_key_id: u32,
    pub registered: bool,
    pub account_jid: Option<String>,
    pub account_lid: Option<String>,
    pub account_name: Option<String>,
    pub account_platform: Option<String>,
    pub account_signature_key: Option<Bytes>,
    pub signed_device_identity: Option<Bytes>,
    pub pairing_code: Option<String>,
    pub routing_info: Option<Bytes>,
}

impl AuthCredentials {
    #[must_use]
    pub fn registration_payload_keys(&self) -> RegistrationPayloadKeys {
        RegistrationPayloadKeys {
            registration_id: self.registration_id,
            signed_identity_public: Bytes::copy_from_slice(&self.signed_identity_key.public),
            signed_pre_key_id: self.signed_pre_key.key_id,
            signed_pre_key_public: Bytes::copy_from_slice(&self.signed_pre_key.key_pair.public),
            signed_pre_key_signature: self.signed_pre_key.signature.clone(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialLoad {
    pub credentials: AuthCredentials,
    pub initialized: bool,
}

pub fn create_initial_credentials() -> CoreResult<AuthCredentials> {
    let signed_identity_key = generate_key_pair();
    let signed_pre_key = create_signed_pre_key(&signed_identity_key, 1)?;
    let adv_secret_key: [u8; 32] = rand::random();

    Ok(AuthCredentials {
        noise_key: generate_key_pair(),
        pairing_ephemeral_key_pair: generate_key_pair(),
        signed_identity_key,
        signed_pre_key,
        registration_id: generate_registration_id(),
        adv_secret_key: adv_secret_key.into(),
        next_pre_key_id: 1,
        first_unuploaded_pre_key_id: 1,
        registered: false,
        account_jid: None,
        account_lid: None,
        account_name: None,
        account_platform: None,
        account_signature_key: None,
        signed_device_identity: None,
        pairing_code: None,
        routing_info: None,
    })
}

pub fn build_device_identity_node(credentials: &AuthCredentials) -> CoreResult<Option<BinaryNode>> {
    let Some(identity) = credentials.signed_device_identity.as_ref() else {
        return Ok(None);
    };
    if identity.is_empty() {
        return Err(CoreError::Payload(
            "stored device identity must not be empty".to_owned(),
        ));
    }
    Ok(Some(
        BinaryNode::new("device-identity").with_content(identity.clone()),
    ))
}

pub fn create_signed_pre_key(identity_key: &KeyPair, key_id: u32) -> CoreResult<SignedPreKey> {
    let key_pair = generate_key_pair();
    let prefixed_public = prefixed_signal_public_key(&key_pair.public);
    let signature = sign_x25519(identity_key.private.expose(), &prefixed_public)?;

    Ok(SignedPreKey {
        key_id,
        key_pair,
        signature: Bytes::copy_from_slice(&signature),
    })
}

#[must_use]
pub fn generate_registration_id() -> u32 {
    u32::from(u16::from_ne_bytes(rand::random::<[u8; 2]>())) & 0x3fff
}

pub async fn load_credentials<S>(store: &S) -> CoreResult<Option<AuthCredentials>>
where
    S: AuthStore,
{
    let version = store
        .get(KeyNamespace::Credentials, SCHEMA_VERSION_KEY)
        .await?;
    let Some(version) = version else {
        return Ok(None);
    };
    if version != SCHEMA_VERSION {
        return Err(StoreError::InvalidData(format!(
            "unsupported credential schema version: {version:?}"
        ))
        .into());
    }

    Ok(Some(AuthCredentials {
        noise_key: read_key_pair_async(store, NOISE_PUBLIC_KEY, NOISE_PRIVATE_KEY).await?,
        pairing_ephemeral_key_pair: read_key_pair_async(
            store,
            PAIRING_PUBLIC_KEY,
            PAIRING_PRIVATE_KEY,
        )
        .await?,
        signed_identity_key: read_key_pair_async(store, IDENTITY_PUBLIC_KEY, IDENTITY_PRIVATE_KEY)
            .await?,
        signed_pre_key: SignedPreKey {
            key_id: read_u32_async(store, SIGNED_PRE_KEY_ID).await?,
            key_pair: read_key_pair_async(store, SIGNED_PRE_KEY_PUBLIC, SIGNED_PRE_KEY_PRIVATE)
                .await?,
            signature: Bytes::from(read_required_async(store, SIGNED_PRE_KEY_SIGNATURE).await?),
        },
        registration_id: read_u32_async(store, REGISTRATION_ID).await?,
        adv_secret_key: SecretBytes::from(read_exact_async::<32, _>(store, ADV_SECRET_KEY).await?),
        next_pre_key_id: read_u32_async(store, NEXT_PRE_KEY_ID).await?,
        first_unuploaded_pre_key_id: read_u32_async(store, FIRST_UNUPLOADED_PRE_KEY_ID).await?,
        registered: read_bool_async(store, REGISTERED).await?,
        account_jid: read_optional_string_async(store, ACCOUNT_JID).await?,
        account_lid: read_optional_string_async(store, ACCOUNT_LID).await?,
        account_name: read_optional_string_async(store, ACCOUNT_NAME).await?,
        account_platform: read_optional_string_async(store, ACCOUNT_PLATFORM).await?,
        account_signature_key: read_optional_bytes_async(store, ACCOUNT_SIGNATURE_KEY).await?,
        signed_device_identity: read_optional_bytes_async(store, SIGNED_DEVICE_IDENTITY).await?,
        pairing_code: read_optional_string_async(store, PAIRING_CODE).await?,
        routing_info: read_optional_bytes_async(store, ROUTING_INFO).await?,
    }))
}

pub async fn save_credentials<S>(store: &S, credentials: AuthCredentials) -> CoreResult<()>
where
    S: AuthStore,
{
    store
        .transaction("save-auth-credentials", move |tx| {
            write_credentials_to_tx(tx, &credentials)?;
            Ok(())
        })
        .await?;
    Ok(())
}

pub async fn load_or_init_credentials<S>(store: &S) -> CoreResult<CredentialLoad>
where
    S: AuthStore,
{
    let generated = create_initial_credentials()?;
    let load = store
        .transaction("load-or-init-auth-credentials", move |tx| {
            if let Some(credentials) = read_credentials_from_tx(tx)? {
                return Ok(CredentialLoad {
                    credentials,
                    initialized: false,
                });
            }

            write_credentials_to_tx(tx, &generated)?;
            Ok(CredentialLoad {
                credentials: generated,
                initialized: true,
            })
        })
        .await?;
    Ok(load)
}

pub(crate) fn read_credentials_from_tx(
    tx: &mut dyn StoreTransaction,
) -> StoreResult<Option<AuthCredentials>> {
    let Some(version) = tx.get(KeyNamespace::Credentials, SCHEMA_VERSION_KEY)? else {
        return Ok(None);
    };
    if version != SCHEMA_VERSION {
        return Err(StoreError::InvalidData(format!(
            "unsupported credential schema version: {version:?}"
        )));
    }

    Ok(Some(AuthCredentials {
        noise_key: read_key_pair_tx(tx, NOISE_PUBLIC_KEY, NOISE_PRIVATE_KEY)?,
        pairing_ephemeral_key_pair: read_key_pair_tx(tx, PAIRING_PUBLIC_KEY, PAIRING_PRIVATE_KEY)?,
        signed_identity_key: read_key_pair_tx(tx, IDENTITY_PUBLIC_KEY, IDENTITY_PRIVATE_KEY)?,
        signed_pre_key: SignedPreKey {
            key_id: read_u32_tx(tx, SIGNED_PRE_KEY_ID)?,
            key_pair: read_key_pair_tx(tx, SIGNED_PRE_KEY_PUBLIC, SIGNED_PRE_KEY_PRIVATE)?,
            signature: Bytes::from(read_required_tx(tx, SIGNED_PRE_KEY_SIGNATURE)?),
        },
        registration_id: read_u32_tx(tx, REGISTRATION_ID)?,
        adv_secret_key: SecretBytes::from(read_exact_tx::<32>(tx, ADV_SECRET_KEY)?),
        next_pre_key_id: read_u32_tx(tx, NEXT_PRE_KEY_ID)?,
        first_unuploaded_pre_key_id: read_u32_tx(tx, FIRST_UNUPLOADED_PRE_KEY_ID)?,
        registered: read_bool_tx(tx, REGISTERED)?,
        account_jid: read_optional_string_tx(tx, ACCOUNT_JID)?,
        account_lid: read_optional_string_tx(tx, ACCOUNT_LID)?,
        account_name: read_optional_string_tx(tx, ACCOUNT_NAME)?,
        account_platform: read_optional_string_tx(tx, ACCOUNT_PLATFORM)?,
        account_signature_key: read_optional_bytes_tx(tx, ACCOUNT_SIGNATURE_KEY)?,
        signed_device_identity: read_optional_bytes_tx(tx, SIGNED_DEVICE_IDENTITY)?,
        pairing_code: read_optional_string_tx(tx, PAIRING_CODE)?,
        routing_info: read_optional_bytes_tx(tx, ROUTING_INFO)?,
    }))
}

pub(crate) fn write_credentials_to_tx(
    tx: &mut dyn StoreTransaction,
    credentials: &AuthCredentials,
) -> StoreResult<()> {
    tx.set(
        KeyNamespace::Credentials,
        SCHEMA_VERSION_KEY,
        SCHEMA_VERSION,
    )?;
    write_key_pair_tx(
        tx,
        NOISE_PUBLIC_KEY,
        NOISE_PRIVATE_KEY,
        &credentials.noise_key,
    )?;
    write_key_pair_tx(
        tx,
        PAIRING_PUBLIC_KEY,
        PAIRING_PRIVATE_KEY,
        &credentials.pairing_ephemeral_key_pair,
    )?;
    write_key_pair_tx(
        tx,
        IDENTITY_PUBLIC_KEY,
        IDENTITY_PRIVATE_KEY,
        &credentials.signed_identity_key,
    )?;
    write_u32_tx(tx, SIGNED_PRE_KEY_ID, credentials.signed_pre_key.key_id)?;
    write_key_pair_tx(
        tx,
        SIGNED_PRE_KEY_PUBLIC,
        SIGNED_PRE_KEY_PRIVATE,
        &credentials.signed_pre_key.key_pair,
    )?;
    tx.set(
        KeyNamespace::Credentials,
        SIGNED_PRE_KEY_SIGNATURE,
        &credentials.signed_pre_key.signature,
    )?;
    write_u32_tx(tx, REGISTRATION_ID, credentials.registration_id)?;
    tx.set(
        KeyNamespace::Credentials,
        ADV_SECRET_KEY,
        credentials.adv_secret_key.expose(),
    )?;
    write_u32_tx(tx, NEXT_PRE_KEY_ID, credentials.next_pre_key_id)?;
    write_u32_tx(
        tx,
        FIRST_UNUPLOADED_PRE_KEY_ID,
        credentials.first_unuploaded_pre_key_id,
    )?;
    tx.set(
        KeyNamespace::Credentials,
        REGISTERED,
        &[u8::from(credentials.registered)],
    )?;
    write_optional_tx(
        tx,
        ACCOUNT_JID,
        credentials.account_jid.as_deref().map(str::as_bytes),
    )?;
    write_optional_tx(
        tx,
        ACCOUNT_LID,
        credentials.account_lid.as_deref().map(str::as_bytes),
    )?;
    write_optional_tx(
        tx,
        ACCOUNT_NAME,
        credentials.account_name.as_deref().map(str::as_bytes),
    )?;
    write_optional_tx(
        tx,
        ACCOUNT_PLATFORM,
        credentials.account_platform.as_deref().map(str::as_bytes),
    )?;
    write_optional_tx(
        tx,
        ACCOUNT_SIGNATURE_KEY,
        credentials
            .account_signature_key
            .as_ref()
            .map(Bytes::as_ref),
    )?;
    write_optional_tx(
        tx,
        SIGNED_DEVICE_IDENTITY,
        credentials
            .signed_device_identity
            .as_ref()
            .map(Bytes::as_ref),
    )?;
    write_optional_tx(
        tx,
        PAIRING_CODE,
        credentials.pairing_code.as_deref().map(str::as_bytes),
    )?;
    write_optional_tx(
        tx,
        ROUTING_INFO,
        credentials.routing_info.as_ref().map(Bytes::as_ref),
    )?;
    Ok(())
}

async fn read_required_async<S>(store: &S, key: &str) -> StoreResult<Vec<u8>>
where
    S: AuthStore,
{
    store
        .get(KeyNamespace::Credentials, key)
        .await?
        .ok_or_else(|| StoreError::InvalidData(format!("missing credential field: {key}")))
}

async fn read_exact_async<const N: usize, S>(store: &S, key: &str) -> StoreResult<[u8; N]>
where
    S: AuthStore,
{
    vec_to_array(read_required_async(store, key).await?, key)
}

async fn read_u32_async<S>(store: &S, key: &str) -> StoreResult<u32>
where
    S: AuthStore,
{
    Ok(u32::from_be_bytes(
        read_exact_async::<4, _>(store, key).await?,
    ))
}

async fn read_bool_async<S>(store: &S, key: &str) -> StoreResult<bool>
where
    S: AuthStore,
{
    match read_required_async(store, key).await?.as_slice() {
        [0] => Ok(false),
        [1] => Ok(true),
        _ => Err(StoreError::InvalidData(format!(
            "invalid boolean credential field: {key}"
        ))),
    }
}

async fn read_key_pair_async<S>(
    store: &S,
    public_key: &str,
    private_key: &str,
) -> StoreResult<KeyPair>
where
    S: AuthStore,
{
    Ok(KeyPair {
        public: read_exact_async::<32, _>(store, public_key).await?,
        private: SecretBytes::from(read_exact_async::<32, _>(store, private_key).await?),
    })
}

async fn read_optional_string_async<S>(store: &S, key: &str) -> StoreResult<Option<String>>
where
    S: AuthStore,
{
    store
        .get(KeyNamespace::Credentials, key)
        .await?
        .map(|value| {
            String::from_utf8(value)
                .map_err(|err| StoreError::InvalidData(format!("invalid UTF-8 in {key}: {err}")))
        })
        .transpose()
}

async fn read_optional_bytes_async<S>(store: &S, key: &str) -> StoreResult<Option<Bytes>>
where
    S: AuthStore,
{
    Ok(store
        .get(KeyNamespace::Credentials, key)
        .await?
        .map(Bytes::from))
}

fn read_required_tx(tx: &mut dyn StoreTransaction, key: &str) -> StoreResult<Vec<u8>> {
    tx.get(KeyNamespace::Credentials, key)?
        .ok_or_else(|| StoreError::InvalidData(format!("missing credential field: {key}")))
}

fn read_exact_tx<const N: usize>(tx: &mut dyn StoreTransaction, key: &str) -> StoreResult<[u8; N]> {
    vec_to_array(read_required_tx(tx, key)?, key)
}

fn read_u32_tx(tx: &mut dyn StoreTransaction, key: &str) -> StoreResult<u32> {
    Ok(u32::from_be_bytes(read_exact_tx::<4>(tx, key)?))
}

fn read_bool_tx(tx: &mut dyn StoreTransaction, key: &str) -> StoreResult<bool> {
    match read_required_tx(tx, key)?.as_slice() {
        [0] => Ok(false),
        [1] => Ok(true),
        _ => Err(StoreError::InvalidData(format!(
            "invalid boolean credential field: {key}"
        ))),
    }
}

fn read_key_pair_tx(
    tx: &mut dyn StoreTransaction,
    public_key: &str,
    private_key: &str,
) -> StoreResult<KeyPair> {
    Ok(KeyPair {
        public: read_exact_tx::<32>(tx, public_key)?,
        private: SecretBytes::from(read_exact_tx::<32>(tx, private_key)?),
    })
}

fn read_optional_string_tx(
    tx: &mut dyn StoreTransaction,
    key: &str,
) -> StoreResult<Option<String>> {
    tx.get(KeyNamespace::Credentials, key)?
        .map(|value| {
            String::from_utf8(value)
                .map_err(|err| StoreError::InvalidData(format!("invalid UTF-8 in {key}: {err}")))
        })
        .transpose()
}

fn read_optional_bytes_tx(tx: &mut dyn StoreTransaction, key: &str) -> StoreResult<Option<Bytes>> {
    Ok(tx.get(KeyNamespace::Credentials, key)?.map(Bytes::from))
}

fn write_key_pair_tx(
    tx: &mut dyn StoreTransaction,
    public_key: &str,
    private_key: &str,
    key_pair: &KeyPair,
) -> StoreResult<()> {
    tx.set(KeyNamespace::Credentials, public_key, &key_pair.public)?;
    tx.set(
        KeyNamespace::Credentials,
        private_key,
        key_pair.private.expose(),
    )
}

fn write_u32_tx(tx: &mut dyn StoreTransaction, key: &str, value: u32) -> StoreResult<()> {
    tx.set(KeyNamespace::Credentials, key, &value.to_be_bytes())
}

fn write_optional_tx(
    tx: &mut dyn StoreTransaction,
    key: &str,
    value: Option<&[u8]>,
) -> StoreResult<()> {
    if let Some(value) = value {
        tx.set(KeyNamespace::Credentials, key, value)
    } else {
        tx.delete(KeyNamespace::Credentials, key)
    }
}

fn vec_to_array<const N: usize>(value: Vec<u8>, key: &str) -> StoreResult<[u8; N]> {
    value.try_into().map_err(|value: Vec<u8>| {
        StoreError::InvalidData(format!(
            "invalid credential field length for {key}: {}",
            value.len()
        ))
    })
}

impl From<wa_crypto::CryptoError> for CoreError {
    fn from(value: wa_crypto::CryptoError) -> Self {
        Self::Crypto(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wa_crypto::{NoiseCertificateVerifier, XEdDsaNoiseCertificateVerifier};
    use wa_store::SqliteAuthStore;

    #[test]
    fn generated_credentials_have_expected_defaults() {
        let credentials = create_initial_credentials().unwrap();

        assert_eq!(credentials.signed_pre_key.key_id, 1);
        assert_eq!(credentials.next_pre_key_id, 1);
        assert_eq!(credentials.first_unuploaded_pre_key_id, 1);
        assert!(!credentials.registered);
        assert!(credentials.registration_id <= 0x3fff);
        assert_eq!(credentials.adv_secret_key.expose().len(), 32);

        let signed_public = prefixed_signal_public_key(&credentials.signed_pre_key.key_pair.public);
        assert!(XEdDsaNoiseCertificateVerifier.verify_signature(
            &credentials.signed_identity_key.public,
            &signed_public,
            &credentials.signed_pre_key.signature
        ));
    }

    #[test]
    fn registration_payload_keys_use_public_material() {
        let credentials = create_initial_credentials().unwrap();
        let keys = credentials.registration_payload_keys();

        assert_eq!(keys.registration_id, credentials.registration_id);
        assert_eq!(
            keys.signed_identity_public,
            Bytes::copy_from_slice(&credentials.signed_identity_key.public)
        );
        assert_eq!(keys.signed_pre_key_id, credentials.signed_pre_key.key_id);
        assert_eq!(
            keys.signed_pre_key_public,
            Bytes::copy_from_slice(&credentials.signed_pre_key.key_pair.public)
        );
        assert_eq!(
            keys.signed_pre_key_signature,
            credentials.signed_pre_key.signature
        );
    }

    #[tokio::test]
    async fn load_or_init_persists_credentials() {
        let store = temp_store().await;
        let first = load_or_init_credentials(&store).await.unwrap();
        let second = load_or_init_credentials(&store).await.unwrap();

        assert!(first.initialized);
        assert!(!second.initialized);
        assert_eq!(first.credentials, second.credentials);
        assert_eq!(
            load_credentials(&store).await.unwrap(),
            Some(first.credentials)
        );
    }

    #[tokio::test]
    async fn save_credentials_replaces_optional_fields() {
        let store = temp_store().await;
        let mut credentials = create_initial_credentials().unwrap();
        credentials.account_jid = Some("12345@s.whatsapp.net".to_owned());
        credentials.account_lid = Some("abc@lid".to_owned());
        credentials.account_name = Some("Business".to_owned());
        credentials.account_platform = Some("Chrome".to_owned());
        credentials.account_signature_key = Some(Bytes::from_static(b"account-key"));
        credentials.signed_device_identity = Some(Bytes::from_static(b"signed-identity"));
        credentials.pairing_code = Some("ABCDEFGH".to_owned());
        credentials.routing_info = Some(Bytes::from_static(b"route"));
        save_credentials(&store, credentials.clone()).await.unwrap();
        assert_eq!(
            load_credentials(&store).await.unwrap().unwrap().account_jid,
            credentials.account_jid
        );

        credentials.account_jid = None;
        credentials.account_lid = None;
        credentials.account_name = None;
        credentials.account_platform = None;
        credentials.account_signature_key = None;
        credentials.signed_device_identity = None;
        credentials.pairing_code = None;
        credentials.routing_info = None;
        save_credentials(&store, credentials).await.unwrap();
        let loaded = load_credentials(&store).await.unwrap().unwrap();
        assert_eq!(loaded.account_jid, None);
        assert_eq!(loaded.account_lid, None);
        assert_eq!(loaded.account_name, None);
        assert_eq!(loaded.account_platform, None);
        assert_eq!(loaded.account_signature_key, None);
        assert_eq!(loaded.signed_device_identity, None);
        assert_eq!(loaded.pairing_code, None);
        assert_eq!(loaded.routing_info, None);
    }

    #[test]
    fn builds_optional_device_identity_node() {
        let mut credentials = create_initial_credentials().unwrap();
        assert_eq!(build_device_identity_node(&credentials).unwrap(), None);

        credentials.signed_device_identity = Some(Bytes::from_static(b"identity"));
        let node = build_device_identity_node(&credentials).unwrap().unwrap();
        assert_eq!(node.tag, "device-identity");
        assert_eq!(
            node.content,
            Some(wa_binary::BinaryNodeContent::Bytes(Bytes::from_static(
                b"identity"
            )))
        );

        credentials.signed_device_identity = Some(Bytes::new());
        assert!(build_device_identity_node(&credentials).is_err());
    }

    async fn temp_store() -> SqliteAuthStore {
        let dir = std::env::temp_dir().join(format!("wa-core-auth-{}", rand::random::<u128>()));
        SqliteAuthStore::open(dir.join("session.db")).await.unwrap()
    }
}
