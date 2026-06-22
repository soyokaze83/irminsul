use crate::{
    AuthCredentials, CoreError, CoreResult, InboundCiphertextType, InboundEncryptedPayload,
    InboundMessageDecryptor, MessageCiphertextType, MessageEncryption, MessageEncryptor,
};
use crate::{
    auth::read_credentials_from_tx,
    payload::KEY_BUNDLE_TYPE,
    pre_keys::{SERVER_JID, read_optional_pre_key_from_tx},
};
use async_trait::async_trait;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use prost::Message as ProstMessage;
use std::{
    collections::{HashMap, HashSet},
    fmt,
    sync::{Arc, Mutex, Weak},
};
use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard};
use wa_binary::{BinaryNode, BinaryNodeContent, JidServer, WaJidDomain, jid_decode, jid_encode};
use wa_crypto::{
    KeyPair, NoiseCertificateVerifier, SIGNAL_PUBLIC_KEY_VERSION, SecretBytes,
    XEdDsaNoiseCertificateVerifier, aes_256_cbc_decrypt_with_iv, aes_256_cbc_encrypt_with_iv,
    generate_key_pair, hkdf_sha256, hmac_sha256, prefixed_signal_public_key,
    public_key_from_private, shared_key, sign_x25519,
};
use wa_proto::proto::{
    SenderKeyDistributionMessage as ProtoSenderKeyDistributionMessage,
    SenderKeyMessage as ProtoSenderKeyMessage, SenderKeyRecordStructure, SenderKeyStateStructure,
    message::SenderKeyDistributionMessage, sender_key_state_structure,
};
use wa_store::{KeyNamespace, SignalKeyStore, StoreTransaction};
use zeroize::Zeroize;

const STORED_SESSION_VERSION: u8 = 1;
const SESSION_RECORD_KIND: u8 = 1;
const PROVIDER_SESSION_VERSION: u8 = 1;
const PROVIDER_SESSION_RECORD_KIND: u8 = 2;
const SIGNAL_MESSAGE_KEY_LEN: usize = 32;
const SIGNAL_MESSAGE_IV_LEN: usize = 16;
const SIGNAL_MESSAGE_MAC_LEN: usize = 8;
const SIGNAL_MESSAGE_DERIVED_KEY_LEN: usize =
    SIGNAL_MESSAGE_KEY_LEN + SIGNAL_MESSAGE_KEY_LEN + SIGNAL_MESSAGE_IV_LEN;
const SIGNAL_MESSAGE_KEYS_INFO: &[u8] = b"WhisperMessageKeys";
const SIGNAL_MESSAGE_KEYS_SALT: [u8; SIGNAL_MESSAGE_KEY_LEN] = [0u8; SIGNAL_MESSAGE_KEY_LEN];
const SIGNAL_MESSAGE_KEY_SEED: [u8; 1] = [0x01];
const SIGNAL_CHAIN_KEY_SEED: [u8; 1] = [0x02];
const SIGNAL_ROOT_RATCHET_INFO: &[u8] = b"WhisperRatchet";
const SIGNAL_ROOT_DERIVED_KEY_LEN: usize = SIGNAL_MESSAGE_KEY_LEN + SIGNAL_MESSAGE_KEY_LEN;
const SIGNAL_PRE_KEY_INFO: &[u8] = b"WhisperText";
const SIGNAL_PRE_KEY_DERIVED_KEY_LEN: usize = SIGNAL_MESSAGE_KEY_LEN + SIGNAL_MESSAGE_KEY_LEN;
const SIGNAL_PRE_KEY_SECRET_INPUT_3DH_LEN: usize =
    SIGNAL_MESSAGE_KEY_LEN + (3 * SIGNAL_MESSAGE_KEY_LEN);
const SIGNAL_PRE_KEY_SECRET_INPUT_4DH_LEN: usize =
    SIGNAL_MESSAGE_KEY_LEN + (4 * SIGNAL_MESSAGE_KEY_LEN);
const SIGNAL_X3DH_DISCONTINUITY: [u8; SIGNAL_MESSAGE_KEY_LEN] = [0xFF; SIGNAL_MESSAGE_KEY_LEN];
const SIGNAL_SENDER_MESSAGE_KEYS_INFO: &[u8] = b"WhisperGroup";
const SIGNAL_SENDER_MESSAGE_DERIVED_KEY_LEN: usize = SIGNAL_MESSAGE_IV_LEN + SIGNAL_MESSAGE_KEY_LEN;
const SIGNAL_SENDER_MESSAGE_KEY_SEED: [u8; 1] = [0x01];
const SIGNAL_SENDER_CHAIN_KEY_SEED: [u8; 1] = [0x02];
const SIGNAL_WIRE_CURRENT_VERSION: u8 = 3;
const SIGNAL_SENDER_KEY_SIGNATURE_LEN: usize = 64;
const SIGNAL_MAX_SENDER_KEY_STATES: usize = 5;
const SIGNAL_MAX_SENDER_MESSAGE_KEYS: usize = 2_000;
const SIGNAL_MAX_PROVIDER_MESSAGE_KEYS: usize = 2_000;
const SIGNAL_MAX_MESSAGE_FORWARD_JUMPS: u32 = 25_000;
const SIGNAL_MAX_SENDER_FORWARD_JUMPS: u32 = 25_000;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignalAddress {
    pub name: String,
    pub device_id: u16,
}

impl fmt::Display for SignalAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.name, self.device_id)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignalPreKey {
    pub key_id: u32,
    pub public_key: Bytes,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignalSignedPreKey {
    pub key_id: u32,
    pub public_key: Bytes,
    pub signature: Bytes,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignalSession {
    pub registration_id: u32,
    pub identity_key: Bytes,
    pub signed_pre_key: SignalSignedPreKey,
    pub pre_key: Option<SignalPreKey>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignalProviderSessionRecord {
    pub remote_registration_id: u32,
    pub remote_identity_key: Bytes,
    pub root_key: SignalRootKey,
    pub sending_chain: SignalMessageChainKey,
    pub receiving_chain: Option<SignalMessageChainKey>,
    pub remote_ratchet_key: Option<Bytes>,
    pub local_ratchet_key_pair: KeyPair,
    pub previous_counter: u32,
    pub message_keys: Vec<SignalProviderStoredMessageKey>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignalProviderStoredMessageKey {
    pub ratchet_key: Bytes,
    pub counter: u32,
    pub message_keys: SignalMessageKeyMaterial,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignalProviderSessionEncryption {
    pub record: Bytes,
    pub message: SignalWhisperMessage,
    pub message_bytes: Bytes,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignalProviderSessionDecryption {
    pub record: Bytes,
    pub message: SignalWhisperMessage,
    pub plaintext: Bytes,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignalProviderPreKeySessionEncryption {
    pub record: Bytes,
    pub message: SignalPreKeyWhisperMessage,
    pub message_bytes: Bytes,
    pub used_one_time_pre_key: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignalProviderPreKeySessionDecryption {
    pub record: Bytes,
    pub message: SignalPreKeyWhisperMessage,
    pub plaintext: Bytes,
    pub used_one_time_pre_key: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionInjection {
    pub jid: String,
    pub session: SignalSession,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetryReceiptSessionBundle {
    pub session: SessionInjection,
    pub device_identity: Option<Bytes>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignalSessionInfo {
    pub address: SignalAddress,
    pub base_key: Bytes,
    pub registration_id: u32,
    pub session: SignalSession,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignalProviderSessionInfo {
    pub address: SignalAddress,
    pub base_key: Bytes,
    pub registration_id: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignalLocalIdentity {
    pub key_pair: KeyPair,
    pub public_key: Bytes,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignalLocalSignedPreKey {
    pub key_id: u32,
    pub key_pair: KeyPair,
    pub public_key: Bytes,
    pub signature: Bytes,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignalLocalPreKey {
    pub key_id: u32,
    pub key_pair: KeyPair,
    pub public_key: Bytes,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignalLocalKeyMaterial {
    pub registration_id: u32,
    pub identity: SignalLocalIdentity,
    pub signed_pre_key: SignalLocalSignedPreKey,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignalWhisperMessage {
    pub ephemeral_key: Bytes,
    pub counter: u32,
    pub previous_counter: u32,
    pub ciphertext: Bytes,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignalPreKeyWhisperMessage {
    pub registration_id: u32,
    pub pre_key_id: Option<u32>,
    pub signed_pre_key_id: u32,
    pub base_key: Bytes,
    pub identity_key: Bytes,
    pub message: SignalWhisperMessage,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignalMessageKeyMaterial {
    pub cipher_key: SecretBytes,
    pub mac_key: SecretBytes,
    pub iv: [u8; SIGNAL_MESSAGE_IV_LEN],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignalMessageChainKey {
    pub key: SecretBytes,
    pub counter: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignalMessageChainStep {
    pub message_counter: u32,
    pub message_keys: SignalMessageKeyMaterial,
    pub next_chain_key: SignalMessageChainKey,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignalRootKey {
    pub key: SecretBytes,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignalRootRatchetStep {
    pub root_key: SignalRootKey,
    pub chain_key: SignalMessageChainKey,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignalPreKeyBootstrap {
    pub root_key: SignalRootKey,
    pub chain_key: SignalMessageChainKey,
    pub used_one_time_pre_key: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignalSenderChainKey {
    pub key: SecretBytes,
    pub iteration: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignalSenderMessageKeyMaterial {
    pub iteration: u32,
    pub seed: SecretBytes,
    pub cipher_key: SecretBytes,
    pub iv: [u8; SIGNAL_MESSAGE_IV_LEN],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignalSenderChainStep {
    pub message_key: SignalSenderMessageKeyMaterial,
    pub next_chain_key: SignalSenderChainKey,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignalSenderKeyDistributionMessage {
    pub message_version: u8,
    pub key_id: u32,
    pub iteration: u32,
    pub chain_key: SecretBytes,
    pub signing_key: Bytes,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignalSenderKeyDistributionRecord {
    pub key: String,
    pub record: Bytes,
    pub distribution: SignalSenderKeyDistributionMessage,
    pub distribution_bytes: Bytes,
    pub created: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignalSenderKeyMessage {
    pub message_version: u8,
    pub key_id: u32,
    pub iteration: u32,
    pub ciphertext: Bytes,
    pub signature: Bytes,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignalSenderStoredMessageKey {
    pub iteration: u32,
    pub seed: SecretBytes,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignalSenderKeyState {
    pub key_id: u32,
    pub chain_key: SignalSenderChainKey,
    pub signing_public_key: Bytes,
    pub signing_private_key: Option<SecretBytes>,
    pub message_keys: Vec<SignalSenderStoredMessageKey>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SignalSenderKeyRecord {
    pub states: Vec<SignalSenderKeyState>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignalSenderKeyEncryption {
    pub record: Bytes,
    pub message: SignalSenderKeyMessage,
    pub message_bytes: Bytes,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignalSenderKeyDecryption {
    pub record: Bytes,
    pub message: SignalSenderKeyMessage,
    pub plaintext: Bytes,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignalSessionValidation {
    pub exists: bool,
    pub reason: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SignalSessionMigration {
    pub migrated: usize,
    pub skipped: usize,
    pub total: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LidPnMapping {
    pub pn: String,
    pub lid: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignalProviderRecordKind {
    Identity,
    PreKey,
    SenderKey,
    SenderKeyMemory,
    Session,
    SignedPreKey,
}

impl SignalProviderRecordKind {
    #[must_use]
    pub const fn namespace(self) -> KeyNamespace {
        match self {
            Self::Identity => KeyNamespace::SignalProviderIdentity,
            Self::PreKey => KeyNamespace::SignalProviderPreKey,
            Self::SenderKey => KeyNamespace::SignalProviderSenderKey,
            Self::SenderKeyMemory => KeyNamespace::SignalProviderSenderKeyMemory,
            Self::Session => KeyNamespace::SignalProviderSession,
            Self::SignedPreKey => KeyNamespace::SignalProviderSignedPreKey,
        }
    }
}

#[async_trait]
pub trait SignalRepository: Send + Sync {
    async fn inject_e2e_session(&self, injection: SessionInjection) -> CoreResult<()>;
    async fn get_session_info(&self, jid: &str) -> CoreResult<Option<SignalSessionInfo>>;
    async fn validate_session(&self, jid: &str) -> CoreResult<SignalSessionValidation>;
    async fn delete_sessions(&self, jids: &[String]) -> CoreResult<()>;
    async fn migrate_session(
        &self,
        from_jid: &str,
        to_jid: &str,
    ) -> CoreResult<SignalSessionMigration>;
    async fn save_identity(&self, jid: &str, identity_key: Bytes) -> CoreResult<bool>;
    async fn store_sender_key_distribution(
        &self,
        author_jid: &str,
        group_jid: &str,
        distribution: Bytes,
    ) -> CoreResult<()>;
    async fn get_sender_key_distribution(
        &self,
        author_jid: &str,
        group_jid: &str,
    ) -> CoreResult<Option<Bytes>>;
    async fn clear_sender_key_memory(&self, group_jid: &str) -> CoreResult<bool>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignalCiphertextType {
    Message,
    PreKey,
    SenderKey,
}

impl SignalCiphertextType {
    #[must_use]
    pub fn as_wire_type(self) -> &'static str {
        match self {
            Self::Message => "msg",
            Self::PreKey => "pkmsg",
            Self::SenderKey => "skmsg",
        }
    }
}

impl From<SignalCiphertextType> for MessageCiphertextType {
    fn from(value: SignalCiphertextType) -> Self {
        match value {
            SignalCiphertextType::Message => Self::Message,
            SignalCiphertextType::PreKey => Self::PreKey,
            SignalCiphertextType::SenderKey => Self::SenderKey,
        }
    }
}

impl From<InboundCiphertextType> for SignalCiphertextType {
    fn from(value: InboundCiphertextType) -> Self {
        match value {
            InboundCiphertextType::Message => Self::Message,
            InboundCiphertextType::PreKey => Self::PreKey,
            InboundCiphertextType::SenderKey => Self::SenderKey,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignalCiphertext {
    pub ciphertext_type: SignalCiphertextType,
    pub ciphertext: Bytes,
}

impl SignalCiphertext {
    #[must_use]
    pub fn new(ciphertext_type: SignalCiphertextType, ciphertext: Bytes) -> Self {
        Self {
            ciphertext_type,
            ciphertext,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignalEncryptionRequest {
    pub recipient_jid: String,
    pub plaintext: Bytes,
    pub session: Option<SignalSessionInfo>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignalDecryptionRequest {
    pub payload: InboundEncryptedPayload,
    pub session: Option<SignalSessionInfo>,
    pub sender_key_distribution: Option<Bytes>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignalSenderKeyDistribution {
    pub author_jid: String,
    pub group_jid: String,
    pub distribution: Bytes,
}

#[derive(Clone, Default)]
pub struct SignalMutationLocks {
    inner: Arc<Mutex<HashMap<String, Weak<AsyncMutex<()>>>>>,
}

impl SignalMutationLocks {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn lock(&self, key: impl Into<String>) -> CoreResult<SignalMutationGuard> {
        let lock = self.lock_handle(key.into())?;
        Ok(SignalMutationGuard {
            _guard: lock.lock_owned().await,
        })
    }

    #[must_use]
    pub fn ptr_eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }

    fn lock_handle(&self, key: String) -> CoreResult<Arc<AsyncMutex<()>>> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| CoreError::Task("Signal mutation lock table poisoned".to_owned()))?;
        if let Some(lock) = inner.get(&key).and_then(Weak::upgrade) {
            return Ok(lock);
        }
        inner.retain(|_, lock| lock.strong_count() > 0);
        let lock = Arc::new(AsyncMutex::new(()));
        inner.insert(key, Arc::downgrade(&lock));
        Ok(lock)
    }
}

#[must_use]
pub struct SignalMutationGuard {
    _guard: OwnedMutexGuard<()>,
}

#[async_trait]
pub trait SignalCryptoProvider: Send + Sync {
    async fn encrypt_signal_message(
        &self,
        request: SignalEncryptionRequest,
    ) -> CoreResult<SignalCiphertext>;

    async fn decrypt_signal_message(&self, request: SignalDecryptionRequest) -> CoreResult<Bytes>;

    async fn process_sender_key_distribution(
        &self,
        _distribution: SignalSenderKeyDistribution,
    ) -> CoreResult<()> {
        Ok(())
    }
}

#[derive(Clone)]
pub struct SignalMessageCodec<R, C> {
    repository: R,
    provider: C,
}

impl<R, C> SignalMessageCodec<R, C> {
    #[must_use]
    pub fn new(repository: R, provider: C) -> Self {
        Self {
            repository,
            provider,
        }
    }

    #[must_use]
    pub fn repository(&self) -> &R {
        &self.repository
    }

    #[must_use]
    pub fn provider(&self) -> &C {
        &self.provider
    }
}

#[derive(Clone)]
pub struct StoreSignalSenderKeyProvider<S, V = XEdDsaNoiseCertificateVerifier> {
    state_store: SignalProviderStateStore<S>,
    verifier: V,
    local_sender_jid: Option<String>,
}

impl<S> StoreSignalSenderKeyProvider<S, XEdDsaNoiseCertificateVerifier> {
    #[must_use]
    pub fn new(store: S) -> Self {
        Self::with_verifier(store, XEdDsaNoiseCertificateVerifier)
    }
}

impl<S, V> StoreSignalSenderKeyProvider<S, V> {
    #[must_use]
    pub fn with_verifier(store: S, verifier: V) -> Self {
        Self::with_verifier_and_mutation_locks(store, verifier, SignalMutationLocks::default())
    }

    #[must_use]
    pub fn with_verifier_and_mutation_locks(
        store: S,
        verifier: V,
        mutation_locks: SignalMutationLocks,
    ) -> Self {
        Self {
            state_store: SignalProviderStateStore::with_mutation_locks(store, mutation_locks),
            verifier,
            local_sender_jid: None,
        }
    }

    pub fn with_local_sender_jid(
        mut self,
        local_sender_jid: impl Into<String>,
    ) -> CoreResult<Self> {
        let local_sender_jid = local_sender_jid.into();
        let local_sender_jid = normalize_signal_session_jid(&local_sender_jid)?;
        validate_sender_key_jid("local sender-key sender JID", &local_sender_jid)?;
        self.local_sender_jid = Some(local_sender_jid);
        Ok(self)
    }

    #[must_use]
    pub fn state_store(&self) -> &SignalProviderStateStore<S> {
        &self.state_store
    }
}

impl<S, V> StoreSignalSenderKeyProvider<S, V>
where
    S: SignalKeyStore,
    V: NoiseCertificateVerifier + Send + Sync,
{
    pub async fn load_or_create_sender_key_distribution(
        &self,
        group_jid: &str,
    ) -> CoreResult<SignalSenderKeyDistributionRecord> {
        let local_sender_jid = self.local_sender_jid.as_deref().ok_or_else(|| {
            CoreError::Protocol(
                "store sender-key provider requires local sender JID for distribution".to_owned(),
            )
        })?;
        self.state_store
            .load_or_create_sender_key_distribution_record(local_sender_jid, group_jid)
            .await
    }

    async fn encrypt_direct_signal_message(
        &self,
        recipient_jid: &str,
        plaintext: &[u8],
        session: Option<SignalSessionInfo>,
    ) -> CoreResult<SignalCiphertext> {
        if let Some(encrypted) = self
            .state_store
            .encrypt_existing_session_record_message(
                recipient_jid,
                Bytes::copy_from_slice(plaintext),
            )
            .await?
        {
            return Ok(SignalCiphertext::new(
                SignalCiphertextType::Message,
                encrypted.message_bytes,
            ));
        }

        let session = session.ok_or_else(|| {
            CoreError::Protocol(format!(
                "missing Signal session for one-to-one recipient: {recipient_jid}"
            ))
        })?;
        let local_key_material = self
            .state_store
            .load_local_key_material()
            .await?
            .ok_or_else(|| {
                CoreError::Protocol(
                    "missing local Signal key material for one-to-one encryption".to_owned(),
                )
            })?;
        let local_base_key = generate_key_pair();
        let encrypted = encrypt_signal_outbound_pre_key_session_message(
            &local_key_material,
            &local_base_key,
            &session.session,
            &self.verifier,
            plaintext,
        )?;
        self.state_store
            .store_session_and_identity_records(
                recipient_jid,
                &encrypted.record,
                &session.session.identity_key,
            )
            .await?;
        Ok(SignalCiphertext::new(
            SignalCiphertextType::PreKey,
            encrypted.message_bytes,
        ))
    }

    async fn decrypt_direct_signal_message(
        &self,
        payload: InboundEncryptedPayload,
    ) -> CoreResult<Bytes> {
        match payload.ciphertext_type {
            InboundCiphertextType::Message => {
                let decrypted = self
                    .state_store
                    .decrypt_session_record_message(&payload.sender_jid, payload.ciphertext)
                    .await?;
                Ok(decrypted.plaintext)
            }
            InboundCiphertextType::PreKey => {
                let pre_key_message = decode_signal_pre_key_whisper_message(&payload.ciphertext)?;
                let local_one_time_pre_key = if let Some(pre_key_id) = pre_key_message.pre_key_id {
                    match self.state_store.load_local_pre_key(pre_key_id).await? {
                        Some(pre_key) => Some(pre_key),
                        None => {
                            if let Some(plaintext) = self
                                .decrypt_missing_pre_key_with_existing_session(
                                    &payload.sender_jid,
                                    &pre_key_message,
                                )
                                .await?
                            {
                                return Ok(plaintext);
                            }
                            return Err(CoreError::Protocol(format!(
                                "missing local Signal one-time pre-key {pre_key_id}"
                            )));
                        }
                    }
                } else {
                    if let Some(plaintext) = self
                        .decrypt_signed_pre_key_replay_with_existing_session(
                            &payload.sender_jid,
                            &pre_key_message,
                        )
                        .await?
                    {
                        return Ok(plaintext);
                    }
                    None
                };
                let local_key_material = self
                    .state_store
                    .load_local_key_material()
                    .await?
                    .ok_or_else(|| {
                        CoreError::Protocol(
                            "missing local Signal key material for pre-key decrypt".to_owned(),
                        )
                    })?;
                let decrypted = decrypt_signal_inbound_pre_key_session_decoded(
                    &local_key_material,
                    local_one_time_pre_key.as_ref(),
                    pre_key_message,
                )?;
                self.state_store
                    .store_inbound_pre_key_session_records(
                        &payload.sender_jid,
                        decrypted.message.pre_key_id,
                        &decrypted.record,
                        &decrypted.message.identity_key,
                    )
                    .await?;
                Ok(decrypted.plaintext)
            }
            InboundCiphertextType::SenderKey => Err(CoreError::Protocol(
                "direct Signal decrypt received sender-key payload".to_owned(),
            )),
        }
    }

    async fn decrypt_missing_pre_key_with_existing_session(
        &self,
        sender_jid: &str,
        pre_key_message: &SignalPreKeyWhisperMessage,
    ) -> CoreResult<Option<Bytes>> {
        let Some(record_bytes) = self.state_store.load_session_record(sender_jid).await? else {
            return Ok(None);
        };
        let Ok(record) = decode_signal_provider_session_record(&record_bytes) else {
            return Ok(None);
        };
        let base_key = normalize_signal_public_key(&pre_key_message.base_key)?;
        if record.remote_ratchet_key.as_ref() != Some(&base_key) {
            return Ok(None);
        }
        let Some(identity) = self.state_store.load_identity_record(sender_jid).await? else {
            return Err(CoreError::Protocol("no provider identity".to_owned()));
        };
        let stored_identity = normalize_signal_public_key(&identity)?;
        let message_identity = normalize_signal_public_key(&pre_key_message.identity_key)?;
        if stored_identity != message_identity {
            let address = signal_protocol_address(sender_jid)?;
            return Err(CoreError::Protocol(format!(
                "Signal provider identity changed for {address}"
            )));
        }
        self.validate_replay_signed_pre_key_id(pre_key_message)
            .await?;
        let message = encode_signal_whisper_message(&pre_key_message.message)?;
        self.state_store
            .decrypt_session_record_message(sender_jid, message)
            .await
            .map(|decrypted| Some(decrypted.plaintext))
    }

    async fn decrypt_signed_pre_key_replay_with_existing_session(
        &self,
        sender_jid: &str,
        pre_key_message: &SignalPreKeyWhisperMessage,
    ) -> CoreResult<Option<Bytes>> {
        let Some(record_bytes) = self.state_store.load_session_record(sender_jid).await? else {
            return Ok(None);
        };
        let Ok(record) = decode_signal_provider_session_record(&record_bytes) else {
            return Ok(None);
        };
        let base_key = normalize_signal_public_key(&pre_key_message.base_key)?;
        if record.remote_ratchet_key.as_ref() != Some(&base_key) {
            return Ok(None);
        }
        let Some(identity) = self.state_store.load_identity_record(sender_jid).await? else {
            return Err(CoreError::Protocol("no provider identity".to_owned()));
        };
        let stored_identity = normalize_signal_public_key(&identity)?;
        let message_identity = normalize_signal_public_key(&pre_key_message.identity_key)?;
        if stored_identity != message_identity {
            let address = signal_protocol_address(sender_jid)?;
            return Err(CoreError::Protocol(format!(
                "Signal provider identity changed for {address}"
            )));
        }
        self.validate_replay_signed_pre_key_id(pre_key_message)
            .await?;
        let message = encode_signal_whisper_message(&pre_key_message.message)?;
        self.state_store
            .decrypt_session_record_message(sender_jid, message)
            .await
            .map(|decrypted| Some(decrypted.plaintext))
    }

    async fn validate_replay_signed_pre_key_id(
        &self,
        pre_key_message: &SignalPreKeyWhisperMessage,
    ) -> CoreResult<()> {
        let Some(local_key_material) = self.state_store.load_local_key_material().await? else {
            return Ok(());
        };
        if pre_key_message.signed_pre_key_id != local_key_material.signed_pre_key.key_id {
            return Err(CoreError::Protocol(format!(
                "Signal signed pre-key id mismatch: message {}, local {}",
                pre_key_message.signed_pre_key_id, local_key_material.signed_pre_key.key_id
            )));
        }
        Ok(())
    }
}

#[async_trait]
impl<S, V> SignalCryptoProvider for StoreSignalSenderKeyProvider<S, V>
where
    S: SignalKeyStore,
    V: NoiseCertificateVerifier + Clone + Send + Sync + 'static,
{
    async fn encrypt_signal_message(
        &self,
        request: SignalEncryptionRequest,
    ) -> CoreResult<SignalCiphertext> {
        let SignalEncryptionRequest {
            recipient_jid,
            plaintext,
            session,
        } = request;
        let recipient_jid = normalize_signal_session_jid(&recipient_jid)?;
        let decoded = jid_decode(&recipient_jid).ok_or_else(|| {
            CoreError::Protocol(format!("invalid Signal recipient JID: {recipient_jid}"))
        })?;
        if decoded.server != JidServer::GUs {
            return self
                .encrypt_direct_signal_message(&recipient_jid, &plaintext, session)
                .await;
        }
        let local_sender_jid = self.local_sender_jid.as_deref().ok_or_else(|| {
            CoreError::Protocol(
                "store sender-key provider requires local sender JID for group encryption"
                    .to_owned(),
            )
        })?;
        let key = sender_key_store_key(local_sender_jid, &recipient_jid)?;
        let encrypted = self
            .state_store
            .encrypt_sender_key_record_message(&key, &plaintext)
            .await?;
        Ok(SignalCiphertext::new(
            SignalCiphertextType::SenderKey,
            encrypted.message_bytes,
        ))
    }

    async fn decrypt_signal_message(&self, request: SignalDecryptionRequest) -> CoreResult<Bytes> {
        let SignalDecryptionRequest {
            mut payload,
            session: _,
            sender_key_distribution,
        } = request;
        payload.sender_jid = normalize_signal_session_jid(&payload.sender_jid)?;
        if payload.ciphertext_type != InboundCiphertextType::SenderKey {
            return self.decrypt_direct_signal_message(payload).await;
        }
        let key = sender_key_store_key(&payload.sender_jid, &payload.chat_jid)?;
        let decrypted = match self
            .state_store
            .decrypt_sender_key_record_message(&key, &payload.ciphertext, self.verifier.clone())
            .await
        {
            Ok(decrypted) => decrypted,
            Err(err) => {
                let Some(distribution) = sender_key_distribution else {
                    return Err(err);
                };
                let Ok(distribution) = decode_signal_sender_key_distribution_message(&distribution)
                else {
                    return Err(err);
                };
                self.state_store
                    .decrypt_sender_key_record_message_with_distribution_retry(
                        &key,
                        &payload.ciphertext,
                        &distribution,
                        self.verifier.clone(),
                    )
                    .await?
            }
        };
        Ok(decrypted.plaintext)
    }

    async fn process_sender_key_distribution(
        &self,
        mut distribution: SignalSenderKeyDistribution,
    ) -> CoreResult<()> {
        distribution.author_jid = normalize_signal_session_jid(&distribution.author_jid)?;
        let key = sender_key_store_key(&distribution.author_jid, &distribution.group_jid)?;
        let distribution =
            decode_signal_sender_key_distribution_message(&distribution.distribution)?;
        self.state_store
            .process_sender_key_distribution_record(&key, &distribution)
            .await?;
        Ok(())
    }
}

#[derive(Clone)]
pub struct StoreSignalRepository<S> {
    store: S,
    mutation_locks: SignalMutationLocks,
}

impl<S> StoreSignalRepository<S> {
    #[must_use]
    pub fn new(store: S) -> Self {
        Self::with_mutation_locks(store, SignalMutationLocks::default())
    }

    #[must_use]
    pub fn with_mutation_locks(store: S, mutation_locks: SignalMutationLocks) -> Self {
        Self {
            store,
            mutation_locks,
        }
    }

    #[must_use]
    pub fn store(&self) -> &S {
        &self.store
    }

    #[must_use]
    pub fn mutation_locks(&self) -> &SignalMutationLocks {
        &self.mutation_locks
    }
}

#[derive(Clone)]
pub struct SignalProviderStateStore<S> {
    store: S,
    mutation_locks: SignalMutationLocks,
}

impl<S> SignalProviderStateStore<S> {
    #[must_use]
    pub fn new(store: S) -> Self {
        Self::with_mutation_locks(store, SignalMutationLocks::default())
    }

    #[must_use]
    pub fn with_mutation_locks(store: S, mutation_locks: SignalMutationLocks) -> Self {
        Self {
            store,
            mutation_locks,
        }
    }

    #[must_use]
    pub fn store(&self) -> &S {
        &self.store
    }

    #[must_use]
    pub fn mutation_locks(&self) -> &SignalMutationLocks {
        &self.mutation_locks
    }
}

impl<S> SignalProviderStateStore<S>
where
    S: SignalKeyStore,
{
    pub async fn load_record(
        &self,
        kind: SignalProviderRecordKind,
        key: &str,
    ) -> CoreResult<Option<Bytes>> {
        validate_provider_record_key(key)?;
        Ok(self
            .store
            .get_signal_key(kind.namespace(), key)
            .await?
            .map(Bytes::from))
    }

    pub async fn store_record(
        &self,
        kind: SignalProviderRecordKind,
        key: &str,
        value: &[u8],
    ) -> CoreResult<()> {
        validate_provider_record_key(key)?;
        validate_provider_record_value(value)?;
        if kind == SignalProviderRecordKind::Session {
            let key = key.to_owned();
            let session = Bytes::copy_from_slice(value);
            let _guard = self
                .mutation_locks
                .lock(provider_session_mutation_lock_key(&key))
                .await?;
            self.store
                .signal_transaction("store-signal-provider-raw-session", move |tx| {
                    if let Some(identity) = tx.get(KeyNamespace::SignalProviderIdentity, &key)?
                        && let Err(err) =
                            validate_decodable_provider_session_identity(&session, &identity)
                    {
                        return Ok(Err(err));
                    }
                    tx.set(KeyNamespace::SignalProviderSession, &key, &session)?;
                    Ok(Ok(()))
                })
                .await??;
            return Ok(());
        }
        if kind == SignalProviderRecordKind::Identity {
            let key = key.to_owned();
            let identity = Bytes::copy_from_slice(value);
            let _guard = self
                .mutation_locks
                .lock(provider_session_mutation_lock_key(&key))
                .await?;
            self.store
                .signal_transaction("store-signal-provider-raw-identity", move |tx| {
                    if let Err(err) =
                        validate_provider_identity_transition_in_tx(tx, &key, &identity)?
                    {
                        return Ok(Err(err));
                    }
                    if let Some(session) = tx.get(KeyNamespace::SignalProviderSession, &key)?
                        && let Err(err) =
                            validate_decodable_provider_session_identity(&session, &identity)
                    {
                        return Ok(Err(err));
                    }
                    tx.set(KeyNamespace::SignalProviderIdentity, &key, &identity)?;
                    Ok(Ok(()))
                })
                .await??;
            return Ok(());
        }
        self.store
            .set_signal_key(kind.namespace(), key, value)
            .await?;
        Ok(())
    }

    pub async fn delete_record(
        &self,
        kind: SignalProviderRecordKind,
        key: &str,
    ) -> CoreResult<bool> {
        validate_provider_record_key(key)?;
        if kind == SignalProviderRecordKind::Session {
            let key = key.to_owned();
            let _guard = self
                .mutation_locks
                .lock(provider_session_mutation_lock_key(&key))
                .await?;
            return self
                .store
                .signal_transaction("delete-signal-provider-raw-session", move |tx| {
                    delete_provider_session_record_in_tx(tx, &key)
                })
                .await
                .map_err(Into::into);
        }
        if kind == SignalProviderRecordKind::Identity {
            let key = key.to_owned();
            let _guard = self
                .mutation_locks
                .lock(provider_session_mutation_lock_key(&key))
                .await?;
            return self
                .store
                .signal_transaction("delete-signal-provider-raw-identity", move |tx| {
                    delete_provider_identity_record_in_tx(tx, &key)
                })
                .await
                .map_err(Into::into);
        }
        delete_provider_record(&self.store, kind.namespace(), key).await
    }

    pub async fn load_session_record(&self, jid: &str) -> CoreResult<Option<Bytes>> {
        let key = signal_protocol_address(jid)?.to_string();
        self.load_record(SignalProviderRecordKind::Session, &key)
            .await
    }

    pub async fn load_session_info(
        &self,
        jid: &str,
    ) -> CoreResult<Option<SignalProviderSessionInfo>> {
        let address = signal_protocol_address(jid)?;
        let key = address.to_string();
        let address_for_info = address.clone();
        let _guard = self
            .mutation_locks
            .lock(provider_session_mutation_lock_key(&key))
            .await?;
        self.store
            .signal_transaction("load-signal-provider-session-info", move |tx| {
                let Some(record) = tx.get(KeyNamespace::SignalProviderSession, &key)? else {
                    return Ok(Ok(None));
                };
                let Ok(record) = decode_signal_provider_session_record(&record) else {
                    return Ok(Ok(None));
                };
                let Some(identity) = tx.get(KeyNamespace::SignalProviderIdentity, &key)? else {
                    return Ok(Ok(None));
                };
                let Ok(identity) = normalize_signal_public_key(&identity) else {
                    return Ok(Ok(None));
                };
                if identity != record.remote_identity_key {
                    return Ok(Ok(None));
                }
                Ok(Ok(Some(SignalProviderSessionInfo {
                    address: address_for_info,
                    base_key: Bytes::copy_from_slice(&prefixed_signal_public_key(
                        &record.local_ratchet_key_pair.public,
                    )),
                    registration_id: record.remote_registration_id,
                })))
            })
            .await?
    }

    pub async fn validate_session_record(&self, jid: &str) -> CoreResult<SignalSessionValidation> {
        let key = signal_protocol_address(jid)?.to_string();
        let _guard = self
            .mutation_locks
            .lock(provider_session_mutation_lock_key(&key))
            .await?;
        Ok(self
            .store
            .signal_transaction("validate-signal-provider-session", move |tx| {
                let Some(record) = tx.get(KeyNamespace::SignalProviderSession, &key)? else {
                    return Ok(SignalSessionValidation {
                        exists: false,
                        reason: Some("no provider session".to_owned()),
                    });
                };

                match decode_signal_provider_session_record(&record) {
                    Ok(record) => {
                        let Some(identity) = tx.get(KeyNamespace::SignalProviderIdentity, &key)?
                        else {
                            return Ok(SignalSessionValidation {
                                exists: false,
                                reason: Some("no provider identity".to_owned()),
                            });
                        };
                        let identity = match normalize_signal_public_key(&identity) {
                            Ok(identity) => identity,
                            Err(err) => {
                                return Ok(SignalSessionValidation {
                                    exists: false,
                                    reason: Some(err.to_string()),
                                });
                            }
                        };
                        if identity != record.remote_identity_key {
                            return Ok(SignalSessionValidation {
                                exists: false,
                                reason: Some("provider identity mismatch".to_owned()),
                            });
                        }
                        Ok(SignalSessionValidation {
                            exists: true,
                            reason: None,
                        })
                    }
                    Err(err) => Ok(SignalSessionValidation {
                        exists: false,
                        reason: Some(err.to_string()),
                    }),
                }
            })
            .await?)
    }

    pub async fn store_session_record(&self, jid: &str, value: &[u8]) -> CoreResult<()> {
        let key = signal_protocol_address(jid)?.to_string();
        validate_provider_record_value(value)?;
        let session = Bytes::copy_from_slice(value);
        let _guard = self
            .mutation_locks
            .lock(provider_session_mutation_lock_key(&key))
            .await?;
        self.store
            .signal_transaction("store-signal-provider-session", move |tx| {
                if let Some(identity) = tx.get(KeyNamespace::SignalProviderIdentity, &key)?
                    && let Err(err) =
                        validate_decodable_provider_session_identity(&session, &identity)
                {
                    return Ok(Err(err));
                }
                tx.set(KeyNamespace::SignalProviderSession, &key, &session)?;
                Ok(Ok(()))
            })
            .await??;
        Ok(())
    }

    pub async fn encrypt_existing_session_record_message(
        &self,
        jid: &str,
        plaintext: Bytes,
    ) -> CoreResult<Option<SignalProviderSessionEncryption>> {
        let address = signal_protocol_address(jid)?.to_string();
        let _guard = self
            .mutation_locks
            .lock(provider_session_mutation_lock_key(&address))
            .await?;
        self.store
            .signal_transaction("encrypt-signal-provider-session-message", move |tx| {
                let Some(record) = tx.get(KeyNamespace::SignalProviderSession, &address)? else {
                    return Ok(Ok(None));
                };
                let decoded = match decode_signal_provider_session_record(&record) {
                    Ok(decoded) => decoded,
                    Err(_) => return Ok(Ok(None)),
                };
                match validate_provider_session_identity_in_tx(tx, &address, &decoded)? {
                    Ok(()) => {}
                    Err(CoreError::Protocol(message)) if message == "no provider identity" => {
                        return Ok(Ok(None));
                    }
                    Err(err) => return Ok(Err(err)),
                }
                let encrypted =
                    match encrypt_signal_provider_session_record_message(&record, &plaintext) {
                        Ok(encrypted) => encrypted,
                        Err(err) => return Ok(Err(err)),
                    };
                tx.set(
                    KeyNamespace::SignalProviderSession,
                    &address,
                    &encrypted.record,
                )?;
                Ok(Ok(Some(encrypted)))
            })
            .await?
    }

    pub async fn decrypt_session_record_message(
        &self,
        jid: &str,
        message: Bytes,
    ) -> CoreResult<SignalProviderSessionDecryption> {
        let address = signal_protocol_address(jid)?.to_string();
        let sender_jid = jid.to_owned();
        let _guard = self
            .mutation_locks
            .lock(provider_session_mutation_lock_key(&address))
            .await?;
        self.store
            .signal_transaction("decrypt-signal-provider-session-message", move |tx| {
                let Some(record) = tx.get(KeyNamespace::SignalProviderSession, &address)? else {
                    return Ok(Err(CoreError::Protocol(format!(
                        "missing Signal provider session for sender: {sender_jid}"
                    ))));
                };
                let decoded = match decode_signal_provider_session_record(&record) {
                    Ok(decoded) => decoded,
                    Err(err) => return Ok(Err(err)),
                };
                if let Err(err) = validate_provider_session_identity_in_tx(tx, &address, &decoded)?
                {
                    return Ok(Err(err));
                }
                let decrypted =
                    match decrypt_signal_provider_session_record_message(&record, &message) {
                        Ok(decrypted) => decrypted,
                        Err(err) => return Ok(Err(err)),
                    };
                tx.set(
                    KeyNamespace::SignalProviderSession,
                    &address,
                    &decrypted.record,
                )?;
                Ok(Ok(decrypted))
            })
            .await?
    }

    pub async fn delete_session_record(&self, jid: &str) -> CoreResult<bool> {
        let key = signal_protocol_address(jid)?.to_string();
        self.delete_record(SignalProviderRecordKind::Session, &key)
            .await
    }

    pub async fn store_session_and_identity_records(
        &self,
        jid: &str,
        session_record: &[u8],
        identity_record: &[u8],
    ) -> CoreResult<()> {
        let address = signal_protocol_address(jid)?.to_string();
        validate_provider_record_value(session_record)?;
        validate_provider_record_value(identity_record)?;
        let session = Bytes::copy_from_slice(session_record);
        let identity = Bytes::copy_from_slice(identity_record);
        let _guard = self
            .mutation_locks
            .lock(provider_session_mutation_lock_key(&address))
            .await?;
        self.store
            .signal_transaction("store-signal-provider-session-and-identity", move |tx| {
                if let Err(err) =
                    validate_provider_identity_transition_in_tx(tx, &address, &identity)?
                {
                    return Ok(Err(err));
                }
                if let Err(err) = validate_decodable_provider_session_identity(&session, &identity)
                {
                    return Ok(Err(err));
                }
                tx.set(KeyNamespace::SignalProviderSession, &address, &session)?;
                tx.set(KeyNamespace::SignalProviderIdentity, &address, &identity)?;
                Ok(Ok(()))
            })
            .await??;
        Ok(())
    }

    pub async fn store_inbound_pre_key_session_records(
        &self,
        jid: &str,
        pre_key_id: Option<u32>,
        session_record: &[u8],
        identity_record: &[u8],
    ) -> CoreResult<()> {
        let address = signal_protocol_address(jid)?.to_string();
        validate_provider_record_value(session_record)?;
        validate_provider_record_value(identity_record)?;
        let requested_pre_key_id = pre_key_id;
        let session = Bytes::copy_from_slice(session_record);
        let identity = Bytes::copy_from_slice(identity_record);
        let _guard = self
            .mutation_locks
            .lock(provider_session_mutation_lock_key(&address))
            .await?;
        let stored = self
            .store
            .signal_transaction("store-signal-inbound-pre-key-session", move |tx| {
                if let Err(err) =
                    validate_provider_identity_transition_in_tx(tx, &address, &identity)?
                {
                    return Ok(Err(err));
                }
                if let Err(err) = validate_decodable_provider_session_identity(&session, &identity)
                {
                    return Ok(Err(err));
                }
                if let Some(pre_key_id) = pre_key_id {
                    if read_optional_pre_key_from_tx(tx, pre_key_id)?.is_none() {
                        return Ok(Ok(false));
                    }
                    tx.delete(KeyNamespace::PreKey, &pre_key_id.to_string())?;
                }
                tx.set(KeyNamespace::SignalProviderSession, &address, &session)?;
                tx.set(KeyNamespace::SignalProviderIdentity, &address, &identity)?;
                Ok(Ok(true))
            })
            .await??;
        if !stored {
            let pre_key_id = requested_pre_key_id.expect("missing pre-key id should be present");
            return Err(CoreError::Protocol(format!(
                "missing local Signal one-time pre-key {pre_key_id}"
            )));
        }
        Ok(())
    }

    pub async fn load_identity_record(&self, jid: &str) -> CoreResult<Option<Bytes>> {
        let key = signal_protocol_address(jid)?.to_string();
        self.load_record(SignalProviderRecordKind::Identity, &key)
            .await
    }

    pub async fn store_identity_record(&self, jid: &str, value: &[u8]) -> CoreResult<()> {
        let key = signal_protocol_address(jid)?.to_string();
        validate_provider_record_value(value)?;
        let identity = Bytes::copy_from_slice(value);
        let _guard = self
            .mutation_locks
            .lock(provider_session_mutation_lock_key(&key))
            .await?;
        self.store
            .signal_transaction("store-signal-provider-identity", move |tx| {
                if let Err(err) = validate_provider_identity_transition_in_tx(tx, &key, &identity)?
                {
                    return Ok(Err(err));
                }
                if let Some(session) = tx.get(KeyNamespace::SignalProviderSession, &key)?
                    && let Err(err) =
                        validate_decodable_provider_session_identity(&session, &identity)
                {
                    return Ok(Err(err));
                }
                tx.set(KeyNamespace::SignalProviderIdentity, &key, &identity)?;
                Ok(Ok(()))
            })
            .await??;
        Ok(())
    }

    pub async fn delete_identity_record(&self, jid: &str) -> CoreResult<bool> {
        let key = signal_protocol_address(jid)?.to_string();
        let _guard = self
            .mutation_locks
            .lock(provider_session_mutation_lock_key(&key))
            .await?;
        self.store
            .signal_transaction("delete-signal-provider-identity", move |tx| {
                delete_provider_identity_record_in_tx(tx, &key)
            })
            .await
            .map_err(Into::into)
    }

    pub async fn load_pre_key_record(&self, key_id: u32) -> CoreResult<Option<Bytes>> {
        self.load_record(SignalProviderRecordKind::PreKey, &key_id.to_string())
            .await
    }

    pub async fn store_pre_key_record(&self, key_id: u32, value: &[u8]) -> CoreResult<()> {
        self.store_record(SignalProviderRecordKind::PreKey, &key_id.to_string(), value)
            .await
    }

    pub async fn delete_pre_key_record(&self, key_id: u32) -> CoreResult<bool> {
        self.delete_record(SignalProviderRecordKind::PreKey, &key_id.to_string())
            .await
    }

    pub async fn load_signed_pre_key_record(&self, key_id: u32) -> CoreResult<Option<Bytes>> {
        self.load_record(SignalProviderRecordKind::SignedPreKey, &key_id.to_string())
            .await
    }

    pub async fn store_signed_pre_key_record(&self, key_id: u32, value: &[u8]) -> CoreResult<()> {
        self.store_record(
            SignalProviderRecordKind::SignedPreKey,
            &key_id.to_string(),
            value,
        )
        .await
    }

    pub async fn delete_signed_pre_key_record(&self, key_id: u32) -> CoreResult<bool> {
        self.delete_record(SignalProviderRecordKind::SignedPreKey, &key_id.to_string())
            .await
    }

    pub async fn load_sender_key_record(&self, key: &str) -> CoreResult<Option<Bytes>> {
        self.load_record(SignalProviderRecordKind::SenderKey, key)
            .await
    }

    pub async fn store_sender_key_record(&self, key: &str, value: &[u8]) -> CoreResult<()> {
        let _guard = self
            .mutation_locks
            .lock(provider_sender_key_mutation_lock_key(key))
            .await?;
        self.store_record(SignalProviderRecordKind::SenderKey, key, value)
            .await
    }

    pub async fn process_sender_key_distribution_record(
        &self,
        key: &str,
        distribution: &SignalSenderKeyDistributionMessage,
    ) -> CoreResult<Bytes> {
        validate_provider_record_key(key)?;
        let key = key.to_owned();
        let distribution = distribution.clone();
        let _guard = self
            .mutation_locks
            .lock(provider_sender_key_mutation_lock_key(&key))
            .await?;
        self.store
            .signal_transaction("process-signal-sender-key-distribution", move |tx| {
                let existing = tx.get(KeyNamespace::SignalProviderSenderKey, &key)?;
                let updated = match process_signal_sender_key_distribution_record(
                    existing.as_deref(),
                    &distribution,
                ) {
                    Ok(updated) => updated,
                    Err(err) => return Ok(Err(err)),
                };
                tx.set(KeyNamespace::SignalProviderSenderKey, &key, &updated)?;
                Ok(Ok(updated))
            })
            .await?
    }

    pub async fn load_or_create_sender_key_distribution_record(
        &self,
        author_jid: &str,
        group_jid: &str,
    ) -> CoreResult<SignalSenderKeyDistributionRecord> {
        let key = sender_key_store_key(author_jid, group_jid)?;
        let _guard = self
            .mutation_locks
            .lock(provider_sender_key_mutation_lock_key(&key))
            .await?;
        self.store
            .signal_transaction("load-or-create-signal-sender-key-distribution", move |tx| {
                if let Some(record) = tx.get(KeyNamespace::SignalProviderSenderKey, &key)?
                    && let Ok(distribution) = signal_sender_key_distribution_record_from_encoded(
                        key.clone(),
                        Bytes::from(record),
                        false,
                    )
                {
                    return Ok(Ok(distribution));
                }
                let distribution = match create_signal_sender_key_distribution_record(key) {
                    Ok(distribution) => distribution,
                    Err(err) => return Ok(Err(err)),
                };
                tx.set(
                    KeyNamespace::SignalProviderSenderKey,
                    &distribution.key,
                    &distribution.record,
                )?;
                Ok(Ok(distribution))
            })
            .await?
    }

    pub async fn encrypt_sender_key_record_message(
        &self,
        key: &str,
        plaintext: &[u8],
    ) -> CoreResult<SignalSenderKeyEncryption> {
        validate_provider_record_key(key)?;
        let key = key.to_owned();
        let plaintext = Bytes::copy_from_slice(plaintext);
        let _guard = self
            .mutation_locks
            .lock(provider_sender_key_mutation_lock_key(&key))
            .await?;
        self.store
            .signal_transaction("encrypt-signal-sender-key-message", move |tx| {
                let Some(record) = tx.get(KeyNamespace::SignalProviderSenderKey, &key)? else {
                    return Ok(Err(CoreError::Protocol(
                        "missing Signal sender-key record".to_owned(),
                    )));
                };
                let encrypted = match encrypt_signal_sender_key_record_message(&record, &plaintext)
                {
                    Ok(encrypted) => encrypted,
                    Err(err) => return Ok(Err(err)),
                };
                tx.set(
                    KeyNamespace::SignalProviderSenderKey,
                    &key,
                    &encrypted.record,
                )?;
                Ok(Ok(encrypted))
            })
            .await?
    }

    pub async fn decrypt_sender_key_record_message<V>(
        &self,
        key: &str,
        message: &[u8],
        verifier: V,
    ) -> CoreResult<SignalSenderKeyDecryption>
    where
        V: NoiseCertificateVerifier + Send + 'static,
    {
        validate_provider_record_key(key)?;
        let key = key.to_owned();
        let message = Bytes::copy_from_slice(message);
        let _guard = self
            .mutation_locks
            .lock(provider_sender_key_mutation_lock_key(&key))
            .await?;
        self.store
            .signal_transaction("decrypt-signal-sender-key-message", move |tx| {
                let Some(record) = tx.get(KeyNamespace::SignalProviderSenderKey, &key)? else {
                    return Ok(Err(CoreError::Protocol(
                        "missing Signal sender-key record".to_owned(),
                    )));
                };
                let decrypted =
                    match decrypt_signal_sender_key_record_message(&record, &message, &verifier) {
                        Ok(decrypted) => decrypted,
                        Err(err) => return Ok(Err(err)),
                    };
                tx.set(
                    KeyNamespace::SignalProviderSenderKey,
                    &key,
                    &decrypted.record,
                )?;
                Ok(Ok(decrypted))
            })
            .await?
    }

    pub async fn decrypt_sender_key_record_message_with_distribution_retry<V>(
        &self,
        key: &str,
        message: &[u8],
        distribution: &SignalSenderKeyDistributionMessage,
        verifier: V,
    ) -> CoreResult<SignalSenderKeyDecryption>
    where
        V: NoiseCertificateVerifier + Send + 'static,
    {
        validate_provider_record_key(key)?;
        let key = key.to_owned();
        let message = Bytes::copy_from_slice(message);
        let distribution = distribution.clone();
        let _guard = self
            .mutation_locks
            .lock(provider_sender_key_mutation_lock_key(&key))
            .await?;
        self.store
            .signal_transaction(
                "decrypt-signal-sender-key-message-with-distribution-retry",
                move |tx| {
                    let existing = tx.get(KeyNamespace::SignalProviderSenderKey, &key)?;
                    if let Some(record) = existing.as_deref() {
                        let existing_record_is_valid =
                            decode_signal_sender_key_record(record).is_ok();
                        match decrypt_signal_sender_key_record_message(record, &message, &verifier)
                        {
                            Ok(decrypted) => {
                                tx.set(
                                    KeyNamespace::SignalProviderSenderKey,
                                    &key,
                                    &decrypted.record,
                                )?;
                                return Ok(Ok(decrypted));
                            }
                            Err(err)
                                if existing_record_is_valid
                                    && !sender_key_decrypt_error_can_retry_distribution(&err) =>
                            {
                                return Ok(Err(err));
                            }
                            Err(_) => {}
                        }
                    }
                    let updated = match process_signal_sender_key_distribution_record(
                        existing.as_deref(),
                        &distribution,
                    ) {
                        Ok(updated) => updated,
                        Err(err) => return Ok(Err(err)),
                    };
                    let decrypted = match decrypt_signal_sender_key_record_message(
                        &updated, &message, &verifier,
                    ) {
                        Ok(decrypted) => decrypted,
                        Err(err) => return Ok(Err(err)),
                    };
                    tx.set(
                        KeyNamespace::SignalProviderSenderKey,
                        &key,
                        &decrypted.record,
                    )?;
                    Ok(Ok(decrypted))
                },
            )
            .await?
    }

    pub async fn delete_sender_key_record(&self, key: &str) -> CoreResult<bool> {
        let _guard = self
            .mutation_locks
            .lock(provider_sender_key_mutation_lock_key(key))
            .await?;
        self.delete_record(SignalProviderRecordKind::SenderKey, key)
            .await
    }

    pub async fn load_sender_key_memory_record(&self, key: &str) -> CoreResult<Option<Bytes>> {
        let _guard = self
            .mutation_locks
            .lock(provider_sender_key_mutation_lock_key(key))
            .await?;
        self.load_record(SignalProviderRecordKind::SenderKeyMemory, key)
            .await
    }

    pub async fn store_sender_key_memory_record(&self, key: &str, value: &[u8]) -> CoreResult<()> {
        let _guard = self
            .mutation_locks
            .lock(provider_sender_key_mutation_lock_key(key))
            .await?;
        self.store_record(SignalProviderRecordKind::SenderKeyMemory, key, value)
            .await
    }

    pub async fn delete_sender_key_memory_record(&self, key: &str) -> CoreResult<bool> {
        let _guard = self
            .mutation_locks
            .lock(provider_sender_key_mutation_lock_key(key))
            .await?;
        self.delete_record(SignalProviderRecordKind::SenderKeyMemory, key)
            .await
    }

    pub async fn load_local_key_material(&self) -> CoreResult<Option<SignalLocalKeyMaterial>> {
        self.store
            .signal_transaction("load-signal-local-key-material", move |tx| {
                Ok(read_credentials_from_tx(tx)?.map(signal_local_key_material))
            })
            .await
            .map_err(Into::into)
    }

    pub async fn load_local_pre_key(&self, key_id: u32) -> CoreResult<Option<SignalLocalPreKey>> {
        self.store
            .signal_transaction("load-signal-local-pre-key", move |tx| {
                Ok(read_optional_pre_key_from_tx(tx, key_id)?
                    .map(|key_pair| signal_local_pre_key(key_id, key_pair)))
            })
            .await
            .map_err(Into::into)
    }

    pub async fn consume_local_pre_key(
        &self,
        key_id: u32,
    ) -> CoreResult<Option<SignalLocalPreKey>> {
        self.store
            .signal_transaction("consume-signal-local-pre-key", move |tx| {
                let Some(key_pair) = read_optional_pre_key_from_tx(tx, key_id)? else {
                    return Ok(None);
                };
                tx.delete(KeyNamespace::PreKey, &key_id.to_string())?;
                Ok(Some(signal_local_pre_key(key_id, key_pair)))
            })
            .await
            .map_err(Into::into)
    }
}

#[async_trait]
impl<S> SignalRepository for StoreSignalRepository<S>
where
    S: SignalKeyStore,
{
    async fn inject_e2e_session(&self, injection: SessionInjection) -> CoreResult<()> {
        let address = signal_protocol_address(&injection.jid)?.to_string();
        let identity_key = normalize_signal_public_key(&injection.session.identity_key)?;
        let session = SignalSession {
            identity_key: identity_key.clone(),
            ..injection.session
        };
        let encoded = encode_stored_session(&session)?;
        let _guards =
            lock_provider_session_mutations(&self.mutation_locks, [address.clone()]).await?;

        self.store
            .signal_transaction("inject-e2e-session", move |tx| {
                tx.set(KeyNamespace::IdentityKey, &address, &identity_key)?;
                tx.set(KeyNamespace::Session, &address, &encoded)?;
                tx.delete(KeyNamespace::SignalProviderSession, &address)?;
                tx.delete(KeyNamespace::SignalProviderIdentity, &address)?;
                Ok(())
            })
            .await?;
        Ok(())
    }

    async fn get_session_info(&self, jid: &str) -> CoreResult<Option<SignalSessionInfo>> {
        let address = signal_protocol_address(jid)?;
        let key = address.to_string();
        let address_for_info = address.clone();
        let _guard = self
            .mutation_locks
            .lock(provider_session_mutation_lock_key(&key))
            .await?;
        self.store
            .signal_transaction("get-session-info", move |tx| {
                let Some(session) = tx.get(KeyNamespace::Session, &key)? else {
                    return Ok(Ok(None));
                };
                let Ok(session) = decode_stored_session(&session) else {
                    return Ok(Ok(None));
                };
                let Some(identity) = tx.get(KeyNamespace::IdentityKey, &key)? else {
                    return Ok(Ok(None));
                };
                let Ok(identity) = normalize_signal_public_key(&identity) else {
                    return Ok(Ok(None));
                };
                if identity != session.identity_key {
                    return Ok(Ok(None));
                }
                let base_key = session
                    .pre_key
                    .as_ref()
                    .map(|pre_key| pre_key.public_key.clone())
                    .unwrap_or_else(|| session.signed_pre_key.public_key.clone());
                Ok(Ok(Some(SignalSessionInfo {
                    address: address_for_info,
                    base_key,
                    registration_id: session.registration_id,
                    session,
                })))
            })
            .await?
    }

    async fn validate_session(&self, jid: &str) -> CoreResult<SignalSessionValidation> {
        let address = signal_protocol_address(jid)?.to_string();
        Ok(self
            .store
            .signal_transaction("validate-session", move |tx| {
                let Some(session) = tx.get(KeyNamespace::Session, &address)? else {
                    return Ok(SignalSessionValidation {
                        exists: false,
                        reason: Some("no session".to_owned()),
                    });
                };
                let session = match decode_stored_session(&session) {
                    Ok(session) => session,
                    Err(err) => {
                        return Ok(SignalSessionValidation {
                            exists: false,
                            reason: Some(err.to_string()),
                        });
                    }
                };
                let Some(identity) = tx.get(KeyNamespace::IdentityKey, &address)? else {
                    return Ok(SignalSessionValidation {
                        exists: false,
                        reason: Some("no identity".to_owned()),
                    });
                };
                let identity = match normalize_signal_public_key(&identity) {
                    Ok(identity) => identity,
                    Err(err) => {
                        return Ok(SignalSessionValidation {
                            exists: false,
                            reason: Some(err.to_string()),
                        });
                    }
                };
                if identity != session.identity_key {
                    return Ok(SignalSessionValidation {
                        exists: false,
                        reason: Some("identity mismatch".to_owned()),
                    });
                }
                Ok(SignalSessionValidation {
                    exists: true,
                    reason: None,
                })
            })
            .await?)
    }

    async fn delete_sessions(&self, jids: &[String]) -> CoreResult<()> {
        let addresses = jids
            .iter()
            .map(|jid| signal_protocol_address(jid).map(|address| address.to_string()))
            .collect::<CoreResult<Vec<_>>>()?;
        let _guards =
            lock_provider_session_mutations(&self.mutation_locks, addresses.iter().cloned())
                .await?;
        self.store
            .signal_transaction("delete-sessions", move |tx| {
                for address in addresses {
                    tx.delete(KeyNamespace::Session, &address)?;
                    tx.delete(KeyNamespace::SignalProviderSession, &address)?;
                    tx.delete(KeyNamespace::SignalProviderIdentity, &address)?;
                }
                Ok(())
            })
            .await?;
        Ok(())
    }

    async fn migrate_session(
        &self,
        from_jid: &str,
        to_jid: &str,
    ) -> CoreResult<SignalSessionMigration> {
        let from = signal_protocol_address(from_jid)?.to_string();
        let to = signal_protocol_address(to_jid)?.to_string();
        let _guards =
            lock_provider_session_mutations(&self.mutation_locks, [from.clone(), to.clone()])
                .await?;
        let migration = self
            .store
            .signal_transaction("migrate-session", move |tx| {
                let mut migrated = 0;
                let mut skipped = 0;
                let mut total = 0;
                migrate_native_signal_records_in_tx(
                    tx,
                    &from,
                    &to,
                    &mut migrated,
                    &mut skipped,
                    &mut total,
                )?;
                migrate_signal_provider_records_in_tx(
                    tx,
                    &from,
                    &to,
                    &mut migrated,
                    &mut skipped,
                    &mut total,
                )?;
                if total == 0 {
                    return Ok(SignalSessionMigration {
                        migrated: 0,
                        skipped: 1,
                        total: 1,
                    });
                };
                Ok(SignalSessionMigration {
                    migrated,
                    skipped,
                    total,
                })
            })
            .await?;
        Ok(migration)
    }

    async fn save_identity(&self, jid: &str, identity_key: Bytes) -> CoreResult<bool> {
        let address = signal_protocol_address(jid)?.to_string();
        let identity_key = normalize_signal_public_key(&identity_key)?;
        let _guards =
            lock_provider_session_mutations(&self.mutation_locks, [address.clone()]).await?;
        let changed = self
            .store
            .signal_transaction("save-identity", move |tx| {
                save_identity_in_tx(tx, &address, &identity_key)
            })
            .await?;
        Ok(changed)
    }

    async fn store_sender_key_distribution(
        &self,
        author_jid: &str,
        group_jid: &str,
        distribution: Bytes,
    ) -> CoreResult<()> {
        if distribution.is_empty() {
            return Err(CoreError::Protocol(
                "sender-key distribution must not be empty".to_owned(),
            ));
        }
        let key = sender_key_store_key(author_jid, group_jid)?;
        let existing = self
            .store
            .get_signal_key(KeyNamespace::SenderKey, &key)
            .await?;
        if !should_replace_cached_signal_sender_key_distribution(
            existing.as_deref(),
            &distribution,
        )? {
            return Ok(());
        }
        self.store
            .set_signal_key(KeyNamespace::SenderKey, &key, &distribution)
            .await?;
        Ok(())
    }

    async fn get_sender_key_distribution(
        &self,
        author_jid: &str,
        group_jid: &str,
    ) -> CoreResult<Option<Bytes>> {
        let key = sender_key_store_key(author_jid, group_jid)?;
        Ok(self
            .store
            .get_signal_key(KeyNamespace::SenderKey, &key)
            .await?
            .map(Bytes::from))
    }

    async fn clear_sender_key_memory(&self, group_jid: &str) -> CoreResult<bool> {
        let decoded = jid_decode(group_jid).ok_or_else(|| {
            CoreError::Protocol(format!("invalid sender-key group JID: {group_jid}"))
        })?;
        if decoded.server != JidServer::GUs {
            return Err(CoreError::Protocol(format!(
                "sender-key group JID must use group server: {group_jid}"
            )));
        }
        let group_jid = group_jid.to_owned();
        let _guard = self
            .mutation_locks
            .lock(provider_sender_key_mutation_lock_key(&group_jid))
            .await?;
        let existed = self
            .store
            .signal_transaction("clear-sender-key-memory", move |tx| {
                let legacy = tx.get(KeyNamespace::SenderKeyMemory, &group_jid)?.is_some();
                let provider = tx
                    .get(KeyNamespace::SignalProviderSenderKeyMemory, &group_jid)?
                    .is_some();
                tx.delete(KeyNamespace::SenderKeyMemory, &group_jid)?;
                tx.delete(KeyNamespace::SignalProviderSenderKeyMemory, &group_jid)?;
                Ok(legacy || provider)
            })
            .await?;
        Ok(existed)
    }
}

#[async_trait]
impl<R, C> MessageEncryptor for SignalMessageCodec<R, C>
where
    R: SignalRepository,
    C: SignalCryptoProvider,
{
    async fn encrypt_message(
        &self,
        recipient_jid: &str,
        plaintext: Bytes,
    ) -> CoreResult<MessageEncryption> {
        let recipient_jid = normalize_signal_session_jid(recipient_jid)?;
        let session = if jid_decode(&recipient_jid).is_some_and(|jid| jid.server == JidServer::GUs)
        {
            None
        } else {
            self.repository.get_session_info(&recipient_jid).await?
        };
        let encrypted = self
            .provider
            .encrypt_signal_message(SignalEncryptionRequest {
                recipient_jid,
                plaintext,
                session,
            })
            .await?;
        Ok(MessageEncryption::new(
            encrypted.ciphertext_type.into(),
            encrypted.ciphertext,
        ))
    }
}

#[async_trait]
impl<R, C> InboundMessageDecryptor for SignalMessageCodec<R, C>
where
    R: SignalRepository,
    C: SignalCryptoProvider,
{
    async fn decrypt_inbound_message(&self, payload: InboundEncryptedPayload) -> CoreResult<Bytes> {
        let mut payload = payload;
        payload.sender_jid = normalize_signal_session_jid(&payload.sender_jid)?;
        let session = match payload.ciphertext_type {
            InboundCiphertextType::Message | InboundCiphertextType::PreKey => {
                self.repository
                    .get_session_info(&payload.sender_jid)
                    .await?
            }
            InboundCiphertextType::SenderKey => None,
        };
        let sender_key_distribution = if payload.ciphertext_type == InboundCiphertextType::SenderKey
        {
            self.repository
                .get_sender_key_distribution(&payload.sender_jid, &payload.chat_jid)
                .await?
        } else {
            None
        };
        self.provider
            .decrypt_signal_message(SignalDecryptionRequest {
                payload,
                session,
                sender_key_distribution,
            })
            .await
    }

    async fn process_sender_key_distribution(
        &self,
        author_jid: &str,
        message: &SenderKeyDistributionMessage,
    ) -> CoreResult<()> {
        let author_jid = normalize_signal_session_jid(author_jid)?;
        let group_jid = message.group_id.as_deref().ok_or_else(|| {
            CoreError::Protocol("sender-key distribution missing group id".to_owned())
        })?;
        let distribution = message
            .axolotl_sender_key_distribution_message
            .clone()
            .ok_or_else(|| {
                CoreError::Protocol("sender-key distribution missing payload".to_owned())
            })?;
        self.provider
            .process_sender_key_distribution(SignalSenderKeyDistribution {
                author_jid: author_jid.clone(),
                group_jid: group_jid.to_owned(),
                distribution: distribution.clone(),
            })
            .await?;
        self.repository
            .store_sender_key_distribution(&author_jid, group_jid, distribution)
            .await
    }
}

fn sender_key_store_key(author_jid: &str, group_jid: &str) -> CoreResult<String> {
    let author_jid = normalize_signal_session_jid(author_jid)?;
    validate_sender_key_jid("sender-key author JID", &author_jid)?;
    let decoded_group = jid_decode(group_jid)
        .ok_or_else(|| CoreError::Protocol(format!("invalid sender-key group JID: {group_jid}")))?;
    if decoded_group.server != JidServer::GUs {
        return Err(CoreError::Protocol(format!(
            "sender-key group JID must use group server: {group_jid}"
        )));
    }
    Ok(format!("{group_jid}|{author_jid}"))
}

async fn lock_provider_session_mutations<I>(
    locks: &SignalMutationLocks,
    addresses: I,
) -> CoreResult<Vec<SignalMutationGuard>>
where
    I: IntoIterator<Item = String>,
{
    let mut keys = addresses
        .into_iter()
        .map(|address| provider_session_mutation_lock_key(&address))
        .collect::<Vec<_>>();
    keys.sort();
    keys.dedup();

    let mut guards = Vec::with_capacity(keys.len());
    for key in keys {
        guards.push(locks.lock(key).await?);
    }
    Ok(guards)
}

fn provider_session_mutation_lock_key(address: &str) -> String {
    format!("signal-provider-session:{address}")
}

fn provider_sender_key_mutation_lock_key(key: &str) -> String {
    format!("signal-provider-sender-key:{key}")
}

fn sender_key_decrypt_error_can_retry_distribution(error: &CoreError) -> bool {
    matches!(
        error,
        CoreError::Protocol(message)
            if message == "invalid Signal sender-key message signature"
                || message.starts_with("Signal sender-key record missing state for key id ")
    ) || matches!(error, CoreError::Crypto(wa_crypto::CryptoError::Decrypt))
}

fn validate_sender_key_jid(label: &str, jid: &str) -> CoreResult<()> {
    let decoded =
        jid_decode(jid).ok_or_else(|| CoreError::Protocol(format!("invalid {label}: {jid}")))?;
    if decoded.user.is_empty() || decoded.server_raw.is_empty() {
        return Err(CoreError::Protocol(format!("invalid {label}: {jid}")));
    }
    Ok(())
}

fn normalize_signal_session_jid(jid: &str) -> CoreResult<String> {
    let decoded = jid_decode(jid)
        .ok_or_else(|| CoreError::Protocol(format!("invalid Signal session JID: {jid}")))?;
    if decoded.user.is_empty() {
        return Err(CoreError::Protocol(format!(
            "Signal session JID user must not be empty: {jid}"
        )));
    }
    if decoded.server != JidServer::CUs {
        return Ok(jid.to_owned());
    }
    Ok(jid_encode(
        decoded.user,
        JidServer::SWhatsAppNet,
        decoded.device.filter(|device| *device != 0),
        decoded.agent,
    ))
}

pub fn signal_protocol_address(jid: &str) -> CoreResult<SignalAddress> {
    let decoded = jid_decode(jid)
        .ok_or_else(|| CoreError::Protocol(format!("invalid JID for signal address: {jid}")))?;
    if decoded.user.is_empty() {
        return Err(CoreError::Protocol(
            "JID user is empty for signal address".to_owned(),
        ));
    }
    if decoded.device == Some(99)
        && decoded.server != JidServer::Hosted
        && decoded.server != JidServer::HostedLid
    {
        return Err(CoreError::Protocol(
            "device 99 is only valid for hosted JIDs".to_owned(),
        ));
    }

    let name = if decoded.domain_type == WaJidDomain::WhatsApp {
        decoded.user
    } else {
        format!("{}_{}", decoded.user, decoded.domain_type as u8)
    };

    Ok(SignalAddress {
        name,
        device_id: decoded.device.unwrap_or(0),
    })
}

pub fn normalize_signal_public_key(key: &[u8]) -> CoreResult<Bytes> {
    match key {
        value if value.len() == 32 => {
            let mut out = BytesMut::with_capacity(33);
            out.put_u8(SIGNAL_PUBLIC_KEY_VERSION);
            out.extend_from_slice(value);
            Ok(out.freeze())
        }
        value if value.len() == 33 && value[0] == SIGNAL_PUBLIC_KEY_VERSION => {
            Ok(Bytes::copy_from_slice(value))
        }
        value => Err(CoreError::Protocol(format!(
            "invalid signal public key length: {}",
            value.len()
        ))),
    }
}

pub fn encode_signal_whisper_message(message: &SignalWhisperMessage) -> CoreResult<Bytes> {
    let message = validate_signal_whisper_message(message)?;
    Ok(SignalWireWhisperMessage::from(message)
        .encode_to_vec()
        .into())
}

pub fn decode_signal_whisper_message(input: &[u8]) -> CoreResult<SignalWhisperMessage> {
    let decoded = SignalWireWhisperMessage::decode(input)
        .map_err(|err| CoreError::Protocol(format!("invalid Signal whisper message: {err}")))?;
    validate_signal_whisper_message(&decoded.try_into()?)
}

pub fn encode_signal_pre_key_whisper_message(
    message: &SignalPreKeyWhisperMessage,
) -> CoreResult<Bytes> {
    let message = validate_signal_pre_key_whisper_message(message)?;
    Ok(SignalWirePreKeyWhisperMessage::try_from(message)?
        .encode_to_vec()
        .into())
}

pub fn decode_signal_pre_key_whisper_message(
    input: &[u8],
) -> CoreResult<SignalPreKeyWhisperMessage> {
    let decoded = SignalWirePreKeyWhisperMessage::decode(input).map_err(|err| {
        CoreError::Protocol(format!("invalid Signal pre-key whisper message: {err}"))
    })?;
    validate_signal_pre_key_whisper_message(&decoded.try_into()?)
}

pub fn derive_signal_message_keys(message_key_seed: &[u8]) -> CoreResult<SignalMessageKeyMaterial> {
    if message_key_seed.len() != SIGNAL_MESSAGE_KEY_LEN {
        return Err(CoreError::Protocol(format!(
            "Signal message key seed must be {SIGNAL_MESSAGE_KEY_LEN} bytes"
        )));
    }
    let mut expanded = hkdf_sha256(
        message_key_seed,
        SIGNAL_MESSAGE_DERIVED_KEY_LEN,
        &SIGNAL_MESSAGE_KEYS_SALT,
        SIGNAL_MESSAGE_KEYS_INFO,
    )
    .map_err(CoreError::Crypto)?;
    let iv: [u8; SIGNAL_MESSAGE_IV_LEN] = expanded[64..80].try_into().map_err(|_| {
        CoreError::Protocol("derived Signal message IV has invalid length".to_owned())
    })?;
    let material = SignalMessageKeyMaterial {
        cipher_key: SecretBytes::from(expanded[0..32].to_vec()),
        mac_key: SecretBytes::from(expanded[32..64].to_vec()),
        iv,
    };
    expanded.zeroize();
    Ok(material)
}

pub fn derive_signal_message_key_seed(chain_key: &[u8]) -> CoreResult<SecretBytes> {
    validate_signal_message_chain_key(chain_key)?;
    Ok(SecretBytes::from(
        hmac_sha256(&SIGNAL_MESSAGE_KEY_SEED, chain_key).map_err(CoreError::Crypto)?,
    ))
}

pub fn advance_signal_message_chain_key(chain_key: &[u8]) -> CoreResult<SecretBytes> {
    validate_signal_message_chain_key(chain_key)?;
    Ok(SecretBytes::from(
        hmac_sha256(&SIGNAL_CHAIN_KEY_SEED, chain_key).map_err(CoreError::Crypto)?,
    ))
}

pub fn ratchet_signal_message_chain(
    chain_key: &SignalMessageChainKey,
) -> CoreResult<SignalMessageChainStep> {
    let message_counter = chain_key
        .counter
        .checked_add(1)
        .ok_or_else(|| CoreError::Protocol("Signal message chain counter overflow".to_owned()))?;
    let message_key_seed = derive_signal_message_key_seed(chain_key.key.expose())?;
    let message_keys = derive_signal_message_keys(message_key_seed.expose())?;
    let next_chain_key = SignalMessageChainKey {
        key: advance_signal_message_chain_key(chain_key.key.expose())?,
        counter: message_counter,
    };
    Ok(SignalMessageChainStep {
        message_counter,
        message_keys,
        next_chain_key,
    })
}

pub fn derive_signal_root_chain_keys(
    root_key: &[u8],
    shared_secret: &[u8],
) -> CoreResult<SignalRootRatchetStep> {
    validate_signal_root_key(root_key)?;
    validate_signal_shared_secret(shared_secret)?;
    let mut expanded = hkdf_sha256(
        shared_secret,
        SIGNAL_ROOT_DERIVED_KEY_LEN,
        root_key,
        SIGNAL_ROOT_RATCHET_INFO,
    )
    .map_err(CoreError::Crypto)?;
    let step = SignalRootRatchetStep {
        root_key: SignalRootKey {
            key: SecretBytes::from(expanded[0..32].to_vec()),
        },
        chain_key: SignalMessageChainKey {
            key: SecretBytes::from(expanded[32..64].to_vec()),
            counter: 0,
        },
    };
    expanded.zeroize();
    Ok(step)
}

pub fn ratchet_signal_root_key(
    root_key: &SignalRootKey,
    local_private_key: &[u8],
    remote_public_key: &[u8],
) -> CoreResult<SignalRootRatchetStep> {
    let local_private_key = signal_private_key_bytes(local_private_key)?;
    let remote_public_key = signal_public_key_bytes(remote_public_key)?;
    let mut shared_secret = shared_key(local_private_key, remote_public_key);
    let step = derive_signal_root_chain_keys(root_key.key.expose(), &shared_secret);
    shared_secret.zeroize();
    step
}

pub fn derive_signal_pre_key_root_chain_keys(
    pre_key_secret_input: &[u8],
) -> CoreResult<SignalRootRatchetStep> {
    validate_signal_pre_key_secret_input(pre_key_secret_input)?;
    let mut expanded = hkdf_sha256(
        pre_key_secret_input,
        SIGNAL_PRE_KEY_DERIVED_KEY_LEN,
        &[],
        SIGNAL_PRE_KEY_INFO,
    )
    .map_err(CoreError::Crypto)?;
    let step = SignalRootRatchetStep {
        root_key: SignalRootKey {
            key: SecretBytes::from(expanded[0..32].to_vec()),
        },
        chain_key: SignalMessageChainKey {
            key: SecretBytes::from(expanded[32..64].to_vec()),
            counter: 0,
        },
    };
    expanded.zeroize();
    Ok(step)
}

pub fn verify_signal_signed_pre_key<V>(
    remote_session: &SignalSession,
    verifier: &V,
) -> CoreResult<()>
where
    V: NoiseCertificateVerifier,
{
    let identity_key = signal_public_key_bytes(&remote_session.identity_key)?;
    let signed_pre_key = normalize_signal_public_key(&remote_session.signed_pre_key.public_key)?;
    if remote_session.signed_pre_key.signature.len() != 64 {
        return Err(CoreError::Protocol(format!(
            "invalid Signal signed pre-key signature length: {}",
            remote_session.signed_pre_key.signature.len()
        )));
    }
    if verifier.verify_signature(
        identity_key,
        &signed_pre_key,
        &remote_session.signed_pre_key.signature,
    ) {
        Ok(())
    } else {
        Err(CoreError::Protocol(
            "invalid Signal signed pre-key signature".to_owned(),
        ))
    }
}

pub fn derive_verified_signal_outbound_pre_key_root_chain_keys<V>(
    local_key_material: &SignalLocalKeyMaterial,
    local_base_key: &KeyPair,
    remote_session: &SignalSession,
    verifier: &V,
) -> CoreResult<SignalPreKeyBootstrap>
where
    V: NoiseCertificateVerifier,
{
    verify_signal_signed_pre_key(remote_session, verifier)?;
    derive_signal_outbound_pre_key_root_chain_keys(
        local_key_material,
        local_base_key,
        remote_session,
    )
}

pub fn derive_signal_outbound_pre_key_root_chain_keys(
    local_key_material: &SignalLocalKeyMaterial,
    local_base_key: &KeyPair,
    remote_session: &SignalSession,
) -> CoreResult<SignalPreKeyBootstrap> {
    let mut secret_input = signal_pre_key_secret_input();
    append_signal_agreement(
        &mut secret_input,
        local_key_material.identity.key_pair.private.expose(),
        &remote_session.signed_pre_key.public_key,
    )?;
    append_signal_agreement(
        &mut secret_input,
        local_base_key.private.expose(),
        &remote_session.identity_key,
    )?;
    append_signal_agreement(
        &mut secret_input,
        local_base_key.private.expose(),
        &remote_session.signed_pre_key.public_key,
    )?;
    let used_one_time_pre_key = if let Some(pre_key) = &remote_session.pre_key {
        append_signal_agreement(
            &mut secret_input,
            local_base_key.private.expose(),
            &pre_key.public_key,
        )?;
        true
    } else {
        false
    };
    let step = derive_signal_pre_key_root_chain_keys(&secret_input);
    secret_input.zeroize();
    step.map(|step| signal_pre_key_bootstrap(step, used_one_time_pre_key))
}

pub fn derive_signal_inbound_pre_key_root_chain_keys(
    local_key_material: &SignalLocalKeyMaterial,
    local_one_time_pre_key: Option<&SignalLocalPreKey>,
    remote_identity_key: &[u8],
    remote_base_key: &[u8],
) -> CoreResult<SignalPreKeyBootstrap> {
    let mut secret_input = signal_pre_key_secret_input();
    append_signal_agreement(
        &mut secret_input,
        local_key_material.signed_pre_key.key_pair.private.expose(),
        remote_identity_key,
    )?;
    append_signal_agreement(
        &mut secret_input,
        local_key_material.identity.key_pair.private.expose(),
        remote_base_key,
    )?;
    append_signal_agreement(
        &mut secret_input,
        local_key_material.signed_pre_key.key_pair.private.expose(),
        remote_base_key,
    )?;
    let used_one_time_pre_key = if let Some(pre_key) = local_one_time_pre_key {
        append_signal_agreement(
            &mut secret_input,
            pre_key.key_pair.private.expose(),
            remote_base_key,
        )?;
        true
    } else {
        false
    };
    let step = derive_signal_pre_key_root_chain_keys(&secret_input);
    secret_input.zeroize();
    step.map(|step| signal_pre_key_bootstrap(step, used_one_time_pre_key))
}

pub fn encrypt_signal_message_body(
    plaintext: &[u8],
    keys: &SignalMessageKeyMaterial,
) -> CoreResult<Bytes> {
    let mut ciphertext = aes_256_cbc_encrypt_with_iv(plaintext, keys.cipher_key.expose(), &keys.iv)
        .map_err(CoreError::Crypto)?;
    let mac = hmac_sha256(&ciphertext, keys.mac_key.expose()).map_err(CoreError::Crypto)?;
    ciphertext.extend_from_slice(&mac[..SIGNAL_MESSAGE_MAC_LEN]);
    Ok(Bytes::from(ciphertext))
}

pub fn decrypt_signal_message_body(
    ciphertext_with_mac: &[u8],
    keys: &SignalMessageKeyMaterial,
) -> CoreResult<Bytes> {
    if ciphertext_with_mac.len() <= SIGNAL_MESSAGE_MAC_LEN {
        return Err(CoreError::Crypto(
            wa_crypto::CryptoError::CiphertextTooShort,
        ));
    }
    let (ciphertext, mac) =
        ciphertext_with_mac.split_at(ciphertext_with_mac.len() - SIGNAL_MESSAGE_MAC_LEN);
    let expected_mac = hmac_sha256(ciphertext, keys.mac_key.expose()).map_err(CoreError::Crypto)?;
    if !constant_time_eq(&expected_mac[..SIGNAL_MESSAGE_MAC_LEN], mac) {
        return Err(CoreError::Crypto(wa_crypto::CryptoError::Decrypt));
    }
    Ok(Bytes::from(
        aes_256_cbc_decrypt_with_iv(ciphertext, keys.cipher_key.expose(), &keys.iv)
            .map_err(CoreError::Crypto)?,
    ))
}

pub fn derive_signal_sender_message_key_seed(chain_key: &[u8]) -> CoreResult<SecretBytes> {
    validate_signal_sender_chain_key(chain_key)?;
    Ok(SecretBytes::from(
        hmac_sha256(&SIGNAL_SENDER_MESSAGE_KEY_SEED, chain_key).map_err(CoreError::Crypto)?,
    ))
}

pub fn advance_signal_sender_chain_key(chain_key: &[u8]) -> CoreResult<SecretBytes> {
    validate_signal_sender_chain_key(chain_key)?;
    Ok(SecretBytes::from(
        hmac_sha256(&SIGNAL_SENDER_CHAIN_KEY_SEED, chain_key).map_err(CoreError::Crypto)?,
    ))
}

pub fn derive_signal_sender_message_keys(
    iteration: u32,
    message_key_seed: &[u8],
) -> CoreResult<SignalSenderMessageKeyMaterial> {
    if message_key_seed.len() != SIGNAL_MESSAGE_KEY_LEN {
        return Err(CoreError::Protocol(format!(
            "Signal sender message key seed must be {SIGNAL_MESSAGE_KEY_LEN} bytes"
        )));
    }
    let mut expanded = hkdf_sha256(
        message_key_seed,
        SIGNAL_SENDER_MESSAGE_DERIVED_KEY_LEN,
        &[],
        SIGNAL_SENDER_MESSAGE_KEYS_INFO,
    )
    .map_err(CoreError::Crypto)?;
    let iv: [u8; SIGNAL_MESSAGE_IV_LEN] = expanded[0..16].try_into().map_err(|_| {
        CoreError::Protocol("derived Signal sender message IV has invalid length".to_owned())
    })?;
    let material = SignalSenderMessageKeyMaterial {
        iteration,
        seed: SecretBytes::from(message_key_seed.to_vec()),
        cipher_key: SecretBytes::from(expanded[16..48].to_vec()),
        iv,
    };
    expanded.zeroize();
    Ok(material)
}

pub fn ratchet_signal_sender_chain(
    chain_key: &SignalSenderChainKey,
) -> CoreResult<SignalSenderChainStep> {
    let next_iteration = chain_key
        .iteration
        .checked_add(1)
        .ok_or_else(|| CoreError::Protocol("Signal sender chain iteration overflow".to_owned()))?;
    let message_key_seed = derive_signal_sender_message_key_seed(chain_key.key.expose())?;
    let message_key =
        derive_signal_sender_message_keys(chain_key.iteration, message_key_seed.expose())?;
    let next_chain_key = SignalSenderChainKey {
        key: advance_signal_sender_chain_key(chain_key.key.expose())?,
        iteration: next_iteration,
    };
    Ok(SignalSenderChainStep {
        message_key,
        next_chain_key,
    })
}

pub fn encrypt_signal_sender_message_body(
    plaintext: &[u8],
    keys: &SignalSenderMessageKeyMaterial,
) -> CoreResult<Bytes> {
    Ok(Bytes::from(
        aes_256_cbc_encrypt_with_iv(plaintext, keys.cipher_key.expose(), &keys.iv)
            .map_err(CoreError::Crypto)?,
    ))
}

pub fn decrypt_signal_sender_message_body(
    ciphertext: &[u8],
    keys: &SignalSenderMessageKeyMaterial,
) -> CoreResult<Bytes> {
    Ok(Bytes::from(
        aes_256_cbc_decrypt_with_iv(ciphertext, keys.cipher_key.expose(), &keys.iv)
            .map_err(CoreError::Crypto)?,
    ))
}

pub fn build_signal_sender_key_distribution_message(
    key_id: u32,
    iteration: u32,
    chain_key: &[u8],
    signing_public_key: &[u8],
) -> CoreResult<SignalSenderKeyDistributionMessage> {
    validate_signal_sender_chain_key(chain_key)?;
    Ok(SignalSenderKeyDistributionMessage {
        message_version: SIGNAL_WIRE_CURRENT_VERSION,
        key_id,
        iteration,
        chain_key: SecretBytes::from(chain_key.to_vec()),
        signing_key: normalize_signal_public_key(signing_public_key)?,
    })
}

pub fn encode_signal_sender_key_distribution_message(
    message: &SignalSenderKeyDistributionMessage,
) -> CoreResult<Bytes> {
    validate_signal_sender_key_distribution_message(message)?;
    let signing_key = normalize_signal_public_key(&message.signing_key)?;
    let proto = ProtoSenderKeyDistributionMessage {
        id: Some(message.key_id),
        iteration: Some(message.iteration),
        chain_key: Some(Bytes::copy_from_slice(message.chain_key.expose())),
        signing_key: Some(signing_key),
    };
    let mut out = BytesMut::with_capacity(1 + proto.encoded_len());
    out.put_u8((message.message_version << 4) | SIGNAL_WIRE_CURRENT_VERSION);
    proto.encode(&mut out).map_err(|err| {
        CoreError::Protocol(format!(
            "invalid Signal sender-key distribution message: {err}"
        ))
    })?;
    Ok(out.freeze())
}

pub fn decode_signal_sender_key_distribution_message(
    input: &[u8],
) -> CoreResult<SignalSenderKeyDistributionMessage> {
    if input.len() < 1 + SIGNAL_MESSAGE_KEY_LEN + 33 {
        return Err(CoreError::Protocol(format!(
            "Signal sender-key distribution message is too short: {}",
            input.len()
        )));
    }
    let message_version = signal_sender_key_message_version(input[0])?;
    let decoded = ProtoSenderKeyDistributionMessage::decode(&input[1..]).map_err(|err| {
        CoreError::Protocol(format!(
            "invalid Signal sender-key distribution message: {err}"
        ))
    })?;
    let chain_key = decoded.chain_key.ok_or_else(|| {
        CoreError::Protocol("Signal sender-key distribution missing chain key".to_owned())
    })?;
    validate_signal_sender_chain_key(&chain_key)?;
    let signing_key = decoded.signing_key.ok_or_else(|| {
        CoreError::Protocol("Signal sender-key distribution missing signing key".to_owned())
    })?;
    validate_signal_sender_signing_key_wire_public(&signing_key)?;
    Ok(SignalSenderKeyDistributionMessage {
        message_version,
        key_id: decoded.id.ok_or_else(|| {
            CoreError::Protocol("Signal sender-key distribution missing id".to_owned())
        })?,
        iteration: decoded.iteration.ok_or_else(|| {
            CoreError::Protocol("Signal sender-key distribution missing iteration".to_owned())
        })?,
        chain_key: SecretBytes::from(chain_key.to_vec()),
        signing_key,
    })
}

pub fn should_replace_cached_signal_sender_key_distribution(
    existing: Option<&[u8]>,
    incoming: &[u8],
) -> CoreResult<bool> {
    let incoming = decode_signal_sender_key_distribution_message(incoming)?;
    if let Some(existing) = existing
        && let Ok(existing) = decode_signal_sender_key_distribution_message(existing)
        && existing.key_id == incoming.key_id
        && existing.signing_key == incoming.signing_key
        && existing.iteration > incoming.iteration
    {
        return Ok(false);
    }
    Ok(true)
}

pub fn encode_signal_sender_key_record(record: &SignalSenderKeyRecord) -> CoreResult<Bytes> {
    validate_signal_sender_key_record(record)?;
    Ok(SenderKeyRecordStructure {
        sender_key_states: record
            .states
            .iter()
            .map(signal_sender_key_state_structure)
            .collect::<CoreResult<Vec<_>>>()?,
    }
    .encode_to_vec()
    .into())
}

pub fn decode_signal_sender_key_record(input: &[u8]) -> CoreResult<SignalSenderKeyRecord> {
    let decoded = SenderKeyRecordStructure::decode(input)
        .map_err(|err| CoreError::Protocol(format!("invalid Signal sender-key record: {err}")))?;
    let record = SignalSenderKeyRecord {
        states: decoded
            .sender_key_states
            .into_iter()
            .map(signal_sender_key_state_from_structure)
            .collect::<CoreResult<Vec<_>>>()?,
    };
    validate_signal_sender_key_record(&record)?;
    Ok(record)
}

fn create_signal_sender_key_distribution_record(
    key: String,
) -> CoreResult<SignalSenderKeyDistributionRecord> {
    let key_id = rand::random::<u32>();
    let chain_key = rand::random::<[u8; SIGNAL_MESSAGE_KEY_LEN]>();
    let signing_key = generate_key_pair();
    let distribution =
        build_signal_sender_key_distribution_message(key_id, 0, &chain_key, &signing_key.public)?;
    let record = encode_signal_sender_key_record(&SignalSenderKeyRecord {
        states: vec![SignalSenderKeyState {
            key_id,
            chain_key: SignalSenderChainKey {
                key: SecretBytes::from(chain_key.to_vec()),
                iteration: 0,
            },
            signing_public_key: distribution.signing_key.clone(),
            signing_private_key: Some(SecretBytes::from(signing_key.private.expose().to_vec())),
            message_keys: Vec::new(),
        }],
    })?;
    let distribution_bytes = encode_signal_sender_key_distribution_message(&distribution)?;
    Ok(SignalSenderKeyDistributionRecord {
        key,
        record,
        distribution,
        distribution_bytes,
        created: true,
    })
}

fn signal_sender_key_distribution_record_from_encoded(
    key: String,
    record: Bytes,
    created: bool,
) -> CoreResult<SignalSenderKeyDistributionRecord> {
    let decoded = decode_signal_sender_key_record(&record)?;
    let state = decoded
        .states
        .first()
        .ok_or_else(|| CoreError::Protocol("Signal sender-key record has no state".to_owned()))?;
    if state.signing_private_key.is_none() {
        return Err(CoreError::Protocol(
            "local Signal sender-key state missing signing private key".to_owned(),
        ));
    }
    let distribution = build_signal_sender_key_distribution_message(
        state.key_id,
        state.chain_key.iteration,
        state.chain_key.key.expose(),
        &state.signing_public_key,
    )?;
    let distribution_bytes = encode_signal_sender_key_distribution_message(&distribution)?;
    Ok(SignalSenderKeyDistributionRecord {
        key,
        record,
        distribution,
        distribution_bytes,
        created,
    })
}

pub fn apply_signal_sender_key_distribution(
    record: &mut SignalSenderKeyRecord,
    distribution: &SignalSenderKeyDistributionMessage,
) -> CoreResult<()> {
    validate_signal_sender_key_record(record)?;
    validate_signal_sender_key_distribution_message(distribution)?;
    let signing_key = normalize_signal_public_key(&distribution.signing_key)?;
    let existing = record
        .states
        .iter()
        .position(|state| {
            state.key_id == distribution.key_id
                && normalize_signal_public_key(&state.signing_public_key)
                    .map(|public_key| public_key == signing_key)
                    .unwrap_or(false)
        })
        .map(|index| record.states.remove(index));
    record
        .states
        .retain(|state| state.key_id != distribution.key_id);
    let state = match existing {
        Some(mut state) => {
            if distribution.iteration > state.chain_key.iteration {
                state.chain_key = SignalSenderChainKey {
                    key: SecretBytes::from(distribution.chain_key.expose().to_vec()),
                    iteration: distribution.iteration,
                };
            }
            state
        }
        None => SignalSenderKeyState {
            key_id: distribution.key_id,
            chain_key: SignalSenderChainKey {
                key: SecretBytes::from(distribution.chain_key.expose().to_vec()),
                iteration: distribution.iteration,
            },
            signing_public_key: signing_key,
            signing_private_key: None,
            message_keys: Vec::new(),
        },
    };
    record.states.insert(0, state);
    record.states.truncate(SIGNAL_MAX_SENDER_KEY_STATES);
    validate_signal_sender_key_record(record)
}

pub fn process_signal_sender_key_distribution_record(
    existing_record: Option<&[u8]>,
    distribution: &SignalSenderKeyDistributionMessage,
) -> CoreResult<Bytes> {
    let mut record = existing_record
        .and_then(|record| decode_signal_sender_key_record(record).ok())
        .unwrap_or_default();
    apply_signal_sender_key_distribution(&mut record, distribution)?;
    encode_signal_sender_key_record(&record)
}

pub fn encrypt_signal_sender_key_record_message(
    record: &[u8],
    plaintext: &[u8],
) -> CoreResult<SignalSenderKeyEncryption> {
    let mut record = decode_signal_sender_key_record(record)?;
    let (key_id, signing_private_key, sender_step) = {
        let state = record.states.first().ok_or_else(|| {
            CoreError::Protocol("Signal sender-key record has no state".to_owned())
        })?;
        let signing_private_key = state.signing_private_key.as_ref().ok_or_else(|| {
            CoreError::Protocol("Signal sender-key state missing signing private key".to_owned())
        })?;
        (
            state.key_id,
            SecretBytes::from(signing_private_key.expose().to_vec()),
            ratchet_signal_sender_chain(&state.chain_key)?,
        )
    };
    let ciphertext = encrypt_signal_sender_message_body(plaintext, &sender_step.message_key)?;
    let message = sign_signal_sender_key_message(
        key_id,
        sender_step.message_key.iteration,
        ciphertext,
        signing_private_key.expose(),
    )?;
    let message_bytes = encode_signal_sender_key_message(&message)?;
    record.states[0].chain_key = sender_step.next_chain_key;
    let record = encode_signal_sender_key_record(&record)?;
    Ok(SignalSenderKeyEncryption {
        record,
        message,
        message_bytes,
    })
}

pub fn decrypt_signal_sender_key_record_message<V>(
    record: &[u8],
    message: &[u8],
    verifier: &V,
) -> CoreResult<SignalSenderKeyDecryption>
where
    V: NoiseCertificateVerifier,
{
    let mut record = decode_signal_sender_key_record(record)?;
    let decoded_message = decode_signal_sender_key_message(message)?;
    let mut matching_state_seen = false;
    let mut verify_error = None;
    let mut verified = None;
    for (index, state) in record
        .states
        .iter()
        .enumerate()
        .filter(|(_, state)| state.key_id == decoded_message.key_id)
    {
        matching_state_seen = true;
        let signing_public_key = state.signing_public_key.clone();
        match verify_signal_sender_key_message_bytes(message, &signing_public_key, verifier) {
            Ok(message) => {
                verified = Some((index, message));
                break;
            }
            Err(err) => verify_error = Some(err),
        }
    }
    let (state_index, verified_message) = if let Some(verified) = verified {
        verified
    } else if matching_state_seen {
        return Err(verify_error.unwrap_or_else(|| {
            CoreError::Protocol("invalid Signal sender-key message signature".to_owned())
        }));
    } else {
        return Err(CoreError::Protocol(format!(
            "Signal sender-key record missing state for key id {}",
            decoded_message.key_id
        )));
    };
    let message_key = signal_sender_message_key_for_iteration(
        &mut record.states[state_index],
        verified_message.iteration,
    )?;
    let plaintext = decrypt_signal_sender_message_body(
        &verified_message.ciphertext,
        message_key.message_key(),
    )?;
    if let SignalSenderMessageKeyLookup::Stored { index, .. } = message_key {
        record.states[state_index].message_keys.remove(index);
    }
    let record = encode_signal_sender_key_record(&record)?;
    Ok(SignalSenderKeyDecryption {
        record,
        message: verified_message,
        plaintext,
    })
}

pub fn sign_signal_sender_key_message(
    key_id: u32,
    iteration: u32,
    ciphertext: Bytes,
    signing_private_key: &[u8],
) -> CoreResult<SignalSenderKeyMessage> {
    let message = SignalSenderKeyMessage {
        message_version: SIGNAL_WIRE_CURRENT_VERSION,
        key_id,
        iteration,
        ciphertext,
        signature: Bytes::new(),
    };
    let signed_payload = encode_signal_sender_key_message_payload(&message)?;
    let signature = sign_x25519(signing_private_key, &signed_payload).map_err(CoreError::Crypto)?;
    Ok(SignalSenderKeyMessage {
        signature: Bytes::copy_from_slice(&signature),
        ..message
    })
}

pub fn encode_signal_sender_key_message(message: &SignalSenderKeyMessage) -> CoreResult<Bytes> {
    validate_signal_sender_key_message(message)?;
    let signed_payload = encode_signal_sender_key_message_payload(message)?;
    let mut out = BytesMut::with_capacity(signed_payload.len() + SIGNAL_SENDER_KEY_SIGNATURE_LEN);
    out.extend_from_slice(&signed_payload);
    out.extend_from_slice(&message.signature);
    Ok(out.freeze())
}

pub fn decode_signal_sender_key_message(input: &[u8]) -> CoreResult<SignalSenderKeyMessage> {
    if input.len() <= SIGNAL_SENDER_KEY_SIGNATURE_LEN {
        return Err(CoreError::Protocol(format!(
            "Signal sender-key message is too short: {}",
            input.len()
        )));
    }
    let message_version = signal_sender_key_message_version(input[0])?;
    let proto_end = input.len() - SIGNAL_SENDER_KEY_SIGNATURE_LEN;
    let decoded = ProtoSenderKeyMessage::decode(&input[1..proto_end])
        .map_err(|err| CoreError::Protocol(format!("invalid Signal sender-key message: {err}")))?;
    let message = SignalSenderKeyMessage {
        message_version,
        key_id: decoded.id.ok_or_else(|| {
            CoreError::Protocol("Signal sender-key message missing id".to_owned())
        })?,
        iteration: decoded.iteration.ok_or_else(|| {
            CoreError::Protocol("Signal sender-key message missing iteration".to_owned())
        })?,
        ciphertext: decoded.ciphertext.ok_or_else(|| {
            CoreError::Protocol("Signal sender-key message missing ciphertext".to_owned())
        })?,
        signature: Bytes::copy_from_slice(&input[proto_end..]),
    };
    validate_signal_sender_key_message(&message)?;
    Ok(message)
}

pub fn verify_signal_sender_key_message<V>(
    message: &SignalSenderKeyMessage,
    signing_public_key: &[u8],
    verifier: &V,
) -> CoreResult<()>
where
    V: NoiseCertificateVerifier,
{
    validate_signal_sender_key_message(message)?;
    let signing_public_key = signal_public_key_bytes(signing_public_key)?;
    let signed_payload = encode_signal_sender_key_message_payload(message)?;
    verify_signal_sender_key_signature(
        signing_public_key,
        &signed_payload,
        &message.signature,
        verifier,
    )
}

pub fn verify_signal_sender_key_message_bytes<V>(
    input: &[u8],
    signing_public_key: &[u8],
    verifier: &V,
) -> CoreResult<SignalSenderKeyMessage>
where
    V: NoiseCertificateVerifier,
{
    let message = decode_signal_sender_key_message(input)?;
    verify_signal_sender_key_message(&message, signing_public_key, verifier)?;
    Ok(message)
}

pub fn parse_e2e_sessions_node(node: &BinaryNode) -> CoreResult<Vec<SessionInjection>> {
    if let Some(error) = e2e_session_error_from_result(node) {
        return Err(error);
    }

    let list = child_node(node, "list")
        .ok_or_else(|| CoreError::Protocol("missing E2E session list node".to_owned()))?;
    let Some(BinaryNodeContent::Nodes(users)) = &list.content else {
        return Err(CoreError::Protocol(
            "E2E session list has no user nodes".to_owned(),
        ));
    };

    let mut out = Vec::with_capacity(users.len());
    for user in users.iter().filter(|node| node.tag == "user") {
        let jid = user
            .attrs
            .get("jid")
            .cloned()
            .ok_or_else(|| CoreError::Protocol("E2E session user missing jid".to_owned()))?;
        let session = SignalSession {
            registration_id: child_u32(user, "registration", 4)?,
            identity_key: normalize_signal_public_key(&child_bytes(user, "identity")?)?,
            signed_pre_key: parse_signed_pre_key(child_node(user, "skey").ok_or_else(|| {
                CoreError::Protocol("E2E session user missing signed pre-key".to_owned())
            })?)?,
            pre_key: Some(parse_pre_key(child_node(user, "key").ok_or_else(
                || CoreError::Protocol("E2E session user missing pre-key".to_owned()),
            )?)?),
        };
        out.push(SessionInjection { jid, session });
    }

    Ok(out)
}

pub fn retry_receipt_session_injection(
    receipt: &BinaryNode,
    participant_jid: &str,
) -> CoreResult<Option<SessionInjection>> {
    Ok(retry_receipt_session_bundle(receipt, participant_jid)?.map(|bundle| bundle.session))
}

pub fn retry_receipt_session_bundle(
    receipt: &BinaryNode,
    participant_jid: &str,
) -> CoreResult<Option<RetryReceiptSessionBundle>> {
    if jid_decode(participant_jid).is_none() {
        return Err(CoreError::Protocol(format!(
            "invalid retry session participant JID: {participant_jid}"
        )));
    }
    let Some(keys) = child_node(receipt, "keys") else {
        return Ok(None);
    };
    let Ok(key_type) = child_bytes(keys, "type") else {
        return Ok(None);
    };
    if key_type.as_ref() != KEY_BUNDLE_TYPE {
        return Ok(None);
    }

    let Ok(registration_id) = child_u32(receipt, "registration", 4) else {
        return Ok(None);
    };
    let Ok(identity_key) =
        child_bytes(keys, "identity").and_then(|bytes| normalize_signal_public_key(&bytes))
    else {
        return Ok(None);
    };
    let Some(skey) = child_node(keys, "skey") else {
        return Ok(None);
    };
    let Ok(signed_pre_key) = parse_signed_pre_key(skey) else {
        return Ok(None);
    };
    let pre_key = match child_node(keys, "key") {
        Some(node) => match parse_pre_key(node) {
            Ok(pre_key) => Some(pre_key),
            Err(_) => return Ok(None),
        },
        None => None,
    };
    let device_identity = match child_node(keys, "device-identity") {
        Some(node) => match node_bytes(node) {
            Ok(bytes) if !bytes.is_empty() => Some(bytes),
            _ => None,
        },
        None => None,
    };

    Ok(Some(RetryReceiptSessionBundle {
        session: SessionInjection {
            jid: participant_jid.to_owned(),
            session: SignalSession {
                registration_id,
                identity_key,
                signed_pre_key,
                pre_key,
            },
        },
        device_identity,
    }))
}

fn e2e_session_error_from_result(node: &BinaryNode) -> Option<CoreError> {
    let error_node = child_node(node, "error");
    if node.attrs.get("type").is_none_or(|value| value != "error") && error_node.is_none() {
        return None;
    }
    let code = error_node
        .and_then(|error| error.attrs.get("code"))
        .or_else(|| node.attrs.get("code"))
        .or_else(|| node.attrs.get("error"))
        .map(String::as_str)
        .unwrap_or("500");
    let text = error_node
        .and_then(|error| error.attrs.get("text"))
        .or_else(|| node.attrs.get("text"))
        .or_else(|| node.attrs.get("reason"))
        .map(String::as_str)
        .unwrap_or("E2E session query failed");
    Some(CoreError::Protocol(format!(
        "E2E session query failed ({code}): {text}"
    )))
}

pub fn build_e2e_session_query<I, T>(
    jids: I,
    force_identity_refresh: bool,
    tag: impl Into<String>,
) -> CoreResult<Option<BinaryNode>>
where
    I: IntoIterator<Item = T>,
    T: AsRef<str>,
{
    let mut unique = Vec::<String>::new();
    for jid in jids {
        let jid = jid.as_ref();
        if jid_decode(jid).is_none() {
            return Err(CoreError::Protocol(format!(
                "invalid JID for E2E session query: {jid}"
            )));
        }
        if !unique.iter().any(|existing| existing == jid) {
            unique.push(jid.to_owned());
        }
    }

    if unique.is_empty() {
        return Ok(None);
    }

    let users = unique
        .into_iter()
        .map(|jid| {
            let mut node = BinaryNode::new("user").with_attr("jid", jid);
            if force_identity_refresh {
                node = node.with_attr("reason", "identity");
            }
            node
        })
        .collect::<Vec<_>>();

    Ok(Some(
        BinaryNode::new("iq")
            .with_attr("id", tag)
            .with_attr("xmlns", "encrypt")
            .with_attr("type", "get")
            .with_attr("to", SERVER_JID)
            .with_content(vec![BinaryNode::new("key").with_content(users)]),
    ))
}

pub fn is_lid_signal_jid(jid: &str) -> CoreResult<bool> {
    let decoded = jid_decode(jid)
        .ok_or_else(|| CoreError::Protocol(format!("invalid JID for LID check: {jid}")))?;
    Ok(matches!(
        decoded.domain_type,
        WaJidDomain::Lid | WaJidDomain::HostedLid
    ))
}

pub fn mapped_lid_session_jid(pn_jid: &str, lid_user: &str) -> CoreResult<String> {
    let decoded = jid_decode(pn_jid)
        .ok_or_else(|| CoreError::Protocol(format!("invalid PN JID for LID mapping: {pn_jid}")))?;
    if lid_user.is_empty() {
        return Err(CoreError::Protocol(
            "mapped LID user must not be empty".to_owned(),
        ));
    }
    let server = if matches!(
        decoded.domain_type,
        WaJidDomain::Hosted | WaJidDomain::HostedLid
    ) || decoded.server == JidServer::Hosted
    {
        JidServer::HostedLid
    } else {
        JidServer::Lid
    };
    Ok(jid_encode(
        lid_user,
        server,
        decoded.device.filter(|device| *device != 0),
        None,
    ))
}

#[derive(Clone)]
pub struct LidPnMappingStore<S> {
    store: S,
}

impl<S> LidPnMappingStore<S> {
    #[must_use]
    pub fn new(store: S) -> Self {
        Self { store }
    }
}

impl<S> LidPnMappingStore<S>
where
    S: SignalKeyStore,
{
    pub async fn store_mappings(&self, mappings: Vec<LidPnMapping>) -> CoreResult<()> {
        let pairs = mappings
            .into_iter()
            .map(|mapping| {
                let pn_user = jid_decode(&mapping.pn)
                    .ok_or_else(|| CoreError::Protocol("invalid PN mapping JID".to_owned()))?
                    .user;
                let lid_user = jid_decode(&mapping.lid)
                    .ok_or_else(|| CoreError::Protocol("invalid LID mapping JID".to_owned()))?
                    .user;
                Ok((pn_user, lid_user))
            })
            .collect::<CoreResult<Vec<_>>>()?;

        self.store
            .signal_transaction("store-lid-pn-mappings", move |tx| {
                for (pn_user, lid_user) in pairs {
                    tx.set(
                        KeyNamespace::LidMapping,
                        &format!("pn:{pn_user}"),
                        lid_user.as_bytes(),
                    )?;
                    tx.set(
                        KeyNamespace::LidMapping,
                        &format!("lid:{lid_user}"),
                        pn_user.as_bytes(),
                    )?;
                }
                Ok(())
            })
            .await?;
        Ok(())
    }

    pub async fn lid_for_pn(&self, pn: &str) -> CoreResult<Option<String>> {
        let decoded = jid_decode(pn)
            .ok_or_else(|| CoreError::Protocol("invalid PN lookup JID".to_owned()))?;
        read_mapping(&self.store, &format!("pn:{}", decoded.user)).await
    }

    pub async fn pn_for_lid(&self, lid: &str) -> CoreResult<Option<String>> {
        let decoded = jid_decode(lid)
            .ok_or_else(|| CoreError::Protocol("invalid LID lookup JID".to_owned()))?;
        read_mapping(&self.store, &format!("lid:{}", decoded.user)).await
    }
}

fn encode_stored_session(session: &SignalSession) -> CoreResult<Bytes> {
    let identity_key = normalize_signal_public_key(&session.identity_key)?;
    let signed_public = normalize_signal_public_key(&session.signed_pre_key.public_key)?;
    if session.signed_pre_key.signature.len() != 64 {
        return Err(CoreError::Protocol(format!(
            "invalid signed pre-key signature length: {}",
            session.signed_pre_key.signature.len()
        )));
    }

    let mut out = BytesMut::with_capacity(160);
    out.put_u8(STORED_SESSION_VERSION);
    out.put_u8(SESSION_RECORD_KIND);
    out.put_u32(session.registration_id);
    put_bytes(&mut out, &identity_key)?;
    out.put_u32(session.signed_pre_key.key_id);
    put_bytes(&mut out, &signed_public)?;
    put_bytes(&mut out, &session.signed_pre_key.signature)?;
    if let Some(pre_key) = &session.pre_key {
        out.put_u8(1);
        out.put_u32(pre_key.key_id);
        put_bytes(&mut out, &normalize_signal_public_key(&pre_key.public_key)?)?;
    } else {
        out.put_u8(0);
    }
    Ok(out.freeze())
}

fn decode_stored_session(input: &[u8]) -> CoreResult<SignalSession> {
    let mut input = input;
    if input.remaining() < 2 {
        return Err(CoreError::Protocol(
            "stored signal session is truncated".to_owned(),
        ));
    }
    let version = input.get_u8();
    let kind = input.get_u8();
    if version != STORED_SESSION_VERSION || kind != SESSION_RECORD_KIND {
        return Err(CoreError::Protocol(
            "unsupported stored signal session version".to_owned(),
        ));
    }
    if input.remaining() < 4 {
        return Err(CoreError::Protocol(
            "stored signal session missing registration id".to_owned(),
        ));
    }
    let registration_id = input.get_u32();
    let identity_key = normalize_signal_public_key(&take_stored_signal_session_bytes(
        &mut input,
        "identity key",
    )?)?;
    let signed_key_id = take_stored_signal_session_u32(&mut input, "signed pre-key id")?;
    let signed_public = normalize_signal_public_key(&take_stored_signal_session_bytes(
        &mut input,
        "signed pre-key public key",
    )?)?;
    let signature = take_stored_signal_session_bytes(&mut input, "signed pre-key signature")?;
    if signature.len() != 64 {
        return Err(CoreError::Protocol(format!(
            "invalid stored signed pre-key signature length: {}",
            signature.len()
        )));
    }
    if input.remaining() < 1 {
        return Err(CoreError::Protocol(
            "stored signal session missing pre-key flag".to_owned(),
        ));
    }
    let pre_key = match input.get_u8() {
        0 => None,
        1 => Some(SignalPreKey {
            key_id: take_stored_signal_session_u32(&mut input, "pre-key id")?,
            public_key: normalize_signal_public_key(&take_stored_signal_session_bytes(
                &mut input,
                "pre-key public key",
            )?)?,
        }),
        _ => {
            return Err(CoreError::Protocol(
                "invalid stored signal session pre-key flag".to_owned(),
            ));
        }
    };
    if input.has_remaining() {
        return Err(CoreError::Protocol(
            "stored signal session has trailing bytes".to_owned(),
        ));
    }

    Ok(SignalSession {
        registration_id,
        identity_key,
        signed_pre_key: SignalSignedPreKey {
            key_id: signed_key_id,
            public_key: signed_public,
            signature,
        },
        pre_key,
    })
}

pub fn encode_signal_provider_session_record(
    record: &SignalProviderSessionRecord,
) -> CoreResult<Bytes> {
    validate_signal_provider_session_record(record)?;
    let mut out = BytesMut::with_capacity(180);
    out.put_u8(PROVIDER_SESSION_VERSION);
    out.put_u8(PROVIDER_SESSION_RECORD_KIND);
    out.put_u32(record.remote_registration_id);
    put_bytes(
        &mut out,
        &normalize_signal_public_key(&record.remote_identity_key)?,
    )?;
    put_bytes(&mut out, record.root_key.key.expose())?;
    out.put_u32(record.sending_chain.counter);
    put_bytes(&mut out, record.sending_chain.key.expose())?;
    put_bytes(
        &mut out,
        &prefixed_signal_public_key(&record.local_ratchet_key_pair.public),
    )?;
    put_bytes(&mut out, record.local_ratchet_key_pair.private.expose())?;
    out.put_u32(record.previous_counter);
    match &record.receiving_chain {
        Some(chain) => {
            out.put_u8(1);
            out.put_u32(chain.counter);
            put_bytes(&mut out, chain.key.expose())?;
        }
        None => out.put_u8(0),
    }
    match &record.remote_ratchet_key {
        Some(key) => {
            out.put_u8(1);
            put_bytes(&mut out, &normalize_signal_public_key(key)?)?;
        }
        None => out.put_u8(0),
    }
    out.put_u32(u32::try_from(record.message_keys.len()).map_err(|_| {
        CoreError::Protocol("too many Signal provider skipped message keys".to_owned())
    })?);
    for message_key in &record.message_keys {
        put_bytes(
            &mut out,
            &normalize_signal_public_key(&message_key.ratchet_key)?,
        )?;
        out.put_u32(message_key.counter);
        put_bytes(&mut out, message_key.message_keys.cipher_key.expose())?;
        put_bytes(&mut out, message_key.message_keys.mac_key.expose())?;
        put_bytes(&mut out, &message_key.message_keys.iv)?;
    }
    Ok(out.freeze())
}

pub fn decode_signal_provider_session_record(
    input: &[u8],
) -> CoreResult<SignalProviderSessionRecord> {
    let mut input = input;
    if input.remaining() < 2 {
        return Err(CoreError::Protocol(
            "stored Signal provider session is truncated".to_owned(),
        ));
    }
    let version = input.get_u8();
    let kind = input.get_u8();
    if version != PROVIDER_SESSION_VERSION || kind != PROVIDER_SESSION_RECORD_KIND {
        return Err(CoreError::Protocol(
            "unsupported Signal provider session version".to_owned(),
        ));
    }
    if input.remaining() < 4 {
        return Err(CoreError::Protocol(
            "stored Signal provider session missing registration id".to_owned(),
        ));
    }
    let remote_registration_id = input.get_u32();
    let remote_identity_key = normalize_signal_public_key(&take_signal_provider_session_bytes(
        &mut input,
        "remote identity key",
    )?)?;
    let root_key = take_signal_provider_session_bytes(&mut input, "root key")?;
    validate_signal_root_key(&root_key)?;
    let sending_counter = take_signal_provider_session_u32(&mut input, "sending counter")?;
    let sending_chain_key = take_signal_provider_session_bytes(&mut input, "sending chain key")?;
    validate_signal_message_chain_key(&sending_chain_key)?;
    let local_public_key = normalize_signal_public_key(&take_signal_provider_session_bytes(
        &mut input,
        "local ratchet public key",
    )?)?;
    let local_private_key =
        take_signal_provider_session_bytes(&mut input, "local ratchet private key")?;
    let local_private_key = *signal_private_key_bytes(&local_private_key)?;
    let previous_counter = take_signal_provider_session_u32(&mut input, "previous counter")?;
    let has_optional_section = input.remaining() > 0;
    let (receiving_chain, remote_ratchet_key) = if has_optional_section {
        let receiving_chain =
            match take_signal_provider_session_flag(&mut input, "receiving-chain")? {
                0 => None,
                1 => {
                    let counter =
                        take_signal_provider_session_u32(&mut input, "receiving-chain counter")?;
                    let key =
                        take_signal_provider_session_bytes(&mut input, "receiving-chain key")?;
                    validate_signal_message_chain_key(&key)?;
                    Some(SignalMessageChainKey {
                        key: SecretBytes::from(key.to_vec()),
                        counter,
                    })
                }
                _ => {
                    return Err(CoreError::Protocol(
                        "stored Signal provider session has invalid receiving-chain flag"
                            .to_owned(),
                    ));
                }
            };
        let remote_ratchet_key =
            match take_signal_provider_session_flag(&mut input, "remote-ratchet")? {
                0 => None,
                1 => Some(normalize_signal_public_key(
                    &take_signal_provider_session_bytes(&mut input, "remote ratchet key")?,
                )?),
                _ => {
                    return Err(CoreError::Protocol(
                        "stored Signal provider session has invalid remote-ratchet flag".to_owned(),
                    ));
                }
            };
        (receiving_chain, remote_ratchet_key)
    } else {
        (None, None)
    };
    let message_keys = if has_optional_section {
        if input.remaining() < 4 {
            return Err(CoreError::Protocol(
                "stored Signal provider session missing skipped-key count".to_owned(),
            ));
        }
        let count = usize::try_from(take_signal_provider_session_u32(
            &mut input,
            "skipped-key count",
        )?)
        .map_err(|_| CoreError::Protocol("invalid Signal provider skipped key count".to_owned()))?;
        if count > SIGNAL_MAX_PROVIDER_MESSAGE_KEYS {
            return Err(CoreError::Protocol(format!(
                "Signal provider session must contain at most {SIGNAL_MAX_PROVIDER_MESSAGE_KEYS} skipped message keys"
            )));
        }
        let mut message_keys = Vec::with_capacity(count);
        for _ in 0..count {
            let ratchet_key = normalize_signal_public_key(&take_signal_provider_session_bytes(
                &mut input,
                "skipped message ratchet key",
            )?)?;
            let counter = take_signal_provider_session_u32(&mut input, "skipped message counter")?;
            let cipher_key =
                take_signal_provider_session_bytes(&mut input, "skipped message cipher key")?;
            validate_signal_message_chain_key(&cipher_key)?;
            let mac_key =
                take_signal_provider_session_bytes(&mut input, "skipped message mac key")?;
            validate_signal_message_chain_key(&mac_key)?;
            let iv = take_signal_provider_session_bytes(&mut input, "skipped message iv")?;
            if iv.len() != SIGNAL_MESSAGE_IV_LEN {
                return Err(CoreError::Protocol(format!(
                    "Signal provider skipped message IV must be {SIGNAL_MESSAGE_IV_LEN} bytes"
                )));
            }
            let mut iv_array = [0u8; SIGNAL_MESSAGE_IV_LEN];
            iv_array.copy_from_slice(&iv);
            message_keys.push(SignalProviderStoredMessageKey {
                ratchet_key,
                counter,
                message_keys: SignalMessageKeyMaterial {
                    cipher_key: SecretBytes::from(cipher_key.to_vec()),
                    mac_key: SecretBytes::from(mac_key.to_vec()),
                    iv: iv_array,
                },
            });
        }
        message_keys
    } else {
        Vec::new()
    };
    if input.has_remaining() {
        return Err(CoreError::Protocol(
            "stored Signal provider session has trailing bytes".to_owned(),
        ));
    }
    let local_public = *signal_public_key_bytes(&local_public_key)?;
    let record = SignalProviderSessionRecord {
        remote_registration_id,
        remote_identity_key,
        root_key: SignalRootKey {
            key: SecretBytes::from(root_key.to_vec()),
        },
        sending_chain: SignalMessageChainKey {
            key: SecretBytes::from(sending_chain_key.to_vec()),
            counter: sending_counter,
        },
        receiving_chain,
        remote_ratchet_key,
        local_ratchet_key_pair: KeyPair {
            public: local_public,
            private: SecretBytes::from(local_private_key.to_vec()),
        },
        previous_counter,
        message_keys,
    };
    validate_signal_provider_session_record(&record)?;
    Ok(record)
}

pub fn encrypt_signal_provider_session_record_message(
    record: &[u8],
    plaintext: &[u8],
) -> CoreResult<SignalProviderSessionEncryption> {
    let mut record = decode_signal_provider_session_record(record)?;
    let (message, message_bytes) =
        encrypt_signal_provider_session_record_plaintext(&mut record, plaintext)?;
    let record = encode_signal_provider_session_record(&record)?;
    Ok(SignalProviderSessionEncryption {
        record,
        message,
        message_bytes,
    })
}

pub fn decrypt_signal_provider_session_record_message(
    record: &[u8],
    message: &[u8],
) -> CoreResult<SignalProviderSessionDecryption> {
    let mut record = decode_signal_provider_session_record(record)?;
    let message = decode_signal_whisper_message(message)?;
    let plaintext = decrypt_signal_provider_session_record_ciphertext(&mut record, &message)?;
    let record = encode_signal_provider_session_record(&record)?;
    Ok(SignalProviderSessionDecryption {
        record,
        message,
        plaintext,
    })
}

pub fn encrypt_signal_outbound_pre_key_session_message<V>(
    local_key_material: &SignalLocalKeyMaterial,
    local_base_key: &KeyPair,
    remote_session: &SignalSession,
    verifier: &V,
    plaintext: &[u8],
) -> CoreResult<SignalProviderPreKeySessionEncryption>
where
    V: NoiseCertificateVerifier,
{
    let bootstrap = derive_verified_signal_outbound_pre_key_root_chain_keys(
        local_key_material,
        local_base_key,
        remote_session,
        verifier,
    )?;
    let mut record = SignalProviderSessionRecord {
        remote_registration_id: remote_session.registration_id,
        remote_identity_key: normalize_signal_public_key(&remote_session.identity_key)?,
        root_key: bootstrap.root_key,
        sending_chain: bootstrap.chain_key,
        receiving_chain: None,
        remote_ratchet_key: None,
        local_ratchet_key_pair: local_base_key.clone(),
        previous_counter: 0,
        message_keys: Vec::new(),
    };
    let (message, _) = encrypt_signal_provider_session_record_plaintext(&mut record, plaintext)?;
    let pre_key_message = SignalPreKeyWhisperMessage {
        registration_id: local_key_material.registration_id,
        pre_key_id: remote_session
            .pre_key
            .as_ref()
            .map(|pre_key| pre_key.key_id),
        signed_pre_key_id: remote_session.signed_pre_key.key_id,
        base_key: Bytes::copy_from_slice(&prefixed_signal_public_key(&local_base_key.public)),
        identity_key: local_key_material.identity.public_key.clone(),
        message,
    };
    let message_bytes = encode_signal_pre_key_whisper_message(&pre_key_message)?;
    let record = encode_signal_provider_session_record(&record)?;
    Ok(SignalProviderPreKeySessionEncryption {
        record,
        message: pre_key_message,
        message_bytes,
        used_one_time_pre_key: bootstrap.used_one_time_pre_key,
    })
}

pub fn decrypt_signal_inbound_pre_key_session_message(
    local_key_material: &SignalLocalKeyMaterial,
    local_one_time_pre_key: Option<&SignalLocalPreKey>,
    message: &[u8],
) -> CoreResult<SignalProviderPreKeySessionDecryption> {
    let message = decode_signal_pre_key_whisper_message(message)?;
    decrypt_signal_inbound_pre_key_session_decoded(
        local_key_material,
        local_one_time_pre_key,
        message,
    )
}

fn decrypt_signal_inbound_pre_key_session_decoded(
    local_key_material: &SignalLocalKeyMaterial,
    local_one_time_pre_key: Option<&SignalLocalPreKey>,
    message: SignalPreKeyWhisperMessage,
) -> CoreResult<SignalProviderPreKeySessionDecryption> {
    let base_key = normalize_signal_public_key(&message.base_key)?;
    let inner_ephemeral_key = normalize_signal_public_key(&message.message.ephemeral_key)?;
    if inner_ephemeral_key != base_key {
        return Err(CoreError::Protocol(
            "Signal pre-key message base key does not match inner ratchet key".to_owned(),
        ));
    }
    if message.pre_key_id.is_some() != local_one_time_pre_key.is_some() {
        return Err(CoreError::Protocol(
            "Signal pre-key message one-time pre-key state mismatch".to_owned(),
        ));
    }
    if let (Some(message_pre_key_id), Some(local_pre_key)) =
        (message.pre_key_id, local_one_time_pre_key)
        && message_pre_key_id != local_pre_key.key_id
    {
        return Err(CoreError::Protocol(format!(
            "Signal pre-key id mismatch: message {message_pre_key_id}, local {}",
            local_pre_key.key_id
        )));
    }
    if message.signed_pre_key_id != local_key_material.signed_pre_key.key_id {
        return Err(CoreError::Protocol(format!(
            "Signal signed pre-key id mismatch: message {}, local {}",
            message.signed_pre_key_id, local_key_material.signed_pre_key.key_id
        )));
    }

    let bootstrap = derive_signal_inbound_pre_key_root_chain_keys(
        local_key_material,
        local_one_time_pre_key,
        &message.identity_key,
        &base_key,
    )?;
    let mut record = SignalProviderSessionRecord {
        remote_registration_id: message.registration_id,
        remote_identity_key: normalize_signal_public_key(&message.identity_key)?,
        root_key: bootstrap.root_key,
        sending_chain: uninitialized_signal_message_chain(),
        receiving_chain: Some(bootstrap.chain_key),
        remote_ratchet_key: Some(base_key),
        local_ratchet_key_pair: local_key_material.signed_pre_key.key_pair.clone(),
        previous_counter: 0,
        message_keys: Vec::new(),
    };
    let plaintext =
        decrypt_signal_provider_session_record_ciphertext(&mut record, &message.message)?;
    let record = encode_signal_provider_session_record(&record)?;
    Ok(SignalProviderPreKeySessionDecryption {
        record,
        message,
        plaintext,
        used_one_time_pre_key: bootstrap.used_one_time_pre_key,
    })
}

fn encrypt_signal_provider_session_record_plaintext(
    record: &mut SignalProviderSessionRecord,
    plaintext: &[u8],
) -> CoreResult<(SignalWhisperMessage, Bytes)> {
    validate_signal_provider_session_record(record)?;
    ensure_signal_provider_sending_chain(record)?;
    let step = ratchet_signal_message_chain(&record.sending_chain)?;
    let ciphertext = encrypt_signal_message_body(plaintext, &step.message_keys)?;
    let message = SignalWhisperMessage {
        ephemeral_key: Bytes::copy_from_slice(&prefixed_signal_public_key(
            &record.local_ratchet_key_pair.public,
        )),
        counter: step.message_counter,
        previous_counter: record.previous_counter,
        ciphertext,
    };
    let message_bytes = encode_signal_whisper_message(&message)?;
    record.sending_chain = step.next_chain_key;
    Ok((message, message_bytes))
}

fn decrypt_signal_provider_session_record_ciphertext(
    record: &mut SignalProviderSessionRecord,
    message: &SignalWhisperMessage,
) -> CoreResult<Bytes> {
    validate_signal_provider_session_record(record)?;
    let message_ratchet_key = normalize_signal_public_key(&message.ephemeral_key)?;
    if let Some(index) = find_signal_provider_stored_message_key_index(
        &record.message_keys,
        &message_ratchet_key,
        message.counter,
    ) {
        let plaintext = decrypt_signal_message_body(
            &message.ciphertext,
            &record.message_keys[index].message_keys,
        )?;
        record.message_keys.remove(index);
        return Ok(plaintext);
    }
    if record.remote_ratchet_key.as_ref() != Some(&message_ratchet_key)
        || record.receiving_chain.is_none()
    {
        if record.remote_ratchet_key.as_ref() != Some(&message_ratchet_key)
            && let Some(oldest_previous_chain_counter) = record
                .message_keys
                .iter()
                .filter(|message_key| message_key.ratchet_key == message_ratchet_key)
                .map(|message_key| message_key.counter)
                .min()
            && message.counter < oldest_previous_chain_counter
        {
            return Err(CoreError::Protocol(format!(
                "Signal previous chain counter moved backwards: message {}, current {}",
                message.counter, oldest_previous_chain_counter
            )));
        }
        if let (Some(previous_ratchet_key), Some(receiving_chain)) = (
            record.remote_ratchet_key.clone(),
            record.receiving_chain.as_mut(),
        ) {
            skip_signal_provider_message_keys_until(
                &mut record.message_keys,
                &previous_ratchet_key,
                receiving_chain,
                message.previous_counter,
            )?;
        }
        record.previous_counter = record.sending_chain.counter;
        let step = ratchet_signal_root_key(
            &record.root_key,
            record.local_ratchet_key_pair.private.expose(),
            &message_ratchet_key,
        )?;
        record.root_key = step.root_key;
        record.receiving_chain = Some(step.chain_key);
        record.remote_ratchet_key = Some(message_ratchet_key.clone());
        record.sending_chain = uninitialized_signal_message_chain();
    }
    let receiving_chain = record
        .receiving_chain
        .as_mut()
        .ok_or_else(|| CoreError::Protocol("missing Signal receiving chain".to_owned()))?;
    let message_keys = signal_message_keys_for_counter(
        &mut record.message_keys,
        &message_ratchet_key,
        receiving_chain,
        message.counter,
    )?;
    decrypt_signal_message_body(&message.ciphertext, &message_keys)
}

fn signal_message_keys_for_counter(
    skipped: &mut Vec<SignalProviderStoredMessageKey>,
    ratchet_key: &Bytes,
    chain_key: &mut SignalMessageChainKey,
    counter: u32,
) -> CoreResult<SignalMessageKeyMaterial> {
    if counter <= chain_key.counter {
        return Err(CoreError::Protocol(format!(
            "duplicate or old Signal message counter: {counter}"
        )));
    }
    let jump = counter - chain_key.counter;
    if jump > SIGNAL_MAX_MESSAGE_FORWARD_JUMPS {
        return Err(CoreError::Protocol(format!(
            "Signal message is too far in the future: {jump}"
        )));
    }
    loop {
        let step = ratchet_signal_message_chain(chain_key)?;
        *chain_key = step.next_chain_key;
        if step.message_counter == counter {
            return Ok(step.message_keys);
        }
        push_signal_provider_stored_message_key(
            skipped,
            SignalProviderStoredMessageKey {
                ratchet_key: ratchet_key.clone(),
                counter: step.message_counter,
                message_keys: step.message_keys,
            },
        )?;
    }
}

fn skip_signal_provider_message_keys_until(
    skipped: &mut Vec<SignalProviderStoredMessageKey>,
    ratchet_key: &Bytes,
    chain_key: &mut SignalMessageChainKey,
    counter: u32,
) -> CoreResult<()> {
    if counter < chain_key.counter {
        return Err(CoreError::Protocol(format!(
            "Signal previous chain counter moved backwards: message {counter}, current {}",
            chain_key.counter
        )));
    }
    if counter == chain_key.counter {
        return Ok(());
    }
    let jump = counter - chain_key.counter;
    if jump > SIGNAL_MAX_MESSAGE_FORWARD_JUMPS {
        return Err(CoreError::Protocol(format!(
            "Signal previous chain is too far in the future: {jump}"
        )));
    }
    while chain_key.counter < counter {
        let step = ratchet_signal_message_chain(chain_key)?;
        *chain_key = step.next_chain_key;
        push_signal_provider_stored_message_key(
            skipped,
            SignalProviderStoredMessageKey {
                ratchet_key: ratchet_key.clone(),
                counter: step.message_counter,
                message_keys: step.message_keys,
            },
        )?;
    }
    Ok(())
}

fn find_signal_provider_stored_message_key_index(
    skipped: &[SignalProviderStoredMessageKey],
    ratchet_key: &Bytes,
    counter: u32,
) -> Option<usize> {
    skipped.iter().position(|message_key| {
        message_key.ratchet_key == *ratchet_key && message_key.counter == counter
    })
}

fn push_signal_provider_stored_message_key(
    skipped: &mut Vec<SignalProviderStoredMessageKey>,
    message_key: SignalProviderStoredMessageKey,
) -> CoreResult<()> {
    validate_signal_provider_stored_message_key(&message_key)?;
    if skipped.iter().any(|existing| {
        existing.ratchet_key == message_key.ratchet_key && existing.counter == message_key.counter
    }) {
        return Ok(());
    }
    skipped.push(message_key);
    if skipped.len() > SIGNAL_MAX_PROVIDER_MESSAGE_KEYS {
        let excess = skipped.len() - SIGNAL_MAX_PROVIDER_MESSAGE_KEYS;
        skipped.drain(..excess);
    }
    Ok(())
}

fn ensure_signal_provider_sending_chain(
    record: &mut SignalProviderSessionRecord,
) -> CoreResult<()> {
    if !is_uninitialized_signal_message_chain(&record.sending_chain) {
        return Ok(());
    }
    let remote_ratchet_key = record.remote_ratchet_key.clone().ok_or_else(|| {
        CoreError::Protocol("missing Signal remote ratchet key for send chain".to_owned())
    })?;
    let local_ratchet_key_pair = generate_key_pair();
    let step = ratchet_signal_root_key(
        &record.root_key,
        local_ratchet_key_pair.private.expose(),
        &remote_ratchet_key,
    )?;
    record.root_key = step.root_key;
    record.sending_chain = step.chain_key;
    record.local_ratchet_key_pair = local_ratchet_key_pair;
    Ok(())
}

fn uninitialized_signal_message_chain() -> SignalMessageChainKey {
    SignalMessageChainKey {
        key: SecretBytes::from([0u8; SIGNAL_MESSAGE_KEY_LEN].to_vec()),
        counter: 0,
    }
}

fn is_uninitialized_signal_message_chain(chain: &SignalMessageChainKey) -> bool {
    chain.counter == 0 && chain.key.expose().iter().all(|byte| *byte == 0)
}

fn validate_signal_provider_session_record(record: &SignalProviderSessionRecord) -> CoreResult<()> {
    normalize_signal_public_key(&record.remote_identity_key)?;
    validate_signal_root_key(record.root_key.key.expose())?;
    validate_signal_message_chain_key(record.sending_chain.key.expose())?;
    if let Some(chain) = &record.receiving_chain {
        validate_signal_message_chain_key(chain.key.expose())?;
    }
    if let Some(key) = &record.remote_ratchet_key {
        normalize_signal_public_key(key)?;
    }
    if record.receiving_chain.is_some() != record.remote_ratchet_key.is_some() {
        return Err(CoreError::Protocol(
            "Signal provider session receiving chain and remote ratchet key must be stored together"
                .to_owned(),
        ));
    }
    if is_uninitialized_signal_message_chain(&record.sending_chain)
        && record.remote_ratchet_key.is_none()
    {
        return Err(CoreError::Protocol(
            "Signal provider session uninitialized sending chain requires remote ratchet key"
                .to_owned(),
        ));
    }
    signal_public_key_bytes(&prefixed_signal_public_key(
        &record.local_ratchet_key_pair.public,
    ))?;
    let local_private_key =
        signal_private_key_bytes(record.local_ratchet_key_pair.private.expose())?;
    if public_key_from_private(local_private_key) != record.local_ratchet_key_pair.public {
        return Err(CoreError::Protocol(
            "Signal provider session local ratchet public key does not match private key"
                .to_owned(),
        ));
    }
    if record.message_keys.len() > SIGNAL_MAX_PROVIDER_MESSAGE_KEYS {
        return Err(CoreError::Protocol(format!(
            "Signal provider session must contain at most {SIGNAL_MAX_PROVIDER_MESSAGE_KEYS} skipped message keys"
        )));
    }
    if !record.message_keys.is_empty() && record.remote_ratchet_key.is_none() {
        return Err(CoreError::Protocol(
            "Signal provider skipped message keys require remote ratchet key".to_owned(),
        ));
    }
    let active_receiving_chain = match (&record.remote_ratchet_key, &record.receiving_chain) {
        (Some(ratchet_key), Some(chain)) => {
            Some((normalize_signal_public_key(ratchet_key)?, chain.counter))
        }
        _ => None,
    };
    let mut skipped_message_keys = HashSet::with_capacity(record.message_keys.len());
    for message_key in &record.message_keys {
        validate_signal_provider_stored_message_key(message_key)?;
        let ratchet_key = normalize_signal_public_key(&message_key.ratchet_key)?;
        if let Some((active_ratchet_key, active_counter)) = &active_receiving_chain
            && ratchet_key == *active_ratchet_key
            && message_key.counter >= *active_counter
        {
            return Err(CoreError::Protocol(
                "Signal provider skipped message counter must be below active receiving counter"
                    .to_owned(),
            ));
        }
        if !skipped_message_keys.insert((ratchet_key, message_key.counter)) {
            return Err(CoreError::Protocol(
                "duplicate Signal provider skipped message key".to_owned(),
            ));
        }
    }
    Ok(())
}

fn validate_signal_provider_stored_message_key(
    message_key: &SignalProviderStoredMessageKey,
) -> CoreResult<()> {
    normalize_signal_public_key(&message_key.ratchet_key)?;
    if message_key.counter == 0 {
        return Err(CoreError::Protocol(
            "Signal provider skipped message counter must be greater than zero".to_owned(),
        ));
    }
    validate_signal_message_chain_key(message_key.message_keys.cipher_key.expose())?;
    validate_signal_message_chain_key(message_key.message_keys.mac_key.expose())?;
    if message_key.message_keys.iv.len() != SIGNAL_MESSAGE_IV_LEN {
        return Err(CoreError::Protocol(format!(
            "Signal provider skipped message IV must be {SIGNAL_MESSAGE_IV_LEN} bytes"
        )));
    }
    Ok(())
}

fn validate_provider_identity_transition_in_tx(
    tx: &mut dyn StoreTransaction,
    address: &str,
    identity_record: &[u8],
) -> wa_store::StoreResult<CoreResult<()>> {
    let Some(existing) = tx.get(KeyNamespace::SignalProviderIdentity, address)? else {
        return Ok(Ok(()));
    };
    if existing == identity_record {
        return Ok(Ok(()));
    }
    let existing = match normalize_signal_public_key(&existing) {
        Ok(existing) => existing,
        Err(_) => {
            return Ok(Err(CoreError::Protocol(format!(
                "Signal provider identity changed for {address}"
            ))));
        }
    };
    let next = match normalize_signal_public_key(identity_record) {
        Ok(next) => next,
        Err(_) => {
            return Ok(Err(CoreError::Protocol(format!(
                "Signal provider identity changed for {address}"
            ))));
        }
    };
    if existing != next {
        return Ok(Err(CoreError::Protocol(format!(
            "Signal provider identity changed for {address}"
        ))));
    }
    Ok(Ok(()))
}

fn validate_decodable_provider_session_identity(
    session_record: &[u8],
    identity_record: &[u8],
) -> CoreResult<()> {
    let Ok(record) = decode_signal_provider_session_record(session_record) else {
        return Ok(());
    };
    let identity = normalize_signal_public_key(identity_record)?;
    if identity != record.remote_identity_key {
        return Err(CoreError::Protocol(
            "provider session identity mismatch".to_owned(),
        ));
    }
    Ok(())
}

fn validate_provider_session_identity_in_tx(
    tx: &mut dyn StoreTransaction,
    address: &str,
    record: &SignalProviderSessionRecord,
) -> wa_store::StoreResult<CoreResult<()>> {
    let Some(identity) = tx.get(KeyNamespace::SignalProviderIdentity, address)? else {
        return Ok(Err(CoreError::Protocol("no provider identity".to_owned())));
    };
    let identity = match normalize_signal_public_key(&identity) {
        Ok(identity) => identity,
        Err(err) => return Ok(Err(err)),
    };
    if identity != record.remote_identity_key {
        return Ok(Err(CoreError::Protocol(
            "provider identity mismatch".to_owned(),
        )));
    }
    Ok(Ok(()))
}

fn delete_provider_identity_record_in_tx(
    tx: &mut dyn StoreTransaction,
    key: &str,
) -> wa_store::StoreResult<bool> {
    let deleted = tx.get(KeyNamespace::SignalProviderIdentity, key)?.is_some();
    if deleted {
        tx.delete(KeyNamespace::SignalProviderIdentity, key)?;
        if let Some(session) = tx.get(KeyNamespace::SignalProviderSession, key)?
            && decode_signal_provider_session_record(&session).is_ok()
        {
            tx.delete(KeyNamespace::SignalProviderSession, key)?;
        }
    }
    Ok(deleted)
}

fn delete_provider_session_record_in_tx(
    tx: &mut dyn StoreTransaction,
    key: &str,
) -> wa_store::StoreResult<bool> {
    let Some(session) = tx.get(KeyNamespace::SignalProviderSession, key)? else {
        return Ok(false);
    };
    tx.delete(KeyNamespace::SignalProviderSession, key)?;
    if decode_signal_provider_session_record(&session).is_ok() {
        tx.delete(KeyNamespace::SignalProviderIdentity, key)?;
    }
    Ok(true)
}

fn save_identity_in_tx(
    tx: &mut dyn StoreTransaction,
    address: &str,
    identity_key: &[u8],
) -> wa_store::StoreResult<bool> {
    let existing = tx.get(KeyNamespace::IdentityKey, address)?;
    if existing.as_deref() == Some(identity_key) {
        return Ok(false);
    }
    if existing.is_some() {
        tx.delete(KeyNamespace::Session, address)?;
        tx.delete(KeyNamespace::SignalProviderSession, address)?;
        tx.delete(KeyNamespace::SignalProviderIdentity, address)?;
    }
    tx.set(KeyNamespace::IdentityKey, address, identity_key)?;
    Ok(existing.is_some())
}

fn native_signal_session_pair_valid(session: &[u8], identity: &[u8]) -> bool {
    let Ok(session) = decode_stored_session(session) else {
        return false;
    };
    let Ok(identity) = normalize_signal_public_key(identity) else {
        return false;
    };
    identity == session.identity_key
}

fn migrate_native_signal_records_in_tx(
    tx: &mut dyn StoreTransaction,
    from: &str,
    to: &str,
    migrated: &mut usize,
    skipped: &mut usize,
    total: &mut usize,
) -> wa_store::StoreResult<()> {
    let from_session = tx.get(KeyNamespace::Session, from)?;
    let from_identity = tx.get(KeyNamespace::IdentityKey, from)?;
    let to_session = tx.get(KeyNamespace::Session, to)?;
    let to_identity = tx.get(KeyNamespace::IdentityKey, to)?;

    if let (Some(session), Some(identity)) = (&from_session, &from_identity) {
        *total += 2;
        let destination_empty = to_session.is_none() && to_identity.is_none();
        let source_pair_valid = native_signal_session_pair_valid(session, identity);
        if !destination_empty || !source_pair_valid {
            *skipped += 2;
            return Ok(());
        }
        tx.set(KeyNamespace::Session, to, session)?;
        tx.set(KeyNamespace::IdentityKey, to, identity)?;
        tx.delete(KeyNamespace::Session, from)?;
        tx.delete(KeyNamespace::IdentityKey, from)?;
        *migrated += 2;
        return Ok(());
    }

    if from_session.is_some() {
        *total += 1;
        *skipped += 1;
    }

    if let Some(identity) = from_identity {
        *total += 1;
        if to_identity.is_some() || to_session.is_some() {
            *skipped += 1;
        } else {
            tx.set(KeyNamespace::IdentityKey, to, &identity)?;
            tx.delete(KeyNamespace::IdentityKey, from)?;
            *migrated += 1;
        }
    }

    Ok(())
}

fn migrate_signal_provider_records_in_tx(
    tx: &mut dyn StoreTransaction,
    from: &str,
    to: &str,
    migrated: &mut usize,
    skipped: &mut usize,
    total: &mut usize,
) -> wa_store::StoreResult<()> {
    let from_session = tx.get(KeyNamespace::SignalProviderSession, from)?;
    let from_identity = tx.get(KeyNamespace::SignalProviderIdentity, from)?;
    let to_session = tx.get(KeyNamespace::SignalProviderSession, to)?;
    let to_identity = tx.get(KeyNamespace::SignalProviderIdentity, to)?;

    if let (Some(session), Some(identity)) = (&from_session, &from_identity) {
        *total += 2;
        let destination_empty = to_session.is_none() && to_identity.is_none();
        let source_pair_valid =
            validate_decodable_provider_session_identity(session, identity).is_ok();
        if !destination_empty || !source_pair_valid {
            *skipped += 2;
            return Ok(());
        }
        tx.set(KeyNamespace::SignalProviderSession, to, session)?;
        tx.set(KeyNamespace::SignalProviderIdentity, to, identity)?;
        tx.delete(KeyNamespace::SignalProviderSession, from)?;
        tx.delete(KeyNamespace::SignalProviderIdentity, from)?;
        *migrated += 2;
        return Ok(());
    }

    if let Some(session) = from_session {
        *total += 1;
        if to_session.is_some()
            || to_identity.is_some()
            || decode_signal_provider_session_record(&session).is_ok()
        {
            *skipped += 1;
        } else {
            tx.set(KeyNamespace::SignalProviderSession, to, &session)?;
            tx.delete(KeyNamespace::SignalProviderSession, from)?;
            *migrated += 1;
        }
    }

    if let Some(identity) = from_identity {
        *total += 1;
        if to_identity.is_some() || to_session.is_some() {
            *skipped += 1;
        } else {
            tx.set(KeyNamespace::SignalProviderIdentity, to, &identity)?;
            tx.delete(KeyNamespace::SignalProviderIdentity, from)?;
            *migrated += 1;
        }
    }

    Ok(())
}

#[derive(Clone, PartialEq, ::prost::Message)]
struct SignalWireWhisperMessage {
    #[prost(bytes = "bytes", tag = "1")]
    ephemeral_key: Bytes,
    #[prost(uint32, optional, tag = "2")]
    counter: Option<u32>,
    #[prost(uint32, optional, tag = "3")]
    previous_counter: Option<u32>,
    #[prost(bytes = "bytes", tag = "4")]
    ciphertext: Bytes,
}

#[derive(Clone, PartialEq, ::prost::Message)]
struct SignalWirePreKeyWhisperMessage {
    #[prost(uint32, optional, tag = "1")]
    pre_key_id: Option<u32>,
    #[prost(bytes = "bytes", tag = "2")]
    base_key: Bytes,
    #[prost(bytes = "bytes", tag = "3")]
    identity_key: Bytes,
    #[prost(bytes = "bytes", tag = "4")]
    message: Bytes,
    #[prost(uint32, optional, tag = "5")]
    registration_id: Option<u32>,
    #[prost(uint32, optional, tag = "6")]
    signed_pre_key_id: Option<u32>,
}

impl From<SignalWhisperMessage> for SignalWireWhisperMessage {
    fn from(value: SignalWhisperMessage) -> Self {
        Self {
            ephemeral_key: value.ephemeral_key,
            counter: Some(value.counter),
            previous_counter: Some(value.previous_counter),
            ciphertext: value.ciphertext,
        }
    }
}

impl TryFrom<SignalWireWhisperMessage> for SignalWhisperMessage {
    type Error = CoreError;

    fn try_from(value: SignalWireWhisperMessage) -> CoreResult<Self> {
        let ephemeral_key = normalize_signal_public_key(&value.ephemeral_key)?;
        let counter = value.counter.ok_or_else(|| {
            CoreError::Protocol("Signal whisper message missing counter".to_owned())
        })?;
        Ok(Self {
            ephemeral_key,
            counter,
            previous_counter: value.previous_counter.unwrap_or(0),
            ciphertext: value.ciphertext,
        })
    }
}

impl TryFrom<SignalPreKeyWhisperMessage> for SignalWirePreKeyWhisperMessage {
    type Error = CoreError;

    fn try_from(value: SignalPreKeyWhisperMessage) -> CoreResult<Self> {
        Ok(Self {
            pre_key_id: value.pre_key_id,
            base_key: value.base_key,
            identity_key: value.identity_key,
            message: encode_signal_whisper_message(&value.message)?,
            registration_id: Some(value.registration_id),
            signed_pre_key_id: Some(value.signed_pre_key_id),
        })
    }
}

impl TryFrom<SignalWirePreKeyWhisperMessage> for SignalPreKeyWhisperMessage {
    type Error = CoreError;

    fn try_from(value: SignalWirePreKeyWhisperMessage) -> CoreResult<Self> {
        if value.message.is_empty() {
            return Err(CoreError::Protocol(
                "Signal pre-key whisper message missing inner message".to_owned(),
            ));
        }
        let registration_id = value.registration_id.ok_or_else(|| {
            CoreError::Protocol("Signal pre-key whisper message missing registration id".to_owned())
        })?;
        let signed_pre_key_id = value.signed_pre_key_id.ok_or_else(|| {
            CoreError::Protocol(
                "Signal pre-key whisper message missing signed pre-key id".to_owned(),
            )
        })?;
        Ok(Self {
            registration_id,
            pre_key_id: value.pre_key_id,
            signed_pre_key_id,
            base_key: normalize_signal_public_key(&value.base_key)?,
            identity_key: normalize_signal_public_key(&value.identity_key)?,
            message: decode_signal_whisper_message(&value.message)?,
        })
    }
}

fn validate_signal_whisper_message(
    message: &SignalWhisperMessage,
) -> CoreResult<SignalWhisperMessage> {
    if message.ciphertext.is_empty() {
        return Err(CoreError::Protocol(
            "Signal whisper message ciphertext must not be empty".to_owned(),
        ));
    }
    Ok(SignalWhisperMessage {
        ephemeral_key: normalize_signal_public_key(&message.ephemeral_key)?,
        counter: message.counter,
        previous_counter: message.previous_counter,
        ciphertext: message.ciphertext.clone(),
    })
}

fn validate_signal_pre_key_whisper_message(
    message: &SignalPreKeyWhisperMessage,
) -> CoreResult<SignalPreKeyWhisperMessage> {
    let base_key = normalize_signal_public_key(&message.base_key)?;
    let inner_message = validate_signal_whisper_message(&message.message)?;
    if inner_message.ephemeral_key != base_key {
        return Err(CoreError::Protocol(
            "Signal pre-key message base key does not match inner ratchet key".to_owned(),
        ));
    }
    Ok(SignalPreKeyWhisperMessage {
        registration_id: message.registration_id,
        pre_key_id: message.pre_key_id,
        signed_pre_key_id: message.signed_pre_key_id,
        base_key,
        identity_key: normalize_signal_public_key(&message.identity_key)?,
        message: inner_message,
    })
}

fn signal_local_key_material(credentials: AuthCredentials) -> SignalLocalKeyMaterial {
    let AuthCredentials {
        signed_identity_key,
        signed_pre_key,
        registration_id,
        ..
    } = credentials;
    SignalLocalKeyMaterial {
        registration_id,
        identity: SignalLocalIdentity {
            public_key: local_key_pair_public_key(&signed_identity_key),
            key_pair: signed_identity_key,
        },
        signed_pre_key: SignalLocalSignedPreKey {
            key_id: signed_pre_key.key_id,
            public_key: local_key_pair_public_key(&signed_pre_key.key_pair),
            key_pair: signed_pre_key.key_pair,
            signature: signed_pre_key.signature,
        },
    }
}

fn signal_local_pre_key(key_id: u32, key_pair: KeyPair) -> SignalLocalPreKey {
    SignalLocalPreKey {
        key_id,
        public_key: local_key_pair_public_key(&key_pair),
        key_pair,
    }
}

fn local_key_pair_public_key(key_pair: &KeyPair) -> Bytes {
    Bytes::copy_from_slice(&prefixed_signal_public_key(&key_pair.public))
}

fn validate_signal_message_chain_key(chain_key: &[u8]) -> CoreResult<()> {
    if chain_key.len() != SIGNAL_MESSAGE_KEY_LEN {
        return Err(CoreError::Protocol(format!(
            "Signal message chain key must be {SIGNAL_MESSAGE_KEY_LEN} bytes"
        )));
    }
    Ok(())
}

fn validate_signal_sender_chain_key(chain_key: &[u8]) -> CoreResult<()> {
    if chain_key.len() != SIGNAL_MESSAGE_KEY_LEN {
        return Err(CoreError::Protocol(format!(
            "Signal sender chain key must be {SIGNAL_MESSAGE_KEY_LEN} bytes"
        )));
    }
    Ok(())
}

fn validate_signal_sender_key_distribution_message(
    message: &SignalSenderKeyDistributionMessage,
) -> CoreResult<()> {
    validate_signal_sender_key_message_version(message.message_version)?;
    validate_signal_sender_chain_key(message.chain_key.expose())?;
    let signing_key = normalize_signal_public_key(&message.signing_key)?;
    validate_signal_sender_signing_key_wire_public(&signing_key)
}

fn validate_signal_sender_signing_key_wire_public(signing_key: &[u8]) -> CoreResult<()> {
    if signing_key.len() != SIGNAL_MESSAGE_KEY_LEN + 1
        || signing_key.first().copied() != Some(SIGNAL_PUBLIC_KEY_VERSION)
    {
        return Err(CoreError::Protocol(format!(
            "Signal sender-key signing public key must be {} prefixed bytes",
            SIGNAL_MESSAGE_KEY_LEN + 1
        )));
    }
    Ok(())
}

fn validate_signal_sender_key_record(record: &SignalSenderKeyRecord) -> CoreResult<()> {
    if record.states.len() > SIGNAL_MAX_SENDER_KEY_STATES {
        return Err(CoreError::Protocol(format!(
            "Signal sender-key record must contain at most {SIGNAL_MAX_SENDER_KEY_STATES} states"
        )));
    }
    let mut state_keys = HashSet::with_capacity(record.states.len());
    for state in &record.states {
        validate_signal_sender_key_state(state)?;
        let signing_public_key = normalize_signal_public_key(&state.signing_public_key)?;
        if !state_keys.insert((state.key_id, signing_public_key)) {
            return Err(CoreError::Protocol(
                "duplicate Signal sender-key state".to_owned(),
            ));
        }
    }
    Ok(())
}

fn validate_signal_sender_key_state(state: &SignalSenderKeyState) -> CoreResult<()> {
    validate_signal_sender_chain_key(state.chain_key.key.expose())?;
    let signing_public_key = normalize_signal_public_key(&state.signing_public_key)?;
    if let Some(private_key) = &state.signing_private_key {
        let private_key = signal_private_key_bytes(private_key.expose())?;
        let expected_public_key = Bytes::copy_from_slice(&prefixed_signal_public_key(
            &public_key_from_private(private_key),
        ));
        if signing_public_key != expected_public_key {
            return Err(CoreError::Protocol(
                "Signal sender-key signing public key does not match private key".to_owned(),
            ));
        }
    }
    if state.message_keys.len() > SIGNAL_MAX_SENDER_MESSAGE_KEYS {
        return Err(CoreError::Protocol(format!(
            "Signal sender-key state must contain at most {SIGNAL_MAX_SENDER_MESSAGE_KEYS} message keys"
        )));
    }
    let mut stored_iterations = HashSet::with_capacity(state.message_keys.len());
    for message_key in &state.message_keys {
        if message_key.iteration >= state.chain_key.iteration {
            return Err(CoreError::Protocol(
                "Signal sender-key skipped iteration must be below chain iteration".to_owned(),
            ));
        }
        if !stored_iterations.insert(message_key.iteration) {
            return Err(CoreError::Protocol(
                "duplicate Signal sender-key skipped message iteration".to_owned(),
            ));
        }
        validate_signal_sender_chain_key(message_key.seed.expose())?;
    }
    Ok(())
}

enum SignalSenderMessageKeyLookup {
    Current(SignalSenderMessageKeyMaterial),
    Stored {
        index: usize,
        message_key: SignalSenderMessageKeyMaterial,
    },
}

impl SignalSenderMessageKeyLookup {
    fn message_key(&self) -> &SignalSenderMessageKeyMaterial {
        match self {
            Self::Current(message_key) | Self::Stored { message_key, .. } => message_key,
        }
    }
}

fn signal_sender_message_key_for_iteration(
    state: &mut SignalSenderKeyState,
    iteration: u32,
) -> CoreResult<SignalSenderMessageKeyLookup> {
    validate_signal_sender_key_state(state)?;
    if state.chain_key.iteration > iteration {
        let index = state
            .message_keys
            .iter()
            .position(|message_key| message_key.iteration == iteration)
            .ok_or_else(|| {
                CoreError::Protocol(format!(
                    "duplicate Signal sender-key message iteration: {iteration}"
                ))
            })?;
        let message_key =
            derive_signal_sender_message_keys(iteration, state.message_keys[index].seed.expose())?;
        return Ok(SignalSenderMessageKeyLookup::Stored { index, message_key });
    }

    let jump = iteration - state.chain_key.iteration;
    if jump > SIGNAL_MAX_SENDER_FORWARD_JUMPS {
        return Err(CoreError::Protocol(format!(
            "Signal sender-key message is too far in the future: {jump}"
        )));
    }

    while state.chain_key.iteration < iteration {
        let step = ratchet_signal_sender_chain(&state.chain_key)?;
        push_signal_sender_stored_message_key(
            state,
            SignalSenderStoredMessageKey {
                iteration: step.message_key.iteration,
                seed: step.message_key.seed,
            },
        )?;
        state.chain_key = step.next_chain_key;
    }

    let step = ratchet_signal_sender_chain(&state.chain_key)?;
    state.chain_key = step.next_chain_key;
    Ok(SignalSenderMessageKeyLookup::Current(step.message_key))
}

fn push_signal_sender_stored_message_key(
    state: &mut SignalSenderKeyState,
    message_key: SignalSenderStoredMessageKey,
) -> CoreResult<()> {
    validate_signal_sender_chain_key(message_key.seed.expose())?;
    state.message_keys.push(message_key);
    if state.message_keys.len() > SIGNAL_MAX_SENDER_MESSAGE_KEYS {
        let excess = state.message_keys.len() - SIGNAL_MAX_SENDER_MESSAGE_KEYS;
        state.message_keys.drain(..excess);
    }
    Ok(())
}

fn signal_sender_key_state_structure(
    state: &SignalSenderKeyState,
) -> CoreResult<SenderKeyStateStructure> {
    validate_signal_sender_key_state(state)?;
    Ok(SenderKeyStateStructure {
        sender_key_id: Some(state.key_id),
        sender_chain_key: Some(sender_key_state_structure::SenderChainKey {
            iteration: Some(state.chain_key.iteration),
            seed: Some(Bytes::copy_from_slice(state.chain_key.key.expose())),
        }),
        sender_signing_key: Some(sender_key_state_structure::SenderSigningKey {
            public: Some(normalize_signal_public_key(&state.signing_public_key)?),
            private: state
                .signing_private_key
                .as_ref()
                .map(|private_key| Bytes::copy_from_slice(private_key.expose())),
        }),
        sender_message_keys: state
            .message_keys
            .iter()
            .map(|message_key| {
                validate_signal_sender_chain_key(message_key.seed.expose())?;
                Ok(sender_key_state_structure::SenderMessageKey {
                    iteration: Some(message_key.iteration),
                    seed: Some(Bytes::copy_from_slice(message_key.seed.expose())),
                })
            })
            .collect::<CoreResult<Vec<_>>>()?,
    })
}

fn signal_sender_key_state_from_structure(
    state: SenderKeyStateStructure,
) -> CoreResult<SignalSenderKeyState> {
    let sender_chain_key = state.sender_chain_key.ok_or_else(|| {
        CoreError::Protocol("Signal sender-key state missing chain key".to_owned())
    })?;
    let chain_key = sender_chain_key.seed.ok_or_else(|| {
        CoreError::Protocol("Signal sender-key state missing chain key seed".to_owned())
    })?;
    validate_signal_sender_chain_key(&chain_key)?;
    let sender_signing_key = state.sender_signing_key.ok_or_else(|| {
        CoreError::Protocol("Signal sender-key state missing signing key".to_owned())
    })?;
    let signing_public_key = sender_signing_key.public.ok_or_else(|| {
        CoreError::Protocol("Signal sender-key state missing signing public key".to_owned())
    })?;
    validate_signal_sender_signing_key_wire_public(&signing_public_key)?;
    if let Some(private_key) = sender_signing_key.private.as_deref() {
        signal_private_key_bytes(private_key)?;
    }
    let message_keys = state
        .sender_message_keys
        .into_iter()
        .map(|message_key| {
            let seed = message_key.seed.ok_or_else(|| {
                CoreError::Protocol("Signal sender-key message key missing seed".to_owned())
            })?;
            validate_signal_sender_chain_key(&seed)?;
            Ok(SignalSenderStoredMessageKey {
                iteration: message_key.iteration.ok_or_else(|| {
                    CoreError::Protocol(
                        "Signal sender-key message key missing iteration".to_owned(),
                    )
                })?,
                seed: SecretBytes::from(seed.to_vec()),
            })
        })
        .collect::<CoreResult<Vec<_>>>()?;
    let decoded = SignalSenderKeyState {
        key_id: state
            .sender_key_id
            .ok_or_else(|| CoreError::Protocol("Signal sender-key state missing id".to_owned()))?,
        chain_key: SignalSenderChainKey {
            key: SecretBytes::from(chain_key.to_vec()),
            iteration: sender_chain_key.iteration.ok_or_else(|| {
                CoreError::Protocol("Signal sender-key state missing chain iteration".to_owned())
            })?,
        },
        signing_public_key,
        signing_private_key: sender_signing_key
            .private
            .map(|private_key| SecretBytes::from(private_key.to_vec())),
        message_keys,
    };
    validate_signal_sender_key_state(&decoded)?;
    Ok(decoded)
}

fn validate_signal_sender_key_message(message: &SignalSenderKeyMessage) -> CoreResult<()> {
    validate_signal_sender_key_message_version(message.message_version)?;
    if message.ciphertext.is_empty() {
        return Err(CoreError::Protocol(
            "Signal sender-key message ciphertext must not be empty".to_owned(),
        ));
    }
    if message.signature.len() != SIGNAL_SENDER_KEY_SIGNATURE_LEN {
        return Err(CoreError::Protocol(format!(
            "invalid Signal sender-key message signature length: {}",
            message.signature.len()
        )));
    }
    Ok(())
}

fn validate_signal_sender_key_message_version(version: u8) -> CoreResult<()> {
    if version != SIGNAL_WIRE_CURRENT_VERSION {
        return Err(CoreError::Protocol(format!(
            "unsupported Signal sender-key message version: {version}"
        )));
    }
    Ok(())
}

fn signal_sender_key_message_version(version_byte: u8) -> CoreResult<u8> {
    let message_version = version_byte >> 4;
    let ciphertext_version = version_byte & 0x0f;
    validate_signal_sender_key_message_version(message_version)?;
    if ciphertext_version != SIGNAL_WIRE_CURRENT_VERSION {
        return Err(CoreError::Protocol(format!(
            "unsupported Signal sender-key ciphertext version: {ciphertext_version}"
        )));
    }
    Ok(message_version)
}

fn encode_signal_sender_key_message_payload(message: &SignalSenderKeyMessage) -> CoreResult<Bytes> {
    validate_signal_sender_key_message_version(message.message_version)?;
    if message.ciphertext.is_empty() {
        return Err(CoreError::Protocol(
            "Signal sender-key message ciphertext must not be empty".to_owned(),
        ));
    }
    let proto = ProtoSenderKeyMessage {
        id: Some(message.key_id),
        iteration: Some(message.iteration),
        ciphertext: Some(message.ciphertext.clone()),
    };
    let mut out = BytesMut::with_capacity(1 + proto.encoded_len());
    out.put_u8((message.message_version << 4) | SIGNAL_WIRE_CURRENT_VERSION);
    proto
        .encode(&mut out)
        .map_err(|err| CoreError::Protocol(format!("invalid Signal sender-key message: {err}")))?;
    Ok(out.freeze())
}

fn verify_signal_sender_key_signature<V>(
    signing_public_key: &[u8; SIGNAL_MESSAGE_KEY_LEN],
    signed_payload: &[u8],
    signature: &[u8],
    verifier: &V,
) -> CoreResult<()>
where
    V: NoiseCertificateVerifier,
{
    if signature.len() != SIGNAL_SENDER_KEY_SIGNATURE_LEN {
        return Err(CoreError::Protocol(format!(
            "invalid Signal sender-key message signature length: {}",
            signature.len()
        )));
    }
    if verifier.verify_signature(signing_public_key, signed_payload, signature) {
        Ok(())
    } else {
        Err(CoreError::Protocol(
            "invalid Signal sender-key message signature".to_owned(),
        ))
    }
}

fn validate_signal_root_key(root_key: &[u8]) -> CoreResult<()> {
    if root_key.len() != SIGNAL_MESSAGE_KEY_LEN {
        return Err(CoreError::Protocol(format!(
            "Signal root key must be {SIGNAL_MESSAGE_KEY_LEN} bytes"
        )));
    }
    Ok(())
}

fn validate_signal_shared_secret(shared_secret: &[u8]) -> CoreResult<()> {
    if shared_secret.len() != SIGNAL_MESSAGE_KEY_LEN {
        return Err(CoreError::Protocol(format!(
            "Signal root shared secret must be {SIGNAL_MESSAGE_KEY_LEN} bytes"
        )));
    }
    if shared_secret.iter().all(|byte| *byte == 0) {
        return Err(CoreError::Protocol(
            "Signal root shared secret must not be all zero".to_owned(),
        ));
    }
    Ok(())
}

fn validate_signal_pre_key_secret_input(pre_key_secret_input: &[u8]) -> CoreResult<()> {
    if pre_key_secret_input.len() != SIGNAL_PRE_KEY_SECRET_INPUT_3DH_LEN
        && pre_key_secret_input.len() != SIGNAL_PRE_KEY_SECRET_INPUT_4DH_LEN
    {
        return Err(CoreError::Protocol(format!(
            "Signal pre-key secret input must be {} or {} bytes",
            SIGNAL_PRE_KEY_SECRET_INPUT_3DH_LEN, SIGNAL_PRE_KEY_SECRET_INPUT_4DH_LEN
        )));
    }
    if &pre_key_secret_input[..SIGNAL_MESSAGE_KEY_LEN] != SIGNAL_X3DH_DISCONTINUITY.as_slice() {
        return Err(CoreError::Protocol(
            "Signal pre-key secret input missing X3DH discontinuity bytes".to_owned(),
        ));
    }
    for agreement in pre_key_secret_input[SIGNAL_MESSAGE_KEY_LEN..].chunks_exact(32) {
        validate_signal_shared_secret(agreement)?;
    }
    Ok(())
}

fn signal_pre_key_secret_input() -> Vec<u8> {
    let mut input = Vec::with_capacity(SIGNAL_PRE_KEY_SECRET_INPUT_4DH_LEN);
    input.extend_from_slice(&SIGNAL_X3DH_DISCONTINUITY);
    input
}

fn append_signal_agreement(
    secret_input: &mut Vec<u8>,
    local_private_key: &[u8],
    remote_public_key: &[u8],
) -> CoreResult<()> {
    let local_private_key = signal_private_key_bytes(local_private_key)?;
    let remote_public_key = signal_public_key_bytes(remote_public_key)?;
    let mut agreement = shared_key(local_private_key, remote_public_key);
    validate_signal_shared_secret(&agreement)?;
    secret_input.extend_from_slice(&agreement);
    agreement.zeroize();
    Ok(())
}

fn signal_pre_key_bootstrap(
    step: SignalRootRatchetStep,
    used_one_time_pre_key: bool,
) -> SignalPreKeyBootstrap {
    SignalPreKeyBootstrap {
        root_key: step.root_key,
        chain_key: step.chain_key,
        used_one_time_pre_key,
    }
}

fn signal_private_key_bytes(private_key: &[u8]) -> CoreResult<&[u8; 32]> {
    private_key.try_into().map_err(|_| {
        CoreError::Protocol(format!(
            "Signal private key must be {SIGNAL_MESSAGE_KEY_LEN} bytes"
        ))
    })
}

fn signal_public_key_bytes(public_key: &[u8]) -> CoreResult<&[u8; 32]> {
    let public_key = match public_key {
        value if value.len() == 32 => value,
        value if value.len() == 33 && value[0] == SIGNAL_PUBLIC_KEY_VERSION => &value[1..],
        value => {
            return Err(CoreError::Protocol(format!(
                "invalid signal public key length: {}",
                value.len()
            )));
        }
    };
    public_key.try_into().map_err(|_| {
        CoreError::Protocol(format!(
            "Signal public key must be {SIGNAL_MESSAGE_KEY_LEN} bytes"
        ))
    })
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right.iter())
        .fold(0u8, |acc, (left, right)| acc | (left ^ right))
        == 0
}

fn validate_provider_record_key(key: &str) -> CoreResult<()> {
    if key.is_empty() {
        return Err(CoreError::Protocol(
            "signal provider record key must not be empty".to_owned(),
        ));
    }
    Ok(())
}

fn validate_provider_record_value(value: &[u8]) -> CoreResult<()> {
    if value.is_empty() {
        return Err(CoreError::Protocol(
            "signal provider record value must not be empty".to_owned(),
        ));
    }
    Ok(())
}

async fn delete_provider_record<S>(
    store: &S,
    namespace: KeyNamespace,
    key: &str,
) -> CoreResult<bool>
where
    S: SignalKeyStore,
{
    let existed = store.get_signal_key(namespace, key).await?.is_some();
    store.delete_signal_key(namespace, key).await?;
    Ok(existed)
}

async fn read_mapping<S>(store: &S, key: &str) -> CoreResult<Option<String>>
where
    S: SignalKeyStore,
{
    store
        .get_signal_key(KeyNamespace::LidMapping, key)
        .await?
        .map(|value| {
            String::from_utf8(value)
                .map_err(|err| CoreError::Protocol(format!("invalid mapping UTF-8: {err}")))
        })
        .transpose()
}

fn parse_signed_pre_key(node: &BinaryNode) -> CoreResult<SignalSignedPreKey> {
    Ok(SignalSignedPreKey {
        key_id: child_u32(node, "id", 3)?,
        public_key: normalize_signal_public_key(&child_bytes(node, "value")?)?,
        signature: child_bytes(node, "signature")?,
    })
}

fn parse_pre_key(node: &BinaryNode) -> CoreResult<SignalPreKey> {
    Ok(SignalPreKey {
        key_id: child_u32(node, "id", 3)?,
        public_key: normalize_signal_public_key(&child_bytes(node, "value")?)?,
    })
}

fn child_node<'a>(node: &'a BinaryNode, tag: &str) -> Option<&'a BinaryNode> {
    let Some(BinaryNodeContent::Nodes(children)) = &node.content else {
        return None;
    };
    children.iter().find(|child| child.tag == tag)
}

fn child_bytes(node: &BinaryNode, tag: &str) -> CoreResult<Bytes> {
    let child = child_node(node, tag)
        .ok_or_else(|| CoreError::Protocol(format!("missing child node: {tag}")))?;
    node_bytes(child)
}

fn child_u32(node: &BinaryNode, tag: &str, width: usize) -> CoreResult<u32> {
    let value = child_bytes(node, tag)?;
    if value.len() != width || width > 4 {
        return Err(CoreError::Protocol(format!(
            "invalid uint child length for {tag}: {}",
            value.len()
        )));
    }
    let mut out = 0u32;
    for byte in value {
        out = (out << 8) | u32::from(byte);
    }
    Ok(out)
}

fn node_bytes(node: &BinaryNode) -> CoreResult<Bytes> {
    match &node.content {
        Some(BinaryNodeContent::Bytes(value)) => Ok(value.clone()),
        Some(BinaryNodeContent::Text(value)) => Ok(Bytes::copy_from_slice(value.as_bytes())),
        _ => Err(CoreError::Protocol(format!(
            "node {} has no byte content",
            node.tag
        ))),
    }
}

fn put_bytes(out: &mut BytesMut, value: &[u8]) -> CoreResult<()> {
    let len = u16::try_from(value.len())
        .map_err(|_| CoreError::Protocol("stored session field too large".to_owned()))?;
    out.put_u16(len);
    out.extend_from_slice(value);
    Ok(())
}

fn take_stored_signal_session_u32(input: &mut &[u8], name: &str) -> CoreResult<u32> {
    if input.remaining() < 4 {
        return Err(CoreError::Protocol(format!(
            "stored signal session missing {name}"
        )));
    }
    Ok(input.get_u32())
}

fn take_stored_signal_session_bytes(input: &mut &[u8], name: &str) -> CoreResult<Bytes> {
    if input.remaining() < 2 {
        return Err(CoreError::Protocol(format!(
            "stored signal session missing {name} length"
        )));
    }
    let len = usize::from(input.get_u16());
    if input.remaining() < len {
        return Err(CoreError::Protocol(format!(
            "stored signal session {name} is truncated"
        )));
    }
    Ok(Bytes::copy_from_slice(&input.copy_to_bytes(len)))
}

fn take_signal_provider_session_flag(input: &mut &[u8], name: &str) -> CoreResult<u8> {
    if input.remaining() < 1 {
        return Err(CoreError::Protocol(format!(
            "stored Signal provider session missing {name} flag"
        )));
    }
    Ok(input.get_u8())
}

fn take_signal_provider_session_u32(input: &mut &[u8], name: &str) -> CoreResult<u32> {
    if input.remaining() < 4 {
        return Err(CoreError::Protocol(format!(
            "stored Signal provider session missing {name}"
        )));
    }
    Ok(input.get_u32())
}

fn take_signal_provider_session_bytes(input: &mut &[u8], name: &str) -> CoreResult<Bytes> {
    if input.remaining() < 2 {
        return Err(CoreError::Protocol(format!(
            "stored Signal provider session missing {name} length"
        )));
    }
    let len = usize::from(input.get_u16());
    if input.remaining() < len {
        return Err(CoreError::Protocol(format!(
            "stored Signal provider session {name} is truncated"
        )));
    }
    Ok(Bytes::copy_from_slice(&input.copy_to_bytes(len)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::{
        MessageRelayOptions, build_group_sender_key_message_relay, build_text_message,
    };
    use crate::{
        create_initial_credentials, encode_big_endian, prepare_pre_key_upload, save_credentials,
    };
    use proptest::prelude::*;
    use std::sync::{Arc, Mutex};
    use wa_binary::BinaryNodeContent;
    use wa_crypto::{XEdDsaNoiseCertificateVerifier, generate_key_pair};
    use wa_store::SqliteAuthStore;

    #[test]
    fn maps_jids_to_signal_addresses() {
        assert_eq!(
            signal_protocol_address("12345:7@s.whatsapp.net")
                .unwrap()
                .to_string(),
            "12345.7"
        );
        assert_eq!(
            signal_protocol_address("abc@lid").unwrap().to_string(),
            "abc_1.0"
        );
        assert!(signal_protocol_address("123:99@s.whatsapp.net").is_err());
        assert_eq!(
            signal_protocol_address("123:99@hosted")
                .unwrap()
                .to_string(),
            "123_128.99"
        );
    }

    #[test]
    fn parses_e2e_session_nodes() {
        let node = BinaryNode::new("iq").with_content(vec![BinaryNode::new("list").with_content(
            vec![BinaryNode::new("user")
                .with_attr("jid", "123:7@s.whatsapp.net")
                .with_content(vec![
                    BinaryNode::new("registration")
                        .with_content(encode_big_endian(0x0102_0304, 4).unwrap()),
                    BinaryNode::new("identity").with_content(Bytes::from(vec![1u8; 32])),
                    BinaryNode::new("skey").with_content(vec![
                        BinaryNode::new("id").with_content(encode_big_endian(7, 3).unwrap()),
                        BinaryNode::new("value").with_content(Bytes::from(vec![2u8; 32])),
                        BinaryNode::new("signature").with_content(Bytes::from(vec![3u8; 64])),
                    ]),
                    BinaryNode::new("key").with_content(vec![
                        BinaryNode::new("id").with_content(encode_big_endian(9, 3).unwrap()),
                        BinaryNode::new("value").with_content(Bytes::from(vec![4u8; 32])),
                    ]),
                ])],
        )]);

        let sessions = parse_e2e_sessions_node(&node).unwrap();
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].jid, "123:7@s.whatsapp.net");
        assert_eq!(sessions[0].session.registration_id, 0x0102_0304);
        assert_eq!(sessions[0].session.signed_pre_key.key_id, 7);
        assert_eq!(sessions[0].session.pre_key.as_ref().unwrap().key_id, 9);
        assert_eq!(
            sessions[0].session.identity_key[0],
            SIGNAL_PUBLIC_KEY_VERSION
        );

        let attr_error = BinaryNode::new("iq")
            .with_attr("type", "error")
            .with_attr("code", "401")
            .with_attr("text", "session denied");
        let err = parse_e2e_sessions_node(&attr_error).unwrap_err();
        assert_eq!(
            err.to_string(),
            "protocol error: E2E session query failed (401): session denied"
        );

        let child_error = BinaryNode::new("iq")
            .with_attr("type", "result")
            .with_content(vec![
                BinaryNode::new("error")
                    .with_attr("code", "503")
                    .with_attr("text", "session unavailable"),
            ]);
        let err = parse_e2e_sessions_node(&child_error).unwrap_err();
        assert_eq!(
            err.to_string(),
            "protocol error: E2E session query failed (503): session unavailable"
        );
    }

    #[test]
    fn parses_retry_receipt_session_bundle() {
        let receipt = BinaryNode::new("receipt")
            .with_attr("id", "m1")
            .with_attr("from", "123:7@s.whatsapp.net")
            .with_attr("type", "retry")
            .with_content(vec![
                BinaryNode::new("registration")
                    .with_content(encode_big_endian(0x0102_0304, 4).unwrap()),
                BinaryNode::new("keys").with_content(vec![
                    BinaryNode::new("type").with_content(Bytes::copy_from_slice(&KEY_BUNDLE_TYPE)),
                    BinaryNode::new("identity").with_content(Bytes::from(vec![1u8; 32])),
                    BinaryNode::new("skey").with_content(vec![
                        BinaryNode::new("id").with_content(encode_big_endian(7, 3).unwrap()),
                        BinaryNode::new("value").with_content(Bytes::from(vec![2u8; 32])),
                        BinaryNode::new("signature").with_content(Bytes::from(vec![3u8; 64])),
                    ]),
                    BinaryNode::new("key").with_content(vec![
                        BinaryNode::new("id").with_content(encode_big_endian(9, 3).unwrap()),
                        BinaryNode::new("value").with_content(Bytes::from(vec![4u8; 32])),
                    ]),
                    BinaryNode::new("device-identity")
                        .with_content(Bytes::from_static(b"retry-device-identity")),
                ]),
            ]);

        let bundle = retry_receipt_session_bundle(&receipt, "123:7@s.whatsapp.net")
            .unwrap()
            .unwrap();
        assert_eq!(
            bundle.device_identity.as_deref(),
            Some(&b"retry-device-identity"[..])
        );
        assert_eq!(bundle.session.jid, "123:7@s.whatsapp.net");
        assert_eq!(bundle.session.session.registration_id, 0x0102_0304);
        assert_eq!(bundle.session.session.signed_pre_key.key_id, 7);
        assert_eq!(bundle.session.session.pre_key.as_ref().unwrap().key_id, 9);
        assert_eq!(
            bundle.session.session.identity_key[0],
            SIGNAL_PUBLIC_KEY_VERSION
        );

        let injection = retry_receipt_session_injection(&receipt, "123:7@s.whatsapp.net")
            .unwrap()
            .unwrap();
        assert_eq!(injection.jid, "123:7@s.whatsapp.net");
        assert_eq!(injection.session.registration_id, 0x0102_0304);
        assert_eq!(injection.session.signed_pre_key.key_id, 7);
        assert_eq!(injection.session.pre_key.as_ref().unwrap().key_id, 9);
        assert_eq!(injection.session.identity_key[0], SIGNAL_PUBLIC_KEY_VERSION);

        let empty_device_identity = BinaryNode::new("receipt")
            .with_attr("id", "m1")
            .with_attr("from", "123:7@s.whatsapp.net")
            .with_attr("type", "retry")
            .with_content(vec![
                BinaryNode::new("registration")
                    .with_content(encode_big_endian(0x0102_0304, 4).unwrap()),
                BinaryNode::new("keys").with_content(vec![
                    BinaryNode::new("type").with_content(Bytes::copy_from_slice(&KEY_BUNDLE_TYPE)),
                    BinaryNode::new("identity").with_content(Bytes::from(vec![1u8; 32])),
                    BinaryNode::new("skey").with_content(vec![
                        BinaryNode::new("id").with_content(encode_big_endian(7, 3).unwrap()),
                        BinaryNode::new("value").with_content(Bytes::from(vec![2u8; 32])),
                        BinaryNode::new("signature").with_content(Bytes::from(vec![3u8; 64])),
                    ]),
                    BinaryNode::new("key").with_content(vec![
                        BinaryNode::new("id").with_content(encode_big_endian(9, 3).unwrap()),
                        BinaryNode::new("value").with_content(Bytes::from(vec![4u8; 32])),
                    ]),
                    BinaryNode::new("device-identity").with_content(Bytes::new()),
                ]),
            ]);
        let bundle = retry_receipt_session_bundle(&empty_device_identity, "123:7@s.whatsapp.net")
            .unwrap()
            .unwrap();
        assert_eq!(bundle.device_identity, None);
        assert_eq!(bundle.session.jid, "123:7@s.whatsapp.net");
        assert_eq!(bundle.session.session.registration_id, 0x0102_0304);

        let wrong_type = BinaryNode::new("receipt").with_content(vec![
            BinaryNode::new("registration").with_content(encode_big_endian(1, 4).unwrap()),
            BinaryNode::new("keys").with_content(vec![
                BinaryNode::new("type").with_content(Bytes::from_static(&[9])),
                BinaryNode::new("identity").with_content(Bytes::from(vec![1u8; 32])),
            ]),
        ]);
        assert!(
            retry_receipt_session_injection(&wrong_type, "123:7@s.whatsapp.net")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn builds_e2e_session_query_and_lid_session_jids() {
        let query = build_e2e_session_query(
            [
                "123:7@s.whatsapp.net",
                "123:7@s.whatsapp.net",
                "lid-user:9@lid",
            ],
            true,
            "session-1",
        )
        .unwrap()
        .unwrap();

        assert_eq!(query.tag, "iq");
        assert_eq!(query.attrs["id"], "session-1");
        assert_eq!(query.attrs["xmlns"], "encrypt");
        assert_eq!(query.attrs["type"], "get");
        assert_eq!(query.attrs["to"], SERVER_JID);
        let key = child_node(&query, "key").unwrap();
        let Some(BinaryNodeContent::Nodes(users)) = &key.content else {
            panic!("key query should contain user nodes");
        };
        assert_eq!(users.len(), 2);
        assert_eq!(users[0].attrs["jid"], "123:7@s.whatsapp.net");
        assert_eq!(users[0].attrs["reason"], "identity");
        assert_eq!(users[1].attrs["jid"], "lid-user:9@lid");

        assert!(build_e2e_session_query(["invalid"], false, "bad").is_err());
        assert!(is_lid_signal_jid("lid-user@lid").unwrap());
        assert!(!is_lid_signal_jid("123@s.whatsapp.net").unwrap());
        assert_eq!(
            mapped_lid_session_jid("123:7@s.whatsapp.net", "lid-user").unwrap(),
            "lid-user:7@lid"
        );
        assert_eq!(
            mapped_lid_session_jid("123:99@hosted", "lid-user").unwrap(),
            "lid-user:99@hosted.lid"
        );
    }

    #[test]
    fn signal_wire_whisper_message_round_trips_and_validates() {
        let message = SignalWhisperMessage {
            ephemeral_key: Bytes::from(vec![7u8; 32]),
            counter: 17,
            previous_counter: 13,
            ciphertext: Bytes::from_static(b"signal-ciphertext"),
        };

        let encoded = encode_signal_whisper_message(&message).unwrap();
        let decoded = decode_signal_whisper_message(&encoded).unwrap();

        assert_eq!(decoded.counter, 17);
        assert_eq!(decoded.previous_counter, 13);
        assert_eq!(decoded.ciphertext, Bytes::from_static(b"signal-ciphertext"));
        assert_eq!(decoded.ephemeral_key[0], SIGNAL_PUBLIC_KEY_VERSION);
        assert_eq!(&decoded.ephemeral_key[1..], &[7u8; 32]);
        assert_eq!(
            decode_signal_whisper_message(&encode_signal_whisper_message(&decoded).unwrap())
                .unwrap(),
            decoded
        );
        let zero_encoded = encode_signal_whisper_message(&SignalWhisperMessage {
            ephemeral_key: Bytes::from(vec![9u8; 32]),
            counter: 0,
            previous_counter: 0,
            ciphertext: Bytes::from_static(b"z"),
        })
        .unwrap();
        let expected_zero_encoded = {
            let mut expected = vec![0x0a, 0x21, SIGNAL_PUBLIC_KEY_VERSION];
            expected.extend([9u8; 32]);
            expected.extend([0x10, 0x00, 0x18, 0x00, 0x22, 0x01, b'z']);
            Bytes::from(expected)
        };
        assert_eq!(zero_encoded, expected_zero_encoded);

        let err = encode_signal_whisper_message(&SignalWhisperMessage {
            ciphertext: Bytes::new(),
            ..decoded.clone()
        })
        .unwrap_err();
        assert!(matches!(
            err,
            CoreError::Protocol(message)
                if message == "Signal whisper message ciphertext must not be empty"
        ));

        let err = decode_signal_whisper_message(&[0x0a, 0x02, 1, 2]).unwrap_err();
        assert!(matches!(
            err,
            CoreError::Protocol(message) if message == "invalid signal public key length: 2"
        ));

        let err =
            decode_signal_whisper_message(&[0x10, 0x0c, 0x18, 0x07, 0x22, 0x01, 0xaa]).unwrap_err();
        assert!(matches!(
            err,
            CoreError::Protocol(message) if message == "invalid signal public key length: 0"
        ));

        let missing_counter = SignalWireWhisperMessage {
            ephemeral_key: prefixed_test_signal_key(4),
            counter: None,
            previous_counter: Some(7),
            ciphertext: Bytes::from_static(b"signal-ciphertext"),
        }
        .encode_to_vec();
        let err = decode_signal_whisper_message(&missing_counter).unwrap_err();
        assert!(matches!(
            err,
            CoreError::Protocol(message) if message == "Signal whisper message missing counter"
        ));

        let missing_previous_counter = SignalWireWhisperMessage {
            ephemeral_key: prefixed_test_signal_key(4),
            counter: Some(7),
            previous_counter: None,
            ciphertext: Bytes::from_static(b"signal-ciphertext"),
        }
        .encode_to_vec();
        let decoded_missing_previous =
            decode_signal_whisper_message(&missing_previous_counter).unwrap();
        assert_eq!(decoded_missing_previous.counter, 7);
        assert_eq!(decoded_missing_previous.previous_counter, 0);
    }

    #[test]
    fn signal_wire_pre_key_whisper_message_round_trips_and_validates() {
        let inner = SignalWhisperMessage {
            ephemeral_key: prefixed_test_signal_key(8),
            counter: 3,
            previous_counter: 2,
            ciphertext: Bytes::from_static(b"inner-ciphertext"),
        };
        let message = SignalPreKeyWhisperMessage {
            registration_id: 0x0102_0304,
            pre_key_id: Some(9),
            signed_pre_key_id: 7,
            base_key: Bytes::from(vec![8u8; 32]),
            identity_key: prefixed_test_signal_key(6),
            message: inner.clone(),
        };

        let encoded = encode_signal_pre_key_whisper_message(&message).unwrap();
        let decoded = decode_signal_pre_key_whisper_message(&encoded).unwrap();

        assert_eq!(decoded.registration_id, 0x0102_0304);
        assert_eq!(decoded.pre_key_id, Some(9));
        assert_eq!(decoded.signed_pre_key_id, 7);
        assert_eq!(decoded.base_key[0], SIGNAL_PUBLIC_KEY_VERSION);
        assert_eq!(&decoded.base_key[1..], &[8u8; 32]);
        assert_eq!(decoded.identity_key, prefixed_test_signal_key(6));
        assert_eq!(decoded.message, inner);

        let without_one_time_pre_key = SignalPreKeyWhisperMessage {
            pre_key_id: None,
            ..decoded.clone()
        };
        assert_eq!(
            decode_signal_pre_key_whisper_message(
                &encode_signal_pre_key_whisper_message(&without_one_time_pre_key).unwrap()
            )
            .unwrap()
            .pre_key_id,
            None
        );

        assert!(
            encode_signal_pre_key_whisper_message(&SignalPreKeyWhisperMessage {
                message: SignalWhisperMessage {
                    ciphertext: Bytes::new(),
                    ..inner
                },
                ..decoded.clone()
            })
            .is_err()
        );
        assert!(
            encode_signal_pre_key_whisper_message(&SignalPreKeyWhisperMessage {
                base_key: prefixed_test_signal_key(9),
                ..decoded.clone()
            })
            .is_err()
        );
        let mismatched_wire = SignalWirePreKeyWhisperMessage {
            pre_key_id: decoded.pre_key_id,
            base_key: prefixed_test_signal_key(9),
            identity_key: decoded.identity_key,
            message: encode_signal_whisper_message(&decoded.message).unwrap(),
            registration_id: Some(decoded.registration_id),
            signed_pre_key_id: Some(decoded.signed_pre_key_id),
        }
        .encode_to_vec();
        let err = decode_signal_pre_key_whisper_message(&mismatched_wire).unwrap_err();
        assert!(matches!(
            err,
            CoreError::Protocol(message)
                if message == "Signal pre-key message base key does not match inner ratchet key"
        ));
        assert!(decode_signal_pre_key_whisper_message(&[0x22, 0x02, 1, 2]).is_err());
    }

    #[test]
    fn signal_wire_pre_key_whisper_rejects_missing_inner_message() {
        let wire = SignalWirePreKeyWhisperMessage {
            pre_key_id: Some(9),
            base_key: prefixed_test_signal_key(8),
            identity_key: prefixed_test_signal_key(6),
            message: Bytes::new(),
            registration_id: Some(0x0102_0304),
            signed_pre_key_id: Some(7),
        }
        .encode_to_vec();

        let err = decode_signal_pre_key_whisper_message(&wire).unwrap_err();
        assert!(matches!(
            err,
            CoreError::Protocol(message)
                if message == "Signal pre-key whisper message missing inner message"
        ));
    }

    #[test]
    fn signal_wire_pre_key_whisper_rejects_missing_registration_and_signed_pre_key_ids() {
        let inner = encode_signal_whisper_message(&SignalWhisperMessage {
            ephemeral_key: prefixed_test_signal_key(8),
            counter: 3,
            previous_counter: 2,
            ciphertext: Bytes::from_static(b"inner-ciphertext"),
        })
        .unwrap();
        let missing_registration = SignalWirePreKeyWhisperMessage {
            pre_key_id: Some(9),
            base_key: prefixed_test_signal_key(8),
            identity_key: prefixed_test_signal_key(6),
            message: inner.clone(),
            registration_id: None,
            signed_pre_key_id: Some(7),
        }
        .encode_to_vec();
        let err = decode_signal_pre_key_whisper_message(&missing_registration).unwrap_err();
        assert!(matches!(
            err,
            CoreError::Protocol(message)
                if message == "Signal pre-key whisper message missing registration id"
        ));

        let missing_signed_pre_key = SignalWirePreKeyWhisperMessage {
            pre_key_id: Some(9),
            base_key: prefixed_test_signal_key(8),
            identity_key: prefixed_test_signal_key(6),
            message: inner,
            registration_id: Some(0x0102_0304),
            signed_pre_key_id: None,
        }
        .encode_to_vec();
        let err = decode_signal_pre_key_whisper_message(&missing_signed_pre_key).unwrap_err();
        assert!(matches!(
            err,
            CoreError::Protocol(message)
                if message == "Signal pre-key whisper message missing signed pre-key id"
        ));
    }

    #[test]
    fn signal_wire_pre_key_whisper_rejects_invalid_identity_key_length() {
        let message = SignalPreKeyWhisperMessage {
            registration_id: 0x0102_0304,
            pre_key_id: Some(9),
            signed_pre_key_id: 7,
            base_key: prefixed_test_signal_key(8),
            identity_key: Bytes::from(vec![0x05; 31]),
            message: SignalWhisperMessage {
                ephemeral_key: prefixed_test_signal_key(8),
                counter: 3,
                previous_counter: 2,
                ciphertext: Bytes::from_static(b"inner-ciphertext"),
            },
        };

        let err = encode_signal_pre_key_whisper_message(&message).unwrap_err();
        assert!(matches!(
            err,
            CoreError::Protocol(message) if message == "invalid signal public key length: 31"
        ));

        let wire = SignalWirePreKeyWhisperMessage {
            pre_key_id: Some(9),
            base_key: prefixed_test_signal_key(8),
            identity_key: Bytes::from(vec![0x05; 31]),
            message: encode_signal_whisper_message(&message.message).unwrap(),
            registration_id: Some(0x0102_0304),
            signed_pre_key_id: Some(7),
        }
        .encode_to_vec();
        let err = decode_signal_pre_key_whisper_message(&wire).unwrap_err();
        assert!(matches!(
            err,
            CoreError::Protocol(message) if message == "invalid signal public key length: 31"
        ));
    }

    #[test]
    fn signal_wire_pre_key_whisper_rejects_missing_inner_ciphertext() {
        let inner = SignalWireWhisperMessage {
            ephemeral_key: prefixed_test_signal_key(8),
            counter: Some(3),
            previous_counter: Some(2),
            ciphertext: Bytes::new(),
        }
        .encode_to_vec();
        let wire = SignalWirePreKeyWhisperMessage {
            pre_key_id: Some(9),
            base_key: prefixed_test_signal_key(8),
            identity_key: prefixed_test_signal_key(6),
            message: inner.into(),
            registration_id: Some(0x0102_0304),
            signed_pre_key_id: Some(7),
        }
        .encode_to_vec();

        let err = decode_signal_pre_key_whisper_message(&wire).unwrap_err();
        assert!(matches!(
            err,
            CoreError::Protocol(message)
                if message == "Signal whisper message ciphertext must not be empty"
        ));
    }

    #[test]
    fn signal_provider_session_record_rejects_mismatched_local_ratchet_key_pair() {
        let local_key_pair = generate_key_pair();
        let record = SignalProviderSessionRecord {
            remote_registration_id: 88,
            remote_identity_key: prefixed_test_signal_key(21),
            root_key: SignalRootKey {
                key: SecretBytes::from(vec![9u8; 32]),
            },
            sending_chain: SignalMessageChainKey {
                key: SecretBytes::from(vec![7u8; 32]),
                counter: 0,
            },
            receiving_chain: None,
            remote_ratchet_key: None,
            local_ratchet_key_pair: local_key_pair.clone(),
            previous_counter: 0,
            message_keys: Vec::new(),
        };
        let encoded = encode_signal_provider_session_record(&record).unwrap();

        let mut mismatched = record.clone();
        mismatched.local_ratchet_key_pair.public[0] ^= 1;
        let err = encode_signal_provider_session_record(&mismatched).unwrap_err();
        assert!(matches!(
            err,
            CoreError::Protocol(message)
                if message == "Signal provider session local ratchet public key does not match private key"
        ));

        let local_public = prefixed_signal_public_key(&local_key_pair.public);
        let offset = encoded
            .windows(local_public.len())
            .position(|window| window == local_public)
            .expect("encoded session contains local ratchet public key");
        let mut tampered = encoded.to_vec();
        tampered[offset + local_public.len() - 1] ^= 1;
        let err = decode_signal_provider_session_record(&tampered).unwrap_err();
        assert!(matches!(
            err,
            CoreError::Protocol(message)
                if message == "Signal provider session local ratchet public key does not match private key"
        ));
    }

    #[test]
    fn signal_provider_session_record_rejects_truncated_optional_flags() {
        let local_key_pair = generate_key_pair();
        let mut encoded = BytesMut::new();
        encoded.put_u8(PROVIDER_SESSION_VERSION);
        encoded.put_u8(PROVIDER_SESSION_RECORD_KIND);
        encoded.put_u32(88);
        put_bytes(&mut encoded, &prefixed_test_signal_key(21)).unwrap();
        put_bytes(&mut encoded, &[9u8; SIGNAL_MESSAGE_KEY_LEN]).unwrap();
        encoded.put_u32(1);
        put_bytes(&mut encoded, &[7u8; SIGNAL_MESSAGE_KEY_LEN]).unwrap();
        put_bytes(
            &mut encoded,
            &prefixed_signal_public_key(&local_key_pair.public),
        )
        .unwrap();
        put_bytes(&mut encoded, local_key_pair.private.expose()).unwrap();
        encoded.put_u32(0);

        let decoded = decode_signal_provider_session_record(&encoded).unwrap();
        assert_eq!(decoded.receiving_chain, None);
        assert_eq!(decoded.remote_ratchet_key, None);
        assert!(decoded.message_keys.is_empty());

        let mut missing_remote_flag = encoded.clone();
        missing_remote_flag.put_u8(0);
        let err = decode_signal_provider_session_record(&missing_remote_flag).unwrap_err();
        assert!(matches!(
            err,
            CoreError::Protocol(message)
                if message == "stored Signal provider session missing remote-ratchet flag"
        ));

        let mut missing_skipped_count = encoded.clone();
        missing_skipped_count.put_u8(0);
        missing_skipped_count.put_u8(0);
        let err = decode_signal_provider_session_record(&missing_skipped_count).unwrap_err();
        assert!(matches!(
            err,
            CoreError::Protocol(message)
                if message == "stored Signal provider session missing skipped-key count"
        ));

        let mut missing_remote_after_receiving_chain = encoded;
        missing_remote_after_receiving_chain.put_u8(1);
        missing_remote_after_receiving_chain.put_u32(3);
        put_bytes(
            &mut missing_remote_after_receiving_chain,
            &[8u8; SIGNAL_MESSAGE_KEY_LEN],
        )
        .unwrap();
        let err = decode_signal_provider_session_record(&missing_remote_after_receiving_chain)
            .unwrap_err();
        assert!(matches!(
            err,
            CoreError::Protocol(message)
                if message == "stored Signal provider session missing remote-ratchet flag"
        ));
    }

    #[test]
    fn signal_provider_session_record_rejects_truncated_required_fields_with_names() {
        let local_key_pair = generate_key_pair();
        let mut missing_identity_length = BytesMut::new();
        missing_identity_length.put_u8(PROVIDER_SESSION_VERSION);
        missing_identity_length.put_u8(PROVIDER_SESSION_RECORD_KIND);
        missing_identity_length.put_u32(88);
        let err = decode_signal_provider_session_record(&missing_identity_length).unwrap_err();
        assert!(matches!(
            err,
            CoreError::Protocol(message)
                if message == "stored Signal provider session missing remote identity key length"
        ));

        let mut truncated_root = missing_identity_length.clone();
        put_bytes(&mut truncated_root, &prefixed_test_signal_key(21)).unwrap();
        truncated_root.put_u16(u16::try_from(SIGNAL_MESSAGE_KEY_LEN).unwrap());
        truncated_root.extend_from_slice(&[9u8; 4]);
        let err = decode_signal_provider_session_record(&truncated_root).unwrap_err();
        assert!(matches!(
            err,
            CoreError::Protocol(message)
                if message == "stored Signal provider session root key is truncated"
        ));

        let mut missing_previous_counter = missing_identity_length;
        put_bytes(&mut missing_previous_counter, &prefixed_test_signal_key(21)).unwrap();
        put_bytes(
            &mut missing_previous_counter,
            &[9u8; SIGNAL_MESSAGE_KEY_LEN],
        )
        .unwrap();
        missing_previous_counter.put_u32(1);
        put_bytes(
            &mut missing_previous_counter,
            &[7u8; SIGNAL_MESSAGE_KEY_LEN],
        )
        .unwrap();
        put_bytes(
            &mut missing_previous_counter,
            &prefixed_signal_public_key(&local_key_pair.public),
        )
        .unwrap();
        put_bytes(
            &mut missing_previous_counter,
            local_key_pair.private.expose(),
        )
        .unwrap();
        let err = decode_signal_provider_session_record(&missing_previous_counter).unwrap_err();
        assert!(matches!(
            err,
            CoreError::Protocol(message)
                if message == "stored Signal provider session missing previous counter"
        ));
    }

    #[test]
    fn signal_provider_session_record_rejects_duplicate_skipped_message_keys() {
        let local_key_pair = generate_key_pair();
        let active_ratchet_key = generate_key_pair();
        let first_ratchet_key = generate_key_pair();
        let second_ratchet_key = generate_key_pair();
        let skipped_message_key =
            |ratchet_key: Bytes, counter: u32| SignalProviderStoredMessageKey {
                ratchet_key,
                counter,
                message_keys: SignalMessageKeyMaterial {
                    cipher_key: SecretBytes::from(vec![1u8; SIGNAL_MESSAGE_KEY_LEN]),
                    mac_key: SecretBytes::from(vec![2u8; SIGNAL_MESSAGE_KEY_LEN]),
                    iv: [3u8; SIGNAL_MESSAGE_IV_LEN],
                },
            };
        let record = SignalProviderSessionRecord {
            remote_registration_id: 88,
            remote_identity_key: prefixed_test_signal_key(21),
            root_key: SignalRootKey {
                key: SecretBytes::from(vec![9u8; 32]),
            },
            sending_chain: SignalMessageChainKey {
                key: SecretBytes::from(vec![7u8; 32]),
                counter: 0,
            },
            receiving_chain: Some(SignalMessageChainKey {
                key: SecretBytes::from(vec![4u8; 32]),
                counter: 10,
            }),
            remote_ratchet_key: Some(Bytes::copy_from_slice(&prefixed_signal_public_key(
                &active_ratchet_key.public,
            ))),
            local_ratchet_key_pair: local_key_pair,
            previous_counter: 0,
            message_keys: vec![
                skipped_message_key(
                    Bytes::copy_from_slice(&prefixed_signal_public_key(&first_ratchet_key.public)),
                    9,
                ),
                skipped_message_key(Bytes::copy_from_slice(&first_ratchet_key.public), 9),
            ],
        };
        let err = encode_signal_provider_session_record(&record).unwrap_err();
        assert!(matches!(
            err,
            CoreError::Protocol(message)
                if message == "duplicate Signal provider skipped message key"
        ));

        let mut valid_record = record;
        valid_record.message_keys[1].ratchet_key =
            Bytes::copy_from_slice(&prefixed_signal_public_key(&second_ratchet_key.public));
        let encoded = encode_signal_provider_session_record(&valid_record).unwrap();
        let first_ratchet = prefixed_signal_public_key(&first_ratchet_key.public);
        let second_ratchet = prefixed_signal_public_key(&second_ratchet_key.public);
        let offset = encoded
            .windows(second_ratchet.len())
            .position(|window| window == second_ratchet)
            .expect("encoded session contains second skipped ratchet key");
        let mut tampered = encoded.to_vec();
        tampered[offset..offset + second_ratchet.len()].copy_from_slice(&first_ratchet);
        let err = decode_signal_provider_session_record(&tampered).unwrap_err();
        assert!(matches!(
            err,
            CoreError::Protocol(message)
                if message == "duplicate Signal provider skipped message key"
        ));
    }

    #[test]
    fn signal_provider_session_record_rejects_zero_counter_skipped_message_keys() {
        let local_key_pair = generate_key_pair();
        let active_ratchet_key = generate_key_pair();
        let skipped_ratchet_key = generate_key_pair();
        let skipped_message_key = |counter: u32| SignalProviderStoredMessageKey {
            ratchet_key: Bytes::copy_from_slice(&prefixed_signal_public_key(
                &skipped_ratchet_key.public,
            )),
            counter,
            message_keys: SignalMessageKeyMaterial {
                cipher_key: SecretBytes::from(vec![1u8; SIGNAL_MESSAGE_KEY_LEN]),
                mac_key: SecretBytes::from(vec![2u8; SIGNAL_MESSAGE_KEY_LEN]),
                iv: [3u8; SIGNAL_MESSAGE_IV_LEN],
            },
        };
        let record = SignalProviderSessionRecord {
            remote_registration_id: 88,
            remote_identity_key: prefixed_test_signal_key(21),
            root_key: SignalRootKey {
                key: SecretBytes::from(vec![9u8; 32]),
            },
            sending_chain: SignalMessageChainKey {
                key: SecretBytes::from(vec![7u8; 32]),
                counter: 0,
            },
            receiving_chain: Some(SignalMessageChainKey {
                key: SecretBytes::from(vec![4u8; 32]),
                counter: 10,
            }),
            remote_ratchet_key: Some(Bytes::copy_from_slice(&prefixed_signal_public_key(
                &active_ratchet_key.public,
            ))),
            local_ratchet_key_pair: local_key_pair,
            previous_counter: 0,
            message_keys: vec![skipped_message_key(0)],
        };
        let err = encode_signal_provider_session_record(&record).unwrap_err();
        assert!(matches!(
            err,
            CoreError::Protocol(message)
                if message == "Signal provider skipped message counter must be greater than zero"
        ));

        let mut valid_record = record;
        valid_record.message_keys[0] = skipped_message_key(9);
        let encoded = encode_signal_provider_session_record(&valid_record).unwrap();
        let ratchet_key = prefixed_signal_public_key(&skipped_ratchet_key.public);
        let offset = encoded
            .windows(ratchet_key.len())
            .position(|window| window == ratchet_key)
            .expect("encoded session contains skipped ratchet key");
        let counter_offset = offset + ratchet_key.len();
        let mut tampered = encoded.to_vec();
        tampered[counter_offset..counter_offset + 4].copy_from_slice(&0u32.to_be_bytes());
        let err = decode_signal_provider_session_record(&tampered).unwrap_err();
        assert!(matches!(
            err,
            CoreError::Protocol(message)
                if message == "Signal provider skipped message counter must be greater than zero"
        ));
    }

    #[test]
    fn signal_provider_session_record_rejects_skipped_keys_without_remote_ratchet() {
        let local_key_pair = generate_key_pair();
        let skipped_ratchet_key = generate_key_pair();
        let skipped_message_key = SignalProviderStoredMessageKey {
            ratchet_key: Bytes::copy_from_slice(&prefixed_signal_public_key(
                &skipped_ratchet_key.public,
            )),
            counter: 9,
            message_keys: SignalMessageKeyMaterial {
                cipher_key: SecretBytes::from(vec![1u8; SIGNAL_MESSAGE_KEY_LEN]),
                mac_key: SecretBytes::from(vec![2u8; SIGNAL_MESSAGE_KEY_LEN]),
                iv: [3u8; SIGNAL_MESSAGE_IV_LEN],
            },
        };
        let record = SignalProviderSessionRecord {
            remote_registration_id: 88,
            remote_identity_key: prefixed_test_signal_key(21),
            root_key: SignalRootKey {
                key: SecretBytes::from(vec![9u8; 32]),
            },
            sending_chain: SignalMessageChainKey {
                key: SecretBytes::from(vec![7u8; 32]),
                counter: 0,
            },
            receiving_chain: None,
            remote_ratchet_key: None,
            local_ratchet_key_pair: local_key_pair.clone(),
            previous_counter: 0,
            message_keys: vec![skipped_message_key.clone()],
        };
        let err = encode_signal_provider_session_record(&record).unwrap_err();
        assert!(matches!(
            err,
            CoreError::Protocol(message)
                if message == "Signal provider skipped message keys require remote ratchet key"
        ));

        let mut encoded = BytesMut::new();
        encoded.put_u8(PROVIDER_SESSION_VERSION);
        encoded.put_u8(PROVIDER_SESSION_RECORD_KIND);
        encoded.put_u32(record.remote_registration_id);
        put_bytes(&mut encoded, &record.remote_identity_key).unwrap();
        put_bytes(&mut encoded, record.root_key.key.expose()).unwrap();
        encoded.put_u32(record.sending_chain.counter);
        put_bytes(&mut encoded, record.sending_chain.key.expose()).unwrap();
        put_bytes(
            &mut encoded,
            &prefixed_signal_public_key(&local_key_pair.public),
        )
        .unwrap();
        put_bytes(&mut encoded, local_key_pair.private.expose()).unwrap();
        encoded.put_u32(record.previous_counter);
        encoded.put_u8(0);
        encoded.put_u8(0);
        encoded.put_u32(1);
        put_bytes(&mut encoded, &skipped_message_key.ratchet_key).unwrap();
        encoded.put_u32(skipped_message_key.counter);
        put_bytes(
            &mut encoded,
            skipped_message_key.message_keys.cipher_key.expose(),
        )
        .unwrap();
        put_bytes(
            &mut encoded,
            skipped_message_key.message_keys.mac_key.expose(),
        )
        .unwrap();
        put_bytes(&mut encoded, &skipped_message_key.message_keys.iv).unwrap();
        let err = decode_signal_provider_session_record(&encoded).unwrap_err();
        assert!(matches!(
            err,
            CoreError::Protocol(message)
                if message == "Signal provider skipped message keys require remote ratchet key"
        ));
    }

    #[test]
    fn signal_provider_session_record_rejects_uninitialized_send_chain_without_remote_ratchet() {
        let local_key_pair = generate_key_pair();
        let record = SignalProviderSessionRecord {
            remote_registration_id: 88,
            remote_identity_key: prefixed_test_signal_key(21),
            root_key: SignalRootKey {
                key: SecretBytes::from(vec![9u8; 32]),
            },
            sending_chain: uninitialized_signal_message_chain(),
            receiving_chain: None,
            remote_ratchet_key: None,
            local_ratchet_key_pair: local_key_pair.clone(),
            previous_counter: 0,
            message_keys: Vec::new(),
        };
        let err = encode_signal_provider_session_record(&record).unwrap_err();
        assert!(matches!(
            err,
            CoreError::Protocol(message)
                if message == "Signal provider session uninitialized sending chain requires remote ratchet key"
        ));

        let mut encoded = BytesMut::new();
        encoded.put_u8(PROVIDER_SESSION_VERSION);
        encoded.put_u8(PROVIDER_SESSION_RECORD_KIND);
        encoded.put_u32(record.remote_registration_id);
        put_bytes(&mut encoded, &record.remote_identity_key).unwrap();
        put_bytes(&mut encoded, record.root_key.key.expose()).unwrap();
        encoded.put_u32(record.sending_chain.counter);
        put_bytes(&mut encoded, record.sending_chain.key.expose()).unwrap();
        put_bytes(
            &mut encoded,
            &prefixed_signal_public_key(&local_key_pair.public),
        )
        .unwrap();
        put_bytes(&mut encoded, local_key_pair.private.expose()).unwrap();
        encoded.put_u32(record.previous_counter);
        encoded.put_u8(0);
        encoded.put_u8(0);
        encoded.put_u32(0);

        let err = decode_signal_provider_session_record(&encoded).unwrap_err();
        assert!(matches!(
            err,
            CoreError::Protocol(message)
                if message == "Signal provider session uninitialized sending chain requires remote ratchet key"
        ));
    }

    #[test]
    fn signal_provider_session_record_rejects_active_ratchet_future_skipped_key() {
        let local_key_pair = generate_key_pair();
        let active_ratchet_key = generate_key_pair();
        let skipped_message_key = |counter: u32| SignalProviderStoredMessageKey {
            ratchet_key: Bytes::copy_from_slice(&prefixed_signal_public_key(
                &active_ratchet_key.public,
            )),
            counter,
            message_keys: SignalMessageKeyMaterial {
                cipher_key: SecretBytes::from(vec![1u8; SIGNAL_MESSAGE_KEY_LEN]),
                mac_key: SecretBytes::from(vec![2u8; SIGNAL_MESSAGE_KEY_LEN]),
                iv: [3u8; SIGNAL_MESSAGE_IV_LEN],
            },
        };
        let record = SignalProviderSessionRecord {
            remote_registration_id: 88,
            remote_identity_key: prefixed_test_signal_key(21),
            root_key: SignalRootKey {
                key: SecretBytes::from(vec![9u8; 32]),
            },
            sending_chain: uninitialized_signal_message_chain(),
            receiving_chain: Some(SignalMessageChainKey {
                key: SecretBytes::from(vec![7u8; 32]),
                counter: 3,
            }),
            remote_ratchet_key: Some(Bytes::copy_from_slice(&prefixed_signal_public_key(
                &active_ratchet_key.public,
            ))),
            local_ratchet_key_pair: local_key_pair,
            previous_counter: 0,
            message_keys: vec![skipped_message_key(3)],
        };
        let err = encode_signal_provider_session_record(&record).unwrap_err();
        assert!(matches!(
            err,
            CoreError::Protocol(message)
                if message == "Signal provider skipped message counter must be below active receiving counter"
        ));

        let mut valid_record = record;
        valid_record.message_keys[0] = skipped_message_key(2);
        let encoded = encode_signal_provider_session_record(&valid_record).unwrap();
        let active_ratchet = prefixed_signal_public_key(&active_ratchet_key.public);
        let offset = encoded
            .windows(active_ratchet.len())
            .rposition(|window| window == active_ratchet)
            .expect("encoded session contains skipped active ratchet key");
        let counter_offset = offset + active_ratchet.len();
        let mut tampered = encoded.to_vec();
        tampered[counter_offset..counter_offset + 4].copy_from_slice(&3u32.to_be_bytes());
        let err = decode_signal_provider_session_record(&tampered).unwrap_err();
        assert!(matches!(
            err,
            CoreError::Protocol(message)
                if message == "Signal provider skipped message counter must be below active receiving counter"
        ));
    }

    proptest! {
        #[test]
        fn signal_wire_whisper_message_round_trips_generated_fields(
            ephemeral_key in any::<[u8; SIGNAL_MESSAGE_KEY_LEN]>(),
            counter in any::<u32>(),
            previous_counter in any::<u32>(),
            ciphertext in prop::collection::vec(any::<u8>(), 1..=128),
        ) {
            let message = SignalWhisperMessage {
                ephemeral_key: Bytes::copy_from_slice(&ephemeral_key),
                counter,
                previous_counter,
                ciphertext: Bytes::from(ciphertext),
            };

            let decoded =
                decode_signal_whisper_message(&encode_signal_whisper_message(&message).unwrap())
                    .unwrap();

            let expected_ephemeral_key =
                Bytes::copy_from_slice(&prefixed_signal_public_key(&ephemeral_key));
            prop_assert_eq!(&decoded.ephemeral_key, &expected_ephemeral_key);
            prop_assert_eq!(decoded.counter, counter);
            prop_assert_eq!(decoded.previous_counter, previous_counter);
            prop_assert_eq!(decoded.ciphertext.as_ref(), message.ciphertext.as_ref());
            prop_assert_eq!(
                decode_signal_whisper_message(
                    &encode_signal_whisper_message(&decoded).unwrap()
                )
                .unwrap(),
                decoded
            );
        }

        #[test]
        fn signal_wire_pre_key_whisper_message_round_trips_generated_fields(
            registration_id in any::<u32>(),
            pre_key_id in prop::option::of(any::<u32>()),
            signed_pre_key_id in any::<u32>(),
            base_key in any::<[u8; SIGNAL_MESSAGE_KEY_LEN]>(),
            identity_key in any::<[u8; SIGNAL_MESSAGE_KEY_LEN]>(),
            counter in any::<u32>(),
            previous_counter in any::<u32>(),
            ciphertext in prop::collection::vec(any::<u8>(), 1..=128),
        ) {
            let message = SignalPreKeyWhisperMessage {
                registration_id,
                pre_key_id,
                signed_pre_key_id,
                base_key: Bytes::copy_from_slice(&base_key),
                identity_key: Bytes::copy_from_slice(&identity_key),
                message: SignalWhisperMessage {
                    ephemeral_key: Bytes::copy_from_slice(&base_key),
                    counter,
                    previous_counter,
                    ciphertext: Bytes::from(ciphertext),
                },
            };

            let decoded = decode_signal_pre_key_whisper_message(
                &encode_signal_pre_key_whisper_message(&message).unwrap()
            )
            .unwrap();

            prop_assert_eq!(decoded.registration_id, registration_id);
            prop_assert_eq!(decoded.pre_key_id, pre_key_id);
            prop_assert_eq!(decoded.signed_pre_key_id, signed_pre_key_id);
            let expected_base_key =
                Bytes::copy_from_slice(&prefixed_signal_public_key(&base_key));
            let expected_identity_key =
                Bytes::copy_from_slice(&prefixed_signal_public_key(&identity_key));
            let expected_ephemeral_key =
                Bytes::copy_from_slice(&prefixed_signal_public_key(&base_key));
            prop_assert_eq!(&decoded.base_key, &expected_base_key);
            prop_assert_eq!(&decoded.identity_key, &expected_identity_key);
            prop_assert_eq!(&decoded.message.ephemeral_key, &expected_ephemeral_key);
            prop_assert_eq!(decoded.message.counter, counter);
            prop_assert_eq!(decoded.message.previous_counter, previous_counter);
            prop_assert_eq!(
                decoded.message.ciphertext.as_ref(),
                message.message.ciphertext.as_ref()
            );
            prop_assert_eq!(
                decode_signal_pre_key_whisper_message(
                    &encode_signal_pre_key_whisper_message(&decoded).unwrap()
                )
                .unwrap(),
                decoded
            );
        }

        #[test]
        fn signal_provider_session_record_round_trips_generated_state(
            remote_registration_id in any::<u32>(),
            remote_identity_key in any::<[u8; SIGNAL_MESSAGE_KEY_LEN]>(),
            root_key in any::<[u8; SIGNAL_MESSAGE_KEY_LEN]>(),
            sending_counter in any::<u32>(),
            sending_chain_key in any::<[u8; SIGNAL_MESSAGE_KEY_LEN]>(),
            local_private_key in any::<[u8; SIGNAL_MESSAGE_KEY_LEN]>(),
            previous_counter in any::<u32>(),
            receiving in prop::option::of((
                any::<u32>(),
                any::<[u8; SIGNAL_MESSAGE_KEY_LEN]>(),
                any::<[u8; SIGNAL_MESSAGE_KEY_LEN]>(),
            )),
            skipped in prop::collection::vec((
                any::<[u8; SIGNAL_MESSAGE_KEY_LEN]>(),
                1u32..=u32::MAX,
                any::<[u8; SIGNAL_MESSAGE_KEY_LEN]>(),
                any::<[u8; SIGNAL_MESSAGE_KEY_LEN]>(),
                any::<[u8; SIGNAL_MESSAGE_IV_LEN]>(),
            ), 0..=8),
        ) {
            let local_public_key = public_key_from_private(&local_private_key);
            let receiving_chain = receiving.as_ref().map(|(counter, chain_key, _)| {
                SignalMessageChainKey {
                    key: SecretBytes::from(chain_key.to_vec()),
                    counter: *counter,
                }
            });
            let remote_ratchet_key =
                receiving.as_ref().map(|(_, _, ratchet_key)| Bytes::copy_from_slice(ratchet_key));
            let message_keys = if receiving.is_some() {
                skipped
                    .into_iter()
                    .map(
                        |(ratchet_key, counter, cipher_key, mac_key, iv)| {
                            SignalProviderStoredMessageKey {
                                ratchet_key: Bytes::copy_from_slice(&ratchet_key),
                                counter,
                                message_keys: SignalMessageKeyMaterial {
                                    cipher_key: SecretBytes::from(cipher_key.to_vec()),
                                    mac_key: SecretBytes::from(mac_key.to_vec()),
                                    iv,
                                },
                            }
                        },
                    )
                    .collect::<Vec<_>>()
            } else {
                Vec::new()
            };
            let record = SignalProviderSessionRecord {
                remote_registration_id,
                remote_identity_key: Bytes::copy_from_slice(&remote_identity_key),
                root_key: SignalRootKey {
                    key: SecretBytes::from(root_key.to_vec()),
                },
                sending_chain: SignalMessageChainKey {
                    key: SecretBytes::from(sending_chain_key.to_vec()),
                    counter: sending_counter,
                },
                receiving_chain,
                remote_ratchet_key,
                local_ratchet_key_pair: KeyPair {
                    public: local_public_key,
                    private: SecretBytes::from(local_private_key.to_vec()),
                },
                previous_counter,
                message_keys,
            };

            let decoded = decode_signal_provider_session_record(
                &encode_signal_provider_session_record(&record).unwrap()
            )
            .unwrap();

            prop_assert_eq!(decoded.remote_registration_id, remote_registration_id);
            let expected_remote_identity_key =
                Bytes::copy_from_slice(&prefixed_signal_public_key(&remote_identity_key));
            prop_assert_eq!(&decoded.remote_identity_key, &expected_remote_identity_key);
            prop_assert_eq!(decoded.root_key.key.expose(), &root_key);
            prop_assert_eq!(decoded.sending_chain.counter, sending_counter);
            prop_assert_eq!(decoded.sending_chain.key.expose(), &sending_chain_key);
            prop_assert_eq!(decoded.local_ratchet_key_pair.public, local_public_key);
            prop_assert_eq!(decoded.local_ratchet_key_pair.private.expose(), &local_private_key);
            prop_assert_eq!(decoded.previous_counter, previous_counter);
            prop_assert_eq!(&decoded.receiving_chain, &record.receiving_chain);
            let expected_remote_ratchet_key = record
                .remote_ratchet_key
                .as_ref()
                .map(|key| normalize_signal_public_key(key).unwrap());
            prop_assert_eq!(
                decoded.remote_ratchet_key.as_ref(),
                expected_remote_ratchet_key.as_ref()
            );
            prop_assert_eq!(decoded.message_keys.len(), record.message_keys.len());
            for (decoded_key, original_key) in
                decoded.message_keys.iter().zip(record.message_keys.iter())
            {
                let expected_ratchet_key =
                    normalize_signal_public_key(&original_key.ratchet_key).unwrap();
                prop_assert_eq!(&decoded_key.ratchet_key, &expected_ratchet_key);
                prop_assert_eq!(decoded_key.counter, original_key.counter);
                prop_assert_eq!(
                    decoded_key.message_keys.cipher_key.expose(),
                    original_key.message_keys.cipher_key.expose()
                );
                prop_assert_eq!(
                    decoded_key.message_keys.mac_key.expose(),
                    original_key.message_keys.mac_key.expose()
                );
                prop_assert_eq!(decoded_key.message_keys.iv, original_key.message_keys.iv);
            }
            prop_assert_eq!(
                decode_signal_provider_session_record(
                    &encode_signal_provider_session_record(&decoded).unwrap()
                )
                .unwrap(),
                decoded
            );
        }

        #[test]
        fn signal_sender_key_distribution_message_round_trips_generated_fields(
            key_id in any::<u32>(),
            iteration in any::<u32>(),
            chain_key in any::<[u8; SIGNAL_MESSAGE_KEY_LEN]>(),
            signing_public_key in any::<[u8; SIGNAL_MESSAGE_KEY_LEN]>(),
        ) {
            let message = build_signal_sender_key_distribution_message(
                key_id,
                iteration,
                &chain_key,
                &signing_public_key,
            )
            .unwrap();

            let decoded = decode_signal_sender_key_distribution_message(
                &encode_signal_sender_key_distribution_message(&message).unwrap()
            )
            .unwrap();

            prop_assert_eq!(decoded.message_version, SIGNAL_WIRE_CURRENT_VERSION);
            prop_assert_eq!(decoded.key_id, key_id);
            prop_assert_eq!(decoded.iteration, iteration);
            prop_assert_eq!(decoded.chain_key.expose(), &chain_key);
            let expected_signing_key =
                Bytes::copy_from_slice(&prefixed_signal_public_key(&signing_public_key));
            prop_assert_eq!(
                &decoded.signing_key,
                &expected_signing_key
            );
            prop_assert_eq!(
                decode_signal_sender_key_distribution_message(
                    &encode_signal_sender_key_distribution_message(&decoded).unwrap()
                )
                .unwrap(),
                decoded
            );
        }

        #[test]
        fn signal_sender_key_message_round_trips_generated_fields(
            key_id in any::<u32>(),
            iteration in any::<u32>(),
            ciphertext in prop::collection::vec(any::<u8>(), 1..=128),
            signature in any::<[u8; SIGNAL_SENDER_KEY_SIGNATURE_LEN]>(),
        ) {
            let message = SignalSenderKeyMessage {
                message_version: SIGNAL_WIRE_CURRENT_VERSION,
                key_id,
                iteration,
                ciphertext: Bytes::from(ciphertext),
                signature: Bytes::copy_from_slice(&signature),
            };

            let decoded = decode_signal_sender_key_message(
                &encode_signal_sender_key_message(&message).unwrap()
            )
            .unwrap();

            prop_assert_eq!(&decoded, &message);
            prop_assert_eq!(
                decode_signal_sender_key_message(
                    &encode_signal_sender_key_message(&decoded).unwrap()
                )
                .unwrap(),
                decoded
            );
        }

        #[test]
        fn signal_sender_key_record_round_trips_generated_states(
            states in prop::collection::vec(signal_sender_key_state_strategy(), 0..=SIGNAL_MAX_SENDER_KEY_STATES),
        ) {
            let record = SignalSenderKeyRecord { states };
            let expected = normalized_signal_sender_key_record(&record);

            let decoded = decode_signal_sender_key_record(
                &encode_signal_sender_key_record(&record).unwrap()
            )
            .unwrap();

            prop_assert_eq!(&decoded, &expected);
            prop_assert_eq!(
                decode_signal_sender_key_record(
                    &encode_signal_sender_key_record(&decoded).unwrap()
                )
                .unwrap(),
                decoded
            );
        }
    }

    #[test]
    fn signal_message_body_crypto_derives_encrypts_and_authenticates() {
        let chain_key = [1u8; 32];
        let keys = derive_signal_message_keys(&chain_key).unwrap();
        assert_eq!(
            keys.cipher_key.expose(),
            &[
                0x9c, 0x1c, 0xa9, 0xc4, 0x7f, 0xad, 0x3f, 0xa5, 0x77, 0x30, 0x60, 0xfc, 0x40, 0xa0,
                0x45, 0x0e, 0x95, 0x15, 0xec, 0x3c, 0x93, 0x67, 0x89, 0xee, 0x86, 0x91, 0x34, 0x59,
                0x69, 0xed, 0x23, 0x6c,
            ]
        );
        assert_eq!(
            keys.mac_key.expose(),
            &[
                0xe3, 0xd1, 0x69, 0xeb, 0x78, 0xe1, 0xcc, 0x49, 0x49, 0x35, 0xeb, 0xec, 0x80, 0x41,
                0x69, 0x2a, 0xfb, 0x4b, 0xb4, 0x09, 0x08, 0xd0, 0x25, 0xa5, 0x02, 0xe1, 0xe7, 0x5c,
                0x03, 0xb6, 0xcb, 0xbc,
            ]
        );
        assert_eq!(
            keys.iv,
            [
                0x36, 0xce, 0x5c, 0x50, 0xe2, 0xe5, 0x88, 0xf8, 0xe5, 0x88, 0xda, 0x1a, 0x36, 0x62,
                0x0f, 0x0e,
            ]
        );

        let encrypted = encrypt_signal_message_body(b"provider plaintext", &keys).unwrap();
        assert_eq!(
            decrypt_signal_message_body(&encrypted, &keys).unwrap(),
            Bytes::from_static(b"provider plaintext")
        );
        assert!(encrypted.len() > "provider plaintext".len() + SIGNAL_MESSAGE_MAC_LEN);

        let mut tampered_mac = encrypted.to_vec();
        *tampered_mac.last_mut().unwrap() ^= 1;
        assert!(decrypt_signal_message_body(&tampered_mac, &keys).is_err());

        let mut tampered_ciphertext = encrypted.to_vec();
        tampered_ciphertext[0] ^= 1;
        assert!(decrypt_signal_message_body(&tampered_ciphertext, &keys).is_err());

        let wrong_keys = derive_signal_message_keys(&[2u8; 32]).unwrap();
        assert!(decrypt_signal_message_body(&encrypted, &wrong_keys).is_err());
        assert!(derive_signal_message_keys(&[1u8; 31]).is_err());
        assert!(decrypt_signal_message_body(&[0u8; SIGNAL_MESSAGE_MAC_LEN], &keys).is_err());
    }

    #[test]
    fn signal_message_chain_ratchet_derives_message_keys_and_advances() {
        let chain_key = SignalMessageChainKey {
            key: SecretBytes::from(vec![1u8; 32]),
            counter: 41,
        };

        let message_key_seed = derive_signal_message_key_seed(chain_key.key.expose()).unwrap();
        assert_eq!(
            message_key_seed.expose(),
            &[
                0xcc, 0x6e, 0xfb, 0x87, 0x2c, 0x23, 0x7f, 0x56, 0x5e, 0xe8, 0x2d, 0xf4, 0x2e, 0x4c,
                0xab, 0x00, 0x09, 0x8b, 0x13, 0x71, 0x03, 0x95, 0xe3, 0xc6, 0xd2, 0x9f, 0x29, 0x07,
                0xd6, 0x9e, 0x4f, 0x04,
            ]
        );

        let next_chain_key = advance_signal_message_chain_key(chain_key.key.expose()).unwrap();
        assert_eq!(
            next_chain_key.expose(),
            &[
                0xc3, 0x1d, 0x79, 0xab, 0xaf, 0x8f, 0x21, 0x50, 0xee, 0x1c, 0xfe, 0x3d, 0xc7, 0x32,
                0xee, 0xd0, 0x2a, 0x56, 0xf7, 0x96, 0x47, 0x90, 0x9b, 0xad, 0x05, 0x5a, 0x83, 0x1c,
                0xb7, 0x62, 0xe9, 0xa2,
            ]
        );

        let step = ratchet_signal_message_chain(&chain_key).unwrap();
        assert_eq!(step.message_counter, 42);
        assert_eq!(step.next_chain_key.counter, 42);
        assert_eq!(step.next_chain_key.key, next_chain_key);
        assert_eq!(
            step.message_keys.cipher_key.expose(),
            &[
                0x3b, 0x9f, 0xc7, 0xfd, 0x6b, 0x27, 0xe7, 0x2d, 0xb2, 0x5c, 0x23, 0xc2, 0x76, 0x13,
                0xde, 0xe5, 0x3e, 0xc6, 0x50, 0x2f, 0x36, 0xb7, 0xc8, 0x56, 0x9b, 0x2c, 0xeb, 0xd8,
                0x90, 0x58, 0xc3, 0x3a,
            ]
        );
        assert_eq!(
            step.message_keys.mac_key.expose(),
            &[
                0x82, 0xb3, 0xe0, 0x0c, 0xd3, 0x78, 0xb8, 0x33, 0xe6, 0x4c, 0x77, 0x61, 0xe3, 0xca,
                0xcd, 0x5f, 0xb0, 0x6d, 0x20, 0xa3, 0x4a, 0x02, 0x58, 0x3b, 0xfa, 0x19, 0x60, 0x25,
                0xeb, 0xaf, 0xcb, 0xa1,
            ]
        );
        assert_eq!(
            step.message_keys.iv,
            [
                0x0f, 0x11, 0x14, 0x8a, 0x4b, 0x7a, 0x5e, 0xd6, 0x30, 0xee, 0xe4, 0xd0, 0x01, 0x93,
                0xbf, 0x41,
            ]
        );

        let encrypted =
            encrypt_signal_message_body(b"ratcheted provider plaintext", &step.message_keys)
                .unwrap();
        assert_eq!(
            decrypt_signal_message_body(&encrypted, &step.message_keys).unwrap(),
            Bytes::from_static(b"ratcheted provider plaintext")
        );
        assert_eq!(chain_key.counter, 41);
        assert_eq!(chain_key.key.expose(), &[1u8; 32]);
        assert!(derive_signal_message_key_seed(&[1u8; 31]).is_err());
        assert!(advance_signal_message_chain_key(&[1u8; 31]).is_err());
        assert!(
            ratchet_signal_message_chain(&SignalMessageChainKey {
                key: SecretBytes::from(vec![1u8; 32]),
                counter: u32::MAX,
            })
            .is_err()
        );
    }

    #[test]
    fn signal_root_ratchet_derives_root_and_chain_keys() {
        let root_key = SignalRootKey {
            key: SecretBytes::from(vec![3u8; 32]),
        };
        let step = derive_signal_root_chain_keys(root_key.key.expose(), &[4u8; 32]).unwrap();

        assert_eq!(
            step.root_key.key.expose(),
            &[
                0x1e, 0x18, 0x22, 0xda, 0xcf, 0xf0, 0xde, 0x08, 0x7c, 0x48, 0x43, 0x1f, 0x6f, 0xab,
                0x81, 0xec, 0xda, 0x13, 0x0d, 0x87, 0xfa, 0xf6, 0x22, 0xd7, 0x59, 0xb2, 0x22, 0x76,
                0xb0, 0xeb, 0x68, 0x1a,
            ]
        );
        assert_eq!(
            step.chain_key.key.expose(),
            &[
                0x2c, 0x34, 0xed, 0x18, 0xc0, 0x2a, 0xf3, 0xc7, 0x73, 0x2e, 0x96, 0xb2, 0xd6, 0x6d,
                0x18, 0xa9, 0x2f, 0xbf, 0x3d, 0xe2, 0xe6, 0x13, 0x23, 0x56, 0xfa, 0x13, 0x7a, 0x06,
                0x7e, 0x43, 0x0a, 0x75,
            ]
        );
        assert_eq!(step.chain_key.counter, 0);
        assert_eq!(root_key.key.expose(), &[3u8; 32]);

        let local_private = [7u8; 32];
        let remote_public = [8u8; 32];
        let expected_secret = shared_key(&local_private, &remote_public);
        let expected_step =
            derive_signal_root_chain_keys(root_key.key.expose(), &expected_secret).unwrap();
        let dh_step = ratchet_signal_root_key(&root_key, &local_private, &remote_public).unwrap();
        assert_eq!(dh_step, expected_step);

        let prefixed_remote = prefixed_test_signal_key(8);
        assert_eq!(
            ratchet_signal_root_key(&root_key, &local_private, &prefixed_remote).unwrap(),
            expected_step
        );

        assert!(derive_signal_root_chain_keys(&[3u8; 31], &[4u8; 32]).is_err());
        assert!(derive_signal_root_chain_keys(&[3u8; 32], &[4u8; 31]).is_err());
        assert!(derive_signal_root_chain_keys(&[3u8; 32], &[0u8; 32]).is_err());
        assert!(ratchet_signal_root_key(&root_key, &[7u8; 31], &remote_public).is_err());
        assert!(ratchet_signal_root_key(&root_key, &local_private, &[8u8; 31]).is_err());
        assert!(ratchet_signal_root_key(&root_key, &local_private, &[0u8; 32]).is_err());
    }

    #[test]
    fn signal_pre_key_bootstrap_derives_initial_root_and_chain_keys() {
        let mut three_dh = signal_pre_key_secret_input();
        three_dh.extend_from_slice(&[1u8; 32]);
        three_dh.extend_from_slice(&[2u8; 32]);
        three_dh.extend_from_slice(&[3u8; 32]);
        let three_dh_step = derive_signal_pre_key_root_chain_keys(&three_dh).unwrap();
        assert_eq!(
            three_dh_step.root_key.key.expose(),
            &[
                0xc8, 0xce, 0x47, 0x41, 0x96, 0xf6, 0xb3, 0x23, 0x5c, 0xc3, 0xe0, 0xf7, 0x1e, 0x52,
                0x2b, 0xa8, 0x0b, 0x98, 0x63, 0x34, 0xfb, 0x41, 0xde, 0x8a, 0xd9, 0xea, 0x8c, 0xe8,
                0xd5, 0x8f, 0x17, 0x07,
            ]
        );
        assert_eq!(
            three_dh_step.chain_key.key.expose(),
            &[
                0xd4, 0x53, 0xda, 0x55, 0x21, 0xb9, 0x57, 0xda, 0x9e, 0x63, 0x2d, 0x9c, 0x51, 0x2b,
                0xfd, 0x01, 0x11, 0x49, 0x92, 0xab, 0xd9, 0xa3, 0x4e, 0xfb, 0xbc, 0x9a, 0x61, 0x8c,
                0x48, 0xdf, 0x45, 0x29,
            ]
        );
        assert_eq!(three_dh_step.chain_key.counter, 0);

        let mut four_dh = three_dh.clone();
        four_dh.extend_from_slice(&[4u8; 32]);
        let four_dh_step = derive_signal_pre_key_root_chain_keys(&four_dh).unwrap();
        assert_eq!(
            four_dh_step.root_key.key.expose(),
            &[
                0x0e, 0x18, 0x05, 0x6f, 0x1b, 0x09, 0x47, 0xb2, 0xbb, 0x35, 0x93, 0xb5, 0x6b, 0xaa,
                0x38, 0x31, 0x7b, 0xd4, 0xfe, 0xf7, 0xca, 0xb2, 0xef, 0x1e, 0x52, 0x85, 0x07, 0x69,
                0xc9, 0x15, 0x65, 0x0a,
            ]
        );
        assert_eq!(
            four_dh_step.chain_key.key.expose(),
            &[
                0x63, 0xe6, 0xd0, 0x44, 0xe3, 0xe4, 0x11, 0xfc, 0x8f, 0xf1, 0x06, 0xf0, 0xab, 0x77,
                0x9a, 0x74, 0x3e, 0x69, 0xba, 0x69, 0x7b, 0x94, 0x7c, 0xf3, 0x41, 0x52, 0x98, 0x80,
                0x9b, 0x05, 0xaf, 0xc1,
            ]
        );

        let mut bad_prefix = three_dh.clone();
        bad_prefix[0] = 0;
        assert!(derive_signal_pre_key_root_chain_keys(&bad_prefix).is_err());
        assert!(derive_signal_pre_key_root_chain_keys(&three_dh[..127]).is_err());
        let mut zero_agreement = three_dh;
        zero_agreement[32..64].fill(0);
        assert!(derive_signal_pre_key_root_chain_keys(&zero_agreement).is_err());
    }

    #[test]
    fn signal_pre_key_bootstrap_uses_outbound_and_inbound_x3dh_ordering() {
        let local_material = SignalLocalKeyMaterial {
            registration_id: 77,
            identity: SignalLocalIdentity {
                key_pair: test_key_pair(11),
                public_key: prefixed_test_signal_key(11),
            },
            signed_pre_key: SignalLocalSignedPreKey {
                key_id: 12,
                key_pair: test_key_pair(12),
                public_key: prefixed_test_signal_key(12),
                signature: Bytes::from(vec![13u8; 64]),
            },
        };
        let local_base_key = test_key_pair(14);
        let remote_session = SignalSession {
            registration_id: 99,
            identity_key: prefixed_test_signal_key(21),
            signed_pre_key: SignalSignedPreKey {
                key_id: 22,
                public_key: prefixed_test_signal_key(22),
                signature: Bytes::from(vec![23u8; 64]),
            },
            pre_key: Some(SignalPreKey {
                key_id: 24,
                public_key: prefixed_test_signal_key(24),
            }),
        };

        let mut expected_outbound = signal_pre_key_secret_input();
        append_signal_agreement(
            &mut expected_outbound,
            local_material.identity.key_pair.private.expose(),
            &remote_session.signed_pre_key.public_key,
        )
        .unwrap();
        append_signal_agreement(
            &mut expected_outbound,
            local_base_key.private.expose(),
            &remote_session.identity_key,
        )
        .unwrap();
        append_signal_agreement(
            &mut expected_outbound,
            local_base_key.private.expose(),
            &remote_session.signed_pre_key.public_key,
        )
        .unwrap();
        append_signal_agreement(
            &mut expected_outbound,
            local_base_key.private.expose(),
            &remote_session.pre_key.as_ref().unwrap().public_key,
        )
        .unwrap();
        let expected_outbound = derive_signal_pre_key_root_chain_keys(&expected_outbound).unwrap();

        let outbound = derive_signal_outbound_pre_key_root_chain_keys(
            &local_material,
            &local_base_key,
            &remote_session,
        )
        .unwrap();
        assert!(outbound.used_one_time_pre_key);
        assert_eq!(outbound.root_key, expected_outbound.root_key);
        assert_eq!(outbound.chain_key, expected_outbound.chain_key);

        let outbound_without_one_time = derive_signal_outbound_pre_key_root_chain_keys(
            &local_material,
            &local_base_key,
            &SignalSession {
                pre_key: None,
                ..remote_session.clone()
            },
        )
        .unwrap();
        assert!(!outbound_without_one_time.used_one_time_pre_key);

        let local_one_time_pre_key = SignalLocalPreKey {
            key_id: 31,
            key_pair: test_key_pair(31),
            public_key: prefixed_test_signal_key(31),
        };
        let remote_identity_key = prefixed_test_signal_key(41);
        let remote_base_key = prefixed_test_signal_key(42);
        let mut expected_inbound = signal_pre_key_secret_input();
        append_signal_agreement(
            &mut expected_inbound,
            local_material.signed_pre_key.key_pair.private.expose(),
            &remote_identity_key,
        )
        .unwrap();
        append_signal_agreement(
            &mut expected_inbound,
            local_material.identity.key_pair.private.expose(),
            &remote_base_key,
        )
        .unwrap();
        append_signal_agreement(
            &mut expected_inbound,
            local_material.signed_pre_key.key_pair.private.expose(),
            &remote_base_key,
        )
        .unwrap();
        append_signal_agreement(
            &mut expected_inbound,
            local_one_time_pre_key.key_pair.private.expose(),
            &remote_base_key,
        )
        .unwrap();
        let expected_inbound = derive_signal_pre_key_root_chain_keys(&expected_inbound).unwrap();

        let inbound = derive_signal_inbound_pre_key_root_chain_keys(
            &local_material,
            Some(&local_one_time_pre_key),
            &remote_identity_key,
            &remote_base_key,
        )
        .unwrap();
        assert!(inbound.used_one_time_pre_key);
        assert_eq!(inbound.root_key, expected_inbound.root_key);
        assert_eq!(inbound.chain_key, expected_inbound.chain_key);

        let inbound_without_one_time = derive_signal_inbound_pre_key_root_chain_keys(
            &local_material,
            None,
            &remote_identity_key,
            &remote_base_key,
        )
        .unwrap();
        assert!(!inbound_without_one_time.used_one_time_pre_key);
        assert!(
            derive_signal_inbound_pre_key_root_chain_keys(
                &local_material,
                None,
                &[0u8; 32],
                &remote_base_key,
            )
            .is_err()
        );
    }

    #[test]
    fn signal_signed_pre_key_verification_accepts_valid_bundle_and_rejects_tampering() {
        let remote_credentials = create_initial_credentials().unwrap();
        let remote_one_time_pre_key = generate_key_pair();
        let remote_session = SignalSession {
            registration_id: remote_credentials.registration_id,
            identity_key: Bytes::copy_from_slice(&remote_credentials.signed_identity_key.public),
            signed_pre_key: SignalSignedPreKey {
                key_id: remote_credentials.signed_pre_key.key_id,
                public_key: Bytes::copy_from_slice(
                    &remote_credentials.signed_pre_key.key_pair.public,
                ),
                signature: remote_credentials.signed_pre_key.signature.clone(),
            },
            pre_key: Some(SignalPreKey {
                key_id: 88,
                public_key: Bytes::copy_from_slice(&remote_one_time_pre_key.public),
            }),
        };

        verify_signal_signed_pre_key(&remote_session, &XEdDsaNoiseCertificateVerifier).unwrap();

        let local_credentials = create_initial_credentials().unwrap();
        let local_material = signal_local_key_material(local_credentials);
        let local_base_key = generate_key_pair();
        let verified = derive_verified_signal_outbound_pre_key_root_chain_keys(
            &local_material,
            &local_base_key,
            &remote_session,
            &XEdDsaNoiseCertificateVerifier,
        )
        .unwrap();
        let raw = derive_signal_outbound_pre_key_root_chain_keys(
            &local_material,
            &local_base_key,
            &remote_session,
        )
        .unwrap();
        assert_eq!(verified, raw);

        let mut tampered_signature = remote_session.clone();
        let mut signature = tampered_signature.signed_pre_key.signature.to_vec();
        signature[0] ^= 1;
        tampered_signature.signed_pre_key.signature = Bytes::from(signature);
        assert!(
            verify_signal_signed_pre_key(&tampered_signature, &XEdDsaNoiseCertificateVerifier)
                .is_err()
        );
        assert!(
            derive_verified_signal_outbound_pre_key_root_chain_keys(
                &local_material,
                &local_base_key,
                &tampered_signature,
                &XEdDsaNoiseCertificateVerifier,
            )
            .is_err()
        );

        let mut tampered_signed_pre_key = remote_session.clone();
        let mut public_key = tampered_signed_pre_key.signed_pre_key.public_key.to_vec();
        public_key[1] ^= 1;
        tampered_signed_pre_key.signed_pre_key.public_key = Bytes::from(public_key);
        assert!(
            verify_signal_signed_pre_key(&tampered_signed_pre_key, &XEdDsaNoiseCertificateVerifier)
                .is_err()
        );

        let mut short_signature = remote_session.clone();
        short_signature.signed_pre_key.signature =
            Bytes::copy_from_slice(&short_signature.signed_pre_key.signature[..63]);
        assert!(
            verify_signal_signed_pre_key(&short_signature, &XEdDsaNoiseCertificateVerifier)
                .is_err()
        );

        let mut invalid_identity = remote_session;
        invalid_identity.identity_key.truncate(31);
        assert!(
            verify_signal_signed_pre_key(&invalid_identity, &XEdDsaNoiseCertificateVerifier)
                .is_err()
        );
    }

    #[test]
    fn signal_signed_pre_key_verification_rejects_invalid_signature_length() {
        let remote_credentials = create_initial_credentials().unwrap();
        let remote_session = SignalSession {
            registration_id: remote_credentials.registration_id,
            identity_key: Bytes::copy_from_slice(&remote_credentials.signed_identity_key.public),
            signed_pre_key: SignalSignedPreKey {
                key_id: remote_credentials.signed_pre_key.key_id,
                public_key: Bytes::copy_from_slice(
                    &remote_credentials.signed_pre_key.key_pair.public,
                ),
                signature: Bytes::from(vec![0x22; 63]),
            },
            pre_key: None,
        };

        let err = verify_signal_signed_pre_key(&remote_session, &XEdDsaNoiseCertificateVerifier)
            .unwrap_err();
        assert!(matches!(
            err,
            CoreError::Protocol(message)
                if message == "invalid Signal signed pre-key signature length: 63"
        ));
    }

    #[test]
    fn signal_signed_pre_key_verification_rejects_invalid_identity_key_length() {
        let remote_credentials = create_initial_credentials().unwrap();
        let remote_session = SignalSession {
            registration_id: remote_credentials.registration_id,
            identity_key: Bytes::from(vec![0x05; 31]),
            signed_pre_key: SignalSignedPreKey {
                key_id: remote_credentials.signed_pre_key.key_id,
                public_key: Bytes::copy_from_slice(
                    &remote_credentials.signed_pre_key.key_pair.public,
                ),
                signature: remote_credentials.signed_pre_key.signature.clone(),
            },
            pre_key: None,
        };

        let err = verify_signal_signed_pre_key(&remote_session, &XEdDsaNoiseCertificateVerifier)
            .unwrap_err();
        assert!(matches!(
            err,
            CoreError::Protocol(message) if message == "invalid signal public key length: 31"
        ));
    }

    #[test]
    fn signal_signed_pre_key_verification_rejects_invalid_signed_public_key_length() {
        let remote_credentials = create_initial_credentials().unwrap();
        let remote_session = SignalSession {
            registration_id: remote_credentials.registration_id,
            identity_key: Bytes::copy_from_slice(&remote_credentials.signed_identity_key.public),
            signed_pre_key: SignalSignedPreKey {
                key_id: remote_credentials.signed_pre_key.key_id,
                public_key: Bytes::from(vec![0x05; 31]),
                signature: remote_credentials.signed_pre_key.signature.clone(),
            },
            pre_key: None,
        };

        let err = verify_signal_signed_pre_key(&remote_session, &XEdDsaNoiseCertificateVerifier)
            .unwrap_err();
        assert!(matches!(
            err,
            CoreError::Protocol(message) if message == "invalid signal public key length: 31"
        ));
    }

    #[test]
    fn signal_outbound_pre_key_session_rejects_invalid_one_time_pre_key_public_key_length() {
        let local_credentials = create_initial_credentials().unwrap();
        let local_material = signal_local_key_material(local_credentials);
        let local_base_key = generate_key_pair();
        let remote_credentials = create_initial_credentials().unwrap();
        let remote_session = SignalSession {
            registration_id: remote_credentials.registration_id,
            identity_key: Bytes::copy_from_slice(&remote_credentials.signed_identity_key.public),
            signed_pre_key: SignalSignedPreKey {
                key_id: remote_credentials.signed_pre_key.key_id,
                public_key: Bytes::copy_from_slice(
                    &remote_credentials.signed_pre_key.key_pair.public,
                ),
                signature: remote_credentials.signed_pre_key.signature.clone(),
            },
            pre_key: Some(SignalPreKey {
                key_id: 88,
                public_key: Bytes::from(vec![0x05; 31]),
            }),
        };

        let err = derive_signal_outbound_pre_key_root_chain_keys(
            &local_material,
            &local_base_key,
            &remote_session,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            CoreError::Protocol(message) if message == "invalid signal public key length: 31"
        ));
    }

    #[test]
    fn signal_sender_chain_ratchet_derives_message_keys_and_advances() {
        let chain_key = SignalSenderChainKey {
            key: SecretBytes::from(vec![1u8; 32]),
            iteration: 5,
        };

        let message_key_seed =
            derive_signal_sender_message_key_seed(chain_key.key.expose()).unwrap();
        assert_eq!(
            message_key_seed.expose(),
            &[
                0xcc, 0x6e, 0xfb, 0x87, 0x2c, 0x23, 0x7f, 0x56, 0x5e, 0xe8, 0x2d, 0xf4, 0x2e, 0x4c,
                0xab, 0x00, 0x09, 0x8b, 0x13, 0x71, 0x03, 0x95, 0xe3, 0xc6, 0xd2, 0x9f, 0x29, 0x07,
                0xd6, 0x9e, 0x4f, 0x04,
            ]
        );

        let next_chain_key = advance_signal_sender_chain_key(chain_key.key.expose()).unwrap();
        assert_eq!(
            next_chain_key.expose(),
            &[
                0xc3, 0x1d, 0x79, 0xab, 0xaf, 0x8f, 0x21, 0x50, 0xee, 0x1c, 0xfe, 0x3d, 0xc7, 0x32,
                0xee, 0xd0, 0x2a, 0x56, 0xf7, 0x96, 0x47, 0x90, 0x9b, 0xad, 0x05, 0x5a, 0x83, 0x1c,
                0xb7, 0x62, 0xe9, 0xa2,
            ]
        );

        let step = ratchet_signal_sender_chain(&chain_key).unwrap();
        assert_eq!(step.message_key.iteration, 5);
        assert_eq!(step.message_key.seed, message_key_seed);
        assert_eq!(
            step.message_key.iv,
            [
                0xb3, 0x3d, 0x1e, 0x55, 0x77, 0x76, 0xdc, 0xb6, 0x39, 0x83, 0x69, 0x9e, 0x51, 0x40,
                0xdd, 0x2d,
            ]
        );
        assert_eq!(
            step.message_key.cipher_key.expose(),
            &[
                0x7e, 0x5e, 0xe4, 0x5f, 0x1a, 0xa1, 0xf5, 0xe5, 0x08, 0x74, 0xbd, 0x77, 0xf4, 0x36,
                0x72, 0xb8, 0x97, 0xb4, 0xbf, 0xcc, 0x0f, 0x3c, 0x6a, 0xad, 0x91, 0xd7, 0x31, 0x61,
                0xef, 0xc3, 0xf4, 0xb6,
            ]
        );
        assert_eq!(step.next_chain_key.iteration, 6);
        assert_eq!(step.next_chain_key.key, next_chain_key);

        let encrypted =
            encrypt_signal_sender_message_body(b"group plaintext", &step.message_key).unwrap();
        assert_eq!(
            decrypt_signal_sender_message_body(&encrypted, &step.message_key).unwrap(),
            Bytes::from_static(b"group plaintext")
        );
        assert!(
            decrypt_signal_sender_message_body(
                &encrypted,
                &derive_signal_sender_message_keys(5, &[2u8; 32]).unwrap()
            )
            .is_err()
        );
        assert!(derive_signal_sender_message_key_seed(&[1u8; 31]).is_err());
        assert!(advance_signal_sender_chain_key(&[1u8; 31]).is_err());
        assert!(derive_signal_sender_message_keys(5, &[1u8; 31]).is_err());
        assert!(
            ratchet_signal_sender_chain(&SignalSenderChainKey {
                key: SecretBytes::from(vec![1u8; 32]),
                iteration: u32::MAX,
            })
            .is_err()
        );
    }

    #[test]
    fn signal_sender_key_distribution_message_encodes_and_decodes_wire_frame() {
        let signing_key = generate_key_pair();
        let chain_key = [7u8; 32];
        let message = build_signal_sender_key_distribution_message(
            0x0102_0304,
            9,
            &chain_key,
            &signing_key.public,
        )
        .unwrap();

        assert_eq!(message.message_version, SIGNAL_WIRE_CURRENT_VERSION);
        assert_eq!(message.key_id, 0x0102_0304);
        assert_eq!(message.iteration, 9);
        assert_eq!(message.chain_key.expose(), &chain_key);
        assert_eq!(
            message.signing_key,
            Bytes::copy_from_slice(&prefixed_signal_public_key(&signing_key.public))
        );

        let encoded = encode_signal_sender_key_distribution_message(&message).unwrap();
        assert_eq!(encoded[0], 0x33);

        let decoded = decode_signal_sender_key_distribution_message(&encoded).unwrap();
        assert_eq!(decoded, message);
        assert_eq!(
            encode_signal_sender_key_distribution_message(&decoded).unwrap(),
            encoded
        );

        let message_from_prefixed = build_signal_sender_key_distribution_message(
            0x0102_0304,
            9,
            &chain_key,
            &prefixed_signal_public_key(&signing_key.public),
        )
        .unwrap();
        assert_eq!(message_from_prefixed, message);
    }

    #[test]
    fn signal_sender_key_distribution_message_rejects_invalid_wire_frames() {
        assert!(decode_signal_sender_key_distribution_message(&[0x33]).is_err());
        assert!(
            build_signal_sender_key_distribution_message(7, 9, &[1u8; 31], &[2u8; 32]).is_err()
        );
        assert!(
            build_signal_sender_key_distribution_message(7, 9, &[1u8; 32], &[2u8; 31]).is_err()
        );

        let signing_key = generate_key_pair();
        let message =
            build_signal_sender_key_distribution_message(7, 9, &[1u8; 32], &signing_key.public)
                .unwrap();
        let encoded = encode_signal_sender_key_distribution_message(&message).unwrap();

        let mut bad_version = encoded.to_vec();
        bad_version[0] = 0x23;
        assert!(decode_signal_sender_key_distribution_message(&bad_version).is_err());

        let mut bad_ciphertext_version = encoded.to_vec();
        bad_ciphertext_version[0] = 0x32;
        assert!(decode_signal_sender_key_distribution_message(&bad_ciphertext_version).is_err());

        let mut missing_id = BytesMut::new();
        missing_id.put_u8(0x33);
        ProtoSenderKeyDistributionMessage {
            id: None,
            iteration: Some(9),
            chain_key: Some(Bytes::copy_from_slice(&[1u8; 32])),
            signing_key: Some(Bytes::copy_from_slice(&prefixed_signal_public_key(
                &signing_key.public,
            ))),
        }
        .encode(&mut missing_id)
        .unwrap();
        assert!(decode_signal_sender_key_distribution_message(&missing_id).is_err());

        let mut missing_iteration = BytesMut::new();
        missing_iteration.put_u8(0x33);
        ProtoSenderKeyDistributionMessage {
            id: Some(7),
            iteration: None,
            chain_key: Some(Bytes::copy_from_slice(&[1u8; 32])),
            signing_key: Some(Bytes::copy_from_slice(&prefixed_signal_public_key(
                &signing_key.public,
            ))),
        }
        .encode(&mut missing_iteration)
        .unwrap();
        let err = decode_signal_sender_key_distribution_message(&missing_iteration).unwrap_err();
        assert!(matches!(
            err,
            CoreError::Protocol(message)
                if message == "Signal sender-key distribution missing iteration"
        ));

        let mut missing_chain_key = BytesMut::new();
        missing_chain_key.put_u8(0x33);
        ProtoSenderKeyDistributionMessage {
            id: Some(7),
            iteration: Some(9),
            chain_key: None,
            signing_key: Some(Bytes::copy_from_slice(&prefixed_signal_public_key(
                &signing_key.public,
            ))),
        }
        .encode(&mut missing_chain_key)
        .unwrap();
        missing_chain_key.extend_from_slice(&[0x7a, 0x20]);
        missing_chain_key.extend_from_slice(&[0u8; SIGNAL_MESSAGE_KEY_LEN]);
        let err = decode_signal_sender_key_distribution_message(&missing_chain_key).unwrap_err();
        assert!(matches!(
            err,
            CoreError::Protocol(message)
                if message == "Signal sender-key distribution missing chain key"
        ));

        let mut missing_signing_key = BytesMut::new();
        missing_signing_key.put_u8(0x33);
        ProtoSenderKeyDistributionMessage {
            id: Some(7),
            iteration: Some(9),
            chain_key: Some(Bytes::copy_from_slice(&[1u8; 32])),
            signing_key: None,
        }
        .encode(&mut missing_signing_key)
        .unwrap();
        missing_signing_key.extend_from_slice(&[0x7a, 0x20]);
        missing_signing_key.extend_from_slice(&[0u8; SIGNAL_MESSAGE_KEY_LEN]);
        let err = decode_signal_sender_key_distribution_message(&missing_signing_key).unwrap_err();
        assert!(matches!(
            err,
            CoreError::Protocol(message)
                if message == "Signal sender-key distribution missing signing key"
        ));

        let mut short_chain_key = BytesMut::new();
        short_chain_key.put_u8(0x33);
        ProtoSenderKeyDistributionMessage {
            id: Some(7),
            iteration: Some(9),
            chain_key: Some(Bytes::copy_from_slice(&[1u8; 31])),
            signing_key: Some(Bytes::copy_from_slice(&prefixed_signal_public_key(
                &signing_key.public,
            ))),
        }
        .encode(&mut short_chain_key)
        .unwrap();
        assert!(decode_signal_sender_key_distribution_message(&short_chain_key).is_err());

        let mut raw_wire_signing_key = BytesMut::new();
        raw_wire_signing_key.put_u8(0x33);
        ProtoSenderKeyDistributionMessage {
            id: Some(7),
            iteration: Some(9),
            chain_key: Some(Bytes::copy_from_slice(&[1u8; 32])),
            signing_key: Some(Bytes::copy_from_slice(&signing_key.public)),
        }
        .encode(&mut raw_wire_signing_key)
        .unwrap();
        assert!(decode_signal_sender_key_distribution_message(&raw_wire_signing_key).is_err());

        let mut invalid_message = message;
        invalid_message.message_version = 2;
        assert!(encode_signal_sender_key_distribution_message(&invalid_message).is_err());
    }

    #[test]
    fn signal_sender_key_record_processes_distribution_and_preserves_matching_state() {
        let signing_key_a = generate_key_pair();
        let signing_key_b = generate_key_pair();
        let distribution_a =
            build_signal_sender_key_distribution_message(11, 7, &[1u8; 32], &signing_key_a.public)
                .unwrap();

        let encoded = process_signal_sender_key_distribution_record(None, &distribution_a).unwrap();
        let record = decode_signal_sender_key_record(&encoded).unwrap();
        assert_eq!(record.states.len(), 1);
        assert_eq!(record.states[0].key_id, 11);
        assert_eq!(record.states[0].chain_key.iteration, 7);
        assert_eq!(record.states[0].chain_key.key.expose(), &[1u8; 32]);
        assert_eq!(record.states[0].message_keys, Vec::new());
        assert_eq!(record.states[0].signing_private_key, None);
        assert_eq!(
            record.states[0].signing_public_key,
            distribution_a.signing_key
        );

        let existing = SignalSenderKeyRecord {
            states: vec![
                SignalSenderKeyState {
                    key_id: 11,
                    chain_key: SignalSenderChainKey {
                        key: SecretBytes::from(vec![9u8; 32]),
                        iteration: 99,
                    },
                    signing_public_key: Bytes::copy_from_slice(&prefixed_signal_public_key(
                        &signing_key_a.public,
                    )),
                    signing_private_key: Some(SecretBytes::from(
                        signing_key_a.private.expose().to_vec(),
                    )),
                    message_keys: vec![SignalSenderStoredMessageKey {
                        iteration: 12,
                        seed: SecretBytes::from(vec![5u8; 32]),
                    }],
                },
                SignalSenderKeyState {
                    key_id: 11,
                    chain_key: SignalSenderChainKey {
                        key: SecretBytes::from(vec![2u8; 32]),
                        iteration: 2,
                    },
                    signing_public_key: Bytes::copy_from_slice(&prefixed_signal_public_key(
                        &signing_key_b.public,
                    )),
                    signing_private_key: None,
                    message_keys: Vec::new(),
                },
                SignalSenderKeyState {
                    key_id: 12,
                    chain_key: SignalSenderChainKey {
                        key: SecretBytes::from(vec![3u8; 32]),
                        iteration: 3,
                    },
                    signing_public_key: Bytes::copy_from_slice(&prefixed_signal_public_key(
                        &signing_key_b.public,
                    )),
                    signing_private_key: None,
                    message_keys: Vec::new(),
                },
            ],
        };
        let existing = encode_signal_sender_key_record(&existing).unwrap();
        let updated =
            process_signal_sender_key_distribution_record(Some(&existing), &distribution_a)
                .unwrap();
        let updated = decode_signal_sender_key_record(&updated).unwrap();
        assert_eq!(updated.states.len(), 2);
        assert_eq!(updated.states[0].key_id, 11);
        assert_eq!(updated.states[0].chain_key.iteration, 99);
        assert_eq!(updated.states[0].chain_key.key.expose(), &[9u8; 32]);
        assert!(updated.states[0].signing_private_key.is_some());
        assert_eq!(updated.states[0].message_keys.len(), 1);
        assert_eq!(updated.states[0].message_keys[0].iteration, 12);
        assert_eq!(updated.states[1].key_id, 12);

        let newer_distribution_a = build_signal_sender_key_distribution_message(
            11,
            101,
            &[4u8; 32],
            &signing_key_a.public,
        )
        .unwrap();
        let newer = encode_signal_sender_key_record(&updated).unwrap();
        let newer =
            process_signal_sender_key_distribution_record(Some(&newer), &newer_distribution_a)
                .unwrap();
        let newer = decode_signal_sender_key_record(&newer).unwrap();
        assert_eq!(newer.states.len(), 2);
        assert_eq!(newer.states[0].key_id, 11);
        assert_eq!(newer.states[0].chain_key.iteration, 101);
        assert_eq!(newer.states[0].chain_key.key.expose(), &[4u8; 32]);
        assert!(newer.states[0].signing_private_key.is_some());
        assert_eq!(newer.states[0].message_keys.len(), 1);
        assert_eq!(newer.states[0].message_keys[0].iteration, 12);
        assert_eq!(newer.states[1].key_id, 12);

        let stale_distribution_a = build_signal_sender_key_distribution_message(
            11,
            100,
            &[5u8; 32],
            &signing_key_a.public,
        )
        .unwrap();
        let stale = encode_signal_sender_key_record(&newer).unwrap();
        let stale =
            process_signal_sender_key_distribution_record(Some(&stale), &stale_distribution_a)
                .unwrap();
        let stale = decode_signal_sender_key_record(&stale).unwrap();
        assert_eq!(stale.states[0].chain_key.iteration, 101);
        assert_eq!(stale.states[0].chain_key.key.expose(), &[4u8; 32]);

        let distribution_b =
            build_signal_sender_key_distribution_message(11, 8, &[6u8; 32], &signing_key_b.public)
                .unwrap();
        let replaced = encode_signal_sender_key_record(&stale).unwrap();
        let replaced =
            process_signal_sender_key_distribution_record(Some(&replaced), &distribution_b)
                .unwrap();
        let replaced = decode_signal_sender_key_record(&replaced).unwrap();
        assert_eq!(replaced.states.len(), 2);
        assert_eq!(replaced.states[0].key_id, 11);
        assert_eq!(replaced.states[0].chain_key.iteration, 8);
        assert_eq!(replaced.states[0].chain_key.key.expose(), &[6u8; 32]);
        assert_eq!(replaced.states[0].signing_private_key, None);
        assert_eq!(replaced.states[0].message_keys, Vec::new());
        assert_eq!(
            replaced.states[0].signing_public_key,
            distribution_b.signing_key
        );
        assert_eq!(replaced.states[1].key_id, 12);
    }

    #[test]
    fn signal_sender_key_record_rejects_malformed_state() {
        let signing_key = generate_key_pair();
        let too_many_states = SignalSenderKeyRecord {
            states: (0..=SIGNAL_MAX_SENDER_KEY_STATES)
                .map(|key_id| SignalSenderKeyState {
                    key_id: key_id as u32,
                    chain_key: SignalSenderChainKey {
                        key: SecretBytes::from(vec![key_id as u8; 32]),
                        iteration: key_id as u32,
                    },
                    signing_public_key: Bytes::copy_from_slice(&prefixed_signal_public_key(
                        &signing_key.public,
                    )),
                    signing_private_key: None,
                    message_keys: Vec::new(),
                })
                .collect(),
        };
        assert!(encode_signal_sender_key_record(&too_many_states).is_err());

        let missing_chain = SenderKeyRecordStructure {
            sender_key_states: vec![SenderKeyStateStructure {
                sender_key_id: Some(7),
                sender_chain_key: None,
                sender_signing_key: Some(sender_key_state_structure::SenderSigningKey {
                    public: Some(Bytes::copy_from_slice(&prefixed_signal_public_key(
                        &signing_key.public,
                    ))),
                    private: None,
                }),
                sender_message_keys: Vec::new(),
            }],
        }
        .encode_to_vec();
        assert!(decode_signal_sender_key_record(&missing_chain).is_err());

        let raw_signing_key = SenderKeyRecordStructure {
            sender_key_states: vec![SenderKeyStateStructure {
                sender_key_id: Some(7),
                sender_chain_key: Some(sender_key_state_structure::SenderChainKey {
                    iteration: Some(9),
                    seed: Some(Bytes::copy_from_slice(&[1u8; 32])),
                }),
                sender_signing_key: Some(sender_key_state_structure::SenderSigningKey {
                    public: Some(Bytes::copy_from_slice(&signing_key.public)),
                    private: None,
                }),
                sender_message_keys: Vec::new(),
            }],
        }
        .encode_to_vec();
        assert!(decode_signal_sender_key_record(&raw_signing_key).is_err());

        let duplicate_state = SignalSenderKeyRecord {
            states: vec![
                SignalSenderKeyState {
                    key_id: 7,
                    chain_key: SignalSenderChainKey {
                        key: SecretBytes::from(vec![1u8; 32]),
                        iteration: 9,
                    },
                    signing_public_key: Bytes::copy_from_slice(&signing_key.public),
                    signing_private_key: None,
                    message_keys: Vec::new(),
                },
                SignalSenderKeyState {
                    key_id: 7,
                    chain_key: SignalSenderChainKey {
                        key: SecretBytes::from(vec![2u8; 32]),
                        iteration: 10,
                    },
                    signing_public_key: Bytes::copy_from_slice(&prefixed_signal_public_key(
                        &signing_key.public,
                    )),
                    signing_private_key: None,
                    message_keys: Vec::new(),
                },
            ],
        };
        let err = encode_signal_sender_key_record(&duplicate_state).unwrap_err();
        assert!(matches!(
            err,
            CoreError::Protocol(message) if message == "duplicate Signal sender-key state"
        ));

        let duplicate_state_wire = SenderKeyRecordStructure {
            sender_key_states: vec![
                SenderKeyStateStructure {
                    sender_key_id: Some(7),
                    sender_chain_key: Some(sender_key_state_structure::SenderChainKey {
                        iteration: Some(9),
                        seed: Some(Bytes::copy_from_slice(&[1u8; 32])),
                    }),
                    sender_signing_key: Some(sender_key_state_structure::SenderSigningKey {
                        public: Some(Bytes::copy_from_slice(&prefixed_signal_public_key(
                            &signing_key.public,
                        ))),
                        private: None,
                    }),
                    sender_message_keys: Vec::new(),
                },
                SenderKeyStateStructure {
                    sender_key_id: Some(7),
                    sender_chain_key: Some(sender_key_state_structure::SenderChainKey {
                        iteration: Some(10),
                        seed: Some(Bytes::copy_from_slice(&[2u8; 32])),
                    }),
                    sender_signing_key: Some(sender_key_state_structure::SenderSigningKey {
                        public: Some(Bytes::copy_from_slice(&prefixed_signal_public_key(
                            &signing_key.public,
                        ))),
                        private: None,
                    }),
                    sender_message_keys: Vec::new(),
                },
            ],
        }
        .encode_to_vec();
        let err = decode_signal_sender_key_record(&duplicate_state_wire).unwrap_err();
        assert!(matches!(
            err,
            CoreError::Protocol(message) if message == "duplicate Signal sender-key state"
        ));

        let other_signing_key = generate_key_pair();
        let mismatched_signing_key = SignalSenderKeyRecord {
            states: vec![SignalSenderKeyState {
                key_id: 7,
                chain_key: SignalSenderChainKey {
                    key: SecretBytes::from(vec![1u8; 32]),
                    iteration: 9,
                },
                signing_public_key: Bytes::copy_from_slice(&prefixed_signal_public_key(
                    &other_signing_key.public,
                )),
                signing_private_key: Some(SecretBytes::from(signing_key.private.expose().to_vec())),
                message_keys: Vec::new(),
            }],
        };
        let err = encode_signal_sender_key_record(&mismatched_signing_key).unwrap_err();
        assert!(matches!(
            err,
            CoreError::Protocol(message)
                if message == "Signal sender-key signing public key does not match private key"
        ));

        let mismatched_signing_key_wire = SenderKeyRecordStructure {
            sender_key_states: vec![SenderKeyStateStructure {
                sender_key_id: Some(7),
                sender_chain_key: Some(sender_key_state_structure::SenderChainKey {
                    iteration: Some(9),
                    seed: Some(Bytes::copy_from_slice(&[1u8; 32])),
                }),
                sender_signing_key: Some(sender_key_state_structure::SenderSigningKey {
                    public: Some(Bytes::copy_from_slice(&prefixed_signal_public_key(
                        &other_signing_key.public,
                    ))),
                    private: Some(Bytes::copy_from_slice(signing_key.private.expose())),
                }),
                sender_message_keys: Vec::new(),
            }],
        }
        .encode_to_vec();
        let err = decode_signal_sender_key_record(&mismatched_signing_key_wire).unwrap_err();
        assert!(matches!(
            err,
            CoreError::Protocol(message)
                if message == "Signal sender-key signing public key does not match private key"
        ));

        let short_message_key = SenderKeyRecordStructure {
            sender_key_states: vec![SenderKeyStateStructure {
                sender_key_id: Some(7),
                sender_chain_key: Some(sender_key_state_structure::SenderChainKey {
                    iteration: Some(9),
                    seed: Some(Bytes::copy_from_slice(&[1u8; 32])),
                }),
                sender_signing_key: Some(sender_key_state_structure::SenderSigningKey {
                    public: Some(Bytes::copy_from_slice(&prefixed_signal_public_key(
                        &signing_key.public,
                    ))),
                    private: None,
                }),
                sender_message_keys: vec![sender_key_state_structure::SenderMessageKey {
                    iteration: Some(10),
                    seed: Some(Bytes::copy_from_slice(&[2u8; 31])),
                }],
            }],
        }
        .encode_to_vec();
        assert!(decode_signal_sender_key_record(&short_message_key).is_err());

        let duplicate_skipped = SignalSenderKeyRecord {
            states: vec![SignalSenderKeyState {
                key_id: 7,
                chain_key: SignalSenderChainKey {
                    key: SecretBytes::from(vec![1u8; 32]),
                    iteration: 9,
                },
                signing_public_key: Bytes::copy_from_slice(&prefixed_signal_public_key(
                    &signing_key.public,
                )),
                signing_private_key: None,
                message_keys: vec![
                    SignalSenderStoredMessageKey {
                        iteration: 3,
                        seed: SecretBytes::from(vec![2u8; 32]),
                    },
                    SignalSenderStoredMessageKey {
                        iteration: 3,
                        seed: SecretBytes::from(vec![3u8; 32]),
                    },
                ],
            }],
        };
        let err = encode_signal_sender_key_record(&duplicate_skipped).unwrap_err();
        assert!(matches!(
            err,
            CoreError::Protocol(message)
                if message == "duplicate Signal sender-key skipped message iteration"
        ));

        let future_skipped = SignalSenderKeyRecord {
            states: vec![SignalSenderKeyState {
                key_id: 7,
                chain_key: SignalSenderChainKey {
                    key: SecretBytes::from(vec![1u8; 32]),
                    iteration: 9,
                },
                signing_public_key: Bytes::copy_from_slice(&prefixed_signal_public_key(
                    &signing_key.public,
                )),
                signing_private_key: None,
                message_keys: vec![SignalSenderStoredMessageKey {
                    iteration: 9,
                    seed: SecretBytes::from(vec![2u8; 32]),
                }],
            }],
        };
        let err = encode_signal_sender_key_record(&future_skipped).unwrap_err();
        assert!(matches!(
            err,
            CoreError::Protocol(message)
                if message == "Signal sender-key skipped iteration must be below chain iteration"
        ));

        let duplicate_skipped_wire = SenderKeyRecordStructure {
            sender_key_states: vec![SenderKeyStateStructure {
                sender_key_id: Some(7),
                sender_chain_key: Some(sender_key_state_structure::SenderChainKey {
                    iteration: Some(9),
                    seed: Some(Bytes::copy_from_slice(&[1u8; 32])),
                }),
                sender_signing_key: Some(sender_key_state_structure::SenderSigningKey {
                    public: Some(Bytes::copy_from_slice(&prefixed_signal_public_key(
                        &signing_key.public,
                    ))),
                    private: None,
                }),
                sender_message_keys: vec![
                    sender_key_state_structure::SenderMessageKey {
                        iteration: Some(3),
                        seed: Some(Bytes::copy_from_slice(&[2u8; 32])),
                    },
                    sender_key_state_structure::SenderMessageKey {
                        iteration: Some(3),
                        seed: Some(Bytes::copy_from_slice(&[3u8; 32])),
                    },
                ],
            }],
        }
        .encode_to_vec();
        let err = decode_signal_sender_key_record(&duplicate_skipped_wire).unwrap_err();
        assert!(matches!(
            err,
            CoreError::Protocol(message)
                if message == "duplicate Signal sender-key skipped message iteration"
        ));

        let future_skipped_wire = SenderKeyRecordStructure {
            sender_key_states: vec![SenderKeyStateStructure {
                sender_key_id: Some(7),
                sender_chain_key: Some(sender_key_state_structure::SenderChainKey {
                    iteration: Some(9),
                    seed: Some(Bytes::copy_from_slice(&[1u8; 32])),
                }),
                sender_signing_key: Some(sender_key_state_structure::SenderSigningKey {
                    public: Some(Bytes::copy_from_slice(&prefixed_signal_public_key(
                        &signing_key.public,
                    ))),
                    private: None,
                }),
                sender_message_keys: vec![sender_key_state_structure::SenderMessageKey {
                    iteration: Some(9),
                    seed: Some(Bytes::copy_from_slice(&[2u8; 32])),
                }],
            }],
        }
        .encode_to_vec();
        let err = decode_signal_sender_key_record(&future_skipped_wire).unwrap_err();
        assert!(matches!(
            err,
            CoreError::Protocol(message)
                if message == "Signal sender-key skipped iteration must be below chain iteration"
        ));
    }

    #[test]
    fn signal_sender_key_record_rejects_missing_required_wire_fields() {
        let signing_key = generate_key_pair();
        let valid_chain_key = sender_key_state_structure::SenderChainKey {
            iteration: Some(9),
            seed: Some(Bytes::copy_from_slice(&[1u8; SIGNAL_MESSAGE_KEY_LEN])),
        };
        let valid_signing_key = sender_key_state_structure::SenderSigningKey {
            public: Some(Bytes::copy_from_slice(&prefixed_signal_public_key(
                &signing_key.public,
            ))),
            private: None,
        };
        let decode_state = |state: SenderKeyStateStructure| {
            decode_signal_sender_key_record(
                &SenderKeyRecordStructure {
                    sender_key_states: vec![state],
                }
                .encode_to_vec(),
            )
        };

        let err = decode_state(SenderKeyStateStructure {
            sender_key_id: None,
            sender_chain_key: Some(valid_chain_key.clone()),
            sender_signing_key: Some(valid_signing_key.clone()),
            sender_message_keys: Vec::new(),
        })
        .unwrap_err();
        assert!(matches!(
            err,
            CoreError::Protocol(message) if message == "Signal sender-key state missing id"
        ));

        let err = decode_state(SenderKeyStateStructure {
            sender_key_id: Some(7),
            sender_chain_key: None,
            sender_signing_key: Some(valid_signing_key.clone()),
            sender_message_keys: Vec::new(),
        })
        .unwrap_err();
        assert!(matches!(
            err,
            CoreError::Protocol(message)
                if message == "Signal sender-key state missing chain key"
        ));

        let err = decode_state(SenderKeyStateStructure {
            sender_key_id: Some(7),
            sender_chain_key: Some(sender_key_state_structure::SenderChainKey {
                iteration: Some(9),
                seed: None,
            }),
            sender_signing_key: Some(valid_signing_key.clone()),
            sender_message_keys: Vec::new(),
        })
        .unwrap_err();
        assert!(matches!(
            err,
            CoreError::Protocol(message)
                if message == "Signal sender-key state missing chain key seed"
        ));

        let err = decode_state(SenderKeyStateStructure {
            sender_key_id: Some(7),
            sender_chain_key: Some(sender_key_state_structure::SenderChainKey {
                iteration: None,
                seed: Some(Bytes::copy_from_slice(&[1u8; SIGNAL_MESSAGE_KEY_LEN])),
            }),
            sender_signing_key: Some(valid_signing_key.clone()),
            sender_message_keys: Vec::new(),
        })
        .unwrap_err();
        assert!(matches!(
            err,
            CoreError::Protocol(message)
                if message == "Signal sender-key state missing chain iteration"
        ));

        let err = decode_state(SenderKeyStateStructure {
            sender_key_id: Some(7),
            sender_chain_key: Some(valid_chain_key.clone()),
            sender_signing_key: None,
            sender_message_keys: Vec::new(),
        })
        .unwrap_err();
        assert!(matches!(
            err,
            CoreError::Protocol(message)
                if message == "Signal sender-key state missing signing key"
        ));

        let err = decode_state(SenderKeyStateStructure {
            sender_key_id: Some(7),
            sender_chain_key: Some(valid_chain_key.clone()),
            sender_signing_key: Some(sender_key_state_structure::SenderSigningKey {
                public: None,
                private: None,
            }),
            sender_message_keys: Vec::new(),
        })
        .unwrap_err();
        assert!(matches!(
            err,
            CoreError::Protocol(message)
                if message == "Signal sender-key state missing signing public key"
        ));

        let err = decode_state(SenderKeyStateStructure {
            sender_key_id: Some(7),
            sender_chain_key: Some(valid_chain_key.clone()),
            sender_signing_key: Some(valid_signing_key.clone()),
            sender_message_keys: vec![sender_key_state_structure::SenderMessageKey {
                iteration: None,
                seed: Some(Bytes::copy_from_slice(&[2u8; SIGNAL_MESSAGE_KEY_LEN])),
            }],
        })
        .unwrap_err();
        assert!(matches!(
            err,
            CoreError::Protocol(message)
                if message == "Signal sender-key message key missing iteration"
        ));

        let err = decode_state(SenderKeyStateStructure {
            sender_key_id: Some(7),
            sender_chain_key: Some(valid_chain_key),
            sender_signing_key: Some(valid_signing_key),
            sender_message_keys: vec![sender_key_state_structure::SenderMessageKey {
                iteration: Some(4),
                seed: None,
            }],
        })
        .unwrap_err();
        assert!(matches!(
            err,
            CoreError::Protocol(message)
                if message == "Signal sender-key message key missing seed"
        ));
    }

    #[test]
    fn signal_sender_key_record_encrypts_and_decrypts_with_state_updates() {
        let signing_key = generate_key_pair();
        let sender_record = SignalSenderKeyRecord {
            states: vec![SignalSenderKeyState {
                key_id: 77,
                chain_key: SignalSenderChainKey {
                    key: SecretBytes::from(vec![4u8; 32]),
                    iteration: 0,
                },
                signing_public_key: Bytes::copy_from_slice(&prefixed_signal_public_key(
                    &signing_key.public,
                )),
                signing_private_key: Some(SecretBytes::from(signing_key.private.expose().to_vec())),
                message_keys: Vec::new(),
            }],
        };
        let sender_record = encode_signal_sender_key_record(&sender_record).unwrap();
        let encrypted =
            encrypt_signal_sender_key_record_message(&sender_record, b"group plaintext").unwrap();
        assert_eq!(encrypted.message.key_id, 77);
        assert_eq!(encrypted.message.iteration, 0);
        assert_eq!(
            decode_signal_sender_key_record(&encrypted.record)
                .unwrap()
                .states[0]
                .chain_key
                .iteration,
            1
        );
        assert!(
            encrypt_signal_sender_key_record_message(&encrypted.record, b"next plaintext").is_ok()
        );

        let distribution =
            build_signal_sender_key_distribution_message(77, 0, &[4u8; 32], &signing_key.public)
                .unwrap();
        let receiver_record =
            process_signal_sender_key_distribution_record(None, &distribution).unwrap();
        let decrypted = decrypt_signal_sender_key_record_message(
            &receiver_record,
            &encrypted.message_bytes,
            &XEdDsaNoiseCertificateVerifier,
        )
        .unwrap();
        assert_eq!(decrypted.message, encrypted.message);
        assert_eq!(decrypted.plaintext, Bytes::from_static(b"group plaintext"));
        let updated_receiver = decode_signal_sender_key_record(&decrypted.record).unwrap();
        assert_eq!(updated_receiver.states[0].chain_key.iteration, 1);
        assert!(updated_receiver.states[0].message_keys.is_empty());
        assert!(
            decrypt_signal_sender_key_record_message(
                &decrypted.record,
                &encrypted.message_bytes,
                &XEdDsaNoiseCertificateVerifier,
            )
            .is_err()
        );
    }

    #[test]
    fn signal_sender_key_record_decrypts_out_of_order_with_skipped_keys() {
        let signing_key = generate_key_pair();
        let sender_record = encode_signal_sender_key_record(&SignalSenderKeyRecord {
            states: vec![SignalSenderKeyState {
                key_id: 88,
                chain_key: SignalSenderChainKey {
                    key: SecretBytes::from(vec![6u8; 32]),
                    iteration: 0,
                },
                signing_public_key: Bytes::copy_from_slice(&prefixed_signal_public_key(
                    &signing_key.public,
                )),
                signing_private_key: Some(SecretBytes::from(signing_key.private.expose().to_vec())),
                message_keys: Vec::new(),
            }],
        })
        .unwrap();
        let first = encrypt_signal_sender_key_record_message(&sender_record, b"first").unwrap();
        let second = encrypt_signal_sender_key_record_message(&first.record, b"second").unwrap();
        assert_eq!(first.message.iteration, 0);
        assert_eq!(second.message.iteration, 1);

        let distribution =
            build_signal_sender_key_distribution_message(88, 0, &[6u8; 32], &signing_key.public)
                .unwrap();
        let receiver_record =
            process_signal_sender_key_distribution_record(None, &distribution).unwrap();
        let second_decrypted = decrypt_signal_sender_key_record_message(
            &receiver_record,
            &second.message_bytes,
            &XEdDsaNoiseCertificateVerifier,
        )
        .unwrap();
        assert_eq!(second_decrypted.plaintext, Bytes::from_static(b"second"));
        let receiver_after_second =
            decode_signal_sender_key_record(&second_decrypted.record).unwrap();
        assert_eq!(receiver_after_second.states[0].chain_key.iteration, 2);
        assert_eq!(receiver_after_second.states[0].message_keys.len(), 1);
        assert_eq!(receiver_after_second.states[0].message_keys[0].iteration, 0);

        let first_decrypted = decrypt_signal_sender_key_record_message(
            &second_decrypted.record,
            &first.message_bytes,
            &XEdDsaNoiseCertificateVerifier,
        )
        .unwrap();
        assert_eq!(first_decrypted.plaintext, Bytes::from_static(b"first"));
        let receiver_after_first =
            decode_signal_sender_key_record(&first_decrypted.record).unwrap();
        assert!(receiver_after_first.states[0].message_keys.is_empty());
        assert!(
            decrypt_signal_sender_key_record_message(
                &first_decrypted.record,
                &first.message_bytes,
                &XEdDsaNoiseCertificateVerifier,
            )
            .is_err()
        );
    }

    #[test]
    fn signal_sender_key_stored_message_key_lookup_does_not_consume_before_decrypt() {
        let signing_key = generate_key_pair();
        let mut state = SignalSenderKeyState {
            key_id: 88,
            chain_key: SignalSenderChainKey {
                key: SecretBytes::from(vec![6u8; 32]),
                iteration: 2,
            },
            signing_public_key: Bytes::copy_from_slice(&prefixed_signal_public_key(
                &signing_key.public,
            )),
            signing_private_key: None,
            message_keys: vec![SignalSenderStoredMessageKey {
                iteration: 0,
                seed: SecretBytes::from(vec![7u8; 32]),
            }],
        };

        let lookup = signal_sender_message_key_for_iteration(&mut state, 0).unwrap();
        assert_eq!(state.message_keys.len(), 1);
        assert_eq!(state.message_keys[0].iteration, 0);
        match lookup {
            SignalSenderMessageKeyLookup::Stored { index, .. } => {
                state.message_keys.remove(index);
            }
            SignalSenderMessageKeyLookup::Current(_) => {
                panic!("stored sender-key message key lookup returned current key")
            }
        }
        assert!(state.message_keys.is_empty());
    }

    #[test]
    fn signal_sender_key_record_decrypts_later_matching_key_id_state() {
        let signing_key = generate_key_pair();
        let wrong_signing_key = generate_key_pair();
        let sender_record = encode_signal_sender_key_record(&SignalSenderKeyRecord {
            states: vec![SignalSenderKeyState {
                key_id: 88,
                chain_key: SignalSenderChainKey {
                    key: SecretBytes::from(vec![6u8; 32]),
                    iteration: 0,
                },
                signing_public_key: Bytes::copy_from_slice(&prefixed_signal_public_key(
                    &signing_key.public,
                )),
                signing_private_key: Some(SecretBytes::from(signing_key.private.expose().to_vec())),
                message_keys: Vec::new(),
            }],
        })
        .unwrap();
        let encrypted =
            encrypt_signal_sender_key_record_message(&sender_record, b"matching state").unwrap();
        let distribution =
            build_signal_sender_key_distribution_message(88, 0, &[6u8; 32], &signing_key.public)
                .unwrap();
        let receiver_record =
            process_signal_sender_key_distribution_record(None, &distribution).unwrap();
        let mut receiver_record = decode_signal_sender_key_record(&receiver_record).unwrap();
        let wrong_signing_public_key =
            Bytes::copy_from_slice(&prefixed_signal_public_key(&wrong_signing_key.public));
        receiver_record.states.insert(
            0,
            SignalSenderKeyState {
                key_id: 88,
                chain_key: SignalSenderChainKey {
                    key: SecretBytes::from(vec![9u8; 32]),
                    iteration: 0,
                },
                signing_public_key: wrong_signing_public_key.clone(),
                signing_private_key: None,
                message_keys: Vec::new(),
            },
        );
        let receiver_record = encode_signal_sender_key_record(&receiver_record).unwrap();

        let decrypted = decrypt_signal_sender_key_record_message(
            &receiver_record,
            &encrypted.message_bytes,
            &XEdDsaNoiseCertificateVerifier,
        )
        .unwrap();
        assert_eq!(decrypted.plaintext, Bytes::from_static(b"matching state"));
        let updated_receiver = decode_signal_sender_key_record(&decrypted.record).unwrap();
        assert_eq!(updated_receiver.states.len(), 2);
        assert_eq!(
            updated_receiver.states[0].signing_public_key,
            wrong_signing_public_key
        );
        assert_eq!(updated_receiver.states[0].chain_key.iteration, 0);
        assert_eq!(
            updated_receiver.states[1].signing_public_key,
            distribution.signing_key
        );
        assert_eq!(updated_receiver.states[1].chain_key.iteration, 1);
        assert!(updated_receiver.states[1].message_keys.is_empty());
    }

    #[test]
    fn signal_sender_key_record_rejects_far_future_iteration() {
        let signing_key = generate_key_pair();
        let sender_record = encode_signal_sender_key_record(&SignalSenderKeyRecord {
            states: vec![SignalSenderKeyState {
                key_id: 88,
                chain_key: SignalSenderChainKey {
                    key: SecretBytes::from(vec![6u8; 32]),
                    iteration: 0,
                },
                signing_public_key: Bytes::copy_from_slice(&prefixed_signal_public_key(
                    &signing_key.public,
                )),
                signing_private_key: Some(SecretBytes::from(signing_key.private.expose().to_vec())),
                message_keys: Vec::new(),
            }],
        })
        .unwrap();
        let first = encrypt_signal_sender_key_record_message(&sender_record, b"first").unwrap();
        let distribution =
            build_signal_sender_key_distribution_message(88, 0, &[6u8; 32], &signing_key.public)
                .unwrap();
        let receiver_record =
            process_signal_sender_key_distribution_record(None, &distribution).unwrap();
        let far_future = sign_signal_sender_key_message(
            88,
            SIGNAL_MAX_SENDER_FORWARD_JUMPS + 1,
            Bytes::from_static(b"far-future-ciphertext"),
            signing_key.private.expose(),
        )
        .unwrap();
        let far_future = encode_signal_sender_key_message(&far_future).unwrap();

        let err = decrypt_signal_sender_key_record_message(
            &receiver_record,
            &far_future,
            &XEdDsaNoiseCertificateVerifier,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            CoreError::Protocol(message)
                if message == "Signal sender-key message is too far in the future: 25001"
        ));

        let decrypted = decrypt_signal_sender_key_record_message(
            &receiver_record,
            &first.message_bytes,
            &XEdDsaNoiseCertificateVerifier,
        )
        .unwrap();
        assert_eq!(decrypted.plaintext, Bytes::from_static(b"first"));
    }

    #[test]
    fn signal_sender_key_record_prunes_oldest_skipped_message_keys() {
        let signing_key = generate_key_pair();
        let target_iteration = u32::try_from(SIGNAL_MAX_SENDER_MESSAGE_KEYS).unwrap() + 1;
        let mut chain = SignalSenderChainKey {
            key: SecretBytes::from(vec![6u8; 32]),
            iteration: 0,
        };
        let mut first_keys = None;
        let mut second_keys = None;
        let mut target_keys = None;
        while chain.iteration <= target_iteration {
            let step = ratchet_signal_sender_chain(&chain).unwrap();
            match step.message_key.iteration {
                0 => first_keys = Some(step.message_key.clone()),
                1 => second_keys = Some(step.message_key.clone()),
                value if value == target_iteration => target_keys = Some(step.message_key.clone()),
                _ => {}
            }
            chain = step.next_chain_key;
        }
        let first_keys = first_keys.unwrap();
        let second_keys = second_keys.unwrap();
        let target_keys = target_keys.unwrap();
        let first = sign_signal_sender_key_message(
            88,
            0,
            encrypt_signal_sender_message_body(b"first", &first_keys).unwrap(),
            signing_key.private.expose(),
        )
        .unwrap();
        let first = encode_signal_sender_key_message(&first).unwrap();
        let second = sign_signal_sender_key_message(
            88,
            1,
            encrypt_signal_sender_message_body(b"second", &second_keys).unwrap(),
            signing_key.private.expose(),
        )
        .unwrap();
        let second = encode_signal_sender_key_message(&second).unwrap();
        let target = sign_signal_sender_key_message(
            88,
            target_iteration,
            encrypt_signal_sender_message_body(b"target", &target_keys).unwrap(),
            signing_key.private.expose(),
        )
        .unwrap();
        let target = encode_signal_sender_key_message(&target).unwrap();
        let distribution =
            build_signal_sender_key_distribution_message(88, 0, &[6u8; 32], &signing_key.public)
                .unwrap();
        let receiver_record =
            process_signal_sender_key_distribution_record(None, &distribution).unwrap();

        let target_decrypted = decrypt_signal_sender_key_record_message(
            &receiver_record,
            &target,
            &XEdDsaNoiseCertificateVerifier,
        )
        .unwrap();
        assert_eq!(target_decrypted.plaintext, Bytes::from_static(b"target"));
        let receiver_after_target =
            decode_signal_sender_key_record(&target_decrypted.record).unwrap();
        assert_eq!(
            receiver_after_target.states[0].message_keys.len(),
            SIGNAL_MAX_SENDER_MESSAGE_KEYS
        );
        assert_eq!(receiver_after_target.states[0].message_keys[0].iteration, 1);
        assert_eq!(
            receiver_after_target.states[0]
                .message_keys
                .last()
                .unwrap()
                .iteration,
            target_iteration - 1
        );

        let err = decrypt_signal_sender_key_record_message(
            &target_decrypted.record,
            &first,
            &XEdDsaNoiseCertificateVerifier,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            CoreError::Protocol(message)
                if message == "duplicate Signal sender-key message iteration: 0"
        ));
        let second_decrypted = decrypt_signal_sender_key_record_message(
            &target_decrypted.record,
            &second,
            &XEdDsaNoiseCertificateVerifier,
        )
        .unwrap();
        assert_eq!(second_decrypted.plaintext, Bytes::from_static(b"second"));
        let receiver_after_second =
            decode_signal_sender_key_record(&second_decrypted.record).unwrap();
        assert_eq!(
            receiver_after_second.states[0].message_keys.len(),
            SIGNAL_MAX_SENDER_MESSAGE_KEYS - 1
        );
        assert_eq!(receiver_after_second.states[0].message_keys[0].iteration, 2);
    }

    #[test]
    fn signal_sender_key_message_signs_verifies_and_decodes_wire_frame() {
        let signing_key = generate_key_pair();
        let chain_step = ratchet_signal_sender_chain(&SignalSenderChainKey {
            key: SecretBytes::from(vec![1u8; 32]),
            iteration: 5,
        })
        .unwrap();
        let ciphertext =
            encrypt_signal_sender_message_body(b"group plaintext", &chain_step.message_key)
                .unwrap();

        let message = sign_signal_sender_key_message(
            0x0102_0304,
            chain_step.message_key.iteration,
            ciphertext.clone(),
            signing_key.private.expose(),
        )
        .unwrap();

        assert_eq!(message.message_version, SIGNAL_WIRE_CURRENT_VERSION);
        assert_eq!(message.key_id, 0x0102_0304);
        assert_eq!(message.iteration, 5);
        assert_eq!(message.ciphertext, ciphertext);
        assert_eq!(message.signature.len(), SIGNAL_SENDER_KEY_SIGNATURE_LEN);

        let encoded = encode_signal_sender_key_message(&message).unwrap();
        assert_eq!(encoded[0], 0x33);

        let decoded = decode_signal_sender_key_message(&encoded).unwrap();
        assert_eq!(decoded, message);
        verify_signal_sender_key_message(
            &decoded,
            &signing_key.public,
            &XEdDsaNoiseCertificateVerifier,
        )
        .unwrap();
        assert_eq!(
            verify_signal_sender_key_message_bytes(
                &encoded,
                &prefixed_signal_public_key(&signing_key.public),
                &XEdDsaNoiseCertificateVerifier,
            )
            .unwrap(),
            decoded
        );
        let proto_end = encoded.len() - SIGNAL_SENDER_KEY_SIGNATURE_LEN;
        let mut unknown_field = encoded[..proto_end].to_vec();
        unknown_field.extend_from_slice(&[0x78, 0x63]);
        unknown_field.extend_from_slice(&encoded[proto_end..]);
        let decoded_unknown = decode_signal_sender_key_message(&unknown_field).unwrap();
        assert_eq!(decoded_unknown, decoded);
        assert_eq!(
            encode_signal_sender_key_message(&decoded_unknown).unwrap(),
            encoded
        );
        assert_eq!(
            verify_signal_sender_key_message_bytes(
                &unknown_field,
                &prefixed_signal_public_key(&signing_key.public),
                &XEdDsaNoiseCertificateVerifier,
            )
            .unwrap(),
            decoded
        );
        assert_eq!(
            decrypt_signal_sender_message_body(&decoded.ciphertext, &chain_step.message_key)
                .unwrap(),
            Bytes::from_static(b"group plaintext")
        );

        let mut tampered_payload = encoded.to_vec();
        let last_payload_byte = tampered_payload.len() - SIGNAL_SENDER_KEY_SIGNATURE_LEN - 1;
        tampered_payload[last_payload_byte] ^= 1;
        let err = verify_signal_sender_key_message_bytes(
            &tampered_payload,
            &signing_key.public,
            &XEdDsaNoiseCertificateVerifier,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            CoreError::Protocol(message)
                if message == "invalid Signal sender-key message signature"
        ));

        let mut tampered_signature = encoded.to_vec();
        let last_signature_byte = tampered_signature.len() - 1;
        tampered_signature[last_signature_byte] ^= 1;
        let err = verify_signal_sender_key_message_bytes(
            &tampered_signature,
            &signing_key.public,
            &XEdDsaNoiseCertificateVerifier,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            CoreError::Protocol(message)
                if message == "invalid Signal sender-key message signature"
        ));

        let wrong_signing_key = generate_key_pair();
        let err = verify_signal_sender_key_message(
            &decoded,
            &wrong_signing_key.public,
            &XEdDsaNoiseCertificateVerifier,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            CoreError::Protocol(message)
                if message == "invalid Signal sender-key message signature"
        ));
    }

    #[test]
    fn signal_sender_key_message_rejects_invalid_wire_frames() {
        let err = decode_signal_sender_key_message(&[0x33]).unwrap_err();
        assert!(matches!(
            err,
            CoreError::Protocol(message)
                if message == "Signal sender-key message is too short: 1"
        ));

        let signing_key = generate_key_pair();
        let message = sign_signal_sender_key_message(
            7,
            9,
            Bytes::from_static(b"ciphertext"),
            signing_key.private.expose(),
        )
        .unwrap();
        let encoded = encode_signal_sender_key_message(&message).unwrap();

        let mut bad_version = encoded.to_vec();
        bad_version[0] = 0x23;
        let err = decode_signal_sender_key_message(&bad_version).unwrap_err();
        assert!(matches!(
            err,
            CoreError::Protocol(message)
                if message == "unsupported Signal sender-key message version: 2"
        ));

        let mut bad_ciphertext_version = encoded.to_vec();
        bad_ciphertext_version[0] = 0x32;
        let err = decode_signal_sender_key_message(&bad_ciphertext_version).unwrap_err();
        assert!(matches!(
            err,
            CoreError::Protocol(message)
                if message == "unsupported Signal sender-key ciphertext version: 2"
        ));

        let mut missing_id = BytesMut::new();
        missing_id.put_u8(0x33);
        ProtoSenderKeyMessage {
            id: None,
            iteration: Some(9),
            ciphertext: Some(Bytes::from_static(b"ciphertext")),
        }
        .encode(&mut missing_id)
        .unwrap();
        missing_id.extend_from_slice(&[0u8; SIGNAL_SENDER_KEY_SIGNATURE_LEN]);
        let err = decode_signal_sender_key_message(&missing_id).unwrap_err();
        assert!(matches!(
            err,
            CoreError::Protocol(message) if message == "Signal sender-key message missing id"
        ));

        let mut missing_iteration = BytesMut::new();
        missing_iteration.put_u8(0x33);
        ProtoSenderKeyMessage {
            id: Some(7),
            iteration: None,
            ciphertext: Some(Bytes::from_static(b"ciphertext")),
        }
        .encode(&mut missing_iteration)
        .unwrap();
        missing_iteration.extend_from_slice(&[0u8; SIGNAL_SENDER_KEY_SIGNATURE_LEN]);
        let err = decode_signal_sender_key_message(&missing_iteration).unwrap_err();
        assert!(matches!(
            err,
            CoreError::Protocol(message)
                if message == "Signal sender-key message missing iteration"
        ));

        let mut missing_ciphertext = BytesMut::new();
        missing_ciphertext.put_u8(0x33);
        ProtoSenderKeyMessage {
            id: Some(7),
            iteration: Some(9),
            ciphertext: None,
        }
        .encode(&mut missing_ciphertext)
        .unwrap();
        missing_ciphertext.extend_from_slice(&[0u8; SIGNAL_SENDER_KEY_SIGNATURE_LEN]);
        let err = decode_signal_sender_key_message(&missing_ciphertext).unwrap_err();
        assert!(matches!(
            err,
            CoreError::Protocol(message)
                if message == "Signal sender-key message missing ciphertext"
        ));

        let mut empty_ciphertext = BytesMut::new();
        empty_ciphertext.put_u8(0x33);
        ProtoSenderKeyMessage {
            id: Some(7),
            iteration: Some(9),
            ciphertext: Some(Bytes::new()),
        }
        .encode(&mut empty_ciphertext)
        .unwrap();
        empty_ciphertext.extend_from_slice(&[0u8; SIGNAL_SENDER_KEY_SIGNATURE_LEN]);
        let err = decode_signal_sender_key_message(&empty_ciphertext).unwrap_err();
        assert!(matches!(
            err,
            CoreError::Protocol(message)
                if message == "Signal sender-key message ciphertext must not be empty"
        ));

        let mut short_signature = message;
        short_signature.signature = Bytes::from_static(b"short");
        let err = encode_signal_sender_key_message(&short_signature).unwrap_err();
        assert!(matches!(
            err,
            CoreError::Protocol(message)
                if message == "invalid Signal sender-key message signature length: 5"
        ));
    }

    #[test]
    fn stored_signal_session_rejects_truncated_fields_with_names() {
        let mut missing_identity_length = BytesMut::new();
        missing_identity_length.put_u8(STORED_SESSION_VERSION);
        missing_identity_length.put_u8(SESSION_RECORD_KIND);
        missing_identity_length.put_u32(1234);
        let err = decode_stored_session(&missing_identity_length).unwrap_err();
        assert!(matches!(
            err,
            CoreError::Protocol(message)
                if message == "stored signal session missing identity key length"
        ));

        let mut truncated_signature = missing_identity_length.clone();
        put_bytes(&mut truncated_signature, &prefixed_test_signal_key(1)).unwrap();
        truncated_signature.put_u32(7);
        put_bytes(&mut truncated_signature, &prefixed_test_signal_key(2)).unwrap();
        truncated_signature.put_u16(64);
        truncated_signature.extend_from_slice(&[3u8; 8]);
        let err = decode_stored_session(&truncated_signature).unwrap_err();
        assert!(matches!(
            err,
            CoreError::Protocol(message)
                if message == "stored signal session signed pre-key signature is truncated"
        ));

        let mut missing_pre_key_id = missing_identity_length;
        put_bytes(&mut missing_pre_key_id, &prefixed_test_signal_key(1)).unwrap();
        missing_pre_key_id.put_u32(7);
        put_bytes(&mut missing_pre_key_id, &prefixed_test_signal_key(2)).unwrap();
        put_bytes(&mut missing_pre_key_id, &[3u8; 64]).unwrap();
        missing_pre_key_id.put_u8(1);
        let err = decode_stored_session(&missing_pre_key_id).unwrap_err();
        assert!(matches!(
            err,
            CoreError::Protocol(message)
                if message == "stored signal session missing pre-key id"
        ));
    }

    #[tokio::test]
    async fn repository_injects_validates_and_deletes_sessions() {
        let store = temp_store().await;
        let provider_store = SignalProviderStateStore::new(store.clone());
        let repository = StoreSignalRepository::new(store.clone());
        let session = test_session();

        provider_store
            .store_session_and_identity_records(
                "123:7@s.whatsapp.net",
                b"native-session-record",
                b"native-identity-record",
            )
            .await
            .unwrap();
        repository
            .inject_e2e_session(SessionInjection {
                jid: "123:7@s.whatsapp.net".to_owned(),
                session: session.clone(),
            })
            .await
            .unwrap();

        let validation = repository
            .validate_session("123:7@s.whatsapp.net")
            .await
            .unwrap();
        assert!(validation.exists);

        let info = repository
            .get_session_info("123:7@s.whatsapp.net")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(info.address.to_string(), "123.7");
        assert_eq!(info.registration_id, session.registration_id);
        assert_eq!(
            info.base_key,
            normalize_signal_public_key(&session.pre_key.unwrap().public_key).unwrap()
        );
        assert_eq!(info.session.signed_pre_key.key_id, 7);
        assert_eq!(info.session.pre_key.as_ref().unwrap().key_id, 9);
        assert!(
            provider_store
                .load_session_record("123:7@s.whatsapp.net")
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            provider_store
                .load_identity_record("123:7@s.whatsapp.net")
                .await
                .unwrap()
                .is_none()
        );

        provider_store
            .store_session_and_identity_records(
                "123:7@s.whatsapp.net",
                b"native-session-record",
                b"native-identity-record",
            )
            .await
            .unwrap();
        repository
            .delete_sessions(&["123:7@s.whatsapp.net".to_owned()])
            .await
            .unwrap();
        let validation = repository
            .validate_session("123:7@s.whatsapp.net")
            .await
            .unwrap();
        assert!(!validation.exists);
        assert!(
            provider_store
                .load_session_record("123:7@s.whatsapp.net")
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            provider_store
                .load_identity_record("123:7@s.whatsapp.net")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn repository_validate_session_requires_matching_identity_record() {
        let store = temp_store().await;
        let repository = StoreSignalRepository::new(store.clone());
        let session = test_session();
        let encoded = encode_stored_session(&session).unwrap();
        let address = signal_protocol_address("123:7@s.whatsapp.net")
            .unwrap()
            .to_string();

        store
            .set_signal_key(KeyNamespace::Session, &address, &encoded)
            .await
            .unwrap();
        let validation = repository
            .validate_session("123:7@s.whatsapp.net")
            .await
            .unwrap();
        assert!(!validation.exists);
        assert_eq!(validation.reason.as_deref(), Some("no identity"));
        assert!(
            repository
                .get_session_info("123:7@s.whatsapp.net")
                .await
                .unwrap()
                .is_none()
        );

        store
            .set_signal_key(KeyNamespace::IdentityKey, &address, &[9u8; 32])
            .await
            .unwrap();
        let validation = repository
            .validate_session("123:7@s.whatsapp.net")
            .await
            .unwrap();
        assert!(!validation.exists);
        assert_eq!(validation.reason.as_deref(), Some("identity mismatch"));
        assert!(
            repository
                .get_session_info("123:7@s.whatsapp.net")
                .await
                .unwrap()
                .is_none()
        );

        store
            .set_signal_key(KeyNamespace::IdentityKey, &address, &session.identity_key)
            .await
            .unwrap();
        let validation = repository
            .validate_session("123:7@s.whatsapp.net")
            .await
            .unwrap();
        assert!(validation.exists);
        assert_eq!(validation.reason, None);
        assert!(
            repository
                .get_session_info("123:7@s.whatsapp.net")
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn provider_state_store_persists_opaque_records() {
        let store = temp_store().await;
        let provider_store = SignalProviderStateStore::new(store.clone());

        provider_store
            .store_session_and_identity_records(
                "123:7@s.whatsapp.net",
                b"native-session-record",
                b"native-identity-record",
            )
            .await
            .unwrap();
        assert_eq!(
            provider_store
                .load_session_record("123:7@s.whatsapp.net")
                .await
                .unwrap()
                .as_deref(),
            Some(&b"native-session-record"[..])
        );
        assert_eq!(
            provider_store
                .load_identity_record("123:7@s.whatsapp.net")
                .await
                .unwrap()
                .as_deref(),
            Some(&b"native-identity-record"[..])
        );
        provider_store
            .store_identity_record("456:8@s.whatsapp.net", b"standalone-identity")
            .await
            .unwrap();
        assert_eq!(
            provider_store
                .load_identity_record("456:8@s.whatsapp.net")
                .await
                .unwrap()
                .as_deref(),
            Some(&b"standalone-identity"[..])
        );

        provider_store
            .store_pre_key_record(7, b"provider-pre-key")
            .await
            .unwrap();
        provider_store
            .store_signed_pre_key_record(8, b"provider-signed-pre-key")
            .await
            .unwrap();
        provider_store
            .store_sender_key_record("555@g.us|123:7@s.whatsapp.net|distribution", b"sender-key")
            .await
            .unwrap();
        provider_store
            .store_sender_key_memory_record("555@g.us|123:7@s.whatsapp.net", b"sender-memory")
            .await
            .unwrap();
        assert_eq!(
            provider_store
                .load_pre_key_record(7)
                .await
                .unwrap()
                .as_deref(),
            Some(&b"provider-pre-key"[..])
        );
        assert_eq!(
            provider_store
                .load_signed_pre_key_record(8)
                .await
                .unwrap()
                .as_deref(),
            Some(&b"provider-signed-pre-key"[..])
        );
        assert_eq!(
            provider_store
                .load_sender_key_record("555@g.us|123:7@s.whatsapp.net|distribution")
                .await
                .unwrap()
                .as_deref(),
            Some(&b"sender-key"[..])
        );
        assert_eq!(
            provider_store
                .load_sender_key_memory_record("555@g.us|123:7@s.whatsapp.net")
                .await
                .unwrap()
                .as_deref(),
            Some(&b"sender-memory"[..])
        );

        assert!(
            provider_store
                .delete_identity_record("456:8@s.whatsapp.net")
                .await
                .unwrap()
        );
        assert!(
            !provider_store
                .delete_identity_record("456:8@s.whatsapp.net")
                .await
                .unwrap()
        );
        assert!(provider_store.delete_pre_key_record(7).await.unwrap());
        assert!(!provider_store.delete_pre_key_record(7).await.unwrap());
        assert!(
            provider_store
                .delete_signed_pre_key_record(8)
                .await
                .unwrap()
        );
        assert!(
            !provider_store
                .delete_signed_pre_key_record(8)
                .await
                .unwrap()
        );
        assert!(
            provider_store
                .delete_sender_key_record("555@g.us|123:7@s.whatsapp.net|distribution")
                .await
                .unwrap()
        );
        assert!(
            !provider_store
                .delete_sender_key_record("555@g.us|123:7@s.whatsapp.net|distribution")
                .await
                .unwrap()
        );
        assert!(
            provider_store
                .delete_sender_key_memory_record("555@g.us|123:7@s.whatsapp.net")
                .await
                .unwrap()
        );
        assert!(
            !provider_store
                .delete_sender_key_memory_record("555@g.us|123:7@s.whatsapp.net")
                .await
                .unwrap()
        );
        assert!(
            provider_store
                .store_record(SignalProviderRecordKind::Session, "", b"x")
                .await
                .is_err()
        );
        assert!(
            provider_store
                .store_record(SignalProviderRecordKind::Session, "x", b"")
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn provider_state_store_identity_delete_clears_decodable_session_pair() {
        let store = temp_store().await;
        let provider_store = SignalProviderStateStore::new(store.clone());
        let record = SignalProviderSessionRecord {
            remote_registration_id: 88,
            remote_identity_key: prefixed_test_signal_key(21),
            root_key: SignalRootKey {
                key: SecretBytes::from(vec![9u8; 32]),
            },
            sending_chain: SignalMessageChainKey {
                key: SecretBytes::from(vec![7u8; 32]),
                counter: 0,
            },
            receiving_chain: None,
            remote_ratchet_key: None,
            local_ratchet_key_pair: test_key_pair(31),
            previous_counter: 0,
            message_keys: Vec::new(),
        };
        let encoded = encode_signal_provider_session_record(&record).unwrap();

        provider_store
            .store_session_and_identity_records(
                "123:7@s.whatsapp.net",
                &encoded,
                &record.remote_identity_key,
            )
            .await
            .unwrap();
        assert!(
            provider_store
                .delete_identity_record("123:7@s.whatsapp.net")
                .await
                .unwrap()
        );
        assert!(
            provider_store
                .load_identity_record("123:7@s.whatsapp.net")
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            provider_store
                .load_session_record("123:7@s.whatsapp.net")
                .await
                .unwrap()
                .is_none()
        );

        provider_store
            .store_session_and_identity_records(
                "456:8@s.whatsapp.net",
                b"native-session-record",
                b"native-identity-record",
            )
            .await
            .unwrap();
        assert!(
            provider_store
                .delete_identity_record("456:8@s.whatsapp.net")
                .await
                .unwrap()
        );
        assert!(
            provider_store
                .load_identity_record("456:8@s.whatsapp.net")
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            provider_store
                .load_session_record("456:8@s.whatsapp.net")
                .await
                .unwrap()
                .as_deref(),
            Some(&b"native-session-record"[..])
        );
    }

    #[tokio::test]
    async fn provider_state_store_session_delete_clears_decodable_identity_pair() {
        let store = temp_store().await;
        let provider_store = SignalProviderStateStore::new(store.clone());
        let record = SignalProviderSessionRecord {
            remote_registration_id: 88,
            remote_identity_key: prefixed_test_signal_key(21),
            root_key: SignalRootKey {
                key: SecretBytes::from(vec![9u8; 32]),
            },
            sending_chain: SignalMessageChainKey {
                key: SecretBytes::from(vec![7u8; 32]),
                counter: 0,
            },
            receiving_chain: None,
            remote_ratchet_key: None,
            local_ratchet_key_pair: test_key_pair(31),
            previous_counter: 0,
            message_keys: Vec::new(),
        };
        let encoded = encode_signal_provider_session_record(&record).unwrap();

        provider_store
            .store_session_and_identity_records(
                "123:7@s.whatsapp.net",
                &encoded,
                &record.remote_identity_key,
            )
            .await
            .unwrap();
        assert!(
            provider_store
                .delete_session_record("123:7@s.whatsapp.net")
                .await
                .unwrap()
        );
        assert!(
            provider_store
                .load_session_record("123:7@s.whatsapp.net")
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            provider_store
                .load_identity_record("123:7@s.whatsapp.net")
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            !provider_store
                .delete_session_record("123:7@s.whatsapp.net")
                .await
                .unwrap()
        );

        provider_store
            .store_session_and_identity_records(
                "456:8@s.whatsapp.net",
                b"native-session-record",
                b"native-identity-record",
            )
            .await
            .unwrap();
        assert!(
            provider_store
                .delete_session_record("456:8@s.whatsapp.net")
                .await
                .unwrap()
        );
        assert!(
            provider_store
                .load_session_record("456:8@s.whatsapp.net")
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            provider_store
                .load_identity_record("456:8@s.whatsapp.net")
                .await
                .unwrap()
                .as_deref(),
            Some(&b"native-identity-record"[..])
        );

        provider_store
            .store_record(SignalProviderRecordKind::Session, "789.9", &encoded)
            .await
            .unwrap();
        provider_store
            .store_record(
                SignalProviderRecordKind::Identity,
                "789.9",
                &record.remote_identity_key,
            )
            .await
            .unwrap();
        assert!(
            provider_store
                .delete_record(SignalProviderRecordKind::Session, "789.9")
                .await
                .unwrap()
        );
        assert!(
            provider_store
                .load_session_record("789:9@s.whatsapp.net")
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            provider_store
                .load_identity_record("789:9@s.whatsapp.net")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn provider_state_store_raw_record_api_enforces_session_identity_pairing() {
        let store = temp_store().await;
        let provider_store = SignalProviderStateStore::new(store.clone());
        let record = SignalProviderSessionRecord {
            remote_registration_id: 88,
            remote_identity_key: prefixed_test_signal_key(21),
            root_key: SignalRootKey {
                key: SecretBytes::from(vec![9u8; 32]),
            },
            sending_chain: SignalMessageChainKey {
                key: SecretBytes::from(vec![7u8; 32]),
                counter: 0,
            },
            receiving_chain: None,
            remote_ratchet_key: None,
            local_ratchet_key_pair: test_key_pair(31),
            previous_counter: 0,
            message_keys: Vec::new(),
        };
        let encoded = encode_signal_provider_session_record(&record).unwrap();

        provider_store
            .store_record(
                SignalProviderRecordKind::Identity,
                "123.7",
                &prefixed_test_signal_key(22),
            )
            .await
            .unwrap();
        let err = provider_store
            .store_record(SignalProviderRecordKind::Session, "123.7", &encoded)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            CoreError::Protocol(message) if message == "provider session identity mismatch"
        ));
        assert!(
            provider_store
                .load_session_record("123:7@s.whatsapp.net")
                .await
                .unwrap()
                .is_none()
        );

        provider_store
            .store_record(
                SignalProviderRecordKind::Session,
                "456.8",
                b"native-session-record",
            )
            .await
            .unwrap();
        provider_store
            .store_record(
                SignalProviderRecordKind::Identity,
                "456.8",
                b"native-identity-record",
            )
            .await
            .unwrap();
        assert!(
            provider_store
                .delete_record(SignalProviderRecordKind::Identity, "456.8")
                .await
                .unwrap()
        );
        assert_eq!(
            provider_store
                .load_session_record("456:8@s.whatsapp.net")
                .await
                .unwrap()
                .as_deref(),
            Some(&b"native-session-record"[..])
        );

        provider_store
            .store_record(SignalProviderRecordKind::Session, "789.9", &encoded)
            .await
            .unwrap();
        provider_store
            .store_record(
                SignalProviderRecordKind::Identity,
                "789.9",
                &record.remote_identity_key,
            )
            .await
            .unwrap();
        assert!(
            provider_store
                .delete_record(SignalProviderRecordKind::Identity, "789.9")
                .await
                .unwrap()
        );
        assert!(
            provider_store
                .load_session_record("789:9@s.whatsapp.net")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn provider_state_store_validates_session_records() {
        let store = temp_store().await;
        let provider_store = SignalProviderStateStore::new(store.clone());

        let missing = provider_store
            .validate_session_record("123:7@s.whatsapp.net")
            .await
            .unwrap();
        assert!(!missing.exists);
        assert_eq!(missing.reason.as_deref(), Some("no provider session"));

        provider_store
            .store_session_record("123:7@s.whatsapp.net", b"not-a-provider-session")
            .await
            .unwrap();
        let malformed = provider_store
            .validate_session_record("123:7@s.whatsapp.net")
            .await
            .unwrap();
        assert!(!malformed.exists);
        assert_eq!(
            malformed.reason.as_deref(),
            Some("protocol error: unsupported Signal provider session version")
        );
        assert!(
            provider_store
                .load_session_info("123:7@s.whatsapp.net")
                .await
                .unwrap()
                .is_none()
        );

        let record = SignalProviderSessionRecord {
            remote_registration_id: 88,
            remote_identity_key: prefixed_test_signal_key(21),
            root_key: SignalRootKey {
                key: SecretBytes::from(vec![9u8; 32]),
            },
            sending_chain: SignalMessageChainKey {
                key: SecretBytes::from(vec![7u8; 32]),
                counter: 0,
            },
            receiving_chain: None,
            remote_ratchet_key: None,
            local_ratchet_key_pair: test_key_pair(31),
            previous_counter: 0,
            message_keys: Vec::new(),
        };
        let encoded = encode_signal_provider_session_record(&record).unwrap();
        provider_store
            .store_session_record("123:7@s.whatsapp.net", &encoded)
            .await
            .unwrap();

        let missing_identity = provider_store
            .validate_session_record("123:7@s.whatsapp.net")
            .await
            .unwrap();
        assert!(!missing_identity.exists);
        assert_eq!(
            missing_identity.reason.as_deref(),
            Some("no provider identity")
        );
        assert!(
            provider_store
                .load_session_info("123:7@s.whatsapp.net")
                .await
                .unwrap()
                .is_none()
        );

        store
            .set_signal_key(KeyNamespace::SignalProviderIdentity, "123.7", b"short")
            .await
            .unwrap();
        let malformed_identity = provider_store
            .validate_session_record("123:7@s.whatsapp.net")
            .await
            .unwrap();
        assert!(!malformed_identity.exists);
        assert_eq!(
            malformed_identity.reason.as_deref(),
            Some("protocol error: invalid signal public key length: 5")
        );
        assert!(
            provider_store
                .load_session_info("123:7@s.whatsapp.net")
                .await
                .unwrap()
                .is_none()
        );

        store
            .set_signal_key(
                KeyNamespace::SignalProviderIdentity,
                "123.7",
                &prefixed_test_signal_key(22),
            )
            .await
            .unwrap();
        let mismatched_identity = provider_store
            .validate_session_record("123:7@s.whatsapp.net")
            .await
            .unwrap();
        assert!(!mismatched_identity.exists);
        assert_eq!(
            mismatched_identity.reason.as_deref(),
            Some("provider identity mismatch")
        );
        assert!(
            provider_store
                .load_session_info("123:7@s.whatsapp.net")
                .await
                .unwrap()
                .is_none()
        );

        store
            .set_signal_key(
                KeyNamespace::SignalProviderIdentity,
                "123.7",
                &record.remote_identity_key,
            )
            .await
            .unwrap();
        let valid = provider_store
            .validate_session_record("123:7@s.whatsapp.net")
            .await
            .unwrap();
        assert!(valid.exists);
        assert!(valid.reason.is_none());
        let info = provider_store
            .load_session_info("123:7@s.whatsapp.net")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(info.address.to_string(), "123.7");
        assert_eq!(info.registration_id, record.remote_registration_id);
    }

    #[tokio::test]
    async fn provider_state_store_rejects_decodable_session_identity_mismatch_atomically() {
        let store = temp_store().await;
        let provider_store = SignalProviderStateStore::new(store.clone());
        let record = SignalProviderSessionRecord {
            remote_registration_id: 88,
            remote_identity_key: prefixed_test_signal_key(21),
            root_key: SignalRootKey {
                key: SecretBytes::from(vec![9u8; 32]),
            },
            sending_chain: SignalMessageChainKey {
                key: SecretBytes::from(vec![7u8; 32]),
                counter: 0,
            },
            receiving_chain: None,
            remote_ratchet_key: None,
            local_ratchet_key_pair: test_key_pair(31),
            previous_counter: 0,
            message_keys: Vec::new(),
        };
        let encoded = encode_signal_provider_session_record(&record).unwrap();
        let err = provider_store
            .store_session_and_identity_records(
                "123:7@s.whatsapp.net",
                &encoded,
                &prefixed_test_signal_key(22),
            )
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            CoreError::Protocol(message) if message == "provider session identity mismatch"
        ));
        assert!(
            provider_store
                .load_session_record("123:7@s.whatsapp.net")
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            provider_store
                .load_identity_record("123:7@s.whatsapp.net")
                .await
                .unwrap()
                .is_none()
        );

        provider_store
            .store_identity_record("222:7@s.whatsapp.net", &prefixed_test_signal_key(22))
            .await
            .unwrap();
        let err = provider_store
            .store_session_record("222:7@s.whatsapp.net", &encoded)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            CoreError::Protocol(message) if message == "provider session identity mismatch"
        ));
        assert!(
            provider_store
                .load_session_record("222:7@s.whatsapp.net")
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            provider_store
                .load_identity_record("222:7@s.whatsapp.net")
                .await
                .unwrap(),
            Some(prefixed_test_signal_key(22))
        );
        provider_store
            .store_session_record("222:7@s.whatsapp.net", b"native-session-record")
            .await
            .unwrap();
        assert_eq!(
            provider_store
                .load_session_record("222:7@s.whatsapp.net")
                .await
                .unwrap()
                .as_deref(),
            Some(&b"native-session-record"[..])
        );

        provider_store
            .store_session_record("123:7@s.whatsapp.net", &encoded)
            .await
            .unwrap();
        let err = provider_store
            .store_identity_record("123:7@s.whatsapp.net", &prefixed_test_signal_key(22))
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            CoreError::Protocol(message) if message == "provider session identity mismatch"
        ));
        assert!(
            provider_store
                .load_identity_record("123:7@s.whatsapp.net")
                .await
                .unwrap()
                .is_none()
        );

        provider_store
            .store_session_and_identity_records(
                "123:7@s.whatsapp.net",
                &encoded,
                &record.remote_identity_key,
            )
            .await
            .unwrap();
        let existing_session = provider_store
            .load_session_record("123:7@s.whatsapp.net")
            .await
            .unwrap()
            .unwrap();
        let existing_identity = provider_store
            .load_identity_record("123:7@s.whatsapp.net")
            .await
            .unwrap()
            .unwrap();

        let mut next_record = record;
        next_record.remote_identity_key = prefixed_test_signal_key(22);
        let next_encoded = encode_signal_provider_session_record(&next_record).unwrap();
        assert_eq!(
            provider_store
                .store_session_and_identity_records(
                    "123:7@s.whatsapp.net",
                    &next_encoded,
                    &next_record.remote_identity_key,
                )
                .await
                .unwrap_err()
                .to_string(),
            "protocol error: Signal provider identity changed for 123.7"
        );
        assert_eq!(
            provider_store
                .load_session_record("123:7@s.whatsapp.net")
                .await
                .unwrap()
                .unwrap(),
            existing_session
        );
        assert_eq!(
            provider_store
                .load_identity_record("123:7@s.whatsapp.net")
                .await
                .unwrap()
                .unwrap(),
            existing_identity
        );

        provider_store
            .store_session_and_identity_records(
                "456:8@s.whatsapp.net",
                b"native-session-record",
                b"native-identity-record",
            )
            .await
            .unwrap();
        assert_eq!(
            provider_store
                .load_session_record("456:8@s.whatsapp.net")
                .await
                .unwrap()
                .as_deref(),
            Some(&b"native-session-record"[..])
        );

        let inbound_store = temp_store().await;
        let credentials = create_initial_credentials().unwrap();
        save_credentials(&inbound_store, credentials.clone())
            .await
            .unwrap();
        let upload = prepare_pre_key_upload(&inbound_store, &credentials, 1, "pre-key")
            .await
            .unwrap();
        let provider_store = SignalProviderStateStore::new(inbound_store);
        let pre_key_id = upload.pre_key_ids[0];
        let pre_key = provider_store
            .load_local_pre_key(pre_key_id)
            .await
            .unwrap()
            .unwrap();
        let err = provider_store
            .store_inbound_pre_key_session_records(
                "789:9@s.whatsapp.net",
                Some(pre_key_id),
                &encoded,
                &prefixed_test_signal_key(22),
            )
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            CoreError::Protocol(message) if message == "provider session identity mismatch"
        ));
        assert_eq!(
            provider_store.load_local_pre_key(pre_key_id).await.unwrap(),
            Some(pre_key)
        );
    }

    #[tokio::test]
    async fn provider_state_store_processes_sender_key_distribution_record() {
        let store = temp_store().await;
        let provider_store = SignalProviderStateStore::new(store.clone());
        let signing_key = generate_key_pair();
        let distribution =
            build_signal_sender_key_distribution_message(77, 3, &[8u8; 32], &signing_key.public)
                .unwrap();
        let key = "555@g.us|123:7@s.whatsapp.net";

        let stored = provider_store
            .process_sender_key_distribution_record(key, &distribution)
            .await
            .unwrap();
        assert_eq!(
            provider_store
                .load_sender_key_record(key)
                .await
                .unwrap()
                .as_deref(),
            Some(stored.as_ref())
        );
        let record = decode_signal_sender_key_record(&stored).unwrap();
        assert_eq!(record.states.len(), 1);
        assert_eq!(record.states[0].key_id, 77);
        assert_eq!(record.states[0].chain_key.iteration, 3);
        assert_eq!(record.states[0].chain_key.key.expose(), &[8u8; 32]);
        assert_eq!(
            record.states[0].signing_public_key,
            distribution.signing_key
        );
    }

    #[tokio::test]
    async fn provider_state_store_truncates_full_sender_key_record_on_distribution() {
        let store = temp_store().await;
        let provider_store = SignalProviderStateStore::new(store.clone());
        let key = "555@g.us|123:7@s.whatsapp.net";
        let existing_states = (0..SIGNAL_MAX_SENDER_KEY_STATES)
            .map(|index| SignalSenderKeyState {
                key_id: 100 + index as u32,
                chain_key: SignalSenderChainKey {
                    key: SecretBytes::from(vec![0x30 + index as u8; 32]),
                    iteration: 7 + index as u32,
                },
                signing_public_key: prefixed_test_signal_key(0xa0 + index as u8),
                signing_private_key: None,
                message_keys: Vec::new(),
            })
            .collect();
        let existing = encode_signal_sender_key_record(&SignalSenderKeyRecord {
            states: existing_states,
        })
        .unwrap();
        provider_store
            .store_sender_key_record(key, &existing)
            .await
            .unwrap();

        let distribution_signing_key = prefixed_test_signal_key(0xf0);
        let distribution = build_signal_sender_key_distribution_message(
            99,
            17,
            &[0x90u8; 32],
            &distribution_signing_key,
        )
        .unwrap();
        let updated = provider_store
            .process_sender_key_distribution_record(key, &distribution)
            .await
            .unwrap();
        assert_eq!(
            provider_store
                .load_sender_key_record(key)
                .await
                .unwrap()
                .as_deref(),
            Some(updated.as_ref())
        );

        let record = decode_signal_sender_key_record(&updated).unwrap();
        let key_ids = record
            .states
            .iter()
            .map(|state| state.key_id)
            .collect::<Vec<_>>();
        assert_eq!(key_ids, vec![99, 100, 101, 102, 103]);
        assert!(!key_ids.contains(&104));
        assert_eq!(record.states[0].chain_key.iteration, 17);
        assert_eq!(record.states[0].chain_key.key.expose(), &[0x90u8; 32]);
        assert_eq!(
            record.states[0].signing_public_key,
            distribution_signing_key
        );
        assert_eq!(record.states[0].signing_private_key, None);
        assert!(record.states[0].message_keys.is_empty());
        for (index, state) in record.states.iter().skip(1).enumerate() {
            assert_eq!(state.chain_key.iteration, 7 + index as u32);
            assert_eq!(state.chain_key.key.expose(), &[0x30 + index as u8; 32]);
            assert_eq!(
                state.signing_public_key,
                prefixed_test_signal_key(0xa0 + index as u8)
            );
        }
    }

    #[tokio::test]
    async fn provider_state_store_replaces_same_key_sender_key_distribution() {
        let store = temp_store().await;
        let provider_store = SignalProviderStateStore::new(store.clone());
        let key = "555@g.us|123:7@s.whatsapp.net";
        let existing_signing_key = generate_key_pair();
        let replacement_signing_key = generate_key_pair();
        let preserved_signing_key = generate_key_pair();
        let existing = encode_signal_sender_key_record(&SignalSenderKeyRecord {
            states: vec![
                SignalSenderKeyState {
                    key_id: 88,
                    chain_key: SignalSenderChainKey {
                        key: SecretBytes::from(vec![0x20u8; 32]),
                        iteration: 9,
                    },
                    signing_public_key: Bytes::copy_from_slice(&prefixed_signal_public_key(
                        &existing_signing_key.public,
                    )),
                    signing_private_key: Some(SecretBytes::from(
                        existing_signing_key.private.expose().to_vec(),
                    )),
                    message_keys: vec![SignalSenderStoredMessageKey {
                        iteration: 8,
                        seed: SecretBytes::from(vec![0x21u8; 32]),
                    }],
                },
                SignalSenderKeyState {
                    key_id: 89,
                    chain_key: SignalSenderChainKey {
                        key: SecretBytes::from(vec![0x30u8; 32]),
                        iteration: 4,
                    },
                    signing_public_key: Bytes::copy_from_slice(&prefixed_signal_public_key(
                        &preserved_signing_key.public,
                    )),
                    signing_private_key: None,
                    message_keys: Vec::new(),
                },
            ],
        })
        .unwrap();
        provider_store
            .store_sender_key_record(key, &existing)
            .await
            .unwrap();

        let distribution = build_signal_sender_key_distribution_message(
            88,
            3,
            &[0x40u8; 32],
            &replacement_signing_key.public,
        )
        .unwrap();
        let updated = provider_store
            .process_sender_key_distribution_record(key, &distribution)
            .await
            .unwrap();
        assert_eq!(
            provider_store
                .load_sender_key_record(key)
                .await
                .unwrap()
                .as_deref(),
            Some(updated.as_ref())
        );

        let record = decode_signal_sender_key_record(&updated).unwrap();
        assert_eq!(record.states.len(), 2);
        assert_eq!(record.states[0].key_id, 88);
        assert_eq!(record.states[0].chain_key.iteration, 3);
        assert_eq!(record.states[0].chain_key.key.expose(), &[0x40u8; 32]);
        assert_eq!(
            record.states[0].signing_public_key,
            distribution.signing_key
        );
        assert_eq!(record.states[0].signing_private_key, None);
        assert!(record.states[0].message_keys.is_empty());
        assert_eq!(record.states[1].key_id, 89);
        assert_eq!(record.states[1].chain_key.iteration, 4);
        assert_eq!(record.states[1].chain_key.key.expose(), &[0x30u8; 32]);
        assert_eq!(
            record.states[1].signing_public_key,
            Bytes::copy_from_slice(&prefixed_signal_public_key(&preserved_signing_key.public))
        );
    }

    #[tokio::test]
    async fn provider_state_store_preserves_same_key_sender_key_distribution_after_stale() {
        let store = temp_store().await;
        let provider_store = SignalProviderStateStore::new(store.clone());
        let key = "555@g.us|123:7@s.whatsapp.net";
        let signing_key = generate_key_pair();
        let preserved_signing_key = generate_key_pair();
        let existing = encode_signal_sender_key_record(&SignalSenderKeyRecord {
            states: vec![
                SignalSenderKeyState {
                    key_id: 88,
                    chain_key: SignalSenderChainKey {
                        key: SecretBytes::from(vec![0x20u8; 32]),
                        iteration: 9,
                    },
                    signing_public_key: Bytes::copy_from_slice(&prefixed_signal_public_key(
                        &signing_key.public,
                    )),
                    signing_private_key: Some(SecretBytes::from(
                        signing_key.private.expose().to_vec(),
                    )),
                    message_keys: vec![SignalSenderStoredMessageKey {
                        iteration: 8,
                        seed: SecretBytes::from(vec![0x21u8; 32]),
                    }],
                },
                SignalSenderKeyState {
                    key_id: 89,
                    chain_key: SignalSenderChainKey {
                        key: SecretBytes::from(vec![0x30u8; 32]),
                        iteration: 4,
                    },
                    signing_public_key: Bytes::copy_from_slice(&prefixed_signal_public_key(
                        &preserved_signing_key.public,
                    )),
                    signing_private_key: None,
                    message_keys: Vec::new(),
                },
            ],
        })
        .unwrap();
        provider_store
            .store_sender_key_record(key, &existing)
            .await
            .unwrap();

        let stale_distribution =
            build_signal_sender_key_distribution_message(88, 7, &[0x40u8; 32], &signing_key.public)
                .unwrap();
        let updated = provider_store
            .process_sender_key_distribution_record(key, &stale_distribution)
            .await
            .unwrap();
        assert_eq!(updated, existing);
        assert_eq!(
            provider_store
                .load_sender_key_record(key)
                .await
                .unwrap()
                .as_deref(),
            Some(existing.as_ref())
        );

        let record = decode_signal_sender_key_record(&updated).unwrap();
        assert_eq!(record.states.len(), 2);
        assert_eq!(record.states[0].key_id, 88);
        assert_eq!(record.states[0].chain_key.iteration, 9);
        assert_eq!(record.states[0].chain_key.key.expose(), &[0x20u8; 32]);
        assert_eq!(
            record.states[0].signing_public_key,
            stale_distribution.signing_key
        );
        assert!(record.states[0].signing_private_key.is_some());
        assert_eq!(record.states[0].message_keys.len(), 1);
        assert_eq!(record.states[0].message_keys[0].iteration, 8);
        assert_eq!(
            record.states[0].message_keys[0].seed.expose(),
            &[0x21u8; 32]
        );
        assert_eq!(record.states[1].key_id, 89);
        assert_eq!(record.states[1].chain_key.iteration, 4);
        assert_eq!(record.states[1].chain_key.key.expose(), &[0x30u8; 32]);
    }

    #[tokio::test]
    async fn provider_state_store_advances_same_key_sender_key_distribution() {
        let store = temp_store().await;
        let provider_store = SignalProviderStateStore::new(store.clone());
        let key = "555@g.us|123:7@s.whatsapp.net";
        let signing_key = generate_key_pair();
        let preserved_signing_key = generate_key_pair();
        let existing = encode_signal_sender_key_record(&SignalSenderKeyRecord {
            states: vec![
                SignalSenderKeyState {
                    key_id: 88,
                    chain_key: SignalSenderChainKey {
                        key: SecretBytes::from(vec![0x20u8; 32]),
                        iteration: 9,
                    },
                    signing_public_key: Bytes::copy_from_slice(&prefixed_signal_public_key(
                        &signing_key.public,
                    )),
                    signing_private_key: Some(SecretBytes::from(
                        signing_key.private.expose().to_vec(),
                    )),
                    message_keys: vec![SignalSenderStoredMessageKey {
                        iteration: 8,
                        seed: SecretBytes::from(vec![0x21u8; 32]),
                    }],
                },
                SignalSenderKeyState {
                    key_id: 89,
                    chain_key: SignalSenderChainKey {
                        key: SecretBytes::from(vec![0x30u8; 32]),
                        iteration: 4,
                    },
                    signing_public_key: Bytes::copy_from_slice(&prefixed_signal_public_key(
                        &preserved_signing_key.public,
                    )),
                    signing_private_key: None,
                    message_keys: Vec::new(),
                },
            ],
        })
        .unwrap();
        provider_store
            .store_sender_key_record(key, &existing)
            .await
            .unwrap();

        let newer_distribution = build_signal_sender_key_distribution_message(
            88,
            11,
            &[0x40u8; 32],
            &signing_key.public,
        )
        .unwrap();
        let updated = provider_store
            .process_sender_key_distribution_record(key, &newer_distribution)
            .await
            .unwrap();
        assert_ne!(updated, existing);
        assert_eq!(
            provider_store
                .load_sender_key_record(key)
                .await
                .unwrap()
                .as_deref(),
            Some(updated.as_ref())
        );

        let record = decode_signal_sender_key_record(&updated).unwrap();
        assert_eq!(record.states.len(), 2);
        assert_eq!(record.states[0].key_id, 88);
        assert_eq!(record.states[0].chain_key.iteration, 11);
        assert_eq!(record.states[0].chain_key.key.expose(), &[0x40u8; 32]);
        assert_eq!(
            record.states[0].signing_public_key,
            newer_distribution.signing_key
        );
        assert_eq!(
            record.states[0]
                .signing_private_key
                .as_ref()
                .unwrap()
                .expose(),
            signing_key.private.expose()
        );
        assert_eq!(record.states[0].message_keys.len(), 1);
        assert_eq!(record.states[0].message_keys[0].iteration, 8);
        assert_eq!(
            record.states[0].message_keys[0].seed.expose(),
            &[0x21u8; 32]
        );
        assert_eq!(record.states[1].key_id, 89);
        assert_eq!(record.states[1].chain_key.iteration, 4);
        assert_eq!(record.states[1].chain_key.key.expose(), &[0x30u8; 32]);
    }

    #[tokio::test]
    async fn provider_state_store_advances_sender_key_encrypt_decrypt_records() {
        let store = temp_store().await;
        let provider_store = SignalProviderStateStore::new(store.clone());
        let signing_key = generate_key_pair();
        let sender_key = "555@g.us|sender";
        let receiver_key = "555@g.us|receiver";
        let sender_record = encode_signal_sender_key_record(&SignalSenderKeyRecord {
            states: vec![SignalSenderKeyState {
                key_id: 91,
                chain_key: SignalSenderChainKey {
                    key: SecretBytes::from(vec![9u8; 32]),
                    iteration: 0,
                },
                signing_public_key: Bytes::copy_from_slice(&prefixed_signal_public_key(
                    &signing_key.public,
                )),
                signing_private_key: Some(SecretBytes::from(signing_key.private.expose().to_vec())),
                message_keys: Vec::new(),
            }],
        })
        .unwrap();
        provider_store
            .store_sender_key_record(sender_key, &sender_record)
            .await
            .unwrap();
        let encrypted = provider_store
            .encrypt_sender_key_record_message(sender_key, b"stored sender-key")
            .await
            .unwrap();
        let stored_sender_record = provider_store
            .load_sender_key_record(sender_key)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored_sender_record, encrypted.record);
        assert_eq!(
            decode_signal_sender_key_record(&stored_sender_record)
                .unwrap()
                .states[0]
                .chain_key
                .iteration,
            1
        );

        let distribution =
            build_signal_sender_key_distribution_message(91, 0, &[9u8; 32], &signing_key.public)
                .unwrap();
        provider_store
            .process_sender_key_distribution_record(receiver_key, &distribution)
            .await
            .unwrap();
        let decrypted = provider_store
            .decrypt_sender_key_record_message(
                receiver_key,
                &encrypted.message_bytes,
                XEdDsaNoiseCertificateVerifier,
            )
            .await
            .unwrap();
        assert_eq!(
            decrypted.plaintext,
            Bytes::from_static(b"stored sender-key")
        );
        let stored_receiver_record = provider_store
            .load_sender_key_record(receiver_key)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored_receiver_record, decrypted.record);
        assert_eq!(
            decode_signal_sender_key_record(&stored_receiver_record)
                .unwrap()
                .states[0]
                .chain_key
                .iteration,
            1
        );
    }

    #[tokio::test]
    async fn provider_state_store_decrypts_later_matching_sender_key_state() {
        let store = temp_store().await;
        let provider_store = SignalProviderStateStore::new(store.clone());
        let old_signing_key = generate_key_pair();
        let replacement_signing_key = generate_key_pair();
        let key_id = 91;
        let old_chain_key = vec![0x41u8; 32];
        let replacement_chain_key = vec![0x61u8; 32];
        let receiver_key = "555@g.us|receiver";
        let old_sender_key = "555@g.us|old-sender";
        let old_sender_record = encode_signal_sender_key_record(&SignalSenderKeyRecord {
            states: vec![SignalSenderKeyState {
                key_id,
                chain_key: SignalSenderChainKey {
                    key: SecretBytes::from(old_chain_key.clone()),
                    iteration: 2,
                },
                signing_public_key: Bytes::copy_from_slice(&prefixed_signal_public_key(
                    &old_signing_key.public,
                )),
                signing_private_key: Some(SecretBytes::from(
                    old_signing_key.private.expose().to_vec(),
                )),
                message_keys: Vec::new(),
            }],
        })
        .unwrap();
        provider_store
            .store_sender_key_record(old_sender_key, &old_sender_record)
            .await
            .unwrap();
        let old_encrypted = provider_store
            .encrypt_sender_key_record_message(old_sender_key, b"preserved sender-key state")
            .await
            .unwrap();
        let receiver_record = encode_signal_sender_key_record(&SignalSenderKeyRecord {
            states: vec![
                SignalSenderKeyState {
                    key_id,
                    chain_key: SignalSenderChainKey {
                        key: SecretBytes::from(replacement_chain_key.clone()),
                        iteration: 7,
                    },
                    signing_public_key: Bytes::copy_from_slice(&prefixed_signal_public_key(
                        &replacement_signing_key.public,
                    )),
                    signing_private_key: None,
                    message_keys: Vec::new(),
                },
                SignalSenderKeyState {
                    key_id,
                    chain_key: SignalSenderChainKey {
                        key: SecretBytes::from(old_chain_key),
                        iteration: 2,
                    },
                    signing_public_key: Bytes::copy_from_slice(&prefixed_signal_public_key(
                        &old_signing_key.public,
                    )),
                    signing_private_key: None,
                    message_keys: Vec::new(),
                },
            ],
        })
        .unwrap();
        provider_store
            .store_sender_key_record(receiver_key, &receiver_record)
            .await
            .unwrap();

        let decrypted = provider_store
            .decrypt_sender_key_record_message(
                receiver_key,
                &old_encrypted.message_bytes,
                XEdDsaNoiseCertificateVerifier,
            )
            .await
            .unwrap();
        assert_eq!(
            decrypted.plaintext,
            Bytes::from_static(b"preserved sender-key state")
        );
        let stored_receiver_record = provider_store
            .load_sender_key_record(receiver_key)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored_receiver_record, decrypted.record);
        let decoded = decode_signal_sender_key_record(&stored_receiver_record).unwrap();
        assert_eq!(decoded.states.len(), 2);
        assert_eq!(decoded.states[0].key_id, key_id);
        assert_eq!(decoded.states[0].chain_key.iteration, 7);
        assert_eq!(
            decoded.states[0].chain_key.key.expose(),
            &replacement_chain_key
        );
        assert_eq!(
            decoded.states[0].signing_public_key,
            Bytes::copy_from_slice(&prefixed_signal_public_key(&replacement_signing_key.public))
        );
        assert_eq!(decoded.states[1].key_id, key_id);
        assert_eq!(decoded.states[1].chain_key.iteration, 3);
        assert_eq!(decoded.states[1].message_keys, Vec::new());
        assert_eq!(
            decoded.states[1].signing_public_key,
            Bytes::copy_from_slice(&prefixed_signal_public_key(&old_signing_key.public))
        );
    }

    #[tokio::test]
    async fn provider_state_store_decrypts_replacement_sender_key_state_after_later_state() {
        let store = temp_store().await;
        let provider_store = SignalProviderStateStore::new(store.clone());
        let old_signing_key = generate_key_pair();
        let replacement_signing_key = generate_key_pair();
        let key_id = 96;
        let old_chain_key = vec![0x46u8; 32];
        let replacement_chain_key = vec![0x66u8; 32];
        let receiver_key = "555@g.us|receiver";
        let old_sender_record = encode_signal_sender_key_record(&SignalSenderKeyRecord {
            states: vec![SignalSenderKeyState {
                key_id,
                chain_key: SignalSenderChainKey {
                    key: SecretBytes::from(old_chain_key.clone()),
                    iteration: 2,
                },
                signing_public_key: Bytes::copy_from_slice(&prefixed_signal_public_key(
                    &old_signing_key.public,
                )),
                signing_private_key: Some(SecretBytes::from(
                    old_signing_key.private.expose().to_vec(),
                )),
                message_keys: Vec::new(),
            }],
        })
        .unwrap();
        let replacement_sender_record = encode_signal_sender_key_record(&SignalSenderKeyRecord {
            states: vec![SignalSenderKeyState {
                key_id,
                chain_key: SignalSenderChainKey {
                    key: SecretBytes::from(replacement_chain_key.clone()),
                    iteration: 7,
                },
                signing_public_key: Bytes::copy_from_slice(&prefixed_signal_public_key(
                    &replacement_signing_key.public,
                )),
                signing_private_key: Some(SecretBytes::from(
                    replacement_signing_key.private.expose().to_vec(),
                )),
                message_keys: Vec::new(),
            }],
        })
        .unwrap();
        let old_encrypted =
            encrypt_signal_sender_key_record_message(&old_sender_record, b"old sender-key state")
                .unwrap();
        let replacement_encrypted = encrypt_signal_sender_key_record_message(
            &replacement_sender_record,
            b"replacement sender-key state",
        )
        .unwrap();
        let expected_replacement_chain = ratchet_signal_sender_chain(&SignalSenderChainKey {
            key: SecretBytes::from(replacement_chain_key.clone()),
            iteration: 7,
        })
        .unwrap()
        .next_chain_key;
        let receiver_record = encode_signal_sender_key_record(&SignalSenderKeyRecord {
            states: vec![
                SignalSenderKeyState {
                    key_id,
                    chain_key: SignalSenderChainKey {
                        key: SecretBytes::from(replacement_chain_key.clone()),
                        iteration: 7,
                    },
                    signing_public_key: Bytes::copy_from_slice(&prefixed_signal_public_key(
                        &replacement_signing_key.public,
                    )),
                    signing_private_key: None,
                    message_keys: Vec::new(),
                },
                SignalSenderKeyState {
                    key_id,
                    chain_key: SignalSenderChainKey {
                        key: SecretBytes::from(old_chain_key),
                        iteration: 2,
                    },
                    signing_public_key: Bytes::copy_from_slice(&prefixed_signal_public_key(
                        &old_signing_key.public,
                    )),
                    signing_private_key: None,
                    message_keys: Vec::new(),
                },
            ],
        })
        .unwrap();
        provider_store
            .store_sender_key_record(receiver_key, &receiver_record)
            .await
            .unwrap();

        let old_decrypted = provider_store
            .decrypt_sender_key_record_message(
                receiver_key,
                &old_encrypted.message_bytes,
                XEdDsaNoiseCertificateVerifier,
            )
            .await
            .unwrap();
        assert_eq!(
            old_decrypted.plaintext,
            Bytes::from_static(b"old sender-key state")
        );
        let after_old = provider_store
            .load_sender_key_record(receiver_key)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(after_old, old_decrypted.record);
        let after_old = decode_signal_sender_key_record(&after_old).unwrap();
        assert_eq!(after_old.states.len(), 2);
        assert_eq!(after_old.states[0].chain_key.iteration, 7);
        assert_eq!(
            after_old.states[0].signing_public_key,
            Bytes::copy_from_slice(&prefixed_signal_public_key(&replacement_signing_key.public))
        );
        assert_eq!(after_old.states[1].chain_key.iteration, 3);
        assert_eq!(
            after_old.states[1].signing_public_key,
            Bytes::copy_from_slice(&prefixed_signal_public_key(&old_signing_key.public))
        );

        let replacement_decrypted = provider_store
            .decrypt_sender_key_record_message(
                receiver_key,
                &replacement_encrypted.message_bytes,
                XEdDsaNoiseCertificateVerifier,
            )
            .await
            .unwrap();
        assert_eq!(
            replacement_decrypted.plaintext,
            Bytes::from_static(b"replacement sender-key state")
        );
        let stored_receiver_record = provider_store
            .load_sender_key_record(receiver_key)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored_receiver_record, replacement_decrypted.record);
        let after_replacement = decode_signal_sender_key_record(&stored_receiver_record).unwrap();
        assert_eq!(after_replacement.states.len(), 2);
        assert_eq!(
            after_replacement.states[0].chain_key.iteration,
            expected_replacement_chain.iteration
        );
        assert_eq!(
            after_replacement.states[0].chain_key.key.expose(),
            expected_replacement_chain.key.expose()
        );
        assert_eq!(
            after_replacement.states[0].signing_public_key,
            Bytes::copy_from_slice(&prefixed_signal_public_key(&replacement_signing_key.public))
        );
        assert_eq!(after_replacement.states[1].chain_key.iteration, 3);
        assert_eq!(
            after_replacement.states[1].signing_public_key,
            Bytes::copy_from_slice(&prefixed_signal_public_key(&old_signing_key.public))
        );
    }

    #[tokio::test]
    async fn provider_state_store_preserves_later_sender_key_state_after_invalid_signature() {
        let store = temp_store().await;
        let provider_store = SignalProviderStateStore::new(store.clone());
        let old_signing_key = generate_key_pair();
        let replacement_signing_key = generate_key_pair();
        let key_id = 92;
        let old_chain_key = vec![0x42u8; 32];
        let replacement_chain_key = vec![0x62u8; 32];
        let receiver_key = "555@g.us|receiver";
        let old_sender_record = encode_signal_sender_key_record(&SignalSenderKeyRecord {
            states: vec![SignalSenderKeyState {
                key_id,
                chain_key: SignalSenderChainKey {
                    key: SecretBytes::from(old_chain_key.clone()),
                    iteration: 2,
                },
                signing_public_key: Bytes::copy_from_slice(&prefixed_signal_public_key(
                    &old_signing_key.public,
                )),
                signing_private_key: Some(SecretBytes::from(
                    old_signing_key.private.expose().to_vec(),
                )),
                message_keys: Vec::new(),
            }],
        })
        .unwrap();
        let old_encrypted =
            encrypt_signal_sender_key_record_message(&old_sender_record, b"old sender-key state")
                .unwrap();
        let replacement_sender_record = encode_signal_sender_key_record(&SignalSenderKeyRecord {
            states: vec![SignalSenderKeyState {
                key_id,
                chain_key: SignalSenderChainKey {
                    key: SecretBytes::from(replacement_chain_key.clone()),
                    iteration: 7,
                },
                signing_public_key: Bytes::copy_from_slice(&prefixed_signal_public_key(
                    &replacement_signing_key.public,
                )),
                signing_private_key: Some(SecretBytes::from(
                    replacement_signing_key.private.expose().to_vec(),
                )),
                message_keys: Vec::new(),
            }],
        })
        .unwrap();
        let replacement_encrypted = encrypt_signal_sender_key_record_message(
            &replacement_sender_record,
            b"replacement sender-key state",
        )
        .unwrap();
        let expected_replacement_chain = ratchet_signal_sender_chain(&SignalSenderChainKey {
            key: SecretBytes::from(replacement_chain_key.clone()),
            iteration: 7,
        })
        .unwrap()
        .next_chain_key;
        let receiver_record = encode_signal_sender_key_record(&SignalSenderKeyRecord {
            states: vec![
                SignalSenderKeyState {
                    key_id,
                    chain_key: SignalSenderChainKey {
                        key: SecretBytes::from(replacement_chain_key),
                        iteration: 7,
                    },
                    signing_public_key: Bytes::copy_from_slice(&prefixed_signal_public_key(
                        &replacement_signing_key.public,
                    )),
                    signing_private_key: None,
                    message_keys: Vec::new(),
                },
                SignalSenderKeyState {
                    key_id,
                    chain_key: SignalSenderChainKey {
                        key: SecretBytes::from(old_chain_key),
                        iteration: 2,
                    },
                    signing_public_key: Bytes::copy_from_slice(&prefixed_signal_public_key(
                        &old_signing_key.public,
                    )),
                    signing_private_key: None,
                    message_keys: Vec::new(),
                },
            ],
        })
        .unwrap();
        provider_store
            .store_sender_key_record(receiver_key, &receiver_record)
            .await
            .unwrap();

        let mut invalid_signature_message = old_encrypted.message_bytes.to_vec();
        *invalid_signature_message.last_mut().unwrap() ^= 1;
        let err = provider_store
            .decrypt_sender_key_record_message(
                receiver_key,
                &invalid_signature_message,
                XEdDsaNoiseCertificateVerifier,
            )
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            CoreError::Protocol(message)
                if message == "invalid Signal sender-key message signature"
        ));
        assert_eq!(
            provider_store
                .load_sender_key_record(receiver_key)
                .await
                .unwrap()
                .unwrap(),
            receiver_record
        );

        let decrypted = provider_store
            .decrypt_sender_key_record_message(
                receiver_key,
                &old_encrypted.message_bytes,
                XEdDsaNoiseCertificateVerifier,
            )
            .await
            .unwrap();
        assert_eq!(
            decrypted.plaintext,
            Bytes::from_static(b"old sender-key state")
        );
        let decoded = decode_signal_sender_key_record(&decrypted.record).unwrap();
        assert_eq!(decoded.states[0].chain_key.iteration, 7);
        assert_eq!(decoded.states[1].chain_key.iteration, 3);

        let replacement_decrypted = provider_store
            .decrypt_sender_key_record_message(
                receiver_key,
                &replacement_encrypted.message_bytes,
                XEdDsaNoiseCertificateVerifier,
            )
            .await
            .unwrap();
        assert_eq!(
            replacement_decrypted.plaintext,
            Bytes::from_static(b"replacement sender-key state")
        );
        let stored_after_replacement = provider_store
            .load_sender_key_record(receiver_key)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored_after_replacement, replacement_decrypted.record);
        let decoded_after_replacement =
            decode_signal_sender_key_record(&stored_after_replacement).unwrap();
        assert_eq!(
            decoded_after_replacement.states[0].chain_key.iteration,
            expected_replacement_chain.iteration
        );
        assert_eq!(
            decoded_after_replacement.states[0].chain_key.key.expose(),
            expected_replacement_chain.key.expose()
        );
        assert_eq!(decoded_after_replacement.states[1].chain_key.iteration, 3);
    }

    #[tokio::test]
    async fn provider_state_store_preserves_later_sender_key_state_after_failed_decrypt() {
        let store = temp_store().await;
        let provider_store = SignalProviderStateStore::new(store.clone());
        let old_signing_key = generate_key_pair();
        let replacement_signing_key = generate_key_pair();
        let key_id = 93;
        let old_chain_key = vec![0x43u8; 32];
        let replacement_chain_key = vec![0x63u8; 32];
        let receiver_key = "555@g.us|receiver";
        let old_sender_record = encode_signal_sender_key_record(&SignalSenderKeyRecord {
            states: vec![SignalSenderKeyState {
                key_id,
                chain_key: SignalSenderChainKey {
                    key: SecretBytes::from(old_chain_key.clone()),
                    iteration: 2,
                },
                signing_public_key: Bytes::copy_from_slice(&prefixed_signal_public_key(
                    &old_signing_key.public,
                )),
                signing_private_key: Some(SecretBytes::from(
                    old_signing_key.private.expose().to_vec(),
                )),
                message_keys: Vec::new(),
            }],
        })
        .unwrap();
        let old_encrypted =
            encrypt_signal_sender_key_record_message(&old_sender_record, b"old sender-key state")
                .unwrap();
        let replacement_sender_record = encode_signal_sender_key_record(&SignalSenderKeyRecord {
            states: vec![SignalSenderKeyState {
                key_id,
                chain_key: SignalSenderChainKey {
                    key: SecretBytes::from(replacement_chain_key.clone()),
                    iteration: 7,
                },
                signing_public_key: Bytes::copy_from_slice(&prefixed_signal_public_key(
                    &replacement_signing_key.public,
                )),
                signing_private_key: Some(SecretBytes::from(
                    replacement_signing_key.private.expose().to_vec(),
                )),
                message_keys: Vec::new(),
            }],
        })
        .unwrap();
        let replacement_encrypted = encrypt_signal_sender_key_record_message(
            &replacement_sender_record,
            b"replacement sender-key state",
        )
        .unwrap();
        let expected_replacement_chain = ratchet_signal_sender_chain(&SignalSenderChainKey {
            key: SecretBytes::from(replacement_chain_key.clone()),
            iteration: 7,
        })
        .unwrap()
        .next_chain_key;
        let receiver_record = encode_signal_sender_key_record(&SignalSenderKeyRecord {
            states: vec![
                SignalSenderKeyState {
                    key_id,
                    chain_key: SignalSenderChainKey {
                        key: SecretBytes::from(replacement_chain_key),
                        iteration: 7,
                    },
                    signing_public_key: Bytes::copy_from_slice(&prefixed_signal_public_key(
                        &replacement_signing_key.public,
                    )),
                    signing_private_key: None,
                    message_keys: Vec::new(),
                },
                SignalSenderKeyState {
                    key_id,
                    chain_key: SignalSenderChainKey {
                        key: SecretBytes::from(old_chain_key),
                        iteration: 2,
                    },
                    signing_public_key: Bytes::copy_from_slice(&prefixed_signal_public_key(
                        &old_signing_key.public,
                    )),
                    signing_private_key: None,
                    message_keys: Vec::new(),
                },
            ],
        })
        .unwrap();
        provider_store
            .store_sender_key_record(receiver_key, &receiver_record)
            .await
            .unwrap();

        let decoded_message =
            decode_signal_sender_key_message(&old_encrypted.message_bytes).unwrap();
        let failed_decrypt_message = sign_signal_sender_key_message(
            decoded_message.key_id,
            decoded_message.iteration,
            Bytes::from_static(b"not-a-valid-cbc-frame"),
            old_signing_key.private.expose(),
        )
        .unwrap();
        let failed_decrypt_message =
            encode_signal_sender_key_message(&failed_decrypt_message).unwrap();
        let err = provider_store
            .decrypt_sender_key_record_message(
                receiver_key,
                &failed_decrypt_message,
                XEdDsaNoiseCertificateVerifier,
            )
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            CoreError::Crypto(wa_crypto::CryptoError::Decrypt)
        ));
        assert_eq!(
            provider_store
                .load_sender_key_record(receiver_key)
                .await
                .unwrap()
                .unwrap(),
            receiver_record
        );

        let decrypted = provider_store
            .decrypt_sender_key_record_message(
                receiver_key,
                &old_encrypted.message_bytes,
                XEdDsaNoiseCertificateVerifier,
            )
            .await
            .unwrap();
        assert_eq!(
            decrypted.plaintext,
            Bytes::from_static(b"old sender-key state")
        );
        let decoded = decode_signal_sender_key_record(&decrypted.record).unwrap();
        assert_eq!(decoded.states[0].chain_key.iteration, 7);
        assert_eq!(decoded.states[1].chain_key.iteration, 3);

        let replacement_decrypted = provider_store
            .decrypt_sender_key_record_message(
                receiver_key,
                &replacement_encrypted.message_bytes,
                XEdDsaNoiseCertificateVerifier,
            )
            .await
            .unwrap();
        assert_eq!(
            replacement_decrypted.plaintext,
            Bytes::from_static(b"replacement sender-key state")
        );
        let stored_after_replacement = provider_store
            .load_sender_key_record(receiver_key)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored_after_replacement, replacement_decrypted.record);
        let decoded_after_replacement =
            decode_signal_sender_key_record(&stored_after_replacement).unwrap();
        assert_eq!(
            decoded_after_replacement.states[0].chain_key.iteration,
            expected_replacement_chain.iteration
        );
        assert_eq!(
            decoded_after_replacement.states[0].chain_key.key.expose(),
            expected_replacement_chain.key.expose()
        );
        assert_eq!(decoded_after_replacement.states[1].chain_key.iteration, 3);
    }

    #[tokio::test]
    async fn provider_state_store_preserves_later_sender_key_state_after_far_future() {
        let store = temp_store().await;
        let provider_store = SignalProviderStateStore::new(store.clone());
        let old_signing_key = generate_key_pair();
        let replacement_signing_key = generate_key_pair();
        let key_id = 94;
        let old_chain_key = vec![0x44u8; 32];
        let replacement_chain_key = vec![0x64u8; 32];
        let receiver_key = "555@g.us|receiver";
        let old_sender_record = encode_signal_sender_key_record(&SignalSenderKeyRecord {
            states: vec![SignalSenderKeyState {
                key_id,
                chain_key: SignalSenderChainKey {
                    key: SecretBytes::from(old_chain_key.clone()),
                    iteration: 2,
                },
                signing_public_key: Bytes::copy_from_slice(&prefixed_signal_public_key(
                    &old_signing_key.public,
                )),
                signing_private_key: Some(SecretBytes::from(
                    old_signing_key.private.expose().to_vec(),
                )),
                message_keys: Vec::new(),
            }],
        })
        .unwrap();
        let old_encrypted =
            encrypt_signal_sender_key_record_message(&old_sender_record, b"old sender-key state")
                .unwrap();
        let replacement_sender_record = encode_signal_sender_key_record(&SignalSenderKeyRecord {
            states: vec![SignalSenderKeyState {
                key_id,
                chain_key: SignalSenderChainKey {
                    key: SecretBytes::from(replacement_chain_key.clone()),
                    iteration: 7,
                },
                signing_public_key: Bytes::copy_from_slice(&prefixed_signal_public_key(
                    &replacement_signing_key.public,
                )),
                signing_private_key: Some(SecretBytes::from(
                    replacement_signing_key.private.expose().to_vec(),
                )),
                message_keys: Vec::new(),
            }],
        })
        .unwrap();
        let replacement_encrypted = encrypt_signal_sender_key_record_message(
            &replacement_sender_record,
            b"replacement sender-key state",
        )
        .unwrap();
        let expected_replacement_chain = ratchet_signal_sender_chain(&SignalSenderChainKey {
            key: SecretBytes::from(replacement_chain_key.clone()),
            iteration: 7,
        })
        .unwrap()
        .next_chain_key;
        let receiver_record = encode_signal_sender_key_record(&SignalSenderKeyRecord {
            states: vec![
                SignalSenderKeyState {
                    key_id,
                    chain_key: SignalSenderChainKey {
                        key: SecretBytes::from(replacement_chain_key),
                        iteration: 7,
                    },
                    signing_public_key: Bytes::copy_from_slice(&prefixed_signal_public_key(
                        &replacement_signing_key.public,
                    )),
                    signing_private_key: None,
                    message_keys: Vec::new(),
                },
                SignalSenderKeyState {
                    key_id,
                    chain_key: SignalSenderChainKey {
                        key: SecretBytes::from(old_chain_key),
                        iteration: 2,
                    },
                    signing_public_key: Bytes::copy_from_slice(&prefixed_signal_public_key(
                        &old_signing_key.public,
                    )),
                    signing_private_key: None,
                    message_keys: Vec::new(),
                },
            ],
        })
        .unwrap();
        provider_store
            .store_sender_key_record(receiver_key, &receiver_record)
            .await
            .unwrap();

        let far_future_message = sign_signal_sender_key_message(
            key_id,
            2 + SIGNAL_MAX_SENDER_FORWARD_JUMPS + 1,
            Bytes::from_static(b"far-future-ciphertext"),
            old_signing_key.private.expose(),
        )
        .unwrap();
        let far_future_message = encode_signal_sender_key_message(&far_future_message).unwrap();
        let err = provider_store
            .decrypt_sender_key_record_message(
                receiver_key,
                &far_future_message,
                XEdDsaNoiseCertificateVerifier,
            )
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            CoreError::Protocol(message)
                if message == "Signal sender-key message is too far in the future: 25001"
        ));
        assert_eq!(
            provider_store
                .load_sender_key_record(receiver_key)
                .await
                .unwrap()
                .unwrap(),
            receiver_record
        );

        let decrypted = provider_store
            .decrypt_sender_key_record_message(
                receiver_key,
                &old_encrypted.message_bytes,
                XEdDsaNoiseCertificateVerifier,
            )
            .await
            .unwrap();
        assert_eq!(
            decrypted.plaintext,
            Bytes::from_static(b"old sender-key state")
        );
        let decoded = decode_signal_sender_key_record(&decrypted.record).unwrap();
        assert_eq!(decoded.states[0].chain_key.iteration, 7);
        assert_eq!(decoded.states[1].chain_key.iteration, 3);

        let replacement_decrypted = provider_store
            .decrypt_sender_key_record_message(
                receiver_key,
                &replacement_encrypted.message_bytes,
                XEdDsaNoiseCertificateVerifier,
            )
            .await
            .unwrap();
        assert_eq!(
            replacement_decrypted.plaintext,
            Bytes::from_static(b"replacement sender-key state")
        );
        let stored_after_replacement = provider_store
            .load_sender_key_record(receiver_key)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored_after_replacement, replacement_decrypted.record);
        let decoded_after_replacement =
            decode_signal_sender_key_record(&stored_after_replacement).unwrap();
        assert_eq!(
            decoded_after_replacement.states[0].chain_key.iteration,
            expected_replacement_chain.iteration
        );
        assert_eq!(
            decoded_after_replacement.states[0].chain_key.key.expose(),
            expected_replacement_chain.key.expose()
        );
        assert_eq!(decoded_after_replacement.states[1].chain_key.iteration, 3);
    }

    #[tokio::test]
    async fn provider_state_store_rejects_later_sender_key_state_replay_without_mutation() {
        let store = temp_store().await;
        let provider_store = SignalProviderStateStore::new(store.clone());
        let old_signing_key = generate_key_pair();
        let replacement_signing_key = generate_key_pair();
        let key_id = 95;
        let old_chain_key = vec![0x45u8; 32];
        let replacement_chain_key = vec![0x65u8; 32];
        let receiver_key = "555@g.us|receiver";
        let old_sender_record = encode_signal_sender_key_record(&SignalSenderKeyRecord {
            states: vec![SignalSenderKeyState {
                key_id,
                chain_key: SignalSenderChainKey {
                    key: SecretBytes::from(old_chain_key.clone()),
                    iteration: 2,
                },
                signing_public_key: Bytes::copy_from_slice(&prefixed_signal_public_key(
                    &old_signing_key.public,
                )),
                signing_private_key: Some(SecretBytes::from(
                    old_signing_key.private.expose().to_vec(),
                )),
                message_keys: Vec::new(),
            }],
        })
        .unwrap();
        let old_encrypted =
            encrypt_signal_sender_key_record_message(&old_sender_record, b"old sender-key state")
                .unwrap();
        let replacement_sender_record = encode_signal_sender_key_record(&SignalSenderKeyRecord {
            states: vec![SignalSenderKeyState {
                key_id,
                chain_key: SignalSenderChainKey {
                    key: SecretBytes::from(replacement_chain_key.clone()),
                    iteration: 7,
                },
                signing_public_key: Bytes::copy_from_slice(&prefixed_signal_public_key(
                    &replacement_signing_key.public,
                )),
                signing_private_key: Some(SecretBytes::from(
                    replacement_signing_key.private.expose().to_vec(),
                )),
                message_keys: Vec::new(),
            }],
        })
        .unwrap();
        let replacement_encrypted = encrypt_signal_sender_key_record_message(
            &replacement_sender_record,
            b"replacement sender-key state",
        )
        .unwrap();
        let expected_replacement_chain = ratchet_signal_sender_chain(&SignalSenderChainKey {
            key: SecretBytes::from(replacement_chain_key.clone()),
            iteration: 7,
        })
        .unwrap()
        .next_chain_key;
        let receiver_record = encode_signal_sender_key_record(&SignalSenderKeyRecord {
            states: vec![
                SignalSenderKeyState {
                    key_id,
                    chain_key: SignalSenderChainKey {
                        key: SecretBytes::from(replacement_chain_key),
                        iteration: 7,
                    },
                    signing_public_key: Bytes::copy_from_slice(&prefixed_signal_public_key(
                        &replacement_signing_key.public,
                    )),
                    signing_private_key: None,
                    message_keys: Vec::new(),
                },
                SignalSenderKeyState {
                    key_id,
                    chain_key: SignalSenderChainKey {
                        key: SecretBytes::from(old_chain_key),
                        iteration: 2,
                    },
                    signing_public_key: Bytes::copy_from_slice(&prefixed_signal_public_key(
                        &old_signing_key.public,
                    )),
                    signing_private_key: None,
                    message_keys: Vec::new(),
                },
            ],
        })
        .unwrap();
        provider_store
            .store_sender_key_record(receiver_key, &receiver_record)
            .await
            .unwrap();

        let decrypted = provider_store
            .decrypt_sender_key_record_message(
                receiver_key,
                &old_encrypted.message_bytes,
                XEdDsaNoiseCertificateVerifier,
            )
            .await
            .unwrap();
        assert_eq!(
            decrypted.plaintext,
            Bytes::from_static(b"old sender-key state")
        );
        let stored_after_first = provider_store
            .load_sender_key_record(receiver_key)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored_after_first, decrypted.record);
        let decoded_after_first = decode_signal_sender_key_record(&stored_after_first).unwrap();
        assert_eq!(decoded_after_first.states[0].chain_key.iteration, 7);
        assert_eq!(decoded_after_first.states[1].chain_key.iteration, 3);

        let replay_err = provider_store
            .decrypt_sender_key_record_message(
                receiver_key,
                &old_encrypted.message_bytes,
                XEdDsaNoiseCertificateVerifier,
            )
            .await
            .unwrap_err();
        assert!(matches!(
            replay_err,
            CoreError::Protocol(message)
                if message == "duplicate Signal sender-key message iteration: 2"
        ));
        assert_eq!(
            provider_store
                .load_sender_key_record(receiver_key)
                .await
                .unwrap()
                .unwrap(),
            stored_after_first
        );

        let replacement_decrypted = provider_store
            .decrypt_sender_key_record_message(
                receiver_key,
                &replacement_encrypted.message_bytes,
                XEdDsaNoiseCertificateVerifier,
            )
            .await
            .unwrap();
        assert_eq!(
            replacement_decrypted.plaintext,
            Bytes::from_static(b"replacement sender-key state")
        );
        let stored_after_replacement = provider_store
            .load_sender_key_record(receiver_key)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored_after_replacement, replacement_decrypted.record);
        let decoded_after_replacement =
            decode_signal_sender_key_record(&stored_after_replacement).unwrap();
        assert_eq!(
            decoded_after_replacement.states[0].chain_key.iteration,
            expected_replacement_chain.iteration
        );
        assert_eq!(
            decoded_after_replacement.states[0].chain_key.key.expose(),
            expected_replacement_chain.key.expose()
        );
        assert_eq!(decoded_after_replacement.states[1].chain_key.iteration, 3);
    }

    #[tokio::test]
    async fn provider_state_store_rejects_invalid_sender_key_record_without_mutation() {
        let store = temp_store().await;
        let provider_store = SignalProviderStateStore::new(store.clone());
        let mismatched_private = test_key_pair(0xc0);
        let duplicate_state_signing = test_key_pair(0x81);
        let duplicate_state_public =
            Bytes::copy_from_slice(&prefixed_signal_public_key(&duplicate_state_signing.public));
        let skipped_signing = test_key_pair(0x82);
        let skipped_public =
            Bytes::copy_from_slice(&prefixed_signal_public_key(&skipped_signing.public));
        let invalid_records = vec![
            (
                "mismatched-signing-key",
                raw_sender_key_record(vec![raw_sender_key_state(
                    101,
                    9,
                    0x11,
                    prefixed_test_signal_key(0xa0),
                    Some(Bytes::copy_from_slice(mismatched_private.private.expose())),
                    &[(4, 0x21)],
                )]),
                "Signal sender-key signing public key does not match private key",
            ),
            (
                "duplicate-state",
                raw_sender_key_record(vec![
                    raw_sender_key_state(102, 9, 0x12, duplicate_state_public.clone(), None, &[]),
                    raw_sender_key_state(102, 10, 0x13, duplicate_state_public, None, &[]),
                ]),
                "duplicate Signal sender-key state",
            ),
            (
                "duplicate-skipped-iteration",
                raw_sender_key_record(vec![raw_sender_key_state(
                    103,
                    9,
                    0x14,
                    skipped_public.clone(),
                    None,
                    &[(3, 0x22), (3, 0x23)],
                )]),
                "duplicate Signal sender-key skipped message iteration",
            ),
            (
                "future-skipped-iteration",
                raw_sender_key_record(vec![raw_sender_key_state(
                    104,
                    9,
                    0x15,
                    skipped_public,
                    None,
                    &[(9, 0x24)],
                )]),
                "Signal sender-key skipped iteration must be below chain iteration",
            ),
        ];

        for (suffix, invalid_record, expected_error) in invalid_records {
            let key = format!("555@g.us|invalid-{suffix}");
            provider_store
                .store_sender_key_record(&key, &invalid_record)
                .await
                .unwrap();
            let err = provider_store
                .decrypt_sender_key_record_message(
                    &key,
                    b"not-read-after-invalid-record",
                    XEdDsaNoiseCertificateVerifier,
                )
                .await
                .unwrap_err();
            assert_eq!(
                err.to_string(),
                format!("protocol error: {expected_error}"),
                "{suffix} expected exact invalid sender-key record error"
            );
            assert_eq!(
                provider_store
                    .load_sender_key_record(&key)
                    .await
                    .unwrap()
                    .unwrap(),
                invalid_record,
                "{suffix} invalid sender-key record should be preserved"
            );
        }
    }

    #[tokio::test]
    async fn provider_state_store_loads_or_creates_local_sender_key_distribution_record() {
        let store = temp_store().await;
        let provider_store = SignalProviderStateStore::new(store.clone());

        let created = provider_store
            .load_or_create_sender_key_distribution_record("999:7@s.whatsapp.net", "555@g.us")
            .await
            .unwrap();

        assert!(created.created);
        assert_eq!(created.key, "555@g.us|999:7@s.whatsapp.net");
        assert_eq!(created.distribution.iteration, 0);
        assert_eq!(
            decode_signal_sender_key_distribution_message(&created.distribution_bytes).unwrap(),
            created.distribution
        );
        let stored = provider_store
            .load_sender_key_record(&created.key)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored, created.record);
        let stored_record = decode_signal_sender_key_record(&stored).unwrap();
        assert_eq!(stored_record.states.len(), 1);
        assert!(stored_record.states[0].signing_private_key.is_some());
        assert_eq!(
            stored_record.states[0].signing_public_key,
            created.distribution.signing_key
        );

        let loaded = provider_store
            .load_or_create_sender_key_distribution_record("999:7@s.whatsapp.net", "555@g.us")
            .await
            .unwrap();
        assert!(!loaded.created);
        assert_eq!(loaded.key, created.key);
        assert_eq!(loaded.record, created.record);
        assert_eq!(loaded.distribution_bytes, created.distribution_bytes);

        let legacy_loaded = provider_store
            .load_or_create_sender_key_distribution_record("999:7@c.us", "555@g.us")
            .await
            .unwrap();
        assert!(!legacy_loaded.created);
        assert_eq!(legacy_loaded.key, created.key);
        assert_eq!(legacy_loaded.record, created.record);
        assert_eq!(legacy_loaded.distribution_bytes, created.distribution_bytes);
    }

    #[tokio::test]
    async fn provider_state_store_recreates_unusable_local_sender_key_distribution_record() {
        let store = temp_store().await;
        let provider_store = SignalProviderStateStore::new(store.clone());
        let author_jid = "999:7@s.whatsapp.net";
        let group_jid = "555@g.us";
        let key = sender_key_store_key(author_jid, group_jid).unwrap();

        provider_store
            .store_sender_key_record(&key, b"opaque-local-sender-key")
            .await
            .unwrap();
        let recovered = provider_store
            .load_or_create_sender_key_distribution_record(author_jid, group_jid)
            .await
            .unwrap();
        assert!(recovered.created);
        assert_eq!(recovered.key, key);
        assert_eq!(
            decode_signal_sender_key_distribution_message(&recovered.distribution_bytes).unwrap(),
            recovered.distribution
        );
        let stored = provider_store
            .load_sender_key_record(&key)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored, recovered.record);
        let stored_record = decode_signal_sender_key_record(&stored).unwrap();
        assert_eq!(stored_record.states.len(), 1);
        assert!(stored_record.states[0].signing_private_key.is_some());
        assert_eq!(
            stored_record.states[0].signing_public_key,
            recovered.distribution.signing_key
        );

        let loaded = provider_store
            .load_or_create_sender_key_distribution_record(author_jid, group_jid)
            .await
            .unwrap();
        assert!(!loaded.created);
        assert_eq!(loaded.record, recovered.record);
        assert_eq!(loaded.distribution_bytes, recovered.distribution_bytes);

        let remote_signing_key = generate_key_pair();
        let remote_distribution = build_signal_sender_key_distribution_message(
            77,
            0,
            &[8u8; 32],
            &remote_signing_key.public,
        )
        .unwrap();
        let no_private_record =
            process_signal_sender_key_distribution_record(None, &remote_distribution).unwrap();
        provider_store
            .store_sender_key_record(&key, &no_private_record)
            .await
            .unwrap();
        let recovered_no_private = provider_store
            .load_or_create_sender_key_distribution_record(author_jid, group_jid)
            .await
            .unwrap();
        assert!(recovered_no_private.created);
        let stored = provider_store
            .load_sender_key_record(&key)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored, recovered_no_private.record);
        let stored_record = decode_signal_sender_key_record(&stored).unwrap();
        assert_eq!(stored_record.states.len(), 1);
        assert!(stored_record.states[0].signing_private_key.is_some());
        assert_eq!(
            stored_record.states[0].signing_public_key,
            recovered_no_private.distribution.signing_key
        );
    }

    #[tokio::test]
    async fn store_sender_key_provider_encrypts_group_relay_from_codec() {
        let store = temp_store().await;
        let local_jid = "999:7@s.whatsapp.net";
        let group_jid = "555@g.us";
        let provider = StoreSignalSenderKeyProvider::new(store.clone())
            .with_local_sender_jid(local_jid)
            .unwrap();
        let signing_key = generate_key_pair();
        let record_key = sender_key_store_key(local_jid, group_jid).unwrap();
        let sender_record = encode_signal_sender_key_record(&SignalSenderKeyRecord {
            states: vec![SignalSenderKeyState {
                key_id: 44,
                chain_key: SignalSenderChainKey {
                    key: SecretBytes::from(vec![4u8; 32]),
                    iteration: 0,
                },
                signing_public_key: Bytes::copy_from_slice(&prefixed_signal_public_key(
                    &signing_key.public,
                )),
                signing_private_key: Some(SecretBytes::from(signing_key.private.expose().to_vec())),
                message_keys: Vec::new(),
            }],
        })
        .unwrap();
        provider
            .state_store()
            .store_sender_key_record(&record_key, &sender_record)
            .await
            .unwrap();
        let codec = SignalMessageCodec::new(StoreSignalRepository::new(store.clone()), provider);

        let relay = build_group_sender_key_message_relay(
            group_jid,
            build_text_message("stored group").unwrap(),
            &codec,
            MessageRelayOptions::new().with_message_id("group-1"),
        )
        .await
        .unwrap();

        assert_eq!(relay.message_id, "group-1");
        let Some(BinaryNodeContent::Nodes(children)) = &relay.node.content else {
            panic!("group relay should contain root enc node");
        };
        assert_eq!(children.len(), 1);
        assert_eq!(children[0].tag, "enc");
        assert_eq!(children[0].attrs["type"], "skmsg");
        let Some(BinaryNodeContent::Bytes(ciphertext)) = &children[0].content else {
            panic!("sender-key enc node should contain bytes");
        };
        let sender_message = decode_signal_sender_key_message(ciphertext).unwrap();
        assert_eq!(sender_message.key_id, 44);
        assert_eq!(sender_message.iteration, 0);
        let stored_record = codec
            .provider()
            .state_store()
            .load_sender_key_record(&record_key)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            decode_signal_sender_key_record(&stored_record)
                .unwrap()
                .states[0]
                .chain_key
                .iteration,
            1
        );
    }

    #[tokio::test]
    async fn store_sender_key_provider_processes_distribution_and_decrypts_group_payload() {
        let sender_store = temp_store().await;
        let receiver_store = temp_store().await;
        let sender_jid = "999:7@s.whatsapp.net";
        let group_jid = "555@g.us";
        let signing_key = generate_key_pair();
        let chain_key = [7u8; 32];
        let sender_record = encode_signal_sender_key_record(&SignalSenderKeyRecord {
            states: vec![SignalSenderKeyState {
                key_id: 55,
                chain_key: SignalSenderChainKey {
                    key: SecretBytes::from(chain_key.to_vec()),
                    iteration: 0,
                },
                signing_public_key: Bytes::copy_from_slice(&prefixed_signal_public_key(
                    &signing_key.public,
                )),
                signing_private_key: Some(SecretBytes::from(signing_key.private.expose().to_vec())),
                message_keys: Vec::new(),
            }],
        })
        .unwrap();
        let sender_record_key = sender_key_store_key(sender_jid, group_jid).unwrap();
        let sender_provider = StoreSignalSenderKeyProvider::new(sender_store.clone())
            .with_local_sender_jid(sender_jid)
            .unwrap();
        sender_provider
            .state_store()
            .store_sender_key_record(&sender_record_key, &sender_record)
            .await
            .unwrap();
        let sender_codec =
            SignalMessageCodec::new(StoreSignalRepository::new(sender_store), sender_provider);
        let encrypted = sender_codec
            .encrypt_message(group_jid, Bytes::from_static(b"group payload"))
            .await
            .unwrap();
        assert_eq!(encrypted.ciphertext_type, MessageCiphertextType::SenderKey);

        let receiver_repository = StoreSignalRepository::new(receiver_store.clone());
        let receiver_provider = StoreSignalSenderKeyProvider::new(receiver_store.clone());
        let receiver_provider_probe = receiver_provider.clone();
        let receiver_codec =
            SignalMessageCodec::new(receiver_repository.clone(), receiver_provider);
        let distribution =
            build_signal_sender_key_distribution_message(55, 0, &chain_key, &signing_key.public)
                .unwrap();
        let distribution_bytes =
            encode_signal_sender_key_distribution_message(&distribution).unwrap();
        receiver_codec
            .process_sender_key_distribution(
                sender_jid,
                &SenderKeyDistributionMessage {
                    group_id: Some(group_jid.to_owned()),
                    axolotl_sender_key_distribution_message: Some(distribution_bytes.clone()),
                },
            )
            .await
            .unwrap();

        assert_eq!(
            receiver_repository
                .get_sender_key_distribution(sender_jid, group_jid)
                .await
                .unwrap(),
            Some(distribution_bytes)
        );
        let receiver_record_key = sender_key_store_key(sender_jid, group_jid).unwrap();
        assert!(
            receiver_provider_probe
                .state_store()
                .load_sender_key_record(&receiver_record_key)
                .await
                .unwrap()
                .is_some()
        );

        let plaintext = receiver_codec
            .decrypt_inbound_message(InboundEncryptedPayload {
                sender_jid: sender_jid.to_owned(),
                chat_jid: group_jid.to_owned(),
                ciphertext_type: InboundCiphertextType::SenderKey,
                ciphertext: encrypted.ciphertext,
            })
            .await
            .unwrap();
        assert_eq!(plaintext, Bytes::from_static(b"group payload"));
    }

    #[tokio::test]
    async fn store_sender_key_provider_does_not_persist_rejected_distribution() {
        let receiver_store = temp_store().await;
        let receiver_repository = StoreSignalRepository::new(receiver_store.clone());
        let receiver_provider = StoreSignalSenderKeyProvider::new(receiver_store.clone());
        let receiver_provider_probe = receiver_provider.clone();
        let receiver_codec =
            SignalMessageCodec::new(receiver_repository.clone(), receiver_provider);
        let sender_jid = "999:7@s.whatsapp.net";
        let group_jid = "555@g.us";
        let err = receiver_codec
            .process_sender_key_distribution(
                sender_jid,
                &SenderKeyDistributionMessage {
                    group_id: Some(group_jid.to_owned()),
                    axolotl_sender_key_distribution_message: Some(Bytes::from_static(
                        b"not-a-sender-key-distribution",
                    )),
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            CoreError::Protocol(message)
                if message == "Signal sender-key distribution message is too short: 29"
        ));

        assert!(
            receiver_repository
                .get_sender_key_distribution(sender_jid, group_jid)
                .await
                .unwrap()
                .is_none()
        );
        let receiver_record_key = sender_key_store_key(sender_jid, group_jid).unwrap();
        assert!(
            receiver_provider_probe
                .state_store()
                .load_sender_key_record(&receiver_record_key)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn store_signal_repository_rejects_malformed_sender_key_distribution_memory() {
        let store = temp_store().await;
        let repository = StoreSignalRepository::new(store.clone());
        let sender_jid = "999:7@s.whatsapp.net";
        let group_jid = "555@g.us";

        let err = repository
            .store_sender_key_distribution(
                sender_jid,
                group_jid,
                Bytes::from_static(b"not-a-sender-key-distribution"),
            )
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            CoreError::Protocol(message)
                if message == "Signal sender-key distribution message is too short: 29"
        ));
        assert!(
            repository
                .get_sender_key_distribution(sender_jid, group_jid)
                .await
                .unwrap()
                .is_none()
        );

        let signing_key = generate_key_pair();
        let distribution =
            build_signal_sender_key_distribution_message(55, 0, &[7u8; 32], &signing_key.public)
                .unwrap();
        let distribution_bytes =
            encode_signal_sender_key_distribution_message(&distribution).unwrap();
        repository
            .store_sender_key_distribution(sender_jid, group_jid, distribution_bytes.clone())
            .await
            .unwrap();
        assert_eq!(
            repository
                .get_sender_key_distribution(sender_jid, group_jid)
                .await
                .unwrap(),
            Some(distribution_bytes.clone())
        );

        let err = repository
            .store_sender_key_distribution(
                sender_jid,
                group_jid,
                Bytes::from_static(b"still-not-a-sender-key-distribution"),
            )
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            CoreError::Protocol(message)
                if message == "Signal sender-key distribution message is too short: 35"
        ));
        assert_eq!(
            repository
                .get_sender_key_distribution(sender_jid, group_jid)
                .await
                .unwrap(),
            Some(distribution_bytes.clone())
        );

        let key = sender_key_store_key(sender_jid, group_jid).unwrap();
        store
            .set_signal_key(
                KeyNamespace::SenderKey,
                &key,
                b"corrupt-existing-sender-key-distribution",
            )
            .await
            .unwrap();
        repository
            .store_sender_key_distribution(sender_jid, group_jid, distribution_bytes.clone())
            .await
            .unwrap();
        assert_eq!(
            repository
                .get_sender_key_distribution(sender_jid, group_jid)
                .await
                .unwrap(),
            Some(distribution_bytes)
        );
    }

    #[tokio::test]
    async fn store_signal_repository_replaces_equal_iteration_same_signer_sender_key_distribution()
    {
        let store = temp_store().await;
        let repository = StoreSignalRepository::new(store);
        let sender_jid = "999:7@s.whatsapp.net";
        let group_jid = "555@g.us";
        let signing_key = generate_key_pair();
        let initial_distribution =
            build_signal_sender_key_distribution_message(56, 4, &[7u8; 32], &signing_key.public)
                .unwrap();
        let initial_distribution_bytes =
            encode_signal_sender_key_distribution_message(&initial_distribution).unwrap();
        let replacement_distribution =
            build_signal_sender_key_distribution_message(56, 4, &[8u8; 32], &signing_key.public)
                .unwrap();
        let replacement_distribution_bytes =
            encode_signal_sender_key_distribution_message(&replacement_distribution).unwrap();

        repository
            .store_sender_key_distribution(
                sender_jid,
                group_jid,
                initial_distribution_bytes.clone(),
            )
            .await
            .unwrap();
        assert_eq!(
            repository
                .get_sender_key_distribution(sender_jid, group_jid)
                .await
                .unwrap(),
            Some(initial_distribution_bytes)
        );

        repository
            .store_sender_key_distribution(
                sender_jid,
                group_jid,
                replacement_distribution_bytes.clone(),
            )
            .await
            .unwrap();
        assert_eq!(
            repository
                .get_sender_key_distribution(sender_jid, group_jid)
                .await
                .unwrap(),
            Some(replacement_distribution_bytes)
        );
    }

    #[tokio::test]
    async fn store_sender_key_provider_recovers_corrupt_record_from_distribution() {
        let sender_store = temp_store().await;
        let receiver_store = temp_store().await;
        let sender_jid = "999:7@s.whatsapp.net";
        let group_jid = "555@g.us";
        let signing_key = generate_key_pair();
        let chain_key = [7u8; 32];
        let sender_record = encode_signal_sender_key_record(&SignalSenderKeyRecord {
            states: vec![SignalSenderKeyState {
                key_id: 55,
                chain_key: SignalSenderChainKey {
                    key: SecretBytes::from(chain_key.to_vec()),
                    iteration: 0,
                },
                signing_public_key: Bytes::copy_from_slice(&prefixed_signal_public_key(
                    &signing_key.public,
                )),
                signing_private_key: Some(SecretBytes::from(signing_key.private.expose().to_vec())),
                message_keys: Vec::new(),
            }],
        })
        .unwrap();
        let sender_record_key = sender_key_store_key(sender_jid, group_jid).unwrap();
        let sender_provider = StoreSignalSenderKeyProvider::new(sender_store.clone())
            .with_local_sender_jid(sender_jid)
            .unwrap();
        sender_provider
            .state_store()
            .store_sender_key_record(&sender_record_key, &sender_record)
            .await
            .unwrap();
        let sender_codec =
            SignalMessageCodec::new(StoreSignalRepository::new(sender_store), sender_provider);
        let encrypted = sender_codec
            .encrypt_message(group_jid, Bytes::from_static(b"group payload"))
            .await
            .unwrap();

        let receiver_repository = StoreSignalRepository::new(receiver_store.clone());
        let receiver_provider = StoreSignalSenderKeyProvider::new(receiver_store.clone());
        let receiver_provider_probe = receiver_provider.clone();
        let receiver_codec =
            SignalMessageCodec::new(receiver_repository.clone(), receiver_provider);
        let distribution =
            build_signal_sender_key_distribution_message(55, 0, &chain_key, &signing_key.public)
                .unwrap();
        let distribution_bytes =
            encode_signal_sender_key_distribution_message(&distribution).unwrap();
        receiver_codec
            .process_sender_key_distribution(
                sender_jid,
                &SenderKeyDistributionMessage {
                    group_id: Some(group_jid.to_owned()),
                    axolotl_sender_key_distribution_message: Some(distribution_bytes.clone()),
                },
            )
            .await
            .unwrap();

        let receiver_record_key = sender_key_store_key(sender_jid, group_jid).unwrap();
        receiver_provider_probe
            .state_store()
            .store_sender_key_record(&receiver_record_key, b"opaque-provider-sender-key")
            .await
            .unwrap();
        assert!(
            decode_signal_sender_key_record(
                &receiver_provider_probe
                    .state_store()
                    .load_sender_key_record(&receiver_record_key)
                    .await
                    .unwrap()
                    .unwrap()
            )
            .is_err()
        );

        let plaintext = receiver_codec
            .decrypt_inbound_message(InboundEncryptedPayload {
                sender_jid: sender_jid.to_owned(),
                chat_jid: group_jid.to_owned(),
                ciphertext_type: InboundCiphertextType::SenderKey,
                ciphertext: encrypted.ciphertext,
            })
            .await
            .unwrap();
        assert_eq!(plaintext, Bytes::from_static(b"group payload"));
        assert_eq!(
            receiver_repository
                .get_sender_key_distribution(sender_jid, group_jid)
                .await
                .unwrap(),
            Some(distribution_bytes)
        );
        let repaired = receiver_provider_probe
            .state_store()
            .load_sender_key_record(&receiver_record_key)
            .await
            .unwrap()
            .unwrap();
        let repaired = decode_signal_sender_key_record(&repaired).unwrap();
        assert_eq!(repaired.states.len(), 1);
        assert_eq!(repaired.states[0].key_id, 55);
        assert_eq!(repaired.states[0].chain_key.iteration, 1);
        assert_eq!(repaired.states[0].signing_private_key, None);
    }

    #[tokio::test]
    async fn store_sender_key_provider_recovers_stale_record_from_distribution_on_decrypt_failure()
    {
        let receiver_store = temp_store().await;
        let sender_jid = "999:7@s.whatsapp.net";
        let group_jid = "555@g.us";
        let receiver_repository = StoreSignalRepository::new(receiver_store.clone());
        let receiver_codec = SignalMessageCodec::new(
            receiver_repository.clone(),
            StoreSignalSenderKeyProvider::new(receiver_store.clone()),
        );
        let receiver_record_key = sender_key_store_key(sender_jid, group_jid).unwrap();

        let stale_signing_key = generate_key_pair();
        let stale_distribution = build_signal_sender_key_distribution_message(
            55,
            0,
            &[7u8; 32],
            &stale_signing_key.public,
        )
        .unwrap();
        receiver_codec
            .process_sender_key_distribution(
                sender_jid,
                &SenderKeyDistributionMessage {
                    group_id: Some(group_jid.to_owned()),
                    axolotl_sender_key_distribution_message: Some(
                        encode_signal_sender_key_distribution_message(&stale_distribution).unwrap(),
                    ),
                },
            )
            .await
            .unwrap();
        assert_eq!(
            decode_signal_sender_key_record(
                &SignalProviderStateStore::new(receiver_store.clone())
                    .load_sender_key_record(&receiver_record_key)
                    .await
                    .unwrap()
                    .unwrap()
            )
            .unwrap()
            .states[0]
                .key_id,
            55
        );

        let fresh_signing_key = generate_key_pair();
        let fresh_chain_key = [9u8; 32];
        let fresh_distribution = build_signal_sender_key_distribution_message(
            99,
            0,
            &fresh_chain_key,
            &fresh_signing_key.public,
        )
        .unwrap();
        let fresh_distribution_bytes =
            encode_signal_sender_key_distribution_message(&fresh_distribution).unwrap();
        receiver_repository
            .store_sender_key_distribution(sender_jid, group_jid, fresh_distribution_bytes.clone())
            .await
            .unwrap();

        let fresh_message_key = ratchet_signal_sender_chain(&SignalSenderChainKey {
            key: SecretBytes::from(fresh_chain_key.to_vec()),
            iteration: 0,
        })
        .unwrap()
        .message_key;
        let fresh_message = sign_signal_sender_key_message(
            99,
            fresh_message_key.iteration,
            encrypt_signal_sender_message_body(b"group fresh", &fresh_message_key).unwrap(),
            fresh_signing_key.private.expose(),
        )
        .unwrap();
        let plaintext = receiver_codec
            .decrypt_inbound_message(InboundEncryptedPayload {
                sender_jid: sender_jid.to_owned(),
                chat_jid: group_jid.to_owned(),
                ciphertext_type: InboundCiphertextType::SenderKey,
                ciphertext: encode_signal_sender_key_message(&fresh_message).unwrap(),
            })
            .await
            .unwrap();
        assert_eq!(plaintext, Bytes::from_static(b"group fresh"));
        assert_eq!(
            receiver_repository
                .get_sender_key_distribution(sender_jid, group_jid)
                .await
                .unwrap(),
            Some(fresh_distribution_bytes)
        );
        let recovered = SignalProviderStateStore::new(receiver_store)
            .load_sender_key_record(&receiver_record_key)
            .await
            .unwrap()
            .unwrap();
        let recovered = decode_signal_sender_key_record(&recovered).unwrap();
        assert_eq!(recovered.states.len(), 2);
        assert_eq!(recovered.states[0].key_id, 99);
        assert_eq!(recovered.states[0].chain_key.iteration, 1);
        assert_eq!(
            recovered.states[0].signing_public_key,
            fresh_distribution.signing_key
        );
        assert_eq!(recovered.states[1].key_id, 55);
    }

    #[tokio::test]
    async fn store_sender_key_provider_recovers_same_signer_stale_chain_from_distribution_after_decrypt_failure()
     {
        let receiver_store = temp_store().await;
        let sender_jid = "999:7@s.whatsapp.net";
        let group_jid = "555@g.us";
        let receiver_repository = StoreSignalRepository::new(receiver_store.clone());
        let receiver_provider_probe = SignalProviderStateStore::new(receiver_store.clone());
        let receiver_codec = SignalMessageCodec::new(
            receiver_repository.clone(),
            StoreSignalSenderKeyProvider::new(receiver_store.clone()),
        );
        let receiver_record_key = sender_key_store_key(sender_jid, group_jid).unwrap();

        let signing_key = generate_key_pair();
        let stale_record = encode_signal_sender_key_record(&SignalSenderKeyRecord {
            states: vec![SignalSenderKeyState {
                key_id: 55,
                chain_key: SignalSenderChainKey {
                    key: SecretBytes::from(vec![7u8; 32]),
                    iteration: 0,
                },
                signing_public_key: Bytes::copy_from_slice(&prefixed_signal_public_key(
                    &signing_key.public,
                )),
                signing_private_key: None,
                message_keys: Vec::new(),
            }],
        })
        .unwrap();
        receiver_provider_probe
            .store_sender_key_record(&receiver_record_key, &stale_record)
            .await
            .unwrap();

        let fresh_chain_key = [9u8; 32];
        let fresh_distribution = build_signal_sender_key_distribution_message(
            55,
            3,
            &fresh_chain_key,
            &signing_key.public,
        )
        .unwrap();
        let fresh_distribution_bytes =
            encode_signal_sender_key_distribution_message(&fresh_distribution).unwrap();
        receiver_repository
            .store_sender_key_distribution(sender_jid, group_jid, fresh_distribution_bytes.clone())
            .await
            .unwrap();

        let fresh_message_key = ratchet_signal_sender_chain(&SignalSenderChainKey {
            key: SecretBytes::from(fresh_chain_key.to_vec()),
            iteration: 3,
        })
        .unwrap()
        .message_key;
        let fresh_message = sign_signal_sender_key_message(
            55,
            fresh_message_key.iteration,
            encrypt_signal_sender_message_body(b"group same-signer fresh", &fresh_message_key)
                .unwrap(),
            signing_key.private.expose(),
        )
        .unwrap();
        let truncated_ciphertext =
            Bytes::copy_from_slice(&fresh_message.ciphertext[..fresh_message.ciphertext.len() - 1]);
        let tampered_fresh_message = sign_signal_sender_key_message(
            55,
            fresh_message_key.iteration,
            truncated_ciphertext,
            signing_key.private.expose(),
        )
        .unwrap();
        let err = receiver_codec
            .decrypt_inbound_message(InboundEncryptedPayload {
                sender_jid: sender_jid.to_owned(),
                chat_jid: group_jid.to_owned(),
                ciphertext_type: InboundCiphertextType::SenderKey,
                ciphertext: encode_signal_sender_key_message(&tampered_fresh_message).unwrap(),
            })
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            CoreError::Crypto(wa_crypto::CryptoError::Decrypt)
        ));
        assert_eq!(
            receiver_provider_probe
                .load_sender_key_record(&receiver_record_key)
                .await
                .unwrap()
                .unwrap(),
            stale_record
        );

        let plaintext = receiver_codec
            .decrypt_inbound_message(InboundEncryptedPayload {
                sender_jid: sender_jid.to_owned(),
                chat_jid: group_jid.to_owned(),
                ciphertext_type: InboundCiphertextType::SenderKey,
                ciphertext: encode_signal_sender_key_message(&fresh_message).unwrap(),
            })
            .await
            .unwrap();
        assert_eq!(plaintext, Bytes::from_static(b"group same-signer fresh"));
        assert_eq!(
            receiver_repository
                .get_sender_key_distribution(sender_jid, group_jid)
                .await
                .unwrap(),
            Some(fresh_distribution_bytes)
        );
        let recovered = receiver_provider_probe
            .load_sender_key_record(&receiver_record_key)
            .await
            .unwrap()
            .unwrap();
        let recovered = decode_signal_sender_key_record(&recovered).unwrap();
        assert_eq!(recovered.states.len(), 1);
        assert_eq!(recovered.states[0].key_id, 55);
        assert_eq!(recovered.states[0].chain_key.iteration, 4);
        assert_eq!(recovered.states[0].chain_key.key.expose().len(), 32);
        assert_eq!(
            recovered.states[0].signing_public_key,
            fresh_distribution.signing_key
        );
        assert_eq!(recovered.states[0].signing_private_key, None);
    }

    #[tokio::test]
    async fn store_sender_key_provider_preserves_stale_record_after_failed_distribution_retry() {
        let receiver_store = temp_store().await;
        let sender_jid = "999:7@s.whatsapp.net";
        let group_jid = "555@g.us";
        let receiver_repository = StoreSignalRepository::new(receiver_store.clone());
        let receiver_codec = SignalMessageCodec::new(
            receiver_repository.clone(),
            StoreSignalSenderKeyProvider::new(receiver_store.clone()),
        );
        let receiver_record_key = sender_key_store_key(sender_jid, group_jid).unwrap();

        let stale_signing_key = generate_key_pair();
        let stale_distribution = build_signal_sender_key_distribution_message(
            55,
            0,
            &[7u8; 32],
            &stale_signing_key.public,
        )
        .unwrap();
        receiver_codec
            .process_sender_key_distribution(
                sender_jid,
                &SenderKeyDistributionMessage {
                    group_id: Some(group_jid.to_owned()),
                    axolotl_sender_key_distribution_message: Some(
                        encode_signal_sender_key_distribution_message(&stale_distribution).unwrap(),
                    ),
                },
            )
            .await
            .unwrap();
        let stale_record = SignalProviderStateStore::new(receiver_store.clone())
            .load_sender_key_record(&receiver_record_key)
            .await
            .unwrap()
            .unwrap();

        let fresh_signing_key = generate_key_pair();
        let fresh_chain_key = [9u8; 32];
        let fresh_distribution = build_signal_sender_key_distribution_message(
            99,
            0,
            &fresh_chain_key,
            &fresh_signing_key.public,
        )
        .unwrap();
        receiver_repository
            .store_sender_key_distribution(
                sender_jid,
                group_jid,
                encode_signal_sender_key_distribution_message(&fresh_distribution).unwrap(),
            )
            .await
            .unwrap();

        let fresh_message_key = ratchet_signal_sender_chain(&SignalSenderChainKey {
            key: SecretBytes::from(fresh_chain_key.to_vec()),
            iteration: 0,
        })
        .unwrap()
        .message_key;
        let fresh_message = sign_signal_sender_key_message(
            99,
            fresh_message_key.iteration,
            encrypt_signal_sender_message_body(b"group fresh", &fresh_message_key).unwrap(),
            fresh_signing_key.private.expose(),
        )
        .unwrap();
        let fresh_message = encode_signal_sender_key_message(&fresh_message).unwrap();
        let mut tampered_message = fresh_message.to_vec();
        *tampered_message.last_mut().unwrap() ^= 1;
        let err = receiver_codec
            .decrypt_inbound_message(InboundEncryptedPayload {
                sender_jid: sender_jid.to_owned(),
                chat_jid: group_jid.to_owned(),
                ciphertext_type: InboundCiphertextType::SenderKey,
                ciphertext: Bytes::from(tampered_message),
            })
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            CoreError::Protocol(message)
                if message == "invalid Signal sender-key message signature"
        ));
        assert_eq!(
            SignalProviderStateStore::new(receiver_store.clone())
                .load_sender_key_record(&receiver_record_key)
                .await
                .unwrap()
                .unwrap(),
            stale_record
        );

        let plaintext = receiver_codec
            .decrypt_inbound_message(InboundEncryptedPayload {
                sender_jid: sender_jid.to_owned(),
                chat_jid: group_jid.to_owned(),
                ciphertext_type: InboundCiphertextType::SenderKey,
                ciphertext: fresh_message,
            })
            .await
            .unwrap();
        assert_eq!(plaintext, Bytes::from_static(b"group fresh"));
        let recovered = SignalProviderStateStore::new(receiver_store)
            .load_sender_key_record(&receiver_record_key)
            .await
            .unwrap()
            .unwrap();
        let recovered = decode_signal_sender_key_record(&recovered).unwrap();
        assert_eq!(recovered.states[0].key_id, 99);
        assert_eq!(recovered.states[0].chain_key.iteration, 1);
    }

    #[tokio::test]
    async fn store_sender_key_provider_preserves_missing_or_corrupt_record_after_failed_attached_distribution()
     {
        for initial_record in [
            None,
            Some(Bytes::from_static(b"opaque-provider-sender-key")),
        ] {
            let receiver_store = temp_store().await;
            let sender_jid = "999:7@s.whatsapp.net";
            let group_jid = "555@g.us";
            let receiver_repository = StoreSignalRepository::new(receiver_store.clone());
            let receiver_codec = SignalMessageCodec::new(
                receiver_repository.clone(),
                StoreSignalSenderKeyProvider::new(receiver_store.clone()),
            );
            let receiver_provider_probe = SignalProviderStateStore::new(receiver_store.clone());
            let receiver_record_key = sender_key_store_key(sender_jid, group_jid).unwrap();
            if let Some(record) = initial_record.as_ref() {
                receiver_provider_probe
                    .store_sender_key_record(&receiver_record_key, record)
                    .await
                    .unwrap();
            }

            let signing_key = generate_key_pair();
            let chain_key = [9u8; 32];
            let distribution = build_signal_sender_key_distribution_message(
                99,
                0,
                &chain_key,
                &signing_key.public,
            )
            .unwrap();
            receiver_repository
                .store_sender_key_distribution(
                    sender_jid,
                    group_jid,
                    encode_signal_sender_key_distribution_message(&distribution).unwrap(),
                )
                .await
                .unwrap();
            let message_key = ratchet_signal_sender_chain(&SignalSenderChainKey {
                key: SecretBytes::from(chain_key.to_vec()),
                iteration: 0,
            })
            .unwrap()
            .message_key;
            let message = sign_signal_sender_key_message(
                99,
                message_key.iteration,
                encrypt_signal_sender_message_body(b"group fresh", &message_key).unwrap(),
                signing_key.private.expose(),
            )
            .unwrap();
            let message = encode_signal_sender_key_message(&message).unwrap();
            let mut tampered_message = message.to_vec();
            *tampered_message.last_mut().unwrap() ^= 1;

            let err = receiver_codec
                .decrypt_inbound_message(InboundEncryptedPayload {
                    sender_jid: sender_jid.to_owned(),
                    chat_jid: group_jid.to_owned(),
                    ciphertext_type: InboundCiphertextType::SenderKey,
                    ciphertext: Bytes::from(tampered_message),
                })
                .await
                .unwrap_err();
            assert!(matches!(
                err,
                CoreError::Protocol(message)
                    if message == "invalid Signal sender-key message signature"
            ));
            assert_eq!(
                receiver_provider_probe
                    .load_sender_key_record(&receiver_record_key)
                    .await
                    .unwrap(),
                initial_record
            );

            let plaintext = receiver_codec
                .decrypt_inbound_message(InboundEncryptedPayload {
                    sender_jid: sender_jid.to_owned(),
                    chat_jid: group_jid.to_owned(),
                    ciphertext_type: InboundCiphertextType::SenderKey,
                    ciphertext: message,
                })
                .await
                .unwrap();
            assert_eq!(plaintext, Bytes::from_static(b"group fresh"));
            let recovered = receiver_provider_probe
                .load_sender_key_record(&receiver_record_key)
                .await
                .unwrap()
                .unwrap();
            let recovered = decode_signal_sender_key_record(&recovered).unwrap();
            assert_eq!(recovered.states.len(), 1);
            assert_eq!(recovered.states[0].key_id, 99);
            assert_eq!(recovered.states[0].chain_key.iteration, 1);
        }
    }

    #[tokio::test]
    async fn store_sender_key_provider_processes_stale_and_replacement_distributions_from_store() {
        let receiver_store = temp_store().await;
        let sender_jid = "999:7@s.whatsapp.net";
        let group_jid = "555@g.us";
        let key_id = 77;
        let signing_key_a = generate_key_pair();
        let signing_key_b = generate_key_pair();
        let receiver_repository = StoreSignalRepository::new(receiver_store.clone());
        let receiver_codec = SignalMessageCodec::new(
            receiver_repository.clone(),
            StoreSignalSenderKeyProvider::new(receiver_store.clone()),
        );
        let distribution_a = build_signal_sender_key_distribution_message(
            key_id,
            0,
            &[7u8; 32],
            &signing_key_a.public,
        )
        .unwrap();
        let distribution_a_bytes =
            encode_signal_sender_key_distribution_message(&distribution_a).unwrap();
        receiver_codec
            .process_sender_key_distribution(
                sender_jid,
                &SenderKeyDistributionMessage {
                    group_id: Some(group_jid.to_owned()),
                    axolotl_sender_key_distribution_message: Some(distribution_a_bytes.clone()),
                },
            )
            .await
            .unwrap();
        assert_eq!(
            receiver_repository
                .get_sender_key_distribution(sender_jid, group_jid)
                .await
                .unwrap(),
            Some(distribution_a_bytes)
        );

        let mut chain = SignalSenderChainKey {
            key: SecretBytes::from(vec![7u8; 32]),
            iteration: 0,
        };
        let mut third_keys = None;
        while chain.iteration <= 2 {
            let step = ratchet_signal_sender_chain(&chain).unwrap();
            if step.message_key.iteration == 2 {
                third_keys = Some(step.message_key.clone());
            }
            chain = step.next_chain_key;
        }
        let third = sign_signal_sender_key_message(
            key_id,
            2,
            encrypt_signal_sender_message_body(b"group third", &third_keys.unwrap()).unwrap(),
            signing_key_a.private.expose(),
        )
        .unwrap();
        let third = encode_signal_sender_key_message(&third).unwrap();
        assert_eq!(
            receiver_codec
                .decrypt_inbound_message(InboundEncryptedPayload {
                    sender_jid: sender_jid.to_owned(),
                    chat_jid: group_jid.to_owned(),
                    ciphertext_type: InboundCiphertextType::SenderKey,
                    ciphertext: third,
                })
                .await
                .unwrap(),
            Bytes::from_static(b"group third")
        );
        let receiver_record_key = sender_key_store_key(sender_jid, group_jid).unwrap();
        let receiver_provider_probe = SignalProviderStateStore::new(receiver_store);
        let after_third = receiver_provider_probe
            .load_sender_key_record(&receiver_record_key)
            .await
            .unwrap()
            .unwrap();
        let after_third = decode_signal_sender_key_record(&after_third).unwrap();
        assert_eq!(after_third.states[0].chain_key.iteration, 3);
        assert_eq!(
            after_third.states[0]
                .message_keys
                .iter()
                .map(|key| key.iteration)
                .collect::<Vec<_>>(),
            vec![0, 1]
        );

        let stale_distribution = build_signal_sender_key_distribution_message(
            key_id,
            1,
            &[8u8; 32],
            &signing_key_a.public,
        )
        .unwrap();
        let stale_distribution_bytes =
            encode_signal_sender_key_distribution_message(&stale_distribution).unwrap();
        receiver_codec
            .process_sender_key_distribution(
                sender_jid,
                &SenderKeyDistributionMessage {
                    group_id: Some(group_jid.to_owned()),
                    axolotl_sender_key_distribution_message: Some(stale_distribution_bytes),
                },
            )
            .await
            .unwrap();
        let after_stale = receiver_provider_probe
            .load_sender_key_record(&receiver_record_key)
            .await
            .unwrap()
            .unwrap();
        let after_stale = decode_signal_sender_key_record(&after_stale).unwrap();
        assert_eq!(after_stale.states, after_third.states);

        let replacement_distribution = build_signal_sender_key_distribution_message(
            key_id,
            5,
            &[9u8; 32],
            &signing_key_b.public,
        )
        .unwrap();
        let replacement_distribution_bytes =
            encode_signal_sender_key_distribution_message(&replacement_distribution).unwrap();
        receiver_codec
            .process_sender_key_distribution(
                sender_jid,
                &SenderKeyDistributionMessage {
                    group_id: Some(group_jid.to_owned()),
                    axolotl_sender_key_distribution_message: Some(replacement_distribution_bytes),
                },
            )
            .await
            .unwrap();
        let after_replacement = receiver_provider_probe
            .load_sender_key_record(&receiver_record_key)
            .await
            .unwrap()
            .unwrap();
        let after_replacement = decode_signal_sender_key_record(&after_replacement).unwrap();
        assert_eq!(after_replacement.states.len(), 1);
        assert_eq!(after_replacement.states[0].key_id, key_id);
        assert_eq!(after_replacement.states[0].chain_key.iteration, 5);
        assert_eq!(
            after_replacement.states[0].chain_key.key.expose(),
            &[9u8; 32]
        );
        assert_eq!(
            after_replacement.states[0].signing_public_key,
            Bytes::copy_from_slice(&prefixed_signal_public_key(&signing_key_b.public))
        );
        assert!(after_replacement.states[0].signing_private_key.is_none());
        assert!(after_replacement.states[0].message_keys.is_empty());
    }

    #[tokio::test]
    async fn store_sender_key_provider_decrypts_out_of_order_group_payloads_from_store() {
        let sender_store = temp_store().await;
        let receiver_store = temp_store().await;
        let sender_jid = "999:7@s.whatsapp.net";
        let group_jid = "555@g.us";
        let signing_key = generate_key_pair();
        let chain_key = [7u8; 32];
        let sender_record = encode_signal_sender_key_record(&SignalSenderKeyRecord {
            states: vec![SignalSenderKeyState {
                key_id: 55,
                chain_key: SignalSenderChainKey {
                    key: SecretBytes::from(chain_key.to_vec()),
                    iteration: 0,
                },
                signing_public_key: Bytes::copy_from_slice(&prefixed_signal_public_key(
                    &signing_key.public,
                )),
                signing_private_key: Some(SecretBytes::from(signing_key.private.expose().to_vec())),
                message_keys: Vec::new(),
            }],
        })
        .unwrap();
        let sender_record_key = sender_key_store_key(sender_jid, group_jid).unwrap();
        let sender_provider = StoreSignalSenderKeyProvider::new(sender_store.clone())
            .with_local_sender_jid(sender_jid)
            .unwrap();
        sender_provider
            .state_store()
            .store_sender_key_record(&sender_record_key, &sender_record)
            .await
            .unwrap();
        let sender_codec =
            SignalMessageCodec::new(StoreSignalRepository::new(sender_store), sender_provider);
        let first = sender_codec
            .encrypt_message(group_jid, Bytes::from_static(b"group first"))
            .await
            .unwrap();
        let second = sender_codec
            .encrypt_message(group_jid, Bytes::from_static(b"group second"))
            .await
            .unwrap();
        let third = sender_codec
            .encrypt_message(group_jid, Bytes::from_static(b"group third"))
            .await
            .unwrap();
        let fourth = sender_codec
            .encrypt_message(group_jid, Bytes::from_static(b"group fourth"))
            .await
            .unwrap();

        let distribution =
            build_signal_sender_key_distribution_message(55, 0, &chain_key, &signing_key.public)
                .unwrap();
        let distribution_bytes =
            encode_signal_sender_key_distribution_message(&distribution).unwrap();
        SignalMessageCodec::new(
            StoreSignalRepository::new(receiver_store.clone()),
            StoreSignalSenderKeyProvider::new(receiver_store.clone()),
        )
        .process_sender_key_distribution(
            sender_jid,
            &SenderKeyDistributionMessage {
                group_id: Some(group_jid.to_owned()),
                axolotl_sender_key_distribution_message: Some(distribution_bytes),
            },
        )
        .await
        .unwrap();
        let receiver_record_key = sender_key_store_key(sender_jid, group_jid).unwrap();
        let receiver_provider_probe = SignalProviderStateStore::new(receiver_store.clone());

        let third_codec = SignalMessageCodec::new(
            StoreSignalRepository::new(receiver_store.clone()),
            StoreSignalSenderKeyProvider::new(receiver_store.clone()),
        );
        assert_eq!(
            third_codec
                .decrypt_inbound_message(InboundEncryptedPayload {
                    sender_jid: sender_jid.to_owned(),
                    chat_jid: group_jid.to_owned(),
                    ciphertext_type: InboundCiphertextType::SenderKey,
                    ciphertext: third.ciphertext,
                })
                .await
                .unwrap(),
            Bytes::from_static(b"group third")
        );
        let after_third = receiver_provider_probe
            .load_sender_key_record(&receiver_record_key)
            .await
            .unwrap()
            .unwrap();
        let after_third = decode_signal_sender_key_record(&after_third).unwrap();
        assert_eq!(after_third.states[0].chain_key.iteration, 3);
        assert_eq!(
            after_third.states[0]
                .message_keys
                .iter()
                .map(|key| key.iteration)
                .collect::<Vec<_>>(),
            vec![0, 1]
        );

        let second_codec = SignalMessageCodec::new(
            StoreSignalRepository::new(receiver_store.clone()),
            StoreSignalSenderKeyProvider::new(receiver_store.clone()),
        );
        assert_eq!(
            second_codec
                .decrypt_inbound_message(InboundEncryptedPayload {
                    sender_jid: sender_jid.to_owned(),
                    chat_jid: group_jid.to_owned(),
                    ciphertext_type: InboundCiphertextType::SenderKey,
                    ciphertext: second.ciphertext.clone(),
                })
                .await
                .unwrap(),
            Bytes::from_static(b"group second")
        );
        let after_second_bytes = receiver_provider_probe
            .load_sender_key_record(&receiver_record_key)
            .await
            .unwrap()
            .unwrap();
        let after_second = decode_signal_sender_key_record(&after_second_bytes).unwrap();
        assert_eq!(after_second.states[0].chain_key.iteration, 3);
        assert_eq!(after_second.states[0].message_keys.len(), 1);
        assert_eq!(after_second.states[0].message_keys[0].iteration, 0);

        let mut invalid_signature_first = first.ciphertext.to_vec();
        *invalid_signature_first.last_mut().unwrap() ^= 1;
        let invalid_signature_err = second_codec
            .decrypt_inbound_message(InboundEncryptedPayload {
                sender_jid: sender_jid.to_owned(),
                chat_jid: group_jid.to_owned(),
                ciphertext_type: InboundCiphertextType::SenderKey,
                ciphertext: Bytes::from(invalid_signature_first),
            })
            .await
            .unwrap_err();
        assert!(matches!(
            invalid_signature_err,
            CoreError::Protocol(message)
                if message == "invalid Signal sender-key message signature"
        ));
        assert_eq!(
            receiver_provider_probe
                .load_sender_key_record(&receiver_record_key)
                .await
                .unwrap()
                .unwrap(),
            after_second_bytes
        );

        let first_message = decode_signal_sender_key_message(&first.ciphertext).unwrap();
        let failed_decrypt_first = sign_signal_sender_key_message(
            first_message.key_id,
            first_message.iteration,
            Bytes::copy_from_slice(&first_message.ciphertext[..first_message.ciphertext.len() - 1]),
            signing_key.private.expose(),
        )
        .unwrap();
        let failed_decrypt_first = encode_signal_sender_key_message(&failed_decrypt_first).unwrap();
        let failed_decrypt_err = second_codec
            .decrypt_inbound_message(InboundEncryptedPayload {
                sender_jid: sender_jid.to_owned(),
                chat_jid: group_jid.to_owned(),
                ciphertext_type: InboundCiphertextType::SenderKey,
                ciphertext: failed_decrypt_first,
            })
            .await
            .unwrap_err();
        assert!(matches!(
            failed_decrypt_err,
            CoreError::Crypto(wa_crypto::CryptoError::Decrypt)
        ));
        assert_eq!(
            receiver_provider_probe
                .load_sender_key_record(&receiver_record_key)
                .await
                .unwrap()
                .unwrap(),
            after_second_bytes
        );

        let replay_err = second_codec
            .decrypt_inbound_message(InboundEncryptedPayload {
                sender_jid: sender_jid.to_owned(),
                chat_jid: group_jid.to_owned(),
                ciphertext_type: InboundCiphertextType::SenderKey,
                ciphertext: second.ciphertext,
            })
            .await
            .unwrap_err();
        assert!(matches!(
            replay_err,
            CoreError::Protocol(message)
                if message == "duplicate Signal sender-key message iteration: 1"
        ));
        assert_eq!(
            receiver_provider_probe
                .load_sender_key_record(&receiver_record_key)
                .await
                .unwrap()
                .unwrap(),
            after_second_bytes
        );

        let fourth_codec = SignalMessageCodec::new(
            StoreSignalRepository::new(receiver_store.clone()),
            StoreSignalSenderKeyProvider::new(receiver_store.clone()),
        );
        assert_eq!(
            fourth_codec
                .decrypt_inbound_message(InboundEncryptedPayload {
                    sender_jid: sender_jid.to_owned(),
                    chat_jid: group_jid.to_owned(),
                    ciphertext_type: InboundCiphertextType::SenderKey,
                    ciphertext: fourth.ciphertext,
                })
                .await
                .unwrap(),
            Bytes::from_static(b"group fourth")
        );

        let replay_codec = SignalMessageCodec::new(
            StoreSignalRepository::new(receiver_store.clone()),
            StoreSignalSenderKeyProvider::new(receiver_store),
        );
        assert_eq!(
            replay_codec
                .decrypt_inbound_message(InboundEncryptedPayload {
                    sender_jid: sender_jid.to_owned(),
                    chat_jid: group_jid.to_owned(),
                    ciphertext_type: InboundCiphertextType::SenderKey,
                    ciphertext: first.ciphertext.clone(),
                })
                .await
                .unwrap(),
            Bytes::from_static(b"group first")
        );
        let after_first_bytes = receiver_provider_probe
            .load_sender_key_record(&receiver_record_key)
            .await
            .unwrap()
            .unwrap();
        let after_first = decode_signal_sender_key_record(&after_first_bytes).unwrap();
        assert_eq!(after_first.states[0].chain_key.iteration, 4);
        assert!(after_first.states[0].message_keys.is_empty());

        let first_replay_err = replay_codec
            .decrypt_inbound_message(InboundEncryptedPayload {
                sender_jid: sender_jid.to_owned(),
                chat_jid: group_jid.to_owned(),
                ciphertext_type: InboundCiphertextType::SenderKey,
                ciphertext: first.ciphertext,
            })
            .await
            .unwrap_err();
        assert!(matches!(
            first_replay_err,
            CoreError::Protocol(message)
                if message == "duplicate Signal sender-key message iteration: 0"
        ));
        assert_eq!(
            receiver_provider_probe
                .load_sender_key_record(&receiver_record_key)
                .await
                .unwrap()
                .unwrap(),
            after_first_bytes
        );
    }

    #[tokio::test]
    async fn store_sender_key_provider_prunes_oldest_skipped_group_message_keys_from_store() {
        let receiver_store = temp_store().await;
        let sender_jid = "999:7@s.whatsapp.net";
        let group_jid = "555@g.us";
        let signing_key = generate_key_pair();
        let target_iteration = u32::try_from(SIGNAL_MAX_SENDER_MESSAGE_KEYS).unwrap() + 1;
        let mut chain = SignalSenderChainKey {
            key: SecretBytes::from(vec![6u8; 32]),
            iteration: 0,
        };
        let mut first_keys = None;
        let mut second_keys = None;
        let mut target_keys = None;
        while chain.iteration <= target_iteration {
            let step = ratchet_signal_sender_chain(&chain).unwrap();
            match step.message_key.iteration {
                0 => first_keys = Some(step.message_key.clone()),
                1 => second_keys = Some(step.message_key.clone()),
                value if value == target_iteration => target_keys = Some(step.message_key.clone()),
                _ => {}
            }
            chain = step.next_chain_key;
        }
        let first = sign_signal_sender_key_message(
            88,
            0,
            encrypt_signal_sender_message_body(b"group first", &first_keys.unwrap()).unwrap(),
            signing_key.private.expose(),
        )
        .unwrap();
        let first = encode_signal_sender_key_message(&first).unwrap();
        let second = sign_signal_sender_key_message(
            88,
            1,
            encrypt_signal_sender_message_body(b"group second", &second_keys.unwrap()).unwrap(),
            signing_key.private.expose(),
        )
        .unwrap();
        let second = encode_signal_sender_key_message(&second).unwrap();
        let target = sign_signal_sender_key_message(
            88,
            target_iteration,
            encrypt_signal_sender_message_body(b"group target", &target_keys.unwrap()).unwrap(),
            signing_key.private.expose(),
        )
        .unwrap();
        let target = encode_signal_sender_key_message(&target).unwrap();

        let distribution =
            build_signal_sender_key_distribution_message(88, 0, &[6u8; 32], &signing_key.public)
                .unwrap();
        let distribution_bytes =
            encode_signal_sender_key_distribution_message(&distribution).unwrap();
        let receiver_codec = SignalMessageCodec::new(
            StoreSignalRepository::new(receiver_store.clone()),
            StoreSignalSenderKeyProvider::new(receiver_store.clone()),
        );
        receiver_codec
            .process_sender_key_distribution(
                sender_jid,
                &SenderKeyDistributionMessage {
                    group_id: Some(group_jid.to_owned()),
                    axolotl_sender_key_distribution_message: Some(distribution_bytes),
                },
            )
            .await
            .unwrap();
        let receiver_record_key = sender_key_store_key(sender_jid, group_jid).unwrap();
        let receiver_provider_probe = SignalProviderStateStore::new(receiver_store);

        assert_eq!(
            receiver_codec
                .decrypt_inbound_message(InboundEncryptedPayload {
                    sender_jid: sender_jid.to_owned(),
                    chat_jid: group_jid.to_owned(),
                    ciphertext_type: InboundCiphertextType::SenderKey,
                    ciphertext: target,
                })
                .await
                .unwrap(),
            Bytes::from_static(b"group target")
        );
        let after_target_bytes = receiver_provider_probe
            .load_sender_key_record(&receiver_record_key)
            .await
            .unwrap()
            .unwrap();
        let after_target = decode_signal_sender_key_record(&after_target_bytes).unwrap();
        assert_eq!(
            after_target.states[0].message_keys.len(),
            SIGNAL_MAX_SENDER_MESSAGE_KEYS
        );
        assert_eq!(after_target.states[0].message_keys[0].iteration, 1);
        assert_eq!(
            after_target.states[0]
                .message_keys
                .last()
                .unwrap()
                .iteration,
            target_iteration - 1
        );

        let replay_err = receiver_codec
            .decrypt_inbound_message(InboundEncryptedPayload {
                sender_jid: sender_jid.to_owned(),
                chat_jid: group_jid.to_owned(),
                ciphertext_type: InboundCiphertextType::SenderKey,
                ciphertext: first,
            })
            .await
            .unwrap_err();
        assert!(matches!(
            replay_err,
            CoreError::Protocol(message)
                if message == "duplicate Signal sender-key message iteration: 0"
        ));
        assert_eq!(
            receiver_provider_probe
                .load_sender_key_record(&receiver_record_key)
                .await
                .unwrap()
                .unwrap(),
            after_target_bytes
        );

        assert_eq!(
            receiver_codec
                .decrypt_inbound_message(InboundEncryptedPayload {
                    sender_jid: sender_jid.to_owned(),
                    chat_jid: group_jid.to_owned(),
                    ciphertext_type: InboundCiphertextType::SenderKey,
                    ciphertext: second.clone(),
                })
                .await
                .unwrap(),
            Bytes::from_static(b"group second")
        );
        let after_second_bytes = receiver_provider_probe
            .load_sender_key_record(&receiver_record_key)
            .await
            .unwrap()
            .unwrap();
        let after_second = decode_signal_sender_key_record(&after_second_bytes).unwrap();
        assert_eq!(
            after_second.states[0].message_keys.len(),
            SIGNAL_MAX_SENDER_MESSAGE_KEYS - 1
        );
        assert_eq!(after_second.states[0].message_keys[0].iteration, 2);

        let consumed_replay_err = receiver_codec
            .decrypt_inbound_message(InboundEncryptedPayload {
                sender_jid: sender_jid.to_owned(),
                chat_jid: group_jid.to_owned(),
                ciphertext_type: InboundCiphertextType::SenderKey,
                ciphertext: second,
            })
            .await
            .unwrap_err();
        assert!(matches!(
            consumed_replay_err,
            CoreError::Protocol(message)
                if message == "duplicate Signal sender-key message iteration: 1"
        ));
        assert_eq!(
            receiver_provider_probe
                .load_sender_key_record(&receiver_record_key)
                .await
                .unwrap()
                .unwrap(),
            after_second_bytes
        );
    }

    #[tokio::test]
    async fn signal_mutation_locks_serialize_same_key_and_allow_distinct_keys() {
        let locks = SignalMutationLocks::new();
        let first = locks.lock("same-session").await.unwrap();
        let other = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            locks.clone().lock("other-session"),
        )
        .await
        .unwrap()
        .unwrap();
        drop(other);

        let entered = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let same_locks = locks.clone();
        let same_entered = entered.clone();
        let same_task = tokio::spawn(async move {
            let _guard = same_locks.lock("same-session").await.unwrap();
            same_entered.store(true, std::sync::atomic::Ordering::SeqCst);
        });

        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        assert!(!entered.load(std::sync::atomic::Ordering::SeqCst));
        drop(first);
        tokio::time::timeout(std::time::Duration::from_secs(1), same_task)
            .await
            .unwrap()
            .unwrap();
        assert!(entered.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[tokio::test]
    async fn sender_key_memory_operations_use_provider_mutation_locks() {
        let store = temp_store().await;
        let locks = SignalMutationLocks::new();
        store
            .set_signal_key(KeyNamespace::SenderKeyMemory, "555@g.us", b"legacy-memory")
            .await
            .unwrap();
        store
            .set_signal_key(
                KeyNamespace::SignalProviderSenderKeyMemory,
                "555@g.us",
                b"provider-memory",
            )
            .await
            .unwrap();

        let guard = locks
            .lock(provider_sender_key_mutation_lock_key("555@g.us"))
            .await
            .unwrap();
        let repository = StoreSignalRepository::with_mutation_locks(store.clone(), locks.clone());
        let cleanup_task = tokio::spawn(async move {
            repository
                .clear_sender_key_memory("555@g.us")
                .await
                .unwrap()
        });
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        assert!(
            store
                .get_signal_key(KeyNamespace::SenderKeyMemory, "555@g.us")
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            store
                .get_signal_key(KeyNamespace::SignalProviderSenderKeyMemory, "555@g.us")
                .await
                .unwrap()
                .is_some()
        );
        drop(guard);
        assert!(
            tokio::time::timeout(std::time::Duration::from_secs(1), cleanup_task)
                .await
                .unwrap()
                .unwrap()
        );
        assert!(
            store
                .get_signal_key(KeyNamespace::SenderKeyMemory, "555@g.us")
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .get_signal_key(KeyNamespace::SignalProviderSenderKeyMemory, "555@g.us")
                .await
                .unwrap()
                .is_none()
        );

        let guard = locks
            .lock(provider_sender_key_mutation_lock_key(
                "555@g.us|123:7@s.whatsapp.net",
            ))
            .await
            .unwrap();
        let provider_store =
            SignalProviderStateStore::with_mutation_locks(store.clone(), locks.clone());
        let store_task = tokio::spawn(async move {
            provider_store
                .store_sender_key_memory_record("555@g.us|123:7@s.whatsapp.net", b"memory")
                .await
                .unwrap();
        });
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        assert!(
            store
                .get_signal_key(
                    KeyNamespace::SignalProviderSenderKeyMemory,
                    "555@g.us|123:7@s.whatsapp.net"
                )
                .await
                .unwrap()
                .is_none()
        );
        drop(guard);
        tokio::time::timeout(std::time::Duration::from_secs(1), store_task)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            store
                .get_signal_key(
                    KeyNamespace::SignalProviderSenderKeyMemory,
                    "555@g.us|123:7@s.whatsapp.net"
                )
                .await
                .unwrap()
                .as_deref(),
            Some(&b"memory"[..])
        );
    }

    #[tokio::test]
    async fn store_signal_provider_preserves_sender_key_after_failed_group_decrypt() {
        let sender_store = temp_store().await;
        let receiver_store = temp_store().await;
        let sender_jid = "999:7@s.whatsapp.net";
        let group_jid = "555@g.us";
        let signing_key = generate_key_pair();
        let chain_key = [7u8; 32];
        let sender_record = encode_signal_sender_key_record(&SignalSenderKeyRecord {
            states: vec![SignalSenderKeyState {
                key_id: 55,
                chain_key: SignalSenderChainKey {
                    key: SecretBytes::from(chain_key.to_vec()),
                    iteration: 0,
                },
                signing_public_key: Bytes::copy_from_slice(&prefixed_signal_public_key(
                    &signing_key.public,
                )),
                signing_private_key: Some(SecretBytes::from(signing_key.private.expose().to_vec())),
                message_keys: Vec::new(),
            }],
        })
        .unwrap();
        let sender_record_key = sender_key_store_key(sender_jid, group_jid).unwrap();
        let sender_provider = StoreSignalSenderKeyProvider::new(sender_store.clone())
            .with_local_sender_jid(sender_jid)
            .unwrap();
        sender_provider
            .state_store()
            .store_sender_key_record(&sender_record_key, &sender_record)
            .await
            .unwrap();
        let sender_codec =
            SignalMessageCodec::new(StoreSignalRepository::new(sender_store), sender_provider);
        let first = sender_codec
            .encrypt_message(group_jid, Bytes::from_static(b"group first"))
            .await
            .unwrap();
        let second = sender_codec
            .encrypt_message(group_jid, Bytes::from_static(b"group second"))
            .await
            .unwrap();

        let receiver_repository = StoreSignalRepository::new(receiver_store.clone());
        let receiver_provider = StoreSignalSenderKeyProvider::new(receiver_store.clone());
        let receiver_provider_probe = receiver_provider.clone();
        let receiver_codec =
            SignalMessageCodec::new(receiver_repository.clone(), receiver_provider);
        let distribution =
            build_signal_sender_key_distribution_message(55, 0, &chain_key, &signing_key.public)
                .unwrap();
        let distribution_bytes =
            encode_signal_sender_key_distribution_message(&distribution).unwrap();
        receiver_codec
            .process_sender_key_distribution(
                sender_jid,
                &SenderKeyDistributionMessage {
                    group_id: Some(group_jid.to_owned()),
                    axolotl_sender_key_distribution_message: Some(distribution_bytes),
                },
            )
            .await
            .unwrap();
        let receiver_record_key = sender_key_store_key(sender_jid, group_jid).unwrap();

        let plaintext = receiver_codec
            .decrypt_inbound_message(InboundEncryptedPayload {
                sender_jid: sender_jid.to_owned(),
                chat_jid: group_jid.to_owned(),
                ciphertext_type: InboundCiphertextType::SenderKey,
                ciphertext: second.ciphertext,
            })
            .await
            .unwrap();
        assert_eq!(plaintext, Bytes::from_static(b"group second"));
        let stored_after_second = receiver_provider_probe
            .state_store()
            .load_sender_key_record(&receiver_record_key)
            .await
            .unwrap()
            .unwrap();
        let after_second = decode_signal_sender_key_record(&stored_after_second).unwrap();
        assert_eq!(after_second.states[0].chain_key.iteration, 2);
        assert_eq!(after_second.states[0].message_keys.len(), 1);
        assert_eq!(after_second.states[0].message_keys[0].iteration, 0);

        let first_message = decode_signal_sender_key_message(&first.ciphertext).unwrap();
        let truncated_ciphertext =
            Bytes::copy_from_slice(&first_message.ciphertext[..first_message.ciphertext.len() - 1]);
        let tampered_first = sign_signal_sender_key_message(
            first_message.key_id,
            first_message.iteration,
            truncated_ciphertext,
            signing_key.private.expose(),
        )
        .unwrap();
        let tampered_first = encode_signal_sender_key_message(&tampered_first).unwrap();
        let err = receiver_codec
            .decrypt_inbound_message(InboundEncryptedPayload {
                sender_jid: sender_jid.to_owned(),
                chat_jid: group_jid.to_owned(),
                ciphertext_type: InboundCiphertextType::SenderKey,
                ciphertext: tampered_first,
            })
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            CoreError::Crypto(wa_crypto::CryptoError::Decrypt)
        ));
        assert_eq!(
            receiver_provider_probe
                .state_store()
                .load_sender_key_record(&receiver_record_key)
                .await
                .unwrap()
                .unwrap(),
            stored_after_second
        );

        let plaintext = receiver_codec
            .decrypt_inbound_message(InboundEncryptedPayload {
                sender_jid: sender_jid.to_owned(),
                chat_jid: group_jid.to_owned(),
                ciphertext_type: InboundCiphertextType::SenderKey,
                ciphertext: first.ciphertext,
            })
            .await
            .unwrap();
        assert_eq!(plaintext, Bytes::from_static(b"group first"));
        let stored_after_first = receiver_provider_probe
            .state_store()
            .load_sender_key_record(&receiver_record_key)
            .await
            .unwrap()
            .unwrap();
        assert_ne!(stored_after_first, stored_after_second);
        assert!(
            decode_signal_sender_key_record(&stored_after_first)
                .unwrap()
                .states[0]
                .message_keys
                .is_empty()
        );
    }

    #[tokio::test]
    async fn store_signal_provider_preserves_sender_key_after_failed_group_signature() {
        let sender_store = temp_store().await;
        let receiver_store = temp_store().await;
        let sender_jid = "999:7@s.whatsapp.net";
        let group_jid = "555@g.us";
        let signing_key = generate_key_pair();
        let chain_key = [7u8; 32];
        let sender_record = encode_signal_sender_key_record(&SignalSenderKeyRecord {
            states: vec![SignalSenderKeyState {
                key_id: 55,
                chain_key: SignalSenderChainKey {
                    key: SecretBytes::from(chain_key.to_vec()),
                    iteration: 0,
                },
                signing_public_key: Bytes::copy_from_slice(&prefixed_signal_public_key(
                    &signing_key.public,
                )),
                signing_private_key: Some(SecretBytes::from(signing_key.private.expose().to_vec())),
                message_keys: Vec::new(),
            }],
        })
        .unwrap();
        let sender_record_key = sender_key_store_key(sender_jid, group_jid).unwrap();
        let sender_provider = StoreSignalSenderKeyProvider::new(sender_store.clone())
            .with_local_sender_jid(sender_jid)
            .unwrap();
        sender_provider
            .state_store()
            .store_sender_key_record(&sender_record_key, &sender_record)
            .await
            .unwrap();
        let sender_codec =
            SignalMessageCodec::new(StoreSignalRepository::new(sender_store), sender_provider);
        let first = sender_codec
            .encrypt_message(group_jid, Bytes::from_static(b"group first"))
            .await
            .unwrap();
        let second = sender_codec
            .encrypt_message(group_jid, Bytes::from_static(b"group second"))
            .await
            .unwrap();

        let receiver_repository = StoreSignalRepository::new(receiver_store.clone());
        let receiver_provider = StoreSignalSenderKeyProvider::new(receiver_store.clone());
        let receiver_provider_probe = receiver_provider.clone();
        let receiver_codec =
            SignalMessageCodec::new(receiver_repository.clone(), receiver_provider);
        let distribution =
            build_signal_sender_key_distribution_message(55, 0, &chain_key, &signing_key.public)
                .unwrap();
        let distribution_bytes =
            encode_signal_sender_key_distribution_message(&distribution).unwrap();
        receiver_codec
            .process_sender_key_distribution(
                sender_jid,
                &SenderKeyDistributionMessage {
                    group_id: Some(group_jid.to_owned()),
                    axolotl_sender_key_distribution_message: Some(distribution_bytes),
                },
            )
            .await
            .unwrap();
        let receiver_record_key = sender_key_store_key(sender_jid, group_jid).unwrap();

        let plaintext = receiver_codec
            .decrypt_inbound_message(InboundEncryptedPayload {
                sender_jid: sender_jid.to_owned(),
                chat_jid: group_jid.to_owned(),
                ciphertext_type: InboundCiphertextType::SenderKey,
                ciphertext: second.ciphertext,
            })
            .await
            .unwrap();
        assert_eq!(plaintext, Bytes::from_static(b"group second"));
        let stored_after_second = receiver_provider_probe
            .state_store()
            .load_sender_key_record(&receiver_record_key)
            .await
            .unwrap()
            .unwrap();
        let after_second = decode_signal_sender_key_record(&stored_after_second).unwrap();
        assert_eq!(after_second.states[0].chain_key.iteration, 2);
        assert_eq!(after_second.states[0].message_keys.len(), 1);
        assert_eq!(after_second.states[0].message_keys[0].iteration, 0);

        let mut tampered_first = first.ciphertext.to_vec();
        *tampered_first.last_mut().unwrap() ^= 1;
        let err = receiver_codec
            .decrypt_inbound_message(InboundEncryptedPayload {
                sender_jid: sender_jid.to_owned(),
                chat_jid: group_jid.to_owned(),
                ciphertext_type: InboundCiphertextType::SenderKey,
                ciphertext: Bytes::from(tampered_first),
            })
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            CoreError::Protocol(message)
                if message == "invalid Signal sender-key message signature"
        ));
        assert_eq!(
            receiver_provider_probe
                .state_store()
                .load_sender_key_record(&receiver_record_key)
                .await
                .unwrap()
                .unwrap(),
            stored_after_second
        );

        let plaintext = receiver_codec
            .decrypt_inbound_message(InboundEncryptedPayload {
                sender_jid: sender_jid.to_owned(),
                chat_jid: group_jid.to_owned(),
                ciphertext_type: InboundCiphertextType::SenderKey,
                ciphertext: first.ciphertext,
            })
            .await
            .unwrap();
        assert_eq!(plaintext, Bytes::from_static(b"group first"));
        let stored_after_first = receiver_provider_probe
            .state_store()
            .load_sender_key_record(&receiver_record_key)
            .await
            .unwrap()
            .unwrap();
        assert_ne!(stored_after_first, stored_after_second);
        assert!(
            decode_signal_sender_key_record(&stored_after_first)
                .unwrap()
                .states[0]
                .message_keys
                .is_empty()
        );
    }

    #[tokio::test]
    async fn provider_state_store_loads_and_consumes_local_key_material() {
        let store = temp_store().await;
        let provider_store = SignalProviderStateStore::new(store.clone());
        assert!(
            provider_store
                .load_local_key_material()
                .await
                .unwrap()
                .is_none()
        );

        let credentials = create_initial_credentials().unwrap();
        save_credentials(&store, credentials.clone()).await.unwrap();
        let upload = prepare_pre_key_upload(&store, &credentials, 1, "pre-key")
            .await
            .unwrap();
        let key_id = upload.pre_key_ids[0];

        let material = provider_store
            .load_local_key_material()
            .await
            .unwrap()
            .unwrap();
        assert_eq!(material.registration_id, upload.credentials.registration_id);
        assert_eq!(
            material.identity.key_pair.public,
            upload.credentials.signed_identity_key.public
        );
        assert_eq!(
            material.identity.key_pair.private.expose(),
            upload.credentials.signed_identity_key.private.expose()
        );
        assert_eq!(material.identity.public_key[0], SIGNAL_PUBLIC_KEY_VERSION);
        assert_eq!(
            &material.identity.public_key[1..],
            &upload.credentials.signed_identity_key.public
        );
        assert_eq!(
            material.signed_pre_key.key_id,
            upload.credentials.signed_pre_key.key_id
        );
        assert_eq!(
            material.signed_pre_key.signature,
            upload.credentials.signed_pre_key.signature
        );
        assert_eq!(
            &material.signed_pre_key.public_key[1..],
            &upload.credentials.signed_pre_key.key_pair.public
        );

        let local_pre_key = provider_store
            .load_local_pre_key(key_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(local_pre_key.key_id, key_id);
        assert_eq!(local_pre_key.public_key[0], SIGNAL_PUBLIC_KEY_VERSION);
        assert_eq!(
            &local_pre_key.public_key[1..],
            &local_pre_key.key_pair.public
        );

        let consumed = provider_store
            .consume_local_pre_key(key_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(consumed, local_pre_key);
        assert!(
            provider_store
                .load_local_pre_key(key_id)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .get_signal_key(KeyNamespace::PreKey, &key_id.to_string())
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            provider_store
                .consume_local_pre_key(key_id)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn provider_state_store_does_not_store_inbound_pre_key_session_when_pre_key_missing() {
        let store = temp_store().await;
        let provider_store = SignalProviderStateStore::new(store);
        let sender_jid = "123:7@s.whatsapp.net";

        let err = provider_store
            .store_inbound_pre_key_session_records(
                sender_jid,
                Some(91),
                b"provider-session-record",
                b"provider-identity-record",
            )
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            CoreError::Protocol(message)
                if message == "missing local Signal one-time pre-key 91"
        ));
        assert!(
            provider_store
                .load_session_record(sender_jid)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            provider_store
                .load_identity_record(sender_jid)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn provider_state_store_rejects_provider_identity_change_before_session_commit() {
        let store = temp_store().await;
        let provider_store = SignalProviderStateStore::new(store.clone());
        let sender_jid = "123:7@s.whatsapp.net";
        let original_identity = prefixed_test_signal_key(21);
        let changed_identity = prefixed_test_signal_key(22);

        provider_store
            .store_session_and_identity_records(
                sender_jid,
                b"provider-session-1",
                &original_identity,
            )
            .await
            .unwrap();

        let err = provider_store
            .store_session_and_identity_records(
                sender_jid,
                b"provider-session-2",
                &changed_identity,
            )
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            CoreError::Protocol(message)
                if message == "Signal provider identity changed for 123.7"
        ));
        assert_eq!(
            provider_store
                .load_session_record(sender_jid)
                .await
                .unwrap()
                .as_deref(),
            Some(&b"provider-session-1"[..])
        );
        assert_eq!(
            provider_store
                .load_identity_record(sender_jid)
                .await
                .unwrap(),
            Some(original_identity.clone())
        );

        let credentials = create_initial_credentials().unwrap();
        save_credentials(&store, credentials.clone()).await.unwrap();
        let upload = prepare_pre_key_upload(&store, &credentials, 1, "pre-key")
            .await
            .unwrap();
        let pre_key_id = upload.pre_key_ids[0];
        let local_pre_key = provider_store
            .load_local_pre_key(pre_key_id)
            .await
            .unwrap()
            .unwrap();

        let err = provider_store
            .store_inbound_pre_key_session_records(
                sender_jid,
                Some(pre_key_id),
                b"provider-session-3",
                &changed_identity,
            )
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            CoreError::Protocol(message)
                if message == "Signal provider identity changed for 123.7"
        ));
        assert_eq!(
            provider_store.load_local_pre_key(pre_key_id).await.unwrap(),
            Some(local_pre_key)
        );
        assert_eq!(
            provider_store
                .load_session_record(sender_jid)
                .await
                .unwrap()
                .as_deref(),
            Some(&b"provider-session-1"[..])
        );
        assert_eq!(
            provider_store
                .load_identity_record(sender_jid)
                .await
                .unwrap(),
            Some(original_identity)
        );
    }

    #[tokio::test]
    async fn provider_state_store_rejects_runtime_session_use_when_identity_mismatches() {
        let store = temp_store().await;
        let provider_store = SignalProviderStateStore::new(store.clone());
        let remote_jid = "123:7@s.whatsapp.net";
        let remote_ratchet_key_pair = test_key_pair(31);
        let record = SignalProviderSessionRecord {
            remote_registration_id: 88,
            remote_identity_key: prefixed_test_signal_key(21),
            root_key: SignalRootKey {
                key: SecretBytes::from(vec![9u8; 32]),
            },
            sending_chain: SignalMessageChainKey {
                key: SecretBytes::from(vec![7u8; 32]),
                counter: 0,
            },
            receiving_chain: Some(SignalMessageChainKey {
                key: SecretBytes::from(vec![8u8; 32]),
                counter: 0,
            }),
            remote_ratchet_key: Some(Bytes::copy_from_slice(&prefixed_signal_public_key(
                &remote_ratchet_key_pair.public,
            ))),
            local_ratchet_key_pair: test_key_pair(41),
            previous_counter: 0,
            message_keys: Vec::new(),
        };
        let encoded = encode_signal_provider_session_record(&record).unwrap();
        provider_store
            .store_session_record(remote_jid, &encoded)
            .await
            .unwrap();
        store
            .set_signal_key(
                KeyNamespace::SignalProviderIdentity,
                "123.7",
                &prefixed_test_signal_key(22),
            )
            .await
            .unwrap();

        let encrypt_err = provider_store
            .encrypt_existing_session_record_message(remote_jid, Bytes::from_static(b"outbound"))
            .await
            .unwrap_err();
        assert!(matches!(
            encrypt_err,
            CoreError::Protocol(message) if message == "provider identity mismatch"
        ));
        assert_eq!(
            provider_store
                .load_session_record(remote_jid)
                .await
                .unwrap()
                .unwrap(),
            encoded
        );

        let mut remote_receiving_chain = SignalMessageChainKey {
            key: SecretBytes::from(vec![8u8; 32]),
            counter: 0,
        };
        let step = ratchet_signal_message_chain(&remote_receiving_chain).unwrap();
        remote_receiving_chain = step.next_chain_key;
        let inbound = encode_signal_whisper_message(&SignalWhisperMessage {
            ephemeral_key: Bytes::copy_from_slice(&prefixed_signal_public_key(
                &remote_ratchet_key_pair.public,
            )),
            counter: step.message_counter,
            previous_counter: 0,
            ciphertext: encrypt_signal_message_body(b"inbound", &step.message_keys).unwrap(),
        })
        .unwrap();
        assert_eq!(remote_receiving_chain.counter, 1);
        let decrypt_err = provider_store
            .decrypt_session_record_message(remote_jid, inbound)
            .await
            .unwrap_err();
        assert!(matches!(
            decrypt_err,
            CoreError::Protocol(message) if message == "provider identity mismatch"
        ));
        assert_eq!(
            provider_store
                .load_session_record(remote_jid)
                .await
                .unwrap()
                .unwrap(),
            encoded
        );

        store
            .set_signal_key(
                KeyNamespace::SignalProviderIdentity,
                "123.7",
                &record.remote_identity_key,
            )
            .await
            .unwrap();
        assert!(
            provider_store
                .encrypt_existing_session_record_message(
                    remote_jid,
                    Bytes::from_static(b"outbound")
                )
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn provider_state_store_rejects_runtime_session_decrypt_when_identity_missing() {
        let store = temp_store().await;
        let provider_store = SignalProviderStateStore::new(store.clone());
        let remote_jid = "123:7@s.whatsapp.net";
        let remote_ratchet_key_pair = test_key_pair(31);
        let record = SignalProviderSessionRecord {
            remote_registration_id: 88,
            remote_identity_key: prefixed_test_signal_key(21),
            root_key: SignalRootKey {
                key: SecretBytes::from(vec![9u8; 32]),
            },
            sending_chain: SignalMessageChainKey {
                key: SecretBytes::from(vec![7u8; 32]),
                counter: 0,
            },
            receiving_chain: Some(SignalMessageChainKey {
                key: SecretBytes::from(vec![8u8; 32]),
                counter: 0,
            }),
            remote_ratchet_key: Some(Bytes::copy_from_slice(&prefixed_signal_public_key(
                &remote_ratchet_key_pair.public,
            ))),
            local_ratchet_key_pair: test_key_pair(41),
            previous_counter: 0,
            message_keys: Vec::new(),
        };
        let encoded = encode_signal_provider_session_record(&record).unwrap();
        provider_store
            .store_session_record(remote_jid, &encoded)
            .await
            .unwrap();

        let mut remote_receiving_chain = SignalMessageChainKey {
            key: SecretBytes::from(vec![8u8; 32]),
            counter: 0,
        };
        let step = ratchet_signal_message_chain(&remote_receiving_chain).unwrap();
        remote_receiving_chain = step.next_chain_key;
        let inbound = encode_signal_whisper_message(&SignalWhisperMessage {
            ephemeral_key: Bytes::copy_from_slice(&prefixed_signal_public_key(
                &remote_ratchet_key_pair.public,
            )),
            counter: step.message_counter,
            previous_counter: 0,
            ciphertext: encrypt_signal_message_body(b"inbound", &step.message_keys).unwrap(),
        })
        .unwrap();
        assert_eq!(remote_receiving_chain.counter, 1);
        let decrypt_err = provider_store
            .decrypt_session_record_message(remote_jid, inbound.clone())
            .await
            .unwrap_err();
        assert!(matches!(
            decrypt_err,
            CoreError::Protocol(message) if message == "no provider identity"
        ));
        assert_eq!(
            provider_store
                .load_session_record(remote_jid)
                .await
                .unwrap()
                .unwrap(),
            encoded
        );

        store
            .set_signal_key(
                KeyNamespace::SignalProviderIdentity,
                "123.7",
                &record.remote_identity_key,
            )
            .await
            .unwrap();
        assert!(
            provider_store
                .decrypt_session_record_message(remote_jid, inbound)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn provider_state_store_rejects_runtime_session_decrypt_when_identity_malformed() {
        let store = temp_store().await;
        let provider_store = SignalProviderStateStore::new(store.clone());
        let remote_jid = "123:7@s.whatsapp.net";
        let remote_ratchet_key_pair = test_key_pair(31);
        let record = SignalProviderSessionRecord {
            remote_registration_id: 88,
            remote_identity_key: prefixed_test_signal_key(21),
            root_key: SignalRootKey {
                key: SecretBytes::from(vec![9u8; 32]),
            },
            sending_chain: SignalMessageChainKey {
                key: SecretBytes::from(vec![7u8; 32]),
                counter: 0,
            },
            receiving_chain: Some(SignalMessageChainKey {
                key: SecretBytes::from(vec![8u8; 32]),
                counter: 0,
            }),
            remote_ratchet_key: Some(Bytes::copy_from_slice(&prefixed_signal_public_key(
                &remote_ratchet_key_pair.public,
            ))),
            local_ratchet_key_pair: test_key_pair(41),
            previous_counter: 0,
            message_keys: Vec::new(),
        };
        let encoded = encode_signal_provider_session_record(&record).unwrap();
        provider_store
            .store_session_record(remote_jid, &encoded)
            .await
            .unwrap();
        let malformed_identity = Bytes::from_static(b"short");
        store
            .set_signal_key(
                KeyNamespace::SignalProviderIdentity,
                "123.7",
                &malformed_identity,
            )
            .await
            .unwrap();

        let mut remote_receiving_chain = SignalMessageChainKey {
            key: SecretBytes::from(vec![8u8; 32]),
            counter: 0,
        };
        let step = ratchet_signal_message_chain(&remote_receiving_chain).unwrap();
        remote_receiving_chain = step.next_chain_key;
        let inbound = encode_signal_whisper_message(&SignalWhisperMessage {
            ephemeral_key: Bytes::copy_from_slice(&prefixed_signal_public_key(
                &remote_ratchet_key_pair.public,
            )),
            counter: step.message_counter,
            previous_counter: 0,
            ciphertext: encrypt_signal_message_body(b"inbound", &step.message_keys).unwrap(),
        })
        .unwrap();
        assert_eq!(remote_receiving_chain.counter, 1);
        let decrypt_err = provider_store
            .decrypt_session_record_message(remote_jid, inbound.clone())
            .await
            .unwrap_err();
        assert!(matches!(
            decrypt_err,
            CoreError::Protocol(message) if message == "invalid signal public key length: 5"
        ));
        assert_eq!(
            provider_store
                .load_session_record(remote_jid)
                .await
                .unwrap()
                .unwrap(),
            encoded
        );
        assert_eq!(
            provider_store
                .load_identity_record(remote_jid)
                .await
                .unwrap(),
            Some(malformed_identity)
        );

        store
            .set_signal_key(
                KeyNamespace::SignalProviderIdentity,
                "123.7",
                &record.remote_identity_key,
            )
            .await
            .unwrap();
        assert!(
            provider_store
                .decrypt_session_record_message(remote_jid, inbound)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn provider_state_store_rejects_runtime_session_decrypt_when_session_missing() {
        let store = temp_store().await;
        let provider_store = SignalProviderStateStore::new(store.clone());
        let remote_jid = "123:7@s.whatsapp.net";
        let identity = prefixed_test_signal_key(21);

        store
            .set_signal_key(KeyNamespace::SignalProviderIdentity, "123.7", &identity)
            .await
            .unwrap();

        let decrypt_err = provider_store
            .decrypt_session_record_message(
                remote_jid,
                Bytes::from_static(b"unused-runtime-session-message"),
            )
            .await
            .unwrap_err();
        assert!(matches!(
            decrypt_err,
            CoreError::Protocol(message)
                if message == "missing Signal provider session for sender: 123:7@s.whatsapp.net"
        ));
        assert!(
            provider_store
                .load_session_record(remote_jid)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            provider_store
                .load_identity_record(remote_jid)
                .await
                .unwrap(),
            Some(identity)
        );
    }

    #[tokio::test]
    async fn provider_state_store_rejects_runtime_session_decrypt_when_session_malformed() {
        let store = temp_store().await;
        let provider_store = SignalProviderStateStore::new(store.clone());
        let remote_jid = "123:7@s.whatsapp.net";
        let malformed_session = Bytes::from_static(b"not-a-provider-session");
        let identity = prefixed_test_signal_key(21);

        provider_store
            .store_session_record(remote_jid, &malformed_session)
            .await
            .unwrap();
        store
            .set_signal_key(KeyNamespace::SignalProviderIdentity, "123.7", &identity)
            .await
            .unwrap();

        let decrypt_err = provider_store
            .decrypt_session_record_message(
                remote_jid,
                Bytes::from_static(b"unused-runtime-session-message"),
            )
            .await
            .unwrap_err();
        assert!(matches!(
            decrypt_err,
            CoreError::Protocol(message)
                if message == "unsupported Signal provider session version"
        ));
        assert_eq!(
            provider_store
                .load_session_record(remote_jid)
                .await
                .unwrap(),
            Some(malformed_session)
        );
        assert_eq!(
            provider_store
                .load_identity_record(remote_jid)
                .await
                .unwrap(),
            Some(identity)
        );
    }

    #[tokio::test]
    async fn provider_state_store_rejects_runtime_session_decrypt_when_session_invariant_invalid() {
        let store = temp_store().await;
        let provider_store = SignalProviderStateStore::new(store.clone());
        let remote_jid = "123:7@s.whatsapp.net";
        let remote_ratchet_key_pair = test_key_pair(31);
        let record = SignalProviderSessionRecord {
            remote_registration_id: 88,
            remote_identity_key: prefixed_test_signal_key(21),
            root_key: SignalRootKey {
                key: SecretBytes::from(vec![9u8; 32]),
            },
            sending_chain: SignalMessageChainKey {
                key: SecretBytes::from(vec![7u8; 32]),
                counter: 0,
            },
            receiving_chain: Some(SignalMessageChainKey {
                key: SecretBytes::from(vec![8u8; 32]),
                counter: 0,
            }),
            remote_ratchet_key: Some(Bytes::copy_from_slice(&prefixed_signal_public_key(
                &remote_ratchet_key_pair.public,
            ))),
            local_ratchet_key_pair: test_key_pair(41),
            previous_counter: 0,
            message_keys: Vec::new(),
        };
        let encoded = encode_signal_provider_session_record(&record).unwrap();
        let local_public = prefixed_signal_public_key(&record.local_ratchet_key_pair.public);
        let offset = encoded
            .windows(local_public.len())
            .position(|window| window == local_public)
            .expect("encoded session contains local ratchet public key");
        let mut invalid_session = encoded.to_vec();
        invalid_session[offset + local_public.len() - 1] ^= 1;
        let invalid_session = Bytes::from(invalid_session);

        store
            .set_signal_key(
                KeyNamespace::SignalProviderSession,
                "123.7",
                &invalid_session,
            )
            .await
            .unwrap();
        store
            .set_signal_key(
                KeyNamespace::SignalProviderIdentity,
                "123.7",
                &record.remote_identity_key,
            )
            .await
            .unwrap();

        let mut remote_receiving_chain = SignalMessageChainKey {
            key: SecretBytes::from(vec![8u8; 32]),
            counter: 0,
        };
        let step = ratchet_signal_message_chain(&remote_receiving_chain).unwrap();
        remote_receiving_chain = step.next_chain_key;
        let inbound = encode_signal_whisper_message(&SignalWhisperMessage {
            ephemeral_key: Bytes::copy_from_slice(&prefixed_signal_public_key(
                &remote_ratchet_key_pair.public,
            )),
            counter: step.message_counter,
            previous_counter: 0,
            ciphertext: encrypt_signal_message_body(b"inbound", &step.message_keys).unwrap(),
        })
        .unwrap();
        assert_eq!(remote_receiving_chain.counter, 1);
        let decrypt_err = provider_store
            .decrypt_session_record_message(remote_jid, inbound.clone())
            .await
            .unwrap_err();
        assert!(matches!(
            decrypt_err,
            CoreError::Protocol(message)
                if message == "Signal provider session local ratchet public key does not match private key"
        ));
        assert_eq!(
            provider_store
                .load_session_record(remote_jid)
                .await
                .unwrap(),
            Some(invalid_session)
        );
        assert_eq!(
            provider_store
                .load_identity_record(remote_jid)
                .await
                .unwrap(),
            Some(record.remote_identity_key.clone())
        );

        store
            .set_signal_key(KeyNamespace::SignalProviderSession, "123.7", &encoded)
            .await
            .unwrap();
        assert!(
            provider_store
                .decrypt_session_record_message(remote_jid, inbound)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn provider_state_store_rejects_runtime_session_decrypt_when_skipped_key_counter_invalid()
    {
        let store = temp_store().await;
        let provider_store = SignalProviderStateStore::new(store.clone());
        let remote_jid = "123:7@s.whatsapp.net";
        let active_ratchet_key = test_key_pair(31);
        let skipped_ratchet_key = test_key_pair(51);
        let skipped_ratchet =
            Bytes::copy_from_slice(&prefixed_signal_public_key(&skipped_ratchet_key.public));
        let record = SignalProviderSessionRecord {
            remote_registration_id: 88,
            remote_identity_key: prefixed_test_signal_key(21),
            root_key: SignalRootKey {
                key: SecretBytes::from(vec![9u8; 32]),
            },
            sending_chain: SignalMessageChainKey {
                key: SecretBytes::from(vec![7u8; 32]),
                counter: 0,
            },
            receiving_chain: Some(SignalMessageChainKey {
                key: SecretBytes::from(vec![8u8; 32]),
                counter: 10,
            }),
            remote_ratchet_key: Some(Bytes::copy_from_slice(&prefixed_signal_public_key(
                &active_ratchet_key.public,
            ))),
            local_ratchet_key_pair: test_key_pair(41),
            previous_counter: 0,
            message_keys: vec![SignalProviderStoredMessageKey {
                ratchet_key: skipped_ratchet.clone(),
                counter: 9,
                message_keys: SignalMessageKeyMaterial {
                    cipher_key: SecretBytes::from(vec![1u8; SIGNAL_MESSAGE_KEY_LEN]),
                    mac_key: SecretBytes::from(vec![2u8; SIGNAL_MESSAGE_KEY_LEN]),
                    iv: [3u8; SIGNAL_MESSAGE_IV_LEN],
                },
            }],
        };
        let encoded = encode_signal_provider_session_record(&record).unwrap();
        let counter_offset = encoded
            .windows(skipped_ratchet.len())
            .position(|window| window == skipped_ratchet)
            .expect("encoded session contains skipped ratchet key")
            + skipped_ratchet.len();
        let mut invalid_session = encoded.to_vec();
        invalid_session[counter_offset..counter_offset + 4].copy_from_slice(&0u32.to_be_bytes());
        let invalid_session = Bytes::from(invalid_session);

        store
            .set_signal_key(
                KeyNamespace::SignalProviderSession,
                "123.7",
                &invalid_session,
            )
            .await
            .unwrap();
        store
            .set_signal_key(
                KeyNamespace::SignalProviderIdentity,
                "123.7",
                &record.remote_identity_key,
            )
            .await
            .unwrap();

        let decrypt_err = provider_store
            .decrypt_session_record_message(
                remote_jid,
                Bytes::from_static(b"unused-runtime-session-message"),
            )
            .await
            .unwrap_err();
        assert!(matches!(
            decrypt_err,
            CoreError::Protocol(message)
                if message == "Signal provider skipped message counter must be greater than zero"
        ));
        assert_eq!(
            provider_store
                .load_session_record(remote_jid)
                .await
                .unwrap(),
            Some(invalid_session)
        );
        assert_eq!(
            provider_store
                .load_identity_record(remote_jid)
                .await
                .unwrap(),
            Some(record.remote_identity_key.clone())
        );

        store
            .set_signal_key(KeyNamespace::SignalProviderSession, "123.7", &encoded)
            .await
            .unwrap();
        assert!(
            provider_store
                .validate_session_record(remote_jid)
                .await
                .unwrap()
                .exists
        );
    }

    #[tokio::test]
    async fn provider_state_store_rejects_runtime_session_decrypt_when_skipped_key_duplicate() {
        let store = temp_store().await;
        let provider_store = SignalProviderStateStore::new(store.clone());
        let remote_jid = "123:7@s.whatsapp.net";
        let active_ratchet_key = test_key_pair(31);
        let skipped_ratchet_key = test_key_pair(51);
        let skipped_ratchet =
            Bytes::copy_from_slice(&prefixed_signal_public_key(&skipped_ratchet_key.public));
        let skipped_message_key = |counter: u32| SignalProviderStoredMessageKey {
            ratchet_key: skipped_ratchet.clone(),
            counter,
            message_keys: SignalMessageKeyMaterial {
                cipher_key: SecretBytes::from(vec![1u8; SIGNAL_MESSAGE_KEY_LEN]),
                mac_key: SecretBytes::from(vec![2u8; SIGNAL_MESSAGE_KEY_LEN]),
                iv: [3u8; SIGNAL_MESSAGE_IV_LEN],
            },
        };
        let record = SignalProviderSessionRecord {
            remote_registration_id: 88,
            remote_identity_key: prefixed_test_signal_key(21),
            root_key: SignalRootKey {
                key: SecretBytes::from(vec![9u8; 32]),
            },
            sending_chain: SignalMessageChainKey {
                key: SecretBytes::from(vec![7u8; 32]),
                counter: 0,
            },
            receiving_chain: Some(SignalMessageChainKey {
                key: SecretBytes::from(vec![8u8; 32]),
                counter: 10,
            }),
            remote_ratchet_key: Some(Bytes::copy_from_slice(&prefixed_signal_public_key(
                &active_ratchet_key.public,
            ))),
            local_ratchet_key_pair: test_key_pair(41),
            previous_counter: 0,
            message_keys: vec![skipped_message_key(9), skipped_message_key(10)],
        };
        let encoded = encode_signal_provider_session_record(&record).unwrap();
        let skipped_offsets = encoded
            .windows(skipped_ratchet.len())
            .enumerate()
            .filter_map(|(offset, window)| (window == skipped_ratchet).then_some(offset))
            .collect::<Vec<_>>();
        assert_eq!(skipped_offsets.len(), 2);
        let second_counter_offset = skipped_offsets[1] + skipped_ratchet.len();
        let mut invalid_session = encoded.to_vec();
        invalid_session[second_counter_offset..second_counter_offset + 4]
            .copy_from_slice(&9u32.to_be_bytes());
        let invalid_session = Bytes::from(invalid_session);

        store
            .set_signal_key(
                KeyNamespace::SignalProviderSession,
                "123.7",
                &invalid_session,
            )
            .await
            .unwrap();
        store
            .set_signal_key(
                KeyNamespace::SignalProviderIdentity,
                "123.7",
                &record.remote_identity_key,
            )
            .await
            .unwrap();

        let decrypt_err = provider_store
            .decrypt_session_record_message(
                remote_jid,
                Bytes::from_static(b"unused-runtime-session-message"),
            )
            .await
            .unwrap_err();
        assert!(matches!(
            decrypt_err,
            CoreError::Protocol(message) if message == "duplicate Signal provider skipped message key"
        ));
        assert_eq!(
            provider_store
                .load_session_record(remote_jid)
                .await
                .unwrap(),
            Some(invalid_session)
        );
        assert_eq!(
            provider_store
                .load_identity_record(remote_jid)
                .await
                .unwrap(),
            Some(record.remote_identity_key.clone())
        );

        store
            .set_signal_key(KeyNamespace::SignalProviderSession, "123.7", &encoded)
            .await
            .unwrap();
        assert!(
            provider_store
                .validate_session_record(remote_jid)
                .await
                .unwrap()
                .exists
        );
    }

    #[tokio::test]
    async fn provider_state_store_rejects_skipped_key_at_active_counter() {
        let store = temp_store().await;
        let provider_store = SignalProviderStateStore::new(store.clone());
        let remote_jid = "123:7@s.whatsapp.net";
        let active_ratchet_key = test_key_pair(31);
        let active_ratchet =
            Bytes::copy_from_slice(&prefixed_signal_public_key(&active_ratchet_key.public));
        let record = SignalProviderSessionRecord {
            remote_registration_id: 88,
            remote_identity_key: prefixed_test_signal_key(21),
            root_key: SignalRootKey {
                key: SecretBytes::from(vec![9u8; 32]),
            },
            sending_chain: SignalMessageChainKey {
                key: SecretBytes::from(vec![7u8; 32]),
                counter: 0,
            },
            receiving_chain: Some(SignalMessageChainKey {
                key: SecretBytes::from(vec![8u8; 32]),
                counter: 10,
            }),
            remote_ratchet_key: Some(active_ratchet.clone()),
            local_ratchet_key_pair: test_key_pair(41),
            previous_counter: 0,
            message_keys: vec![SignalProviderStoredMessageKey {
                ratchet_key: active_ratchet.clone(),
                counter: 9,
                message_keys: SignalMessageKeyMaterial {
                    cipher_key: SecretBytes::from(vec![1u8; SIGNAL_MESSAGE_KEY_LEN]),
                    mac_key: SecretBytes::from(vec![2u8; SIGNAL_MESSAGE_KEY_LEN]),
                    iv: [3u8; SIGNAL_MESSAGE_IV_LEN],
                },
            }],
        };
        let encoded = encode_signal_provider_session_record(&record).unwrap();
        let active_ratchet_offsets = encoded
            .windows(active_ratchet.len())
            .enumerate()
            .filter_map(|(offset, window)| (window == active_ratchet).then_some(offset))
            .collect::<Vec<_>>();
        assert!(
            active_ratchet_offsets.len() >= 2,
            "encoded session should contain active ratchet plus skipped key"
        );
        let skipped_counter_offset = active_ratchet_offsets[1] + active_ratchet.len();
        let mut invalid_session = encoded.to_vec();
        invalid_session[skipped_counter_offset..skipped_counter_offset + 4]
            .copy_from_slice(&10u32.to_be_bytes());
        let invalid_session = Bytes::from(invalid_session);

        store
            .set_signal_key(
                KeyNamespace::SignalProviderSession,
                "123.7",
                &invalid_session,
            )
            .await
            .unwrap();
        store
            .set_signal_key(
                KeyNamespace::SignalProviderIdentity,
                "123.7",
                &record.remote_identity_key,
            )
            .await
            .unwrap();

        let decrypt_err = provider_store
            .decrypt_session_record_message(
                remote_jid,
                Bytes::from_static(b"unused-runtime-session-message"),
            )
            .await
            .unwrap_err();
        assert!(matches!(
            decrypt_err,
            CoreError::Protocol(message)
                if message == "Signal provider skipped message counter must be below active receiving counter"
        ));
        assert_eq!(
            provider_store
                .load_session_record(remote_jid)
                .await
                .unwrap(),
            Some(invalid_session)
        );
        assert_eq!(
            provider_store
                .load_identity_record(remote_jid)
                .await
                .unwrap(),
            Some(record.remote_identity_key.clone())
        );

        store
            .set_signal_key(KeyNamespace::SignalProviderSession, "123.7", &encoded)
            .await
            .unwrap();
        assert!(
            provider_store
                .validate_session_record(remote_jid)
                .await
                .unwrap()
                .exists
        );
    }

    #[tokio::test]
    async fn provider_state_store_rejects_skipped_key_without_remote_ratchet() {
        let store = temp_store().await;
        let provider_store = SignalProviderStateStore::new(store.clone());
        let remote_jid = "123:7@s.whatsapp.net";
        let skipped_ratchet_key = test_key_pair(51);
        let skipped_ratchet =
            Bytes::copy_from_slice(&prefixed_signal_public_key(&skipped_ratchet_key.public));
        let skipped_message_keys = SignalMessageKeyMaterial {
            cipher_key: SecretBytes::from(vec![1u8; SIGNAL_MESSAGE_KEY_LEN]),
            mac_key: SecretBytes::from(vec![2u8; SIGNAL_MESSAGE_KEY_LEN]),
            iv: [3u8; SIGNAL_MESSAGE_IV_LEN],
        };
        let record = SignalProviderSessionRecord {
            remote_registration_id: 88,
            remote_identity_key: prefixed_test_signal_key(21),
            root_key: SignalRootKey {
                key: SecretBytes::from(vec![9u8; 32]),
            },
            sending_chain: SignalMessageChainKey {
                key: SecretBytes::from(vec![7u8; 32]),
                counter: 1,
            },
            receiving_chain: None,
            remote_ratchet_key: None,
            local_ratchet_key_pair: test_key_pair(41),
            previous_counter: 0,
            message_keys: Vec::new(),
        };
        let encoded = encode_signal_provider_session_record(&record).unwrap();
        assert_eq!(&encoded[encoded.len() - 6..], &[0, 0, 0, 0, 0, 0]);
        let mut invalid_session = BytesMut::from(&encoded[..encoded.len() - 6]);
        invalid_session.put_u8(0);
        invalid_session.put_u8(0);
        invalid_session.put_u32(1);
        put_bytes(&mut invalid_session, &skipped_ratchet).unwrap();
        invalid_session.put_u32(1);
        put_bytes(
            &mut invalid_session,
            skipped_message_keys.cipher_key.expose(),
        )
        .unwrap();
        put_bytes(&mut invalid_session, skipped_message_keys.mac_key.expose()).unwrap();
        put_bytes(&mut invalid_session, &skipped_message_keys.iv).unwrap();
        let invalid_session = invalid_session.freeze();

        store
            .set_signal_key(
                KeyNamespace::SignalProviderSession,
                "123.7",
                &invalid_session,
            )
            .await
            .unwrap();
        store
            .set_signal_key(
                KeyNamespace::SignalProviderIdentity,
                "123.7",
                &record.remote_identity_key,
            )
            .await
            .unwrap();

        let decrypt_err = provider_store
            .decrypt_session_record_message(
                remote_jid,
                Bytes::from_static(b"unused-runtime-session-message"),
            )
            .await
            .unwrap_err();
        assert!(matches!(
            decrypt_err,
            CoreError::Protocol(message)
                if message == "Signal provider skipped message keys require remote ratchet key"
        ));
        assert_eq!(
            provider_store
                .load_session_record(remote_jid)
                .await
                .unwrap(),
            Some(invalid_session)
        );
        assert_eq!(
            provider_store
                .load_identity_record(remote_jid)
                .await
                .unwrap(),
            Some(record.remote_identity_key.clone())
        );

        store
            .set_signal_key(KeyNamespace::SignalProviderSession, "123.7", &encoded)
            .await
            .unwrap();
        assert!(
            provider_store
                .validate_session_record(remote_jid)
                .await
                .unwrap()
                .exists
        );
    }

    #[tokio::test]
    async fn provider_state_store_rejects_receiving_chain_without_remote_ratchet() {
        let store = temp_store().await;
        let provider_store = SignalProviderStateStore::new(store.clone());
        let remote_jid = "123:7@s.whatsapp.net";
        let remote_ratchet_key_pair = test_key_pair(31);
        let remote_ratchet =
            Bytes::copy_from_slice(&prefixed_signal_public_key(&remote_ratchet_key_pair.public));
        let record = SignalProviderSessionRecord {
            remote_registration_id: 88,
            remote_identity_key: prefixed_test_signal_key(21),
            root_key: SignalRootKey {
                key: SecretBytes::from(vec![9u8; 32]),
            },
            sending_chain: SignalMessageChainKey {
                key: SecretBytes::from(vec![7u8; 32]),
                counter: 1,
            },
            receiving_chain: Some(SignalMessageChainKey {
                key: SecretBytes::from(vec![8u8; 32]),
                counter: 1,
            }),
            remote_ratchet_key: Some(remote_ratchet.clone()),
            local_ratchet_key_pair: test_key_pair(41),
            previous_counter: 0,
            message_keys: Vec::new(),
        };
        let encoded = encode_signal_provider_session_record(&record).unwrap();
        let mut remote_tail = BytesMut::new();
        remote_tail.put_u8(1);
        put_bytes(&mut remote_tail, &remote_ratchet).unwrap();
        remote_tail.put_u32(0);
        assert_eq!(
            &encoded[encoded.len() - remote_tail.len()..],
            remote_tail.as_ref()
        );
        let mut invalid_session = BytesMut::from(&encoded[..encoded.len() - remote_tail.len()]);
        invalid_session.put_u8(0);
        invalid_session.put_u32(0);
        let invalid_session = invalid_session.freeze();

        store
            .set_signal_key(
                KeyNamespace::SignalProviderSession,
                "123.7",
                &invalid_session,
            )
            .await
            .unwrap();
        store
            .set_signal_key(
                KeyNamespace::SignalProviderIdentity,
                "123.7",
                &record.remote_identity_key,
            )
            .await
            .unwrap();

        let decrypt_err = provider_store
            .decrypt_session_record_message(
                remote_jid,
                Bytes::from_static(b"unused-runtime-session-message"),
            )
            .await
            .unwrap_err();
        assert!(matches!(
            decrypt_err,
            CoreError::Protocol(message)
                if message == "Signal provider session receiving chain and remote ratchet key must be stored together"
        ));
        assert_eq!(
            provider_store
                .load_session_record(remote_jid)
                .await
                .unwrap(),
            Some(invalid_session)
        );
        assert_eq!(
            provider_store
                .load_identity_record(remote_jid)
                .await
                .unwrap(),
            Some(record.remote_identity_key.clone())
        );

        store
            .set_signal_key(KeyNamespace::SignalProviderSession, "123.7", &encoded)
            .await
            .unwrap();
        assert!(
            provider_store
                .validate_session_record(remote_jid)
                .await
                .unwrap()
                .exists
        );
    }

    #[tokio::test]
    async fn provider_state_store_rejects_uninitialized_sending_chain_without_remote_ratchet() {
        let store = temp_store().await;
        let provider_store = SignalProviderStateStore::new(store.clone());
        let remote_jid = "123:7@s.whatsapp.net";
        let record = SignalProviderSessionRecord {
            remote_registration_id: 88,
            remote_identity_key: prefixed_test_signal_key(21),
            root_key: SignalRootKey {
                key: SecretBytes::from(vec![9u8; 32]),
            },
            sending_chain: SignalMessageChainKey {
                key: SecretBytes::from(vec![7u8; 32]),
                counter: 1,
            },
            receiving_chain: None,
            remote_ratchet_key: None,
            local_ratchet_key_pair: test_key_pair(41),
            previous_counter: 0,
            message_keys: Vec::new(),
        };
        let encoded = encode_signal_provider_session_record(&record).unwrap();
        let sending_key = record.sending_chain.key.expose();
        let sending_key_offsets = encoded
            .windows(sending_key.len())
            .enumerate()
            .filter_map(|(offset, window)| (window == sending_key).then_some(offset))
            .collect::<Vec<_>>();
        assert_eq!(sending_key_offsets.len(), 1);
        let sending_key_offset = sending_key_offsets[0];
        assert!(sending_key_offset >= 6);
        let sending_counter_offset = sending_key_offset - 6;
        let mut invalid_session = encoded.to_vec();
        invalid_session[sending_counter_offset..sending_counter_offset + 4]
            .copy_from_slice(&0u32.to_be_bytes());
        invalid_session[sending_key_offset..sending_key_offset + sending_key.len()].fill(0);
        let invalid_session = Bytes::from(invalid_session);

        store
            .set_signal_key(
                KeyNamespace::SignalProviderSession,
                "123.7",
                &invalid_session,
            )
            .await
            .unwrap();
        store
            .set_signal_key(
                KeyNamespace::SignalProviderIdentity,
                "123.7",
                &record.remote_identity_key,
            )
            .await
            .unwrap();

        let decrypt_err = provider_store
            .decrypt_session_record_message(
                remote_jid,
                Bytes::from_static(b"unused-runtime-session-message"),
            )
            .await
            .unwrap_err();
        assert!(matches!(
            decrypt_err,
            CoreError::Protocol(message)
                if message == "Signal provider session uninitialized sending chain requires remote ratchet key"
        ));
        assert_eq!(
            provider_store
                .load_session_record(remote_jid)
                .await
                .unwrap(),
            Some(invalid_session)
        );
        assert_eq!(
            provider_store
                .load_identity_record(remote_jid)
                .await
                .unwrap(),
            Some(record.remote_identity_key.clone())
        );

        store
            .set_signal_key(KeyNamespace::SignalProviderSession, "123.7", &encoded)
            .await
            .unwrap();
        assert!(
            provider_store
                .validate_session_record(remote_jid)
                .await
                .unwrap()
                .exists
        );
    }

    #[tokio::test]
    async fn provider_state_store_rejects_remote_ratchet_without_receiving_chain() {
        let store = temp_store().await;
        let provider_store = SignalProviderStateStore::new(store.clone());
        let remote_jid = "123:7@s.whatsapp.net";
        let remote_ratchet_key_pair = test_key_pair(31);
        let remote_ratchet =
            Bytes::copy_from_slice(&prefixed_signal_public_key(&remote_ratchet_key_pair.public));
        let record = SignalProviderSessionRecord {
            remote_registration_id: 88,
            remote_identity_key: prefixed_test_signal_key(21),
            root_key: SignalRootKey {
                key: SecretBytes::from(vec![9u8; 32]),
            },
            sending_chain: SignalMessageChainKey {
                key: SecretBytes::from(vec![7u8; 32]),
                counter: 1,
            },
            receiving_chain: None,
            remote_ratchet_key: None,
            local_ratchet_key_pair: test_key_pair(41),
            previous_counter: 0,
            message_keys: Vec::new(),
        };
        let encoded = encode_signal_provider_session_record(&record).unwrap();
        assert_eq!(&encoded[encoded.len() - 6..], &[0, 0, 0, 0, 0, 0]);
        let mut invalid_session = BytesMut::from(&encoded[..encoded.len() - 6]);
        invalid_session.put_u8(0);
        invalid_session.put_u8(1);
        put_bytes(&mut invalid_session, &remote_ratchet).unwrap();
        invalid_session.put_u32(0);
        let invalid_session = invalid_session.freeze();

        store
            .set_signal_key(
                KeyNamespace::SignalProviderSession,
                "123.7",
                &invalid_session,
            )
            .await
            .unwrap();
        store
            .set_signal_key(
                KeyNamespace::SignalProviderIdentity,
                "123.7",
                &record.remote_identity_key,
            )
            .await
            .unwrap();

        let decrypt_err = provider_store
            .decrypt_session_record_message(
                remote_jid,
                Bytes::from_static(b"unused-runtime-session-message"),
            )
            .await
            .unwrap_err();
        assert!(matches!(
            decrypt_err,
            CoreError::Protocol(message)
                if message == "Signal provider session receiving chain and remote ratchet key must be stored together"
        ));
        assert_eq!(
            provider_store
                .load_session_record(remote_jid)
                .await
                .unwrap(),
            Some(invalid_session)
        );
        assert_eq!(
            provider_store
                .load_identity_record(remote_jid)
                .await
                .unwrap(),
            Some(record.remote_identity_key.clone())
        );

        store
            .set_signal_key(KeyNamespace::SignalProviderSession, "123.7", &encoded)
            .await
            .unwrap();
        assert!(
            provider_store
                .validate_session_record(remote_jid)
                .await
                .unwrap()
                .exists
        );
    }

    #[tokio::test]
    async fn repository_clears_group_sender_key_memory() {
        let store = temp_store().await;
        store
            .set_signal_key(KeyNamespace::SenderKeyMemory, "555@g.us", b"sender-memory")
            .await
            .unwrap();
        store
            .set_signal_key(
                KeyNamespace::SignalProviderSenderKeyMemory,
                "555@g.us",
                b"provider-sender-memory",
            )
            .await
            .unwrap();
        let repository = StoreSignalRepository::new(store.clone());

        assert!(
            repository
                .clear_sender_key_memory("555@g.us")
                .await
                .unwrap()
        );
        assert!(
            store
                .get_signal_key(KeyNamespace::SenderKeyMemory, "555@g.us")
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .get_signal_key(KeyNamespace::SignalProviderSenderKeyMemory, "555@g.us")
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            !repository
                .clear_sender_key_memory("555@g.us")
                .await
                .unwrap()
        );
        assert!(
            repository
                .clear_sender_key_memory("123@s.whatsapp.net")
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn repository_clears_session_on_identity_change_and_migrates_sessions() {
        let store = temp_store().await;
        let provider_store = SignalProviderStateStore::new(store.clone());
        let repository = StoreSignalRepository::new(store);

        repository
            .inject_e2e_session(SessionInjection {
                jid: "123:7@s.whatsapp.net".to_owned(),
                session: test_session(),
            })
            .await
            .unwrap();
        provider_store
            .store_session_record("123:7@s.whatsapp.net", b"native-session")
            .await
            .unwrap();
        provider_store
            .store_identity_record("123:7@s.whatsapp.net", b"native-identity")
            .await
            .unwrap();
        assert!(
            repository
                .save_identity("123:7@s.whatsapp.net", Bytes::from(vec![9u8; 32]))
                .await
                .unwrap()
        );
        assert!(
            !repository
                .validate_session("123:7@s.whatsapp.net")
                .await
                .unwrap()
                .exists
        );
        assert!(
            provider_store
                .load_session_record("123:7@s.whatsapp.net")
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            provider_store
                .load_identity_record("123:7@s.whatsapp.net")
                .await
                .unwrap()
                .is_none()
        );

        repository
            .inject_e2e_session(SessionInjection {
                jid: "123:7@s.whatsapp.net".to_owned(),
                session: test_session(),
            })
            .await
            .unwrap();
        provider_store
            .store_session_record("123:7@s.whatsapp.net", b"native-session")
            .await
            .unwrap();
        provider_store
            .store_identity_record("123:7@s.whatsapp.net", b"native-identity")
            .await
            .unwrap();
        let migration = repository
            .migrate_session("123:7@s.whatsapp.net", "lid-user:7@lid")
            .await
            .unwrap();
        assert_eq!(
            migration,
            SignalSessionMigration {
                migrated: 4,
                skipped: 0,
                total: 4
            }
        );
        assert!(
            repository
                .validate_session("lid-user:7@lid")
                .await
                .unwrap()
                .exists
        );
        assert!(
            provider_store
                .load_session_record("123:7@s.whatsapp.net")
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            provider_store
                .load_identity_record("123:7@s.whatsapp.net")
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            provider_store
                .load_session_record("lid-user:7@lid")
                .await
                .unwrap()
                .as_deref(),
            Some(&b"native-session"[..])
        );
        assert_eq!(
            provider_store
                .load_identity_record("lid-user:7@lid")
                .await
                .unwrap()
                .as_deref(),
            Some(&b"native-identity"[..])
        );
        assert!(
            repository
                .save_identity("lid-user:7@lid", Bytes::from(vec![7u8; 32]))
                .await
                .unwrap()
        );
        assert!(
            !repository
                .validate_session("lid-user:7@lid")
                .await
                .unwrap()
                .exists
        );
        assert!(
            provider_store
                .load_session_record("lid-user:7@lid")
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            provider_store
                .load_identity_record("lid-user:7@lid")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn repository_migrates_native_sessions_as_valid_identity_pairs() {
        let store = temp_store().await;
        let repository = StoreSignalRepository::new(store.clone());
        let source_jid = "123:7@s.whatsapp.net";
        let destination_jid = "lid-user:7@lid";
        let source = signal_protocol_address(source_jid).unwrap().to_string();
        let destination = signal_protocol_address(destination_jid)
            .unwrap()
            .to_string();
        let session = test_session();
        let encoded = encode_stored_session(&session).unwrap();

        store
            .set_signal_key(KeyNamespace::Session, &source, &encoded)
            .await
            .unwrap();
        let migration = repository
            .migrate_session(source_jid, destination_jid)
            .await
            .unwrap();
        assert_eq!(
            migration,
            SignalSessionMigration {
                migrated: 0,
                skipped: 1,
                total: 1
            }
        );
        assert!(
            store
                .get_signal_key(KeyNamespace::Session, &source)
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            store
                .get_signal_key(KeyNamespace::Session, &destination)
                .await
                .unwrap()
                .is_none()
        );

        store
            .set_signal_key(KeyNamespace::IdentityKey, &source, &[9u8; 32])
            .await
            .unwrap();
        let migration = repository
            .migrate_session(source_jid, destination_jid)
            .await
            .unwrap();
        assert_eq!(
            migration,
            SignalSessionMigration {
                migrated: 0,
                skipped: 2,
                total: 2
            }
        );
        assert_eq!(
            repository
                .validate_session(source_jid)
                .await
                .unwrap()
                .reason
                .as_deref(),
            Some("identity mismatch")
        );
        assert!(
            !repository
                .validate_session(destination_jid)
                .await
                .unwrap()
                .exists
        );

        store
            .set_signal_key(KeyNamespace::IdentityKey, &source, &session.identity_key)
            .await
            .unwrap();
        let migration = repository
            .migrate_session(source_jid, destination_jid)
            .await
            .unwrap();
        assert_eq!(
            migration,
            SignalSessionMigration {
                migrated: 2,
                skipped: 0,
                total: 2
            }
        );
        assert!(
            store
                .get_signal_key(KeyNamespace::Session, &source)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .get_signal_key(KeyNamespace::IdentityKey, &source)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            repository
                .validate_session(destination_jid)
                .await
                .unwrap()
                .exists
        );
    }

    #[tokio::test]
    async fn repository_skips_native_pair_migration_when_destination_conflicts() {
        let store = temp_store().await;
        let repository = StoreSignalRepository::new(store.clone());
        let source_jid = "123:7@s.whatsapp.net";
        let destination_jid = "456:7@s.whatsapp.net";
        let source = signal_protocol_address(source_jid).unwrap().to_string();
        let destination = signal_protocol_address(destination_jid)
            .unwrap()
            .to_string();
        let session = test_session();
        let encoded = encode_stored_session(&session).unwrap();

        store
            .set_signal_key(KeyNamespace::Session, &source, &encoded)
            .await
            .unwrap();
        store
            .set_signal_key(KeyNamespace::IdentityKey, &source, &session.identity_key)
            .await
            .unwrap();
        store
            .set_signal_key(KeyNamespace::IdentityKey, &destination, &[8u8; 32])
            .await
            .unwrap();

        let migration = repository
            .migrate_session(source_jid, destination_jid)
            .await
            .unwrap();
        assert_eq!(
            migration,
            SignalSessionMigration {
                migrated: 0,
                skipped: 2,
                total: 2
            }
        );
        assert!(
            repository
                .validate_session(source_jid)
                .await
                .unwrap()
                .exists
        );
        assert!(
            store
                .get_signal_key(KeyNamespace::Session, &destination)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            store
                .get_signal_key(KeyNamespace::IdentityKey, &destination)
                .await
                .unwrap()
                .as_deref(),
            Some(&[8u8; 32][..])
        );
    }

    #[tokio::test]
    async fn repository_skips_provider_pair_migration_when_destination_identity_conflicts() {
        let store = temp_store().await;
        let provider_store = SignalProviderStateStore::new(store.clone());
        let repository = StoreSignalRepository::new(store);
        let source_jid = "123:7@s.whatsapp.net";
        let destination_jid = "456:7@s.whatsapp.net";
        let record = SignalProviderSessionRecord {
            remote_registration_id: 88,
            remote_identity_key: prefixed_test_signal_key(21),
            root_key: SignalRootKey {
                key: SecretBytes::from(vec![9u8; 32]),
            },
            sending_chain: SignalMessageChainKey {
                key: SecretBytes::from(vec![7u8; 32]),
                counter: 0,
            },
            receiving_chain: None,
            remote_ratchet_key: None,
            local_ratchet_key_pair: test_key_pair(31),
            previous_counter: 0,
            message_keys: Vec::new(),
        };
        let encoded = encode_signal_provider_session_record(&record).unwrap();

        provider_store
            .store_session_and_identity_records(source_jid, &encoded, &record.remote_identity_key)
            .await
            .unwrap();
        provider_store
            .store_identity_record(destination_jid, &prefixed_test_signal_key(22))
            .await
            .unwrap();

        let migration = repository
            .migrate_session(source_jid, destination_jid)
            .await
            .unwrap();
        assert_eq!(
            migration,
            SignalSessionMigration {
                migrated: 0,
                skipped: 2,
                total: 2
            }
        );
        assert_eq!(
            provider_store
                .load_session_record(source_jid)
                .await
                .unwrap()
                .unwrap(),
            encoded
        );
        assert_eq!(
            provider_store
                .load_identity_record(source_jid)
                .await
                .unwrap(),
            Some(record.remote_identity_key)
        );
        assert!(
            provider_store
                .load_session_record(destination_jid)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            provider_store
                .load_identity_record(destination_jid)
                .await
                .unwrap(),
            Some(prefixed_test_signal_key(22))
        );
    }

    #[tokio::test]
    async fn repository_skips_partial_decodable_provider_session_migration() {
        let store = temp_store().await;
        let provider_store = SignalProviderStateStore::new(store.clone());
        let repository = StoreSignalRepository::new(store);
        let record = SignalProviderSessionRecord {
            remote_registration_id: 88,
            remote_identity_key: prefixed_test_signal_key(21),
            root_key: SignalRootKey {
                key: SecretBytes::from(vec![9u8; 32]),
            },
            sending_chain: SignalMessageChainKey {
                key: SecretBytes::from(vec![7u8; 32]),
                counter: 0,
            },
            receiving_chain: None,
            remote_ratchet_key: None,
            local_ratchet_key_pair: test_key_pair(31),
            previous_counter: 0,
            message_keys: Vec::new(),
        };
        let encoded = encode_signal_provider_session_record(&record).unwrap();

        provider_store
            .store_session_record("123:7@s.whatsapp.net", &encoded)
            .await
            .unwrap();
        let migration = repository
            .migrate_session("123:7@s.whatsapp.net", "456:7@s.whatsapp.net")
            .await
            .unwrap();
        assert_eq!(
            migration,
            SignalSessionMigration {
                migrated: 0,
                skipped: 1,
                total: 1
            }
        );
        assert_eq!(
            provider_store
                .load_session_record("123:7@s.whatsapp.net")
                .await
                .unwrap()
                .unwrap(),
            encoded
        );
        assert!(
            provider_store
                .load_session_record("456:7@s.whatsapp.net")
                .await
                .unwrap()
                .is_none()
        );

        provider_store
            .store_session_record("321:7@s.whatsapp.net", b"native-session-record")
            .await
            .unwrap();
        let migration = repository
            .migrate_session("321:7@s.whatsapp.net", "654:7@s.whatsapp.net")
            .await
            .unwrap();
        assert_eq!(
            migration,
            SignalSessionMigration {
                migrated: 1,
                skipped: 0,
                total: 1
            }
        );
        assert!(
            provider_store
                .load_session_record("321:7@s.whatsapp.net")
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            provider_store
                .load_session_record("654:7@s.whatsapp.net")
                .await
                .unwrap()
                .as_deref(),
            Some(&b"native-session-record"[..])
        );
    }

    #[tokio::test]
    async fn lid_mapping_store_persists_forward_and_reverse_mappings() {
        let store = temp_store().await;
        let mappings = LidPnMappingStore::new(store);

        mappings
            .store_mappings(vec![LidPnMapping {
                pn: "123@s.whatsapp.net".to_owned(),
                lid: "abc@lid".to_owned(),
            }])
            .await
            .unwrap();

        assert_eq!(
            mappings.lid_for_pn("123@s.whatsapp.net").await.unwrap(),
            Some("abc".to_owned())
        );
        assert_eq!(
            mappings.pn_for_lid("abc@lid").await.unwrap(),
            Some("123".to_owned())
        );
    }

    #[tokio::test]
    async fn signal_message_codec_encrypts_with_store_session() {
        let store = temp_store().await;
        let repository = StoreSignalRepository::new(store);
        repository
            .inject_e2e_session(SessionInjection {
                jid: "123:7@s.whatsapp.net".to_owned(),
                session: test_session(),
            })
            .await
            .unwrap();
        let provider = RecordingSignalProvider::default();
        let codec = SignalMessageCodec::new(repository, provider.clone());

        let encrypted = codec
            .encrypt_message("123:7@s.whatsapp.net", Bytes::from_static(b"plain"))
            .await
            .unwrap();

        assert_eq!(encrypted.ciphertext_type, MessageCiphertextType::Message);
        assert_eq!(encrypted.ciphertext, Bytes::from_static(b"cipher:plain"));
        {
            let requests = provider.encrypt_requests.lock().unwrap();
            assert_eq!(requests.len(), 1);
            assert_eq!(requests[0].recipient_jid, "123:7@s.whatsapp.net");
            let session = requests[0].session.as_ref().unwrap();
            assert_eq!(session.address.to_string(), "123.7");
            assert_eq!(session.registration_id, 1234);
            assert_eq!(
                session.base_key,
                normalize_signal_public_key(&[4u8; 32]).unwrap()
            );
            assert_eq!(session.session.signed_pre_key.key_id, 7);
            assert_eq!(
                session.session.pre_key.as_ref().unwrap().public_key,
                normalize_signal_public_key(&[4u8; 32]).unwrap()
            );
        }

        let encrypted = codec
            .encrypt_message("456:7@s.whatsapp.net", Bytes::from_static(b"native-plain"))
            .await
            .unwrap();

        assert_eq!(
            encrypted.ciphertext,
            Bytes::from_static(b"cipher:native-plain")
        );
        {
            let requests = provider.encrypt_requests.lock().unwrap();
            assert_eq!(requests.len(), 2);
            assert_eq!(requests[1].recipient_jid, "456:7@s.whatsapp.net");
            assert!(requests[1].session.is_none());
        }
    }

    #[tokio::test]
    async fn signal_message_codec_decrypts_with_sessions_and_sender_keys() {
        let store = temp_store().await;
        let repository = StoreSignalRepository::new(store);
        repository
            .inject_e2e_session(SessionInjection {
                jid: "123:7@s.whatsapp.net".to_owned(),
                session: test_session(),
            })
            .await
            .unwrap();
        let provider = RecordingSignalProvider::default();
        let codec = SignalMessageCodec::new(repository.clone(), provider.clone());

        let plaintext = codec
            .decrypt_inbound_message(InboundEncryptedPayload {
                sender_jid: "123:7@s.whatsapp.net".to_owned(),
                chat_jid: "123@s.whatsapp.net".to_owned(),
                ciphertext_type: InboundCiphertextType::Message,
                ciphertext: Bytes::from_static(b"ciphertext"),
            })
            .await
            .unwrap();

        assert_eq!(plaintext, Bytes::from_static(b"plain:ciphertext"));
        {
            let requests = provider.decrypt_requests.lock().unwrap();
            assert_eq!(requests.len(), 1);
            assert!(requests[0].session.is_some());
            assert!(requests[0].sender_key_distribution.is_none());
        }

        let plaintext = codec
            .decrypt_inbound_message(InboundEncryptedPayload {
                sender_jid: "456:7@s.whatsapp.net".to_owned(),
                chat_jid: "456@s.whatsapp.net".to_owned(),
                ciphertext_type: InboundCiphertextType::PreKey,
                ciphertext: Bytes::from_static(b"pre-key-ciphertext"),
            })
            .await
            .unwrap();

        assert_eq!(plaintext, Bytes::from_static(b"plain:pre-key-ciphertext"));
        {
            let requests = provider.decrypt_requests.lock().unwrap();
            assert_eq!(requests.len(), 2);
            assert!(requests[1].session.is_none());
            assert!(requests[1].sender_key_distribution.is_none());
        }

        let plaintext = codec
            .decrypt_inbound_message(InboundEncryptedPayload {
                sender_jid: "789:7@s.whatsapp.net".to_owned(),
                chat_jid: "789@s.whatsapp.net".to_owned(),
                ciphertext_type: InboundCiphertextType::Message,
                ciphertext: Bytes::from_static(b"native-session-ciphertext"),
            })
            .await
            .unwrap();

        assert_eq!(
            plaintext,
            Bytes::from_static(b"plain:native-session-ciphertext")
        );
        {
            let requests = provider.decrypt_requests.lock().unwrap();
            assert_eq!(requests.len(), 3);
            assert!(requests[2].session.is_none());
            assert!(requests[2].sender_key_distribution.is_none());
        }

        let signing_key = test_key_pair(91);
        let sender_key_distribution =
            build_signal_sender_key_distribution_message(55, 0, &[7u8; 32], &signing_key.public)
                .unwrap();
        let sender_key_distribution =
            encode_signal_sender_key_distribution_message(&sender_key_distribution).unwrap();
        codec
            .process_sender_key_distribution(
                "123:7@s.whatsapp.net",
                &SenderKeyDistributionMessage {
                    group_id: Some("555@g.us".to_owned()),
                    axolotl_sender_key_distribution_message: Some(sender_key_distribution.clone()),
                },
            )
            .await
            .unwrap();
        assert_eq!(
            repository
                .get_sender_key_distribution("123:7@s.whatsapp.net", "555@g.us")
                .await
                .unwrap(),
            Some(sender_key_distribution.clone())
        );

        let plaintext = codec
            .decrypt_inbound_message(InboundEncryptedPayload {
                sender_jid: "123:7@s.whatsapp.net".to_owned(),
                chat_jid: "555@g.us".to_owned(),
                ciphertext_type: InboundCiphertextType::SenderKey,
                ciphertext: Bytes::from_static(b"group-ciphertext"),
            })
            .await
            .unwrap();

        assert_eq!(plaintext, Bytes::from_static(b"plain:group-ciphertext"));
        let requests = provider.decrypt_requests.lock().unwrap();
        assert_eq!(requests.len(), 4);
        assert!(requests[3].session.is_none());
        assert_eq!(
            requests[3].sender_key_distribution.as_deref(),
            Some(sender_key_distribution.as_ref())
        );
        assert_eq!(
            provider.sender_key_distributions.lock().unwrap().as_slice(),
            &[SignalSenderKeyDistribution {
                author_jid: "123:7@s.whatsapp.net".to_owned(),
                group_jid: "555@g.us".to_owned(),
                distribution: sender_key_distribution,
            }]
        );
    }

    #[tokio::test]
    async fn signal_message_codec_normalizes_legacy_c_us_signal_jids() {
        let store = temp_store().await;
        let repository = StoreSignalRepository::new(store.clone());
        repository
            .inject_e2e_session(SessionInjection {
                jid: "123:7@s.whatsapp.net".to_owned(),
                session: test_session(),
            })
            .await
            .unwrap();
        let provider = RecordingSignalProvider::default();
        let codec = SignalMessageCodec::new(repository.clone(), provider.clone());

        let encrypted = codec
            .encrypt_message("123:7@c.us", Bytes::from_static(b"legacy-send"))
            .await
            .unwrap();
        assert_eq!(
            encrypted.ciphertext,
            Bytes::from_static(b"cipher:legacy-send")
        );
        {
            let requests = provider.encrypt_requests.lock().unwrap();
            assert_eq!(requests.len(), 1);
            assert_eq!(requests[0].recipient_jid, "123:7@s.whatsapp.net");
            assert_eq!(
                requests[0].session.as_ref().unwrap().address.to_string(),
                "123.7"
            );
        }

        let plaintext = codec
            .decrypt_inbound_message(InboundEncryptedPayload {
                sender_jid: "123:7@c.us".to_owned(),
                chat_jid: "123@c.us".to_owned(),
                ciphertext_type: InboundCiphertextType::Message,
                ciphertext: Bytes::from_static(b"legacy-ciphertext"),
            })
            .await
            .unwrap();
        assert_eq!(plaintext, Bytes::from_static(b"plain:legacy-ciphertext"));
        {
            let requests = provider.decrypt_requests.lock().unwrap();
            assert_eq!(requests.len(), 1);
            assert_eq!(requests[0].payload.sender_jid, "123:7@s.whatsapp.net");
            assert_eq!(requests[0].payload.chat_jid, "123@c.us");
            assert!(requests[0].session.is_some());
        }

        let signing_key = test_key_pair(92);
        let sender_key_distribution =
            build_signal_sender_key_distribution_message(56, 0, &[8u8; 32], &signing_key.public)
                .unwrap();
        let sender_key_distribution =
            encode_signal_sender_key_distribution_message(&sender_key_distribution).unwrap();
        codec
            .process_sender_key_distribution(
                "123:7@c.us",
                &SenderKeyDistributionMessage {
                    group_id: Some("555@g.us".to_owned()),
                    axolotl_sender_key_distribution_message: Some(sender_key_distribution.clone()),
                },
            )
            .await
            .unwrap();
        assert_eq!(
            provider.sender_key_distributions.lock().unwrap().as_slice(),
            &[SignalSenderKeyDistribution {
                author_jid: "123:7@s.whatsapp.net".to_owned(),
                group_jid: "555@g.us".to_owned(),
                distribution: sender_key_distribution.clone(),
            }]
        );
        assert_eq!(
            repository
                .get_sender_key_distribution("123:7@c.us", "555@g.us")
                .await
                .unwrap(),
            Some(sender_key_distribution.clone())
        );
        assert_eq!(
            store
                .get_signal_key(KeyNamespace::SenderKey, "555@g.us|123:7@s.whatsapp.net")
                .await
                .unwrap()
                .as_deref(),
            Some(sender_key_distribution.as_ref())
        );
        assert!(
            store
                .get_signal_key(KeyNamespace::SenderKey, "555@g.us|123:7@c.us")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn signal_provider_session_record_encrypts_and_advances_send_chain() {
        let local_ratchet_key_pair = test_key_pair(31);
        let record = SignalProviderSessionRecord {
            remote_registration_id: 88,
            remote_identity_key: prefixed_test_signal_key(21),
            root_key: SignalRootKey {
                key: SecretBytes::from(vec![9u8; 32]),
            },
            sending_chain: SignalMessageChainKey {
                key: SecretBytes::from(vec![7u8; 32]),
                counter: 0,
            },
            receiving_chain: None,
            remote_ratchet_key: None,
            local_ratchet_key_pair,
            previous_counter: 0,
            message_keys: Vec::new(),
        };
        let encoded = encode_signal_provider_session_record(&record).unwrap();
        assert_eq!(
            decode_signal_provider_session_record(&encoded).unwrap(),
            record
        );

        let first =
            encrypt_signal_provider_session_record_message(&encoded, b"direct first").unwrap();
        assert_eq!(first.message.counter, 1);
        assert_eq!(first.message.previous_counter, 0);
        assert_eq!(
            first.message.ephemeral_key,
            Bytes::copy_from_slice(&prefixed_signal_public_key(
                &record.local_ratchet_key_pair.public
            ))
        );
        let first_keys = ratchet_signal_message_chain(&record.sending_chain).unwrap();
        assert_eq!(
            decrypt_signal_message_body(&first.message.ciphertext, &first_keys.message_keys)
                .unwrap(),
            Bytes::from_static(b"direct first")
        );
        let after_first = decode_signal_provider_session_record(&first.record).unwrap();
        assert_eq!(after_first.sending_chain.counter, 1);

        let second =
            encrypt_signal_provider_session_record_message(&first.record, b"direct second")
                .unwrap();
        assert_eq!(second.message.counter, 2);
        let second_keys = ratchet_signal_message_chain(&after_first.sending_chain).unwrap();
        assert_eq!(
            decrypt_signal_message_body(&second.message.ciphertext, &second_keys.message_keys)
                .unwrap(),
            Bytes::from_static(b"direct second")
        );
        assert_eq!(
            decode_signal_provider_session_record(&second.record)
                .unwrap()
                .sending_chain
                .counter,
            2
        );
    }

    #[test]
    fn signal_provider_session_record_decrypts_receiving_chain_and_rejects_replay() {
        let sender_ratchet_key_pair = test_key_pair(31);
        let sender_record = SignalProviderSessionRecord {
            remote_registration_id: 88,
            remote_identity_key: prefixed_test_signal_key(21),
            root_key: SignalRootKey {
                key: SecretBytes::from(vec![9u8; 32]),
            },
            sending_chain: SignalMessageChainKey {
                key: SecretBytes::from(vec![7u8; 32]),
                counter: 0,
            },
            receiving_chain: None,
            remote_ratchet_key: None,
            local_ratchet_key_pair: sender_ratchet_key_pair.clone(),
            previous_counter: 0,
            message_keys: Vec::new(),
        };
        let first = encrypt_signal_provider_session_record_message(
            &encode_signal_provider_session_record(&sender_record).unwrap(),
            b"direct first",
        )
        .unwrap();
        let second =
            encrypt_signal_provider_session_record_message(&first.record, b"direct second")
                .unwrap();
        let receiver_record = SignalProviderSessionRecord {
            remote_registration_id: 88,
            remote_identity_key: prefixed_test_signal_key(21),
            root_key: SignalRootKey {
                key: SecretBytes::from(vec![9u8; 32]),
            },
            sending_chain: uninitialized_signal_message_chain(),
            receiving_chain: Some(SignalMessageChainKey {
                key: SecretBytes::from(vec![7u8; 32]),
                counter: 0,
            }),
            remote_ratchet_key: Some(Bytes::copy_from_slice(&prefixed_signal_public_key(
                &sender_ratchet_key_pair.public,
            ))),
            local_ratchet_key_pair: test_key_pair(41),
            previous_counter: 0,
            message_keys: Vec::new(),
        };
        let receiver_record = encode_signal_provider_session_record(&receiver_record).unwrap();

        let decrypted =
            decrypt_signal_provider_session_record_message(&receiver_record, &first.message_bytes)
                .unwrap();
        assert_eq!(decrypted.plaintext, Bytes::from_static(b"direct first"));
        assert_eq!(
            decode_signal_provider_session_record(&decrypted.record)
                .unwrap()
                .receiving_chain
                .as_ref()
                .unwrap()
                .counter,
            1
        );
        assert!(
            decrypt_signal_provider_session_record_message(&decrypted.record, &first.message_bytes)
                .is_err()
        );
        let decrypted_second = decrypt_signal_provider_session_record_message(
            &decrypted.record,
            &second.message_bytes,
        )
        .unwrap();
        assert_eq!(
            decrypted_second.plaintext,
            Bytes::from_static(b"direct second")
        );

        let mut tampered = second.message_bytes.to_vec();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(
            decrypt_signal_provider_session_record_message(&receiver_record, &tampered).is_err()
        );
    }

    #[test]
    fn signal_provider_session_record_decrypts_out_of_order_with_skipped_keys() {
        let sender_ratchet_key_pair = test_key_pair(31);
        let sender_record = SignalProviderSessionRecord {
            remote_registration_id: 88,
            remote_identity_key: prefixed_test_signal_key(21),
            root_key: SignalRootKey {
                key: SecretBytes::from(vec![9u8; 32]),
            },
            sending_chain: SignalMessageChainKey {
                key: SecretBytes::from(vec![7u8; 32]),
                counter: 0,
            },
            receiving_chain: None,
            remote_ratchet_key: None,
            local_ratchet_key_pair: sender_ratchet_key_pair.clone(),
            previous_counter: 0,
            message_keys: Vec::new(),
        };
        let first = encrypt_signal_provider_session_record_message(
            &encode_signal_provider_session_record(&sender_record).unwrap(),
            b"direct first",
        )
        .unwrap();
        let second =
            encrypt_signal_provider_session_record_message(&first.record, b"direct second")
                .unwrap();
        let receiver_record = encode_signal_provider_session_record(&SignalProviderSessionRecord {
            remote_registration_id: 88,
            remote_identity_key: prefixed_test_signal_key(21),
            root_key: SignalRootKey {
                key: SecretBytes::from(vec![9u8; 32]),
            },
            sending_chain: uninitialized_signal_message_chain(),
            receiving_chain: Some(SignalMessageChainKey {
                key: SecretBytes::from(vec![7u8; 32]),
                counter: 0,
            }),
            remote_ratchet_key: Some(Bytes::copy_from_slice(&prefixed_signal_public_key(
                &sender_ratchet_key_pair.public,
            ))),
            local_ratchet_key_pair: test_key_pair(41),
            previous_counter: 0,
            message_keys: Vec::new(),
        })
        .unwrap();

        let second_decrypted =
            decrypt_signal_provider_session_record_message(&receiver_record, &second.message_bytes)
                .unwrap();
        assert_eq!(
            second_decrypted.plaintext,
            Bytes::from_static(b"direct second")
        );
        let after_second = decode_signal_provider_session_record(&second_decrypted.record).unwrap();
        assert_eq!(after_second.receiving_chain.as_ref().unwrap().counter, 2);
        assert_eq!(after_second.message_keys.len(), 1);
        assert_eq!(after_second.message_keys[0].counter, 1);

        let first_decrypted = decrypt_signal_provider_session_record_message(
            &second_decrypted.record,
            &first.message_bytes,
        )
        .unwrap();
        assert_eq!(
            first_decrypted.plaintext,
            Bytes::from_static(b"direct first")
        );
        assert!(
            decode_signal_provider_session_record(&first_decrypted.record)
                .unwrap()
                .message_keys
                .is_empty()
        );
        assert!(
            decrypt_signal_provider_session_record_message(
                &first_decrypted.record,
                &first.message_bytes,
            )
            .is_err()
        );
    }

    #[test]
    fn signal_provider_session_record_prunes_oldest_skipped_message_keys() {
        let sender_ratchet_key_pair = test_key_pair(31);
        let mut chain = SignalMessageChainKey {
            key: SecretBytes::from(vec![7u8; 32]),
            counter: 0,
        };
        let target_counter = u32::try_from(SIGNAL_MAX_PROVIDER_MESSAGE_KEYS).unwrap() + 2;
        let mut first_keys = None;
        let mut second_keys = None;
        let mut target_keys = None;
        while chain.counter < target_counter {
            let step = ratchet_signal_message_chain(&chain).unwrap();
            match step.message_counter {
                1 => first_keys = Some(step.message_keys.clone()),
                2 => second_keys = Some(step.message_keys.clone()),
                value if value == target_counter => target_keys = Some(step.message_keys.clone()),
                _ => {}
            }
            chain = step.next_chain_key;
        }
        let first_keys = first_keys.unwrap();
        let second_keys = second_keys.unwrap();
        let target_keys = target_keys.unwrap();
        let sender_ratchet_key =
            Bytes::copy_from_slice(&prefixed_signal_public_key(&sender_ratchet_key_pair.public));
        let first = encode_signal_whisper_message(&SignalWhisperMessage {
            ephemeral_key: sender_ratchet_key.clone(),
            counter: 1,
            previous_counter: 0,
            ciphertext: encrypt_signal_message_body(b"direct first", &first_keys).unwrap(),
        })
        .unwrap();
        let second = encode_signal_whisper_message(&SignalWhisperMessage {
            ephemeral_key: sender_ratchet_key.clone(),
            counter: 2,
            previous_counter: 0,
            ciphertext: encrypt_signal_message_body(b"direct second", &second_keys).unwrap(),
        })
        .unwrap();
        let target = encode_signal_whisper_message(&SignalWhisperMessage {
            ephemeral_key: sender_ratchet_key.clone(),
            counter: target_counter,
            previous_counter: 0,
            ciphertext: encrypt_signal_message_body(b"direct target", &target_keys).unwrap(),
        })
        .unwrap();
        let receiver_record = encode_signal_provider_session_record(&SignalProviderSessionRecord {
            remote_registration_id: 88,
            remote_identity_key: prefixed_test_signal_key(21),
            root_key: SignalRootKey {
                key: SecretBytes::from(vec![9u8; 32]),
            },
            sending_chain: uninitialized_signal_message_chain(),
            receiving_chain: Some(SignalMessageChainKey {
                key: SecretBytes::from(vec![7u8; 32]),
                counter: 0,
            }),
            remote_ratchet_key: Some(sender_ratchet_key),
            local_ratchet_key_pair: test_key_pair(41),
            previous_counter: 0,
            message_keys: Vec::new(),
        })
        .unwrap();

        let target_decrypted =
            decrypt_signal_provider_session_record_message(&receiver_record, &target).unwrap();
        assert_eq!(
            target_decrypted.plaintext,
            Bytes::from_static(b"direct target")
        );
        let after_target = decode_signal_provider_session_record(&target_decrypted.record).unwrap();
        assert_eq!(
            after_target.message_keys.len(),
            SIGNAL_MAX_PROVIDER_MESSAGE_KEYS
        );
        assert_eq!(after_target.message_keys[0].counter, 2);
        assert_eq!(
            after_target.message_keys.last().unwrap().counter,
            target_counter - 1
        );

        let err = decrypt_signal_provider_session_record_message(&target_decrypted.record, &first)
            .unwrap_err();
        assert!(matches!(
            err,
            CoreError::Protocol(message)
                if message == "duplicate or old Signal message counter: 1"
        ));
        let second_decrypted =
            decrypt_signal_provider_session_record_message(&target_decrypted.record, &second)
                .unwrap();
        assert_eq!(
            second_decrypted.plaintext,
            Bytes::from_static(b"direct second")
        );
        let after_second = decode_signal_provider_session_record(&second_decrypted.record).unwrap();
        assert_eq!(
            after_second.message_keys.len(),
            SIGNAL_MAX_PROVIDER_MESSAGE_KEYS - 1
        );
        assert_eq!(after_second.message_keys[0].counter, 3);
    }

    #[test]
    fn signal_provider_session_record_keeps_previous_chain_skipped_keys_after_ratchet() {
        let sender_credentials = create_initial_credentials().unwrap();
        let sender_material = signal_local_key_material(sender_credentials);
        let sender_base_key = generate_key_pair();
        let receiver_credentials = create_initial_credentials().unwrap();
        let receiver_one_time_pre_key = generate_key_pair();
        let receiver_pre_key = signal_local_pre_key(91, receiver_one_time_pre_key);
        let receiver_session = SignalSession {
            registration_id: receiver_credentials.registration_id,
            identity_key: Bytes::copy_from_slice(&receiver_credentials.signed_identity_key.public),
            signed_pre_key: SignalSignedPreKey {
                key_id: receiver_credentials.signed_pre_key.key_id,
                public_key: Bytes::copy_from_slice(
                    &receiver_credentials.signed_pre_key.key_pair.public,
                ),
                signature: receiver_credentials.signed_pre_key.signature.clone(),
            },
            pre_key: Some(SignalPreKey {
                key_id: receiver_pre_key.key_id,
                public_key: receiver_pre_key.public_key.clone(),
            }),
        };
        let first = encrypt_signal_outbound_pre_key_session_message(
            &sender_material,
            &sender_base_key,
            &receiver_session,
            &XEdDsaNoiseCertificateVerifier,
            b"direct first",
        )
        .unwrap();
        let second =
            encrypt_signal_provider_session_record_message(&first.record, b"direct second")
                .unwrap();
        let receiver_material = signal_local_key_material(receiver_credentials);
        let receiver_after_first = decrypt_signal_inbound_pre_key_session_message(
            &receiver_material,
            Some(&receiver_pre_key),
            &first.message_bytes,
        )
        .unwrap();
        let reply =
            encrypt_signal_provider_session_record_message(&receiver_after_first.record, b"reply")
                .unwrap();
        let sender_after_reply =
            decrypt_signal_provider_session_record_message(&second.record, &reply.message_bytes)
                .unwrap();
        let third =
            encrypt_signal_provider_session_record_message(&sender_after_reply.record, b"third")
                .unwrap();
        assert_eq!(third.message.previous_counter, 2);
        let fourth =
            encrypt_signal_provider_session_record_message(&third.record, b"fourth").unwrap();

        let receiver_after_third =
            decrypt_signal_provider_session_record_message(&reply.record, &third.message_bytes)
                .unwrap();
        assert_eq!(receiver_after_third.plaintext, Bytes::from_static(b"third"));
        let after_third =
            decode_signal_provider_session_record(&receiver_after_third.record).unwrap();
        assert_eq!(after_third.message_keys.len(), 1);
        assert_eq!(after_third.message_keys[0].counter, 2);

        let second_decrypted = decrypt_signal_provider_session_record_message(
            &receiver_after_third.record,
            &second.message_bytes,
        )
        .unwrap();
        assert_eq!(
            second_decrypted.plaintext,
            Bytes::from_static(b"direct second")
        );
        assert!(
            decode_signal_provider_session_record(&second_decrypted.record)
                .unwrap()
                .message_keys
                .is_empty()
        );
        let after_second = decode_signal_provider_session_record(&second_decrypted.record).unwrap();
        assert_eq!(
            after_second.remote_ratchet_key,
            Some(third.message.ephemeral_key)
        );
        assert_eq!(after_second.receiving_chain.as_ref().unwrap().counter, 1);

        let fourth_decrypted = decrypt_signal_provider_session_record_message(
            &second_decrypted.record,
            &fourth.message_bytes,
        )
        .unwrap();
        assert_eq!(fourth_decrypted.plaintext, Bytes::from_static(b"fourth"));
        assert_eq!(
            decode_signal_provider_session_record(&fourth_decrypted.record)
                .unwrap()
                .receiving_chain
                .as_ref()
                .unwrap()
                .counter,
            2
        );
    }

    #[test]
    fn signal_inbound_pre_key_session_rejects_signed_pre_key_id_mismatch() {
        let sender_credentials = create_initial_credentials().unwrap();
        let sender_material = signal_local_key_material(sender_credentials);
        let sender_base_key = generate_key_pair();
        let receiver_credentials = create_initial_credentials().unwrap();
        let receiver_one_time_pre_key = generate_key_pair();
        let receiver_pre_key = signal_local_pre_key(91, receiver_one_time_pre_key);
        let receiver_session = SignalSession {
            registration_id: receiver_credentials.registration_id,
            identity_key: Bytes::copy_from_slice(&receiver_credentials.signed_identity_key.public),
            signed_pre_key: SignalSignedPreKey {
                key_id: receiver_credentials.signed_pre_key.key_id,
                public_key: Bytes::copy_from_slice(
                    &receiver_credentials.signed_pre_key.key_pair.public,
                ),
                signature: receiver_credentials.signed_pre_key.signature.clone(),
            },
            pre_key: Some(SignalPreKey {
                key_id: receiver_pre_key.key_id,
                public_key: receiver_pre_key.public_key.clone(),
            }),
        };
        let first = encrypt_signal_outbound_pre_key_session_message(
            &sender_material,
            &sender_base_key,
            &receiver_session,
            &XEdDsaNoiseCertificateVerifier,
            b"direct first",
        )
        .unwrap();
        let mut mismatched = decode_signal_pre_key_whisper_message(&first.message_bytes).unwrap();
        mismatched.signed_pre_key_id = receiver_credentials.signed_pre_key.key_id.wrapping_add(1);
        let mismatched = encode_signal_pre_key_whisper_message(&mismatched).unwrap();
        let receiver_material = signal_local_key_material(receiver_credentials.clone());
        let expected_error = format!(
            "Signal signed pre-key id mismatch: message {}, local {}",
            receiver_credentials.signed_pre_key.key_id.wrapping_add(1),
            receiver_credentials.signed_pre_key.key_id
        );

        let err = decrypt_signal_inbound_pre_key_session_message(
            &receiver_material,
            Some(&receiver_pre_key),
            &mismatched,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            CoreError::Protocol(message) if message == expected_error
        ));
    }

    #[test]
    fn signal_inbound_pre_key_session_rejects_pre_key_id_mismatch() {
        let sender_credentials = create_initial_credentials().unwrap();
        let sender_material = signal_local_key_material(sender_credentials);
        let sender_base_key = generate_key_pair();
        let receiver_credentials = create_initial_credentials().unwrap();
        let receiver_one_time_pre_key = generate_key_pair();
        let receiver_pre_key = signal_local_pre_key(91, receiver_one_time_pre_key);
        let receiver_session = SignalSession {
            registration_id: receiver_credentials.registration_id,
            identity_key: Bytes::copy_from_slice(&receiver_credentials.signed_identity_key.public),
            signed_pre_key: SignalSignedPreKey {
                key_id: receiver_credentials.signed_pre_key.key_id,
                public_key: Bytes::copy_from_slice(
                    &receiver_credentials.signed_pre_key.key_pair.public,
                ),
                signature: receiver_credentials.signed_pre_key.signature.clone(),
            },
            pre_key: Some(SignalPreKey {
                key_id: receiver_pre_key.key_id,
                public_key: receiver_pre_key.public_key.clone(),
            }),
        };
        let first = encrypt_signal_outbound_pre_key_session_message(
            &sender_material,
            &sender_base_key,
            &receiver_session,
            &XEdDsaNoiseCertificateVerifier,
            b"direct first",
        )
        .unwrap();
        let mut mismatched = decode_signal_pre_key_whisper_message(&first.message_bytes).unwrap();
        mismatched.pre_key_id = Some(receiver_pre_key.key_id.wrapping_add(1));
        let mismatched = encode_signal_pre_key_whisper_message(&mismatched).unwrap();
        let receiver_material = signal_local_key_material(receiver_credentials);
        let expected_error = format!(
            "Signal pre-key id mismatch: message {}, local {}",
            receiver_pre_key.key_id.wrapping_add(1),
            receiver_pre_key.key_id
        );

        let err = decrypt_signal_inbound_pre_key_session_message(
            &receiver_material,
            Some(&receiver_pre_key),
            &mismatched,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            CoreError::Protocol(message) if message == expected_error
        ));
    }

    #[test]
    fn signal_inbound_pre_key_session_rejects_one_time_pre_key_state_mismatch() {
        let sender_credentials = create_initial_credentials().unwrap();
        let sender_material = signal_local_key_material(sender_credentials);
        let sender_base_key = generate_key_pair();
        let receiver_credentials = create_initial_credentials().unwrap();
        let receiver_one_time_pre_key = generate_key_pair();
        let receiver_pre_key = signal_local_pre_key(91, receiver_one_time_pre_key);
        let receiver_session = SignalSession {
            registration_id: receiver_credentials.registration_id,
            identity_key: Bytes::copy_from_slice(&receiver_credentials.signed_identity_key.public),
            signed_pre_key: SignalSignedPreKey {
                key_id: receiver_credentials.signed_pre_key.key_id,
                public_key: Bytes::copy_from_slice(
                    &receiver_credentials.signed_pre_key.key_pair.public,
                ),
                signature: receiver_credentials.signed_pre_key.signature.clone(),
            },
            pre_key: Some(SignalPreKey {
                key_id: receiver_pre_key.key_id,
                public_key: receiver_pre_key.public_key.clone(),
            }),
        };
        let first = encrypt_signal_outbound_pre_key_session_message(
            &sender_material,
            &sender_base_key,
            &receiver_session,
            &XEdDsaNoiseCertificateVerifier,
            b"direct first",
        )
        .unwrap();
        let receiver_material = signal_local_key_material(receiver_credentials);

        let err = decrypt_signal_inbound_pre_key_session_message(
            &receiver_material,
            None,
            &first.message_bytes,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            CoreError::Protocol(message)
                if message == "Signal pre-key message one-time pre-key state mismatch"
        ));
    }

    #[test]
    fn signal_inbound_pre_key_session_rejects_unexpected_one_time_pre_key_state_mismatch() {
        let sender_credentials = create_initial_credentials().unwrap();
        let sender_material = signal_local_key_material(sender_credentials);
        let sender_base_key = generate_key_pair();
        let receiver_credentials = create_initial_credentials().unwrap();
        let unexpected_receiver_pre_key = signal_local_pre_key(91, generate_key_pair());
        let receiver_session = SignalSession {
            registration_id: receiver_credentials.registration_id,
            identity_key: Bytes::copy_from_slice(&receiver_credentials.signed_identity_key.public),
            signed_pre_key: SignalSignedPreKey {
                key_id: receiver_credentials.signed_pre_key.key_id,
                public_key: Bytes::copy_from_slice(
                    &receiver_credentials.signed_pre_key.key_pair.public,
                ),
                signature: receiver_credentials.signed_pre_key.signature.clone(),
            },
            pre_key: None,
        };
        let first = encrypt_signal_outbound_pre_key_session_message(
            &sender_material,
            &sender_base_key,
            &receiver_session,
            &XEdDsaNoiseCertificateVerifier,
            b"direct signed-pre-key only",
        )
        .unwrap();
        assert_eq!(first.message.pre_key_id, None);
        let receiver_material = signal_local_key_material(receiver_credentials);

        let err = decrypt_signal_inbound_pre_key_session_message(
            &receiver_material,
            Some(&unexpected_receiver_pre_key),
            &first.message_bytes,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            CoreError::Protocol(message)
                if message == "Signal pre-key message one-time pre-key state mismatch"
        ));
    }

    #[test]
    fn signal_provider_session_record_rejects_far_future_message_counter() {
        let sender_ratchet_key_pair = test_key_pair(31);
        let sender_record = SignalProviderSessionRecord {
            remote_registration_id: 88,
            remote_identity_key: prefixed_test_signal_key(21),
            root_key: SignalRootKey {
                key: SecretBytes::from(vec![9u8; 32]),
            },
            sending_chain: SignalMessageChainKey {
                key: SecretBytes::from(vec![7u8; 32]),
                counter: 0,
            },
            receiving_chain: None,
            remote_ratchet_key: None,
            local_ratchet_key_pair: sender_ratchet_key_pair.clone(),
            previous_counter: 0,
            message_keys: Vec::new(),
        };
        let first = encrypt_signal_provider_session_record_message(
            &encode_signal_provider_session_record(&sender_record).unwrap(),
            b"direct first",
        )
        .unwrap();
        let receiver_record = encode_signal_provider_session_record(&SignalProviderSessionRecord {
            remote_registration_id: 88,
            remote_identity_key: prefixed_test_signal_key(21),
            root_key: SignalRootKey {
                key: SecretBytes::from(vec![9u8; 32]),
            },
            sending_chain: uninitialized_signal_message_chain(),
            receiving_chain: Some(SignalMessageChainKey {
                key: SecretBytes::from(vec![7u8; 32]),
                counter: 0,
            }),
            remote_ratchet_key: Some(Bytes::copy_from_slice(&prefixed_signal_public_key(
                &sender_ratchet_key_pair.public,
            ))),
            local_ratchet_key_pair: test_key_pair(41),
            previous_counter: 0,
            message_keys: Vec::new(),
        })
        .unwrap();

        let far_future = SignalWhisperMessage {
            ephemeral_key: Bytes::copy_from_slice(&prefixed_signal_public_key(
                &sender_ratchet_key_pair.public,
            )),
            counter: SIGNAL_MAX_MESSAGE_FORWARD_JUMPS + 1,
            previous_counter: 0,
            ciphertext: Bytes::from_static(b"far-future-ciphertext"),
        };
        let err = decrypt_signal_provider_session_record_message(
            &receiver_record,
            &encode_signal_whisper_message(&far_future).unwrap(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            CoreError::Protocol(message)
                if message == "Signal message is too far in the future: 25001"
        ));

        let decrypted =
            decrypt_signal_provider_session_record_message(&receiver_record, &first.message_bytes)
                .unwrap();
        assert_eq!(decrypted.plaintext, Bytes::from_static(b"direct first"));
    }

    #[test]
    fn signal_provider_session_record_rejects_far_future_previous_counter() {
        let sender_ratchet_key_pair = test_key_pair(31);
        let sender_record = SignalProviderSessionRecord {
            remote_registration_id: 88,
            remote_identity_key: prefixed_test_signal_key(21),
            root_key: SignalRootKey {
                key: SecretBytes::from(vec![9u8; 32]),
            },
            sending_chain: SignalMessageChainKey {
                key: SecretBytes::from(vec![7u8; 32]),
                counter: 0,
            },
            receiving_chain: None,
            remote_ratchet_key: None,
            local_ratchet_key_pair: sender_ratchet_key_pair.clone(),
            previous_counter: 0,
            message_keys: Vec::new(),
        };
        let first = encrypt_signal_provider_session_record_message(
            &encode_signal_provider_session_record(&sender_record).unwrap(),
            b"direct first",
        )
        .unwrap();
        let receiver_record = encode_signal_provider_session_record(&SignalProviderSessionRecord {
            remote_registration_id: 88,
            remote_identity_key: prefixed_test_signal_key(21),
            root_key: SignalRootKey {
                key: SecretBytes::from(vec![9u8; 32]),
            },
            sending_chain: uninitialized_signal_message_chain(),
            receiving_chain: Some(SignalMessageChainKey {
                key: SecretBytes::from(vec![7u8; 32]),
                counter: 0,
            }),
            remote_ratchet_key: Some(Bytes::copy_from_slice(&prefixed_signal_public_key(
                &sender_ratchet_key_pair.public,
            ))),
            local_ratchet_key_pair: test_key_pair(41),
            previous_counter: 0,
            message_keys: Vec::new(),
        })
        .unwrap();

        let new_ratchet_key_pair = test_key_pair(51);
        let far_future = SignalWhisperMessage {
            ephemeral_key: Bytes::copy_from_slice(&prefixed_signal_public_key(
                &new_ratchet_key_pair.public,
            )),
            counter: 1,
            previous_counter: SIGNAL_MAX_MESSAGE_FORWARD_JUMPS + 1,
            ciphertext: Bytes::from_static(b"far-future-ciphertext"),
        };
        let err = decrypt_signal_provider_session_record_message(
            &receiver_record,
            &encode_signal_whisper_message(&far_future).unwrap(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            CoreError::Protocol(message)
                if message == "Signal previous chain is too far in the future: 25001"
        ));

        let decrypted =
            decrypt_signal_provider_session_record_message(&receiver_record, &first.message_bytes)
                .unwrap();
        assert_eq!(decrypted.plaintext, Bytes::from_static(b"direct first"));
    }

    #[test]
    fn signal_provider_session_record_rejects_stale_previous_counter() {
        let sender_ratchet_key_pair = test_key_pair(31);
        let sender_ratchet_key =
            Bytes::copy_from_slice(&prefixed_signal_public_key(&sender_ratchet_key_pair.public));
        let initial_chain = SignalMessageChainKey {
            key: SecretBytes::from(vec![7u8; 32]),
            counter: 0,
        };
        let first_step = ratchet_signal_message_chain(&initial_chain).unwrap();
        let second_step = ratchet_signal_message_chain(&first_step.next_chain_key).unwrap();
        let third_step = ratchet_signal_message_chain(&second_step.next_chain_key).unwrap();
        let receiver_record = encode_signal_provider_session_record(&SignalProviderSessionRecord {
            remote_registration_id: 88,
            remote_identity_key: prefixed_test_signal_key(21),
            root_key: SignalRootKey {
                key: SecretBytes::from(vec![9u8; 32]),
            },
            sending_chain: uninitialized_signal_message_chain(),
            receiving_chain: Some(second_step.next_chain_key.clone()),
            remote_ratchet_key: Some(sender_ratchet_key.clone()),
            local_ratchet_key_pair: test_key_pair(41),
            previous_counter: 0,
            message_keys: Vec::new(),
        })
        .unwrap();

        let new_ratchet_key_pair = test_key_pair(51);
        let stale_previous_counter = SignalWhisperMessage {
            ephemeral_key: Bytes::copy_from_slice(&prefixed_signal_public_key(
                &new_ratchet_key_pair.public,
            )),
            counter: 1,
            previous_counter: 1,
            ciphertext: Bytes::from_static(b"stale-previous-counter"),
        };
        let err = decrypt_signal_provider_session_record_message(
            &receiver_record,
            &encode_signal_whisper_message(&stale_previous_counter).unwrap(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            CoreError::Protocol(message)
                if message == "Signal previous chain counter moved backwards: message 1, current 2"
        ));

        let third = encode_signal_whisper_message(&SignalWhisperMessage {
            ephemeral_key: sender_ratchet_key,
            counter: 3,
            previous_counter: 0,
            ciphertext: encrypt_signal_message_body(b"direct third", &third_step.message_keys)
                .unwrap(),
        })
        .unwrap();
        let decrypted =
            decrypt_signal_provider_session_record_message(&receiver_record, &third).unwrap();
        assert_eq!(decrypted.plaintext, Bytes::from_static(b"direct third"));
    }

    #[tokio::test]
    async fn store_signal_provider_encrypts_direct_pre_key_then_session_messages() {
        let store = temp_store().await;
        let local_credentials = create_initial_credentials().unwrap();
        save_credentials(&store, local_credentials.clone())
            .await
            .unwrap();
        let remote_credentials = create_initial_credentials().unwrap();
        let remote_one_time_pre_key = generate_key_pair();
        let remote_jid = "123:7@s.whatsapp.net";
        let remote_session = SignalSession {
            registration_id: remote_credentials.registration_id,
            identity_key: Bytes::copy_from_slice(&remote_credentials.signed_identity_key.public),
            signed_pre_key: SignalSignedPreKey {
                key_id: remote_credentials.signed_pre_key.key_id,
                public_key: Bytes::copy_from_slice(
                    &remote_credentials.signed_pre_key.key_pair.public,
                ),
                signature: remote_credentials.signed_pre_key.signature.clone(),
            },
            pre_key: Some(SignalPreKey {
                key_id: 91,
                public_key: Bytes::copy_from_slice(&remote_one_time_pre_key.public),
            }),
        };
        let repository = StoreSignalRepository::new(store.clone());
        repository
            .inject_e2e_session(SessionInjection {
                jid: remote_jid.to_owned(),
                session: remote_session.clone(),
            })
            .await
            .unwrap();
        let provider = StoreSignalSenderKeyProvider::new(store.clone());
        let codec = SignalMessageCodec::new(repository, provider.clone());

        let first = codec
            .encrypt_message(remote_jid, Bytes::from_static(b"direct first"))
            .await
            .unwrap();
        assert_eq!(first.ciphertext_type, MessageCiphertextType::PreKey);
        let first_message = decode_signal_pre_key_whisper_message(&first.ciphertext).unwrap();
        assert_eq!(
            first_message.registration_id,
            local_credentials.registration_id
        );
        assert_eq!(first_message.pre_key_id, Some(91));
        assert_eq!(
            first_message.signed_pre_key_id,
            remote_credentials.signed_pre_key.key_id
        );
        assert_eq!(first_message.identity_key[0], SIGNAL_PUBLIC_KEY_VERSION);
        assert_eq!(
            &first_message.identity_key[1..],
            &local_credentials.signed_identity_key.public
        );
        assert_eq!(first_message.message.counter, 1);

        let first_record = provider
            .state_store()
            .load_session_record(remote_jid)
            .await
            .unwrap()
            .unwrap();
        let first_record = decode_signal_provider_session_record(&first_record).unwrap();
        assert_eq!(
            first_record.remote_registration_id,
            remote_credentials.registration_id
        );
        assert_eq!(
            first_record.remote_identity_key,
            normalize_signal_public_key(&remote_credentials.signed_identity_key.public).unwrap()
        );
        assert_eq!(first_record.sending_chain.counter, 1);
        assert_eq!(
            provider
                .state_store()
                .load_identity_record(remote_jid)
                .await
                .unwrap(),
            Some(
                normalize_signal_public_key(&remote_credentials.signed_identity_key.public)
                    .unwrap()
            )
        );

        let local_material = signal_local_key_material(local_credentials);
        let initial = derive_signal_outbound_pre_key_root_chain_keys(
            &local_material,
            &first_record.local_ratchet_key_pair,
            &remote_session,
        )
        .unwrap();
        let first_keys = ratchet_signal_message_chain(&initial.chain_key).unwrap();
        assert_eq!(
            decrypt_signal_message_body(
                &first_message.message.ciphertext,
                &first_keys.message_keys
            )
            .unwrap(),
            Bytes::from_static(b"direct first")
        );

        let second = codec
            .encrypt_message(remote_jid, Bytes::from_static(b"direct second"))
            .await
            .unwrap();
        assert_eq!(second.ciphertext_type, MessageCiphertextType::Message);
        let second_message = decode_signal_whisper_message(&second.ciphertext).unwrap();
        assert_eq!(second_message.counter, 2);
        assert_eq!(second_message.previous_counter, 0);
        assert_eq!(
            second_message.ephemeral_key,
            Bytes::copy_from_slice(&prefixed_signal_public_key(
                &first_record.local_ratchet_key_pair.public
            ))
        );
        let second_keys = ratchet_signal_message_chain(&first_record.sending_chain).unwrap();
        assert_eq!(
            decrypt_signal_message_body(&second_message.ciphertext, &second_keys.message_keys)
                .unwrap(),
            Bytes::from_static(b"direct second")
        );
        let second_record = provider
            .state_store()
            .load_session_record(remote_jid)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            decode_signal_provider_session_record(&second_record)
                .unwrap()
                .sending_chain
                .counter,
            2
        );
    }

    #[tokio::test]
    async fn store_signal_provider_rejects_outbound_pre_key_identity_change() {
        let store = temp_store().await;
        let local_credentials = create_initial_credentials().unwrap();
        save_credentials(&store, local_credentials).await.unwrap();
        let remote_credentials = create_initial_credentials().unwrap();
        let remote_jid = "123:7@s.whatsapp.net";
        let existing_identity = prefixed_test_signal_key(77);
        let remote_session = SignalSession {
            registration_id: remote_credentials.registration_id,
            identity_key: Bytes::copy_from_slice(&remote_credentials.signed_identity_key.public),
            signed_pre_key: SignalSignedPreKey {
                key_id: remote_credentials.signed_pre_key.key_id,
                public_key: Bytes::copy_from_slice(
                    &remote_credentials.signed_pre_key.key_pair.public,
                ),
                signature: remote_credentials.signed_pre_key.signature.clone(),
            },
            pre_key: None,
        };
        assert_ne!(
            normalize_signal_public_key(&remote_session.identity_key).unwrap(),
            existing_identity
        );

        let repository = StoreSignalRepository::new(store.clone());
        repository
            .inject_e2e_session(SessionInjection {
                jid: remote_jid.to_owned(),
                session: remote_session,
            })
            .await
            .unwrap();
        let provider = StoreSignalSenderKeyProvider::new(store);
        provider
            .state_store()
            .store_identity_record(remote_jid, &existing_identity)
            .await
            .unwrap();
        let codec = SignalMessageCodec::new(repository, provider.clone());

        let err = codec
            .encrypt_message(remote_jid, Bytes::from_static(b"direct identity change"))
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            CoreError::Protocol(message) if message == "Signal provider identity changed for 123.7"
        ));
        assert!(
            provider
                .state_store()
                .load_session_record(remote_jid)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            provider
                .state_store()
                .load_identity_record(remote_jid)
                .await
                .unwrap(),
            Some(existing_identity)
        );
    }

    #[tokio::test]
    async fn store_signal_provider_uses_pre_key_when_existing_provider_session_is_unusable() {
        let store = temp_store().await;
        let local_credentials = create_initial_credentials().unwrap();
        save_credentials(&store, local_credentials).await.unwrap();
        let remote_credentials = create_initial_credentials().unwrap();
        let remote_identity =
            normalize_signal_public_key(&remote_credentials.signed_identity_key.public).unwrap();
        let remote_session = SignalSession {
            registration_id: remote_credentials.registration_id,
            identity_key: Bytes::copy_from_slice(&remote_credentials.signed_identity_key.public),
            signed_pre_key: SignalSignedPreKey {
                key_id: remote_credentials.signed_pre_key.key_id,
                public_key: Bytes::copy_from_slice(
                    &remote_credentials.signed_pre_key.key_pair.public,
                ),
                signature: remote_credentials.signed_pre_key.signature.clone(),
            },
            pre_key: None,
        };
        let repository = StoreSignalRepository::new(store.clone());
        for jid in ["123:7@s.whatsapp.net", "456:8@s.whatsapp.net"] {
            repository
                .inject_e2e_session(SessionInjection {
                    jid: jid.to_owned(),
                    session: remote_session.clone(),
                })
                .await
                .unwrap();
        }

        let provider = StoreSignalSenderKeyProvider::new(store);
        provider
            .state_store()
            .store_session_record("123:7@s.whatsapp.net", b"opaque-provider-session")
            .await
            .unwrap();
        let stale_record = SignalProviderSessionRecord {
            remote_registration_id: 99,
            remote_identity_key: prefixed_test_signal_key(77),
            root_key: SignalRootKey {
                key: SecretBytes::from(vec![9u8; 32]),
            },
            sending_chain: SignalMessageChainKey {
                key: SecretBytes::from(vec![7u8; 32]),
                counter: 0,
            },
            receiving_chain: None,
            remote_ratchet_key: None,
            local_ratchet_key_pair: test_key_pair(31),
            previous_counter: 0,
            message_keys: Vec::new(),
        };
        provider
            .state_store()
            .store_session_record(
                "456:8@s.whatsapp.net",
                &encode_signal_provider_session_record(&stale_record).unwrap(),
            )
            .await
            .unwrap();

        let codec = SignalMessageCodec::new(repository, provider.clone());
        for jid in ["123:7@s.whatsapp.net", "456:8@s.whatsapp.net"] {
            let encrypted = codec
                .encrypt_message(jid, Bytes::from_static(b"direct fallback pre-key"))
                .await
                .unwrap();
            assert_eq!(encrypted.ciphertext_type, MessageCiphertextType::PreKey);
            let message = decode_signal_pre_key_whisper_message(&encrypted.ciphertext).unwrap();
            assert_eq!(
                message.signed_pre_key_id,
                remote_credentials.signed_pre_key.key_id
            );

            let stored = provider
                .state_store()
                .load_session_record(jid)
                .await
                .unwrap()
                .unwrap();
            let stored = decode_signal_provider_session_record(&stored).unwrap();
            assert_eq!(
                stored.remote_registration_id,
                remote_credentials.registration_id
            );
            assert_eq!(stored.remote_identity_key, remote_identity);
            assert_eq!(
                provider
                    .state_store()
                    .load_identity_record(jid)
                    .await
                    .unwrap(),
                Some(remote_identity.clone())
            );
        }
    }

    #[tokio::test]
    async fn store_signal_provider_encrypts_direct_pre_key_without_one_time_pre_key() {
        let store = temp_store().await;
        let local_credentials = create_initial_credentials().unwrap();
        save_credentials(&store, local_credentials.clone())
            .await
            .unwrap();
        let remote_credentials = create_initial_credentials().unwrap();
        let remote_jid = "123:7@s.whatsapp.net";
        let remote_session = SignalSession {
            registration_id: remote_credentials.registration_id,
            identity_key: Bytes::copy_from_slice(&remote_credentials.signed_identity_key.public),
            signed_pre_key: SignalSignedPreKey {
                key_id: remote_credentials.signed_pre_key.key_id,
                public_key: Bytes::copy_from_slice(
                    &remote_credentials.signed_pre_key.key_pair.public,
                ),
                signature: remote_credentials.signed_pre_key.signature.clone(),
            },
            pre_key: None,
        };
        let repository = StoreSignalRepository::new(store.clone());
        repository
            .inject_e2e_session(SessionInjection {
                jid: remote_jid.to_owned(),
                session: remote_session.clone(),
            })
            .await
            .unwrap();
        let provider = StoreSignalSenderKeyProvider::new(store.clone());
        let codec = SignalMessageCodec::new(repository, provider.clone());

        let first = codec
            .encrypt_message(
                remote_jid,
                Bytes::from_static(b"direct signed-pre-key only"),
            )
            .await
            .unwrap();
        assert_eq!(first.ciphertext_type, MessageCiphertextType::PreKey);
        let first_message = decode_signal_pre_key_whisper_message(&first.ciphertext).unwrap();
        assert_eq!(
            first_message.registration_id,
            local_credentials.registration_id
        );
        assert_eq!(first_message.pre_key_id, None);
        assert_eq!(
            first_message.signed_pre_key_id,
            remote_credentials.signed_pre_key.key_id
        );
        assert_eq!(first_message.identity_key[0], SIGNAL_PUBLIC_KEY_VERSION);
        assert_eq!(
            &first_message.identity_key[1..],
            &local_credentials.signed_identity_key.public
        );
        assert_eq!(first_message.message.counter, 1);

        let first_record = provider
            .state_store()
            .load_session_record(remote_jid)
            .await
            .unwrap()
            .unwrap();
        let first_record = decode_signal_provider_session_record(&first_record).unwrap();
        assert_eq!(
            first_record.remote_registration_id,
            remote_credentials.registration_id
        );
        assert_eq!(
            first_record.remote_identity_key,
            normalize_signal_public_key(&remote_credentials.signed_identity_key.public).unwrap()
        );
        assert_eq!(first_record.sending_chain.counter, 1);
        assert_eq!(first_record.previous_counter, 0);
        assert_eq!(first_record.receiving_chain, None);
        assert_eq!(first_record.remote_ratchet_key, None);
        assert_eq!(
            provider
                .state_store()
                .load_identity_record(remote_jid)
                .await
                .unwrap(),
            Some(
                normalize_signal_public_key(&remote_credentials.signed_identity_key.public)
                    .unwrap()
            )
        );

        let local_material = signal_local_key_material(local_credentials);
        let initial = derive_signal_outbound_pre_key_root_chain_keys(
            &local_material,
            &first_record.local_ratchet_key_pair,
            &remote_session,
        )
        .unwrap();
        assert!(!initial.used_one_time_pre_key);
        let first_keys = ratchet_signal_message_chain(&initial.chain_key).unwrap();
        assert_eq!(
            decrypt_signal_message_body(
                &first_message.message.ciphertext,
                &first_keys.message_keys
            )
            .unwrap(),
            Bytes::from_static(b"direct signed-pre-key only")
        );

        let second = codec
            .encrypt_message(remote_jid, Bytes::from_static(b"direct second"))
            .await
            .unwrap();
        assert_eq!(second.ciphertext_type, MessageCiphertextType::Message);
        let second_message = decode_signal_whisper_message(&second.ciphertext).unwrap();
        assert_eq!(second_message.counter, 2);
        assert_eq!(second_message.previous_counter, 0);
        assert_eq!(
            second_message.ephemeral_key,
            Bytes::copy_from_slice(&prefixed_signal_public_key(
                &first_record.local_ratchet_key_pair.public
            ))
        );
        let second_keys = ratchet_signal_message_chain(&first_record.sending_chain).unwrap();
        assert_eq!(
            decrypt_signal_message_body(&second_message.ciphertext, &second_keys.message_keys)
                .unwrap(),
            Bytes::from_static(b"direct second")
        );
        let second_record = provider
            .state_store()
            .load_session_record(remote_jid)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            decode_signal_provider_session_record(&second_record)
                .unwrap()
                .sending_chain
                .counter,
            2
        );
    }

    #[tokio::test]
    async fn store_signal_provider_decrypts_inbound_pre_key_then_session_messages() {
        let receiver_store = temp_store().await;
        let receiver_credentials = create_initial_credentials().unwrap();
        save_credentials(&receiver_store, receiver_credentials.clone())
            .await
            .unwrap();
        let upload = prepare_pre_key_upload(&receiver_store, &receiver_credentials, 1, "pre-key")
            .await
            .unwrap();
        let receiver_credentials = upload.credentials;
        save_credentials(&receiver_store, receiver_credentials.clone())
            .await
            .unwrap();
        let receiver_pre_key_id = upload.pre_key_ids[0];
        let receiver_provider_probe = SignalProviderStateStore::new(receiver_store.clone());
        let receiver_pre_key = receiver_provider_probe
            .load_local_pre_key(receiver_pre_key_id)
            .await
            .unwrap()
            .unwrap();

        let sender_credentials = create_initial_credentials().unwrap();
        let sender_material = signal_local_key_material(sender_credentials.clone());
        let sender_base_key = generate_key_pair();
        let receiver_session = SignalSession {
            registration_id: receiver_credentials.registration_id,
            identity_key: Bytes::copy_from_slice(&receiver_credentials.signed_identity_key.public),
            signed_pre_key: SignalSignedPreKey {
                key_id: receiver_credentials.signed_pre_key.key_id,
                public_key: Bytes::copy_from_slice(
                    &receiver_credentials.signed_pre_key.key_pair.public,
                ),
                signature: receiver_credentials.signed_pre_key.signature.clone(),
            },
            pre_key: Some(SignalPreKey {
                key_id: receiver_pre_key_id,
                public_key: receiver_pre_key.public_key.clone(),
            }),
        };
        let first = encrypt_signal_outbound_pre_key_session_message(
            &sender_material,
            &sender_base_key,
            &receiver_session,
            &XEdDsaNoiseCertificateVerifier,
            b"inbound first",
        )
        .unwrap();
        let first_message_bytes = pre_key_message_outer_unknown_field(&first.message_bytes);
        let sender_jid = "123:7@s.whatsapp.net";
        let provider = StoreSignalSenderKeyProvider::new(receiver_store.clone());
        let codec = SignalMessageCodec::new(
            StoreSignalRepository::new(receiver_store.clone()),
            provider.clone(),
        );

        let plaintext = codec
            .decrypt_inbound_message(InboundEncryptedPayload {
                sender_jid: sender_jid.to_owned(),
                chat_jid: "123@s.whatsapp.net".to_owned(),
                ciphertext_type: InboundCiphertextType::PreKey,
                ciphertext: first_message_bytes.clone(),
            })
            .await
            .unwrap();

        assert_eq!(plaintext, Bytes::from_static(b"inbound first"));
        assert!(
            provider
                .state_store()
                .load_local_pre_key(receiver_pre_key_id)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            provider
                .state_store()
                .load_identity_record(sender_jid)
                .await
                .unwrap(),
            Some(sender_material.identity.public_key.clone())
        );
        let receiver_record_bytes = provider
            .state_store()
            .load_session_record(sender_jid)
            .await
            .unwrap()
            .unwrap();
        let receiver_record =
            decode_signal_provider_session_record(&receiver_record_bytes).unwrap();
        assert_eq!(
            receiver_record.remote_identity_key,
            sender_material.identity.public_key
        );
        assert_eq!(
            receiver_record.remote_ratchet_key,
            Some(Bytes::copy_from_slice(&prefixed_signal_public_key(
                &sender_base_key.public
            )))
        );
        assert_eq!(receiver_record.receiving_chain.as_ref().unwrap().counter, 1);
        assert!(is_uninitialized_signal_message_chain(
            &receiver_record.sending_chain
        ));
        receiver_store
            .delete_signal_key(KeyNamespace::Credentials, "schema-version")
            .await
            .unwrap();
        let replay_without_material_err = codec
            .decrypt_inbound_message(InboundEncryptedPayload {
                sender_jid: sender_jid.to_owned(),
                chat_jid: "123@s.whatsapp.net".to_owned(),
                ciphertext_type: InboundCiphertextType::PreKey,
                ciphertext: first_message_bytes.clone(),
            })
            .await
            .unwrap_err();
        assert!(matches!(
            replay_without_material_err,
            CoreError::Protocol(message)
                if message == "duplicate or old Signal message counter: 1"
        ));
        assert_eq!(
            provider
                .state_store()
                .load_session_record(sender_jid)
                .await
                .unwrap()
                .unwrap(),
            receiver_record_bytes
        );
        save_credentials(&receiver_store, receiver_credentials.clone())
            .await
            .unwrap();
        receiver_store
            .delete_signal_key(KeyNamespace::SignalProviderIdentity, "123.7")
            .await
            .unwrap();
        let replay_without_identity_err = codec
            .decrypt_inbound_message(InboundEncryptedPayload {
                sender_jid: sender_jid.to_owned(),
                chat_jid: "123@s.whatsapp.net".to_owned(),
                ciphertext_type: InboundCiphertextType::PreKey,
                ciphertext: first_message_bytes.clone(),
            })
            .await
            .unwrap_err();
        assert!(matches!(
            replay_without_identity_err,
            CoreError::Protocol(message) if message == "no provider identity"
        ));
        assert_eq!(
            provider
                .state_store()
                .load_session_record(sender_jid)
                .await
                .unwrap()
                .unwrap(),
            receiver_record_bytes
        );
        provider
            .state_store()
            .store_identity_record(sender_jid, &sender_material.identity.public_key)
            .await
            .unwrap();
        let replay_err = codec
            .decrypt_inbound_message(InboundEncryptedPayload {
                sender_jid: sender_jid.to_owned(),
                chat_jid: "123@s.whatsapp.net".to_owned(),
                ciphertext_type: InboundCiphertextType::PreKey,
                ciphertext: first_message_bytes.clone(),
            })
            .await
            .unwrap_err();
        assert!(matches!(
            replay_err,
            CoreError::Protocol(message)
                if message == "duplicate or old Signal message counter: 1"
        ));
        assert_eq!(
            provider
                .state_store()
                .load_session_record(sender_jid)
                .await
                .unwrap()
                .unwrap(),
            receiver_record_bytes
        );

        let second =
            encrypt_signal_provider_session_record_message(&first.record, b"inbound second")
                .unwrap();
        let plaintext = codec
            .decrypt_inbound_message(InboundEncryptedPayload {
                sender_jid: sender_jid.to_owned(),
                chat_jid: "123@s.whatsapp.net".to_owned(),
                ciphertext_type: InboundCiphertextType::Message,
                ciphertext: second.message_bytes,
            })
            .await
            .unwrap();
        assert_eq!(plaintext, Bytes::from_static(b"inbound second"));
        let receiver_record = provider
            .state_store()
            .load_session_record(sender_jid)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            decode_signal_provider_session_record(&receiver_record)
                .unwrap()
                .receiving_chain
                .as_ref()
                .unwrap()
                .counter,
            2
        );

        let reply = codec
            .encrypt_message(sender_jid, Bytes::from_static(b"receiver reply"))
            .await
            .unwrap();
        assert_eq!(reply.ciphertext_type, MessageCiphertextType::Message);
        let reply_message = decode_signal_whisper_message(&reply.ciphertext).unwrap();
        assert_eq!(reply_message.counter, 1);
        assert_eq!(reply_message.previous_counter, 0);
        assert_ne!(
            reply_message.ephemeral_key,
            Bytes::copy_from_slice(&prefixed_signal_public_key(&sender_base_key.public))
        );
        let decrypted_reply =
            decrypt_signal_provider_session_record_message(&first.record, &reply.ciphertext)
                .unwrap();
        assert_eq!(
            decrypted_reply.plaintext,
            Bytes::from_static(b"receiver reply")
        );
        let receiver_record = provider
            .state_store()
            .load_session_record(sender_jid)
            .await
            .unwrap()
            .unwrap();
        let receiver_record = decode_signal_provider_session_record(&receiver_record).unwrap();
        assert_eq!(receiver_record.sending_chain.counter, 1);
        assert_eq!(
            receiver_record.remote_ratchet_key,
            Some(Bytes::copy_from_slice(&prefixed_signal_public_key(
                &sender_base_key.public
            )))
        );
    }

    #[tokio::test]
    async fn store_signal_provider_rejects_inbound_pre_key_when_one_time_pre_key_missing() {
        let receiver_store = temp_store().await;
        let receiver_credentials = create_initial_credentials().unwrap();
        save_credentials(&receiver_store, receiver_credentials.clone())
            .await
            .unwrap();
        let upload = prepare_pre_key_upload(&receiver_store, &receiver_credentials, 1, "pre-key")
            .await
            .unwrap();
        let receiver_credentials = upload.credentials;
        save_credentials(&receiver_store, receiver_credentials.clone())
            .await
            .unwrap();
        let receiver_pre_key_id = upload.pre_key_ids[0];
        let provider_probe = SignalProviderStateStore::new(receiver_store.clone());
        let receiver_pre_key = provider_probe
            .load_local_pre_key(receiver_pre_key_id)
            .await
            .unwrap()
            .unwrap();

        let sender_credentials = create_initial_credentials().unwrap();
        let sender_material = signal_local_key_material(sender_credentials);
        let sender_base_key = generate_key_pair();
        let receiver_session = SignalSession {
            registration_id: receiver_credentials.registration_id,
            identity_key: Bytes::copy_from_slice(&receiver_credentials.signed_identity_key.public),
            signed_pre_key: SignalSignedPreKey {
                key_id: receiver_credentials.signed_pre_key.key_id,
                public_key: Bytes::copy_from_slice(
                    &receiver_credentials.signed_pre_key.key_pair.public,
                ),
                signature: receiver_credentials.signed_pre_key.signature.clone(),
            },
            pre_key: Some(SignalPreKey {
                key_id: receiver_pre_key_id,
                public_key: receiver_pre_key.public_key.clone(),
            }),
        };
        let first = encrypt_signal_outbound_pre_key_session_message(
            &sender_material,
            &sender_base_key,
            &receiver_session,
            &XEdDsaNoiseCertificateVerifier,
            b"inbound first",
        )
        .unwrap();
        assert_eq!(first.message.pre_key_id, Some(receiver_pre_key_id));

        assert_eq!(
            provider_probe
                .consume_local_pre_key(receiver_pre_key_id)
                .await
                .unwrap(),
            Some(receiver_pre_key)
        );
        let sender_jid = "123:7@s.whatsapp.net";
        let codec = SignalMessageCodec::new(
            StoreSignalRepository::new(receiver_store.clone()),
            StoreSignalSenderKeyProvider::new(receiver_store),
        );
        let err = codec
            .decrypt_inbound_message(InboundEncryptedPayload {
                sender_jid: sender_jid.to_owned(),
                chat_jid: "123@s.whatsapp.net".to_owned(),
                ciphertext_type: InboundCiphertextType::PreKey,
                ciphertext: first.message_bytes,
            })
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            CoreError::Protocol(message)
                if message == format!("missing local Signal one-time pre-key {receiver_pre_key_id}")
        ));
        assert!(
            provider_probe
                .load_session_record(sender_jid)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            provider_probe
                .load_identity_record(sender_jid)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn store_signal_provider_preserves_pre_key_when_local_key_material_missing() {
        let receiver_store = temp_store().await;
        let receiver_credentials = create_initial_credentials().unwrap();
        save_credentials(&receiver_store, receiver_credentials.clone())
            .await
            .unwrap();
        let upload = prepare_pre_key_upload(&receiver_store, &receiver_credentials, 1, "pre-key")
            .await
            .unwrap();
        let receiver_credentials = upload.credentials;
        save_credentials(&receiver_store, receiver_credentials.clone())
            .await
            .unwrap();
        let receiver_pre_key_id = upload.pre_key_ids[0];
        let provider_probe = SignalProviderStateStore::new(receiver_store.clone());
        let receiver_pre_key = provider_probe
            .load_local_pre_key(receiver_pre_key_id)
            .await
            .unwrap()
            .unwrap();

        let sender_credentials = create_initial_credentials().unwrap();
        let sender_material = signal_local_key_material(sender_credentials);
        let sender_base_key = generate_key_pair();
        let receiver_session = SignalSession {
            registration_id: receiver_credentials.registration_id,
            identity_key: Bytes::copy_from_slice(&receiver_credentials.signed_identity_key.public),
            signed_pre_key: SignalSignedPreKey {
                key_id: receiver_credentials.signed_pre_key.key_id,
                public_key: Bytes::copy_from_slice(
                    &receiver_credentials.signed_pre_key.key_pair.public,
                ),
                signature: receiver_credentials.signed_pre_key.signature.clone(),
            },
            pre_key: Some(SignalPreKey {
                key_id: receiver_pre_key_id,
                public_key: receiver_pre_key.public_key.clone(),
            }),
        };
        let first = encrypt_signal_outbound_pre_key_session_message(
            &sender_material,
            &sender_base_key,
            &receiver_session,
            &XEdDsaNoiseCertificateVerifier,
            b"inbound first without local material",
        )
        .unwrap();
        assert_eq!(first.message.pre_key_id, Some(receiver_pre_key_id));

        receiver_store
            .delete_signal_key(KeyNamespace::Credentials, "schema-version")
            .await
            .unwrap();
        let sender_jid = "123:7@s.whatsapp.net";
        let codec = SignalMessageCodec::new(
            StoreSignalRepository::new(receiver_store.clone()),
            StoreSignalSenderKeyProvider::new(receiver_store),
        );
        let err = codec
            .decrypt_inbound_message(InboundEncryptedPayload {
                sender_jid: sender_jid.to_owned(),
                chat_jid: "123@s.whatsapp.net".to_owned(),
                ciphertext_type: InboundCiphertextType::PreKey,
                ciphertext: first.message_bytes,
            })
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            CoreError::Protocol(message)
                if message == "missing local Signal key material for pre-key decrypt"
        ));
        assert_eq!(
            provider_probe
                .load_local_pre_key(receiver_pre_key_id)
                .await
                .unwrap(),
            Some(receiver_pre_key)
        );
        assert!(
            provider_probe
                .load_session_record(sender_jid)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            provider_probe
                .load_identity_record(sender_jid)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn store_signal_provider_preserves_pre_keys_after_wrong_pre_key_material() {
        let receiver_store = temp_store().await;
        let receiver_credentials = create_initial_credentials().unwrap();
        save_credentials(&receiver_store, receiver_credentials.clone())
            .await
            .unwrap();
        let upload = prepare_pre_key_upload(&receiver_store, &receiver_credentials, 2, "pre-key")
            .await
            .unwrap();
        let receiver_credentials = upload.credentials;
        save_credentials(&receiver_store, receiver_credentials.clone())
            .await
            .unwrap();
        let receiver_pre_key_id = upload.pre_key_ids[0];
        let wrong_pre_key_id = upload.pre_key_ids[1];
        let provider_probe = SignalProviderStateStore::new(receiver_store.clone());
        let receiver_pre_key = provider_probe
            .load_local_pre_key(receiver_pre_key_id)
            .await
            .unwrap()
            .unwrap();
        let wrong_pre_key = provider_probe
            .load_local_pre_key(wrong_pre_key_id)
            .await
            .unwrap()
            .unwrap();

        let sender_credentials = create_initial_credentials().unwrap();
        let sender_material = signal_local_key_material(sender_credentials);
        let sender_base_key = generate_key_pair();
        let receiver_session = SignalSession {
            registration_id: receiver_credentials.registration_id,
            identity_key: Bytes::copy_from_slice(&receiver_credentials.signed_identity_key.public),
            signed_pre_key: SignalSignedPreKey {
                key_id: receiver_credentials.signed_pre_key.key_id,
                public_key: Bytes::copy_from_slice(
                    &receiver_credentials.signed_pre_key.key_pair.public,
                ),
                signature: receiver_credentials.signed_pre_key.signature.clone(),
            },
            pre_key: Some(SignalPreKey {
                key_id: receiver_pre_key_id,
                public_key: receiver_pre_key.public_key.clone(),
            }),
        };
        let first = encrypt_signal_outbound_pre_key_session_message(
            &sender_material,
            &sender_base_key,
            &receiver_session,
            &XEdDsaNoiseCertificateVerifier,
            b"inbound first with wrong pre-key material",
        )
        .unwrap();
        assert_eq!(first.message.pre_key_id, Some(receiver_pre_key_id));
        let mut wrong_pre_key_message =
            decode_signal_pre_key_whisper_message(&first.message_bytes).unwrap();
        wrong_pre_key_message.pre_key_id = Some(wrong_pre_key_id);
        let wrong_pre_key_message =
            encode_signal_pre_key_whisper_message(&wrong_pre_key_message).unwrap();

        let sender_jid = "123:7@s.whatsapp.net";
        let codec = SignalMessageCodec::new(
            StoreSignalRepository::new(receiver_store.clone()),
            StoreSignalSenderKeyProvider::new(receiver_store),
        );
        let err = codec
            .decrypt_inbound_message(InboundEncryptedPayload {
                sender_jid: sender_jid.to_owned(),
                chat_jid: "123@s.whatsapp.net".to_owned(),
                ciphertext_type: InboundCiphertextType::PreKey,
                ciphertext: wrong_pre_key_message,
            })
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            CoreError::Crypto(wa_crypto::CryptoError::Decrypt)
        ));
        assert_eq!(
            provider_probe
                .load_local_pre_key(receiver_pre_key_id)
                .await
                .unwrap(),
            Some(receiver_pre_key)
        );
        assert_eq!(
            provider_probe
                .load_local_pre_key(wrong_pre_key_id)
                .await
                .unwrap(),
            Some(wrong_pre_key)
        );
        assert!(
            provider_probe
                .load_session_record(sender_jid)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            provider_probe
                .load_identity_record(sender_jid)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn store_signal_provider_preserves_pre_key_after_inbound_identity_change() {
        let receiver_store = temp_store().await;
        let receiver_credentials = create_initial_credentials().unwrap();
        save_credentials(&receiver_store, receiver_credentials.clone())
            .await
            .unwrap();
        let upload = prepare_pre_key_upload(&receiver_store, &receiver_credentials, 1, "pre-key")
            .await
            .unwrap();
        let receiver_credentials = upload.credentials;
        save_credentials(&receiver_store, receiver_credentials.clone())
            .await
            .unwrap();
        let receiver_pre_key_id = upload.pre_key_ids[0];
        let provider_probe = SignalProviderStateStore::new(receiver_store.clone());
        let receiver_pre_key = provider_probe
            .load_local_pre_key(receiver_pre_key_id)
            .await
            .unwrap()
            .unwrap();

        let sender_jid = "123:7@s.whatsapp.net";
        let existing_identity = prefixed_test_signal_key(77);
        let existing_session = Bytes::from_static(b"opaque-provider-session");
        provider_probe
            .store_session_record(sender_jid, &existing_session)
            .await
            .unwrap();
        provider_probe
            .store_identity_record(sender_jid, &existing_identity)
            .await
            .unwrap();

        let sender_credentials = create_initial_credentials().unwrap();
        let sender_material = signal_local_key_material(sender_credentials);
        assert_ne!(sender_material.identity.public_key, existing_identity);
        let sender_base_key = generate_key_pair();
        let receiver_session = SignalSession {
            registration_id: receiver_credentials.registration_id,
            identity_key: Bytes::copy_from_slice(&receiver_credentials.signed_identity_key.public),
            signed_pre_key: SignalSignedPreKey {
                key_id: receiver_credentials.signed_pre_key.key_id,
                public_key: Bytes::copy_from_slice(
                    &receiver_credentials.signed_pre_key.key_pair.public,
                ),
                signature: receiver_credentials.signed_pre_key.signature.clone(),
            },
            pre_key: Some(SignalPreKey {
                key_id: receiver_pre_key_id,
                public_key: receiver_pre_key.public_key.clone(),
            }),
        };
        let first = encrypt_signal_outbound_pre_key_session_message(
            &sender_material,
            &sender_base_key,
            &receiver_session,
            &XEdDsaNoiseCertificateVerifier,
            b"inbound identity change",
        )
        .unwrap();

        let codec = SignalMessageCodec::new(
            StoreSignalRepository::new(receiver_store.clone()),
            StoreSignalSenderKeyProvider::new(receiver_store),
        );
        let err = codec
            .decrypt_inbound_message(InboundEncryptedPayload {
                sender_jid: sender_jid.to_owned(),
                chat_jid: "123@s.whatsapp.net".to_owned(),
                ciphertext_type: InboundCiphertextType::PreKey,
                ciphertext: first.message_bytes,
            })
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            CoreError::Protocol(message) if message == "Signal provider identity changed for 123.7"
        ));
        assert_eq!(
            provider_probe
                .load_local_pre_key(receiver_pre_key_id)
                .await
                .unwrap(),
            Some(receiver_pre_key)
        );
        assert_eq!(
            provider_probe
                .load_session_record(sender_jid)
                .await
                .unwrap(),
            Some(existing_session)
        );
        assert_eq!(
            provider_probe
                .load_identity_record(sender_jid)
                .await
                .unwrap(),
            Some(existing_identity)
        );
    }

    #[tokio::test]
    async fn store_signal_provider_decrypts_inbound_pre_key_without_one_time_pre_key() {
        let receiver_store = temp_store().await;
        let receiver_credentials = create_initial_credentials().unwrap();
        save_credentials(&receiver_store, receiver_credentials.clone())
            .await
            .unwrap();
        let upload = prepare_pre_key_upload(&receiver_store, &receiver_credentials, 1, "pre-key")
            .await
            .unwrap();
        let receiver_credentials = upload.credentials;
        save_credentials(&receiver_store, receiver_credentials.clone())
            .await
            .unwrap();
        let unrelated_pre_key_id = upload.pre_key_ids[0];
        let provider_probe = SignalProviderStateStore::new(receiver_store.clone());
        let unrelated_pre_key = provider_probe
            .load_local_pre_key(unrelated_pre_key_id)
            .await
            .unwrap()
            .unwrap();

        let sender_credentials = create_initial_credentials().unwrap();
        let sender_material = signal_local_key_material(sender_credentials.clone());
        let sender_base_key = generate_key_pair();
        let receiver_session = SignalSession {
            registration_id: receiver_credentials.registration_id,
            identity_key: Bytes::copy_from_slice(&receiver_credentials.signed_identity_key.public),
            signed_pre_key: SignalSignedPreKey {
                key_id: receiver_credentials.signed_pre_key.key_id,
                public_key: Bytes::copy_from_slice(
                    &receiver_credentials.signed_pre_key.key_pair.public,
                ),
                signature: receiver_credentials.signed_pre_key.signature.clone(),
            },
            pre_key: None,
        };
        let first = encrypt_signal_outbound_pre_key_session_message(
            &sender_material,
            &sender_base_key,
            &receiver_session,
            &XEdDsaNoiseCertificateVerifier,
            b"inbound signed-pre-key only",
        )
        .unwrap();
        assert!(!first.used_one_time_pre_key);
        assert_eq!(first.message.pre_key_id, None);
        let first_message_bytes = pre_key_message_outer_unknown_field(&first.message_bytes);

        let sender_jid = "123:7@s.whatsapp.net";
        let provider = StoreSignalSenderKeyProvider::new(receiver_store.clone());
        let codec = SignalMessageCodec::new(
            StoreSignalRepository::new(receiver_store.clone()),
            provider.clone(),
        );
        let plaintext = codec
            .decrypt_inbound_message(InboundEncryptedPayload {
                sender_jid: sender_jid.to_owned(),
                chat_jid: "123@s.whatsapp.net".to_owned(),
                ciphertext_type: InboundCiphertextType::PreKey,
                ciphertext: first_message_bytes.clone(),
            })
            .await
            .unwrap();

        assert_eq!(
            plaintext,
            Bytes::from_static(b"inbound signed-pre-key only")
        );
        assert_eq!(
            provider
                .state_store()
                .load_local_pre_key(unrelated_pre_key_id)
                .await
                .unwrap(),
            Some(unrelated_pre_key.clone())
        );
        assert_eq!(
            provider
                .state_store()
                .load_identity_record(sender_jid)
                .await
                .unwrap(),
            Some(sender_material.identity.public_key.clone())
        );
        let receiver_record_bytes = provider
            .state_store()
            .load_session_record(sender_jid)
            .await
            .unwrap()
            .unwrap();
        let receiver_record =
            decode_signal_provider_session_record(&receiver_record_bytes).unwrap();
        assert_eq!(
            receiver_record.remote_identity_key,
            sender_material.identity.public_key
        );
        assert_eq!(
            receiver_record.remote_ratchet_key,
            Some(Bytes::copy_from_slice(&prefixed_signal_public_key(
                &sender_base_key.public
            )))
        );
        assert_eq!(receiver_record.receiving_chain.as_ref().unwrap().counter, 1);
        assert!(is_uninitialized_signal_message_chain(
            &receiver_record.sending_chain
        ));
        receiver_store
            .delete_signal_key(KeyNamespace::Credentials, "schema-version")
            .await
            .unwrap();
        let replay_without_material_err = codec
            .decrypt_inbound_message(InboundEncryptedPayload {
                sender_jid: sender_jid.to_owned(),
                chat_jid: "123@s.whatsapp.net".to_owned(),
                ciphertext_type: InboundCiphertextType::PreKey,
                ciphertext: first_message_bytes.clone(),
            })
            .await
            .unwrap_err();
        assert!(matches!(
            replay_without_material_err,
            CoreError::Protocol(message)
                if message == "duplicate or old Signal message counter: 1"
        ));
        assert_eq!(
            provider
                .state_store()
                .load_session_record(sender_jid)
                .await
                .unwrap()
                .unwrap(),
            receiver_record_bytes
        );
        save_credentials(&receiver_store, receiver_credentials.clone())
            .await
            .unwrap();
        receiver_store
            .delete_signal_key(KeyNamespace::SignalProviderIdentity, "123.7")
            .await
            .unwrap();
        let replay_without_identity_err = codec
            .decrypt_inbound_message(InboundEncryptedPayload {
                sender_jid: sender_jid.to_owned(),
                chat_jid: "123@s.whatsapp.net".to_owned(),
                ciphertext_type: InboundCiphertextType::PreKey,
                ciphertext: first_message_bytes.clone(),
            })
            .await
            .unwrap_err();
        assert!(matches!(
            replay_without_identity_err,
            CoreError::Protocol(message) if message == "no provider identity"
        ));
        assert_eq!(
            provider
                .state_store()
                .load_session_record(sender_jid)
                .await
                .unwrap()
                .unwrap(),
            receiver_record_bytes
        );
        provider
            .state_store()
            .store_identity_record(sender_jid, &sender_material.identity.public_key)
            .await
            .unwrap();

        let second =
            encrypt_signal_provider_session_record_message(&first.record, b"signed-only second")
                .unwrap();
        let sender_base_public_key =
            Bytes::copy_from_slice(&prefixed_signal_public_key(&sender_base_key.public));
        let mismatched_signed_pre_key_wrapped_second = SignalPreKeyWhisperMessage {
            registration_id: sender_material.registration_id,
            pre_key_id: None,
            signed_pre_key_id: receiver_credentials.signed_pre_key.key_id.wrapping_add(1),
            base_key: sender_base_public_key,
            identity_key: sender_material.identity.public_key.clone(),
            message: second.message,
        };
        let mismatched_signed_pre_key_wrapped_second =
            encode_signal_pre_key_whisper_message(&mismatched_signed_pre_key_wrapped_second)
                .expect("signed-only same-base mismatch wrapper should encode");
        let expected_signed_pre_key_error = format!(
            "Signal signed pre-key id mismatch: message {}, local {}",
            receiver_credentials.signed_pre_key.key_id.wrapping_add(1),
            receiver_credentials.signed_pre_key.key_id
        );
        let signed_pre_key_err = codec
            .decrypt_inbound_message(InboundEncryptedPayload {
                sender_jid: sender_jid.to_owned(),
                chat_jid: "123@s.whatsapp.net".to_owned(),
                ciphertext_type: InboundCiphertextType::PreKey,
                ciphertext: mismatched_signed_pre_key_wrapped_second,
            })
            .await
            .unwrap_err();
        assert!(matches!(
            signed_pre_key_err,
            CoreError::Protocol(message) if message == expected_signed_pre_key_error
        ));
        assert_eq!(
            provider
                .state_store()
                .load_session_record(sender_jid)
                .await
                .unwrap()
                .unwrap(),
            receiver_record_bytes
        );
        assert_eq!(
            provider
                .state_store()
                .load_identity_record(sender_jid)
                .await
                .unwrap(),
            Some(sender_material.identity.public_key.clone())
        );

        let replay_err = codec
            .decrypt_inbound_message(InboundEncryptedPayload {
                sender_jid: sender_jid.to_owned(),
                chat_jid: "123@s.whatsapp.net".to_owned(),
                ciphertext_type: InboundCiphertextType::PreKey,
                ciphertext: first_message_bytes,
            })
            .await
            .unwrap_err();
        assert!(matches!(
            replay_err,
            CoreError::Protocol(message)
                if message == "duplicate or old Signal message counter: 1"
        ));
        assert_eq!(
            provider
                .state_store()
                .load_session_record(sender_jid)
                .await
                .unwrap()
                .unwrap(),
            receiver_record_bytes
        );

        let changed_sender_material =
            signal_local_key_material(create_initial_credentials().unwrap());
        assert_ne!(
            changed_sender_material.identity.public_key,
            sender_material.identity.public_key
        );
        let changed_identity = encrypt_signal_outbound_pre_key_session_message(
            &changed_sender_material,
            &sender_base_key,
            &receiver_session,
            &XEdDsaNoiseCertificateVerifier,
            b"inbound signed-pre-key changed identity",
        )
        .unwrap();
        assert!(!changed_identity.used_one_time_pre_key);
        assert_eq!(changed_identity.message.pre_key_id, None);
        let changed_identity_err = codec
            .decrypt_inbound_message(InboundEncryptedPayload {
                sender_jid: sender_jid.to_owned(),
                chat_jid: "123@s.whatsapp.net".to_owned(),
                ciphertext_type: InboundCiphertextType::PreKey,
                ciphertext: changed_identity.message_bytes,
            })
            .await
            .unwrap_err();
        assert!(matches!(
            changed_identity_err,
            CoreError::Protocol(message) if message == "Signal provider identity changed for 123.7"
        ));
        assert_eq!(
            provider
                .state_store()
                .load_session_record(sender_jid)
                .await
                .unwrap()
                .unwrap(),
            receiver_record_bytes
        );
        assert_eq!(
            provider
                .state_store()
                .load_identity_record(sender_jid)
                .await
                .unwrap(),
            Some(sender_material.identity.public_key.clone())
        );

        let replacement_base_key = generate_key_pair();
        let replacement = encrypt_signal_outbound_pre_key_session_message(
            &sender_material,
            &replacement_base_key,
            &receiver_session,
            &XEdDsaNoiseCertificateVerifier,
            b"inbound signed-pre-key replacement",
        )
        .unwrap();
        assert!(!replacement.used_one_time_pre_key);
        assert_eq!(replacement.message.pre_key_id, None);
        let replacement_plaintext = codec
            .decrypt_inbound_message(InboundEncryptedPayload {
                sender_jid: sender_jid.to_owned(),
                chat_jid: "123@s.whatsapp.net".to_owned(),
                ciphertext_type: InboundCiphertextType::PreKey,
                ciphertext: replacement.message_bytes,
            })
            .await
            .unwrap();
        assert_eq!(
            replacement_plaintext,
            Bytes::from_static(b"inbound signed-pre-key replacement")
        );
        let replacement_record = provider
            .state_store()
            .load_session_record(sender_jid)
            .await
            .unwrap()
            .unwrap();
        assert_ne!(replacement_record, receiver_record_bytes);
        let replacement_record =
            decode_signal_provider_session_record(&replacement_record).unwrap();
        assert_eq!(
            replacement_record.remote_ratchet_key,
            Some(Bytes::copy_from_slice(&prefixed_signal_public_key(
                &replacement_base_key.public
            )))
        );
        assert_eq!(
            replacement_record.receiving_chain.as_ref().unwrap().counter,
            1
        );
        assert_eq!(
            provider
                .state_store()
                .load_local_pre_key(unrelated_pre_key_id)
                .await
                .unwrap(),
            Some(unrelated_pre_key)
        );
    }

    #[tokio::test]
    async fn store_signal_provider_preserves_existing_session_after_failed_replacement_pre_key() {
        let receiver_store = temp_store().await;
        let receiver_credentials = create_initial_credentials().unwrap();
        save_credentials(&receiver_store, receiver_credentials.clone())
            .await
            .unwrap();
        let upload = prepare_pre_key_upload(&receiver_store, &receiver_credentials, 1, "pre-key")
            .await
            .unwrap();
        let receiver_credentials = upload.credentials;
        save_credentials(&receiver_store, receiver_credentials.clone())
            .await
            .unwrap();
        let receiver_pre_key_id = upload.pre_key_ids[0];
        let provider_probe = SignalProviderStateStore::new(receiver_store.clone());
        let receiver_pre_key = provider_probe
            .load_local_pre_key(receiver_pre_key_id)
            .await
            .unwrap()
            .unwrap();

        let sender_credentials = create_initial_credentials().unwrap();
        let sender_material = signal_local_key_material(sender_credentials);
        let sender_base_key = generate_key_pair();
        let receiver_session = SignalSession {
            registration_id: receiver_credentials.registration_id,
            identity_key: Bytes::copy_from_slice(&receiver_credentials.signed_identity_key.public),
            signed_pre_key: SignalSignedPreKey {
                key_id: receiver_credentials.signed_pre_key.key_id,
                public_key: Bytes::copy_from_slice(
                    &receiver_credentials.signed_pre_key.key_pair.public,
                ),
                signature: receiver_credentials.signed_pre_key.signature.clone(),
            },
            pre_key: Some(SignalPreKey {
                key_id: receiver_pre_key_id,
                public_key: receiver_pre_key.public_key.clone(),
            }),
        };
        let first = encrypt_signal_outbound_pre_key_session_message(
            &sender_material,
            &sender_base_key,
            &receiver_session,
            &XEdDsaNoiseCertificateVerifier,
            b"inbound first before failed replacement",
        )
        .unwrap();
        let sender_jid = "123:7@s.whatsapp.net";
        let chat_jid = "123@s.whatsapp.net";
        let provider = StoreSignalSenderKeyProvider::new(receiver_store.clone());
        let codec = SignalMessageCodec::new(
            StoreSignalRepository::new(receiver_store.clone()),
            provider.clone(),
        );
        let first_plaintext = codec
            .decrypt_inbound_message(InboundEncryptedPayload {
                sender_jid: sender_jid.to_owned(),
                chat_jid: chat_jid.to_owned(),
                ciphertext_type: InboundCiphertextType::PreKey,
                ciphertext: first.message_bytes,
            })
            .await
            .unwrap();
        assert_eq!(
            first_plaintext,
            Bytes::from_static(b"inbound first before failed replacement")
        );
        let established_record = provider_probe
            .load_session_record(sender_jid)
            .await
            .unwrap()
            .unwrap();
        let established_identity = provider_probe
            .load_identity_record(sender_jid)
            .await
            .unwrap()
            .unwrap();

        let replacement_base_key = generate_key_pair();
        let replacement_session = SignalSession {
            pre_key: None,
            ..receiver_session
        };
        let replacement = encrypt_signal_outbound_pre_key_session_message(
            &sender_material,
            &replacement_base_key,
            &replacement_session,
            &XEdDsaNoiseCertificateVerifier,
            b"inbound replacement should fail first",
        )
        .unwrap();
        assert!(!replacement.used_one_time_pre_key);
        assert_eq!(replacement.message.pre_key_id, None);
        let mut tampered =
            decode_signal_pre_key_whisper_message(&replacement.message_bytes).unwrap();
        let mut tampered_ciphertext = tampered.message.ciphertext.to_vec();
        *tampered_ciphertext.last_mut().unwrap() ^= 1;
        tampered.message.ciphertext = Bytes::from(tampered_ciphertext);
        let tampered = encode_signal_pre_key_whisper_message(&tampered).unwrap();

        let err = codec
            .decrypt_inbound_message(InboundEncryptedPayload {
                sender_jid: sender_jid.to_owned(),
                chat_jid: chat_jid.to_owned(),
                ciphertext_type: InboundCiphertextType::PreKey,
                ciphertext: tampered,
            })
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            CoreError::Crypto(wa_crypto::CryptoError::Decrypt)
        ));
        assert_eq!(
            provider_probe
                .load_session_record(sender_jid)
                .await
                .unwrap()
                .unwrap(),
            established_record
        );
        assert_eq!(
            provider_probe
                .load_identity_record(sender_jid)
                .await
                .unwrap()
                .unwrap(),
            established_identity
        );

        let old_session_second = encrypt_signal_provider_session_record_message(
            &first.record,
            b"old session still decrypts",
        )
        .unwrap();
        let old_plaintext = codec
            .decrypt_inbound_message(InboundEncryptedPayload {
                sender_jid: sender_jid.to_owned(),
                chat_jid: chat_jid.to_owned(),
                ciphertext_type: InboundCiphertextType::Message,
                ciphertext: old_session_second.message_bytes,
            })
            .await
            .unwrap();
        assert_eq!(
            old_plaintext,
            Bytes::from_static(b"old session still decrypts")
        );

        let replacement_plaintext = codec
            .decrypt_inbound_message(InboundEncryptedPayload {
                sender_jid: sender_jid.to_owned(),
                chat_jid: chat_jid.to_owned(),
                ciphertext_type: InboundCiphertextType::PreKey,
                ciphertext: replacement.message_bytes,
            })
            .await
            .unwrap();
        assert_eq!(
            replacement_plaintext,
            Bytes::from_static(b"inbound replacement should fail first")
        );
        let replacement_record = provider_probe
            .load_session_record(sender_jid)
            .await
            .unwrap()
            .unwrap();
        assert_ne!(replacement_record, established_record);
        let replacement_record =
            decode_signal_provider_session_record(&replacement_record).unwrap();
        assert_eq!(
            replacement_record.remote_ratchet_key,
            Some(Bytes::copy_from_slice(&prefixed_signal_public_key(
                &replacement_base_key.public
            )))
        );
        assert_eq!(
            replacement_record.receiving_chain.as_ref().unwrap().counter,
            1
        );
        assert_eq!(
            provider_probe
                .load_identity_record(sender_jid)
                .await
                .unwrap()
                .unwrap(),
            established_identity
        );
    }

    #[tokio::test]
    async fn store_signal_provider_preserves_state_after_signed_replacement_identity_change() {
        let receiver_store = temp_store().await;
        let receiver_credentials = create_initial_credentials().unwrap();
        save_credentials(&receiver_store, receiver_credentials.clone())
            .await
            .unwrap();
        let upload = prepare_pre_key_upload(&receiver_store, &receiver_credentials, 1, "pre-key")
            .await
            .unwrap();
        let receiver_credentials = upload.credentials;
        save_credentials(&receiver_store, receiver_credentials.clone())
            .await
            .unwrap();
        let receiver_pre_key_id = upload.pre_key_ids[0];
        let provider_probe = SignalProviderStateStore::new(receiver_store.clone());
        let receiver_pre_key = provider_probe
            .load_local_pre_key(receiver_pre_key_id)
            .await
            .unwrap()
            .unwrap();

        let sender_credentials = create_initial_credentials().unwrap();
        let sender_material = signal_local_key_material(sender_credentials);
        let sender_base_key = generate_key_pair();
        let receiver_session = SignalSession {
            registration_id: receiver_credentials.registration_id,
            identity_key: Bytes::copy_from_slice(&receiver_credentials.signed_identity_key.public),
            signed_pre_key: SignalSignedPreKey {
                key_id: receiver_credentials.signed_pre_key.key_id,
                public_key: Bytes::copy_from_slice(
                    &receiver_credentials.signed_pre_key.key_pair.public,
                ),
                signature: receiver_credentials.signed_pre_key.signature.clone(),
            },
            pre_key: Some(SignalPreKey {
                key_id: receiver_pre_key_id,
                public_key: receiver_pre_key.public_key.clone(),
            }),
        };
        let first = encrypt_signal_outbound_pre_key_session_message(
            &sender_material,
            &sender_base_key,
            &receiver_session,
            &XEdDsaNoiseCertificateVerifier,
            b"inbound first before signed replacement identity change",
        )
        .unwrap();
        assert!(first.used_one_time_pre_key);

        let sender_jid = "123:7@s.whatsapp.net";
        let chat_jid = "123@s.whatsapp.net";
        let provider = StoreSignalSenderKeyProvider::new(receiver_store.clone());
        let codec = SignalMessageCodec::new(
            StoreSignalRepository::new(receiver_store.clone()),
            provider.clone(),
        );
        let first_plaintext = codec
            .decrypt_inbound_message(InboundEncryptedPayload {
                sender_jid: sender_jid.to_owned(),
                chat_jid: chat_jid.to_owned(),
                ciphertext_type: InboundCiphertextType::PreKey,
                ciphertext: first.message_bytes,
            })
            .await
            .unwrap();
        assert_eq!(
            first_plaintext,
            Bytes::from_static(b"inbound first before signed replacement identity change")
        );
        assert!(
            provider_probe
                .load_local_pre_key(receiver_pre_key_id)
                .await
                .unwrap()
                .is_none()
        );
        let established_record = provider_probe
            .load_session_record(sender_jid)
            .await
            .unwrap()
            .unwrap();
        let established_identity = provider_probe
            .load_identity_record(sender_jid)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(established_identity, sender_material.identity.public_key);

        let changed_sender_material =
            signal_local_key_material(create_initial_credentials().unwrap());
        assert_ne!(
            changed_sender_material.identity.public_key,
            established_identity
        );
        let signed_only_session = SignalSession {
            pre_key: None,
            ..receiver_session
        };
        let changed_identity_replacement = encrypt_signal_outbound_pre_key_session_message(
            &changed_sender_material,
            &generate_key_pair(),
            &signed_only_session,
            &XEdDsaNoiseCertificateVerifier,
            b"inbound signed replacement changed identity",
        )
        .unwrap();
        assert!(!changed_identity_replacement.used_one_time_pre_key);
        assert_eq!(changed_identity_replacement.message.pre_key_id, None);

        let err = codec
            .decrypt_inbound_message(InboundEncryptedPayload {
                sender_jid: sender_jid.to_owned(),
                chat_jid: chat_jid.to_owned(),
                ciphertext_type: InboundCiphertextType::PreKey,
                ciphertext: changed_identity_replacement.message_bytes,
            })
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            CoreError::Protocol(message) if message == "Signal provider identity changed for 123.7"
        ));
        assert_eq!(
            provider_probe
                .load_session_record(sender_jid)
                .await
                .unwrap()
                .unwrap(),
            established_record
        );
        assert_eq!(
            provider_probe
                .load_identity_record(sender_jid)
                .await
                .unwrap()
                .unwrap(),
            established_identity
        );

        let old_session_second = encrypt_signal_provider_session_record_message(
            &first.record,
            b"old session still decrypts after signed identity change",
        )
        .unwrap();
        let old_plaintext = codec
            .decrypt_inbound_message(InboundEncryptedPayload {
                sender_jid: sender_jid.to_owned(),
                chat_jid: chat_jid.to_owned(),
                ciphertext_type: InboundCiphertextType::Message,
                ciphertext: old_session_second.message_bytes,
            })
            .await
            .unwrap();
        assert_eq!(
            old_plaintext,
            Bytes::from_static(b"old session still decrypts after signed identity change")
        );

        let valid_replacement_base_key = generate_key_pair();
        let valid_replacement = encrypt_signal_outbound_pre_key_session_message(
            &sender_material,
            &valid_replacement_base_key,
            &signed_only_session,
            &XEdDsaNoiseCertificateVerifier,
            b"inbound signed replacement after identity change",
        )
        .unwrap();
        assert!(!valid_replacement.used_one_time_pre_key);
        let valid_plaintext = codec
            .decrypt_inbound_message(InboundEncryptedPayload {
                sender_jid: sender_jid.to_owned(),
                chat_jid: chat_jid.to_owned(),
                ciphertext_type: InboundCiphertextType::PreKey,
                ciphertext: valid_replacement.message_bytes,
            })
            .await
            .unwrap();
        assert_eq!(
            valid_plaintext,
            Bytes::from_static(b"inbound signed replacement after identity change")
        );
        let replacement_record = provider_probe
            .load_session_record(sender_jid)
            .await
            .unwrap()
            .unwrap();
        assert_ne!(replacement_record, established_record);
        let replacement_record =
            decode_signal_provider_session_record(&replacement_record).unwrap();
        assert_eq!(
            replacement_record.remote_ratchet_key,
            Some(Bytes::copy_from_slice(&prefixed_signal_public_key(
                &valid_replacement_base_key.public
            )))
        );
        assert_eq!(
            replacement_record.receiving_chain.as_ref().unwrap().counter,
            1
        );
        assert_eq!(
            provider_probe
                .load_identity_record(sender_jid)
                .await
                .unwrap()
                .unwrap(),
            established_identity
        );
    }

    #[tokio::test]
    async fn store_signal_provider_rejects_missing_one_time_replacement_with_new_base_key() {
        let receiver_store = temp_store().await;
        let receiver_credentials = create_initial_credentials().unwrap();
        save_credentials(&receiver_store, receiver_credentials.clone())
            .await
            .unwrap();
        let upload = prepare_pre_key_upload(&receiver_store, &receiver_credentials, 1, "pre-key")
            .await
            .unwrap();
        let receiver_credentials = upload.credentials;
        save_credentials(&receiver_store, receiver_credentials.clone())
            .await
            .unwrap();
        let receiver_pre_key_id = upload.pre_key_ids[0];
        let provider_probe = SignalProviderStateStore::new(receiver_store.clone());
        let receiver_pre_key = provider_probe
            .load_local_pre_key(receiver_pre_key_id)
            .await
            .unwrap()
            .unwrap();

        let sender_credentials = create_initial_credentials().unwrap();
        let sender_material = signal_local_key_material(sender_credentials);
        let sender_base_key = generate_key_pair();
        let receiver_session = SignalSession {
            registration_id: receiver_credentials.registration_id,
            identity_key: Bytes::copy_from_slice(&receiver_credentials.signed_identity_key.public),
            signed_pre_key: SignalSignedPreKey {
                key_id: receiver_credentials.signed_pre_key.key_id,
                public_key: Bytes::copy_from_slice(
                    &receiver_credentials.signed_pre_key.key_pair.public,
                ),
                signature: receiver_credentials.signed_pre_key.signature.clone(),
            },
            pre_key: Some(SignalPreKey {
                key_id: receiver_pre_key_id,
                public_key: receiver_pre_key.public_key.clone(),
            }),
        };
        let first = encrypt_signal_outbound_pre_key_session_message(
            &sender_material,
            &sender_base_key,
            &receiver_session,
            &XEdDsaNoiseCertificateVerifier,
            b"inbound first before missing replacement pre-key",
        )
        .unwrap();
        assert!(first.used_one_time_pre_key);

        let sender_jid = "123:7@s.whatsapp.net";
        let chat_jid = "123@s.whatsapp.net";
        let provider = StoreSignalSenderKeyProvider::new(receiver_store.clone());
        let codec = SignalMessageCodec::new(
            StoreSignalRepository::new(receiver_store.clone()),
            provider.clone(),
        );
        let first_plaintext = codec
            .decrypt_inbound_message(InboundEncryptedPayload {
                sender_jid: sender_jid.to_owned(),
                chat_jid: chat_jid.to_owned(),
                ciphertext_type: InboundCiphertextType::PreKey,
                ciphertext: first.message_bytes,
            })
            .await
            .unwrap();
        assert_eq!(
            first_plaintext,
            Bytes::from_static(b"inbound first before missing replacement pre-key")
        );
        assert!(
            provider_probe
                .load_local_pre_key(receiver_pre_key_id)
                .await
                .unwrap()
                .is_none()
        );
        let established_record = provider_probe
            .load_session_record(sender_jid)
            .await
            .unwrap()
            .unwrap();
        let established_identity = provider_probe
            .load_identity_record(sender_jid)
            .await
            .unwrap()
            .unwrap();
        let decoded_established_record =
            decode_signal_provider_session_record(&established_record).unwrap();

        let replacement_base_key = generate_key_pair();
        let replacement_ratchet_key =
            Bytes::copy_from_slice(&prefixed_signal_public_key(&replacement_base_key.public));
        assert_ne!(
            decoded_established_record.remote_ratchet_key.as_ref(),
            Some(&replacement_ratchet_key)
        );
        let root_step = ratchet_signal_root_key(
            &decoded_established_record.root_key,
            decoded_established_record
                .local_ratchet_key_pair
                .private
                .expose(),
            &replacement_ratchet_key,
        )
        .unwrap();
        let message_step = ratchet_signal_message_chain(&root_step.chain_key).unwrap();
        let replacement_plaintext =
            Bytes::from_static(b"missing one-time replacement must not advance");
        let replacement_ciphertext =
            encrypt_signal_message_body(&replacement_plaintext, &message_step.message_keys)
                .unwrap();
        let wrapped_replacement = SignalPreKeyWhisperMessage {
            registration_id: sender_material.registration_id,
            pre_key_id: Some(receiver_pre_key_id),
            signed_pre_key_id: receiver_credentials.signed_pre_key.key_id,
            base_key: replacement_ratchet_key.clone(),
            identity_key: sender_material.identity.public_key.clone(),
            message: SignalWhisperMessage {
                ephemeral_key: replacement_ratchet_key,
                counter: message_step.message_counter,
                previous_counter: decoded_established_record
                    .receiving_chain
                    .as_ref()
                    .unwrap()
                    .counter,
                ciphertext: replacement_ciphertext,
            },
        };
        let wrapped_replacement = encode_signal_pre_key_whisper_message(&wrapped_replacement)
            .expect("replacement pre-key wrapper should encode");

        let err = codec
            .decrypt_inbound_message(InboundEncryptedPayload {
                sender_jid: sender_jid.to_owned(),
                chat_jid: chat_jid.to_owned(),
                ciphertext_type: InboundCiphertextType::PreKey,
                ciphertext: wrapped_replacement,
            })
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            CoreError::Protocol(message)
                if message == format!("missing local Signal one-time pre-key {receiver_pre_key_id}")
        ));
        assert_eq!(
            provider_probe
                .load_session_record(sender_jid)
                .await
                .unwrap()
                .unwrap(),
            established_record
        );
        assert_eq!(
            provider_probe
                .load_identity_record(sender_jid)
                .await
                .unwrap()
                .unwrap(),
            established_identity
        );
        assert!(
            provider_probe
                .load_local_pre_key(receiver_pre_key_id)
                .await
                .unwrap()
                .is_none()
        );

        let old_session_second = encrypt_signal_provider_session_record_message(
            &first.record,
            b"old session still decrypts after missing one-time replacement",
        )
        .unwrap();
        let old_plaintext = codec
            .decrypt_inbound_message(InboundEncryptedPayload {
                sender_jid: sender_jid.to_owned(),
                chat_jid: chat_jid.to_owned(),
                ciphertext_type: InboundCiphertextType::Message,
                ciphertext: old_session_second.message_bytes,
            })
            .await
            .unwrap();
        assert_eq!(
            old_plaintext,
            Bytes::from_static(b"old session still decrypts after missing one-time replacement")
        );
    }

    #[tokio::test]
    async fn store_signal_provider_decrypts_missing_one_time_existing_session_same_base() {
        let receiver_store = temp_store().await;
        let receiver_credentials = create_initial_credentials().unwrap();
        save_credentials(&receiver_store, receiver_credentials.clone())
            .await
            .unwrap();
        let upload = prepare_pre_key_upload(&receiver_store, &receiver_credentials, 1, "pre-key")
            .await
            .unwrap();
        let receiver_credentials = upload.credentials;
        save_credentials(&receiver_store, receiver_credentials.clone())
            .await
            .unwrap();
        let receiver_pre_key_id = upload.pre_key_ids[0];
        let provider_probe = SignalProviderStateStore::new(receiver_store.clone());
        let receiver_pre_key = provider_probe
            .load_local_pre_key(receiver_pre_key_id)
            .await
            .unwrap()
            .unwrap();

        let sender_credentials = create_initial_credentials().unwrap();
        let sender_material = signal_local_key_material(sender_credentials);
        let sender_base_key = generate_key_pair();
        let sender_base_public_key =
            Bytes::copy_from_slice(&prefixed_signal_public_key(&sender_base_key.public));
        let receiver_session = SignalSession {
            registration_id: receiver_credentials.registration_id,
            identity_key: Bytes::copy_from_slice(&receiver_credentials.signed_identity_key.public),
            signed_pre_key: SignalSignedPreKey {
                key_id: receiver_credentials.signed_pre_key.key_id,
                public_key: Bytes::copy_from_slice(
                    &receiver_credentials.signed_pre_key.key_pair.public,
                ),
                signature: receiver_credentials.signed_pre_key.signature.clone(),
            },
            pre_key: Some(SignalPreKey {
                key_id: receiver_pre_key_id,
                public_key: receiver_pre_key.public_key.clone(),
            }),
        };
        let first = encrypt_signal_outbound_pre_key_session_message(
            &sender_material,
            &sender_base_key,
            &receiver_session,
            &XEdDsaNoiseCertificateVerifier,
            b"inbound first before same-base missing pre-key wrapper",
        )
        .unwrap();
        assert!(first.used_one_time_pre_key);

        let sender_jid = "123:7@s.whatsapp.net";
        let chat_jid = "123@s.whatsapp.net";
        let provider = StoreSignalSenderKeyProvider::new(receiver_store.clone());
        let codec = SignalMessageCodec::new(
            StoreSignalRepository::new(receiver_store.clone()),
            provider.clone(),
        );
        let first_plaintext = codec
            .decrypt_inbound_message(InboundEncryptedPayload {
                sender_jid: sender_jid.to_owned(),
                chat_jid: chat_jid.to_owned(),
                ciphertext_type: InboundCiphertextType::PreKey,
                ciphertext: first.message_bytes,
            })
            .await
            .unwrap();
        assert_eq!(
            first_plaintext,
            Bytes::from_static(b"inbound first before same-base missing pre-key wrapper")
        );
        assert!(
            provider_probe
                .load_local_pre_key(receiver_pre_key_id)
                .await
                .unwrap()
                .is_none()
        );
        let established_record = provider_probe
            .load_session_record(sender_jid)
            .await
            .unwrap()
            .unwrap();
        let established_identity = provider_probe
            .load_identity_record(sender_jid)
            .await
            .unwrap()
            .unwrap();

        let second = encrypt_signal_provider_session_record_message(
            &first.record,
            b"same-base wrapped existing session",
        )
        .unwrap();
        let changed_sender_material =
            signal_local_key_material(create_initial_credentials().unwrap());
        assert_ne!(
            changed_sender_material.identity.public_key,
            sender_material.identity.public_key
        );
        let changed_identity_wrapped_second = SignalPreKeyWhisperMessage {
            registration_id: changed_sender_material.registration_id,
            pre_key_id: Some(receiver_pre_key_id),
            signed_pre_key_id: receiver_credentials.signed_pre_key.key_id,
            base_key: sender_base_public_key.clone(),
            identity_key: changed_sender_material.identity.public_key,
            message: second.message.clone(),
        };
        let changed_identity_wrapped_second =
            encode_signal_pre_key_whisper_message(&changed_identity_wrapped_second)
                .expect("same-base changed-identity wrapper should encode");
        let changed_identity_err = codec
            .decrypt_inbound_message(InboundEncryptedPayload {
                sender_jid: sender_jid.to_owned(),
                chat_jid: chat_jid.to_owned(),
                ciphertext_type: InboundCiphertextType::PreKey,
                ciphertext: changed_identity_wrapped_second,
            })
            .await
            .unwrap_err();
        assert!(matches!(
            changed_identity_err,
            CoreError::Protocol(message) if message == "Signal provider identity changed for 123.7"
        ));
        assert_eq!(
            provider_probe
                .load_session_record(sender_jid)
                .await
                .unwrap()
                .unwrap(),
            established_record
        );
        assert_eq!(
            provider_probe
                .load_identity_record(sender_jid)
                .await
                .unwrap()
                .unwrap(),
            established_identity
        );
        assert!(
            provider_probe
                .load_local_pre_key(receiver_pre_key_id)
                .await
                .unwrap()
                .is_none()
        );

        let mismatched_signed_pre_key_wrapped_second = SignalPreKeyWhisperMessage {
            registration_id: sender_material.registration_id,
            pre_key_id: Some(receiver_pre_key_id),
            signed_pre_key_id: receiver_credentials.signed_pre_key.key_id.wrapping_add(1),
            base_key: sender_base_public_key.clone(),
            identity_key: sender_material.identity.public_key.clone(),
            message: second.message.clone(),
        };
        let mismatched_signed_pre_key_wrapped_second =
            encode_signal_pre_key_whisper_message(&mismatched_signed_pre_key_wrapped_second)
                .expect("same-base signed-pre-key-id mismatch wrapper should encode");
        let expected_signed_pre_key_error = format!(
            "Signal signed pre-key id mismatch: message {}, local {}",
            receiver_credentials.signed_pre_key.key_id.wrapping_add(1),
            receiver_credentials.signed_pre_key.key_id
        );
        let signed_pre_key_err = codec
            .decrypt_inbound_message(InboundEncryptedPayload {
                sender_jid: sender_jid.to_owned(),
                chat_jid: chat_jid.to_owned(),
                ciphertext_type: InboundCiphertextType::PreKey,
                ciphertext: mismatched_signed_pre_key_wrapped_second,
            })
            .await
            .unwrap_err();
        assert!(matches!(
            signed_pre_key_err,
            CoreError::Protocol(message) if message == expected_signed_pre_key_error
        ));
        assert_eq!(
            provider_probe
                .load_session_record(sender_jid)
                .await
                .unwrap()
                .unwrap(),
            established_record
        );
        assert_eq!(
            provider_probe
                .load_identity_record(sender_jid)
                .await
                .unwrap()
                .unwrap(),
            established_identity
        );
        assert!(
            provider_probe
                .load_local_pre_key(receiver_pre_key_id)
                .await
                .unwrap()
                .is_none()
        );

        let wrapped_second = SignalPreKeyWhisperMessage {
            registration_id: sender_material.registration_id,
            pre_key_id: Some(receiver_pre_key_id),
            signed_pre_key_id: receiver_credentials.signed_pre_key.key_id,
            base_key: sender_base_public_key.clone(),
            identity_key: sender_material.identity.public_key.clone(),
            message: second.message,
        };
        let wrapped_second = encode_signal_pre_key_whisper_message(&wrapped_second)
            .expect("same-base existing-session wrapper should encode");

        let second_plaintext = codec
            .decrypt_inbound_message(InboundEncryptedPayload {
                sender_jid: sender_jid.to_owned(),
                chat_jid: chat_jid.to_owned(),
                ciphertext_type: InboundCiphertextType::PreKey,
                ciphertext: wrapped_second.clone(),
            })
            .await
            .unwrap();
        assert_eq!(
            second_plaintext,
            Bytes::from_static(b"same-base wrapped existing session")
        );
        let after_second = provider_probe
            .load_session_record(sender_jid)
            .await
            .unwrap()
            .unwrap();
        assert_ne!(after_second, established_record);
        let decoded_after_second = decode_signal_provider_session_record(&after_second).unwrap();
        assert_eq!(
            decoded_after_second.remote_ratchet_key,
            Some(sender_base_public_key)
        );
        assert_eq!(
            decoded_after_second
                .receiving_chain
                .as_ref()
                .unwrap()
                .counter,
            2
        );
        assert_eq!(
            provider_probe
                .load_identity_record(sender_jid)
                .await
                .unwrap()
                .unwrap(),
            established_identity
        );
        assert!(
            provider_probe
                .load_local_pre_key(receiver_pre_key_id)
                .await
                .unwrap()
                .is_none()
        );

        let replay_err = codec
            .decrypt_inbound_message(InboundEncryptedPayload {
                sender_jid: sender_jid.to_owned(),
                chat_jid: chat_jid.to_owned(),
                ciphertext_type: InboundCiphertextType::PreKey,
                ciphertext: wrapped_second,
            })
            .await
            .unwrap_err();
        assert!(matches!(
            replay_err,
            CoreError::Protocol(message)
                if message == "duplicate or old Signal message counter: 2"
        ));
        assert_eq!(
            provider_probe
                .load_session_record(sender_jid)
                .await
                .unwrap()
                .unwrap(),
            after_second
        );
    }

    #[tokio::test]
    async fn store_signal_provider_preserves_state_after_failed_one_time_replacement() {
        let receiver_store = temp_store().await;
        let receiver_credentials = create_initial_credentials().unwrap();
        save_credentials(&receiver_store, receiver_credentials.clone())
            .await
            .unwrap();
        let upload = prepare_pre_key_upload(&receiver_store, &receiver_credentials, 2, "pre-key")
            .await
            .unwrap();
        let receiver_credentials = upload.credentials;
        save_credentials(&receiver_store, receiver_credentials.clone())
            .await
            .unwrap();
        let first_pre_key_id = upload.pre_key_ids[0];
        let replacement_pre_key_id = upload.pre_key_ids[1];
        let provider_probe = SignalProviderStateStore::new(receiver_store.clone());
        let first_pre_key = provider_probe
            .load_local_pre_key(first_pre_key_id)
            .await
            .unwrap()
            .unwrap();
        let replacement_pre_key = provider_probe
            .load_local_pre_key(replacement_pre_key_id)
            .await
            .unwrap()
            .unwrap();

        let sender_credentials = create_initial_credentials().unwrap();
        let sender_material = signal_local_key_material(sender_credentials);
        let sender_base_key = generate_key_pair();
        let receiver_session = SignalSession {
            registration_id: receiver_credentials.registration_id,
            identity_key: Bytes::copy_from_slice(&receiver_credentials.signed_identity_key.public),
            signed_pre_key: SignalSignedPreKey {
                key_id: receiver_credentials.signed_pre_key.key_id,
                public_key: Bytes::copy_from_slice(
                    &receiver_credentials.signed_pre_key.key_pair.public,
                ),
                signature: receiver_credentials.signed_pre_key.signature.clone(),
            },
            pre_key: Some(SignalPreKey {
                key_id: first_pre_key_id,
                public_key: first_pre_key.public_key.clone(),
            }),
        };
        let first = encrypt_signal_outbound_pre_key_session_message(
            &sender_material,
            &sender_base_key,
            &receiver_session,
            &XEdDsaNoiseCertificateVerifier,
            b"inbound first before failed one-time replacement",
        )
        .unwrap();
        assert!(first.used_one_time_pre_key);
        assert_eq!(first.message.pre_key_id, Some(first_pre_key_id));

        let sender_jid = "123:7@s.whatsapp.net";
        let chat_jid = "123@s.whatsapp.net";
        let provider = StoreSignalSenderKeyProvider::new(receiver_store.clone());
        let codec = SignalMessageCodec::new(
            StoreSignalRepository::new(receiver_store.clone()),
            provider.clone(),
        );
        let first_plaintext = codec
            .decrypt_inbound_message(InboundEncryptedPayload {
                sender_jid: sender_jid.to_owned(),
                chat_jid: chat_jid.to_owned(),
                ciphertext_type: InboundCiphertextType::PreKey,
                ciphertext: first.message_bytes,
            })
            .await
            .unwrap();
        assert_eq!(
            first_plaintext,
            Bytes::from_static(b"inbound first before failed one-time replacement")
        );
        assert!(
            provider_probe
                .load_local_pre_key(first_pre_key_id)
                .await
                .unwrap()
                .is_none()
        );
        let established_record = provider_probe
            .load_session_record(sender_jid)
            .await
            .unwrap()
            .unwrap();
        let established_identity = provider_probe
            .load_identity_record(sender_jid)
            .await
            .unwrap()
            .unwrap();

        let replacement_base_key = generate_key_pair();
        let replacement_session = SignalSession {
            registration_id: receiver_credentials.registration_id,
            identity_key: Bytes::copy_from_slice(&receiver_credentials.signed_identity_key.public),
            signed_pre_key: SignalSignedPreKey {
                key_id: receiver_credentials.signed_pre_key.key_id,
                public_key: Bytes::copy_from_slice(
                    &receiver_credentials.signed_pre_key.key_pair.public,
                ),
                signature: receiver_credentials.signed_pre_key.signature.clone(),
            },
            pre_key: Some(SignalPreKey {
                key_id: replacement_pre_key_id,
                public_key: replacement_pre_key.public_key.clone(),
            }),
        };
        let replacement = encrypt_signal_outbound_pre_key_session_message(
            &sender_material,
            &replacement_base_key,
            &replacement_session,
            &XEdDsaNoiseCertificateVerifier,
            b"inbound one-time replacement should fail first",
        )
        .unwrap();
        assert!(replacement.used_one_time_pre_key);
        assert_eq!(replacement.message.pre_key_id, Some(replacement_pre_key_id));
        let mut tampered =
            decode_signal_pre_key_whisper_message(&replacement.message_bytes).unwrap();
        let mut tampered_ciphertext = tampered.message.ciphertext.to_vec();
        *tampered_ciphertext.last_mut().unwrap() ^= 1;
        tampered.message.ciphertext = Bytes::from(tampered_ciphertext);
        let tampered = encode_signal_pre_key_whisper_message(&tampered).unwrap();

        let err = codec
            .decrypt_inbound_message(InboundEncryptedPayload {
                sender_jid: sender_jid.to_owned(),
                chat_jid: chat_jid.to_owned(),
                ciphertext_type: InboundCiphertextType::PreKey,
                ciphertext: tampered,
            })
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            CoreError::Crypto(wa_crypto::CryptoError::Decrypt)
        ));
        assert_eq!(
            provider_probe
                .load_session_record(sender_jid)
                .await
                .unwrap()
                .unwrap(),
            established_record
        );
        assert_eq!(
            provider_probe
                .load_identity_record(sender_jid)
                .await
                .unwrap()
                .unwrap(),
            established_identity
        );
        assert_eq!(
            provider_probe
                .load_local_pre_key(replacement_pre_key_id)
                .await
                .unwrap(),
            Some(replacement_pre_key)
        );

        let old_session_second = encrypt_signal_provider_session_record_message(
            &first.record,
            b"old session still decrypts after one-time replacement failure",
        )
        .unwrap();
        let old_plaintext = codec
            .decrypt_inbound_message(InboundEncryptedPayload {
                sender_jid: sender_jid.to_owned(),
                chat_jid: chat_jid.to_owned(),
                ciphertext_type: InboundCiphertextType::Message,
                ciphertext: old_session_second.message_bytes,
            })
            .await
            .unwrap();
        assert_eq!(
            old_plaintext,
            Bytes::from_static(b"old session still decrypts after one-time replacement failure")
        );

        let replacement_plaintext = codec
            .decrypt_inbound_message(InboundEncryptedPayload {
                sender_jid: sender_jid.to_owned(),
                chat_jid: chat_jid.to_owned(),
                ciphertext_type: InboundCiphertextType::PreKey,
                ciphertext: replacement.message_bytes,
            })
            .await
            .unwrap();
        assert_eq!(
            replacement_plaintext,
            Bytes::from_static(b"inbound one-time replacement should fail first")
        );
        assert!(
            provider_probe
                .load_local_pre_key(replacement_pre_key_id)
                .await
                .unwrap()
                .is_none()
        );
        let replacement_record = provider_probe
            .load_session_record(sender_jid)
            .await
            .unwrap()
            .unwrap();
        assert_ne!(replacement_record, established_record);
        let replacement_record =
            decode_signal_provider_session_record(&replacement_record).unwrap();
        assert_eq!(
            replacement_record.remote_ratchet_key,
            Some(Bytes::copy_from_slice(&prefixed_signal_public_key(
                &replacement_base_key.public
            )))
        );
        assert_eq!(
            replacement_record.receiving_chain.as_ref().unwrap().counter,
            1
        );
        assert_eq!(
            provider_probe
                .load_identity_record(sender_jid)
                .await
                .unwrap()
                .unwrap(),
            established_identity
        );
    }

    #[tokio::test]
    async fn store_signal_provider_preserves_state_after_one_time_replacement_identity_change() {
        let receiver_store = temp_store().await;
        let receiver_credentials = create_initial_credentials().unwrap();
        save_credentials(&receiver_store, receiver_credentials.clone())
            .await
            .unwrap();
        let upload = prepare_pre_key_upload(&receiver_store, &receiver_credentials, 2, "pre-key")
            .await
            .unwrap();
        let receiver_credentials = upload.credentials;
        save_credentials(&receiver_store, receiver_credentials.clone())
            .await
            .unwrap();
        let first_pre_key_id = upload.pre_key_ids[0];
        let replacement_pre_key_id = upload.pre_key_ids[1];
        let provider_probe = SignalProviderStateStore::new(receiver_store.clone());
        let first_pre_key = provider_probe
            .load_local_pre_key(first_pre_key_id)
            .await
            .unwrap()
            .unwrap();
        let replacement_pre_key = provider_probe
            .load_local_pre_key(replacement_pre_key_id)
            .await
            .unwrap()
            .unwrap();

        let sender_credentials = create_initial_credentials().unwrap();
        let sender_material = signal_local_key_material(sender_credentials);
        let sender_base_key = generate_key_pair();
        let receiver_session = SignalSession {
            registration_id: receiver_credentials.registration_id,
            identity_key: Bytes::copy_from_slice(&receiver_credentials.signed_identity_key.public),
            signed_pre_key: SignalSignedPreKey {
                key_id: receiver_credentials.signed_pre_key.key_id,
                public_key: Bytes::copy_from_slice(
                    &receiver_credentials.signed_pre_key.key_pair.public,
                ),
                signature: receiver_credentials.signed_pre_key.signature.clone(),
            },
            pre_key: Some(SignalPreKey {
                key_id: first_pre_key_id,
                public_key: first_pre_key.public_key.clone(),
            }),
        };
        let first = encrypt_signal_outbound_pre_key_session_message(
            &sender_material,
            &sender_base_key,
            &receiver_session,
            &XEdDsaNoiseCertificateVerifier,
            b"inbound first before one-time replacement identity change",
        )
        .unwrap();
        assert!(first.used_one_time_pre_key);

        let sender_jid = "123:7@s.whatsapp.net";
        let chat_jid = "123@s.whatsapp.net";
        let provider = StoreSignalSenderKeyProvider::new(receiver_store.clone());
        let codec = SignalMessageCodec::new(
            StoreSignalRepository::new(receiver_store.clone()),
            provider.clone(),
        );
        let first_plaintext = codec
            .decrypt_inbound_message(InboundEncryptedPayload {
                sender_jid: sender_jid.to_owned(),
                chat_jid: chat_jid.to_owned(),
                ciphertext_type: InboundCiphertextType::PreKey,
                ciphertext: first.message_bytes,
            })
            .await
            .unwrap();
        assert_eq!(
            first_plaintext,
            Bytes::from_static(b"inbound first before one-time replacement identity change")
        );
        let established_record = provider_probe
            .load_session_record(sender_jid)
            .await
            .unwrap()
            .unwrap();
        let established_identity = provider_probe
            .load_identity_record(sender_jid)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(established_identity, sender_material.identity.public_key);

        let changed_sender_material =
            signal_local_key_material(create_initial_credentials().unwrap());
        assert_ne!(
            changed_sender_material.identity.public_key,
            established_identity
        );
        let replacement_session = SignalSession {
            registration_id: receiver_credentials.registration_id,
            identity_key: Bytes::copy_from_slice(&receiver_credentials.signed_identity_key.public),
            signed_pre_key: SignalSignedPreKey {
                key_id: receiver_credentials.signed_pre_key.key_id,
                public_key: Bytes::copy_from_slice(
                    &receiver_credentials.signed_pre_key.key_pair.public,
                ),
                signature: receiver_credentials.signed_pre_key.signature.clone(),
            },
            pre_key: Some(SignalPreKey {
                key_id: replacement_pre_key_id,
                public_key: replacement_pre_key.public_key.clone(),
            }),
        };
        let changed_identity_replacement = encrypt_signal_outbound_pre_key_session_message(
            &changed_sender_material,
            &generate_key_pair(),
            &replacement_session,
            &XEdDsaNoiseCertificateVerifier,
            b"inbound one-time replacement changed identity",
        )
        .unwrap();
        assert!(changed_identity_replacement.used_one_time_pre_key);
        assert_eq!(
            changed_identity_replacement.message.pre_key_id,
            Some(replacement_pre_key_id)
        );

        let err = codec
            .decrypt_inbound_message(InboundEncryptedPayload {
                sender_jid: sender_jid.to_owned(),
                chat_jid: chat_jid.to_owned(),
                ciphertext_type: InboundCiphertextType::PreKey,
                ciphertext: changed_identity_replacement.message_bytes,
            })
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            CoreError::Protocol(message) if message == "Signal provider identity changed for 123.7"
        ));
        assert_eq!(
            provider_probe
                .load_session_record(sender_jid)
                .await
                .unwrap()
                .unwrap(),
            established_record
        );
        assert_eq!(
            provider_probe
                .load_identity_record(sender_jid)
                .await
                .unwrap()
                .unwrap(),
            established_identity
        );
        assert_eq!(
            provider_probe
                .load_local_pre_key(replacement_pre_key_id)
                .await
                .unwrap(),
            Some(replacement_pre_key.clone())
        );

        let old_session_second = encrypt_signal_provider_session_record_message(
            &first.record,
            b"old session still decrypts after one-time identity change",
        )
        .unwrap();
        let old_plaintext = codec
            .decrypt_inbound_message(InboundEncryptedPayload {
                sender_jid: sender_jid.to_owned(),
                chat_jid: chat_jid.to_owned(),
                ciphertext_type: InboundCiphertextType::Message,
                ciphertext: old_session_second.message_bytes,
            })
            .await
            .unwrap();
        assert_eq!(
            old_plaintext,
            Bytes::from_static(b"old session still decrypts after one-time identity change")
        );

        let valid_replacement_base_key = generate_key_pair();
        let valid_replacement = encrypt_signal_outbound_pre_key_session_message(
            &sender_material,
            &valid_replacement_base_key,
            &replacement_session,
            &XEdDsaNoiseCertificateVerifier,
            b"inbound one-time replacement after identity change",
        )
        .unwrap();
        let valid_plaintext = codec
            .decrypt_inbound_message(InboundEncryptedPayload {
                sender_jid: sender_jid.to_owned(),
                chat_jid: chat_jid.to_owned(),
                ciphertext_type: InboundCiphertextType::PreKey,
                ciphertext: valid_replacement.message_bytes,
            })
            .await
            .unwrap();
        assert_eq!(
            valid_plaintext,
            Bytes::from_static(b"inbound one-time replacement after identity change")
        );
        assert!(
            provider_probe
                .load_local_pre_key(replacement_pre_key_id)
                .await
                .unwrap()
                .is_none()
        );
        let replacement_record = provider_probe
            .load_session_record(sender_jid)
            .await
            .unwrap()
            .unwrap();
        let replacement_record =
            decode_signal_provider_session_record(&replacement_record).unwrap();
        assert_eq!(
            replacement_record.remote_ratchet_key,
            Some(Bytes::copy_from_slice(&prefixed_signal_public_key(
                &valid_replacement_base_key.public
            )))
        );
        assert_eq!(
            provider_probe
                .load_identity_record(sender_jid)
                .await
                .unwrap()
                .unwrap(),
            established_identity
        );
    }

    #[tokio::test]
    async fn store_signal_provider_decrypts_out_of_order_session_messages_from_store() {
        let receiver_store = temp_store().await;
        let receiver_credentials = create_initial_credentials().unwrap();
        save_credentials(&receiver_store, receiver_credentials.clone())
            .await
            .unwrap();
        let upload = prepare_pre_key_upload(&receiver_store, &receiver_credentials, 1, "pre-key")
            .await
            .unwrap();
        let receiver_credentials = upload.credentials;
        save_credentials(&receiver_store, receiver_credentials.clone())
            .await
            .unwrap();
        let receiver_pre_key_id = upload.pre_key_ids[0];
        let provider_probe = SignalProviderStateStore::new(receiver_store.clone());
        let receiver_pre_key = provider_probe
            .load_local_pre_key(receiver_pre_key_id)
            .await
            .unwrap()
            .unwrap();

        let sender_credentials = create_initial_credentials().unwrap();
        let sender_material = signal_local_key_material(sender_credentials);
        let sender_base_key = generate_key_pair();
        let receiver_session = SignalSession {
            registration_id: receiver_credentials.registration_id,
            identity_key: Bytes::copy_from_slice(&receiver_credentials.signed_identity_key.public),
            signed_pre_key: SignalSignedPreKey {
                key_id: receiver_credentials.signed_pre_key.key_id,
                public_key: Bytes::copy_from_slice(
                    &receiver_credentials.signed_pre_key.key_pair.public,
                ),
                signature: receiver_credentials.signed_pre_key.signature.clone(),
            },
            pre_key: Some(SignalPreKey {
                key_id: receiver_pre_key_id,
                public_key: receiver_pre_key.public_key.clone(),
            }),
        };
        let first = encrypt_signal_outbound_pre_key_session_message(
            &sender_material,
            &sender_base_key,
            &receiver_session,
            &XEdDsaNoiseCertificateVerifier,
            b"inbound first",
        )
        .unwrap();
        let second =
            encrypt_signal_provider_session_record_message(&first.record, b"inbound second")
                .unwrap();
        let third =
            encrypt_signal_provider_session_record_message(&second.record, b"inbound third")
                .unwrap();
        let fourth =
            encrypt_signal_provider_session_record_message(&third.record, b"inbound fourth")
                .unwrap();
        let sender_jid = "123:7@s.whatsapp.net";
        let chat_jid = "123@s.whatsapp.net";

        let first_provider = StoreSignalSenderKeyProvider::new(receiver_store.clone());
        let first_codec = SignalMessageCodec::new(
            StoreSignalRepository::new(receiver_store.clone()),
            first_provider,
        );
        assert_eq!(
            first_codec
                .decrypt_inbound_message(InboundEncryptedPayload {
                    sender_jid: sender_jid.to_owned(),
                    chat_jid: chat_jid.to_owned(),
                    ciphertext_type: InboundCiphertextType::PreKey,
                    ciphertext: first.message_bytes,
                })
                .await
                .unwrap(),
            Bytes::from_static(b"inbound first")
        );

        let third_provider = StoreSignalSenderKeyProvider::new(receiver_store.clone());
        let third_codec = SignalMessageCodec::new(
            StoreSignalRepository::new(receiver_store.clone()),
            third_provider,
        );
        assert_eq!(
            third_codec
                .decrypt_inbound_message(InboundEncryptedPayload {
                    sender_jid: sender_jid.to_owned(),
                    chat_jid: chat_jid.to_owned(),
                    ciphertext_type: InboundCiphertextType::Message,
                    ciphertext: third.message_bytes,
                })
                .await
                .unwrap(),
            Bytes::from_static(b"inbound third")
        );
        let stored_after_third = provider_probe
            .load_session_record(sender_jid)
            .await
            .unwrap()
            .unwrap();
        let stored_after_third =
            decode_signal_provider_session_record(&stored_after_third).unwrap();
        assert_eq!(
            stored_after_third.receiving_chain.as_ref().unwrap().counter,
            3
        );
        assert_eq!(stored_after_third.message_keys.len(), 1);
        assert_eq!(stored_after_third.message_keys[0].counter, 2);

        let second_provider = StoreSignalSenderKeyProvider::new(receiver_store.clone());
        let second_codec = SignalMessageCodec::new(
            StoreSignalRepository::new(receiver_store.clone()),
            second_provider,
        );
        assert_eq!(
            second_codec
                .decrypt_inbound_message(InboundEncryptedPayload {
                    sender_jid: sender_jid.to_owned(),
                    chat_jid: chat_jid.to_owned(),
                    ciphertext_type: InboundCiphertextType::Message,
                    ciphertext: second.message_bytes.clone(),
                })
                .await
                .unwrap(),
            Bytes::from_static(b"inbound second")
        );
        let stored_after_second_bytes = provider_probe
            .load_session_record(sender_jid)
            .await
            .unwrap()
            .unwrap();
        let stored_after_second =
            decode_signal_provider_session_record(&stored_after_second_bytes).unwrap();
        assert!(stored_after_second.message_keys.is_empty());
        assert_eq!(
            stored_after_second
                .receiving_chain
                .as_ref()
                .unwrap()
                .counter,
            3
        );
        let replay_err = second_codec
            .decrypt_inbound_message(InboundEncryptedPayload {
                sender_jid: sender_jid.to_owned(),
                chat_jid: chat_jid.to_owned(),
                ciphertext_type: InboundCiphertextType::Message,
                ciphertext: second.message_bytes,
            })
            .await
            .unwrap_err();
        assert!(matches!(
            replay_err,
            CoreError::Protocol(message)
                if message == "duplicate or old Signal message counter: 2"
        ));
        assert_eq!(
            provider_probe
                .load_session_record(sender_jid)
                .await
                .unwrap()
                .unwrap(),
            stored_after_second_bytes
        );

        let fourth_provider = StoreSignalSenderKeyProvider::new(receiver_store.clone());
        let fourth_codec =
            SignalMessageCodec::new(StoreSignalRepository::new(receiver_store), fourth_provider);
        assert_eq!(
            fourth_codec
                .decrypt_inbound_message(InboundEncryptedPayload {
                    sender_jid: sender_jid.to_owned(),
                    chat_jid: chat_jid.to_owned(),
                    ciphertext_type: InboundCiphertextType::Message,
                    ciphertext: fourth.message_bytes,
                })
                .await
                .unwrap(),
            Bytes::from_static(b"inbound fourth")
        );
    }

    #[tokio::test]
    async fn store_signal_provider_prunes_oldest_skipped_message_keys_from_store() {
        let store = temp_store().await;
        let provider_store = SignalProviderStateStore::new(store.clone());
        let sender_jid = "123:7@s.whatsapp.net";
        let sender_ratchet_key_pair = test_key_pair(31);
        let sender_ratchet_key =
            Bytes::copy_from_slice(&prefixed_signal_public_key(&sender_ratchet_key_pair.public));
        let mut chain = SignalMessageChainKey {
            key: SecretBytes::from(vec![7u8; 32]),
            counter: 0,
        };
        let target_counter = u32::try_from(SIGNAL_MAX_PROVIDER_MESSAGE_KEYS).unwrap() + 2;
        let mut first_keys = None;
        let mut second_keys = None;
        let mut target_keys = None;
        while chain.counter < target_counter {
            let step = ratchet_signal_message_chain(&chain).unwrap();
            match step.message_counter {
                1 => first_keys = Some(step.message_keys.clone()),
                2 => second_keys = Some(step.message_keys.clone()),
                value if value == target_counter => target_keys = Some(step.message_keys.clone()),
                _ => {}
            }
            chain = step.next_chain_key;
        }
        let first = encode_signal_whisper_message(&SignalWhisperMessage {
            ephemeral_key: sender_ratchet_key.clone(),
            counter: 1,
            previous_counter: 0,
            ciphertext: encrypt_signal_message_body(b"inbound first", &first_keys.unwrap())
                .unwrap(),
        })
        .unwrap();
        let second = encode_signal_whisper_message(&SignalWhisperMessage {
            ephemeral_key: sender_ratchet_key.clone(),
            counter: 2,
            previous_counter: 0,
            ciphertext: encrypt_signal_message_body(b"inbound second", &second_keys.unwrap())
                .unwrap(),
        })
        .unwrap();
        let target = encode_signal_whisper_message(&SignalWhisperMessage {
            ephemeral_key: sender_ratchet_key.clone(),
            counter: target_counter,
            previous_counter: 0,
            ciphertext: encrypt_signal_message_body(b"inbound target", &target_keys.unwrap())
                .unwrap(),
        })
        .unwrap();
        let receiver_record = SignalProviderSessionRecord {
            remote_registration_id: 88,
            remote_identity_key: prefixed_test_signal_key(21),
            root_key: SignalRootKey {
                key: SecretBytes::from(vec![9u8; 32]),
            },
            sending_chain: uninitialized_signal_message_chain(),
            receiving_chain: Some(SignalMessageChainKey {
                key: SecretBytes::from(vec![7u8; 32]),
                counter: 0,
            }),
            remote_ratchet_key: Some(sender_ratchet_key),
            local_ratchet_key_pair: test_key_pair(41),
            previous_counter: 0,
            message_keys: Vec::new(),
        };
        provider_store
            .store_session_and_identity_records(
                sender_jid,
                &encode_signal_provider_session_record(&receiver_record).unwrap(),
                &receiver_record.remote_identity_key,
            )
            .await
            .unwrap();

        let target_decrypted = provider_store
            .decrypt_session_record_message(sender_jid, target)
            .await
            .unwrap();
        assert_eq!(
            target_decrypted.plaintext,
            Bytes::from_static(b"inbound target")
        );
        let stored_after_target = provider_store
            .load_session_record(sender_jid)
            .await
            .unwrap()
            .unwrap();
        let stored_after_target =
            decode_signal_provider_session_record(&stored_after_target).unwrap();
        assert_eq!(
            stored_after_target.message_keys.len(),
            SIGNAL_MAX_PROVIDER_MESSAGE_KEYS
        );
        assert_eq!(stored_after_target.message_keys[0].counter, 2);
        assert_eq!(
            stored_after_target.message_keys.last().unwrap().counter,
            target_counter - 1
        );

        let err = provider_store
            .decrypt_session_record_message(sender_jid, first)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            CoreError::Protocol(message)
                if message == "duplicate or old Signal message counter: 1"
        ));
        let stored_after_pruned_replay = provider_store
            .load_session_record(sender_jid)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            decode_signal_provider_session_record(&stored_after_pruned_replay).unwrap(),
            stored_after_target
        );

        let second_decrypted = provider_store
            .decrypt_session_record_message(sender_jid, second)
            .await
            .unwrap();
        assert_eq!(
            second_decrypted.plaintext,
            Bytes::from_static(b"inbound second")
        );
        let stored_after_second = provider_store
            .load_session_record(sender_jid)
            .await
            .unwrap()
            .unwrap();
        let stored_after_second =
            decode_signal_provider_session_record(&stored_after_second).unwrap();
        assert_eq!(
            stored_after_second.message_keys.len(),
            SIGNAL_MAX_PROVIDER_MESSAGE_KEYS - 1
        );
        assert_eq!(stored_after_second.message_keys[0].counter, 3);
    }

    #[tokio::test]
    async fn store_signal_provider_rejects_stale_previous_counter_without_mutation() {
        let store = temp_store().await;
        let provider_store = SignalProviderStateStore::new(store);
        let sender_jid = "123:7@s.whatsapp.net";
        let sender_ratchet_key_pair = test_key_pair(31);
        let sender_ratchet_key =
            Bytes::copy_from_slice(&prefixed_signal_public_key(&sender_ratchet_key_pair.public));
        let initial_chain = SignalMessageChainKey {
            key: SecretBytes::from(vec![7u8; 32]),
            counter: 0,
        };
        let first_step = ratchet_signal_message_chain(&initial_chain).unwrap();
        let second_step = ratchet_signal_message_chain(&first_step.next_chain_key).unwrap();
        let third_step = ratchet_signal_message_chain(&second_step.next_chain_key).unwrap();
        let receiver_record = SignalProviderSessionRecord {
            remote_registration_id: 88,
            remote_identity_key: prefixed_test_signal_key(21),
            root_key: SignalRootKey {
                key: SecretBytes::from(vec![9u8; 32]),
            },
            sending_chain: uninitialized_signal_message_chain(),
            receiving_chain: Some(second_step.next_chain_key.clone()),
            remote_ratchet_key: Some(sender_ratchet_key.clone()),
            local_ratchet_key_pair: test_key_pair(41),
            previous_counter: 0,
            message_keys: Vec::new(),
        };
        let receiver_record_bytes =
            encode_signal_provider_session_record(&receiver_record).unwrap();
        provider_store
            .store_session_and_identity_records(
                sender_jid,
                &receiver_record_bytes,
                &receiver_record.remote_identity_key,
            )
            .await
            .unwrap();

        let stale_previous_counter = SignalWhisperMessage {
            ephemeral_key: Bytes::copy_from_slice(&prefixed_signal_public_key(
                &test_key_pair(51).public,
            )),
            counter: 1,
            previous_counter: 1,
            ciphertext: Bytes::from_static(b"stale-previous-counter"),
        };
        let err = provider_store
            .decrypt_session_record_message(
                sender_jid,
                encode_signal_whisper_message(&stale_previous_counter).unwrap(),
            )
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            CoreError::Protocol(message)
                if message == "Signal previous chain counter moved backwards: message 1, current 2"
        ));
        assert_eq!(
            provider_store
                .load_session_record(sender_jid)
                .await
                .unwrap()
                .unwrap(),
            receiver_record_bytes
        );

        let third = encode_signal_whisper_message(&SignalWhisperMessage {
            ephemeral_key: sender_ratchet_key,
            counter: 3,
            previous_counter: 0,
            ciphertext: encrypt_signal_message_body(b"inbound third", &third_step.message_keys)
                .unwrap(),
        })
        .unwrap();
        let decrypted = provider_store
            .decrypt_session_record_message(sender_jid, third)
            .await
            .unwrap();
        assert_eq!(decrypted.plaintext, Bytes::from_static(b"inbound third"));
    }

    #[tokio::test]
    async fn store_signal_provider_rejects_far_future_counters_without_mutation() {
        let store = temp_store().await;
        let provider_store = SignalProviderStateStore::new(store);
        let active_sender_jid = "123:7@s.whatsapp.net";
        let sender_ratchet_key_pair = test_key_pair(31);
        let sender_ratchet_key =
            Bytes::copy_from_slice(&prefixed_signal_public_key(&sender_ratchet_key_pair.public));
        let sender_record = SignalProviderSessionRecord {
            remote_registration_id: 88,
            remote_identity_key: prefixed_test_signal_key(21),
            root_key: SignalRootKey {
                key: SecretBytes::from(vec![9u8; 32]),
            },
            sending_chain: SignalMessageChainKey {
                key: SecretBytes::from(vec![7u8; 32]),
                counter: 0,
            },
            receiving_chain: None,
            remote_ratchet_key: None,
            local_ratchet_key_pair: sender_ratchet_key_pair.clone(),
            previous_counter: 0,
            message_keys: Vec::new(),
        };
        let first = encrypt_signal_provider_session_record_message(
            &encode_signal_provider_session_record(&sender_record).unwrap(),
            b"inbound first",
        )
        .unwrap();
        let receiver_record = SignalProviderSessionRecord {
            remote_registration_id: 88,
            remote_identity_key: prefixed_test_signal_key(21),
            root_key: SignalRootKey {
                key: SecretBytes::from(vec![9u8; 32]),
            },
            sending_chain: uninitialized_signal_message_chain(),
            receiving_chain: Some(SignalMessageChainKey {
                key: SecretBytes::from(vec![7u8; 32]),
                counter: 0,
            }),
            remote_ratchet_key: Some(sender_ratchet_key.clone()),
            local_ratchet_key_pair: test_key_pair(41),
            previous_counter: 0,
            message_keys: Vec::new(),
        };
        let receiver_record_bytes =
            encode_signal_provider_session_record(&receiver_record).unwrap();
        provider_store
            .store_session_and_identity_records(
                active_sender_jid,
                &receiver_record_bytes,
                &receiver_record.remote_identity_key,
            )
            .await
            .unwrap();

        let far_future = SignalWhisperMessage {
            ephemeral_key: sender_ratchet_key,
            counter: SIGNAL_MAX_MESSAGE_FORWARD_JUMPS + 1,
            previous_counter: 0,
            ciphertext: Bytes::from_static(b"far-future-ciphertext"),
        };
        let err = provider_store
            .decrypt_session_record_message(
                active_sender_jid,
                encode_signal_whisper_message(&far_future).unwrap(),
            )
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            CoreError::Protocol(message)
                if message == "Signal message is too far in the future: 25001"
        ));
        assert_eq!(
            provider_store
                .load_session_record(active_sender_jid)
                .await
                .unwrap()
                .unwrap(),
            receiver_record_bytes
        );
        let decrypted = provider_store
            .decrypt_session_record_message(active_sender_jid, first.message_bytes)
            .await
            .unwrap();
        assert_eq!(decrypted.plaintext, Bytes::from_static(b"inbound first"));

        let previous_sender_jid = "456:7@s.whatsapp.net";
        let sender_ratchet_key_pair = test_key_pair(51);
        let sender_ratchet_key =
            Bytes::copy_from_slice(&prefixed_signal_public_key(&sender_ratchet_key_pair.public));
        let sender_record = SignalProviderSessionRecord {
            remote_registration_id: 89,
            remote_identity_key: prefixed_test_signal_key(22),
            root_key: SignalRootKey {
                key: SecretBytes::from(vec![11u8; 32]),
            },
            sending_chain: SignalMessageChainKey {
                key: SecretBytes::from(vec![13u8; 32]),
                counter: 0,
            },
            receiving_chain: None,
            remote_ratchet_key: None,
            local_ratchet_key_pair: sender_ratchet_key_pair.clone(),
            previous_counter: 0,
            message_keys: Vec::new(),
        };
        let first = encrypt_signal_provider_session_record_message(
            &encode_signal_provider_session_record(&sender_record).unwrap(),
            b"inbound previous first",
        )
        .unwrap();
        let receiver_record = SignalProviderSessionRecord {
            remote_registration_id: 89,
            remote_identity_key: prefixed_test_signal_key(22),
            root_key: SignalRootKey {
                key: SecretBytes::from(vec![11u8; 32]),
            },
            sending_chain: uninitialized_signal_message_chain(),
            receiving_chain: Some(SignalMessageChainKey {
                key: SecretBytes::from(vec![13u8; 32]),
                counter: 0,
            }),
            remote_ratchet_key: Some(sender_ratchet_key),
            local_ratchet_key_pair: test_key_pair(61),
            previous_counter: 0,
            message_keys: Vec::new(),
        };
        let receiver_record_bytes =
            encode_signal_provider_session_record(&receiver_record).unwrap();
        provider_store
            .store_session_and_identity_records(
                previous_sender_jid,
                &receiver_record_bytes,
                &receiver_record.remote_identity_key,
            )
            .await
            .unwrap();

        let far_future = SignalWhisperMessage {
            ephemeral_key: Bytes::copy_from_slice(&prefixed_signal_public_key(
                &test_key_pair(71).public,
            )),
            counter: 1,
            previous_counter: SIGNAL_MAX_MESSAGE_FORWARD_JUMPS + 1,
            ciphertext: Bytes::from_static(b"far-future-previous-ciphertext"),
        };
        let err = provider_store
            .decrypt_session_record_message(
                previous_sender_jid,
                encode_signal_whisper_message(&far_future).unwrap(),
            )
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            CoreError::Protocol(message)
                if message == "Signal previous chain is too far in the future: 25001"
        ));
        assert_eq!(
            provider_store
                .load_session_record(previous_sender_jid)
                .await
                .unwrap()
                .unwrap(),
            receiver_record_bytes
        );
        let decrypted = provider_store
            .decrypt_session_record_message(previous_sender_jid, first.message_bytes)
            .await
            .unwrap();
        assert_eq!(
            decrypted.plaintext,
            Bytes::from_static(b"inbound previous first")
        );
    }

    #[tokio::test]
    async fn store_signal_provider_persists_previous_chain_skipped_keys_after_ratchet() {
        let receiver_store = temp_store().await;
        let receiver_credentials = create_initial_credentials().unwrap();
        save_credentials(&receiver_store, receiver_credentials.clone())
            .await
            .unwrap();
        let upload = prepare_pre_key_upload(&receiver_store, &receiver_credentials, 1, "pre-key")
            .await
            .unwrap();
        let receiver_credentials = upload.credentials;
        save_credentials(&receiver_store, receiver_credentials.clone())
            .await
            .unwrap();
        let receiver_pre_key_id = upload.pre_key_ids[0];
        let receiver_probe = SignalProviderStateStore::new(receiver_store.clone());
        let receiver_pre_key = receiver_probe
            .load_local_pre_key(receiver_pre_key_id)
            .await
            .unwrap()
            .unwrap();

        let sender_credentials = create_initial_credentials().unwrap();
        let sender_material = signal_local_key_material(sender_credentials);
        let sender_base_key = generate_key_pair();
        let receiver_session = SignalSession {
            registration_id: receiver_credentials.registration_id,
            identity_key: Bytes::copy_from_slice(&receiver_credentials.signed_identity_key.public),
            signed_pre_key: SignalSignedPreKey {
                key_id: receiver_credentials.signed_pre_key.key_id,
                public_key: Bytes::copy_from_slice(
                    &receiver_credentials.signed_pre_key.key_pair.public,
                ),
                signature: receiver_credentials.signed_pre_key.signature.clone(),
            },
            pre_key: Some(SignalPreKey {
                key_id: receiver_pre_key_id,
                public_key: receiver_pre_key.public_key.clone(),
            }),
        };
        let first = encrypt_signal_outbound_pre_key_session_message(
            &sender_material,
            &sender_base_key,
            &receiver_session,
            &XEdDsaNoiseCertificateVerifier,
            b"inbound first",
        )
        .unwrap();
        let second =
            encrypt_signal_provider_session_record_message(&first.record, b"inbound second")
                .unwrap();
        let sender_jid = "123:7@s.whatsapp.net";
        let chat_jid = "123@s.whatsapp.net";

        let first_provider = StoreSignalSenderKeyProvider::new(receiver_store.clone());
        let first_codec = SignalMessageCodec::new(
            StoreSignalRepository::new(receiver_store.clone()),
            first_provider,
        );
        assert_eq!(
            first_codec
                .decrypt_inbound_message(InboundEncryptedPayload {
                    sender_jid: sender_jid.to_owned(),
                    chat_jid: chat_jid.to_owned(),
                    ciphertext_type: InboundCiphertextType::PreKey,
                    ciphertext: first.message_bytes,
                })
                .await
                .unwrap(),
            Bytes::from_static(b"inbound first")
        );

        let reply_provider = SignalProviderStateStore::new(receiver_store.clone());
        let reply = reply_provider
            .encrypt_existing_session_record_message(sender_jid, Bytes::from_static(b"reply"))
            .await
            .unwrap()
            .unwrap();
        let sender_after_reply =
            decrypt_signal_provider_session_record_message(&second.record, &reply.message_bytes)
                .unwrap();
        let third = encrypt_signal_provider_session_record_message(
            &sender_after_reply.record,
            b"inbound third",
        )
        .unwrap();
        assert_eq!(third.message.previous_counter, 2);
        let fourth =
            encrypt_signal_provider_session_record_message(&third.record, b"inbound fourth")
                .unwrap();

        let third_provider = SignalProviderStateStore::new(receiver_store.clone());
        let third_decrypted = third_provider
            .decrypt_session_record_message(sender_jid, third.message_bytes)
            .await
            .unwrap();
        assert_eq!(
            third_decrypted.plaintext,
            Bytes::from_static(b"inbound third")
        );
        let stored_after_third = SignalProviderStateStore::new(receiver_store.clone())
            .load_session_record(sender_jid)
            .await
            .unwrap()
            .unwrap();
        let stored_after_third =
            decode_signal_provider_session_record(&stored_after_third).unwrap();
        assert_eq!(stored_after_third.message_keys.len(), 1);
        assert_eq!(stored_after_third.message_keys[0].counter, 2);

        let second_provider = SignalProviderStateStore::new(receiver_store.clone());
        let second_decrypted = second_provider
            .decrypt_session_record_message(sender_jid, second.message_bytes)
            .await
            .unwrap();
        assert_eq!(
            second_decrypted.plaintext,
            Bytes::from_static(b"inbound second")
        );
        let stored_after_second = SignalProviderStateStore::new(receiver_store.clone())
            .load_session_record(sender_jid)
            .await
            .unwrap()
            .unwrap();
        let stored_after_second =
            decode_signal_provider_session_record(&stored_after_second).unwrap();
        assert!(stored_after_second.message_keys.is_empty());
        assert_eq!(
            stored_after_second.remote_ratchet_key,
            Some(third.message.ephemeral_key)
        );
        assert_eq!(
            stored_after_second
                .receiving_chain
                .as_ref()
                .unwrap()
                .counter,
            1
        );

        let fourth_provider = SignalProviderStateStore::new(receiver_store);
        let fourth_decrypted = fourth_provider
            .decrypt_session_record_message(sender_jid, fourth.message_bytes)
            .await
            .unwrap();
        assert_eq!(
            fourth_decrypted.plaintext,
            Bytes::from_static(b"inbound fourth")
        );
    }

    #[tokio::test]
    async fn store_signal_provider_consumes_multiple_previous_chain_skipped_keys_after_ratchet() {
        let receiver_store = temp_store().await;
        let receiver_credentials = create_initial_credentials().unwrap();
        save_credentials(&receiver_store, receiver_credentials.clone())
            .await
            .unwrap();
        let upload = prepare_pre_key_upload(&receiver_store, &receiver_credentials, 1, "pre-key")
            .await
            .unwrap();
        let receiver_credentials = upload.credentials;
        save_credentials(&receiver_store, receiver_credentials.clone())
            .await
            .unwrap();
        let receiver_pre_key_id = upload.pre_key_ids[0];
        let receiver_probe = SignalProviderStateStore::new(receiver_store.clone());
        let receiver_pre_key = receiver_probe
            .load_local_pre_key(receiver_pre_key_id)
            .await
            .unwrap()
            .unwrap();

        let sender_credentials = create_initial_credentials().unwrap();
        let sender_material = signal_local_key_material(sender_credentials);
        let sender_base_key = generate_key_pair();
        let receiver_session = SignalSession {
            registration_id: receiver_credentials.registration_id,
            identity_key: Bytes::copy_from_slice(&receiver_credentials.signed_identity_key.public),
            signed_pre_key: SignalSignedPreKey {
                key_id: receiver_credentials.signed_pre_key.key_id,
                public_key: Bytes::copy_from_slice(
                    &receiver_credentials.signed_pre_key.key_pair.public,
                ),
                signature: receiver_credentials.signed_pre_key.signature.clone(),
            },
            pre_key: Some(SignalPreKey {
                key_id: receiver_pre_key_id,
                public_key: receiver_pre_key.public_key.clone(),
            }),
        };
        let first = encrypt_signal_outbound_pre_key_session_message(
            &sender_material,
            &sender_base_key,
            &receiver_session,
            &XEdDsaNoiseCertificateVerifier,
            b"inbound first",
        )
        .unwrap();
        let second =
            encrypt_signal_provider_session_record_message(&first.record, b"inbound second")
                .unwrap();
        let old_third =
            encrypt_signal_provider_session_record_message(&second.record, b"inbound old third")
                .unwrap();
        assert_eq!(old_third.message.counter, 3);

        let sender_jid = "123:7@s.whatsapp.net";
        let chat_jid = "123@s.whatsapp.net";
        let first_codec = SignalMessageCodec::new(
            StoreSignalRepository::new(receiver_store.clone()),
            StoreSignalSenderKeyProvider::new(receiver_store.clone()),
        );
        assert_eq!(
            first_codec
                .decrypt_inbound_message(InboundEncryptedPayload {
                    sender_jid: sender_jid.to_owned(),
                    chat_jid: chat_jid.to_owned(),
                    ciphertext_type: InboundCiphertextType::PreKey,
                    ciphertext: first.message_bytes,
                })
                .await
                .unwrap(),
            Bytes::from_static(b"inbound first")
        );

        let reply_provider = SignalProviderStateStore::new(receiver_store.clone());
        let reply = reply_provider
            .encrypt_existing_session_record_message(sender_jid, Bytes::from_static(b"reply"))
            .await
            .unwrap()
            .unwrap();
        let sender_after_reply =
            decrypt_signal_provider_session_record_message(&old_third.record, &reply.message_bytes)
                .unwrap();
        let fourth = encrypt_signal_provider_session_record_message(
            &sender_after_reply.record,
            b"inbound fourth",
        )
        .unwrap();
        assert_eq!(fourth.message.previous_counter, 3);
        let fifth =
            encrypt_signal_provider_session_record_message(&fourth.record, b"inbound fifth")
                .unwrap();

        let fourth_provider = SignalProviderStateStore::new(receiver_store.clone());
        let fourth_decrypted = fourth_provider
            .decrypt_session_record_message(sender_jid, fourth.message_bytes)
            .await
            .unwrap();
        assert_eq!(
            fourth_decrypted.plaintext,
            Bytes::from_static(b"inbound fourth")
        );
        let stored_after_fourth = SignalProviderStateStore::new(receiver_store.clone())
            .load_session_record(sender_jid)
            .await
            .unwrap()
            .unwrap();
        let stored_after_fourth =
            decode_signal_provider_session_record(&stored_after_fourth).unwrap();
        assert_eq!(
            stored_after_fourth.remote_ratchet_key,
            Some(fourth.message.ephemeral_key.clone())
        );
        assert_eq!(
            stored_after_fourth
                .receiving_chain
                .as_ref()
                .unwrap()
                .counter,
            1
        );
        assert_eq!(
            stored_after_fourth
                .message_keys
                .iter()
                .map(|message_key| message_key.counter)
                .collect::<Vec<_>>(),
            vec![2, 3]
        );
        let stored_after_fourth_bytes = SignalProviderStateStore::new(receiver_store.clone())
            .load_session_record(sender_jid)
            .await
            .unwrap()
            .unwrap();

        let mut tampered_old_third =
            decode_signal_whisper_message(&old_third.message_bytes).unwrap();
        let mut tampered_ciphertext = tampered_old_third.ciphertext.to_vec();
        *tampered_ciphertext.last_mut().unwrap() ^= 1;
        tampered_old_third.ciphertext = Bytes::from(tampered_ciphertext);
        let tampered_old_third = encode_signal_whisper_message(&tampered_old_third).unwrap();
        let tampered_old_third_provider = SignalProviderStateStore::new(receiver_store.clone());
        let err = tampered_old_third_provider
            .decrypt_session_record_message(sender_jid, tampered_old_third)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            CoreError::Crypto(wa_crypto::CryptoError::Decrypt)
        ));
        assert_eq!(
            SignalProviderStateStore::new(receiver_store.clone())
                .load_session_record(sender_jid)
                .await
                .unwrap()
                .unwrap(),
            stored_after_fourth_bytes
        );

        let old_third_provider = SignalProviderStateStore::new(receiver_store.clone());
        let old_third_decrypted = old_third_provider
            .decrypt_session_record_message(sender_jid, old_third.message_bytes.clone())
            .await
            .unwrap();
        assert_eq!(
            old_third_decrypted.plaintext,
            Bytes::from_static(b"inbound old third")
        );
        let stored_after_old_third_bytes = SignalProviderStateStore::new(receiver_store.clone())
            .load_session_record(sender_jid)
            .await
            .unwrap()
            .unwrap();
        let stored_after_old_third =
            decode_signal_provider_session_record(&stored_after_old_third_bytes).unwrap();
        assert_eq!(
            stored_after_old_third
                .message_keys
                .iter()
                .map(|message_key| message_key.counter)
                .collect::<Vec<_>>(),
            vec![2]
        );
        assert_eq!(
            stored_after_old_third.remote_ratchet_key,
            Some(fourth.message.ephemeral_key.clone())
        );

        let old_third_replay_provider = SignalProviderStateStore::new(receiver_store.clone());
        let replay_err = old_third_replay_provider
            .decrypt_session_record_message(sender_jid, old_third.message_bytes)
            .await
            .unwrap_err();
        assert!(matches!(
            replay_err,
            CoreError::Protocol(message)
                if message == "Signal previous chain counter moved backwards: message 0, current 1"
        ));
        assert_eq!(
            SignalProviderStateStore::new(receiver_store.clone())
                .load_session_record(sender_jid)
                .await
                .unwrap()
                .unwrap(),
            stored_after_old_third_bytes
        );

        let second_provider = SignalProviderStateStore::new(receiver_store.clone());
        let second_decrypted = second_provider
            .decrypt_session_record_message(sender_jid, second.message_bytes)
            .await
            .unwrap();
        assert_eq!(
            second_decrypted.plaintext,
            Bytes::from_static(b"inbound second")
        );
        let stored_after_second = SignalProviderStateStore::new(receiver_store.clone())
            .load_session_record(sender_jid)
            .await
            .unwrap()
            .unwrap();
        let stored_after_second =
            decode_signal_provider_session_record(&stored_after_second).unwrap();
        assert!(stored_after_second.message_keys.is_empty());
        assert_eq!(
            stored_after_second.remote_ratchet_key,
            Some(fourth.message.ephemeral_key)
        );
        assert_eq!(
            stored_after_second
                .receiving_chain
                .as_ref()
                .unwrap()
                .counter,
            1
        );

        let fifth_provider = SignalProviderStateStore::new(receiver_store);
        let fifth_decrypted = fifth_provider
            .decrypt_session_record_message(sender_jid, fifth.message_bytes)
            .await
            .unwrap();
        assert_eq!(
            fifth_decrypted.plaintext,
            Bytes::from_static(b"inbound fifth")
        );
        let stored_after_fifth = fifth_provider
            .load_session_record(sender_jid)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            decode_signal_provider_session_record(&stored_after_fifth)
                .unwrap()
                .receiving_chain
                .as_ref()
                .unwrap()
                .counter,
            2
        );
    }

    #[tokio::test]
    async fn store_signal_provider_preserves_state_after_failed_pre_key_decrypt() {
        let receiver_store = temp_store().await;
        let receiver_credentials = create_initial_credentials().unwrap();
        save_credentials(&receiver_store, receiver_credentials.clone())
            .await
            .unwrap();
        let upload = prepare_pre_key_upload(&receiver_store, &receiver_credentials, 1, "pre-key")
            .await
            .unwrap();
        let receiver_credentials = upload.credentials;
        save_credentials(&receiver_store, receiver_credentials.clone())
            .await
            .unwrap();
        let receiver_pre_key_id = upload.pre_key_ids[0];
        let provider_probe = SignalProviderStateStore::new(receiver_store.clone());
        let receiver_pre_key = provider_probe
            .load_local_pre_key(receiver_pre_key_id)
            .await
            .unwrap()
            .unwrap();

        let sender_credentials = create_initial_credentials().unwrap();
        let sender_material = signal_local_key_material(sender_credentials);
        let sender_base_key = generate_key_pair();
        let receiver_session = SignalSession {
            registration_id: receiver_credentials.registration_id,
            identity_key: Bytes::copy_from_slice(&receiver_credentials.signed_identity_key.public),
            signed_pre_key: SignalSignedPreKey {
                key_id: receiver_credentials.signed_pre_key.key_id,
                public_key: Bytes::copy_from_slice(
                    &receiver_credentials.signed_pre_key.key_pair.public,
                ),
                signature: receiver_credentials.signed_pre_key.signature.clone(),
            },
            pre_key: Some(SignalPreKey {
                key_id: receiver_pre_key_id,
                public_key: receiver_pre_key.public_key.clone(),
            }),
        };
        let first = encrypt_signal_outbound_pre_key_session_message(
            &sender_material,
            &sender_base_key,
            &receiver_session,
            &XEdDsaNoiseCertificateVerifier,
            b"inbound first",
        )
        .unwrap();
        let mut tampered = decode_signal_pre_key_whisper_message(&first.message_bytes).unwrap();
        let mut tampered_ciphertext = tampered.message.ciphertext.to_vec();
        *tampered_ciphertext.last_mut().unwrap() ^= 1;
        tampered.message.ciphertext = Bytes::from(tampered_ciphertext);
        let tampered = encode_signal_pre_key_whisper_message(&tampered).unwrap();

        let sender_jid = "123:7@s.whatsapp.net";
        let provider = StoreSignalSenderKeyProvider::new(receiver_store.clone());
        let codec = SignalMessageCodec::new(StoreSignalRepository::new(receiver_store), provider);
        let err = codec
            .decrypt_inbound_message(InboundEncryptedPayload {
                sender_jid: sender_jid.to_owned(),
                chat_jid: "123@s.whatsapp.net".to_owned(),
                ciphertext_type: InboundCiphertextType::PreKey,
                ciphertext: tampered,
            })
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            CoreError::Crypto(wa_crypto::CryptoError::Decrypt)
        ));
        let mut mismatched_signed_pre_key =
            decode_signal_pre_key_whisper_message(&first.message_bytes).unwrap();
        mismatched_signed_pre_key.signed_pre_key_id =
            receiver_credentials.signed_pre_key.key_id.wrapping_add(1);
        let mismatched_signed_pre_key =
            encode_signal_pre_key_whisper_message(&mismatched_signed_pre_key).unwrap();
        let expected_signed_pre_key_error = format!(
            "Signal signed pre-key id mismatch: message {}, local {}",
            receiver_credentials.signed_pre_key.key_id.wrapping_add(1),
            receiver_credentials.signed_pre_key.key_id
        );
        let err = codec
            .decrypt_inbound_message(InboundEncryptedPayload {
                sender_jid: sender_jid.to_owned(),
                chat_jid: "123@s.whatsapp.net".to_owned(),
                ciphertext_type: InboundCiphertextType::PreKey,
                ciphertext: mismatched_signed_pre_key,
            })
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            CoreError::Protocol(message) if message == expected_signed_pre_key_error
        ));

        let receiver_session_without_one_time = SignalSession {
            pre_key: None,
            ..receiver_session
        };
        let signed_only = encrypt_signal_outbound_pre_key_session_message(
            &sender_material,
            &sender_base_key,
            &receiver_session_without_one_time,
            &XEdDsaNoiseCertificateVerifier,
            b"inbound signed-pre-key-only failure",
        )
        .unwrap();
        assert!(!signed_only.used_one_time_pre_key);
        assert_eq!(signed_only.message.pre_key_id, None);
        let mut tampered_signed_only =
            decode_signal_pre_key_whisper_message(&signed_only.message_bytes).unwrap();
        let mut tampered_signed_only_ciphertext = tampered_signed_only.message.ciphertext.to_vec();
        *tampered_signed_only_ciphertext.last_mut().unwrap() ^= 1;
        tampered_signed_only.message.ciphertext = Bytes::from(tampered_signed_only_ciphertext);
        let tampered_signed_only =
            encode_signal_pre_key_whisper_message(&tampered_signed_only).unwrap();
        let err = codec
            .decrypt_inbound_message(InboundEncryptedPayload {
                sender_jid: sender_jid.to_owned(),
                chat_jid: "123@s.whatsapp.net".to_owned(),
                ciphertext_type: InboundCiphertextType::PreKey,
                ciphertext: tampered_signed_only,
            })
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            CoreError::Crypto(wa_crypto::CryptoError::Decrypt)
        ));

        assert_eq!(
            provider_probe
                .load_local_pre_key(receiver_pre_key_id)
                .await
                .unwrap(),
            Some(receiver_pre_key)
        );
        assert!(
            provider_probe
                .load_session_record(sender_jid)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            provider_probe
                .load_identity_record(sender_jid)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn store_signal_provider_preserves_session_after_failed_message_decrypt() {
        let receiver_store = temp_store().await;
        let receiver_credentials = create_initial_credentials().unwrap();
        save_credentials(&receiver_store, receiver_credentials.clone())
            .await
            .unwrap();
        let upload = prepare_pre_key_upload(&receiver_store, &receiver_credentials, 1, "pre-key")
            .await
            .unwrap();
        let receiver_credentials = upload.credentials;
        save_credentials(&receiver_store, receiver_credentials.clone())
            .await
            .unwrap();
        let receiver_pre_key_id = upload.pre_key_ids[0];
        let provider_probe = SignalProviderStateStore::new(receiver_store.clone());
        let receiver_pre_key = provider_probe
            .load_local_pre_key(receiver_pre_key_id)
            .await
            .unwrap()
            .unwrap();

        let sender_credentials = create_initial_credentials().unwrap();
        let sender_material = signal_local_key_material(sender_credentials);
        let sender_base_key = generate_key_pair();
        let receiver_session = SignalSession {
            registration_id: receiver_credentials.registration_id,
            identity_key: Bytes::copy_from_slice(&receiver_credentials.signed_identity_key.public),
            signed_pre_key: SignalSignedPreKey {
                key_id: receiver_credentials.signed_pre_key.key_id,
                public_key: Bytes::copy_from_slice(
                    &receiver_credentials.signed_pre_key.key_pair.public,
                ),
                signature: receiver_credentials.signed_pre_key.signature.clone(),
            },
            pre_key: Some(SignalPreKey {
                key_id: receiver_pre_key_id,
                public_key: receiver_pre_key.public_key.clone(),
            }),
        };
        let first = encrypt_signal_outbound_pre_key_session_message(
            &sender_material,
            &sender_base_key,
            &receiver_session,
            &XEdDsaNoiseCertificateVerifier,
            b"inbound first",
        )
        .unwrap();
        let sender_jid = "123:7@s.whatsapp.net";
        let provider = StoreSignalSenderKeyProvider::new(receiver_store.clone());
        let codec = SignalMessageCodec::new(
            StoreSignalRepository::new(receiver_store.clone()),
            provider.clone(),
        );
        let plaintext = codec
            .decrypt_inbound_message(InboundEncryptedPayload {
                sender_jid: sender_jid.to_owned(),
                chat_jid: "123@s.whatsapp.net".to_owned(),
                ciphertext_type: InboundCiphertextType::PreKey,
                ciphertext: first.message_bytes,
            })
            .await
            .unwrap();
        assert_eq!(plaintext, Bytes::from_static(b"inbound first"));
        let stored_record = provider_probe
            .load_session_record(sender_jid)
            .await
            .unwrap()
            .unwrap();

        let second =
            encrypt_signal_provider_session_record_message(&first.record, b"inbound second")
                .unwrap();
        let third =
            encrypt_signal_provider_session_record_message(&second.record, b"inbound third")
                .unwrap();
        let fourth =
            encrypt_signal_provider_session_record_message(&third.record, b"inbound fourth")
                .unwrap();
        let mut tampered = decode_signal_whisper_message(&third.message_bytes).unwrap();
        let mut tampered_ciphertext = tampered.ciphertext.to_vec();
        *tampered_ciphertext.last_mut().unwrap() ^= 1;
        tampered.ciphertext = Bytes::from(tampered_ciphertext);
        let tampered = encode_signal_whisper_message(&tampered).unwrap();
        let err = codec
            .decrypt_inbound_message(InboundEncryptedPayload {
                sender_jid: sender_jid.to_owned(),
                chat_jid: "123@s.whatsapp.net".to_owned(),
                ciphertext_type: InboundCiphertextType::Message,
                ciphertext: tampered,
            })
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            CoreError::Crypto(wa_crypto::CryptoError::Decrypt)
        ));
        assert_eq!(
            provider_probe
                .load_session_record(sender_jid)
                .await
                .unwrap()
                .unwrap(),
            stored_record
        );

        let plaintext = codec
            .decrypt_inbound_message(InboundEncryptedPayload {
                sender_jid: sender_jid.to_owned(),
                chat_jid: "123@s.whatsapp.net".to_owned(),
                ciphertext_type: InboundCiphertextType::Message,
                ciphertext: third.message_bytes,
            })
            .await
            .unwrap();
        assert_eq!(plaintext, Bytes::from_static(b"inbound third"));
        let stored_after_third_bytes = provider_probe
            .load_session_record(sender_jid)
            .await
            .unwrap()
            .unwrap();
        let stored_after_third =
            decode_signal_provider_session_record(&stored_after_third_bytes).unwrap();
        assert_eq!(
            stored_after_third.receiving_chain.as_ref().unwrap().counter,
            3
        );
        assert_eq!(stored_after_third.message_keys.len(), 1);
        assert_eq!(stored_after_third.message_keys[0].counter, 2);

        let mut tampered_skipped = decode_signal_whisper_message(&second.message_bytes).unwrap();
        let mut tampered_skipped_ciphertext = tampered_skipped.ciphertext.to_vec();
        *tampered_skipped_ciphertext.last_mut().unwrap() ^= 1;
        tampered_skipped.ciphertext = Bytes::from(tampered_skipped_ciphertext);
        let tampered_skipped = encode_signal_whisper_message(&tampered_skipped).unwrap();
        let err = codec
            .decrypt_inbound_message(InboundEncryptedPayload {
                sender_jid: sender_jid.to_owned(),
                chat_jid: "123@s.whatsapp.net".to_owned(),
                ciphertext_type: InboundCiphertextType::Message,
                ciphertext: tampered_skipped,
            })
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            CoreError::Crypto(wa_crypto::CryptoError::Decrypt)
        ));
        assert_eq!(
            provider_probe
                .load_session_record(sender_jid)
                .await
                .unwrap()
                .unwrap(),
            stored_after_third_bytes
        );

        let plaintext = codec
            .decrypt_inbound_message(InboundEncryptedPayload {
                sender_jid: sender_jid.to_owned(),
                chat_jid: "123@s.whatsapp.net".to_owned(),
                ciphertext_type: InboundCiphertextType::Message,
                ciphertext: second.message_bytes,
            })
            .await
            .unwrap();
        assert_eq!(plaintext, Bytes::from_static(b"inbound second"));
        let stored_after_second = provider_probe
            .load_session_record(sender_jid)
            .await
            .unwrap()
            .unwrap();
        let stored_after_second =
            decode_signal_provider_session_record(&stored_after_second).unwrap();
        assert!(stored_after_second.message_keys.is_empty());
        assert_eq!(
            stored_after_second
                .receiving_chain
                .as_ref()
                .unwrap()
                .counter,
            3
        );

        let plaintext = codec
            .decrypt_inbound_message(InboundEncryptedPayload {
                sender_jid: sender_jid.to_owned(),
                chat_jid: "123@s.whatsapp.net".to_owned(),
                ciphertext_type: InboundCiphertextType::Message,
                ciphertext: fourth.message_bytes,
            })
            .await
            .unwrap();
        assert_eq!(plaintext, Bytes::from_static(b"inbound fourth"));
        assert_ne!(
            provider_probe
                .load_session_record(sender_jid)
                .await
                .unwrap()
                .unwrap(),
            stored_record
        );
    }

    #[tokio::test]
    async fn store_signal_provider_preserves_session_after_failed_new_ratchet_decrypt() {
        let receiver_store = temp_store().await;
        let receiver_credentials = create_initial_credentials().unwrap();
        save_credentials(&receiver_store, receiver_credentials.clone())
            .await
            .unwrap();
        let upload = prepare_pre_key_upload(&receiver_store, &receiver_credentials, 1, "pre-key")
            .await
            .unwrap();
        let receiver_credentials = upload.credentials;
        save_credentials(&receiver_store, receiver_credentials.clone())
            .await
            .unwrap();
        let receiver_pre_key_id = upload.pre_key_ids[0];
        let provider_probe = SignalProviderStateStore::new(receiver_store.clone());
        let receiver_pre_key = provider_probe
            .load_local_pre_key(receiver_pre_key_id)
            .await
            .unwrap()
            .unwrap();

        let sender_credentials = create_initial_credentials().unwrap();
        let sender_material = signal_local_key_material(sender_credentials);
        let sender_base_key = generate_key_pair();
        let receiver_session = SignalSession {
            registration_id: receiver_credentials.registration_id,
            identity_key: Bytes::copy_from_slice(&receiver_credentials.signed_identity_key.public),
            signed_pre_key: SignalSignedPreKey {
                key_id: receiver_credentials.signed_pre_key.key_id,
                public_key: Bytes::copy_from_slice(
                    &receiver_credentials.signed_pre_key.key_pair.public,
                ),
                signature: receiver_credentials.signed_pre_key.signature.clone(),
            },
            pre_key: Some(SignalPreKey {
                key_id: receiver_pre_key_id,
                public_key: receiver_pre_key.public_key.clone(),
            }),
        };
        let first = encrypt_signal_outbound_pre_key_session_message(
            &sender_material,
            &sender_base_key,
            &receiver_session,
            &XEdDsaNoiseCertificateVerifier,
            b"inbound first",
        )
        .unwrap();
        let second =
            encrypt_signal_provider_session_record_message(&first.record, b"inbound second")
                .unwrap();

        let sender_jid = "123:7@s.whatsapp.net";
        let chat_jid = "123@s.whatsapp.net";
        let provider = StoreSignalSenderKeyProvider::new(receiver_store.clone());
        let codec = SignalMessageCodec::new(
            StoreSignalRepository::new(receiver_store.clone()),
            provider.clone(),
        );
        let plaintext = codec
            .decrypt_inbound_message(InboundEncryptedPayload {
                sender_jid: sender_jid.to_owned(),
                chat_jid: chat_jid.to_owned(),
                ciphertext_type: InboundCiphertextType::PreKey,
                ciphertext: first.message_bytes,
            })
            .await
            .unwrap();
        assert_eq!(plaintext, Bytes::from_static(b"inbound first"));

        let reply = provider
            .state_store()
            .encrypt_existing_session_record_message(sender_jid, Bytes::from_static(b"reply"))
            .await
            .unwrap()
            .unwrap();
        let sender_after_reply =
            decrypt_signal_provider_session_record_message(&second.record, &reply.message_bytes)
                .unwrap();
        let third = encrypt_signal_provider_session_record_message(
            &sender_after_reply.record,
            b"inbound third",
        )
        .unwrap();
        assert_eq!(third.message.previous_counter, 2);
        let stored_after_reply = provider_probe
            .load_session_record(sender_jid)
            .await
            .unwrap()
            .unwrap();

        let mut tampered = decode_signal_whisper_message(&third.message_bytes).unwrap();
        let mut tampered_ciphertext = tampered.ciphertext.to_vec();
        *tampered_ciphertext.last_mut().unwrap() ^= 1;
        tampered.ciphertext = Bytes::from(tampered_ciphertext);
        let tampered = encode_signal_whisper_message(&tampered).unwrap();
        let err = codec
            .decrypt_inbound_message(InboundEncryptedPayload {
                sender_jid: sender_jid.to_owned(),
                chat_jid: chat_jid.to_owned(),
                ciphertext_type: InboundCiphertextType::Message,
                ciphertext: tampered,
            })
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            CoreError::Crypto(wa_crypto::CryptoError::Decrypt)
        ));
        assert_eq!(
            provider_probe
                .load_session_record(sender_jid)
                .await
                .unwrap()
                .unwrap(),
            stored_after_reply
        );

        let plaintext = codec
            .decrypt_inbound_message(InboundEncryptedPayload {
                sender_jid: sender_jid.to_owned(),
                chat_jid: chat_jid.to_owned(),
                ciphertext_type: InboundCiphertextType::Message,
                ciphertext: third.message_bytes,
            })
            .await
            .unwrap();
        assert_eq!(plaintext, Bytes::from_static(b"inbound third"));
        let stored_after_third = provider_probe
            .load_session_record(sender_jid)
            .await
            .unwrap()
            .unwrap();
        let stored_after_third =
            decode_signal_provider_session_record(&stored_after_third).unwrap();
        assert_eq!(stored_after_third.message_keys.len(), 1);
        assert_eq!(stored_after_third.message_keys[0].counter, 2);

        let plaintext = codec
            .decrypt_inbound_message(InboundEncryptedPayload {
                sender_jid: sender_jid.to_owned(),
                chat_jid: chat_jid.to_owned(),
                ciphertext_type: InboundCiphertextType::Message,
                ciphertext: second.message_bytes,
            })
            .await
            .unwrap();
        assert_eq!(plaintext, Bytes::from_static(b"inbound second"));
        let stored_after_second = provider_probe
            .load_session_record(sender_jid)
            .await
            .unwrap()
            .unwrap();
        let stored_after_second =
            decode_signal_provider_session_record(&stored_after_second).unwrap();
        assert!(stored_after_second.message_keys.is_empty());
        assert_eq!(
            stored_after_second.remote_ratchet_key,
            Some(third.message.ephemeral_key)
        );
        assert_eq!(
            stored_after_second
                .receiving_chain
                .as_ref()
                .unwrap()
                .counter,
            1
        );
    }

    fn test_session() -> SignalSession {
        SignalSession {
            registration_id: 1234,
            identity_key: Bytes::from(vec![1u8; 32]),
            signed_pre_key: SignalSignedPreKey {
                key_id: 7,
                public_key: Bytes::from(vec![2u8; 32]),
                signature: Bytes::from(vec![3u8; 64]),
            },
            pre_key: Some(SignalPreKey {
                key_id: 9,
                public_key: Bytes::from(vec![4u8; 32]),
            }),
        }
    }

    fn signal_sender_key_state_strategy() -> impl Strategy<Value = SignalSenderKeyState> {
        (
            any::<u32>(),
            any::<[u8; SIGNAL_MESSAGE_KEY_LEN]>(),
            any::<u32>(),
            any::<[u8; SIGNAL_MESSAGE_KEY_LEN]>(),
            prop::option::of(any::<[u8; SIGNAL_MESSAGE_KEY_LEN]>()),
            prop::collection::vec((any::<u32>(), any::<[u8; SIGNAL_MESSAGE_KEY_LEN]>()), 0..=8),
        )
            .prop_map(
                |(
                    key_id,
                    chain_key,
                    iteration,
                    signing_public_key,
                    signing_private_key,
                    message_keys,
                )| SignalSenderKeyState {
                    key_id,
                    chain_key: SignalSenderChainKey {
                        key: SecretBytes::from(chain_key.to_vec()),
                        iteration,
                    },
                    signing_public_key: signing_private_key
                        .as_ref()
                        .map(|private_key| {
                            Bytes::copy_from_slice(&prefixed_signal_public_key(
                                &public_key_from_private(private_key),
                            ))
                        })
                        .unwrap_or_else(|| Bytes::copy_from_slice(&signing_public_key)),
                    signing_private_key: signing_private_key
                        .map(|private_key| SecretBytes::from(private_key.to_vec())),
                    message_keys: {
                        let mut seen = HashSet::new();
                        message_keys
                            .into_iter()
                            .filter_map(|(raw_iteration, seed)| {
                                if iteration == 0 {
                                    return None;
                                }
                                let skipped_iteration = raw_iteration % iteration;
                                if !seen.insert(skipped_iteration) {
                                    return None;
                                }
                                Some(SignalSenderStoredMessageKey {
                                    iteration: skipped_iteration,
                                    seed: SecretBytes::from(seed.to_vec()),
                                })
                            })
                            .collect()
                    },
                },
            )
    }

    fn normalized_signal_sender_key_record(
        record: &SignalSenderKeyRecord,
    ) -> SignalSenderKeyRecord {
        SignalSenderKeyRecord {
            states: record
                .states
                .iter()
                .map(|state| SignalSenderKeyState {
                    signing_public_key: normalize_signal_public_key(&state.signing_public_key)
                        .unwrap(),
                    ..state.clone()
                })
                .collect(),
        }
    }

    fn pre_key_message_outer_unknown_field(message: &[u8]) -> Bytes {
        let mut unknown = message.to_vec();
        unknown.extend_from_slice(&[0x78, 0x63]);
        let decoded = decode_signal_pre_key_whisper_message(&unknown).unwrap();
        assert_eq!(
            encode_signal_pre_key_whisper_message(&decoded).unwrap(),
            Bytes::copy_from_slice(message)
        );
        Bytes::from(unknown)
    }

    fn prefixed_test_signal_key(fill: u8) -> Bytes {
        let mut key = Vec::with_capacity(33);
        key.push(SIGNAL_PUBLIC_KEY_VERSION);
        key.extend_from_slice(&[fill; 32]);
        Bytes::from(key)
    }

    fn raw_sender_key_record(states: Vec<SenderKeyStateStructure>) -> Bytes {
        SenderKeyRecordStructure {
            sender_key_states: states,
        }
        .encode_to_vec()
        .into()
    }

    fn raw_sender_key_state(
        key_id: u32,
        chain_iteration: u32,
        chain_key_fill: u8,
        signing_public_key: Bytes,
        signing_private_key: Option<Bytes>,
        message_keys: &[(u32, u8)],
    ) -> SenderKeyStateStructure {
        SenderKeyStateStructure {
            sender_key_id: Some(key_id),
            sender_chain_key: Some(sender_key_state_structure::SenderChainKey {
                iteration: Some(chain_iteration),
                seed: Some(Bytes::from(vec![chain_key_fill; SIGNAL_MESSAGE_KEY_LEN])),
            }),
            sender_signing_key: Some(sender_key_state_structure::SenderSigningKey {
                public: Some(signing_public_key),
                private: signing_private_key,
            }),
            sender_message_keys: message_keys
                .iter()
                .map(
                    |(iteration, seed_fill)| sender_key_state_structure::SenderMessageKey {
                        iteration: Some(*iteration),
                        seed: Some(Bytes::from(vec![*seed_fill; SIGNAL_MESSAGE_KEY_LEN])),
                    },
                )
                .collect(),
        }
    }

    fn test_key_pair(fill: u8) -> KeyPair {
        let private = [fill; 32];
        KeyPair {
            public: public_key_from_private(&private),
            private: SecretBytes::from(private.to_vec()),
        }
    }

    async fn temp_store() -> SqliteAuthStore {
        let dir = std::env::temp_dir().join(format!("wa-core-signal-{}", rand::random::<u128>()));
        SqliteAuthStore::open(dir.join("session.db")).await.unwrap()
    }

    #[derive(Clone, Default)]
    struct RecordingSignalProvider {
        encrypt_requests: Arc<Mutex<Vec<SignalEncryptionRequest>>>,
        decrypt_requests: Arc<Mutex<Vec<SignalDecryptionRequest>>>,
        sender_key_distributions: Arc<Mutex<Vec<SignalSenderKeyDistribution>>>,
    }

    #[async_trait]
    impl SignalCryptoProvider for RecordingSignalProvider {
        async fn encrypt_signal_message(
            &self,
            request: SignalEncryptionRequest,
        ) -> CoreResult<SignalCiphertext> {
            let mut ciphertext = BytesMut::from(&b"cipher:"[..]);
            ciphertext.extend_from_slice(&request.plaintext);
            self.encrypt_requests.lock().unwrap().push(request);
            Ok(SignalCiphertext::new(
                SignalCiphertextType::Message,
                ciphertext.freeze(),
            ))
        }

        async fn decrypt_signal_message(
            &self,
            request: SignalDecryptionRequest,
        ) -> CoreResult<Bytes> {
            let mut plaintext = BytesMut::from(&b"plain:"[..]);
            plaintext.extend_from_slice(&request.payload.ciphertext);
            self.decrypt_requests.lock().unwrap().push(request);
            Ok(plaintext.freeze())
        }

        async fn process_sender_key_distribution(
            &self,
            distribution: SignalSenderKeyDistribution,
        ) -> CoreResult<()> {
            self.sender_key_distributions
                .lock()
                .unwrap()
                .push(distribution);
            Ok(())
        }
    }
}
