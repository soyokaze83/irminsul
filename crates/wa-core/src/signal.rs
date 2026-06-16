use crate::{
    CoreError, CoreResult, InboundCiphertextType, InboundEncryptedPayload, InboundMessageDecryptor,
    MessageCiphertextType, MessageEncryption, MessageEncryptor,
};
use crate::{payload::KEY_BUNDLE_TYPE, pre_keys::SERVER_JID};
use async_trait::async_trait;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::fmt;
use wa_binary::{BinaryNode, BinaryNodeContent, JidServer, WaJidDomain, jid_decode, jid_encode};
use wa_crypto::SIGNAL_PUBLIC_KEY_VERSION;
use wa_proto::proto::message::SenderKeyDistributionMessage;
use wa_store::{KeyNamespace, SignalKeyStore, StoreTransaction};

const STORED_SESSION_VERSION: u8 = 1;
const SESSION_RECORD_KIND: u8 = 1;

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
    pub base_key: Bytes,
    pub registration_id: u32,
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
    pub session: SignalSessionInfo,
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
pub struct StoreSignalRepository<S> {
    store: S,
}

impl<S> StoreSignalRepository<S> {
    #[must_use]
    pub fn new(store: S) -> Self {
        Self { store }
    }

    #[must_use]
    pub fn store(&self) -> &S {
        &self.store
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

        self.store
            .signal_transaction("inject-e2e-session", move |tx| {
                tx.set(KeyNamespace::IdentityKey, &address, &identity_key)?;
                tx.set(KeyNamespace::Session, &address, &encoded)?;
                Ok(())
            })
            .await?;
        Ok(())
    }

    async fn get_session_info(&self, jid: &str) -> CoreResult<Option<SignalSessionInfo>> {
        let address = signal_protocol_address(jid)?.to_string();
        let Some(session) = self
            .store
            .get_signal_key(KeyNamespace::Session, &address)
            .await?
        else {
            return Ok(None);
        };
        let session = decode_stored_session(&session)?;
        let base_key = session
            .pre_key
            .as_ref()
            .map(|pre_key| pre_key.public_key.clone())
            .unwrap_or_else(|| session.signed_pre_key.public_key.clone());

        Ok(Some(SignalSessionInfo {
            base_key,
            registration_id: session.registration_id,
        }))
    }

    async fn validate_session(&self, jid: &str) -> CoreResult<SignalSessionValidation> {
        let address = signal_protocol_address(jid)?.to_string();
        let Some(session) = self
            .store
            .get_signal_key(KeyNamespace::Session, &address)
            .await?
        else {
            return Ok(SignalSessionValidation {
                exists: false,
                reason: Some("no session".to_owned()),
            });
        };

        match decode_stored_session(&session) {
            Ok(_) => Ok(SignalSessionValidation {
                exists: true,
                reason: None,
            }),
            Err(err) => Ok(SignalSessionValidation {
                exists: false,
                reason: Some(err.to_string()),
            }),
        }
    }

    async fn delete_sessions(&self, jids: &[String]) -> CoreResult<()> {
        let addresses = jids
            .iter()
            .map(|jid| signal_protocol_address(jid).map(|address| address.to_string()))
            .collect::<CoreResult<Vec<_>>>()?;
        self.store
            .signal_transaction("delete-sessions", move |tx| {
                for address in addresses {
                    tx.delete(KeyNamespace::Session, &address)?;
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
        let migration = self
            .store
            .signal_transaction("migrate-session", move |tx| {
                let Some(session) = tx.get(KeyNamespace::Session, &from)? else {
                    return Ok(SignalSessionMigration {
                        migrated: 0,
                        skipped: 1,
                        total: 1,
                    });
                };
                if tx.get(KeyNamespace::Session, &to)?.is_some() {
                    return Ok(SignalSessionMigration {
                        migrated: 0,
                        skipped: 1,
                        total: 1,
                    });
                }
                tx.set(KeyNamespace::Session, &to, &session)?;
                tx.delete(KeyNamespace::Session, &from)?;
                Ok(SignalSessionMigration {
                    migrated: 1,
                    skipped: 0,
                    total: 1,
                })
            })
            .await?;
        Ok(migration)
    }

    async fn save_identity(&self, jid: &str, identity_key: Bytes) -> CoreResult<bool> {
        let address = signal_protocol_address(jid)?.to_string();
        let identity_key = normalize_signal_public_key(&identity_key)?;
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
        let existed = self
            .store
            .get_signal_key(KeyNamespace::SenderKeyMemory, group_jid)
            .await?
            .is_some();
        self.store
            .delete_signal_key(KeyNamespace::SenderKeyMemory, group_jid)
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
        let session = self
            .repository
            .get_session_info(recipient_jid)
            .await?
            .ok_or_else(|| {
                CoreError::Protocol(format!(
                    "missing Signal session for recipient {recipient_jid}"
                ))
            })?;
        let encrypted = self
            .provider
            .encrypt_signal_message(SignalEncryptionRequest {
                recipient_jid: recipient_jid.to_owned(),
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
        let session = match payload.ciphertext_type {
            InboundCiphertextType::Message | InboundCiphertextType::PreKey => {
                Some(required_session(&self.repository, &payload.sender_jid).await?)
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
        let group_jid = message.group_id.as_deref().ok_or_else(|| {
            CoreError::Protocol("sender-key distribution missing group id".to_owned())
        })?;
        let distribution = message
            .axolotl_sender_key_distribution_message
            .clone()
            .ok_or_else(|| {
                CoreError::Protocol("sender-key distribution missing payload".to_owned())
            })?;
        self.repository
            .store_sender_key_distribution(author_jid, group_jid, distribution.clone())
            .await?;
        self.provider
            .process_sender_key_distribution(SignalSenderKeyDistribution {
                author_jid: author_jid.to_owned(),
                group_jid: group_jid.to_owned(),
                distribution,
            })
            .await
    }
}

async fn required_session<R>(repository: &R, jid: &str) -> CoreResult<SignalSessionInfo>
where
    R: SignalRepository,
{
    repository
        .get_session_info(jid)
        .await?
        .ok_or_else(|| CoreError::Protocol(format!("missing Signal session for sender {jid}")))
}

fn sender_key_store_key(author_jid: &str, group_jid: &str) -> CoreResult<String> {
    validate_sender_key_jid("sender-key author JID", author_jid)?;
    let decoded_group = jid_decode(group_jid)
        .ok_or_else(|| CoreError::Protocol(format!("invalid sender-key group JID: {group_jid}")))?;
    if decoded_group.server != JidServer::GUs {
        return Err(CoreError::Protocol(format!(
            "sender-key group JID must use group server: {group_jid}"
        )));
    }
    Ok(format!("{group_jid}|{author_jid}"))
}

fn validate_sender_key_jid(label: &str, jid: &str) -> CoreResult<()> {
    let decoded =
        jid_decode(jid).ok_or_else(|| CoreError::Protocol(format!("invalid {label}: {jid}")))?;
    if decoded.user.is_empty() || decoded.server_raw.is_empty() {
        return Err(CoreError::Protocol(format!("invalid {label}: {jid}")));
    }
    Ok(())
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
            _ => return Ok(None),
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
    let identity_key = normalize_signal_public_key(&take_bytes(&mut input)?)?;
    let signed_key_id = take_u32(&mut input)?;
    let signed_public = normalize_signal_public_key(&take_bytes(&mut input)?)?;
    let signature = take_bytes(&mut input)?;
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
            key_id: take_u32(&mut input)?,
            public_key: normalize_signal_public_key(&take_bytes(&mut input)?)?,
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
    }
    tx.set(KeyNamespace::IdentityKey, address, identity_key)?;
    Ok(existing.is_some())
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

fn take_u32(input: &mut &[u8]) -> CoreResult<u32> {
    if input.remaining() < 4 {
        return Err(CoreError::Protocol(
            "stored signal session missing u32 field".to_owned(),
        ));
    }
    Ok(input.get_u32())
}

fn take_bytes(input: &mut &[u8]) -> CoreResult<Bytes> {
    if input.remaining() < 2 {
        return Err(CoreError::Protocol(
            "stored signal session missing byte field length".to_owned(),
        ));
    }
    let len = usize::from(input.get_u16());
    if input.remaining() < len {
        return Err(CoreError::Protocol(
            "stored signal session byte field is truncated".to_owned(),
        ));
    }
    Ok(Bytes::copy_from_slice(&input.copy_to_bytes(len)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encode_big_endian;
    use std::sync::{Arc, Mutex};
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
        assert!(
            err.to_string()
                .contains("E2E session query failed (401): session denied")
        );

        let child_error = BinaryNode::new("iq")
            .with_attr("type", "result")
            .with_content(vec![
                BinaryNode::new("error")
                    .with_attr("code", "503")
                    .with_attr("text", "session unavailable"),
            ]);
        let err = parse_e2e_sessions_node(&child_error).unwrap_err();
        assert!(
            err.to_string()
                .contains("E2E session query failed (503): session unavailable")
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

    #[tokio::test]
    async fn repository_injects_validates_and_deletes_sessions() {
        let store = temp_store().await;
        let repository = StoreSignalRepository::new(store.clone());
        let session = test_session();

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
        assert_eq!(info.registration_id, session.registration_id);
        assert_eq!(
            info.base_key,
            normalize_signal_public_key(&session.pre_key.unwrap().public_key).unwrap()
        );

        repository
            .delete_sessions(&["123:7@s.whatsapp.net".to_owned()])
            .await
            .unwrap();
        let validation = repository
            .validate_session("123:7@s.whatsapp.net")
            .await
            .unwrap();
        assert!(!validation.exists);
    }

    #[tokio::test]
    async fn repository_clears_group_sender_key_memory() {
        let store = temp_store().await;
        store
            .set_signal_key(KeyNamespace::SenderKeyMemory, "555@g.us", b"sender-memory")
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
        let repository = StoreSignalRepository::new(store);

        repository
            .inject_e2e_session(SessionInjection {
                jid: "123:7@s.whatsapp.net".to_owned(),
                session: test_session(),
            })
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

        repository
            .inject_e2e_session(SessionInjection {
                jid: "123:7@s.whatsapp.net".to_owned(),
                session: test_session(),
            })
            .await
            .unwrap();
        let migration = repository
            .migrate_session("123:7@s.whatsapp.net", "lid-user:7@lid")
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
            repository
                .validate_session("lid-user:7@lid")
                .await
                .unwrap()
                .exists
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
            assert_eq!(requests[0].session.registration_id, 1234);
            assert_eq!(
                requests[0].session.base_key,
                normalize_signal_public_key(&[4u8; 32]).unwrap()
            );
        }

        assert!(
            codec
                .encrypt_message("456:7@s.whatsapp.net", Bytes::from_static(b"plain"))
                .await
                .is_err()
        );
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

        codec
            .process_sender_key_distribution(
                "123:7@s.whatsapp.net",
                &SenderKeyDistributionMessage {
                    group_id: Some("555@g.us".to_owned()),
                    axolotl_sender_key_distribution_message: Some(Bytes::from_static(
                        b"sender-key",
                    )),
                },
            )
            .await
            .unwrap();
        assert_eq!(
            repository
                .get_sender_key_distribution("123:7@s.whatsapp.net", "555@g.us")
                .await
                .unwrap(),
            Some(Bytes::from_static(b"sender-key"))
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
        assert_eq!(requests.len(), 2);
        assert!(requests[1].session.is_none());
        assert_eq!(
            requests[1].sender_key_distribution.as_deref(),
            Some(&b"sender-key"[..])
        );
        assert_eq!(
            provider.sender_key_distributions.lock().unwrap().as_slice(),
            &[SignalSenderKeyDistribution {
                author_jid: "123:7@s.whatsapp.net".to_owned(),
                group_jid: "555@g.us".to_owned(),
                distribution: Bytes::from_static(b"sender-key"),
            }]
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
