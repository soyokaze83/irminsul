#[cfg(feature = "noise")]
use crate::{
    ChatEvent, ContactEvent, EventBatch, LabelAssociationEvent, LabelEvent, MessageEvent,
    MessageEventKey, MessageUpdate, QuickReplyEvent,
    media::{MediaTransfer, MediaTransport},
    message::UploadedMedia,
};
use crate::{CoreError, CoreResult};
#[cfg(feature = "noise")]
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use bytes::Bytes;
use prost::Message as _;
#[cfg(feature = "noise")]
use std::collections::BTreeMap;
#[cfg(feature = "noise")]
use wa_binary::jid::JidServer;
use wa_binary::jid::S_WHATSAPP_NET;
use wa_binary::{BinaryNode, BinaryNodeContent, jid_decode};
#[cfg(feature = "noise")]
use wa_proto::proto::message::{AppStateSyncKeyData, protocol_message};
use wa_proto::proto::{
    ExternalBlobReference, MessageKey, SyncActionData, SyncActionValue, SyncdPatch, SyncdVersion,
    sync_action_value,
};
#[cfg(feature = "noise")]
use wa_proto::proto::{
    KeyId, Message as ProtoMessage, SyncdIndex, SyncdMutation, SyncdMutations, SyncdRecord,
    SyncdSnapshot, SyncdValue,
};
#[cfg(feature = "noise")]
use wa_store::{AuthStore, KeyNamespace};

pub const APP_STATE_HASH_LEN: usize = 128;
#[cfg(feature = "noise")]
pub const APP_STATE_MAC_LEN: usize = 32;
#[cfg(feature = "noise")]
const APP_STATE_STORE_MAGIC: &[u8; 4] = b"ASPS";
#[cfg(feature = "noise")]
const APP_STATE_STORE_FORMAT_VERSION: u8 = 1;
#[cfg(feature = "noise")]
const APP_STATE_BLOCKED_STORE_MAGIC: &[u8; 4] = b"ASBK";
#[cfg(feature = "noise")]
const APP_STATE_BLOCKED_STORE_FORMAT_VERSION: u8 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum AppStateCollection {
    Regular,
    RegularHigh,
    RegularLow,
    CriticalBlock,
    CriticalUnblock,
    CriticalUnblockLow,
    CriticalIdentity,
}

impl AppStateCollection {
    #[must_use]
    pub fn all() -> &'static [Self] {
        &[
            Self::Regular,
            Self::RegularHigh,
            Self::RegularLow,
            Self::CriticalBlock,
            Self::CriticalUnblock,
            Self::CriticalUnblockLow,
            Self::CriticalIdentity,
        ]
    }

    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Regular => "regular",
            Self::RegularHigh => "regular_high",
            Self::RegularLow => "regular_low",
            Self::CriticalBlock => "critical_block",
            Self::CriticalUnblock => "critical_unblock",
            Self::CriticalUnblockLow => "critical_unblock_low",
            Self::CriticalIdentity => "critical_identity",
        }
    }

    pub fn from_name(name: &str) -> CoreResult<Self> {
        match name {
            "regular" => Ok(Self::Regular),
            "regular_high" => Ok(Self::RegularHigh),
            "regular_low" => Ok(Self::RegularLow),
            "critical_block" => Ok(Self::CriticalBlock),
            "critical_unblock" => Ok(Self::CriticalUnblock),
            "critical_unblock_low" => Ok(Self::CriticalUnblockLow),
            "critical_identity" => Ok(Self::CriticalIdentity),
            _ => Err(CoreError::Protocol(format!(
                "unknown app-state collection: {name}"
            ))),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum DirtyBitType {
    AccountSync,
    Groups,
}

impl DirtyBitType {
    #[must_use]
    pub fn value(self) -> &'static str {
        match self {
            Self::AccountSync => "account_sync",
            Self::Groups => "groups",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirtyNotification {
    pub dirty_type: String,
    pub timestamp: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppStateCollectionRequest {
    pub collection: AppStateCollection,
    pub version: u64,
    pub return_snapshot: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AppStateQueryKind {
    Sync,
    PatchUpload,
}

impl AppStateQueryKind {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Sync => "app-state sync query",
            Self::PatchUpload => "app-state patch upload",
        }
    }
}

impl AppStateCollectionRequest {
    #[must_use]
    pub fn new(collection: AppStateCollection, version: u64) -> Self {
        Self {
            collection,
            version,
            return_snapshot: version == 0,
        }
    }

    #[must_use]
    pub fn with_return_snapshot(mut self, return_snapshot: bool) -> Self {
        self.return_snapshot = return_snapshot;
        self
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct AppStateSyncResponse {
    pub collections: Vec<AppStateSyncCollection>,
}

impl AppStateSyncResponse {
    #[must_use]
    pub fn collection(&self, collection: AppStateCollection) -> Option<&AppStateSyncCollection> {
        self.collections
            .iter()
            .find(|entry| entry.collection == collection)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct AppStateSyncCollection {
    pub collection: AppStateCollection,
    pub version: Option<u64>,
    pub has_more_patches: bool,
    pub snapshot: Option<ExternalBlobReference>,
    pub patches: Vec<SyncdPatch>,
}

#[cfg(feature = "noise")]
#[derive(Clone, Debug, PartialEq)]
pub struct AppStatePendingSnapshot {
    pub collection: AppStateCollection,
    pub reference: ExternalBlobReference,
}

#[cfg(feature = "noise")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppStateBlockedCollection {
    pub collection: AppStateCollection,
    pub key_id: Bytes,
    pub previous_version: u64,
}

#[cfg(feature = "noise")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppStateSyncKeyShareItem {
    pub key_id: Bytes,
    pub key_data: Bytes,
}

#[cfg(feature = "noise")]
#[derive(Clone, Debug, PartialEq)]
pub struct AppStateCollectionSyncOutcome {
    pub collection: AppStateCollection,
    pub response_version: Option<u64>,
    pub final_version: u64,
    pub applied_patches: usize,
    pub emitted_batches: usize,
    pub has_more_patches: bool,
    pub snapshot_pending: bool,
}

#[cfg(feature = "noise")]
#[derive(Clone, Debug, Default, PartialEq)]
pub struct AppStateSyncApplyOutcome {
    pub batches: Vec<EventBatch>,
    pub collections: Vec<AppStateCollectionSyncOutcome>,
    pub pending_snapshots: Vec<AppStatePendingSnapshot>,
    pub blocked: Vec<AppStateBlockedCollection>,
}

#[cfg(feature = "noise")]
impl AppStateSyncApplyOutcome {
    pub fn append(&mut self, mut other: Self) {
        self.batches.append(&mut other.batches);
        self.collections.append(&mut other.collections);
        self.pending_snapshots.append(&mut other.pending_snapshots);
        self.blocked.append(&mut other.blocked);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AppStatePatchOperation {
    Set,
    Remove,
}

impl AppStatePatchOperation {
    #[must_use]
    pub fn proto_value(self) -> i32 {
        match self {
            Self::Set => 0,
            Self::Remove => 1,
        }
    }

    pub fn from_proto_value(value: i32) -> CoreResult<Self> {
        match value {
            0 => Ok(Self::Set),
            1 => Ok(Self::Remove),
            _ => Err(CoreError::Protocol(format!(
                "unknown app-state patch operation: {value}"
            ))),
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct ChatMutationMessageRef {
    pub key: MessageKey,
    pub timestamp: Option<u64>,
}

impl ChatMutationMessageRef {
    #[must_use]
    pub fn new(key: MessageKey) -> Self {
        Self {
            key,
            timestamp: None,
        }
    }

    #[must_use]
    pub fn with_timestamp(mut self, timestamp: u64) -> Self {
        self.timestamp = Some(timestamp);
        self
    }
}

#[derive(Clone, Default, PartialEq, Eq)]
pub struct ChatMutationMessageRange {
    pub last_message_timestamp: Option<u64>,
    pub last_system_message_timestamp: Option<u64>,
    pub messages: Vec<ChatMutationMessageRef>,
}

impl ChatMutationMessageRange {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_last_message_timestamp(mut self, timestamp: u64) -> Self {
        self.last_message_timestamp = Some(timestamp);
        self
    }

    #[must_use]
    pub fn with_last_system_message_timestamp(mut self, timestamp: u64) -> Self {
        self.last_system_message_timestamp = Some(timestamp);
        self
    }

    #[must_use]
    pub fn with_message(mut self, message: ChatMutationMessageRef) -> Self {
        self.messages.push(message);
        self
    }

    pub fn to_proto(&self) -> CoreResult<sync_action_value::SyncActionMessageRange> {
        Ok(sync_action_value::SyncActionMessageRange {
            last_message_timestamp: self.last_message_timestamp.map(u64_to_i64).transpose()?,
            last_system_message_timestamp: self
                .last_system_message_timestamp
                .map(u64_to_i64)
                .transpose()?,
            messages: self
                .messages
                .iter()
                .map(|message| {
                    validate_message_key(&message.key)?;
                    Ok(sync_action_value::SyncActionMessage {
                        key: Some(message.key.clone()),
                        timestamp: message.timestamp.map(u64_to_i64).transpose()?,
                    })
                })
                .collect::<CoreResult<Vec<_>>>()?,
        })
    }
}

pub type LabelListType = sync_action_value::label_edit_action::ListType;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ContactSyncAction {
    pub full_name: Option<String>,
    pub first_name: Option<String>,
    pub lid_jid: Option<String>,
    pub save_on_primary_addressbook: Option<bool>,
    pub pn_jid: Option<String>,
    pub username: Option<String>,
}

impl ContactSyncAction {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_full_name(mut self, full_name: impl Into<String>) -> Self {
        self.full_name = Some(full_name.into());
        self
    }

    #[must_use]
    pub fn with_first_name(mut self, first_name: impl Into<String>) -> Self {
        self.first_name = Some(first_name.into());
        self
    }

    #[must_use]
    pub fn with_lid_jid(mut self, lid_jid: impl Into<String>) -> Self {
        self.lid_jid = Some(lid_jid.into());
        self
    }

    #[must_use]
    pub fn with_save_on_primary_addressbook(mut self, save: bool) -> Self {
        self.save_on_primary_addressbook = Some(save);
        self
    }

    #[must_use]
    pub fn with_pn_jid(mut self, pn_jid: impl Into<String>) -> Self {
        self.pn_jid = Some(pn_jid.into());
        self
    }

    #[must_use]
    pub fn with_username(mut self, username: impl Into<String>) -> Self {
        self.username = Some(username.into());
        self
    }

    #[must_use]
    fn has_fields(&self) -> bool {
        self.full_name.is_some()
            || self.first_name.is_some()
            || self.lid_jid.is_some()
            || self.save_on_primary_addressbook.is_some()
            || self.pn_jid.is_some()
            || self.username.is_some()
    }

    fn to_proto(&self) -> CoreResult<sync_action_value::ContactAction> {
        Ok(sync_action_value::ContactAction {
            full_name: optional_non_empty("contact full name", self.full_name.as_deref())?,
            first_name: optional_non_empty("contact first name", self.first_name.as_deref())?,
            lid_jid: optional_jid("contact LID JID", self.lid_jid.as_deref())?,
            save_on_primary_addressbook: self.save_on_primary_addressbook,
            pn_jid: optional_jid("contact phone JID", self.pn_jid.as_deref())?,
            username: optional_non_empty("contact username", self.username.as_deref())?,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuickReplyMutation {
    pub id: String,
    pub shortcut: String,
    pub message: String,
    pub keywords: Vec<String>,
    pub count: Option<i32>,
    pub deleted: bool,
}

impl QuickReplyMutation {
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        shortcut: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            shortcut: shortcut.into(),
            message: message.into(),
            keywords: Vec::new(),
            count: Some(0),
            deleted: false,
        }
    }

    #[must_use]
    pub fn delete(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            shortcut: String::new(),
            message: String::new(),
            keywords: Vec::new(),
            count: Some(0),
            deleted: true,
        }
    }

    #[must_use]
    pub fn with_keyword(mut self, keyword: impl Into<String>) -> Self {
        self.keywords.push(keyword.into());
        self
    }

    #[must_use]
    pub fn with_count(mut self, count: i32) -> Self {
        self.count = Some(count);
        self
    }

    fn to_proto(&self) -> CoreResult<sync_action_value::QuickReplyAction> {
        validate_non_empty("quick reply id", &self.id)?;
        if !self.deleted {
            validate_non_empty("quick reply shortcut", &self.shortcut)?;
            validate_non_empty("quick reply message", &self.message)?;
        }
        for keyword in &self.keywords {
            validate_non_empty("quick reply keyword", keyword)?;
        }
        if let Some(count) = self.count
            && count < 0
        {
            return Err(CoreError::Protocol(
                "quick reply count must not be negative".to_owned(),
            ));
        }
        Ok(sync_action_value::QuickReplyAction {
            shortcut: Some(self.shortcut.clone()),
            message: Some(self.message.clone()),
            keywords: self.keywords.clone(),
            count: Some(self.count.unwrap_or(0)),
            deleted: Some(self.deleted),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LabelEditMutation {
    pub id: String,
    pub name: Option<String>,
    pub color: Option<i32>,
    pub predefined_id: Option<i32>,
    pub deleted: bool,
    pub order_index: Option<i32>,
    pub is_active: Option<bool>,
    pub list_type: Option<LabelListType>,
    pub is_immutable: Option<bool>,
    pub mute_end_time_ms: Option<u64>,
}

impl LabelEditMutation {
    #[must_use]
    pub fn new(id: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: Some(name.into()),
            color: None,
            predefined_id: None,
            deleted: false,
            order_index: None,
            is_active: None,
            list_type: None,
            is_immutable: None,
            mute_end_time_ms: None,
        }
    }

    #[must_use]
    pub fn delete(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: None,
            color: None,
            predefined_id: None,
            deleted: true,
            order_index: None,
            is_active: None,
            list_type: None,
            is_immutable: None,
            mute_end_time_ms: None,
        }
    }

    #[must_use]
    pub fn with_color(mut self, color: i32) -> Self {
        self.color = Some(color);
        self
    }

    #[must_use]
    pub fn with_predefined_id(mut self, predefined_id: i32) -> Self {
        self.predefined_id = Some(predefined_id);
        self
    }

    #[must_use]
    pub fn with_order_index(mut self, order_index: i32) -> Self {
        self.order_index = Some(order_index);
        self
    }

    #[must_use]
    pub fn with_active(mut self, is_active: bool) -> Self {
        self.is_active = Some(is_active);
        self
    }

    #[must_use]
    pub fn with_list_type(mut self, list_type: LabelListType) -> Self {
        self.list_type = Some(list_type);
        self
    }

    #[must_use]
    pub fn with_immutable(mut self, is_immutable: bool) -> Self {
        self.is_immutable = Some(is_immutable);
        self
    }

    #[must_use]
    pub fn with_mute_end_time_ms(mut self, mute_end_time_ms: u64) -> Self {
        self.mute_end_time_ms = Some(mute_end_time_ms);
        self
    }

    fn to_proto(&self) -> CoreResult<sync_action_value::LabelEditAction> {
        validate_non_empty("label id", &self.id)?;
        let name = optional_non_empty("label name", self.name.as_deref())?;
        if !self.deleted
            && name.is_none()
            && self.color.is_none()
            && self.predefined_id.is_none()
            && self.order_index.is_none()
            && self.is_active.is_none()
            && self.list_type.is_none()
            && self.is_immutable.is_none()
            && self.mute_end_time_ms.is_none()
        {
            return Err(CoreError::Protocol(
                "label edit action must include at least one field".to_owned(),
            ));
        }
        Ok(sync_action_value::LabelEditAction {
            name,
            color: self.color,
            predefined_id: self.predefined_id,
            deleted: Some(self.deleted),
            order_index: self.order_index,
            is_active: self.is_active,
            r#type: self.list_type.map(|kind| kind as i32),
            is_immutable: self.is_immutable,
            mute_end_time_ms: self.mute_end_time_ms.map(u64_to_i64).transpose()?,
        })
    }
}

#[derive(Clone, PartialEq)]
pub struct ChatMutationPatch {
    pub collection: AppStateCollection,
    pub operation: AppStatePatchOperation,
    pub api_version: i32,
    pub index: Vec<String>,
    pub value: SyncActionValue,
}

#[cfg(feature = "noise")]
#[derive(Clone, PartialEq, Eq)]
pub struct EncryptedAppStateMutation {
    pub index_mac: Bytes,
    pub value_mac: Bytes,
    pub encrypted_value: Bytes,
    pub mutation: SyncdMutation,
}

#[cfg(feature = "noise")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppStateHashMutation {
    pub operation: AppStatePatchOperation,
    pub index_mac: Bytes,
    pub value_mac: Bytes,
}

#[cfg(feature = "noise")]
impl AppStateHashMutation {
    pub fn new(
        operation: AppStatePatchOperation,
        index_mac: impl Into<Bytes>,
        value_mac: impl Into<Bytes>,
    ) -> CoreResult<Self> {
        let index_mac = index_mac.into();
        let value_mac = value_mac.into();
        validate_app_state_mac("app-state index mac", &index_mac)?;
        validate_app_state_mac("app-state value mac", &value_mac)?;
        Ok(Self {
            operation,
            index_mac,
            value_mac,
        })
    }

    pub fn from_encrypted(mutation: &EncryptedAppStateMutation) -> CoreResult<Self> {
        Self::new(
            AppStatePatchOperation::from_proto_value(mutation.mutation.operation.ok_or_else(
                || CoreError::Protocol("app-state mutation is missing operation".to_owned()),
            )?)?,
            mutation.index_mac.clone(),
            mutation.value_mac.clone(),
        )
    }
}

#[cfg(feature = "noise")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppStatePatchState {
    version: u64,
    hash: Bytes,
    index_value_macs: BTreeMap<String, Bytes>,
}

#[cfg(feature = "noise")]
impl AppStatePatchState {
    #[must_use]
    pub fn empty() -> Self {
        Self {
            version: 0,
            hash: Bytes::from(vec![0u8; APP_STATE_HASH_LEN]),
            index_value_macs: BTreeMap::new(),
        }
    }

    pub fn new(version: u64, hash: impl Into<Bytes>) -> CoreResult<Self> {
        Self::from_index_value_macs(version, hash, [])
    }

    pub fn from_index_value_macs<I>(
        version: u64,
        hash: impl Into<Bytes>,
        entries: I,
    ) -> CoreResult<Self>
    where
        I: IntoIterator<Item = (Bytes, Bytes)>,
    {
        let hash = hash.into();
        validate_app_state_hash(&hash)?;
        let mut index_value_macs = BTreeMap::new();
        for (index_mac, value_mac) in entries {
            validate_app_state_mac("app-state index mac", &index_mac)?;
            validate_app_state_mac("app-state value mac", &value_mac)?;
            index_value_macs.insert(index_mac_key(&index_mac)?, value_mac);
        }
        Ok(Self {
            version,
            hash,
            index_value_macs,
        })
    }

    #[must_use]
    pub fn version(&self) -> u64 {
        self.version
    }

    #[must_use]
    pub fn hash(&self) -> &Bytes {
        &self.hash
    }

    #[must_use]
    pub fn index_value_mac_count(&self) -> usize {
        self.index_value_macs.len()
    }

    pub fn value_mac_for_index_mac(&self, index_mac: &[u8]) -> CoreResult<Option<&Bytes>> {
        Ok(self.index_value_macs.get(&index_mac_key(index_mac)?))
    }

    pub fn advance_with_hash_mutations<I>(&self, mutations: I) -> CoreResult<Self>
    where
        I: IntoIterator<Item = AppStateHashMutation>,
    {
        let version = self
            .version
            .checked_add(1)
            .ok_or_else(|| CoreError::Payload("app-state patch version overflow".to_owned()))?;
        self.apply_hash_mutations_at_version(version, mutations)
    }

    pub fn apply_hash_mutations_at_version<I>(&self, version: u64, mutations: I) -> CoreResult<Self>
    where
        I: IntoIterator<Item = AppStateHashMutation>,
    {
        let mut index_value_macs = self.index_value_macs.clone();
        let mut add_value_macs = Vec::<Bytes>::new();
        let mut subtract_value_macs = Vec::<Bytes>::new();

        for mutation in mutations {
            let index_key = index_mac_key(&mutation.index_mac)?;
            match mutation.operation {
                AppStatePatchOperation::Set => {
                    if let Some(previous) =
                        index_value_macs.insert(index_key, mutation.value_mac.clone())
                    {
                        subtract_value_macs.push(previous);
                    }
                    add_value_macs.push(mutation.value_mac);
                }
                AppStatePatchOperation::Remove => {
                    let Some(previous) = index_value_macs.remove(&index_key) else {
                        continue;
                    };
                    subtract_value_macs.push(previous);
                }
            }
        }

        let hash = wa_crypto::app_state_lt_hash_subtract_then_add(
            &self.hash,
            subtract_value_macs.iter().map(|mac| mac.as_ref()),
            add_value_macs.iter().map(|mac| mac.as_ref()),
        )
        .map_err(CoreError::Crypto)?;
        Ok(Self {
            version,
            hash: Bytes::copy_from_slice(&hash),
            index_value_macs,
        })
    }
}

#[cfg(feature = "noise")]
#[derive(Clone, PartialEq)]
pub struct AppStatePatchBundle {
    pub collection: AppStateCollection,
    pub previous_version: u64,
    pub next_state: AppStatePatchState,
    pub patch: SyncdPatch,
    pub encoded_patch: Bytes,
}

#[cfg(feature = "noise")]
#[derive(Clone, PartialEq)]
pub struct DecodedAppStateMutation {
    pub operation: AppStatePatchOperation,
    pub key_id: Bytes,
    pub index_mac: Bytes,
    pub value_mac: Bytes,
    pub encrypted_value: Bytes,
    pub index: Vec<String>,
    pub sync_action: SyncActionData,
}

#[cfg(feature = "noise")]
#[derive(Clone, PartialEq)]
pub struct DecodedAppStatePatch {
    pub collection: AppStateCollection,
    pub previous_version: u64,
    pub next_state: AppStatePatchState,
    pub patch: SyncdPatch,
    pub mutations: Vec<DecodedAppStateMutation>,
}

#[cfg(feature = "noise")]
#[derive(Clone, PartialEq)]
pub struct DecodedAppStateSnapshot {
    pub collection: AppStateCollection,
    pub version: u64,
    pub state: AppStatePatchState,
    pub snapshot: SyncdSnapshot,
    pub mutations: Vec<DecodedAppStateMutation>,
}

impl ChatMutationPatch {
    #[must_use]
    pub fn new(
        collection: AppStateCollection,
        api_version: i32,
        index: Vec<String>,
        value: SyncActionValue,
    ) -> Self {
        Self {
            collection,
            operation: AppStatePatchOperation::Set,
            api_version,
            index,
            value,
        }
    }

    #[must_use]
    pub fn with_operation(mut self, operation: AppStatePatchOperation) -> Self {
        self.operation = operation;
        self
    }
}

pub fn build_sync_action_data(patch: &ChatMutationPatch) -> CoreResult<SyncActionData> {
    if patch.index.is_empty() {
        return Err(CoreError::Protocol(
            "sync action index must not be empty".to_owned(),
        ));
    }
    if patch.api_version <= 0 {
        return Err(CoreError::Protocol(
            "sync action API version must be positive".to_owned(),
        ));
    }
    let index = serde_json::to_vec(&patch.index)
        .map_err(|err| CoreError::Payload(format!("failed to encode sync action index: {err}")))?;
    Ok(SyncActionData {
        index: Some(Bytes::from(index)),
        value: Some(patch.value.clone()),
        padding: Some(Bytes::new()),
        version: Some(patch.api_version),
    })
}

pub fn encode_sync_action_data(patch: &ChatMutationPatch) -> CoreResult<Bytes> {
    Ok(Bytes::from(build_sync_action_data(patch)?.encode_to_vec()))
}

#[must_use]
pub fn encode_app_state_patch(patch: &SyncdPatch) -> Bytes {
    Bytes::from(patch.encode_to_vec())
}

pub fn build_app_state_patch_query_from_patch(
    collection: AppStateCollection,
    previous_version: u64,
    patch: &SyncdPatch,
    tag: impl Into<String>,
) -> CoreResult<BinaryNode> {
    build_app_state_patch_query(
        collection,
        previous_version,
        encode_app_state_patch(patch),
        tag,
    )
}

#[cfg(feature = "noise")]
pub fn encrypt_chat_mutation_patch_with_iv(
    patch: &ChatMutationPatch,
    key_id: &[u8],
    key_data: &[u8],
    iv: &[u8],
) -> CoreResult<EncryptedAppStateMutation> {
    if key_id.is_empty() {
        return Err(CoreError::Protocol(
            "app-state mutation key id must not be empty".to_owned(),
        ));
    }
    let sync_action = build_sync_action_data(patch)?;
    let index = sync_action
        .index
        .clone()
        .ok_or_else(|| CoreError::Protocol("sync action index missing".to_owned()))?;
    let encoded = Bytes::from(sync_action.encode_to_vec());
    let keys = wa_crypto::derive_app_state_keys(key_data).map_err(CoreError::Crypto)?;
    let encrypted_value = wa_crypto::encrypt_app_state_value_with_iv(&encoded, &keys, iv)
        .map_err(CoreError::Crypto)?;
    let value_mac = wa_crypto::app_state_value_mac(
        crypto_operation(patch.operation),
        &encrypted_value,
        key_id,
        &keys,
    )
    .map_err(CoreError::Crypto)?;
    let index_mac = wa_crypto::app_state_index_mac(&index, &keys).map_err(CoreError::Crypto)?;

    let mut value_blob = Vec::with_capacity(encrypted_value.len() + value_mac.len());
    value_blob.extend_from_slice(&encrypted_value);
    value_blob.extend_from_slice(&value_mac);

    let mutation = SyncdMutation {
        operation: Some(patch.operation.proto_value()),
        record: Some(SyncdRecord {
            index: Some(SyncdIndex {
                blob: Some(Bytes::copy_from_slice(&index_mac)),
            }),
            value: Some(SyncdValue {
                blob: Some(Bytes::from(value_blob)),
            }),
            key_id: Some(KeyId {
                id: Some(Bytes::copy_from_slice(key_id)),
            }),
        }),
    };

    Ok(EncryptedAppStateMutation {
        index_mac: Bytes::copy_from_slice(&index_mac),
        value_mac: Bytes::copy_from_slice(&value_mac),
        encrypted_value,
        mutation,
    })
}

#[cfg(feature = "noise")]
pub fn encrypt_chat_mutation_patch(
    patch: &ChatMutationPatch,
    key_id: &[u8],
    key_data: &[u8],
) -> CoreResult<EncryptedAppStateMutation> {
    let iv: [u8; 16] = rand::random();
    encrypt_chat_mutation_patch_with_iv(patch, key_id, key_data, &iv)
}

#[cfg(feature = "noise")]
pub fn build_app_state_patch_bundle<I>(
    collection: AppStateCollection,
    previous_state: &AppStatePatchState,
    key_id: &[u8],
    key_data: &[u8],
    mutations: I,
) -> CoreResult<AppStatePatchBundle>
where
    I: IntoIterator<Item = EncryptedAppStateMutation>,
{
    if key_id.is_empty() {
        return Err(CoreError::Protocol(
            "app-state patch key id must not be empty".to_owned(),
        ));
    }
    let mutations = mutations.into_iter().collect::<Vec<_>>();
    if mutations.is_empty() {
        return Err(CoreError::Protocol(
            "app-state patch requires at least one mutation".to_owned(),
        ));
    }
    for mutation in &mutations {
        validate_mutation_key_id(&mutation.mutation, key_id)?;
    }

    let hash_mutations = mutations
        .iter()
        .map(AppStateHashMutation::from_encrypted)
        .collect::<CoreResult<Vec<_>>>()?;
    let next_state = previous_state.advance_with_hash_mutations(hash_mutations)?;
    let next_version = next_state.version;
    let keys = wa_crypto::derive_app_state_keys(key_data).map_err(CoreError::Crypto)?;
    let snapshot_mac =
        wa_crypto::app_state_snapshot_mac(&next_state.hash, next_version, collection.name(), &keys)
            .map_err(CoreError::Crypto)?;
    let patch_mac = wa_crypto::app_state_patch_mac(
        &snapshot_mac,
        mutations.iter().map(|mutation| mutation.value_mac.as_ref()),
        next_version,
        collection.name(),
        &keys,
    )
    .map_err(CoreError::Crypto)?;

    let patch = SyncdPatch {
        version: Some(SyncdVersion {
            version: Some(next_version),
        }),
        mutations: mutations
            .into_iter()
            .map(|mutation| mutation.mutation)
            .collect(),
        external_mutations: None,
        snapshot_mac: Some(Bytes::copy_from_slice(&snapshot_mac)),
        patch_mac: Some(Bytes::copy_from_slice(&patch_mac)),
        key_id: Some(KeyId {
            id: Some(Bytes::copy_from_slice(key_id)),
        }),
        exit_code: None,
        device_index: None,
        client_debug_data: None,
    };
    let encoded_patch = encode_app_state_patch(&patch);
    Ok(AppStatePatchBundle {
        collection,
        previous_version: previous_state.version,
        next_state,
        patch,
        encoded_patch,
    })
}

#[cfg(feature = "noise")]
pub fn decode_app_state_patch(
    collection: AppStateCollection,
    previous_state: &AppStatePatchState,
    patch: &SyncdPatch,
    key_data: &[u8],
) -> CoreResult<DecodedAppStatePatch> {
    if patch.mutations.is_empty() {
        return Err(CoreError::Protocol(
            "app-state patch requires at least one mutation".to_owned(),
        ));
    }
    let version = patch
        .version
        .as_ref()
        .and_then(|version| version.version)
        .ok_or_else(|| CoreError::Protocol("app-state patch is missing version".to_owned()))?;
    let expected_version = previous_state
        .version
        .checked_add(1)
        .ok_or_else(|| CoreError::Payload("app-state patch version overflow".to_owned()))?;
    if version != expected_version {
        return Err(CoreError::Protocol(format!(
            "app-state patch version {version} does not follow previous version {}",
            previous_state.version
        )));
    }

    let patch_key_id = patch_key_id(patch)?;
    let snapshot_mac = patch
        .snapshot_mac
        .as_ref()
        .ok_or_else(|| CoreError::Protocol("app-state patch is missing snapshot MAC".to_owned()))?;
    validate_app_state_mac("app-state snapshot mac", snapshot_mac)?;
    let patch_mac = patch
        .patch_mac
        .as_ref()
        .ok_or_else(|| CoreError::Protocol("app-state patch is missing patch MAC".to_owned()))?;
    validate_app_state_mac("app-state patch mac", patch_mac)?;

    let keys = wa_crypto::derive_app_state_keys(key_data).map_err(CoreError::Crypto)?;
    let decoded = patch
        .mutations
        .iter()
        .map(|mutation| decode_app_state_mutation(mutation, &keys))
        .collect::<CoreResult<Vec<_>>>()?;
    for mutation in &decoded {
        if mutation.key_id.as_ref() != patch_key_id.as_ref() {
            return Err(CoreError::Protocol(
                "app-state mutation key id does not match patch key id".to_owned(),
            ));
        }
    }

    let expected_patch_mac = wa_crypto::app_state_patch_mac(
        snapshot_mac,
        decoded.iter().map(|mutation| mutation.value_mac.as_ref()),
        version,
        collection.name(),
        &keys,
    )
    .map_err(CoreError::Crypto)?;
    if !constant_time_eq(&expected_patch_mac, patch_mac) {
        return Err(CoreError::Protocol(
            "app-state patch MAC verification failed".to_owned(),
        ));
    }

    let hash_mutations = decoded
        .iter()
        .map(|mutation| {
            AppStateHashMutation::new(
                mutation.operation,
                mutation.index_mac.clone(),
                mutation.value_mac.clone(),
            )
        })
        .collect::<CoreResult<Vec<_>>>()?;
    let next_state = previous_state.advance_with_hash_mutations(hash_mutations)?;
    let expected_snapshot_mac =
        wa_crypto::app_state_snapshot_mac(next_state.hash(), version, collection.name(), &keys)
            .map_err(CoreError::Crypto)?;
    if !constant_time_eq(&expected_snapshot_mac, snapshot_mac) {
        return Err(CoreError::Protocol(
            "app-state snapshot MAC verification failed".to_owned(),
        ));
    }

    Ok(DecodedAppStatePatch {
        collection,
        previous_version: previous_state.version,
        next_state,
        patch: patch.clone(),
        mutations: decoded,
    })
}

#[cfg(feature = "noise")]
pub fn decode_app_state_snapshot(
    collection: AppStateCollection,
    snapshot: &SyncdSnapshot,
    key_data: &[u8],
) -> CoreResult<DecodedAppStateSnapshot> {
    let version = snapshot
        .version
        .as_ref()
        .and_then(|version| version.version)
        .ok_or_else(|| CoreError::Protocol("app-state snapshot is missing version".to_owned()))?;
    let snapshot_key_id = snapshot_key_id(snapshot)?;
    let snapshot_mac = snapshot
        .mac
        .as_ref()
        .ok_or_else(|| CoreError::Protocol("app-state snapshot is missing MAC".to_owned()))?;
    validate_app_state_mac("app-state snapshot mac", snapshot_mac)?;

    let keys = wa_crypto::derive_app_state_keys(key_data).map_err(CoreError::Crypto)?;
    let decoded = snapshot
        .records
        .iter()
        .map(|record| decode_app_state_record(AppStatePatchOperation::Set, record, &keys))
        .collect::<CoreResult<Vec<_>>>()?;
    for mutation in &decoded {
        if mutation.key_id.as_ref() != snapshot_key_id.as_ref() {
            return Err(CoreError::Protocol(
                "app-state snapshot record key id does not match snapshot key id".to_owned(),
            ));
        }
    }

    let hash_mutations = decoded
        .iter()
        .map(|mutation| {
            AppStateHashMutation::new(
                mutation.operation,
                mutation.index_mac.clone(),
                mutation.value_mac.clone(),
            )
        })
        .collect::<CoreResult<Vec<_>>>()?;
    let state =
        AppStatePatchState::empty().apply_hash_mutations_at_version(version, hash_mutations)?;
    let expected_snapshot_mac =
        wa_crypto::app_state_snapshot_mac(state.hash(), version, collection.name(), &keys)
            .map_err(CoreError::Crypto)?;
    if !constant_time_eq(&expected_snapshot_mac, snapshot_mac) {
        return Err(CoreError::Protocol(
            "app-state snapshot MAC verification failed".to_owned(),
        ));
    }

    Ok(DecodedAppStateSnapshot {
        collection,
        version,
        state,
        snapshot: snapshot.clone(),
        mutations: decoded,
    })
}

#[cfg(feature = "noise")]
pub fn event_batch_from_decoded_app_state_patch(
    patch: &DecodedAppStatePatch,
    is_initial_sync: bool,
) -> CoreResult<EventBatch> {
    event_batch_from_decoded_app_state_mutations(&patch.mutations, is_initial_sync)
}

#[cfg(feature = "noise")]
pub fn event_batch_from_decoded_app_state_snapshot(
    snapshot: &DecodedAppStateSnapshot,
) -> CoreResult<EventBatch> {
    event_batch_from_decoded_app_state_mutations(&snapshot.mutations, true)
}

#[cfg(feature = "noise")]
pub fn event_batch_from_decoded_app_state_mutations<'a, I>(
    mutations: I,
    is_initial_sync: bool,
) -> CoreResult<EventBatch>
where
    I: IntoIterator<Item = &'a DecodedAppStateMutation>,
{
    let mut batch = EventBatch::default();
    for mutation in mutations {
        push_app_state_mutation_event(&mut batch, mutation, is_initial_sync)?;
    }
    Ok(batch)
}

#[cfg(feature = "noise")]
pub async fn load_app_state_patch_state<S>(
    store: &S,
    collection: AppStateCollection,
) -> CoreResult<AppStatePatchState>
where
    S: AuthStore,
{
    let Some(encoded) = store
        .get(KeyNamespace::AppStateSyncVersion, collection.name())
        .await?
    else {
        return Ok(AppStatePatchState::empty());
    };
    decode_app_state_patch_state_bytes(&encoded)
}

#[cfg(feature = "noise")]
pub async fn save_app_state_patch_state<S>(
    store: &S,
    collection: AppStateCollection,
    state: &AppStatePatchState,
) -> CoreResult<()>
where
    S: AuthStore,
{
    let encoded = encode_app_state_patch_state_bytes(state)?;
    store
        .set(
            KeyNamespace::AppStateSyncVersion,
            collection.name(),
            &encoded,
        )
        .await?;
    Ok(())
}

#[cfg(feature = "noise")]
pub fn app_state_sync_key_store_id(key_id: &[u8]) -> CoreResult<String> {
    if key_id.is_empty() {
        return Err(CoreError::Protocol(
            "app-state sync key id must not be empty".to_owned(),
        ));
    }
    Ok(BASE64.encode(key_id))
}

#[cfg(feature = "noise")]
pub fn app_state_patch_key_id(patch: &SyncdPatch) -> CoreResult<Bytes> {
    patch_key_id(patch).cloned()
}

#[cfg(feature = "noise")]
pub async fn load_app_state_sync_key_data<S>(store: &S, key_id: &[u8]) -> CoreResult<Option<Bytes>>
where
    S: AuthStore,
{
    let store_id = app_state_sync_key_store_id(key_id)?;
    let Some(encoded) = store.get(KeyNamespace::AppStateSyncKey, &store_id).await? else {
        return Ok(None);
    };
    let key = AppStateSyncKeyData::decode(encoded.as_slice())?;
    let key_data = key
        .key_data
        .filter(|key_data| !key_data.is_empty())
        .ok_or_else(|| CoreError::Protocol("app-state sync key data is missing".to_owned()))?;
    Ok(Some(key_data))
}

#[cfg(feature = "noise")]
pub async fn save_app_state_sync_key_data<S>(
    store: &S,
    key_id: &[u8],
    key_data: &[u8],
) -> CoreResult<()>
where
    S: AuthStore,
{
    if key_data.is_empty() {
        return Err(CoreError::Protocol(
            "app-state sync key data must not be empty".to_owned(),
        ));
    }
    let store_id = app_state_sync_key_store_id(key_id)?;
    let encoded = AppStateSyncKeyData {
        key_data: Some(Bytes::copy_from_slice(key_data)),
        fingerprint: None,
        timestamp: None,
    }
    .encode_to_vec();
    store
        .set(KeyNamespace::AppStateSyncKey, &store_id, &encoded)
        .await?;
    Ok(())
}

#[cfg(feature = "noise")]
pub async fn save_app_state_blocked_collection<S>(
    store: &S,
    blocked: &AppStateBlockedCollection,
) -> CoreResult<()>
where
    S: AuthStore,
{
    let encoded = encode_app_state_blocked_collection_bytes(blocked)?;
    store
        .set(
            KeyNamespace::AppStateSyncBlocked,
            blocked.collection.name(),
            &encoded,
        )
        .await?;
    Ok(())
}

#[cfg(feature = "noise")]
pub async fn load_app_state_blocked_collection<S>(
    store: &S,
    collection: AppStateCollection,
) -> CoreResult<Option<AppStateBlockedCollection>>
where
    S: AuthStore,
{
    let Some(encoded) = store
        .get(KeyNamespace::AppStateSyncBlocked, collection.name())
        .await?
    else {
        return Ok(None);
    };
    decode_app_state_blocked_collection_bytes(collection, &encoded).map(Some)
}

#[cfg(feature = "noise")]
pub async fn delete_app_state_blocked_collection<S>(
    store: &S,
    collection: AppStateCollection,
) -> CoreResult<()>
where
    S: AuthStore,
{
    store
        .delete(KeyNamespace::AppStateSyncBlocked, collection.name())
        .await?;
    Ok(())
}

#[cfg(feature = "noise")]
pub async fn load_app_state_blocked_collections_for_keys<'a, S, I>(
    store: &S,
    key_ids: I,
) -> CoreResult<Vec<AppStateBlockedCollection>>
where
    S: AuthStore,
    I: IntoIterator<Item = &'a [u8]>,
{
    let key_ids = key_ids
        .into_iter()
        .map(Bytes::copy_from_slice)
        .collect::<Vec<_>>();
    if key_ids.is_empty() {
        return Ok(Vec::new());
    }

    let mut blocked = Vec::new();
    for collection in AppStateCollection::all() {
        if let Some(entry) = load_app_state_blocked_collection(store, *collection).await?
            && key_ids.iter().any(|key_id| key_id == &entry.key_id)
        {
            blocked.push(entry);
        }
    }
    Ok(blocked)
}

#[cfg(feature = "noise")]
pub fn app_state_sync_key_share_from_message(
    message: &ProtoMessage,
    from_me: bool,
) -> CoreResult<Vec<AppStateSyncKeyShareItem>> {
    let Some(protocol) = message.protocol_message.as_ref() else {
        return Ok(Vec::new());
    };
    let Some(protocol_type) = protocol.r#type else {
        return Ok(Vec::new());
    };
    if protocol_message::Type::try_from(protocol_type).ok()
        != Some(protocol_message::Type::AppStateSyncKeyShare)
    {
        return Ok(Vec::new());
    }
    if !from_me {
        return Ok(Vec::new());
    }

    let share = protocol.app_state_sync_key_share.as_ref().ok_or_else(|| {
        CoreError::Protocol("app-state sync key-share message is missing keys".to_owned())
    })?;
    share
        .keys
        .iter()
        .map(|key| {
            let key_id = key
                .key_id
                .as_ref()
                .and_then(|key_id| key_id.key_id.as_ref())
                .filter(|key_id| !key_id.is_empty())
                .ok_or_else(|| {
                    CoreError::Protocol("app-state sync key-share missing key id".to_owned())
                })?;
            let key_data = key
                .key_data
                .as_ref()
                .and_then(|key_data| key_data.key_data.as_ref())
                .filter(|key_data| !key_data.is_empty())
                .ok_or_else(|| {
                    CoreError::Protocol("app-state sync key-share missing key data".to_owned())
                })?;
            Ok(AppStateSyncKeyShareItem {
                key_id: key_id.clone(),
                key_data: key_data.clone(),
            })
        })
        .collect()
}

#[cfg(feature = "noise")]
pub fn app_state_sync_key_share_from_message_event(
    event: &MessageEvent,
) -> CoreResult<Vec<AppStateSyncKeyShareItem>> {
    let Some(payload) = event.payload.as_ref() else {
        return Ok(Vec::new());
    };
    let message = ProtoMessage::decode(payload.as_ref())?;
    let from_me = event
        .fields
        .get("from_me")
        .is_some_and(|value| value == "true");
    app_state_sync_key_share_from_message(&message, from_me)
}

#[cfg(feature = "noise")]
pub async fn save_app_state_sync_key_share<S, I>(
    store: &S,
    keys: I,
) -> CoreResult<Vec<AppStateBlockedCollection>>
where
    S: AuthStore,
    I: IntoIterator<Item = AppStateSyncKeyShareItem>,
{
    let keys = keys.into_iter().collect::<Vec<_>>();
    for key in &keys {
        save_app_state_sync_key_data(store, &key.key_id, &key.key_data).await?;
    }
    load_app_state_blocked_collections_for_keys(store, keys.iter().map(|key| key.key_id.as_ref()))
        .await
}

#[cfg(feature = "noise")]
pub async fn apply_decoded_app_state_patch_to_store<S>(
    store: &S,
    patch: &DecodedAppStatePatch,
    is_initial_sync: bool,
) -> CoreResult<EventBatch>
where
    S: AuthStore,
{
    let batch = event_batch_from_decoded_app_state_patch(patch, is_initial_sync)?;
    save_app_state_patch_state(store, patch.collection, &patch.next_state).await?;
    Ok(batch)
}

#[cfg(feature = "noise")]
pub async fn apply_decoded_app_state_snapshot_to_store<S>(
    store: &S,
    snapshot: &DecodedAppStateSnapshot,
) -> CoreResult<EventBatch>
where
    S: AuthStore,
{
    let batch = event_batch_from_decoded_app_state_snapshot(snapshot)?;
    save_app_state_patch_state(store, snapshot.collection, &snapshot.state).await?;
    Ok(batch)
}

#[cfg(feature = "noise")]
pub async fn apply_app_state_sync_response_to_store<S>(
    store: &S,
    response: &AppStateSyncResponse,
    key_data: &[u8],
    is_initial_sync: bool,
) -> CoreResult<AppStateSyncApplyOutcome>
where
    S: AuthStore,
{
    let mut outcome = AppStateSyncApplyOutcome::default();

    for collection in &response.collections {
        let mut state = load_app_state_patch_state(store, collection.collection).await?;
        let mut applied_patches = 0usize;
        let batch_count_before = outcome.batches.len();

        for patch in &collection.patches {
            let decoded = decode_app_state_patch(collection.collection, &state, patch, key_data)?;
            let batch =
                apply_decoded_app_state_patch_to_store(store, &decoded, is_initial_sync).await?;
            state = decoded.next_state;
            applied_patches += 1;
            if !batch.is_empty() {
                outcome.batches.push(batch);
            }
        }

        if let Some(reference) = &collection.snapshot {
            outcome.pending_snapshots.push(AppStatePendingSnapshot {
                collection: collection.collection,
                reference: reference.clone(),
            });
        }

        outcome.collections.push(AppStateCollectionSyncOutcome {
            collection: collection.collection,
            response_version: collection.version,
            final_version: state.version(),
            applied_patches,
            emitted_batches: outcome.batches.len() - batch_count_before,
            has_more_patches: collection.has_more_patches,
            snapshot_pending: collection.snapshot.is_some(),
        });
    }

    Ok(outcome)
}

#[cfg(feature = "noise")]
pub async fn apply_app_state_sync_response_with_store_keys<S>(
    store: &S,
    response: &AppStateSyncResponse,
    is_initial_sync: bool,
) -> CoreResult<AppStateSyncApplyOutcome>
where
    S: AuthStore,
{
    let mut outcome = AppStateSyncApplyOutcome::default();

    for collection in &response.collections {
        let mut state = load_app_state_patch_state(store, collection.collection).await?;
        let mut applied_patches = 0usize;
        let batch_count_before = outcome.batches.len();
        let mut blocked = false;

        for patch in &collection.patches {
            let key_id = app_state_patch_key_id(patch)?;
            let Some(key_data) = load_app_state_sync_key_data(store, &key_id).await? else {
                let blocked_collection = AppStateBlockedCollection {
                    collection: collection.collection,
                    key_id,
                    previous_version: state.version(),
                };
                save_app_state_blocked_collection(store, &blocked_collection).await?;
                outcome.blocked.push(blocked_collection);
                blocked = true;
                break;
            };
            let decoded = decode_app_state_patch(collection.collection, &state, patch, &key_data)?;
            let batch =
                apply_decoded_app_state_patch_to_store(store, &decoded, is_initial_sync).await?;
            state = decoded.next_state;
            applied_patches += 1;
            if !batch.is_empty() {
                outcome.batches.push(batch);
            }
        }

        if !blocked && let Some(reference) = &collection.snapshot {
            outcome.pending_snapshots.push(AppStatePendingSnapshot {
                collection: collection.collection,
                reference: reference.clone(),
            });
        }
        if !blocked {
            delete_app_state_blocked_collection(store, collection.collection).await?;
        }

        outcome.collections.push(AppStateCollectionSyncOutcome {
            collection: collection.collection,
            response_version: collection.version,
            final_version: state.version(),
            applied_patches,
            emitted_batches: outcome.batches.len() - batch_count_before,
            has_more_patches: collection.has_more_patches,
            snapshot_pending: !blocked && collection.snapshot.is_some(),
        });
    }

    Ok(outcome)
}

#[cfg(feature = "noise")]
fn push_app_state_mutation_event(
    batch: &mut EventBatch,
    mutation: &DecodedAppStateMutation,
    is_initial_sync: bool,
) -> CoreResult<()> {
    let value = mutation
        .sync_action
        .value
        .as_ref()
        .ok_or_else(|| CoreError::Protocol("sync action value is missing".to_owned()))?;

    if let Some(action) = value.contact_action.as_ref() {
        push_contact_sync_event(batch, mutation, action)?;
    } else if let Some(action) = value.quick_reply_action.as_ref() {
        push_quick_reply_sync_event(batch, mutation, action)?;
    } else if let Some(action) = value.label_edit_action.as_ref() {
        push_label_edit_sync_event(batch, mutation, action)?;
    } else if let Some(action) = value.label_association_action.as_ref() {
        push_label_association_sync_event(batch, mutation, action)?;
    } else if let Some(action) = value.archive_chat_action.as_ref() {
        let chat_jid = required_index_jid(mutation, 1, "archive chat JID")?;
        let archived = action.archived.unwrap_or(false);
        batch
            .chats_update
            .push(ChatEvent::new(chat_jid).with_field("archived", archived.to_string()));
    } else if let Some(action) = value.mark_chat_as_read_action.as_ref() {
        let chat_jid = required_index_jid(mutation, 1, "mark-read chat JID")?;
        let unread_count = if action.read.unwrap_or(false) {
            "0"
        } else {
            "-1"
        };
        batch
            .chats_update
            .push(ChatEvent::new(chat_jid).with_field("unread_count", unread_count.to_owned()));
    } else if let Some(action) = value.mute_action.as_ref() {
        let chat_jid = required_index_jid(mutation, 1, "mute chat JID")?;
        let mut event =
            ChatEvent::new(chat_jid).with_field("muted", action.muted.unwrap_or(false).to_string());
        if let Some(timestamp) = action.mute_end_timestamp {
            event = event.with_field("mute_end_timestamp", timestamp.to_string());
        }
        batch.chats_update.push(event);
    } else if let Some(action) = value.pin_action.as_ref() {
        let chat_jid = required_index_jid(mutation, 1, "pin chat JID")?;
        let pinned = action.pinned.unwrap_or(false);
        let value = if pinned {
            value
                .timestamp
                .map(|timestamp| timestamp.to_string())
                .unwrap_or_else(|| "true".to_owned())
        } else {
            "false".to_owned()
        };
        batch
            .chats_update
            .push(ChatEvent::new(chat_jid).with_field("pinned", value));
    } else if value.delete_chat_action.is_some() && !is_initial_sync {
        let chat_jid = required_index_jid(mutation, 1, "delete chat JID")?;
        batch.chats_delete.push(chat_jid);
    } else if let Some(action) = value.star_action.as_ref() {
        let chat_jid = required_index_jid(mutation, 1, "star chat JID")?;
        let message_id = required_index_value(mutation, 2, "star message id")?.to_owned();
        let starred = action.starred.unwrap_or(false);
        batch.messages_update.push(
            MessageUpdate::new(MessageEventKey::new(chat_jid, message_id, None))
                .with_field("starred", starred.to_string()),
        );
    }

    Ok(())
}

#[cfg(feature = "noise")]
fn push_contact_sync_event(
    batch: &mut EventBatch,
    mutation: &DecodedAppStateMutation,
    action: &sync_action_value::ContactAction,
) -> CoreResult<()> {
    let chat_jid = required_index_jid(mutation, 1, "contact chat JID")?;
    if mutation.operation == AppStatePatchOperation::Remove {
        batch.contacts_delete.push(chat_jid);
        return Ok(());
    }

    let mut event = ContactEvent::new(chat_jid.clone());
    if let Some(name) = first_non_empty([
        action.full_name.as_deref(),
        action.first_name.as_deref(),
        action.username.as_deref(),
    ]) {
        event = event.with_field("name", name.to_owned());
    }
    if let Some(username) = action.username.as_deref().filter(|value| !value.is_empty()) {
        event = event.with_field("username", username.to_owned());
    }
    if let Some(lid) = action.lid_jid.as_deref().filter(|value| !value.is_empty()) {
        validate_jid("contact LID JID", lid)?;
        event = event.with_field("lid", lid.to_owned());
    }
    if let Some(pn) = contact_phone_number(&chat_jid, action.pn_jid.as_deref())? {
        event = event.with_field("phone_number", pn);
    }
    batch.contacts_upsert.push(event);
    Ok(())
}

#[cfg(feature = "noise")]
fn push_quick_reply_sync_event(
    batch: &mut EventBatch,
    mutation: &DecodedAppStateMutation,
    action: &sync_action_value::QuickReplyAction,
) -> CoreResult<()> {
    let id = required_index_value(mutation, 1, "quick reply id")?.to_owned();
    let mut event = QuickReplyEvent::new(id);
    if let Some(shortcut) = action.shortcut.as_deref() {
        event = event.with_field("shortcut", shortcut.to_owned());
    }
    if let Some(message) = action.message.as_deref() {
        event = event.with_field("message", message.to_owned());
    }
    if !action.keywords.is_empty() {
        let keywords = serde_json::to_string(&action.keywords).map_err(|err| {
            CoreError::Payload(format!("failed to encode quick reply keywords: {err}"))
        })?;
        event = event.with_field("keywords", keywords);
    }
    if let Some(count) = action.count {
        event = event.with_field("count", count.to_string());
    }
    if let Some(deleted) = action.deleted {
        event = event.with_field("deleted", deleted.to_string());
    }
    batch.quick_replies_update.push(event);
    Ok(())
}

#[cfg(feature = "noise")]
fn push_label_edit_sync_event(
    batch: &mut EventBatch,
    mutation: &DecodedAppStateMutation,
    action: &sync_action_value::LabelEditAction,
) -> CoreResult<()> {
    let id = required_index_value(mutation, 1, "label id")?.to_owned();
    let mut event = LabelEvent::new(id);
    if let Some(name) = action.name.as_deref() {
        event = event.with_field("name", name.to_owned());
    }
    if let Some(color) = action.color {
        event = event.with_field("color", color.to_string());
    }
    if let Some(predefined_id) = action.predefined_id {
        event = event.with_field("predefined_id", predefined_id.to_string());
    }
    if let Some(deleted) = action.deleted {
        event = event.with_field("deleted", deleted.to_string());
    }
    if let Some(order_index) = action.order_index {
        event = event.with_field("order_index", order_index.to_string());
    }
    if let Some(is_active) = action.is_active {
        event = event.with_field("is_active", is_active.to_string());
    }
    if let Some(list_type) = action.r#type {
        event = event.with_field("list_type", list_type.to_string());
    }
    if let Some(is_immutable) = action.is_immutable {
        event = event.with_field("is_immutable", is_immutable.to_string());
    }
    if let Some(mute_end_time_ms) = action.mute_end_time_ms {
        event = event.with_field("mute_end_time_ms", mute_end_time_ms.to_string());
    }
    batch.labels_edit.push(event);
    Ok(())
}

#[cfg(feature = "noise")]
fn push_label_association_sync_event(
    batch: &mut EventBatch,
    mutation: &DecodedAppStateMutation,
    action: &sync_action_value::LabelAssociationAction,
) -> CoreResult<()> {
    let association_type = required_index_value(mutation, 0, "label association type")?;
    let label_id = required_index_value(mutation, 1, "label id")?.to_owned();
    let chat_jid = required_index_jid(mutation, 2, "label association chat JID")?;
    let labeled = action.labeled.unwrap_or(false);
    match association_type {
        "label_jid" => batch
            .labels_association
            .push(LabelAssociationEvent::chat(label_id, chat_jid, labeled)),
        "label_message" => {
            let message_id =
                required_index_value(mutation, 3, "label association message id")?.to_owned();
            batch
                .labels_association
                .push(LabelAssociationEvent::message(
                    label_id, chat_jid, message_id, labeled,
                ));
        }
        value => {
            return Err(CoreError::Protocol(format!(
                "unknown label association type: {value}"
            )));
        }
    }
    Ok(())
}

#[cfg(feature = "noise")]
pub fn uploaded_media_from_app_state_external_blob(
    reference: &ExternalBlobReference,
) -> CoreResult<UploadedMedia> {
    let media_key = required_external_blob_bytes(reference.media_key.as_ref(), "media key")?;
    let file_sha256 = required_external_blob_bytes(reference.file_sha256.as_ref(), "file SHA-256")?;
    let file_enc_sha256 =
        required_external_blob_bytes(reference.file_enc_sha256.as_ref(), "encrypted file SHA-256")?;
    validate_external_blob_len("media key", &media_key, 32)?;
    validate_external_blob_len("file SHA-256", &file_sha256, 32)?;
    validate_external_blob_len("encrypted file SHA-256", &file_enc_sha256, 32)?;

    let file_size_bytes = reference.file_size_bytes.ok_or_else(|| {
        CoreError::Payload("app-state external blob missing file size".to_owned())
    })?;
    let direct_path = reference
        .direct_path
        .as_deref()
        .filter(|path| !path.is_empty())
        .ok_or_else(|| {
            CoreError::Payload("app-state external blob missing direct path".to_owned())
        })?;

    Ok(
        UploadedMedia::new(media_key, file_sha256, file_enc_sha256, file_size_bytes)
            .with_direct_path(direct_path.to_owned()),
    )
}

#[cfg(feature = "noise")]
pub async fn download_app_state_external_blob<T>(
    transfer: &MediaTransfer<T>,
    reference: &ExternalBlobReference,
    fallback_host: Option<&str>,
) -> CoreResult<Bytes>
where
    T: MediaTransport,
{
    let media = uploaded_media_from_app_state_external_blob(reference)?;
    validate_external_blob_declared_size(&media, transfer.config().max_download_ciphertext_bytes)?;
    let plaintext = transfer
        .download_bytes(&media, wa_crypto::MediaKind::AppState, fallback_host)
        .await?;
    let actual_len = u64::try_from(plaintext.len())
        .map_err(|_| CoreError::Payload("app-state external blob length exceeds u64".to_owned()))?;
    if actual_len != media.file_length {
        return Err(CoreError::Payload(format!(
            "app-state external blob length mismatch: expected {}, got {actual_len}",
            media.file_length
        )));
    }
    Ok(Bytes::from(plaintext))
}

#[cfg(feature = "noise")]
pub async fn download_app_state_external_snapshot<T>(
    transfer: &MediaTransfer<T>,
    reference: &ExternalBlobReference,
    fallback_host: Option<&str>,
) -> CoreResult<SyncdSnapshot>
where
    T: MediaTransport,
{
    let plaintext = download_app_state_external_blob(transfer, reference, fallback_host).await?;
    SyncdSnapshot::decode(plaintext.as_ref()).map_err(CoreError::from)
}

#[cfg(feature = "noise")]
pub async fn download_and_decode_app_state_snapshot<T>(
    transfer: &MediaTransfer<T>,
    collection: AppStateCollection,
    reference: &ExternalBlobReference,
    key_data: &[u8],
    fallback_host: Option<&str>,
) -> CoreResult<DecodedAppStateSnapshot>
where
    T: MediaTransport,
{
    let snapshot = download_app_state_external_snapshot(transfer, reference, fallback_host).await?;
    decode_app_state_snapshot(collection, &snapshot, key_data)
}

#[cfg(feature = "noise")]
pub async fn download_app_state_external_mutations<T>(
    transfer: &MediaTransfer<T>,
    reference: &ExternalBlobReference,
    fallback_host: Option<&str>,
) -> CoreResult<SyncdMutations>
where
    T: MediaTransport,
{
    let plaintext = download_app_state_external_blob(transfer, reference, fallback_host).await?;
    SyncdMutations::decode(plaintext.as_ref()).map_err(CoreError::from)
}

pub fn build_clean_dirty_bits_node(
    dirty_type: DirtyBitType,
    from_timestamp: Option<u64>,
    tag: impl Into<String>,
) -> CoreResult<BinaryNode> {
    let mut clean = BinaryNode::new("clean").with_attr("type", dirty_type.value());
    if let Some(timestamp) = from_timestamp {
        clean = clean.with_attr("timestamp", timestamp.to_string());
    }
    Ok(BinaryNode::new("iq")
        .with_attr("id", tag.into())
        .with_attr("to", S_WHATSAPP_NET)
        .with_attr("type", "set")
        .with_attr("xmlns", "urn:xmpp:whatsapp:dirty")
        .with_content(vec![clean]))
}

pub fn parse_dirty_notification_node(node: &BinaryNode) -> CoreResult<Option<DirtyNotification>> {
    let dirty = if node.tag == "dirty" {
        Some(node)
    } else {
        child_node(node, "dirty")
    };
    let Some(dirty) = dirty else {
        return Ok(None);
    };
    let dirty_type = dirty
        .attrs
        .get("type")
        .map(String::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| CoreError::Protocol("dirty notification missing type".to_owned()))?;
    let timestamp = optional_u64_attr(dirty, "timestamp")?.or(optional_u64_attr(dirty, "t")?);
    Ok(Some(DirtyNotification {
        dirty_type: dirty_type.to_owned(),
        timestamp,
    }))
}

pub fn build_app_state_sync_query<I>(
    collections: I,
    tag: impl Into<String>,
) -> CoreResult<BinaryNode>
where
    I: IntoIterator<Item = AppStateCollectionRequest>,
{
    let collection_nodes = collections
        .into_iter()
        .map(|request| {
            BinaryNode::new("collection")
                .with_attr("name", request.collection.name())
                .with_attr("version", request.version.to_string())
                .with_attr("return_snapshot", request.return_snapshot.to_string())
        })
        .collect::<Vec<_>>();
    if collection_nodes.is_empty() {
        return Err(CoreError::Protocol(
            "app-state sync requires at least one collection".to_owned(),
        ));
    }

    Ok(
        app_state_iq(tag)
            .with_content(vec![BinaryNode::new("sync").with_content(collection_nodes)]),
    )
}

pub fn parse_app_state_sync_response(
    node: &BinaryNode,
) -> CoreResult<Option<AppStateSyncResponse>> {
    if node.attrs.get("type").is_none_or(|value| value != "result") {
        return Ok(None);
    }
    let Some(sync) = child_node(node, "sync") else {
        return Ok(Some(AppStateSyncResponse::default()));
    };
    let collections = node_children(sync, "collection")
        .into_iter()
        .map(parse_app_state_sync_collection)
        .collect::<CoreResult<Vec<_>>>()?;
    Ok(Some(AppStateSyncResponse { collections }))
}

pub fn parse_app_state_query_result(node: &BinaryNode, query: AppStateQueryKind) -> CoreResult<()> {
    let label = query.label();
    if node.tag != "iq" {
        return Err(CoreError::Protocol(format!(
            "{label} response must be iq, got {}",
            node.tag
        )));
    }
    if let Some(error) = app_state_error_from_result(node) {
        return Err(CoreError::Protocol(format!(
            "{label} failed{}",
            app_state_error_suffix(&error)
        )));
    }
    match node.attrs.get("type").map(String::as_str) {
        Some("result") => Ok(()),
        Some(value) => Err(CoreError::Protocol(format!(
            "unexpected {label} response type: {value}"
        ))),
        None => Err(CoreError::Protocol(format!(
            "{label} response missing type"
        ))),
    }
}

fn parse_app_state_sync_collection(node: &BinaryNode) -> CoreResult<AppStateSyncCollection> {
    let name = node
        .attrs
        .get("name")
        .ok_or_else(|| CoreError::Protocol("app-state collection is missing name".to_owned()))?;
    let collection = AppStateCollection::from_name(name)?;
    let version = optional_u64_attr(node, "version")?;
    let has_more_patches = node
        .attrs
        .get("has_more_patches")
        .is_some_and(|value| value == "true");
    let snapshot = if let Some(snapshot) = child_node(node, "snapshot") {
        node_bytes(snapshot)?
            .map(|bytes| ExternalBlobReference::decode(bytes.as_ref()).map_err(CoreError::from))
            .transpose()?
    } else {
        None
    };
    let patch_parent = child_node(node, "patches").unwrap_or(node);
    let patches = node_children(patch_parent, "patch")
        .into_iter()
        .filter_map(|patch| match node_bytes(patch) {
            Ok(Some(bytes)) => Some(decode_syncd_patch_from_node_bytes(bytes, version)),
            Ok(None) => None,
            Err(err) => Some(Err(err)),
        })
        .collect::<CoreResult<Vec<_>>>()?;

    Ok(AppStateSyncCollection {
        collection,
        version,
        has_more_patches,
        snapshot,
        patches,
    })
}

fn decode_syncd_patch_from_node_bytes(
    bytes: &Bytes,
    collection_version: Option<u64>,
) -> CoreResult<SyncdPatch> {
    let mut patch = SyncdPatch::decode(bytes.as_ref())?;
    if patch.version.is_none() {
        let version = collection_version
            .ok_or_else(|| {
                CoreError::Protocol(
                    "app-state patch without version requires collection version".to_owned(),
                )
            })?
            .checked_add(1)
            .ok_or_else(|| CoreError::Payload("app-state patch version overflow".to_owned()))?;
        patch.version = Some(SyncdVersion {
            version: Some(version),
        });
    }
    Ok(patch)
}

pub fn build_app_state_patch_query(
    collection: AppStateCollection,
    previous_version: u64,
    encoded_patch: impl Into<Bytes>,
    tag: impl Into<String>,
) -> CoreResult<BinaryNode> {
    let encoded_patch = encoded_patch.into();
    if encoded_patch.is_empty() {
        return Err(CoreError::Payload(
            "encoded app-state patch must not be empty".to_owned(),
        ));
    }

    Ok(
        app_state_iq(tag).with_content(vec![BinaryNode::new("sync").with_content(vec![
        BinaryNode::new("collection")
            .with_attr("name", collection.name())
            .with_attr("version", previous_version.to_string())
            .with_attr("return_snapshot", "false")
            .with_content(vec![BinaryNode::new("patch").with_content(encoded_patch)]),
    ])]),
    )
}

pub fn build_mute_chat_patch(
    chat_jid: impl AsRef<str>,
    mute_end_timestamp: Option<u64>,
    action_timestamp_ms: u64,
) -> CoreResult<ChatMutationPatch> {
    let chat_jid = validate_jid("mute chat JID", chat_jid.as_ref())?.to_owned();
    let mut value = sync_action_value(action_timestamp_ms)?;
    value.mute_action = Some(sync_action_value::MuteAction {
        muted: Some(mute_end_timestamp.is_some()),
        mute_end_timestamp: mute_end_timestamp.map(u64_to_i64).transpose()?,
        auto_muted: None,
    });
    Ok(ChatMutationPatch::new(
        AppStateCollection::RegularHigh,
        2,
        vec!["mute".to_owned(), chat_jid],
        value,
    ))
}

pub fn build_archive_chat_patch(
    chat_jid: impl AsRef<str>,
    archived: bool,
    message_range: Option<ChatMutationMessageRange>,
    action_timestamp_ms: u64,
) -> CoreResult<ChatMutationPatch> {
    let chat_jid = validate_jid("archive chat JID", chat_jid.as_ref())?.to_owned();
    let mut value = sync_action_value(action_timestamp_ms)?;
    value.archive_chat_action = Some(sync_action_value::ArchiveChatAction {
        archived: Some(archived),
        message_range: message_range
            .as_ref()
            .map(ChatMutationMessageRange::to_proto)
            .transpose()?,
    });
    Ok(ChatMutationPatch::new(
        AppStateCollection::RegularLow,
        3,
        vec!["archive".to_owned(), chat_jid],
        value,
    ))
}

pub fn build_mark_chat_read_patch(
    chat_jid: impl AsRef<str>,
    read: bool,
    message_range: Option<ChatMutationMessageRange>,
    action_timestamp_ms: u64,
) -> CoreResult<ChatMutationPatch> {
    let chat_jid = validate_jid("mark-read chat JID", chat_jid.as_ref())?.to_owned();
    let mut value = sync_action_value(action_timestamp_ms)?;
    value.mark_chat_as_read_action = Some(sync_action_value::MarkChatAsReadAction {
        read: Some(read),
        message_range: message_range
            .as_ref()
            .map(ChatMutationMessageRange::to_proto)
            .transpose()?,
    });
    Ok(ChatMutationPatch::new(
        AppStateCollection::RegularLow,
        3,
        vec!["markChatAsRead".to_owned(), chat_jid],
        value,
    ))
}

pub fn build_pin_chat_patch(
    chat_jid: impl AsRef<str>,
    pinned: bool,
    action_timestamp_ms: u64,
) -> CoreResult<ChatMutationPatch> {
    let chat_jid = validate_jid("pin chat JID", chat_jid.as_ref())?.to_owned();
    let mut value = sync_action_value(action_timestamp_ms)?;
    value.pin_action = Some(sync_action_value::PinAction {
        pinned: Some(pinned),
    });
    Ok(ChatMutationPatch::new(
        AppStateCollection::RegularLow,
        5,
        vec!["pin_v1".to_owned(), chat_jid],
        value,
    ))
}

pub fn build_star_message_patch(
    key: MessageKey,
    starred: bool,
    action_timestamp_ms: u64,
) -> CoreResult<ChatMutationPatch> {
    let (remote_jid, message_id, from_me) = message_index_parts(&key)?;
    let mut value = sync_action_value(action_timestamp_ms)?;
    value.star_action = Some(sync_action_value::StarAction {
        starred: Some(starred),
    });
    Ok(ChatMutationPatch::new(
        AppStateCollection::RegularLow,
        2,
        vec![
            "star".to_owned(),
            remote_jid,
            message_id,
            if from_me { "1" } else { "0" }.to_owned(),
            "0".to_owned(),
        ],
        value,
    ))
}

pub fn build_delete_chat_patch(
    chat_jid: impl AsRef<str>,
    message_range: Option<ChatMutationMessageRange>,
    action_timestamp_ms: u64,
) -> CoreResult<ChatMutationPatch> {
    let chat_jid = validate_jid("delete chat JID", chat_jid.as_ref())?.to_owned();
    let mut value = sync_action_value(action_timestamp_ms)?;
    value.delete_chat_action = Some(sync_action_value::DeleteChatAction {
        message_range: message_range
            .as_ref()
            .map(ChatMutationMessageRange::to_proto)
            .transpose()?,
    });
    Ok(ChatMutationPatch::new(
        AppStateCollection::RegularHigh,
        6,
        vec!["deleteChat".to_owned(), chat_jid, "1".to_owned()],
        value,
    ))
}

pub fn build_push_name_patch(
    name: impl AsRef<str>,
    action_timestamp_ms: u64,
) -> CoreResult<ChatMutationPatch> {
    let name = validate_non_empty("push name", name.as_ref())?.to_owned();
    let mut value = sync_action_value(action_timestamp_ms)?;
    value.push_name_setting = Some(sync_action_value::PushNameSetting { name: Some(name) });
    Ok(ChatMutationPatch::new(
        AppStateCollection::CriticalBlock,
        1,
        vec!["setting_pushName".to_owned()],
        value,
    ))
}

pub fn build_contact_patch(
    chat_jid: impl AsRef<str>,
    contact: Option<ContactSyncAction>,
    action_timestamp_ms: u64,
) -> CoreResult<ChatMutationPatch> {
    let chat_jid = validate_jid("contact chat JID", chat_jid.as_ref())?.to_owned();
    if let Some(contact) = contact.as_ref()
        && !contact.has_fields()
    {
        return Err(CoreError::Protocol(
            "contact action must include at least one field".to_owned(),
        ));
    }
    let operation = if contact.is_some() {
        AppStatePatchOperation::Set
    } else {
        AppStatePatchOperation::Remove
    };
    let mut value = sync_action_value(action_timestamp_ms)?;
    value.contact_action = Some(match contact {
        Some(contact) => contact.to_proto()?,
        None => sync_action_value::ContactAction::default(),
    });
    Ok(ChatMutationPatch::new(
        AppStateCollection::CriticalUnblockLow,
        2,
        vec!["contact".to_owned(), chat_jid],
        value,
    )
    .with_operation(operation))
}

pub fn build_quick_reply_patch(
    quick_reply: QuickReplyMutation,
    action_timestamp_ms: u64,
) -> CoreResult<ChatMutationPatch> {
    let id = validate_non_empty("quick reply id", &quick_reply.id)?.to_owned();
    let mut value = sync_action_value(action_timestamp_ms)?;
    value.quick_reply_action = Some(quick_reply.to_proto()?);
    Ok(ChatMutationPatch::new(
        AppStateCollection::Regular,
        2,
        vec!["quick_reply".to_owned(), id],
        value,
    ))
}

pub fn build_label_edit_patch(
    label: LabelEditMutation,
    action_timestamp_ms: u64,
) -> CoreResult<ChatMutationPatch> {
    let id = validate_non_empty("label id", &label.id)?.to_owned();
    let mut value = sync_action_value(action_timestamp_ms)?;
    value.label_edit_action = Some(label.to_proto()?);
    Ok(ChatMutationPatch::new(
        AppStateCollection::Regular,
        3,
        vec!["label_edit".to_owned(), id],
        value,
    ))
}

pub fn build_chat_label_association_patch(
    chat_jid: impl AsRef<str>,
    label_id: impl AsRef<str>,
    labeled: bool,
    action_timestamp_ms: u64,
) -> CoreResult<ChatMutationPatch> {
    let chat_jid = validate_jid("label association chat JID", chat_jid.as_ref())?.to_owned();
    let label_id = validate_non_empty("label id", label_id.as_ref())?.to_owned();
    let mut value = sync_action_value(action_timestamp_ms)?;
    value.label_association_action = Some(sync_action_value::LabelAssociationAction {
        labeled: Some(labeled),
    });
    Ok(ChatMutationPatch::new(
        AppStateCollection::Regular,
        3,
        vec!["label_jid".to_owned(), label_id, chat_jid],
        value,
    ))
}

pub fn build_message_label_association_patch(
    chat_jid: impl AsRef<str>,
    label_id: impl AsRef<str>,
    message_id: impl AsRef<str>,
    labeled: bool,
    action_timestamp_ms: u64,
) -> CoreResult<ChatMutationPatch> {
    let chat_jid = validate_jid("label association chat JID", chat_jid.as_ref())?.to_owned();
    let label_id = validate_non_empty("label id", label_id.as_ref())?.to_owned();
    let message_id =
        validate_non_empty("label association message id", message_id.as_ref())?.to_owned();
    let mut value = sync_action_value(action_timestamp_ms)?;
    value.label_association_action = Some(sync_action_value::LabelAssociationAction {
        labeled: Some(labeled),
    });
    Ok(ChatMutationPatch::new(
        AppStateCollection::Regular,
        3,
        vec![
            "label_message".to_owned(),
            label_id,
            chat_jid,
            message_id,
            "0".to_owned(),
            "0".to_owned(),
        ],
        value,
    ))
}

fn app_state_iq(tag: impl Into<String>) -> BinaryNode {
    BinaryNode::new("iq")
        .with_attr("id", tag.into())
        .with_attr("to", S_WHATSAPP_NET)
        .with_attr("type", "set")
        .with_attr("xmlns", "w:sync:app:state")
}

fn app_state_error_from_result(node: &BinaryNode) -> Option<CoreError> {
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
        .unwrap_or("app-state query failed");
    Some(CoreError::Protocol(format!(
        "app-state query failed ({code}): {text}"
    )))
}

fn app_state_error_suffix(error: &CoreError) -> String {
    match error {
        CoreError::Protocol(message) if !message.is_empty() => format!(": {message}"),
        _ => String::new(),
    }
}

fn child_node<'a>(node: &'a BinaryNode, tag: &str) -> Option<&'a BinaryNode> {
    node_children(node, tag).into_iter().next()
}

fn node_children<'a>(node: &'a BinaryNode, tag: &str) -> Vec<&'a BinaryNode> {
    let Some(BinaryNodeContent::Nodes(children)) = &node.content else {
        return Vec::new();
    };
    children.iter().filter(|child| child.tag == tag).collect()
}

fn node_bytes(node: &BinaryNode) -> CoreResult<Option<&Bytes>> {
    match &node.content {
        Some(BinaryNodeContent::Bytes(bytes)) => Ok(Some(bytes)),
        None => Ok(None),
        Some(BinaryNodeContent::Text(_)) | Some(BinaryNodeContent::Nodes(_)) => Err(
            CoreError::Payload(format!("app-state {} node content must be bytes", node.tag)),
        ),
    }
}

fn optional_u64_attr(node: &BinaryNode, attr: &str) -> CoreResult<Option<u64>> {
    node.attrs
        .get(attr)
        .map(|value| {
            value.parse::<u64>().map_err(|err| {
                CoreError::Protocol(format!("invalid app-state {attr} value {value}: {err}"))
            })
        })
        .transpose()
}

fn sync_action_value(timestamp_ms: u64) -> CoreResult<SyncActionValue> {
    Ok(SyncActionValue {
        timestamp: Some(u64_to_i64(timestamp_ms)?),
        ..Default::default()
    })
}

#[cfg(feature = "noise")]
fn validate_app_state_hash(hash: &[u8]) -> CoreResult<()> {
    if hash.len() != APP_STATE_HASH_LEN {
        return Err(CoreError::Payload(format!(
            "app-state hash must be {APP_STATE_HASH_LEN} bytes"
        )));
    }
    Ok(())
}

#[cfg(feature = "noise")]
fn validate_app_state_mac(label: &'static str, mac: &[u8]) -> CoreResult<()> {
    if mac.len() != APP_STATE_MAC_LEN {
        return Err(CoreError::Payload(format!(
            "{label} must be {APP_STATE_MAC_LEN} bytes"
        )));
    }
    Ok(())
}

#[cfg(feature = "noise")]
fn required_external_blob_bytes(bytes: Option<&Bytes>, label: &str) -> CoreResult<Bytes> {
    bytes
        .cloned()
        .filter(|bytes| !bytes.is_empty())
        .ok_or_else(|| CoreError::Payload(format!("app-state external blob missing {label}")))
}

#[cfg(feature = "noise")]
fn validate_external_blob_len(label: &str, bytes: &[u8], expected: usize) -> CoreResult<()> {
    if bytes.len() != expected {
        return Err(CoreError::Payload(format!(
            "app-state external blob {label} must be {expected} bytes"
        )));
    }
    Ok(())
}

#[cfg(feature = "noise")]
fn validate_external_blob_declared_size(
    media: &UploadedMedia,
    max_download: usize,
) -> CoreResult<()> {
    if max_download == 0 {
        return Err(CoreError::Payload(
            "app-state external blob size limit must be greater than zero".to_owned(),
        ));
    }
    let declared_len = usize::try_from(media.file_length).map_err(|_| {
        CoreError::Payload("app-state external blob declared size exceeds usize".to_owned())
    })?;
    if declared_len > max_download {
        return Err(CoreError::Payload(format!(
            "app-state external blob declared size exceeds configured limit: {declared_len} bytes exceeds {max_download}"
        )));
    }
    Ok(())
}

#[cfg(feature = "noise")]
fn index_mac_key(index_mac: &[u8]) -> CoreResult<String> {
    validate_app_state_mac("app-state index mac", index_mac)?;
    Ok(BASE64.encode(index_mac))
}

#[cfg(feature = "noise")]
fn validate_mutation_key_id(mutation: &SyncdMutation, key_id: &[u8]) -> CoreResult<()> {
    let actual = mutation
        .record
        .as_ref()
        .and_then(|record| record.key_id.as_ref())
        .and_then(|key_id| key_id.id.as_ref())
        .ok_or_else(|| CoreError::Protocol("app-state mutation is missing key id".to_owned()))?;
    if actual.as_ref() != key_id {
        return Err(CoreError::Protocol(
            "app-state mutation key id does not match patch key id".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(feature = "noise")]
fn decode_app_state_mutation(
    mutation: &SyncdMutation,
    keys: &wa_crypto::AppStateKeyMaterial,
) -> CoreResult<DecodedAppStateMutation> {
    let operation = AppStatePatchOperation::from_proto_value(
        mutation
            .operation
            .unwrap_or_else(|| AppStatePatchOperation::Set.proto_value()),
    )?;
    let record = mutation
        .record
        .as_ref()
        .ok_or_else(|| CoreError::Protocol("app-state mutation is missing record".to_owned()))?;
    decode_app_state_record(operation, record, keys)
}

#[cfg(feature = "noise")]
fn decode_app_state_record(
    operation: AppStatePatchOperation,
    record: &SyncdRecord,
    keys: &wa_crypto::AppStateKeyMaterial,
) -> CoreResult<DecodedAppStateMutation> {
    let index_mac = record
        .index
        .as_ref()
        .and_then(|index| index.blob.as_ref())
        .ok_or_else(|| CoreError::Protocol("app-state mutation is missing index MAC".to_owned()))?;
    validate_app_state_mac("app-state index mac", index_mac)?;
    let key_id = record
        .key_id
        .as_ref()
        .and_then(|key_id| key_id.id.as_ref())
        .ok_or_else(|| CoreError::Protocol("app-state mutation is missing key id".to_owned()))?;
    if key_id.is_empty() {
        return Err(CoreError::Protocol(
            "app-state mutation key id must not be empty".to_owned(),
        ));
    }
    let value_blob = record
        .value
        .as_ref()
        .and_then(|value| value.blob.as_ref())
        .ok_or_else(|| CoreError::Protocol("app-state mutation is missing value".to_owned()))?;
    if value_blob.len() <= APP_STATE_MAC_LEN {
        return Err(CoreError::Payload(
            "app-state mutation value is too short".to_owned(),
        ));
    }
    let encrypted_value = &value_blob[..value_blob.len() - APP_STATE_MAC_LEN];
    let value_mac = &value_blob[value_blob.len() - APP_STATE_MAC_LEN..];
    validate_app_state_mac("app-state value mac", value_mac)?;

    let expected_value_mac =
        wa_crypto::app_state_value_mac(crypto_operation(operation), encrypted_value, key_id, keys)
            .map_err(CoreError::Crypto)?;
    if !constant_time_eq(&expected_value_mac, value_mac) {
        return Err(CoreError::Protocol(
            "app-state value MAC verification failed".to_owned(),
        ));
    }

    let plaintext =
        wa_crypto::decrypt_app_state_value(encrypted_value, keys).map_err(CoreError::Crypto)?;
    let sync_action = SyncActionData::decode(plaintext.as_slice())?;
    let index_bytes = sync_action
        .index
        .as_ref()
        .ok_or_else(|| CoreError::Protocol("sync action is missing index".to_owned()))?;
    let expected_index_mac =
        wa_crypto::app_state_index_mac(index_bytes, keys).map_err(CoreError::Crypto)?;
    if !constant_time_eq(&expected_index_mac, index_mac) {
        return Err(CoreError::Protocol(
            "app-state index MAC verification failed".to_owned(),
        ));
    }
    let index = serde_json::from_slice(index_bytes).map_err(|err| {
        CoreError::Payload(format!("failed to decode app-state mutation index: {err}"))
    })?;

    Ok(DecodedAppStateMutation {
        operation,
        key_id: key_id.clone(),
        index_mac: index_mac.clone(),
        value_mac: Bytes::copy_from_slice(value_mac),
        encrypted_value: Bytes::copy_from_slice(encrypted_value),
        index,
        sync_action,
    })
}

#[cfg(feature = "noise")]
fn patch_key_id(patch: &SyncdPatch) -> CoreResult<&Bytes> {
    let key_id = patch
        .key_id
        .as_ref()
        .and_then(|key_id| key_id.id.as_ref())
        .ok_or_else(|| CoreError::Protocol("app-state patch is missing key id".to_owned()))?;
    if key_id.is_empty() {
        return Err(CoreError::Protocol(
            "app-state patch key id must not be empty".to_owned(),
        ));
    }
    Ok(key_id)
}

#[cfg(feature = "noise")]
fn snapshot_key_id(snapshot: &SyncdSnapshot) -> CoreResult<&Bytes> {
    let key_id = snapshot
        .key_id
        .as_ref()
        .and_then(|key_id| key_id.id.as_ref())
        .ok_or_else(|| CoreError::Protocol("app-state snapshot is missing key id".to_owned()))?;
    if key_id.is_empty() {
        return Err(CoreError::Protocol(
            "app-state snapshot key id must not be empty".to_owned(),
        ));
    }
    Ok(key_id)
}

#[cfg(feature = "noise")]
fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}

#[cfg(feature = "noise")]
fn crypto_operation(operation: AppStatePatchOperation) -> wa_crypto::AppStateMutationOperation {
    match operation {
        AppStatePatchOperation::Set => wa_crypto::AppStateMutationOperation::Set,
        AppStatePatchOperation::Remove => wa_crypto::AppStateMutationOperation::Remove,
    }
}

fn message_index_parts(key: &MessageKey) -> CoreResult<(String, String, bool)> {
    validate_message_key(key)?;
    Ok((
        key.remote_jid.clone().unwrap_or_default(),
        key.id.clone().unwrap_or_default(),
        key.from_me.unwrap_or(false),
    ))
}

fn validate_message_key(key: &MessageKey) -> CoreResult<()> {
    let remote_jid = key
        .remote_jid
        .as_deref()
        .ok_or_else(|| CoreError::Protocol("message key is missing remote JID".to_owned()))?;
    validate_jid("message key remote JID", remote_jid)?;
    if key.id.as_deref().is_none_or(|id| id.trim().is_empty()) {
        return Err(CoreError::Protocol(
            "message key is missing message id".to_owned(),
        ));
    }
    if let Some(participant) = key.participant.as_deref() {
        validate_jid("message key participant JID", participant)?;
    }
    if key.from_me.is_none() {
        return Err(CoreError::Protocol(
            "message key is missing from-me flag".to_owned(),
        ));
    }
    Ok(())
}

fn validate_jid<'a>(label: &str, jid: &'a str) -> CoreResult<&'a str> {
    jid_decode(jid).ok_or_else(|| CoreError::Protocol(format!("invalid {label}: {jid}")))?;
    Ok(jid)
}

fn validate_non_empty<'a>(label: &str, value: &'a str) -> CoreResult<&'a str> {
    if value.trim().is_empty() {
        return Err(CoreError::Protocol(format!("{label} must not be empty")));
    }
    Ok(value)
}

#[cfg(feature = "noise")]
fn required_index_value<'a>(
    mutation: &'a DecodedAppStateMutation,
    position: usize,
    label: &str,
) -> CoreResult<&'a str> {
    let value = mutation.index.get(position).ok_or_else(|| {
        CoreError::Protocol(format!(
            "sync action index is missing {label} at position {position}"
        ))
    })?;
    validate_non_empty(label, value)
}

#[cfg(feature = "noise")]
fn required_index_jid(
    mutation: &DecodedAppStateMutation,
    position: usize,
    label: &str,
) -> CoreResult<String> {
    let jid = required_index_value(mutation, position, label)?;
    validate_jid(label, jid)?;
    Ok(jid.to_owned())
}

#[cfg(feature = "noise")]
fn first_non_empty<const N: usize>(values: [Option<&str>; N]) -> Option<&str> {
    values
        .into_iter()
        .flatten()
        .find(|value| !value.trim().is_empty())
}

#[cfg(feature = "noise")]
fn contact_phone_number(
    index_jid: &str,
    action_pn_jid: Option<&str>,
) -> CoreResult<Option<String>> {
    let decoded = jid_decode(index_jid)
        .ok_or_else(|| CoreError::Protocol(format!("invalid contact chat JID: {index_jid}")))?;
    if matches!(decoded.server, JidServer::SWhatsAppNet | JidServer::CUs) {
        return Ok(Some(index_jid.to_owned()));
    }
    action_pn_jid
        .filter(|jid| !jid.trim().is_empty())
        .map(|jid| validate_jid("contact phone JID", jid).map(str::to_owned))
        .transpose()
}

#[cfg(feature = "noise")]
fn encode_app_state_patch_state_bytes(state: &AppStatePatchState) -> CoreResult<Vec<u8>> {
    let entry_count = u32::try_from(state.index_value_macs.len()).map_err(|_| {
        CoreError::Payload("app-state store has too many index/value MAC entries".to_owned())
    })?;
    let mut output = Vec::with_capacity(
        APP_STATE_STORE_MAGIC.len()
            + 1
            + 8
            + 4
            + state.hash.len()
            + 4
            + state.index_value_macs.len() * (4 + APP_STATE_MAC_LEN + 4 + APP_STATE_MAC_LEN),
    );
    output.extend_from_slice(APP_STATE_STORE_MAGIC);
    output.push(APP_STATE_STORE_FORMAT_VERSION);
    output.extend_from_slice(&state.version.to_be_bytes());
    write_len_prefixed(&mut output, &state.hash)?;
    output.extend_from_slice(&entry_count.to_be_bytes());
    for (index_key, value_mac) in &state.index_value_macs {
        let index_mac = BASE64.decode(index_key).map_err(|err| {
            CoreError::Payload(format!("failed to decode app-state index MAC key: {err}"))
        })?;
        validate_app_state_mac("app-state index mac", &index_mac)?;
        validate_app_state_mac("app-state value mac", value_mac)?;
        write_len_prefixed(&mut output, &index_mac)?;
        write_len_prefixed(&mut output, value_mac)?;
    }
    Ok(output)
}

#[cfg(feature = "noise")]
fn decode_app_state_patch_state_bytes(bytes: &[u8]) -> CoreResult<AppStatePatchState> {
    let mut offset = 0usize;
    let magic = read_exact(
        bytes,
        &mut offset,
        APP_STATE_STORE_MAGIC.len(),
        "app-state store magic",
    )?;
    if magic != APP_STATE_STORE_MAGIC {
        return Err(CoreError::Payload(
            "app-state store state has invalid magic".to_owned(),
        ));
    }
    let format_version = read_u8(bytes, &mut offset, "app-state store format version")?;
    if format_version != APP_STATE_STORE_FORMAT_VERSION {
        return Err(CoreError::Payload(format!(
            "unsupported app-state store format version: {format_version}"
        )));
    }
    let version = read_u64(bytes, &mut offset, "app-state store version")?;
    let hash = Bytes::copy_from_slice(read_len_prefixed(
        bytes,
        &mut offset,
        "app-state store hash",
    )?);
    let entry_count = read_u32(bytes, &mut offset, "app-state store entry count")?;
    let mut entries =
        Vec::with_capacity(usize::try_from(entry_count).map_err(|_| {
            CoreError::Payload("app-state store entry count exceeds usize".to_owned())
        })?);
    for _ in 0..entry_count {
        let index_mac = Bytes::copy_from_slice(read_len_prefixed(
            bytes,
            &mut offset,
            "app-state store index MAC",
        )?);
        let value_mac = Bytes::copy_from_slice(read_len_prefixed(
            bytes,
            &mut offset,
            "app-state store value MAC",
        )?);
        entries.push((index_mac, value_mac));
    }
    if offset != bytes.len() {
        return Err(CoreError::Payload(
            "app-state store state has trailing bytes".to_owned(),
        ));
    }
    AppStatePatchState::from_index_value_macs(version, hash, entries)
}

#[cfg(feature = "noise")]
fn encode_app_state_blocked_collection_bytes(
    blocked: &AppStateBlockedCollection,
) -> CoreResult<Vec<u8>> {
    if blocked.key_id.is_empty() {
        return Err(CoreError::Protocol(
            "app-state blocked collection key id must not be empty".to_owned(),
        ));
    }
    let mut output =
        Vec::with_capacity(APP_STATE_BLOCKED_STORE_MAGIC.len() + 1 + 8 + 4 + blocked.key_id.len());
    output.extend_from_slice(APP_STATE_BLOCKED_STORE_MAGIC);
    output.push(APP_STATE_BLOCKED_STORE_FORMAT_VERSION);
    output.extend_from_slice(&blocked.previous_version.to_be_bytes());
    write_len_prefixed(&mut output, &blocked.key_id)?;
    Ok(output)
}

#[cfg(feature = "noise")]
fn decode_app_state_blocked_collection_bytes(
    collection: AppStateCollection,
    bytes: &[u8],
) -> CoreResult<AppStateBlockedCollection> {
    let mut offset = 0usize;
    let magic = read_exact(
        bytes,
        &mut offset,
        APP_STATE_BLOCKED_STORE_MAGIC.len(),
        "app-state blocked store magic",
    )?;
    if magic != APP_STATE_BLOCKED_STORE_MAGIC {
        return Err(CoreError::Payload(
            "app-state blocked store state has invalid magic".to_owned(),
        ));
    }
    let format_version = read_u8(bytes, &mut offset, "app-state blocked store format version")?;
    if format_version != APP_STATE_BLOCKED_STORE_FORMAT_VERSION {
        return Err(CoreError::Payload(format!(
            "unsupported app-state blocked store format version: {format_version}"
        )));
    }
    let previous_version = read_u64(bytes, &mut offset, "app-state blocked previous version")?;
    let key_id = Bytes::copy_from_slice(read_len_prefixed(
        bytes,
        &mut offset,
        "app-state blocked key id",
    )?);
    if key_id.is_empty() {
        return Err(CoreError::Protocol(
            "app-state blocked key id must not be empty".to_owned(),
        ));
    }
    if offset != bytes.len() {
        return Err(CoreError::Payload(
            "app-state blocked store state has trailing bytes".to_owned(),
        ));
    }
    Ok(AppStateBlockedCollection {
        collection,
        key_id,
        previous_version,
    })
}

#[cfg(feature = "noise")]
fn write_len_prefixed(output: &mut Vec<u8>, bytes: &[u8]) -> CoreResult<()> {
    let len = u32::try_from(bytes.len())
        .map_err(|_| CoreError::Payload("app-state store field exceeds u32 length".to_owned()))?;
    output.extend_from_slice(&len.to_be_bytes());
    output.extend_from_slice(bytes);
    Ok(())
}

#[cfg(feature = "noise")]
fn read_len_prefixed<'a>(bytes: &'a [u8], offset: &mut usize, label: &str) -> CoreResult<&'a [u8]> {
    let len = usize::try_from(read_u32(bytes, offset, label)?)
        .map_err(|_| CoreError::Payload(format!("{label} length exceeds usize")))?;
    read_exact(bytes, offset, len, label)
}

#[cfg(feature = "noise")]
fn read_u8(bytes: &[u8], offset: &mut usize, label: &str) -> CoreResult<u8> {
    Ok(read_exact(bytes, offset, 1, label)?[0])
}

#[cfg(feature = "noise")]
fn read_u32(bytes: &[u8], offset: &mut usize, label: &str) -> CoreResult<u32> {
    let value = read_exact(bytes, offset, 4, label)?;
    Ok(u32::from_be_bytes(
        value.try_into().expect("u32 slice length"),
    ))
}

#[cfg(feature = "noise")]
fn read_u64(bytes: &[u8], offset: &mut usize, label: &str) -> CoreResult<u64> {
    let value = read_exact(bytes, offset, 8, label)?;
    Ok(u64::from_be_bytes(
        value.try_into().expect("u64 slice length"),
    ))
}

#[cfg(feature = "noise")]
fn read_exact<'a>(
    bytes: &'a [u8],
    offset: &mut usize,
    len: usize,
    label: &str,
) -> CoreResult<&'a [u8]> {
    let end = offset
        .checked_add(len)
        .ok_or_else(|| CoreError::Payload(format!("{label} length overflow")))?;
    if end > bytes.len() {
        return Err(CoreError::Payload(format!(
            "{label} exceeds app-state store state length"
        )));
    }
    let value = &bytes[*offset..end];
    *offset = end;
    Ok(value)
}

fn optional_non_empty(label: &str, value: Option<&str>) -> CoreResult<Option<String>> {
    value
        .map(|value| validate_non_empty(label, value).map(str::to_owned))
        .transpose()
}

fn optional_jid(label: &str, jid: Option<&str>) -> CoreResult<Option<String>> {
    jid.map(|jid| validate_jid(label, jid).map(str::to_owned))
        .transpose()
}

fn u64_to_i64(value: u64) -> CoreResult<i64> {
    i64::try_from(value)
        .map_err(|_| CoreError::Payload(format!("timestamp exceeds i64 range: {value}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "noise")]
    use async_trait::async_trait;
    #[cfg(feature = "noise")]
    use std::collections::BTreeMap;
    #[cfg(feature = "noise")]
    use std::sync::atomic::{AtomicU64, Ordering};
    #[cfg(feature = "noise")]
    use std::sync::{Arc, Mutex};
    use wa_binary::BinaryNodeContent;

    #[test]
    fn builds_dirty_bit_and_app_state_queries() {
        let clean = build_clean_dirty_bits_node(DirtyBitType::Groups, Some(42), "q-1").unwrap();
        assert_eq!(clean.attrs["xmlns"], "urn:xmpp:whatsapp:dirty");
        assert_eq!(clean.attrs["type"], "set");
        let clean_child = child(&clean, "clean");
        assert_eq!(clean_child.attrs["type"], "groups");
        assert_eq!(clean_child.attrs["timestamp"], "42");

        let sync = build_app_state_sync_query(
            [
                AppStateCollectionRequest::new(AppStateCollection::RegularHigh, 0),
                AppStateCollectionRequest::new(AppStateCollection::RegularLow, 7)
                    .with_return_snapshot(false),
            ],
            "q-2",
        )
        .unwrap();
        assert_eq!(sync.attrs["xmlns"], "w:sync:app:state");
        let collections = children(child(&sync, "sync"), "collection");
        assert_eq!(collections[0].attrs["name"], "regular_high");
        assert_eq!(collections[0].attrs["version"], "0");
        assert_eq!(collections[0].attrs["return_snapshot"], "true");
        assert_eq!(collections[1].attrs["name"], "regular_low");
        assert_eq!(collections[1].attrs["version"], "7");
        assert_eq!(collections[1].attrs["return_snapshot"], "false");

        let patch = build_app_state_patch_query(
            AppStateCollection::RegularHigh,
            8,
            Bytes::from_static(b"patch"),
            "q-3",
        )
        .unwrap();
        let collection = child(child(&patch, "sync"), "collection");
        assert_eq!(collection.attrs["name"], "regular_high");
        assert_eq!(collection.attrs["version"], "8");
        assert_eq!(collection.attrs["return_snapshot"], "false");
        assert_eq!(
            child(collection, "patch").content.as_ref().unwrap(),
            &BinaryNodeContent::Bytes(Bytes::from_static(b"patch"))
        );

        assert!(build_app_state_sync_query([], "q").is_err());
        assert!(
            build_app_state_patch_query(AppStateCollection::Regular, 0, Bytes::new(), "q").is_err()
        );
    }

    #[test]
    fn parses_dirty_notification_nodes() {
        let wrapped = BinaryNode::new("ib").with_content(vec![
            BinaryNode::new("dirty")
                .with_attr("type", "communities")
                .with_attr("timestamp", "123"),
        ]);
        assert_eq!(
            parse_dirty_notification_node(&wrapped).unwrap(),
            Some(DirtyNotification {
                dirty_type: "communities".to_owned(),
                timestamp: Some(123),
            })
        );

        let direct = BinaryNode::new("dirty")
            .with_attr("type", "groups")
            .with_attr("t", "456");
        assert_eq!(
            parse_dirty_notification_node(&direct).unwrap(),
            Some(DirtyNotification {
                dirty_type: "groups".to_owned(),
                timestamp: Some(456),
            })
        );

        assert_eq!(
            parse_dirty_notification_node(&BinaryNode::new("message")).unwrap(),
            None
        );
        assert!(
            parse_dirty_notification_node(
                &BinaryNode::new("ib").with_content(vec![BinaryNode::new("dirty")])
            )
            .is_err()
        );
    }

    #[test]
    fn parses_app_state_sync_response_collections() {
        let patch = SyncdPatch {
            version: None,
            mutations: Vec::new(),
            external_mutations: None,
            snapshot_mac: None,
            patch_mac: None,
            key_id: None,
            exit_code: None,
            device_index: None,
            client_debug_data: None,
        };
        let snapshot_ref = ExternalBlobReference {
            media_key: Some(Bytes::from_static(b"media-key")),
            direct_path: Some("/snapshot".to_owned()),
            handle: Some("handle-1".to_owned()),
            file_size_bytes: Some(42),
            file_sha256: None,
            file_enc_sha256: None,
        };
        let result = BinaryNode::new("iq")
            .with_attr("type", "result")
            .with_content(vec![BinaryNode::new("sync").with_content(vec![
                BinaryNode::new("collection")
                    .with_attr("name", "regular_low")
                    .with_attr("version", "4")
                    .with_attr("has_more_patches", "true")
                    .with_content(vec![
                        BinaryNode::new("snapshot")
                            .with_content(Bytes::from(snapshot_ref.encode_to_vec())),
                        BinaryNode::new("patches").with_content(vec![
                            BinaryNode::new("patch")
                                .with_content(Bytes::from(patch.encode_to_vec())),
                        ]),
                    ]),
            ])]);

        let parsed = parse_app_state_sync_response(&result).unwrap().unwrap();
        let collection = parsed.collection(AppStateCollection::RegularLow).unwrap();
        assert_eq!(collection.version, Some(4));
        assert!(collection.has_more_patches);
        assert_eq!(
            collection.snapshot.as_ref().unwrap().direct_path.as_deref(),
            Some("/snapshot")
        );
        assert_eq!(collection.patches.len(), 1);
        assert_eq!(
            collection.patches[0].version.as_ref().unwrap().version,
            Some(5)
        );
        assert!(
            parse_app_state_sync_response(&BinaryNode::new("iq"))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn parses_app_state_query_results() {
        let result = BinaryNode::new("iq").with_attr("type", "result");
        assert!(parse_app_state_query_result(&result, AppStateQueryKind::Sync).is_ok());
        assert!(parse_app_state_query_result(&result, AppStateQueryKind::PatchUpload).is_ok());

        let attr_error = BinaryNode::new("iq")
            .with_attr("type", "error")
            .with_attr("code", "409")
            .with_attr("text", "collection conflict");
        assert!(matches!(
            parse_app_state_query_result(&attr_error, AppStateQueryKind::Sync),
            Err(CoreError::Protocol(message))
                if message == "app-state sync query failed: app-state query failed (409): collection conflict"
        ));

        let child_error = BinaryNode::new("iq")
            .with_attr("type", "result")
            .with_content(vec![
                BinaryNode::new("error")
                    .with_attr("code", "500")
                    .with_attr("text", "patch rejected"),
            ]);
        assert!(matches!(
            parse_app_state_query_result(&child_error, AppStateQueryKind::PatchUpload),
            Err(CoreError::Protocol(message))
                if message == "app-state patch upload failed: app-state query failed (500): patch rejected"
        ));

        let invalid = BinaryNode::new("message").with_attr("type", "result");
        assert!(matches!(
            parse_app_state_query_result(&invalid, AppStateQueryKind::Sync),
            Err(CoreError::Protocol(message))
                if message == "app-state sync query response must be iq, got message"
        ));
    }

    #[test]
    fn rejects_malformed_app_state_sync_response() {
        let unknown_collection = BinaryNode::new("iq")
            .with_attr("type", "result")
            .with_content(vec![BinaryNode::new("sync").with_content(vec![
                BinaryNode::new("collection").with_attr("name", "unknown"),
            ])]);
        assert!(parse_app_state_sync_response(&unknown_collection).is_err());

        let patch_without_collection_version = SyncdPatch {
            version: None,
            mutations: Vec::new(),
            external_mutations: None,
            snapshot_mac: None,
            patch_mac: None,
            key_id: None,
            exit_code: None,
            device_index: None,
            client_debug_data: None,
        };
        let missing_version = BinaryNode::new("iq")
            .with_attr("type", "result")
            .with_content(vec![BinaryNode::new("sync").with_content(vec![
                    BinaryNode::new("collection")
                        .with_attr("name", "regular_low")
                        .with_content(vec![BinaryNode::new("patch").with_content(Bytes::from(
                            patch_without_collection_version.encode_to_vec(),
                        ))]),
                ])]);
        assert!(parse_app_state_sync_response(&missing_version).is_err());

        let text_patch = BinaryNode::new("iq")
            .with_attr("type", "result")
            .with_content(vec![BinaryNode::new("sync").with_content(vec![
                BinaryNode::new("collection")
                    .with_attr("name", "regular_low")
                    .with_attr("version", "1")
                    .with_content(vec![BinaryNode::new("patch").with_content("not-bytes")]),
            ])]);
        assert!(parse_app_state_sync_response(&text_patch).is_err());
    }

    #[test]
    fn builds_basic_chat_mutation_patches() {
        let mute = build_mute_chat_patch("123@s.whatsapp.net", Some(1_700_000_000), 10).unwrap();
        assert_eq!(mute.collection, AppStateCollection::RegularHigh);
        assert_eq!(mute.api_version, 2);
        assert_eq!(mute.index, vec!["mute", "123@s.whatsapp.net"]);
        let mute_action = mute.value.mute_action.unwrap();
        assert_eq!(mute_action.muted, Some(true));
        assert_eq!(mute_action.mute_end_timestamp, Some(1_700_000_000));
        assert_eq!(mute.value.timestamp, Some(10));

        let archive = build_archive_chat_patch("123@s.whatsapp.net", true, None, 11).unwrap();
        assert_eq!(archive.collection, AppStateCollection::RegularLow);
        assert_eq!(archive.api_version, 3);
        assert_eq!(archive.index, vec!["archive", "123@s.whatsapp.net"]);
        assert_eq!(
            archive.value.archive_chat_action.unwrap().archived,
            Some(true)
        );

        let mark = build_mark_chat_read_patch("123@s.whatsapp.net", false, None, 12).unwrap();
        assert_eq!(mark.api_version, 3);
        assert_eq!(mark.index, vec!["markChatAsRead", "123@s.whatsapp.net"]);
        assert_eq!(
            mark.value.mark_chat_as_read_action.unwrap().read,
            Some(false)
        );

        let pin = build_pin_chat_patch("123@s.whatsapp.net", true, 13).unwrap();
        assert_eq!(pin.api_version, 5);
        assert_eq!(pin.index, vec!["pin_v1", "123@s.whatsapp.net"]);
        assert_eq!(pin.value.pin_action.unwrap().pinned, Some(true));

        let push_name = build_push_name_patch("Agent", 14).unwrap();
        assert_eq!(push_name.collection, AppStateCollection::CriticalBlock);
        assert_eq!(push_name.api_version, 1);
        assert_eq!(push_name.index, vec!["setting_pushName"]);
        assert_eq!(
            push_name.value.push_name_setting.unwrap().name.as_deref(),
            Some("Agent")
        );
    }

    #[test]
    fn builds_contact_quick_reply_and_label_mutation_patches() {
        let contact = ContactSyncAction::new()
            .with_full_name("Agent Smith")
            .with_first_name("Agent")
            .with_pn_jid("123@s.whatsapp.net")
            .with_save_on_primary_addressbook(true);
        let contact_patch = build_contact_patch("123@s.whatsapp.net", Some(contact), 17).unwrap();
        assert_eq!(
            contact_patch.collection,
            AppStateCollection::CriticalUnblockLow
        );
        assert_eq!(contact_patch.operation, AppStatePatchOperation::Set);
        assert_eq!(contact_patch.api_version, 2);
        assert_eq!(contact_patch.index, vec!["contact", "123@s.whatsapp.net"]);
        let contact_action = contact_patch.value.contact_action.unwrap();
        assert_eq!(contact_action.full_name.as_deref(), Some("Agent Smith"));
        assert_eq!(contact_action.first_name.as_deref(), Some("Agent"));
        assert_eq!(contact_action.pn_jid.as_deref(), Some("123@s.whatsapp.net"));
        assert_eq!(contact_action.save_on_primary_addressbook, Some(true));

        let remove_contact = build_contact_patch("123@s.whatsapp.net", None, 18).unwrap();
        assert_eq!(remove_contact.operation, AppStatePatchOperation::Remove);
        assert_eq!(
            remove_contact.value.contact_action,
            Some(Default::default())
        );

        let quick_reply = QuickReplyMutation::new("1700000000", "/hi", "hello")
            .with_keyword("hello")
            .with_count(3);
        let quick_patch = build_quick_reply_patch(quick_reply, 19).unwrap();
        assert_eq!(quick_patch.collection, AppStateCollection::Regular);
        assert_eq!(quick_patch.api_version, 2);
        assert_eq!(quick_patch.index, vec!["quick_reply", "1700000000"]);
        let quick_action = quick_patch.value.quick_reply_action.unwrap();
        assert_eq!(quick_action.shortcut.as_deref(), Some("/hi"));
        assert_eq!(quick_action.message.as_deref(), Some("hello"));
        assert_eq!(quick_action.keywords, vec!["hello"]);
        assert_eq!(quick_action.count, Some(3));
        assert_eq!(quick_action.deleted, Some(false));

        let label = LabelEditMutation::new("7", "Important")
            .with_color(4)
            .with_list_type(LabelListType::Custom);
        let label_patch = build_label_edit_patch(label, 20).unwrap();
        assert_eq!(label_patch.collection, AppStateCollection::Regular);
        assert_eq!(label_patch.api_version, 3);
        assert_eq!(label_patch.index, vec!["label_edit", "7"]);
        let label_action = label_patch.value.label_edit_action.unwrap();
        assert_eq!(label_action.name.as_deref(), Some("Important"));
        assert_eq!(label_action.color, Some(4));
        assert_eq!(label_action.r#type, Some(LabelListType::Custom as i32));

        let chat_label =
            build_chat_label_association_patch("123@s.whatsapp.net", "7", true, 21).unwrap();
        assert_eq!(
            chat_label.index,
            vec!["label_jid", "7", "123@s.whatsapp.net"]
        );
        assert_eq!(
            chat_label.value.label_association_action.unwrap().labeled,
            Some(true)
        );

        let message_label =
            build_message_label_association_patch("123@s.whatsapp.net", "7", "msg-1", false, 22)
                .unwrap();
        assert_eq!(
            message_label.index,
            vec![
                "label_message",
                "7",
                "123@s.whatsapp.net",
                "msg-1",
                "0",
                "0"
            ]
        );
        assert_eq!(
            message_label
                .value
                .label_association_action
                .unwrap()
                .labeled,
            Some(false)
        );
    }

    #[test]
    fn builds_message_range_and_message_chat_mutations() {
        let key = MessageKey {
            remote_jid: Some("123@s.whatsapp.net".to_owned()),
            from_me: Some(false),
            id: Some("msg-1".to_owned()),
            participant: Some("456@s.whatsapp.net".to_owned()),
        };
        let range = ChatMutationMessageRange::new()
            .with_last_message_timestamp(99)
            .with_message(ChatMutationMessageRef::new(key.clone()).with_timestamp(100));

        let delete =
            build_delete_chat_patch("123@s.whatsapp.net", Some(range.clone()), 15).unwrap();
        assert_eq!(delete.api_version, 6);
        assert_eq!(delete.index, vec!["deleteChat", "123@s.whatsapp.net", "1"]);
        let delete_range = delete
            .value
            .delete_chat_action
            .unwrap()
            .message_range
            .unwrap();
        assert_eq!(delete_range.last_message_timestamp, Some(99));
        assert_eq!(delete_range.messages[0].timestamp, Some(100));
        assert_eq!(delete_range.messages[0].key.as_ref(), Some(&key));

        let star = build_star_message_patch(key, true, 16).unwrap();
        assert_eq!(star.api_version, 2);
        assert_eq!(
            star.index,
            vec!["star", "123@s.whatsapp.net", "msg-1", "0", "0"]
        );
        assert_eq!(star.value.star_action.unwrap().starred, Some(true));
    }

    #[cfg(feature = "noise")]
    #[test]
    fn maps_decoded_app_state_mutations_to_store_event_batch() {
        let contact = ContactSyncAction::new()
            .with_full_name("Agent Smith")
            .with_lid_jid("abc@lid")
            .with_pn_jid("123@s.whatsapp.net");
        let contact_patch = build_contact_patch("123@s.whatsapp.net", Some(contact), 17).unwrap();
        let remove_contact = build_contact_patch("123@s.whatsapp.net", None, 18).unwrap();
        let quick_reply =
            build_quick_reply_patch(QuickReplyMutation::new("qr-1", "/hi", "hello"), 19).unwrap();
        let label = build_label_edit_patch(LabelEditMutation::new("7", "Important"), 20).unwrap();
        let chat_label =
            build_chat_label_association_patch("123@s.whatsapp.net", "7", true, 21).unwrap();
        let message_label =
            build_message_label_association_patch("123@s.whatsapp.net", "7", "msg-1", false, 22)
                .unwrap();
        let star = build_star_message_patch(
            MessageKey {
                remote_jid: Some("123@s.whatsapp.net".to_owned()),
                from_me: Some(false),
                id: Some("msg-1".to_owned()),
                participant: None,
            },
            true,
            23,
        )
        .unwrap();
        let delete = build_delete_chat_patch("123@s.whatsapp.net", None, 24).unwrap();

        let mutations = vec![
            decoded_mutation_from_patch(contact_patch),
            decoded_mutation_from_patch(remove_contact),
            decoded_mutation_from_patch(quick_reply),
            decoded_mutation_from_patch(label),
            decoded_mutation_from_patch(chat_label),
            decoded_mutation_from_patch(message_label),
            decoded_mutation_from_patch(star),
            decoded_mutation_from_patch(delete.clone()),
        ];
        let batch = event_batch_from_decoded_app_state_mutations(&mutations, false).unwrap();

        assert_eq!(batch.contacts_upsert.len(), 1);
        assert_eq!(
            batch.contacts_upsert[0].fields.get("name").unwrap(),
            "Agent Smith"
        );
        assert_eq!(
            batch.contacts_upsert[0].fields.get("lid").unwrap(),
            "abc@lid"
        );
        assert_eq!(
            batch.contacts_upsert[0].fields.get("phone_number").unwrap(),
            "123@s.whatsapp.net"
        );
        assert_eq!(batch.contacts_delete, vec!["123@s.whatsapp.net"]);
        assert_eq!(batch.quick_replies_update.len(), 1);
        assert_eq!(batch.quick_replies_update[0].id, "qr-1");
        assert_eq!(
            batch.quick_replies_update[0]
                .fields
                .get("shortcut")
                .unwrap(),
            "/hi"
        );
        assert_eq!(batch.labels_edit.len(), 1);
        assert_eq!(batch.labels_edit[0].id, "7");
        assert_eq!(
            batch.labels_edit[0].fields.get("name").unwrap(),
            "Important"
        );
        assert_eq!(batch.labels_association.len(), 2);
        assert!(batch.labels_association[0].labeled);
        assert!(!batch.labels_association[1].labeled);
        assert_eq!(batch.messages_update.len(), 1);
        assert_eq!(
            batch.messages_update[0].fields.get("starred").unwrap(),
            "true"
        );
        assert_eq!(batch.chats_delete, vec!["123@s.whatsapp.net"]);

        let initial_delete = decoded_mutation_from_patch(delete);
        let batch = event_batch_from_decoded_app_state_mutations([&initial_delete], true).unwrap();
        assert!(batch.chats_delete.is_empty());
    }

    #[cfg(feature = "noise")]
    #[tokio::test]
    async fn applies_decoded_app_state_patch_to_native_store() {
        let store = temp_store().await;
        let previous = load_app_state_patch_state(&store, AppStateCollection::Regular)
            .await
            .unwrap();
        assert_eq!(previous.version(), 0);

        let key_id = [4u8; 32];
        let key_data = [8u8; 32];
        let patch =
            build_quick_reply_patch(QuickReplyMutation::new("qr-1", "/hi", "hello"), 19).unwrap();
        let mutation =
            encrypt_chat_mutation_patch_with_iv(&patch, &key_id, &key_data, &[3u8; 16]).unwrap();
        let bundle = build_app_state_patch_bundle(
            AppStateCollection::Regular,
            &previous,
            &key_id,
            &key_data,
            [mutation],
        )
        .unwrap();
        let decoded = decode_app_state_patch(
            AppStateCollection::Regular,
            &previous,
            &bundle.patch,
            &key_data,
        )
        .unwrap();

        let batch = apply_decoded_app_state_patch_to_store(&store, &decoded, false)
            .await
            .unwrap();
        assert_eq!(batch.quick_replies_update.len(), 1);
        assert_eq!(batch.quick_replies_update[0].id, "qr-1");

        let reloaded = load_app_state_patch_state(&store, AppStateCollection::Regular)
            .await
            .unwrap();
        assert_eq!(reloaded.version(), bundle.next_state.version());
        assert_eq!(reloaded.hash(), bundle.next_state.hash());
        assert_eq!(
            reloaded.index_value_mac_count(),
            bundle.next_state.index_value_mac_count()
        );

        store
            .set(
                KeyNamespace::AppStateSyncVersion,
                AppStateCollection::Regular.name(),
                b"corrupt",
            )
            .await
            .unwrap();
        assert!(
            load_app_state_patch_state(&store, AppStateCollection::Regular)
                .await
                .is_err()
        );
    }

    #[cfg(feature = "noise")]
    #[tokio::test]
    async fn applies_inline_app_state_sync_response_to_native_store() {
        let store = temp_store().await;
        let previous = load_app_state_patch_state(&store, AppStateCollection::Regular)
            .await
            .unwrap();
        let key_id = [4u8; 32];
        let key_data = [8u8; 32];

        let quick_patch =
            build_quick_reply_patch(QuickReplyMutation::new("qr-1", "/hi", "hello"), 19).unwrap();
        let quick_mutation =
            encrypt_chat_mutation_patch_with_iv(&quick_patch, &key_id, &key_data, &[3u8; 16])
                .unwrap();
        let quick_bundle = build_app_state_patch_bundle(
            AppStateCollection::Regular,
            &previous,
            &key_id,
            &key_data,
            [quick_mutation],
        )
        .unwrap();

        let label_patch =
            build_label_edit_patch(LabelEditMutation::new("7", "Important"), 20).unwrap();
        let label_mutation =
            encrypt_chat_mutation_patch_with_iv(&label_patch, &key_id, &key_data, &[4u8; 16])
                .unwrap();
        let label_bundle = build_app_state_patch_bundle(
            AppStateCollection::Regular,
            &quick_bundle.next_state,
            &key_id,
            &key_data,
            [label_mutation],
        )
        .unwrap();
        let snapshot_ref = ExternalBlobReference {
            media_key: Some(Bytes::from(vec![9u8; 32])),
            direct_path: Some("/app-state/snapshot".to_owned()),
            handle: None,
            file_size_bytes: Some(123),
            file_sha256: Some(Bytes::from(vec![10u8; 32])),
            file_enc_sha256: Some(Bytes::from(vec![11u8; 32])),
        };

        let response = AppStateSyncResponse {
            collections: vec![AppStateSyncCollection {
                collection: AppStateCollection::Regular,
                version: Some(label_bundle.next_state.version()),
                has_more_patches: true,
                snapshot: Some(snapshot_ref.clone()),
                patches: vec![quick_bundle.patch.clone(), label_bundle.patch.clone()],
            }],
        };

        let outcome = apply_app_state_sync_response_to_store(&store, &response, &key_data, false)
            .await
            .unwrap();
        assert_eq!(outcome.batches.len(), 2);
        assert_eq!(outcome.batches[0].quick_replies_update[0].id, "qr-1");
        assert_eq!(outcome.batches[1].labels_edit[0].id, "7");
        assert_eq!(outcome.pending_snapshots.len(), 1);
        assert_eq!(
            outcome.pending_snapshots[0].collection,
            AppStateCollection::Regular
        );
        assert_eq!(outcome.pending_snapshots[0].reference, snapshot_ref);
        assert_eq!(outcome.collections.len(), 1);
        assert_eq!(
            outcome.collections[0],
            AppStateCollectionSyncOutcome {
                collection: AppStateCollection::Regular,
                response_version: Some(label_bundle.next_state.version()),
                final_version: label_bundle.next_state.version(),
                applied_patches: 2,
                emitted_batches: 2,
                has_more_patches: true,
                snapshot_pending: true,
            }
        );

        let stored = load_app_state_patch_state(&store, AppStateCollection::Regular)
            .await
            .unwrap();
        assert_eq!(stored.version(), label_bundle.next_state.version());
        assert_eq!(stored.hash(), label_bundle.next_state.hash());
        assert_eq!(
            stored.index_value_mac_count(),
            label_bundle.next_state.index_value_mac_count()
        );
    }

    #[cfg(feature = "noise")]
    #[tokio::test]
    async fn app_state_sync_response_with_store_keys_blocks_missing_key_then_applies() {
        let store = temp_store().await;
        let previous = load_app_state_patch_state(&store, AppStateCollection::Regular)
            .await
            .unwrap();
        let key_id = [4u8; 32];
        let key_data = [8u8; 32];
        let patch =
            build_quick_reply_patch(QuickReplyMutation::new("qr-1", "/hi", "hello"), 19).unwrap();
        let mutation =
            encrypt_chat_mutation_patch_with_iv(&patch, &key_id, &key_data, &[3u8; 16]).unwrap();
        let bundle = build_app_state_patch_bundle(
            AppStateCollection::Regular,
            &previous,
            &key_id,
            &key_data,
            [mutation],
        )
        .unwrap();
        let response = AppStateSyncResponse {
            collections: vec![AppStateSyncCollection {
                collection: AppStateCollection::Regular,
                version: Some(bundle.next_state.version()),
                has_more_patches: true,
                snapshot: None,
                patches: vec![bundle.patch.clone()],
            }],
        };

        let blocked = apply_app_state_sync_response_with_store_keys(&store, &response, false)
            .await
            .unwrap();
        assert!(blocked.batches.is_empty());
        assert!(blocked.pending_snapshots.is_empty());
        assert_eq!(
            blocked.blocked,
            vec![AppStateBlockedCollection {
                collection: AppStateCollection::Regular,
                key_id: Bytes::copy_from_slice(&key_id),
                previous_version: 0,
            }]
        );
        assert_eq!(blocked.collections[0].final_version, 0);
        assert_eq!(blocked.collections[0].applied_patches, 0);
        assert_eq!(
            load_app_state_patch_state(&store, AppStateCollection::Regular)
                .await
                .unwrap()
                .version(),
            0
        );
        assert_eq!(
            load_app_state_blocked_collection(&store, AppStateCollection::Regular)
                .await
                .unwrap(),
            Some(blocked.blocked[0].clone())
        );

        save_app_state_sync_key_data(&store, &key_id, &key_data)
            .await
            .unwrap();
        assert_eq!(
            load_app_state_sync_key_data(&store, &key_id)
                .await
                .unwrap()
                .unwrap(),
            Bytes::copy_from_slice(&key_data)
        );

        let applied = apply_app_state_sync_response_with_store_keys(&store, &response, false)
            .await
            .unwrap();
        assert!(applied.blocked.is_empty());
        assert_eq!(applied.batches.len(), 1);
        assert_eq!(applied.batches[0].quick_replies_update[0].id, "qr-1");
        assert_eq!(applied.collections[0].applied_patches, 1);
        assert_eq!(
            load_app_state_patch_state(&store, AppStateCollection::Regular)
                .await
                .unwrap()
                .version(),
            bundle.next_state.version()
        );
        assert!(
            load_app_state_blocked_collection(&store, AppStateCollection::Regular)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn encodes_sync_action_data_from_chat_mutation_patch() {
        let patch = build_pin_chat_patch("123@s.whatsapp.net", true, 13).unwrap();
        let data = build_sync_action_data(&patch).unwrap();
        assert_eq!(data.version, Some(5));
        assert_eq!(data.padding, Some(Bytes::new()));
        assert_eq!(
            data.index.as_ref().unwrap(),
            &Bytes::from_static(br#"["pin_v1","123@s.whatsapp.net"]"#)
        );
        assert_eq!(
            data.value
                .as_ref()
                .unwrap()
                .pin_action
                .as_ref()
                .unwrap()
                .pinned,
            Some(true)
        );

        let encoded = encode_sync_action_data(&patch).unwrap();
        let decoded = SyncActionData::decode(encoded.as_ref()).unwrap();
        assert_eq!(decoded.version, Some(5));
        assert_eq!(decoded.index, data.index);
        assert_eq!(
            decoded.value.unwrap().pin_action.unwrap().pinned,
            Some(true)
        );

        let mut invalid = patch;
        invalid.api_version = 0;
        assert!(build_sync_action_data(&invalid).is_err());
    }

    #[cfg(feature = "noise")]
    #[test]
    fn encrypts_chat_mutation_patch_into_syncd_mutation_record() {
        let patch = build_pin_chat_patch("123@s.whatsapp.net", true, 13).unwrap();
        let key_id = [4u8; 32];
        let key_data = [8u8; 32];
        let iv = [3u8; 16];
        let encrypted =
            encrypt_chat_mutation_patch_with_iv(&patch, &key_id, &key_data, &iv).unwrap();

        assert_eq!(
            encrypted.mutation.operation,
            Some(AppStatePatchOperation::Set.proto_value())
        );
        assert_eq!(encrypted.index_mac.len(), 32);
        assert_eq!(encrypted.value_mac.len(), 32);
        assert_eq!(&encrypted.encrypted_value[..16], &iv);

        let record = encrypted.mutation.record.unwrap();
        assert_eq!(
            record.index.unwrap().blob.as_ref(),
            Some(&encrypted.index_mac)
        );
        assert_eq!(record.key_id.unwrap().id.as_deref(), Some(&key_id[..]));
        let value_blob = record.value.unwrap().blob.unwrap();
        assert_eq!(
            &value_blob[value_blob.len() - 32..],
            encrypted.value_mac.as_ref()
        );

        let keys = wa_crypto::derive_app_state_keys(&key_data).unwrap();
        let decrypted =
            wa_crypto::decrypt_app_state_value(&value_blob[..value_blob.len() - 32], &keys)
                .unwrap();
        let decoded = SyncActionData::decode(decrypted.as_slice()).unwrap();
        assert_eq!(
            decoded.index.as_ref().unwrap(),
            &Bytes::from_static(br#"["pin_v1","123@s.whatsapp.net"]"#)
        );
        assert_eq!(
            decoded.value.unwrap().pin_action.unwrap().pinned,
            Some(true)
        );
    }

    #[cfg(feature = "noise")]
    #[test]
    fn encrypts_chat_mutation_patch_with_generated_iv() {
        let patch = build_archive_chat_patch("123@s.whatsapp.net", true, None, 13).unwrap();
        let key_id = [4u8; 32];
        let key_data = [8u8; 32];

        let encrypted = encrypt_chat_mutation_patch(&patch, &key_id, &key_data).unwrap();
        assert!(!encrypted.encrypted_value.is_empty());
        assert_eq!(encrypted.index_mac.len(), APP_STATE_MAC_LEN);
        assert_eq!(encrypted.value_mac.len(), APP_STATE_MAC_LEN);
        assert_eq!(
            encrypted
                .mutation
                .record
                .as_ref()
                .unwrap()
                .key_id
                .as_ref()
                .unwrap()
                .id
                .as_deref(),
            Some(key_id.as_slice())
        );
    }

    #[cfg(feature = "noise")]
    #[test]
    fn wraps_encrypted_mutations_into_syncd_patch_bundle() {
        let chat_patch = build_pin_chat_patch("123@s.whatsapp.net", true, 13).unwrap();
        let key_id = [4u8; 32];
        let key_data = [8u8; 32];
        let mutation =
            encrypt_chat_mutation_patch_with_iv(&chat_patch, &key_id, &key_data, &[3u8; 16])
                .unwrap();
        let previous =
            AppStatePatchState::new(7, Bytes::from(vec![0u8; APP_STATE_HASH_LEN])).unwrap();
        let bundle = build_app_state_patch_bundle(
            AppStateCollection::RegularLow,
            &previous,
            &key_id,
            &key_data,
            [mutation.clone()],
        )
        .unwrap();

        assert_eq!(bundle.collection, AppStateCollection::RegularLow);
        assert_eq!(bundle.previous_version, 7);
        assert_eq!(bundle.next_state.version(), 8);
        assert_ne!(bundle.next_state.hash(), previous.hash());
        assert_eq!(bundle.next_state.hash().len(), APP_STATE_HASH_LEN);
        assert_eq!(bundle.next_state.index_value_mac_count(), 1);
        assert_eq!(
            bundle
                .next_state
                .value_mac_for_index_mac(&mutation.index_mac)
                .unwrap(),
            Some(&mutation.value_mac)
        );
        assert_eq!(bundle.patch.version.as_ref().unwrap().version, Some(8));
        assert_eq!(
            bundle.patch.key_id.as_ref().unwrap().id.as_deref(),
            Some(&key_id[..])
        );
        assert_eq!(bundle.patch.snapshot_mac.as_ref().unwrap().len(), 32);
        assert_eq!(bundle.patch.patch_mac.as_ref().unwrap().len(), 32);
        assert_eq!(bundle.patch.mutations.len(), 1);
        assert_eq!(bundle.patch.mutations[0], mutation.mutation);

        let decoded = SyncdPatch::decode(bundle.encoded_patch.as_ref()).unwrap();
        assert_eq!(decoded.version.unwrap().version, Some(8));
        assert_eq!(decoded.mutations.len(), 1);

        let query = build_app_state_patch_query_from_patch(
            AppStateCollection::RegularLow,
            bundle.previous_version,
            &decoded,
            "q-4",
        )
        .unwrap();
        let collection = child(child(&query, "sync"), "collection");
        assert_eq!(collection.attrs["name"], "regular_low");
        assert_eq!(collection.attrs["version"], "7");
        assert_eq!(
            child(collection, "patch").content.as_ref().unwrap(),
            &BinaryNodeContent::Bytes(encode_app_state_patch(&decoded))
        );
    }

    #[cfg(feature = "noise")]
    #[test]
    fn decodes_and_verifies_app_state_patch_bundle() {
        let chat_patch = build_pin_chat_patch("123@s.whatsapp.net", true, 13).unwrap();
        let key_id = [4u8; 32];
        let key_data = [8u8; 32];
        let mutation =
            encrypt_chat_mutation_patch_with_iv(&chat_patch, &key_id, &key_data, &[3u8; 16])
                .unwrap();
        let previous =
            AppStatePatchState::new(7, Bytes::from(vec![0u8; APP_STATE_HASH_LEN])).unwrap();
        let bundle = build_app_state_patch_bundle(
            AppStateCollection::RegularLow,
            &previous,
            &key_id,
            &key_data,
            [mutation],
        )
        .unwrap();

        let decoded = decode_app_state_patch(
            AppStateCollection::RegularLow,
            &previous,
            &bundle.patch,
            &key_data,
        )
        .unwrap();
        assert_eq!(decoded.collection, AppStateCollection::RegularLow);
        assert_eq!(decoded.previous_version, 7);
        assert_eq!(decoded.next_state, bundle.next_state);
        assert_eq!(decoded.mutations.len(), 1);
        assert_eq!(
            decoded.mutations[0].index,
            vec!["pin_v1".to_owned(), "123@s.whatsapp.net".to_owned()]
        );
        assert_eq!(decoded.mutations[0].key_id.as_ref(), &key_id);
        assert_eq!(
            decoded.mutations[0]
                .sync_action
                .value
                .as_ref()
                .unwrap()
                .pin_action
                .as_ref()
                .unwrap()
                .pinned,
            Some(true)
        );
        assert_eq!(
            decoded
                .next_state
                .value_mac_for_index_mac(&decoded.mutations[0].index_mac)
                .unwrap(),
            Some(&decoded.mutations[0].value_mac)
        );
    }

    #[cfg(feature = "noise")]
    #[test]
    fn rejects_tampered_app_state_patch_decode_inputs() {
        let chat_patch = build_pin_chat_patch("123@s.whatsapp.net", true, 13).unwrap();
        let key_id = [4u8; 32];
        let key_data = [8u8; 32];
        let mutation =
            encrypt_chat_mutation_patch_with_iv(&chat_patch, &key_id, &key_data, &[3u8; 16])
                .unwrap();
        let previous = AppStatePatchState::empty();
        let bundle = build_app_state_patch_bundle(
            AppStateCollection::RegularLow,
            &previous,
            &key_id,
            &key_data,
            [mutation],
        )
        .unwrap();

        let mut bad_patch_mac = bundle.patch.clone();
        let mut patch_mac = bad_patch_mac.patch_mac.clone().unwrap().to_vec();
        patch_mac[0] ^= 0x01;
        bad_patch_mac.patch_mac = Some(Bytes::from(patch_mac));
        assert!(
            decode_app_state_patch(
                AppStateCollection::RegularLow,
                &previous,
                &bad_patch_mac,
                &key_data
            )
            .is_err()
        );

        let mut bad_operation = bundle.patch.clone();
        bad_operation.mutations[0].operation = Some(99);
        assert!(
            decode_app_state_patch(
                AppStateCollection::RegularLow,
                &previous,
                &bad_operation,
                &key_data
            )
            .is_err()
        );

        let wrong_previous =
            AppStatePatchState::new(0, Bytes::from(vec![9u8; APP_STATE_HASH_LEN])).unwrap();
        assert!(
            decode_app_state_patch(
                AppStateCollection::RegularLow,
                &wrong_previous,
                &bundle.patch,
                &key_data
            )
            .is_err()
        );
    }

    #[cfg(feature = "noise")]
    #[test]
    fn decodes_and_verifies_app_state_snapshot() {
        let chat_patch = build_pin_chat_patch("123@s.whatsapp.net", true, 13).unwrap();
        let key_id = [4u8; 32];
        let key_data = [8u8; 32];
        let mutation =
            encrypt_chat_mutation_patch_with_iv(&chat_patch, &key_id, &key_data, &[3u8; 16])
                .unwrap();
        let expected_state = AppStatePatchState::empty()
            .apply_hash_mutations_at_version(
                11,
                [AppStateHashMutation::from_encrypted(&mutation).unwrap()],
            )
            .unwrap();
        let keys = wa_crypto::derive_app_state_keys(&key_data).unwrap();
        let snapshot_mac = wa_crypto::app_state_snapshot_mac(
            expected_state.hash(),
            11,
            AppStateCollection::RegularLow.name(),
            &keys,
        )
        .unwrap();
        let snapshot = SyncdSnapshot {
            version: Some(SyncdVersion { version: Some(11) }),
            records: vec![mutation.mutation.record.unwrap()],
            mac: Some(Bytes::copy_from_slice(&snapshot_mac)),
            key_id: Some(KeyId {
                id: Some(Bytes::copy_from_slice(&key_id)),
            }),
        };

        let decoded =
            decode_app_state_snapshot(AppStateCollection::RegularLow, &snapshot, &key_data)
                .unwrap();
        assert_eq!(decoded.collection, AppStateCollection::RegularLow);
        assert_eq!(decoded.version, 11);
        assert_eq!(decoded.state, expected_state);
        assert_eq!(decoded.mutations.len(), 1);
        assert_eq!(
            decoded.mutations[0].index,
            vec!["pin_v1".to_owned(), "123@s.whatsapp.net".to_owned()]
        );
        assert_eq!(
            decoded
                .state
                .value_mac_for_index_mac(&decoded.mutations[0].index_mac)
                .unwrap(),
            Some(&decoded.mutations[0].value_mac)
        );
    }

    #[cfg(feature = "noise")]
    #[test]
    fn rejects_tampered_app_state_snapshot_inputs() {
        let chat_patch = build_pin_chat_patch("123@s.whatsapp.net", true, 13).unwrap();
        let key_id = [4u8; 32];
        let key_data = [8u8; 32];
        let mutation =
            encrypt_chat_mutation_patch_with_iv(&chat_patch, &key_id, &key_data, &[3u8; 16])
                .unwrap();
        let expected_state = AppStatePatchState::empty()
            .apply_hash_mutations_at_version(
                1,
                [AppStateHashMutation::from_encrypted(&mutation).unwrap()],
            )
            .unwrap();
        let keys = wa_crypto::derive_app_state_keys(&key_data).unwrap();
        let snapshot_mac = wa_crypto::app_state_snapshot_mac(
            expected_state.hash(),
            1,
            AppStateCollection::RegularLow.name(),
            &keys,
        )
        .unwrap();
        let snapshot = SyncdSnapshot {
            version: Some(SyncdVersion { version: Some(1) }),
            records: vec![mutation.mutation.record.clone().unwrap()],
            mac: Some(Bytes::copy_from_slice(&snapshot_mac)),
            key_id: Some(KeyId {
                id: Some(Bytes::copy_from_slice(&key_id)),
            }),
        };

        let mut bad_mac = snapshot.clone();
        let mut mac = bad_mac.mac.clone().unwrap().to_vec();
        mac[0] ^= 0x01;
        bad_mac.mac = Some(Bytes::from(mac));
        assert!(
            decode_app_state_snapshot(AppStateCollection::RegularLow, &bad_mac, &key_data).is_err()
        );

        let mut mismatched_key = snapshot;
        mismatched_key.key_id = Some(KeyId {
            id: Some(Bytes::from(vec![9u8; 32])),
        });
        assert!(
            decode_app_state_snapshot(AppStateCollection::RegularLow, &mismatched_key, &key_data)
                .is_err()
        );
    }

    #[cfg(feature = "noise")]
    #[tokio::test]
    async fn downloads_and_decodes_external_app_state_snapshot_blob() {
        let chat_patch = build_pin_chat_patch("123@s.whatsapp.net", true, 13).unwrap();
        let key_id = [4u8; 32];
        let key_data = [8u8; 32];
        let mutation =
            encrypt_chat_mutation_patch_with_iv(&chat_patch, &key_id, &key_data, &[3u8; 16])
                .unwrap();
        let expected_state = AppStatePatchState::empty()
            .apply_hash_mutations_at_version(
                11,
                [AppStateHashMutation::from_encrypted(&mutation).unwrap()],
            )
            .unwrap();
        let keys = wa_crypto::derive_app_state_keys(&key_data).unwrap();
        let snapshot_mac = wa_crypto::app_state_snapshot_mac(
            expected_state.hash(),
            11,
            AppStateCollection::RegularLow.name(),
            &keys,
        )
        .unwrap();
        let snapshot = SyncdSnapshot {
            version: Some(SyncdVersion { version: Some(11) }),
            records: vec![mutation.mutation.record.clone().unwrap()],
            mac: Some(Bytes::copy_from_slice(&snapshot_mac)),
            key_id: Some(KeyId {
                id: Some(Bytes::copy_from_slice(&key_id)),
            }),
        };
        let snapshot_bytes = Bytes::from(snapshot.encode_to_vec());
        let encrypted = wa_crypto::encrypt_media_bytes_with_key(
            &snapshot_bytes,
            wa_crypto::MediaKind::AppState,
            &[6u8; 32],
        )
        .unwrap();
        let reference = app_state_external_blob_reference(&encrypted, "/app-state/snapshot");
        let transport = AppStateBlobTransport::default();
        transport.add_download(
            "https://blob.test/app-state/snapshot",
            encrypted.ciphertext_with_mac.clone(),
        );
        let transfer = crate::media::MediaTransfer::new(transport.clone());

        let plaintext = download_app_state_external_blob(&transfer, &reference, Some("blob.test"))
            .await
            .unwrap();
        assert_eq!(plaintext, snapshot_bytes);

        let downloaded_snapshot =
            download_app_state_external_snapshot(&transfer, &reference, Some("blob.test"))
                .await
                .unwrap();
        assert_eq!(downloaded_snapshot.version.unwrap().version, Some(11));

        let decoded = download_and_decode_app_state_snapshot(
            &transfer,
            AppStateCollection::RegularLow,
            &reference,
            &key_data,
            Some("blob.test"),
        )
        .await
        .unwrap();
        assert_eq!(decoded.state, expected_state);
        assert_eq!(decoded.mutations.len(), 1);
        assert_eq!(
            transport.download_urls.lock().unwrap().as_slice(),
            &[
                "https://blob.test/app-state/snapshot".to_owned(),
                "https://blob.test/app-state/snapshot".to_owned(),
                "https://blob.test/app-state/snapshot".to_owned(),
            ]
        );
    }

    #[cfg(feature = "noise")]
    #[tokio::test]
    async fn downloads_external_app_state_mutations_blob() {
        let chat_patch = build_pin_chat_patch("123@s.whatsapp.net", true, 13).unwrap();
        let mutation =
            encrypt_chat_mutation_patch_with_iv(&chat_patch, &[4u8; 32], &[8u8; 32], &[3u8; 16])
                .unwrap();
        let mutations = SyncdMutations {
            mutations: vec![mutation.mutation],
        };
        let encoded = Bytes::from(mutations.encode_to_vec());
        let encrypted = wa_crypto::encrypt_media_bytes_with_key(
            &encoded,
            wa_crypto::MediaKind::AppState,
            &[7u8; 32],
        )
        .unwrap();
        let reference = app_state_external_blob_reference(&encrypted, "/app-state/mutations");
        let transport = AppStateBlobTransport::default();
        transport.add_download(
            "https://blob.test/app-state/mutations",
            encrypted.ciphertext_with_mac.clone(),
        );
        let transfer = crate::media::MediaTransfer::new(transport);

        let decoded =
            download_app_state_external_mutations(&transfer, &reference, Some("blob.test"))
                .await
                .unwrap();
        assert_eq!(decoded.mutations.len(), 1);
    }

    #[cfg(feature = "noise")]
    #[tokio::test]
    async fn rejects_invalid_external_app_state_blob_metadata() {
        let encoded = Bytes::from_static(b"snapshot");
        let encrypted = wa_crypto::encrypt_media_bytes_with_key(
            &encoded,
            wa_crypto::MediaKind::AppState,
            &[6u8; 32],
        )
        .unwrap();
        let reference = app_state_external_blob_reference(&encrypted, "/app-state/snapshot");
        let mut missing_key = reference.clone();
        missing_key.media_key = None;
        assert!(uploaded_media_from_app_state_external_blob(&missing_key).is_err());

        let mut missing_path = reference.clone();
        missing_path.direct_path = None;
        assert!(uploaded_media_from_app_state_external_blob(&missing_path).is_err());

        let transport = AppStateBlobTransport::default();
        let transfer = crate::media::MediaTransfer::with_config(
            transport.clone(),
            crate::media::MediaTransferConfig {
                max_upload_plaintext_bytes: 1024,
                max_download_ciphertext_bytes: encoded.len() - 1,
            },
        );
        assert!(
            download_app_state_external_blob(&transfer, &reference, Some("blob.test"))
                .await
                .is_err()
        );
        assert!(transport.download_urls.lock().unwrap().is_empty());
    }

    #[cfg(feature = "noise")]
    #[test]
    fn rejects_invalid_patch_bundle_inputs() {
        let chat_patch = build_pin_chat_patch("123@s.whatsapp.net", true, 13).unwrap();
        let key_id = [4u8; 32];
        let key_data = [8u8; 32];
        let mutation =
            encrypt_chat_mutation_patch_with_iv(&chat_patch, &key_id, &key_data, &[3u8; 16])
                .unwrap();
        let previous = AppStatePatchState::empty();
        assert!(AppStatePatchState::new(1, Bytes::from(vec![0u8; 127])).is_err());
        assert!(
            AppStateHashMutation::new(
                AppStatePatchOperation::Set,
                Bytes::from(vec![1u8; 31]),
                Bytes::from(vec![2u8; APP_STATE_MAC_LEN]),
            )
            .is_err()
        );
        assert!(
            build_app_state_patch_bundle(
                AppStateCollection::RegularLow,
                &previous,
                &key_id,
                &key_data,
                [],
            )
            .is_err()
        );
        assert!(
            build_app_state_patch_bundle(
                AppStateCollection::RegularLow,
                &previous,
                &[9u8; 32],
                &key_data,
                [mutation],
            )
            .is_err()
        );
    }

    #[cfg(feature = "noise")]
    #[test]
    fn advances_patch_state_with_set_overwrite_remove_and_missing_remove() {
        let index = Bytes::from(vec![1u8; APP_STATE_MAC_LEN]);
        let old_value = Bytes::from(vec![2u8; APP_STATE_MAC_LEN]);
        let new_value = Bytes::from(vec![3u8; APP_STATE_MAC_LEN]);
        let ghost_index = Bytes::from(vec![4u8; APP_STATE_MAC_LEN]);
        let ghost_value = Bytes::from(vec![5u8; APP_STATE_MAC_LEN]);

        let initial = AppStatePatchState::empty();
        let after_set = initial
            .advance_with_hash_mutations([AppStateHashMutation::new(
                AppStatePatchOperation::Set,
                index.clone(),
                old_value.clone(),
            )
            .unwrap()])
            .unwrap();
        assert_eq!(after_set.version(), 1);
        assert_eq!(
            after_set.value_mac_for_index_mac(&index).unwrap(),
            Some(&old_value)
        );
        assert_ne!(after_set.hash(), initial.hash());

        let after_overwrite = after_set
            .advance_with_hash_mutations([AppStateHashMutation::new(
                AppStatePatchOperation::Set,
                index.clone(),
                new_value.clone(),
            )
            .unwrap()])
            .unwrap();
        assert_eq!(after_overwrite.version(), 2);
        assert_eq!(
            after_overwrite.value_mac_for_index_mac(&index).unwrap(),
            Some(&new_value)
        );
        assert_ne!(after_overwrite.hash(), after_set.hash());

        let after_missing_remove = after_overwrite
            .advance_with_hash_mutations([AppStateHashMutation::new(
                AppStatePatchOperation::Remove,
                ghost_index,
                ghost_value,
            )
            .unwrap()])
            .unwrap();
        assert_eq!(after_missing_remove.version(), 3);
        assert_eq!(after_missing_remove.hash(), after_overwrite.hash());
        assert_eq!(after_missing_remove.index_value_mac_count(), 1);

        let after_remove = after_missing_remove
            .advance_with_hash_mutations([AppStateHashMutation::new(
                AppStatePatchOperation::Remove,
                index.clone(),
                old_value,
            )
            .unwrap()])
            .unwrap();
        assert_eq!(after_remove.version(), 4);
        assert_eq!(after_remove.value_mac_for_index_mac(&index).unwrap(), None);
        assert_eq!(after_remove.hash(), initial.hash());
    }

    #[test]
    fn rejects_invalid_chat_mutation_inputs() {
        assert!(build_mute_chat_patch("invalid", None, 1).is_err());
        assert!(build_push_name_patch(" ", 1).is_err());
        assert!(
            build_star_message_patch(
                MessageKey {
                    remote_jid: Some("123@s.whatsapp.net".to_owned()),
                    from_me: None,
                    id: Some("msg".to_owned()),
                    participant: None,
                },
                true,
                1,
            )
            .is_err()
        );
        assert!(build_mute_chat_patch("123@s.whatsapp.net", None, u64::MAX).is_err());
    }

    fn child<'a>(node: &'a BinaryNode, tag: &str) -> &'a BinaryNode {
        children(node, tag)
            .into_iter()
            .next()
            .unwrap_or_else(|| panic!("missing child node {tag}"))
    }

    fn children<'a>(node: &'a BinaryNode, tag: &str) -> Vec<&'a BinaryNode> {
        let Some(BinaryNodeContent::Nodes(children)) = &node.content else {
            panic!("node has no child list");
        };
        children.iter().filter(|child| child.tag == tag).collect()
    }

    #[cfg(feature = "noise")]
    fn decoded_mutation_from_patch(patch: ChatMutationPatch) -> DecodedAppStateMutation {
        DecodedAppStateMutation {
            operation: patch.operation,
            key_id: Bytes::from_static(b"key"),
            index_mac: Bytes::from(vec![1u8; APP_STATE_MAC_LEN]),
            value_mac: Bytes::from(vec![2u8; APP_STATE_MAC_LEN]),
            encrypted_value: Bytes::from_static(b"encrypted"),
            index: patch.index.clone(),
            sync_action: build_sync_action_data(&patch).unwrap(),
        }
    }

    #[cfg(feature = "noise")]
    async fn temp_store() -> wa_store::SqliteAuthStore {
        static TEST_DB_COUNTER: AtomicU64 = AtomicU64::new(0);
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let counter = u128::from(TEST_DB_COUNTER.fetch_add(1, Ordering::AcqRel));
        let process_id = u128::from(std::process::id());
        let suffix = timestamp ^ (process_id << 32) ^ counter;
        let dir = std::env::temp_dir().join(format!("wa-core-app-state-{suffix}"));
        wa_store::SqliteAuthStore::open(dir.join("session.db"))
            .await
            .unwrap()
    }

    #[cfg(feature = "noise")]
    fn app_state_external_blob_reference(
        encrypted: &wa_crypto::EncryptedMedia,
        direct_path: &str,
    ) -> ExternalBlobReference {
        ExternalBlobReference {
            media_key: Some(Bytes::copy_from_slice(encrypted.media_key.expose())),
            direct_path: Some(direct_path.to_owned()),
            handle: None,
            file_size_bytes: Some(encrypted.file_length),
            file_sha256: Some(encrypted.file_sha256.clone()),
            file_enc_sha256: Some(encrypted.file_enc_sha256.clone()),
        }
    }

    #[cfg(feature = "noise")]
    #[derive(Clone, Default)]
    struct AppStateBlobTransport {
        downloads: Arc<Mutex<BTreeMap<String, Bytes>>>,
        download_urls: Arc<Mutex<Vec<String>>>,
    }

    #[cfg(feature = "noise")]
    impl AppStateBlobTransport {
        fn add_download(&self, url: impl Into<String>, bytes: Bytes) {
            self.downloads.lock().unwrap().insert(url.into(), bytes);
        }
    }

    #[cfg(feature = "noise")]
    #[async_trait]
    impl crate::media::MediaTransport for AppStateBlobTransport {
        async fn upload_media(
            &self,
            _request: crate::media::MediaUploadRequest,
        ) -> CoreResult<crate::media::UploadedMediaLocation> {
            Err(CoreError::Payload(
                "app-state blob transport does not upload".to_owned(),
            ))
        }

        async fn download_media(&self, url: &str) -> CoreResult<Bytes> {
            self.download_urls.lock().unwrap().push(url.to_owned());
            self.downloads
                .lock()
                .unwrap()
                .get(url)
                .cloned()
                .ok_or_else(|| CoreError::Payload(format!("missing download fixture: {url}")))
        }
    }
}
