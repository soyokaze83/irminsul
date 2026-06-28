use crate::{
    AppStateCollection, BlocklistAction, CoreError, CoreResult, MessageCappingInfo,
    MessageCappingMultiVariationStatus, MessageCappingOneTimeExtensionStatus, MessageCappingStatus,
    ReachoutTimelockEnforcementType, ReachoutTimelockState,
};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::collections::{BTreeMap, BTreeSet};
use tokio::sync::broadcast;
use wa_binary::BinaryNode;

const STORED_MESSAGE_EVENT_MAGIC: &[u8; 4] = b"MSEV";
const STORED_MESSAGE_UPDATE_MAGIC: &[u8; 4] = b"MSUP";
const STORED_CHAT_EVENT_MAGIC: &[u8; 4] = b"CHTE";
const STORED_CONTACT_EVENT_MAGIC: &[u8; 4] = b"CNTE";
const STORED_GROUP_EVENT_MAGIC: &[u8; 4] = b"GRPE";
const STORED_BUSINESS_NOTIFICATION_EVENT_MAGIC: &[u8; 4] = b"BZNF";
const STORED_NEWSLETTER_REACTION_EVENT_MAGIC: &[u8; 4] = b"NLRC";
const STORED_NEWSLETTER_VIEW_EVENT_MAGIC: &[u8; 4] = b"NLVW";
const STORED_NEWSLETTER_PARTICIPANT_EVENT_MAGIC: &[u8; 4] = b"NLPT";
const STORED_NEWSLETTER_SETTINGS_EVENT_MAGIC: &[u8; 4] = b"NLST";
const STORED_REACHOUT_TIMELOCK_MAGIC: &[u8; 4] = b"RTLK";
const STORED_MESSAGE_CAPPING_INFO_MAGIC: &[u8; 4] = b"MCAP";
const STORED_DEFAULT_DISAPPEARING_MODE_MAGIC: &[u8; 4] = b"DDMD";
const STORED_ACCOUNT_SETTINGS_EVENT_MAGIC: &[u8; 4] = b"ACST";
const STORED_LABEL_EVENT_MAGIC: &[u8; 4] = b"LBLE";
const STORED_LABEL_ASSOCIATION_MAGIC: &[u8; 4] = b"LBLA";
const STORED_QUICK_REPLY_EVENT_MAGIC: &[u8; 4] = b"QRPE";
const STORED_RECEIPT_EVENT_MAGIC: &[u8; 4] = b"RCPT";
const STORED_REACTION_EVENT_MAGIC: &[u8; 4] = b"RCTN";
const STORED_MEDIA_RETRY_EVENT_MAGIC: &[u8; 4] = b"MDRT";
const STORED_RECENT_STICKER_EVENT_MAGIC: &[u8; 4] = b"RSTK";
const STORED_CALL_EVENT_MAGIC: &[u8; 4] = b"CALL";
const STORED_PRESENCE_EVENT_MAGIC: &[u8; 4] = b"PRES";
const STORED_EVENT_RECORD_VERSION: u8 = 1;
const MAX_STORED_EVENT_RECORD_BYTES: usize = 8 * 1024 * 1024;
const MAX_STORED_EVENT_PAYLOAD_BYTES: usize = 8 * 1024 * 1024;
const MAX_STORED_EVENT_STRING_BYTES: usize = 64 * 1024;
const MAX_STORED_EVENT_FIELD_COUNT: usize = 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConnectionState {
    Connecting,
    Open,
    Closed,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct MessageEventKey {
    pub remote_jid: String,
    pub id: String,
    pub participant: Option<String>,
}

impl MessageEventKey {
    #[must_use]
    pub fn new(
        remote_jid: impl Into<String>,
        id: impl Into<String>,
        participant: Option<String>,
    ) -> Self {
        Self {
            remote_jid: remote_jid.into(),
            id: id.into(),
            participant,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MessageEvent {
    pub key: MessageEventKey,
    pub timestamp: Option<u64>,
    pub payload: Option<Bytes>,
    pub fields: BTreeMap<String, String>,
}

impl MessageEvent {
    #[must_use]
    pub fn new(key: MessageEventKey) -> Self {
        Self {
            key,
            timestamp: None,
            payload: None,
            fields: BTreeMap::new(),
        }
    }

    #[must_use]
    pub fn with_timestamp(mut self, timestamp: u64) -> Self {
        self.timestamp = Some(timestamp);
        self
    }

    #[must_use]
    pub fn with_payload(mut self, payload: Bytes) -> Self {
        self.payload = Some(payload);
        self
    }

    #[must_use]
    pub fn with_field(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.fields.insert(key.into(), value.into());
        self
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MessageUpdate {
    pub key: MessageEventKey,
    pub timestamp: Option<u64>,
    pub fields: BTreeMap<String, String>,
}

impl MessageUpdate {
    #[must_use]
    pub fn new(key: MessageEventKey) -> Self {
        Self {
            key,
            timestamp: None,
            fields: BTreeMap::new(),
        }
    }

    #[must_use]
    pub fn with_timestamp(mut self, timestamp: u64) -> Self {
        self.timestamp = Some(timestamp);
        self
    }

    #[must_use]
    pub fn with_field(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.fields.insert(key.into(), value.into());
        self
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChatEvent {
    pub jid: String,
    pub fields: BTreeMap<String, String>,
}

impl ChatEvent {
    #[must_use]
    pub fn new(jid: impl Into<String>) -> Self {
        Self {
            jid: jid.into(),
            fields: BTreeMap::new(),
        }
    }

    #[must_use]
    pub fn with_field(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.fields.insert(key.into(), value.into());
        self
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContactEvent {
    pub jid: String,
    pub fields: BTreeMap<String, String>,
}

impl ContactEvent {
    #[must_use]
    pub fn new(jid: impl Into<String>) -> Self {
        Self {
            jid: jid.into(),
            fields: BTreeMap::new(),
        }
    }

    #[must_use]
    pub fn with_field(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.fields.insert(key.into(), value.into());
        self
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PresenceEvent {
    pub jid: String,
    pub presence_type: String,
    pub participant: Option<String>,
    pub timestamp: Option<u64>,
    pub fields: BTreeMap<String, String>,
}

impl PresenceEvent {
    #[must_use]
    pub fn new(jid: impl Into<String>, presence_type: impl Into<String>) -> Self {
        Self {
            jid: jid.into(),
            presence_type: presence_type.into(),
            participant: None,
            timestamp: None,
            fields: BTreeMap::new(),
        }
    }

    #[must_use]
    pub fn with_participant(mut self, participant: impl Into<String>) -> Self {
        self.participant = Some(participant.into());
        self
    }

    #[must_use]
    pub fn with_timestamp(mut self, timestamp: u64) -> Self {
        self.timestamp = Some(timestamp);
        self
    }

    #[must_use]
    pub fn with_field(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.fields.insert(key.into(), value.into());
        self
    }

    fn buffer_key(&self) -> PresenceBufferKey {
        PresenceBufferKey {
            jid: self.jid.clone(),
            participant: self.participant.clone(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct PresenceBufferKey {
    jid: String,
    participant: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlocklistUpdateEvent {
    pub jid: String,
    pub action: BlocklistAction,
}

impl BlocklistUpdateEvent {
    #[must_use]
    pub fn new(jid: impl Into<String>, action: BlocklistAction) -> Self {
        Self {
            jid: jid.into(),
            action,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DefaultDisappearingMode {
    pub duration_seconds: u32,
    pub timestamp: Option<u64>,
}

impl DefaultDisappearingMode {
    #[must_use]
    pub fn new(duration_seconds: u32) -> Self {
        Self {
            duration_seconds,
            timestamp: None,
        }
    }

    #[must_use]
    pub fn with_timestamp(mut self, timestamp: u64) -> Self {
        self.timestamp = Some(timestamp);
        self
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountSettingsEvent {
    pub id: String,
    pub fields: BTreeMap<String, String>,
}

impl AccountSettingsEvent {
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            fields: BTreeMap::new(),
        }
    }

    #[must_use]
    pub fn with_field(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.fields.insert(key.into(), value.into());
        self
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LabelEvent {
    pub id: String,
    pub fields: BTreeMap<String, String>,
}

impl LabelEvent {
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            fields: BTreeMap::new(),
        }
    }

    #[must_use]
    pub fn with_field(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.fields.insert(key.into(), value.into());
        self
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum LabelAssociationTarget {
    Chat {
        chat_jid: String,
    },
    Message {
        chat_jid: String,
        message_id: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LabelAssociationEvent {
    pub label_id: String,
    pub target: LabelAssociationTarget,
    pub labeled: bool,
}

impl LabelAssociationEvent {
    #[must_use]
    pub fn chat(label_id: impl Into<String>, chat_jid: impl Into<String>, labeled: bool) -> Self {
        Self {
            label_id: label_id.into(),
            target: LabelAssociationTarget::Chat {
                chat_jid: chat_jid.into(),
            },
            labeled,
        }
    }

    #[must_use]
    pub fn message(
        label_id: impl Into<String>,
        chat_jid: impl Into<String>,
        message_id: impl Into<String>,
        labeled: bool,
    ) -> Self {
        Self {
            label_id: label_id.into(),
            target: LabelAssociationTarget::Message {
                chat_jid: chat_jid.into(),
                message_id: message_id.into(),
            },
            labeled,
        }
    }

    fn buffer_key(&self) -> LabelAssociationBufferKey {
        LabelAssociationBufferKey {
            label_id: self.label_id.clone(),
            target: self.target.clone(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct LabelAssociationBufferKey {
    label_id: String,
    target: LabelAssociationTarget,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuickReplyEvent {
    pub id: String,
    pub fields: BTreeMap<String, String>,
}

impl QuickReplyEvent {
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            fields: BTreeMap::new(),
        }
    }

    #[must_use]
    pub fn with_field(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.fields.insert(key.into(), value.into());
        self
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupUpdateEvent {
    pub jid: String,
    pub fields: BTreeMap<String, String>,
}

impl GroupUpdateEvent {
    #[must_use]
    pub fn new(jid: impl Into<String>) -> Self {
        Self {
            jid: jid.into(),
            fields: BTreeMap::new(),
        }
    }

    #[must_use]
    pub fn with_field(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.fields.insert(key.into(), value.into());
        self
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiptEvent {
    pub key: MessageEventKey,
    pub receipt_type: String,
    pub participant: Option<String>,
    pub timestamp: Option<u64>,
}

impl ReceiptEvent {
    #[must_use]
    pub fn new(key: MessageEventKey, receipt_type: impl Into<String>) -> Self {
        Self {
            key,
            receipt_type: receipt_type.into(),
            participant: None,
            timestamp: None,
        }
    }

    #[must_use]
    pub fn with_participant(mut self, participant: impl Into<String>) -> Self {
        self.participant = Some(participant.into());
        self
    }

    #[must_use]
    pub fn with_timestamp(mut self, timestamp: u64) -> Self {
        self.timestamp = Some(timestamp);
        self
    }

    fn buffer_key(&self) -> ReceiptBufferKey {
        ReceiptBufferKey {
            key: self.key.clone(),
            receipt_type: self.receipt_type.clone(),
            participant: self.participant.clone(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct ReceiptBufferKey {
    key: MessageEventKey,
    receipt_type: String,
    participant: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReactionEvent {
    pub key: MessageEventKey,
    pub from_jid: String,
    pub text: Option<String>,
    pub timestamp: Option<u64>,
}

impl ReactionEvent {
    #[must_use]
    pub fn new(key: MessageEventKey, from_jid: impl Into<String>) -> Self {
        Self {
            key,
            from_jid: from_jid.into(),
            text: None,
            timestamp: None,
        }
    }

    #[must_use]
    pub fn with_text(mut self, text: impl Into<String>) -> Self {
        self.text = Some(text.into());
        self
    }

    #[must_use]
    pub fn with_timestamp(mut self, timestamp: u64) -> Self {
        self.timestamp = Some(timestamp);
        self
    }

    fn buffer_key(&self) -> ReactionBufferKey {
        ReactionBufferKey {
            key: self.key.clone(),
            from_jid: self.from_jid.clone(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct ReactionBufferKey {
    key: MessageEventKey,
    from_jid: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MediaRetryEvent {
    pub key: MessageEventKey,
    pub from_me: bool,
    pub encrypted_payload: Option<Bytes>,
    pub iv: Option<Bytes>,
    pub error_code: Option<u16>,
    pub error_text: Option<String>,
    pub status_code: Option<u16>,
}

impl MediaRetryEvent {
    #[must_use]
    pub fn new(key: MessageEventKey, from_me: bool) -> Self {
        Self {
            key,
            from_me,
            encrypted_payload: None,
            iv: None,
            error_code: None,
            error_text: None,
            status_code: None,
        }
    }

    #[must_use]
    pub fn with_encrypted_payload(mut self, encrypted_payload: Bytes, iv: Bytes) -> Self {
        self.encrypted_payload = Some(encrypted_payload);
        self.iv = Some(iv);
        self
    }

    #[must_use]
    pub fn with_error(mut self, code: u16, text: Option<String>, status_code: u16) -> Self {
        self.error_code = Some(code);
        self.error_text = text;
        self.status_code = Some(status_code);
        self
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecentStickerEvent {
    pub id: String,
    pub file_sha256: Option<Bytes>,
    pub file_enc_sha256: Option<Bytes>,
    pub media_key: Option<Bytes>,
    pub fields: BTreeMap<String, String>,
}

impl RecentStickerEvent {
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            file_sha256: None,
            file_enc_sha256: None,
            media_key: None,
            fields: BTreeMap::new(),
        }
    }

    #[must_use]
    pub fn with_file_sha256(mut self, value: Bytes) -> Self {
        self.file_sha256 = Some(value);
        self
    }

    #[must_use]
    pub fn with_file_enc_sha256(mut self, value: Bytes) -> Self {
        self.file_enc_sha256 = Some(value);
        self
    }

    #[must_use]
    pub fn with_media_key(mut self, value: Bytes) -> Self {
        self.media_key = Some(value);
        self
    }

    #[must_use]
    pub fn with_field(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.fields.insert(key.into(), value.into());
        self
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LidMappingEvent {
    pub lid_jid: String,
    pub pn_jid: String,
}

impl LidMappingEvent {
    #[must_use]
    pub fn new(lid_jid: impl Into<String>, pn_jid: impl Into<String>) -> Self {
        Self {
            lid_jid: lid_jid.into(),
            pn_jid: pn_jid.into(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BusinessNotificationEvent {
    pub from: String,
    pub notification_id: String,
    pub event_type: String,
    pub fields: BTreeMap<String, String>,
}

impl BusinessNotificationEvent {
    #[must_use]
    pub fn new(
        from: impl Into<String>,
        notification_id: impl Into<String>,
        event_type: impl Into<String>,
    ) -> Self {
        Self {
            from: from.into(),
            notification_id: notification_id.into(),
            event_type: event_type.into(),
            fields: BTreeMap::new(),
        }
    }

    #[must_use]
    pub fn with_field(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.fields.insert(key.into(), value.into());
        self
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NewsletterReactionEvent {
    pub id: String,
    pub server_id: String,
    pub code: Option<String>,
    pub count: Option<u64>,
    pub removed: bool,
}

impl NewsletterReactionEvent {
    #[must_use]
    pub fn new(id: impl Into<String>, server_id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            server_id: server_id.into(),
            code: None,
            count: None,
            removed: false,
        }
    }

    #[must_use]
    pub fn with_code(mut self, code: impl Into<String>) -> Self {
        self.code = Some(code.into());
        self
    }

    #[must_use]
    pub fn with_count(mut self, count: u64) -> Self {
        self.count = Some(count);
        self
    }

    #[must_use]
    pub fn removed(mut self) -> Self {
        self.removed = true;
        self
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NewsletterViewEvent {
    pub id: String,
    pub server_id: String,
    pub count: u64,
}

impl NewsletterViewEvent {
    #[must_use]
    pub fn new(id: impl Into<String>, server_id: impl Into<String>, count: u64) -> Self {
        Self {
            id: id.into(),
            server_id: server_id.into(),
            count,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NewsletterParticipantUpdateEvent {
    pub id: String,
    pub author: String,
    pub user: String,
    pub action: String,
    pub new_role: String,
}

impl NewsletterParticipantUpdateEvent {
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        author: impl Into<String>,
        user: impl Into<String>,
        action: impl Into<String>,
        new_role: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            author: author.into(),
            user: user.into(),
            action: action.into(),
            new_role: new_role.into(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NewsletterSettingsUpdateEvent {
    pub id: String,
    pub fields: BTreeMap<String, String>,
}

impl NewsletterSettingsUpdateEvent {
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            fields: BTreeMap::new(),
        }
    }

    #[must_use]
    pub fn with_field(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.fields.insert(key.into(), value.into());
        self
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CallEvent {
    pub id: String,
    pub from: String,
    pub event_type: String,
    pub call_id: Option<String>,
    pub participant: Option<String>,
    pub timestamp: Option<u64>,
    pub fields: BTreeMap<String, String>,
}

impl CallEvent {
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        from: impl Into<String>,
        event_type: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            from: from.into(),
            event_type: event_type.into(),
            call_id: None,
            participant: None,
            timestamp: None,
            fields: BTreeMap::new(),
        }
    }

    #[must_use]
    pub fn with_call_id(mut self, call_id: impl Into<String>) -> Self {
        self.call_id = Some(call_id.into());
        self
    }

    #[must_use]
    pub fn with_participant(mut self, participant: impl Into<String>) -> Self {
        self.participant = Some(participant.into());
        self
    }

    #[must_use]
    pub fn with_timestamp(mut self, timestamp: u64) -> Self {
        self.timestamp = Some(timestamp);
        self
    }

    #[must_use]
    pub fn with_field(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.fields.insert(key.into(), value.into());
        self
    }

    fn buffer_key(&self) -> String {
        call_event_store_key(self)
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct HistorySetEvent {
    pub chats: Vec<ChatEvent>,
    pub contacts: Vec<ContactEvent>,
    pub messages: Vec<MessageEvent>,
    pub is_latest: bool,
}

impl HistorySetEvent {
    #[must_use]
    pub fn pending_items(&self) -> usize {
        self.chats.len() + self.contacts.len() + self.messages.len()
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EventBatch {
    pub history: Option<HistorySetEvent>,
    pub messages_upsert: Vec<MessageEvent>,
    pub messages_update: Vec<MessageUpdate>,
    pub messages_delete: Vec<MessageEventKey>,
    pub chats_upsert: Vec<ChatEvent>,
    pub chats_update: Vec<ChatEvent>,
    pub chats_delete: Vec<String>,
    pub contacts_upsert: Vec<ContactEvent>,
    pub contacts_update: Vec<ContactEvent>,
    pub contacts_delete: Vec<String>,
    pub labels_edit: Vec<LabelEvent>,
    pub labels_association: Vec<LabelAssociationEvent>,
    pub quick_replies_update: Vec<QuickReplyEvent>,
    pub groups_update: Vec<GroupUpdateEvent>,
    pub receipts_update: Vec<ReceiptEvent>,
    pub reactions_update: Vec<ReactionEvent>,
    pub media_retry: Vec<MediaRetryEvent>,
    pub recent_stickers: Vec<RecentStickerEvent>,
    pub account_settings: Vec<AccountSettingsEvent>,
    pub business_notifications: Vec<BusinessNotificationEvent>,
    pub calls_update: Vec<CallEvent>,
    pub presence_update: Vec<PresenceEvent>,
}

impl EventBatch {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pending_items() == 0
    }

    #[must_use]
    pub fn pending_items(&self) -> usize {
        self.history
            .as_ref()
            .map_or(0, HistorySetEvent::pending_items)
            + self.messages_upsert.len()
            + self.messages_update.len()
            + self.messages_delete.len()
            + self.chats_upsert.len()
            + self.chats_update.len()
            + self.chats_delete.len()
            + self.contacts_upsert.len()
            + self.contacts_update.len()
            + self.contacts_delete.len()
            + self.labels_edit.len()
            + self.labels_association.len()
            + self.quick_replies_update.len()
            + self.groups_update.len()
            + self.receipts_update.len()
            + self.reactions_update.len()
            + self.media_retry.len()
            + self.recent_stickers.len()
            + self.account_settings.len()
            + self.business_notifications.len()
            + self.calls_update.len()
            + self.presence_update.len()
    }
}

#[must_use]
pub fn message_event_store_key(key: &MessageEventKey) -> String {
    match &key.participant {
        Some(participant) => format!("{}|{}|{}", key.remote_jid, key.id, participant),
        None => format!("{}|{}", key.remote_jid, key.id),
    }
}

#[must_use]
pub fn receipt_event_store_key(event: &ReceiptEvent) -> String {
    match &event.participant {
        Some(participant) => format!(
            "{}|{}|{}",
            message_event_store_key(&event.key),
            event.receipt_type,
            participant
        ),
        None => format!(
            "{}|{}",
            message_event_store_key(&event.key),
            event.receipt_type
        ),
    }
}

#[must_use]
pub fn reaction_event_store_key(event: &ReactionEvent) -> String {
    format!("{}|{}", message_event_store_key(&event.key), event.from_jid)
}

#[must_use]
pub fn media_retry_event_store_key(event: &MediaRetryEvent) -> String {
    message_event_store_key(&event.key)
}

#[must_use]
pub fn recent_sticker_event_store_key(event: &RecentStickerEvent) -> String {
    event.id.clone()
}

#[must_use]
pub fn business_notification_event_store_key(event: &BusinessNotificationEvent) -> String {
    format!(
        "{}|{}|{}",
        event.from, event.notification_id, event.event_type
    )
}

#[must_use]
pub fn newsletter_reaction_event_store_key(event: &NewsletterReactionEvent) -> String {
    format!(
        "{}|{}|{}",
        event.id,
        event.server_id,
        event.code.as_deref().unwrap_or_default()
    )
}

#[must_use]
pub fn newsletter_view_event_store_key(event: &NewsletterViewEvent) -> String {
    format!("{}|{}", event.id, event.server_id)
}

#[must_use]
pub fn newsletter_participant_update_event_store_key(
    event: &NewsletterParticipantUpdateEvent,
) -> String {
    format!(
        "{}|{}|{}|{}",
        event.id, event.user, event.action, event.new_role
    )
}

#[must_use]
pub fn newsletter_settings_update_event_store_key(event: &NewsletterSettingsUpdateEvent) -> String {
    event.id.clone()
}

#[must_use]
pub fn reachout_timelock_store_key() -> &'static str {
    "account"
}

#[must_use]
pub fn message_capping_info_store_key() -> &'static str {
    "new-chat"
}

#[must_use]
pub fn default_disappearing_mode_store_key() -> &'static str {
    "account"
}

#[must_use]
pub fn account_settings_event_store_key(event: &AccountSettingsEvent) -> String {
    event.id.clone()
}

#[must_use]
pub fn call_event_store_key(event: &CallEvent) -> String {
    match &event.call_id {
        Some(call_id) => format!(
            "{}|{}|{}|{}",
            event.from, event.id, event.event_type, call_id
        ),
        None => format!("{}|{}|{}", event.from, event.id, event.event_type),
    }
}

#[must_use]
pub fn presence_event_store_key(event: &PresenceEvent) -> String {
    match &event.participant {
        Some(participant) => format!("{}|{}", event.jid, participant),
        None => event.jid.clone(),
    }
}

#[must_use]
pub fn label_association_store_key(event: &LabelAssociationEvent) -> String {
    match &event.target {
        LabelAssociationTarget::Chat { chat_jid } => {
            format!("{}|chat|{}", event.label_id, chat_jid)
        }
        LabelAssociationTarget::Message {
            chat_jid,
            message_id,
        } => format!("{}|message|{}|{}", event.label_id, chat_jid, message_id),
    }
}

pub fn encode_stored_message_event(event: &MessageEvent) -> CoreResult<Vec<u8>> {
    let mut out = BytesMut::new();
    out.extend_from_slice(STORED_MESSAGE_EVENT_MAGIC);
    out.put_u8(STORED_EVENT_RECORD_VERSION);
    put_message_event_key(&mut out, &event.key)?;
    put_optional_u64(&mut out, event.timestamp);
    put_optional_bytes(&mut out, event.payload.as_ref().map(Bytes::as_ref))?;
    put_string_map(&mut out, &event.fields)?;
    Ok(out.to_vec())
}

pub fn decode_stored_message_event(value: &[u8]) -> CoreResult<MessageEvent> {
    validate_stored_record_len(value)?;
    let mut input = value;
    read_magic(&mut input, STORED_MESSAGE_EVENT_MAGIC, "message event")?;
    let key = read_message_event_key(&mut input)?;
    let timestamp = read_optional_u64(&mut input)?;
    let payload = read_optional_bytes(&mut input)?.map(Bytes::from);
    let fields = read_string_map(&mut input)?;
    reject_trailing_stored_bytes(input, "message event")?;
    Ok(MessageEvent {
        key,
        timestamp,
        payload,
        fields,
    })
}

pub fn encode_stored_message_update(update: &MessageUpdate) -> CoreResult<Vec<u8>> {
    let mut out = BytesMut::new();
    out.extend_from_slice(STORED_MESSAGE_UPDATE_MAGIC);
    out.put_u8(STORED_EVENT_RECORD_VERSION);
    put_message_event_key(&mut out, &update.key)?;
    put_optional_u64(&mut out, update.timestamp);
    put_string_map(&mut out, &update.fields)?;
    Ok(out.to_vec())
}

pub fn decode_stored_message_update(value: &[u8]) -> CoreResult<MessageUpdate> {
    validate_stored_record_len(value)?;
    let mut input = value;
    read_magic(&mut input, STORED_MESSAGE_UPDATE_MAGIC, "message update")?;
    let key = read_message_event_key(&mut input)?;
    let timestamp = read_optional_u64(&mut input)?;
    let fields = read_string_map(&mut input)?;
    reject_trailing_stored_bytes(input, "message update")?;
    Ok(MessageUpdate {
        key,
        timestamp,
        fields,
    })
}

pub fn encode_stored_chat_event(event: &ChatEvent) -> CoreResult<Vec<u8>> {
    encode_stored_jid_fields_record(STORED_CHAT_EVENT_MAGIC, &event.jid, &event.fields)
}

pub fn decode_stored_chat_event(value: &[u8]) -> CoreResult<ChatEvent> {
    let (jid, fields) = decode_stored_jid_fields_record(value, STORED_CHAT_EVENT_MAGIC, "chat")?;
    Ok(ChatEvent { jid, fields })
}

pub fn encode_stored_contact_event(event: &ContactEvent) -> CoreResult<Vec<u8>> {
    encode_stored_jid_fields_record(STORED_CONTACT_EVENT_MAGIC, &event.jid, &event.fields)
}

pub fn decode_stored_contact_event(value: &[u8]) -> CoreResult<ContactEvent> {
    let (jid, fields) =
        decode_stored_jid_fields_record(value, STORED_CONTACT_EVENT_MAGIC, "contact")?;
    Ok(ContactEvent { jid, fields })
}

pub fn encode_stored_group_event(event: &GroupUpdateEvent) -> CoreResult<Vec<u8>> {
    encode_stored_jid_fields_record(STORED_GROUP_EVENT_MAGIC, &event.jid, &event.fields)
}

pub fn decode_stored_group_event(value: &[u8]) -> CoreResult<GroupUpdateEvent> {
    let (jid, fields) = decode_stored_jid_fields_record(value, STORED_GROUP_EVENT_MAGIC, "group")?;
    Ok(GroupUpdateEvent { jid, fields })
}

pub fn encode_stored_business_notification_event(
    event: &BusinessNotificationEvent,
) -> CoreResult<Vec<u8>> {
    let mut out = BytesMut::new();
    out.extend_from_slice(STORED_BUSINESS_NOTIFICATION_EVENT_MAGIC);
    out.put_u8(STORED_EVENT_RECORD_VERSION);
    put_string(&mut out, &event.from)?;
    put_string(&mut out, &event.notification_id)?;
    put_string(&mut out, &event.event_type)?;
    put_string_map(&mut out, &event.fields)?;
    Ok(out.to_vec())
}

pub fn decode_stored_business_notification_event(
    value: &[u8],
) -> CoreResult<BusinessNotificationEvent> {
    validate_stored_record_len(value)?;
    let mut input = value;
    read_magic(
        &mut input,
        STORED_BUSINESS_NOTIFICATION_EVENT_MAGIC,
        "business notification",
    )?;
    let from = read_string(&mut input)?;
    let notification_id = read_string(&mut input)?;
    let event_type = read_string(&mut input)?;
    let fields = read_string_map(&mut input)?;
    reject_trailing_stored_bytes(input, "business notification")?;
    Ok(BusinessNotificationEvent {
        from,
        notification_id,
        event_type,
        fields,
    })
}

pub fn encode_stored_newsletter_reaction_event(
    event: &NewsletterReactionEvent,
) -> CoreResult<Vec<u8>> {
    let mut out = BytesMut::new();
    out.extend_from_slice(STORED_NEWSLETTER_REACTION_EVENT_MAGIC);
    out.put_u8(STORED_EVENT_RECORD_VERSION);
    put_string(&mut out, &event.id)?;
    put_string(&mut out, &event.server_id)?;
    put_optional_string(&mut out, event.code.as_deref())?;
    put_optional_u64(&mut out, event.count);
    out.put_u8(u8::from(event.removed));
    Ok(out.to_vec())
}

pub fn decode_stored_newsletter_reaction_event(
    value: &[u8],
) -> CoreResult<NewsletterReactionEvent> {
    validate_stored_record_len(value)?;
    let mut input = value;
    read_magic(
        &mut input,
        STORED_NEWSLETTER_REACTION_EVENT_MAGIC,
        "newsletter reaction",
    )?;
    let id = read_string(&mut input)?;
    let server_id = read_string(&mut input)?;
    let code = read_optional_string(&mut input)?;
    let count = read_optional_u64(&mut input)?;
    if input.remaining() < 1 {
        return Err(CoreError::Protocol(
            "stored newsletter reaction missing removed flag".to_owned(),
        ));
    }
    let removed = match input.get_u8() {
        0 => false,
        1 => true,
        value => {
            return Err(CoreError::Protocol(format!(
                "stored newsletter reaction has invalid removed flag {value}"
            )));
        }
    };
    reject_trailing_stored_bytes(input, "newsletter reaction")?;
    Ok(NewsletterReactionEvent {
        id,
        server_id,
        code,
        count,
        removed,
    })
}

pub fn encode_stored_newsletter_view_event(event: &NewsletterViewEvent) -> CoreResult<Vec<u8>> {
    let mut out = BytesMut::new();
    out.extend_from_slice(STORED_NEWSLETTER_VIEW_EVENT_MAGIC);
    out.put_u8(STORED_EVENT_RECORD_VERSION);
    put_string(&mut out, &event.id)?;
    put_string(&mut out, &event.server_id)?;
    out.put_u64(event.count);
    Ok(out.to_vec())
}

pub fn decode_stored_newsletter_view_event(value: &[u8]) -> CoreResult<NewsletterViewEvent> {
    validate_stored_record_len(value)?;
    let mut input = value;
    read_magic(
        &mut input,
        STORED_NEWSLETTER_VIEW_EVENT_MAGIC,
        "newsletter view",
    )?;
    let id = read_string(&mut input)?;
    let server_id = read_string(&mut input)?;
    if input.remaining() < 8 {
        return Err(CoreError::Protocol(
            "stored newsletter view has truncated count".to_owned(),
        ));
    }
    let count = input.get_u64();
    reject_trailing_stored_bytes(input, "newsletter view")?;
    Ok(NewsletterViewEvent {
        id,
        server_id,
        count,
    })
}

pub fn encode_stored_newsletter_participant_update_event(
    event: &NewsletterParticipantUpdateEvent,
) -> CoreResult<Vec<u8>> {
    let mut out = BytesMut::new();
    out.extend_from_slice(STORED_NEWSLETTER_PARTICIPANT_EVENT_MAGIC);
    out.put_u8(STORED_EVENT_RECORD_VERSION);
    put_string(&mut out, &event.id)?;
    put_string(&mut out, &event.author)?;
    put_string(&mut out, &event.user)?;
    put_string(&mut out, &event.action)?;
    put_string(&mut out, &event.new_role)?;
    Ok(out.to_vec())
}

pub fn decode_stored_newsletter_participant_update_event(
    value: &[u8],
) -> CoreResult<NewsletterParticipantUpdateEvent> {
    validate_stored_record_len(value)?;
    let mut input = value;
    read_magic(
        &mut input,
        STORED_NEWSLETTER_PARTICIPANT_EVENT_MAGIC,
        "newsletter participant",
    )?;
    let id = read_string(&mut input)?;
    let author = read_string(&mut input)?;
    let user = read_string(&mut input)?;
    let action = read_string(&mut input)?;
    let new_role = read_string(&mut input)?;
    reject_trailing_stored_bytes(input, "newsletter participant")?;
    Ok(NewsletterParticipantUpdateEvent {
        id,
        author,
        user,
        action,
        new_role,
    })
}

pub fn encode_stored_newsletter_settings_update_event(
    event: &NewsletterSettingsUpdateEvent,
) -> CoreResult<Vec<u8>> {
    let mut out = BytesMut::new();
    out.extend_from_slice(STORED_NEWSLETTER_SETTINGS_EVENT_MAGIC);
    out.put_u8(STORED_EVENT_RECORD_VERSION);
    put_string(&mut out, &event.id)?;
    put_string_map(&mut out, &event.fields)?;
    Ok(out.to_vec())
}

pub fn decode_stored_newsletter_settings_update_event(
    value: &[u8],
) -> CoreResult<NewsletterSettingsUpdateEvent> {
    validate_stored_record_len(value)?;
    let mut input = value;
    read_magic(
        &mut input,
        STORED_NEWSLETTER_SETTINGS_EVENT_MAGIC,
        "newsletter settings",
    )?;
    let id = read_string(&mut input)?;
    let fields = read_string_map(&mut input)?;
    reject_trailing_stored_bytes(input, "newsletter settings")?;
    Ok(NewsletterSettingsUpdateEvent { id, fields })
}

pub fn encode_stored_reachout_timelock_state(state: &ReachoutTimelockState) -> CoreResult<Vec<u8>> {
    let mut out = BytesMut::new();
    out.extend_from_slice(STORED_REACHOUT_TIMELOCK_MAGIC);
    out.put_u8(STORED_EVENT_RECORD_VERSION);
    out.put_u8(u8::from(state.is_active));
    put_optional_u64(&mut out, state.time_enforcement_ends);
    put_string(&mut out, state.enforcement_type.as_wire_str())?;
    Ok(out.to_vec())
}

pub fn decode_stored_reachout_timelock_state(value: &[u8]) -> CoreResult<ReachoutTimelockState> {
    validate_stored_record_len(value)?;
    let mut input = value;
    read_magic(
        &mut input,
        STORED_REACHOUT_TIMELOCK_MAGIC,
        "reachout timelock",
    )?;
    if input.remaining() < 1 {
        return Err(CoreError::Protocol(
            "stored reachout timelock missing active flag".to_owned(),
        ));
    }
    let is_active = match input.get_u8() {
        0 => false,
        1 => true,
        value => {
            return Err(CoreError::Protocol(format!(
                "stored reachout timelock has invalid active flag {value}"
            )));
        }
    };
    let time_enforcement_ends = read_optional_u64(&mut input)?;
    let enforcement_type = ReachoutTimelockEnforcementType::from_wire(&read_string(&mut input)?);
    reject_trailing_stored_bytes(input, "reachout timelock")?;
    Ok(ReachoutTimelockState {
        is_active,
        time_enforcement_ends,
        enforcement_type,
    })
}

pub fn encode_stored_message_capping_info(info: &MessageCappingInfo) -> CoreResult<Vec<u8>> {
    let mut out = BytesMut::new();
    out.extend_from_slice(STORED_MESSAGE_CAPPING_INFO_MAGIC);
    out.put_u8(STORED_EVENT_RECORD_VERSION);
    put_optional_u64(&mut out, info.total_quota);
    put_optional_u64(&mut out, info.used_quota);
    put_optional_u64(&mut out, info.cycle_start_timestamp);
    put_optional_u64(&mut out, info.cycle_end_timestamp);
    put_optional_u64(&mut out, info.server_sent_timestamp);
    put_optional_string(
        &mut out,
        info.one_time_extension_status
            .as_ref()
            .map(MessageCappingOneTimeExtensionStatus::as_wire_str),
    )?;
    put_optional_string(
        &mut out,
        info.multi_variation_status
            .as_ref()
            .map(MessageCappingMultiVariationStatus::as_wire_str),
    )?;
    put_optional_string(
        &mut out,
        info.capping_status
            .as_ref()
            .map(MessageCappingStatus::as_wire_str),
    )?;
    Ok(out.to_vec())
}

pub fn decode_stored_message_capping_info(value: &[u8]) -> CoreResult<MessageCappingInfo> {
    validate_stored_record_len(value)?;
    let mut input = value;
    read_magic(
        &mut input,
        STORED_MESSAGE_CAPPING_INFO_MAGIC,
        "message capping info",
    )?;
    let total_quota = read_optional_u64(&mut input)?;
    let used_quota = read_optional_u64(&mut input)?;
    let cycle_start_timestamp = read_optional_u64(&mut input)?;
    let cycle_end_timestamp = read_optional_u64(&mut input)?;
    let server_sent_timestamp = read_optional_u64(&mut input)?;
    let one_time_extension_status = read_optional_string(&mut input)?
        .map(|value| MessageCappingOneTimeExtensionStatus::from_wire(&value));
    let multi_variation_status = read_optional_string(&mut input)?
        .map(|value| MessageCappingMultiVariationStatus::from_wire(&value));
    let capping_status =
        read_optional_string(&mut input)?.map(|value| MessageCappingStatus::from_wire(&value));
    reject_trailing_stored_bytes(input, "message capping info")?;
    Ok(MessageCappingInfo {
        total_quota,
        used_quota,
        cycle_start_timestamp,
        cycle_end_timestamp,
        server_sent_timestamp,
        one_time_extension_status,
        multi_variation_status,
        capping_status,
    })
}

pub fn encode_stored_default_disappearing_mode(
    mode: &DefaultDisappearingMode,
) -> CoreResult<Vec<u8>> {
    let mut out = BytesMut::new();
    out.extend_from_slice(STORED_DEFAULT_DISAPPEARING_MODE_MAGIC);
    out.put_u8(STORED_EVENT_RECORD_VERSION);
    out.put_u32(mode.duration_seconds);
    put_optional_u64(&mut out, mode.timestamp);
    Ok(out.to_vec())
}

pub fn decode_stored_default_disappearing_mode(
    value: &[u8],
) -> CoreResult<DefaultDisappearingMode> {
    validate_stored_record_len(value)?;
    let mut input = value;
    read_magic(
        &mut input,
        STORED_DEFAULT_DISAPPEARING_MODE_MAGIC,
        "default disappearing mode",
    )?;
    if input.remaining() < 4 {
        return Err(CoreError::Protocol(
            "stored default disappearing mode missing duration".to_owned(),
        ));
    }
    let duration_seconds = input.get_u32();
    let timestamp = read_optional_u64(&mut input)?;
    reject_trailing_stored_bytes(input, "default disappearing mode")?;
    Ok(DefaultDisappearingMode {
        duration_seconds,
        timestamp,
    })
}

pub fn encode_stored_account_settings_event(event: &AccountSettingsEvent) -> CoreResult<Vec<u8>> {
    let mut out = BytesMut::new();
    out.extend_from_slice(STORED_ACCOUNT_SETTINGS_EVENT_MAGIC);
    out.put_u8(STORED_EVENT_RECORD_VERSION);
    put_string(&mut out, &event.id)?;
    put_string_map(&mut out, &event.fields)?;
    Ok(out.to_vec())
}

pub fn decode_stored_account_settings_event(value: &[u8]) -> CoreResult<AccountSettingsEvent> {
    validate_stored_record_len(value)?;
    let mut input = value;
    read_magic(
        &mut input,
        STORED_ACCOUNT_SETTINGS_EVENT_MAGIC,
        "account settings",
    )?;
    let id = read_string(&mut input)?;
    let fields = read_string_map(&mut input)?;
    reject_trailing_stored_bytes(input, "account settings")?;
    Ok(AccountSettingsEvent { id, fields })
}

pub fn encode_stored_label_event(event: &LabelEvent) -> CoreResult<Vec<u8>> {
    let mut out = BytesMut::new();
    out.extend_from_slice(STORED_LABEL_EVENT_MAGIC);
    out.put_u8(STORED_EVENT_RECORD_VERSION);
    put_string(&mut out, &event.id)?;
    put_string_map(&mut out, &event.fields)?;
    Ok(out.to_vec())
}

pub fn decode_stored_label_event(value: &[u8]) -> CoreResult<LabelEvent> {
    validate_stored_record_len(value)?;
    let mut input = value;
    read_magic(&mut input, STORED_LABEL_EVENT_MAGIC, "label")?;
    let id = read_string(&mut input)?;
    let fields = read_string_map(&mut input)?;
    reject_trailing_stored_bytes(input, "label")?;
    Ok(LabelEvent { id, fields })
}

pub fn encode_stored_label_association_event(event: &LabelAssociationEvent) -> CoreResult<Vec<u8>> {
    let mut out = BytesMut::new();
    out.extend_from_slice(STORED_LABEL_ASSOCIATION_MAGIC);
    out.put_u8(STORED_EVENT_RECORD_VERSION);
    put_string(&mut out, &event.label_id)?;
    match &event.target {
        LabelAssociationTarget::Chat { chat_jid } => {
            out.put_u8(0);
            put_string(&mut out, chat_jid)?;
        }
        LabelAssociationTarget::Message {
            chat_jid,
            message_id,
        } => {
            out.put_u8(1);
            put_string(&mut out, chat_jid)?;
            put_string(&mut out, message_id)?;
        }
    }
    out.put_u8(u8::from(event.labeled));
    Ok(out.to_vec())
}

pub fn decode_stored_label_association_event(value: &[u8]) -> CoreResult<LabelAssociationEvent> {
    validate_stored_record_len(value)?;
    let mut input = value;
    read_magic(
        &mut input,
        STORED_LABEL_ASSOCIATION_MAGIC,
        "label association",
    )?;
    let label_id = read_string(&mut input)?;
    if input.remaining() < 1 {
        return Err(CoreError::Protocol(
            "stored label association missing target type".to_owned(),
        ));
    }
    let target = match input.get_u8() {
        0 => LabelAssociationTarget::Chat {
            chat_jid: read_string(&mut input)?,
        },
        1 => LabelAssociationTarget::Message {
            chat_jid: read_string(&mut input)?,
            message_id: read_string(&mut input)?,
        },
        target => {
            return Err(CoreError::Protocol(format!(
                "stored label association has invalid target type {target}"
            )));
        }
    };
    if input.remaining() < 1 {
        return Err(CoreError::Protocol(
            "stored label association missing labeled flag".to_owned(),
        ));
    }
    let labeled = match input.get_u8() {
        0 => false,
        1 => true,
        value => {
            return Err(CoreError::Protocol(format!(
                "stored label association has invalid labeled flag {value}"
            )));
        }
    };
    reject_trailing_stored_bytes(input, "label association")?;
    Ok(LabelAssociationEvent {
        label_id,
        target,
        labeled,
    })
}

pub fn encode_stored_quick_reply_event(event: &QuickReplyEvent) -> CoreResult<Vec<u8>> {
    let mut out = BytesMut::new();
    out.extend_from_slice(STORED_QUICK_REPLY_EVENT_MAGIC);
    out.put_u8(STORED_EVENT_RECORD_VERSION);
    put_string(&mut out, &event.id)?;
    put_string_map(&mut out, &event.fields)?;
    Ok(out.to_vec())
}

pub fn decode_stored_quick_reply_event(value: &[u8]) -> CoreResult<QuickReplyEvent> {
    validate_stored_record_len(value)?;
    let mut input = value;
    read_magic(&mut input, STORED_QUICK_REPLY_EVENT_MAGIC, "quick reply")?;
    let id = read_string(&mut input)?;
    let fields = read_string_map(&mut input)?;
    reject_trailing_stored_bytes(input, "quick reply")?;
    Ok(QuickReplyEvent { id, fields })
}

pub fn encode_stored_receipt_event(event: &ReceiptEvent) -> CoreResult<Vec<u8>> {
    let mut out = BytesMut::new();
    out.extend_from_slice(STORED_RECEIPT_EVENT_MAGIC);
    out.put_u8(STORED_EVENT_RECORD_VERSION);
    put_message_event_key(&mut out, &event.key)?;
    put_string(&mut out, &event.receipt_type)?;
    put_optional_string(&mut out, event.participant.as_deref())?;
    put_optional_u64(&mut out, event.timestamp);
    Ok(out.to_vec())
}

pub fn decode_stored_receipt_event(value: &[u8]) -> CoreResult<ReceiptEvent> {
    validate_stored_record_len(value)?;
    let mut input = value;
    read_magic(&mut input, STORED_RECEIPT_EVENT_MAGIC, "receipt")?;
    let key = read_message_event_key(&mut input)?;
    let receipt_type = read_string(&mut input)?;
    let participant = read_optional_string(&mut input)?;
    let timestamp = read_optional_u64(&mut input)?;
    reject_trailing_stored_bytes(input, "receipt")?;
    Ok(ReceiptEvent {
        key,
        receipt_type,
        participant,
        timestamp,
    })
}

pub fn encode_stored_reaction_event(event: &ReactionEvent) -> CoreResult<Vec<u8>> {
    let mut out = BytesMut::new();
    out.extend_from_slice(STORED_REACTION_EVENT_MAGIC);
    out.put_u8(STORED_EVENT_RECORD_VERSION);
    put_message_event_key(&mut out, &event.key)?;
    put_string(&mut out, &event.from_jid)?;
    put_optional_string(&mut out, event.text.as_deref())?;
    put_optional_u64(&mut out, event.timestamp);
    Ok(out.to_vec())
}

pub fn decode_stored_reaction_event(value: &[u8]) -> CoreResult<ReactionEvent> {
    validate_stored_record_len(value)?;
    let mut input = value;
    read_magic(&mut input, STORED_REACTION_EVENT_MAGIC, "reaction")?;
    let key = read_message_event_key(&mut input)?;
    let from_jid = read_string(&mut input)?;
    let text = read_optional_string(&mut input)?;
    let timestamp = read_optional_u64(&mut input)?;
    reject_trailing_stored_bytes(input, "reaction")?;
    Ok(ReactionEvent {
        key,
        from_jid,
        text,
        timestamp,
    })
}

pub fn encode_stored_media_retry_event(event: &MediaRetryEvent) -> CoreResult<Vec<u8>> {
    let mut out = BytesMut::new();
    out.extend_from_slice(STORED_MEDIA_RETRY_EVENT_MAGIC);
    out.put_u8(STORED_EVENT_RECORD_VERSION);
    put_message_event_key(&mut out, &event.key)?;
    out.put_u8(u8::from(event.from_me));
    put_optional_bytes(
        &mut out,
        event.encrypted_payload.as_ref().map(Bytes::as_ref),
    )?;
    put_optional_bytes(&mut out, event.iv.as_ref().map(Bytes::as_ref))?;
    put_optional_u16(&mut out, event.error_code);
    put_optional_string(&mut out, event.error_text.as_deref())?;
    put_optional_u16(&mut out, event.status_code);
    Ok(out.to_vec())
}

pub fn decode_stored_media_retry_event(value: &[u8]) -> CoreResult<MediaRetryEvent> {
    validate_stored_record_len(value)?;
    let mut input = value;
    read_magic(&mut input, STORED_MEDIA_RETRY_EVENT_MAGIC, "media retry")?;
    let key = read_message_event_key(&mut input)?;
    if input.remaining() < 1 {
        return Err(CoreError::Protocol(
            "stored media retry missing from_me flag".to_owned(),
        ));
    }
    let from_me = match input.get_u8() {
        0 => false,
        1 => true,
        value => {
            return Err(CoreError::Protocol(format!(
                "stored media retry has invalid from_me flag {value}"
            )));
        }
    };
    let encrypted_payload = read_optional_bytes(&mut input)?.map(Bytes::from);
    let iv = read_optional_bytes(&mut input)?.map(Bytes::from);
    let error_code = read_optional_u16(&mut input)?;
    let error_text = read_optional_string(&mut input)?;
    let status_code = read_optional_u16(&mut input)?;
    reject_trailing_stored_bytes(input, "media retry")?;
    Ok(MediaRetryEvent {
        key,
        from_me,
        encrypted_payload,
        iv,
        error_code,
        error_text,
        status_code,
    })
}

pub fn encode_stored_recent_sticker_event(event: &RecentStickerEvent) -> CoreResult<Vec<u8>> {
    let mut out = BytesMut::new();
    out.extend_from_slice(STORED_RECENT_STICKER_EVENT_MAGIC);
    out.put_u8(STORED_EVENT_RECORD_VERSION);
    put_string(&mut out, &event.id)?;
    put_optional_bytes(&mut out, event.file_sha256.as_ref().map(Bytes::as_ref))?;
    put_optional_bytes(&mut out, event.file_enc_sha256.as_ref().map(Bytes::as_ref))?;
    put_optional_bytes(&mut out, event.media_key.as_ref().map(Bytes::as_ref))?;
    put_string_map(&mut out, &event.fields)?;
    Ok(out.to_vec())
}

pub fn decode_stored_recent_sticker_event(value: &[u8]) -> CoreResult<RecentStickerEvent> {
    validate_stored_record_len(value)?;
    let mut input = value;
    read_magic(
        &mut input,
        STORED_RECENT_STICKER_EVENT_MAGIC,
        "recent sticker",
    )?;
    let id = read_string(&mut input)?;
    let file_sha256 = read_optional_bytes(&mut input)?.map(Bytes::from);
    let file_enc_sha256 = read_optional_bytes(&mut input)?.map(Bytes::from);
    let media_key = read_optional_bytes(&mut input)?.map(Bytes::from);
    let fields = read_string_map(&mut input)?;
    reject_trailing_stored_bytes(input, "recent sticker")?;
    Ok(RecentStickerEvent {
        id,
        file_sha256,
        file_enc_sha256,
        media_key,
        fields,
    })
}

pub fn encode_stored_call_event(event: &CallEvent) -> CoreResult<Vec<u8>> {
    let mut out = BytesMut::new();
    out.extend_from_slice(STORED_CALL_EVENT_MAGIC);
    out.put_u8(STORED_EVENT_RECORD_VERSION);
    put_string(&mut out, &event.id)?;
    put_string(&mut out, &event.from)?;
    put_string(&mut out, &event.event_type)?;
    put_optional_string(&mut out, event.call_id.as_deref())?;
    put_optional_string(&mut out, event.participant.as_deref())?;
    put_optional_u64(&mut out, event.timestamp);
    put_string_map(&mut out, &event.fields)?;
    Ok(out.to_vec())
}

pub fn decode_stored_call_event(value: &[u8]) -> CoreResult<CallEvent> {
    validate_stored_record_len(value)?;
    let mut input = value;
    read_magic(&mut input, STORED_CALL_EVENT_MAGIC, "call")?;
    let id = read_string(&mut input)?;
    let from = read_string(&mut input)?;
    let event_type = read_string(&mut input)?;
    let call_id = read_optional_string(&mut input)?;
    let participant = read_optional_string(&mut input)?;
    let timestamp = read_optional_u64(&mut input)?;
    let fields = read_string_map(&mut input)?;
    reject_trailing_stored_bytes(input, "call")?;
    Ok(CallEvent {
        id,
        from,
        event_type,
        call_id,
        participant,
        timestamp,
        fields,
    })
}

pub fn encode_stored_presence_event(event: &PresenceEvent) -> CoreResult<Vec<u8>> {
    let mut out = BytesMut::new();
    out.extend_from_slice(STORED_PRESENCE_EVENT_MAGIC);
    out.put_u8(STORED_EVENT_RECORD_VERSION);
    put_string(&mut out, &event.jid)?;
    put_string(&mut out, &event.presence_type)?;
    put_optional_string(&mut out, event.participant.as_deref())?;
    put_optional_u64(&mut out, event.timestamp);
    put_string_map(&mut out, &event.fields)?;
    Ok(out.to_vec())
}

pub fn decode_stored_presence_event(value: &[u8]) -> CoreResult<PresenceEvent> {
    validate_stored_record_len(value)?;
    let mut input = value;
    read_magic(&mut input, STORED_PRESENCE_EVENT_MAGIC, "presence")?;
    let jid = read_string(&mut input)?;
    let presence_type = read_string(&mut input)?;
    let participant = read_optional_string(&mut input)?;
    let timestamp = read_optional_u64(&mut input)?;
    let fields = read_string_map(&mut input)?;
    reject_trailing_stored_bytes(input, "presence")?;
    Ok(PresenceEvent {
        jid,
        presence_type,
        participant,
        timestamp,
        fields,
    })
}

fn encode_stored_jid_fields_record(
    magic: &[u8; 4],
    jid: &str,
    fields: &BTreeMap<String, String>,
) -> CoreResult<Vec<u8>> {
    let mut out = BytesMut::new();
    out.extend_from_slice(magic);
    out.put_u8(STORED_EVENT_RECORD_VERSION);
    put_string(&mut out, jid)?;
    put_string_map(&mut out, fields)?;
    Ok(out.to_vec())
}

fn decode_stored_jid_fields_record(
    value: &[u8],
    magic: &[u8; 4],
    label: &str,
) -> CoreResult<(String, BTreeMap<String, String>)> {
    validate_stored_record_len(value)?;
    let mut input = value;
    read_magic(&mut input, magic, label)?;
    let jid = read_string(&mut input)?;
    let fields = read_string_map(&mut input)?;
    reject_trailing_stored_bytes(input, label)?;
    Ok((jid, fields))
}

fn validate_stored_record_len(value: &[u8]) -> CoreResult<()> {
    if value.len() > MAX_STORED_EVENT_RECORD_BYTES {
        return Err(CoreError::Protocol(format!(
            "stored message record exceeds {} bytes",
            MAX_STORED_EVENT_RECORD_BYTES
        )));
    }
    Ok(())
}

fn put_message_event_key(out: &mut BytesMut, key: &MessageEventKey) -> CoreResult<()> {
    put_string(out, &key.remote_jid)?;
    put_string(out, &key.id)?;
    put_optional_string(out, key.participant.as_deref())
}

fn read_message_event_key(input: &mut &[u8]) -> CoreResult<MessageEventKey> {
    let remote_jid = read_string(input)?;
    let id = read_string(input)?;
    let participant = read_optional_string(input)?;
    Ok(MessageEventKey {
        remote_jid,
        id,
        participant,
    })
}

fn put_optional_u64(out: &mut BytesMut, value: Option<u64>) {
    match value {
        Some(value) => {
            out.put_u8(1);
            out.put_u64(value);
        }
        None => out.put_u8(0),
    }
}

fn read_optional_u64(input: &mut &[u8]) -> CoreResult<Option<u64>> {
    if input.remaining() < 1 {
        return Err(CoreError::Protocol(
            "stored message record missing optional u64 tag".to_owned(),
        ));
    }
    match input.get_u8() {
        0 => Ok(None),
        1 => {
            if input.remaining() < 8 {
                return Err(CoreError::Protocol(
                    "stored message record has truncated u64".to_owned(),
                ));
            }
            Ok(Some(input.get_u64()))
        }
        tag => Err(CoreError::Protocol(format!(
            "stored message record has invalid optional u64 tag {tag}"
        ))),
    }
}

fn put_optional_u16(out: &mut BytesMut, value: Option<u16>) {
    match value {
        Some(value) => {
            out.put_u8(1);
            out.put_u16(value);
        }
        None => out.put_u8(0),
    }
}

fn read_optional_u16(input: &mut &[u8]) -> CoreResult<Option<u16>> {
    if input.remaining() < 1 {
        return Err(CoreError::Protocol(
            "stored event record missing optional u16 tag".to_owned(),
        ));
    }
    match input.get_u8() {
        0 => Ok(None),
        1 => {
            if input.remaining() < 2 {
                return Err(CoreError::Protocol(
                    "stored event record has truncated u16".to_owned(),
                ));
            }
            Ok(Some(input.get_u16()))
        }
        tag => Err(CoreError::Protocol(format!(
            "stored event record has invalid optional u16 tag {tag}"
        ))),
    }
}

fn put_optional_string(out: &mut BytesMut, value: Option<&str>) -> CoreResult<()> {
    match value {
        Some(value) => {
            out.put_u8(1);
            put_string(out, value)
        }
        None => {
            out.put_u8(0);
            Ok(())
        }
    }
}

fn read_optional_string(input: &mut &[u8]) -> CoreResult<Option<String>> {
    if input.remaining() < 1 {
        return Err(CoreError::Protocol(
            "stored message record missing optional string tag".to_owned(),
        ));
    }
    match input.get_u8() {
        0 => Ok(None),
        1 => read_string(input).map(Some),
        tag => Err(CoreError::Protocol(format!(
            "stored message record has invalid optional string tag {tag}"
        ))),
    }
}

fn put_optional_bytes(out: &mut BytesMut, value: Option<&[u8]>) -> CoreResult<()> {
    match value {
        Some(value) => {
            out.put_u8(1);
            put_len_prefixed_bytes(out, value, MAX_STORED_EVENT_PAYLOAD_BYTES)
        }
        None => {
            out.put_u8(0);
            Ok(())
        }
    }
}

fn read_optional_bytes(input: &mut &[u8]) -> CoreResult<Option<Vec<u8>>> {
    if input.remaining() < 1 {
        return Err(CoreError::Protocol(
            "stored message record missing optional bytes tag".to_owned(),
        ));
    }
    match input.get_u8() {
        0 => Ok(None),
        1 => read_len_prefixed_bytes(input, MAX_STORED_EVENT_PAYLOAD_BYTES).map(Some),
        tag => Err(CoreError::Protocol(format!(
            "stored message record has invalid optional bytes tag {tag}"
        ))),
    }
}

fn put_string_map(out: &mut BytesMut, fields: &BTreeMap<String, String>) -> CoreResult<()> {
    if fields.len() > MAX_STORED_EVENT_FIELD_COUNT {
        return Err(CoreError::Protocol(format!(
            "stored message record has too many fields: {}",
            fields.len()
        )));
    }
    out.put_u32(u32::try_from(fields.len()).map_err(|_| {
        CoreError::Protocol("stored message field count does not fit u32".to_owned())
    })?);
    for (key, value) in fields {
        put_string(out, key)?;
        put_string(out, value)?;
    }
    Ok(())
}

fn read_string_map(input: &mut &[u8]) -> CoreResult<BTreeMap<String, String>> {
    if input.remaining() < 4 {
        return Err(CoreError::Protocol(
            "stored message record missing field count".to_owned(),
        ));
    }
    let count = input.get_u32() as usize;
    if count > MAX_STORED_EVENT_FIELD_COUNT {
        return Err(CoreError::Protocol(format!(
            "stored message record has too many fields: {count}"
        )));
    }
    let mut fields = BTreeMap::new();
    for _ in 0..count {
        let key = read_string(input)?;
        let value = read_string(input)?;
        fields.insert(key, value);
    }
    Ok(fields)
}

fn put_string(out: &mut BytesMut, value: &str) -> CoreResult<()> {
    put_bytes(out, value.as_bytes())
}

fn read_string(input: &mut &[u8]) -> CoreResult<String> {
    let value = read_bytes(input)?;
    String::from_utf8(value)
        .map_err(|_| CoreError::Protocol("stored message record contains invalid UTF-8".to_owned()))
}

fn put_bytes(out: &mut BytesMut, value: &[u8]) -> CoreResult<()> {
    put_len_prefixed_bytes(out, value, MAX_STORED_EVENT_STRING_BYTES)
}

fn read_bytes(input: &mut &[u8]) -> CoreResult<Vec<u8>> {
    read_len_prefixed_bytes(input, MAX_STORED_EVENT_STRING_BYTES)
}

fn put_len_prefixed_bytes(out: &mut BytesMut, value: &[u8], max_len: usize) -> CoreResult<()> {
    if value.len() > max_len {
        return Err(CoreError::Protocol(format!(
            "stored message record field exceeds {max_len} bytes"
        )));
    }
    out.put_u32(u32::try_from(value.len()).map_err(|_| {
        CoreError::Protocol("stored message field length does not fit u32".to_owned())
    })?);
    out.extend_from_slice(value);
    Ok(())
}

fn read_len_prefixed_bytes(input: &mut &[u8], max_len: usize) -> CoreResult<Vec<u8>> {
    if input.remaining() < 4 {
        return Err(CoreError::Protocol(
            "stored message record missing byte length".to_owned(),
        ));
    }
    let len = input.get_u32() as usize;
    if len > max_len {
        return Err(CoreError::Protocol(format!(
            "stored message record field exceeds {max_len} bytes"
        )));
    }
    if input.remaining() < len {
        return Err(CoreError::Protocol(
            "stored message record has truncated bytes".to_owned(),
        ));
    }
    let value = input[..len].to_vec();
    input.advance(len);
    Ok(value)
}

fn read_magic(input: &mut &[u8], expected: &[u8; 4], label: &str) -> CoreResult<()> {
    if input.remaining() < 5 {
        return Err(CoreError::Protocol(format!(
            "stored {label} record is truncated"
        )));
    }
    if &input[..4] != expected {
        return Err(CoreError::Protocol(format!(
            "stored {label} record has invalid magic"
        )));
    }
    input.advance(4);
    let version = input.get_u8();
    if version != STORED_EVENT_RECORD_VERSION {
        return Err(CoreError::Protocol(format!(
            "stored {label} record version {version} is not supported"
        )));
    }
    Ok(())
}

fn reject_trailing_stored_bytes(input: &[u8], label: &str) -> CoreResult<()> {
    if input.is_empty() {
        return Ok(());
    }
    Err(CoreError::Protocol(format!(
        "stored {label} record has {} trailing bytes",
        input.len()
    )))
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Event {
    ConnectionUpdate(ConnectionState),
    Frame(Bytes),
    RawNode(BinaryNode),
    Node(BinaryNode),
    Qr(String),
    CredentialsUpdated,
    Batch(Box<EventBatch>),
    HistorySet(HistorySetEvent),
    MessagesUpsert(Vec<MessageEvent>),
    MessagesUpdate(Vec<MessageUpdate>),
    MessagesDelete(Vec<MessageEventKey>),
    ChatsUpsert(Vec<ChatEvent>),
    ChatsUpdate(Vec<ChatEvent>),
    ChatsDelete(Vec<String>),
    ContactsUpsert(Vec<ContactEvent>),
    ContactsUpdate(Vec<ContactEvent>),
    ContactsDelete(Vec<String>),
    LabelsEdit(Vec<LabelEvent>),
    LabelsAssociation(Vec<LabelAssociationEvent>),
    QuickRepliesUpdate(Vec<QuickReplyEvent>),
    GroupsUpdate(Vec<GroupUpdateEvent>),
    ReceiptsUpdate(Vec<ReceiptEvent>),
    ReactionsUpdate(Vec<ReactionEvent>),
    MediaRetry(Vec<MediaRetryEvent>),
    RecentStickersUpdate(Vec<RecentStickerEvent>),
    #[cfg(feature = "noise")]
    MediaRetryProcessed(crate::MediaRetryBatchOutcome),
    LidMappingUpdate(Vec<LidMappingEvent>),
    AccountSettingsUpdate(Vec<AccountSettingsEvent>),
    BusinessNotificationUpdate(Vec<BusinessNotificationEvent>),
    NewsletterReactionUpdate(Vec<NewsletterReactionEvent>),
    NewsletterViewUpdate(Vec<NewsletterViewEvent>),
    NewsletterParticipantsUpdate(Vec<NewsletterParticipantUpdateEvent>),
    NewsletterSettingsUpdate(Vec<NewsletterSettingsUpdateEvent>),
    ReachoutTimelockUpdate(ReachoutTimelockState),
    MessageCappingUpdate(MessageCappingInfo),
    DefaultDisappearingModeUpdate(DefaultDisappearingMode),
    BlocklistUpdate(Vec<BlocklistUpdateEvent>),
    ServerSyncCollections(Vec<AppStateCollection>),
    CallsUpdate(Vec<CallEvent>),
    PresenceUpdate(Vec<PresenceEvent>),
}

#[derive(Clone)]
pub struct EventHub {
    tx: broadcast::Sender<Event>,
}

impl EventHub {
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        let (tx, _) = broadcast::channel(capacity);
        Self { tx }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.tx.subscribe()
    }

    pub fn emit(&self, event: Event) {
        let _ = self.tx.send(event);
    }

    pub fn emit_batch(&self, batch: EventBatch) {
        if !batch.is_empty() {
            self.emit(Event::Batch(Box::new(batch)));
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EventBufferConfig {
    pub max_pending_items: usize,
}

impl Default for EventBufferConfig {
    fn default() -> Self {
        Self {
            max_pending_items: 4096,
        }
    }
}

#[derive(Clone, Debug)]
pub struct EventBuffer {
    config: EventBufferConfig,
    history: Option<HistorySetEvent>,
    messages_upsert: BTreeMap<MessageEventKey, MessageEvent>,
    messages_update: BTreeMap<MessageEventKey, MessageUpdate>,
    messages_delete: BTreeSet<MessageEventKey>,
    chats_upsert: BTreeMap<String, ChatEvent>,
    chats_update: BTreeMap<String, ChatEvent>,
    chats_delete: BTreeSet<String>,
    contacts_upsert: BTreeMap<String, ContactEvent>,
    contacts_update: BTreeMap<String, ContactEvent>,
    contacts_delete: BTreeSet<String>,
    labels_edit: BTreeMap<String, LabelEvent>,
    labels_association: BTreeMap<LabelAssociationBufferKey, LabelAssociationEvent>,
    quick_replies_update: BTreeMap<String, QuickReplyEvent>,
    groups_update: BTreeMap<String, GroupUpdateEvent>,
    receipts_update: BTreeMap<ReceiptBufferKey, ReceiptEvent>,
    reactions_update: BTreeMap<ReactionBufferKey, ReactionEvent>,
    media_retry: BTreeMap<MessageEventKey, MediaRetryEvent>,
    recent_stickers: BTreeMap<String, RecentStickerEvent>,
    account_settings: BTreeMap<String, AccountSettingsEvent>,
    business_notifications: BTreeMap<String, BusinessNotificationEvent>,
    calls_update: BTreeMap<String, CallEvent>,
    presence_update: BTreeMap<PresenceBufferKey, PresenceEvent>,
    immediate: Vec<Event>,
}

impl EventBuffer {
    #[must_use]
    pub fn new(config: EventBufferConfig) -> Self {
        Self {
            config,
            history: None,
            messages_upsert: BTreeMap::new(),
            messages_update: BTreeMap::new(),
            messages_delete: BTreeSet::new(),
            chats_upsert: BTreeMap::new(),
            chats_update: BTreeMap::new(),
            chats_delete: BTreeSet::new(),
            contacts_upsert: BTreeMap::new(),
            contacts_update: BTreeMap::new(),
            contacts_delete: BTreeSet::new(),
            labels_edit: BTreeMap::new(),
            labels_association: BTreeMap::new(),
            quick_replies_update: BTreeMap::new(),
            groups_update: BTreeMap::new(),
            receipts_update: BTreeMap::new(),
            reactions_update: BTreeMap::new(),
            media_retry: BTreeMap::new(),
            recent_stickers: BTreeMap::new(),
            account_settings: BTreeMap::new(),
            business_notifications: BTreeMap::new(),
            calls_update: BTreeMap::new(),
            presence_update: BTreeMap::new(),
            immediate: Vec::new(),
        }
    }

    #[must_use]
    pub fn config(&self) -> EventBufferConfig {
        self.config
    }

    #[must_use]
    pub fn pending_items(&self) -> usize {
        self.history
            .as_ref()
            .map_or(0, HistorySetEvent::pending_items)
            + self.messages_upsert.len()
            + self.messages_update.len()
            + self.messages_delete.len()
            + self.chats_upsert.len()
            + self.chats_update.len()
            + self.chats_delete.len()
            + self.contacts_upsert.len()
            + self.contacts_update.len()
            + self.contacts_delete.len()
            + self.labels_edit.len()
            + self.labels_association.len()
            + self.quick_replies_update.len()
            + self.groups_update.len()
            + self.receipts_update.len()
            + self.reactions_update.len()
            + self.media_retry.len()
            + self.recent_stickers.len()
            + self.account_settings.len()
            + self.business_notifications.len()
            + self.calls_update.len()
            + self.presence_update.len()
            + self.immediate.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pending_items() == 0
    }

    pub fn push(&mut self, event: Event) -> CoreResult<()> {
        let snapshot = self.clone();
        self.apply(event);
        if self.pending_items() > self.config.max_pending_items {
            *self = snapshot;
            return Err(CoreError::Protocol(format!(
                "event buffer limit exceeded: {} pending items exceeds {}",
                self.pending_items(),
                self.config.max_pending_items
            )));
        }
        Ok(())
    }

    pub fn flush(&mut self) -> Option<EventBatch> {
        let batch = EventBatch {
            history: self.history.take(),
            messages_upsert: drain_map_values(&mut self.messages_upsert),
            messages_update: drain_map_values(&mut self.messages_update),
            messages_delete: drain_set_values(&mut self.messages_delete),
            chats_upsert: drain_map_values(&mut self.chats_upsert),
            chats_update: drain_map_values(&mut self.chats_update),
            chats_delete: drain_set_values(&mut self.chats_delete),
            contacts_upsert: drain_map_values(&mut self.contacts_upsert),
            contacts_update: drain_map_values(&mut self.contacts_update),
            contacts_delete: drain_set_values(&mut self.contacts_delete),
            labels_edit: drain_map_values(&mut self.labels_edit),
            labels_association: drain_map_values(&mut self.labels_association),
            quick_replies_update: drain_map_values(&mut self.quick_replies_update),
            groups_update: drain_map_values(&mut self.groups_update),
            receipts_update: drain_map_values(&mut self.receipts_update),
            reactions_update: drain_map_values(&mut self.reactions_update),
            media_retry: drain_map_values(&mut self.media_retry),
            recent_stickers: drain_map_values(&mut self.recent_stickers),
            account_settings: drain_map_values(&mut self.account_settings),
            business_notifications: drain_map_values(&mut self.business_notifications),
            calls_update: drain_map_values(&mut self.calls_update),
            presence_update: drain_map_values(&mut self.presence_update),
        };

        if batch.is_empty() { None } else { Some(batch) }
    }

    pub fn drain_events(&mut self) -> Vec<Event> {
        let mut events = std::mem::take(&mut self.immediate);
        if let Some(batch) = self.flush() {
            events.push(Event::Batch(Box::new(batch)));
        }
        events
    }

    pub fn flush_into(&mut self, hub: &EventHub) {
        for event in self.drain_events() {
            hub.emit(event);
        }
    }

    fn apply(&mut self, event: Event) {
        match event {
            Event::Batch(batch) => self.apply_batch(*batch),
            Event::HistorySet(history) => {
                self.history = Some(history);
            }
            Event::MessagesUpsert(messages) => {
                for message in messages {
                    self.messages_delete.remove(&message.key);
                    self.messages_update.remove(&message.key);
                    self.messages_upsert.insert(message.key.clone(), message);
                }
            }
            Event::MessagesUpdate(updates) => {
                for update in updates {
                    if let Some(message) = self.messages_upsert.get_mut(&update.key) {
                        merge_fields(&mut message.fields, update.fields);
                        if update.timestamp.is_some() {
                            message.timestamp = update.timestamp;
                        }
                    } else if !self.messages_delete.contains(&update.key) {
                        merge_message_update(&mut self.messages_update, update);
                    }
                }
            }
            Event::MessagesDelete(keys) => {
                for key in keys {
                    self.messages_upsert.remove(&key);
                    self.messages_update.remove(&key);
                    self.messages_delete.insert(key);
                }
            }
            Event::ChatsUpsert(chats) => {
                for chat in chats {
                    self.chats_delete.remove(&chat.jid);
                    self.chats_update.remove(&chat.jid);
                    self.chats_upsert.insert(chat.jid.clone(), chat);
                }
            }
            Event::ChatsUpdate(chats) => {
                for chat in chats {
                    if let Some(existing) = self.chats_upsert.get_mut(&chat.jid) {
                        merge_fields(&mut existing.fields, chat.fields);
                    } else if !self.chats_delete.contains(&chat.jid) {
                        merge_chat_event(&mut self.chats_update, chat);
                    }
                }
            }
            Event::ChatsDelete(jids) => {
                for jid in jids {
                    self.chats_upsert.remove(&jid);
                    self.chats_update.remove(&jid);
                    self.chats_delete.insert(jid);
                }
            }
            Event::ContactsUpsert(contacts) => {
                for contact in contacts {
                    self.contacts_delete.remove(&contact.jid);
                    self.contacts_update.remove(&contact.jid);
                    self.contacts_upsert.insert(contact.jid.clone(), contact);
                }
            }
            Event::ContactsUpdate(contacts) => {
                for contact in contacts {
                    if let Some(existing) = self.contacts_upsert.get_mut(&contact.jid) {
                        merge_fields(&mut existing.fields, contact.fields);
                    } else if !self.contacts_delete.contains(&contact.jid) {
                        merge_contact_event(&mut self.contacts_update, contact);
                    }
                }
            }
            Event::ContactsDelete(jids) => {
                for jid in jids {
                    self.contacts_upsert.remove(&jid);
                    self.contacts_update.remove(&jid);
                    self.contacts_delete.insert(jid);
                }
            }
            Event::LabelsEdit(labels) => {
                for label in labels {
                    merge_label_event(&mut self.labels_edit, label);
                }
            }
            Event::LabelsAssociation(associations) => {
                for association in associations {
                    self.labels_association
                        .insert(association.buffer_key(), association);
                }
            }
            Event::QuickRepliesUpdate(replies) => {
                for reply in replies {
                    merge_quick_reply_event(&mut self.quick_replies_update, reply);
                }
            }
            Event::GroupsUpdate(groups) => {
                for group in groups {
                    merge_group_event(&mut self.groups_update, group);
                }
            }
            Event::ReceiptsUpdate(receipts) => {
                for receipt in receipts {
                    self.receipts_update.insert(receipt.buffer_key(), receipt);
                }
            }
            Event::ReactionsUpdate(reactions) => {
                for reaction in reactions {
                    self.reactions_update
                        .insert(reaction.buffer_key(), reaction);
                }
            }
            Event::MediaRetry(updates) => {
                for update in updates {
                    self.media_retry.insert(update.key.clone(), update);
                }
            }
            Event::RecentStickersUpdate(stickers) => {
                for sticker in stickers {
                    merge_recent_sticker_event(&mut self.recent_stickers, sticker);
                }
            }
            Event::AccountSettingsUpdate(settings) => {
                for setting in settings {
                    merge_account_settings_event(&mut self.account_settings, setting);
                }
            }
            Event::BusinessNotificationUpdate(updates) => {
                for update in updates {
                    merge_business_notification_event(&mut self.business_notifications, update);
                }
            }
            Event::CallsUpdate(calls) => {
                for call in calls {
                    merge_call_event(&mut self.calls_update, call);
                }
            }
            Event::PresenceUpdate(updates) => {
                for update in updates {
                    self.presence_update.insert(update.buffer_key(), update);
                }
            }
            event => self.immediate.push(event),
        }
    }

    fn apply_batch(&mut self, batch: EventBatch) {
        if let Some(history) = batch.history {
            self.history = Some(history);
        }
        self.apply(Event::MessagesUpsert(batch.messages_upsert));
        self.apply(Event::MessagesUpdate(batch.messages_update));
        self.apply(Event::MessagesDelete(batch.messages_delete));
        self.apply(Event::ChatsUpsert(batch.chats_upsert));
        self.apply(Event::ChatsUpdate(batch.chats_update));
        self.apply(Event::ChatsDelete(batch.chats_delete));
        self.apply(Event::ContactsUpsert(batch.contacts_upsert));
        self.apply(Event::ContactsUpdate(batch.contacts_update));
        self.apply(Event::ContactsDelete(batch.contacts_delete));
        self.apply(Event::LabelsEdit(batch.labels_edit));
        self.apply(Event::LabelsAssociation(batch.labels_association));
        self.apply(Event::QuickRepliesUpdate(batch.quick_replies_update));
        self.apply(Event::GroupsUpdate(batch.groups_update));
        self.apply(Event::ReceiptsUpdate(batch.receipts_update));
        self.apply(Event::ReactionsUpdate(batch.reactions_update));
        self.apply(Event::MediaRetry(batch.media_retry));
        self.apply(Event::RecentStickersUpdate(batch.recent_stickers));
        self.apply(Event::AccountSettingsUpdate(batch.account_settings));
        self.apply(Event::BusinessNotificationUpdate(
            batch.business_notifications,
        ));
        self.apply(Event::CallsUpdate(batch.calls_update));
        self.apply(Event::PresenceUpdate(batch.presence_update));
    }
}

fn merge_message_update(
    updates: &mut BTreeMap<MessageEventKey, MessageUpdate>,
    update: MessageUpdate,
) {
    updates
        .entry(update.key.clone())
        .and_modify(|existing| {
            merge_fields(&mut existing.fields, update.fields.clone());
            if update.timestamp.is_some() {
                existing.timestamp = update.timestamp;
            }
        })
        .or_insert(update);
}

fn merge_chat_event(events: &mut BTreeMap<String, ChatEvent>, event: ChatEvent) {
    events
        .entry(event.jid.clone())
        .and_modify(|existing| merge_fields(&mut existing.fields, event.fields.clone()))
        .or_insert(event);
}

fn merge_contact_event(events: &mut BTreeMap<String, ContactEvent>, event: ContactEvent) {
    events
        .entry(event.jid.clone())
        .and_modify(|existing| merge_fields(&mut existing.fields, event.fields.clone()))
        .or_insert(event);
}

fn merge_label_event(events: &mut BTreeMap<String, LabelEvent>, event: LabelEvent) {
    events
        .entry(event.id.clone())
        .and_modify(|existing| merge_fields(&mut existing.fields, event.fields.clone()))
        .or_insert(event);
}

fn merge_quick_reply_event(events: &mut BTreeMap<String, QuickReplyEvent>, event: QuickReplyEvent) {
    events
        .entry(event.id.clone())
        .and_modify(|existing| merge_fields(&mut existing.fields, event.fields.clone()))
        .or_insert(event);
}

fn merge_group_event(events: &mut BTreeMap<String, GroupUpdateEvent>, event: GroupUpdateEvent) {
    events
        .entry(event.jid.clone())
        .and_modify(|existing| merge_fields(&mut existing.fields, event.fields.clone()))
        .or_insert(event);
}

fn merge_recent_sticker_event(
    events: &mut BTreeMap<String, RecentStickerEvent>,
    event: RecentStickerEvent,
) {
    events
        .entry(event.id.clone())
        .and_modify(|existing| {
            merge_fields(&mut existing.fields, event.fields.clone());
            if event.file_sha256.is_some() {
                existing.file_sha256 = event.file_sha256.clone();
            }
            if event.file_enc_sha256.is_some() {
                existing.file_enc_sha256 = event.file_enc_sha256.clone();
            }
            if event.media_key.is_some() {
                existing.media_key = event.media_key.clone();
            }
        })
        .or_insert(event);
}

fn merge_account_settings_event(
    events: &mut BTreeMap<String, AccountSettingsEvent>,
    event: AccountSettingsEvent,
) {
    events
        .entry(event.id.clone())
        .and_modify(|existing| merge_fields(&mut existing.fields, event.fields.clone()))
        .or_insert(event);
}

fn merge_business_notification_event(
    events: &mut BTreeMap<String, BusinessNotificationEvent>,
    event: BusinessNotificationEvent,
) {
    events
        .entry(business_notification_event_store_key(&event))
        .and_modify(|existing| merge_fields(&mut existing.fields, event.fields.clone()))
        .or_insert(event);
}

fn merge_call_event(events: &mut BTreeMap<String, CallEvent>, event: CallEvent) {
    events
        .entry(event.buffer_key())
        .and_modify(|existing| {
            merge_fields(&mut existing.fields, event.fields.clone());
            if event.participant.is_some() {
                existing.participant = event.participant.clone();
            }
            if event.timestamp.is_some() {
                existing.timestamp = event.timestamp;
            }
        })
        .or_insert(event);
}

fn merge_fields(target: &mut BTreeMap<String, String>, update: BTreeMap<String, String>) {
    for (key, value) in update {
        target.insert(key, value);
    }
}

fn drain_map_values<K: Ord, V>(map: &mut BTreeMap<K, V>) -> Vec<V> {
    std::mem::take(map).into_values().collect()
}

fn drain_set_values<T: Ord>(set: &mut BTreeSet<T>) -> Vec<T> {
    std::mem::take(set).into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message_key(id: &str) -> MessageEventKey {
        MessageEventKey::new("123@s.whatsapp.net", id, None)
    }

    #[test]
    fn stored_message_event_round_trips() {
        let key = MessageEventKey::new("123@g.us", "m1", Some("456@s.whatsapp.net".to_owned()));
        let event = MessageEvent::new(key.clone())
            .with_timestamp(1_700_000_000)
            .with_payload(Bytes::from_static(b"proto"))
            .with_field("source", "invite_accept")
            .with_field("stub_type", "group_participant_add");

        let encoded = encode_stored_message_event(&event).unwrap();
        assert_eq!(decode_stored_message_event(&encoded).unwrap(), event);
        assert_eq!(
            message_event_store_key(&key),
            "123@g.us|m1|456@s.whatsapp.net"
        );
    }

    #[test]
    fn stored_message_update_round_trips() {
        let update = MessageUpdate::new(message_key("m1"))
            .with_timestamp(1_700_000_001)
            .with_field("invite_status", "accepted")
            .with_field("invite_expiration", "0");

        let encoded = encode_stored_message_update(&update).unwrap();
        assert_eq!(decode_stored_message_update(&encoded).unwrap(), update);
    }

    #[test]
    fn stored_chat_contact_and_group_events_round_trip() {
        let chat = ChatEvent::new("123@s.whatsapp.net")
            .with_field("display_name", "Alice")
            .with_field("unread_count", "2");
        let contact = ContactEvent::new("123@s.whatsapp.net")
            .with_field("name", "Alice")
            .with_field("notify", "A");
        let group = GroupUpdateEvent::new("456@g.us")
            .with_field("subject", "Team")
            .with_field("announce", "false");

        let encoded_chat = encode_stored_chat_event(&chat).unwrap();
        let encoded_contact = encode_stored_contact_event(&contact).unwrap();
        let encoded_group = encode_stored_group_event(&group).unwrap();

        assert_eq!(decode_stored_chat_event(&encoded_chat).unwrap(), chat);
        assert_eq!(
            decode_stored_contact_event(&encoded_contact).unwrap(),
            contact
        );
        assert_eq!(decode_stored_group_event(&encoded_group).unwrap(), group);
    }

    #[test]
    fn stored_presence_event_round_trips() {
        let event = PresenceEvent::new("123@g.us", "composing")
            .with_participant("456@s.whatsapp.net")
            .with_timestamp(1_700_000_008)
            .with_field("last", "1700000000")
            .with_field("child_composing_media", "audio");

        let encoded = encode_stored_presence_event(&event).unwrap();
        assert_eq!(decode_stored_presence_event(&encoded).unwrap(), event);
        assert_eq!(
            presence_event_store_key(&event),
            "123@g.us|456@s.whatsapp.net"
        );
    }

    #[test]
    fn stored_label_association_and_quick_reply_events_round_trip() {
        let label = LabelEvent::new("7")
            .with_field("name", "Important")
            .with_field("color", "4");
        let association = LabelAssociationEvent::message("7", "123@s.whatsapp.net", "msg-1", false);
        let quick_reply = QuickReplyEvent::new("qr-1")
            .with_field("shortcut", "/hi")
            .with_field("message", "hello");

        let encoded_label = encode_stored_label_event(&label).unwrap();
        let encoded_association = encode_stored_label_association_event(&association).unwrap();
        let encoded_quick_reply = encode_stored_quick_reply_event(&quick_reply).unwrap();

        assert_eq!(decode_stored_label_event(&encoded_label).unwrap(), label);
        assert_eq!(
            decode_stored_label_association_event(&encoded_association).unwrap(),
            association
        );
        assert_eq!(
            decode_stored_quick_reply_event(&encoded_quick_reply).unwrap(),
            quick_reply
        );
        assert_eq!(
            label_association_store_key(&association),
            "7|message|123@s.whatsapp.net|msg-1"
        );
    }

    #[test]
    fn stored_receipt_and_reaction_events_round_trip() {
        let key = MessageEventKey::new(
            "123@s.whatsapp.net",
            "m1",
            Some("456@s.whatsapp.net".to_owned()),
        );
        let receipt = ReceiptEvent::new(key.clone(), "read")
            .with_participant("789@s.whatsapp.net")
            .with_timestamp(1_700_000_002);
        let reaction = ReactionEvent::new(key, "789@s.whatsapp.net")
            .with_text("+")
            .with_timestamp(1_700_000_003);

        let encoded_receipt = encode_stored_receipt_event(&receipt).unwrap();
        let encoded_reaction = encode_stored_reaction_event(&reaction).unwrap();

        assert_eq!(
            decode_stored_receipt_event(&encoded_receipt).unwrap(),
            receipt
        );
        assert_eq!(
            decode_stored_reaction_event(&encoded_reaction).unwrap(),
            reaction
        );
        assert_eq!(
            receipt_event_store_key(&receipt),
            "123@s.whatsapp.net|m1|456@s.whatsapp.net|read|789@s.whatsapp.net"
        );
        assert_eq!(
            reaction_event_store_key(&reaction),
            "123@s.whatsapp.net|m1|456@s.whatsapp.net|789@s.whatsapp.net"
        );
    }

    #[test]
    fn stored_media_retry_event_round_trips() {
        let key = MessageEventKey::new(
            "123@s.whatsapp.net",
            "m1",
            Some("456@s.whatsapp.net".to_owned()),
        );
        let event = MediaRetryEvent::new(key, false)
            .with_encrypted_payload(Bytes::from_static(b"payload"), Bytes::from_static(b"iv"))
            .with_error(2, Some("missing".to_owned()), 404);

        let encoded = encode_stored_media_retry_event(&event).unwrap();
        assert_eq!(decode_stored_media_retry_event(&encoded).unwrap(), event);
        assert_eq!(
            media_retry_event_store_key(&event),
            "123@s.whatsapp.net|m1|456@s.whatsapp.net"
        );
    }

    #[test]
    fn stored_recent_sticker_event_round_trips() {
        let event = RecentStickerEvent::new("file_sha256:010203")
            .with_file_sha256(Bytes::from_static(&[1, 2, 3]))
            .with_file_enc_sha256(Bytes::from_static(&[4, 5, 6]))
            .with_media_key(Bytes::from_static(&[7; 32]))
            .with_field("mimetype", "image/webp")
            .with_field("direct_path", "/sticker");

        let encoded = encode_stored_recent_sticker_event(&event).unwrap();
        assert_eq!(decode_stored_recent_sticker_event(&encoded).unwrap(), event);
        assert_eq!(recent_sticker_event_store_key(&event), "file_sha256:010203");

        let mut trailing = encoded;
        trailing.push(0);
        assert!(decode_stored_recent_sticker_event(&trailing).is_err());
    }

    #[test]
    fn stored_account_settings_event_round_trips() {
        let event = AccountSettingsEvent::new("history_sync")
            .with_field("media_visibility", "ON")
            .with_field("thread_id_user_secret_present", "true");

        let encoded = encode_stored_account_settings_event(&event).unwrap();
        assert_eq!(
            decode_stored_account_settings_event(&encoded).unwrap(),
            event
        );
        assert_eq!(account_settings_event_store_key(&event), "history_sync");

        let mut trailing = encoded;
        trailing.push(0);
        assert!(decode_stored_account_settings_event(&trailing).is_err());
    }

    #[test]
    fn stored_call_event_round_trips() {
        let event = CallEvent::new("call-stanza-1", "123@s.whatsapp.net", "offer")
            .with_call_id("call-1")
            .with_participant("456@s.whatsapp.net")
            .with_timestamp(1_700_000_007)
            .with_field("call-creator", "123@s.whatsapp.net")
            .with_field("child_audio", "true");

        let encoded = encode_stored_call_event(&event).unwrap();
        assert_eq!(decode_stored_call_event(&encoded).unwrap(), event);
        assert_eq!(
            call_event_store_key(&event),
            "123@s.whatsapp.net|call-stanza-1|offer|call-1"
        );
    }

    #[test]
    fn stored_business_notification_event_round_trips() {
        let event =
            BusinessNotificationEvent::new("server@s.whatsapp.net", "biz-1", "product_catalog")
                .with_field("attr_version", "1")
                .with_field("child_product_id", "sku-1");

        let encoded = encode_stored_business_notification_event(&event).unwrap();
        assert_eq!(
            decode_stored_business_notification_event(&encoded).unwrap(),
            event
        );
        assert_eq!(
            business_notification_event_store_key(&event),
            "server@s.whatsapp.net|biz-1|product_catalog"
        );

        let mut trailing = encoded;
        trailing.push(0);
        assert!(decode_stored_business_notification_event(&trailing).is_err());
    }

    #[test]
    fn stored_newsletter_events_round_trip() {
        let reaction = NewsletterReactionEvent::new("abc@newsletter", "server-1")
            .with_code("+")
            .with_count(4);
        let view = NewsletterViewEvent::new("abc@newsletter", "server-1", 42);
        let participant = NewsletterParticipantUpdateEvent::new(
            "abc@newsletter",
            "111@s.whatsapp.net",
            "222@s.whatsapp.net",
            "promote",
            "ADMIN",
        );
        let settings = NewsletterSettingsUpdateEvent::new("abc@newsletter")
            .with_field("name", "Updates")
            .with_field("description", "Daily notes");

        let encoded_reaction = encode_stored_newsletter_reaction_event(&reaction).unwrap();
        let encoded_view = encode_stored_newsletter_view_event(&view).unwrap();
        let encoded_participant =
            encode_stored_newsletter_participant_update_event(&participant).unwrap();
        let encoded_settings = encode_stored_newsletter_settings_update_event(&settings).unwrap();

        assert_eq!(
            decode_stored_newsletter_reaction_event(&encoded_reaction).unwrap(),
            reaction
        );
        assert_eq!(
            decode_stored_newsletter_view_event(&encoded_view).unwrap(),
            view
        );
        assert_eq!(
            decode_stored_newsletter_participant_update_event(&encoded_participant).unwrap(),
            participant
        );
        assert_eq!(
            decode_stored_newsletter_settings_update_event(&encoded_settings).unwrap(),
            settings
        );
        assert_eq!(
            newsletter_reaction_event_store_key(&reaction),
            "abc@newsletter|server-1|+"
        );
        assert_eq!(
            newsletter_view_event_store_key(&view),
            "abc@newsletter|server-1"
        );
        assert_eq!(
            newsletter_participant_update_event_store_key(&participant),
            "abc@newsletter|222@s.whatsapp.net|promote|ADMIN"
        );
        assert_eq!(
            newsletter_settings_update_event_store_key(&settings),
            "abc@newsletter"
        );

        let mut trailing = encoded_settings;
        trailing.push(0);
        assert!(decode_stored_newsletter_settings_update_event(&trailing).is_err());
    }

    #[test]
    fn stored_account_state_records_round_trip() {
        let reachout = ReachoutTimelockState {
            is_active: true,
            time_enforcement_ends: Some(1_700_000_000),
            enforcement_type: ReachoutTimelockEnforcementType::WebCompanionOnly,
        };
        let capping = MessageCappingInfo {
            total_quota: Some(50),
            used_quota: Some(12),
            cycle_start_timestamp: Some(1_700_000_001),
            cycle_end_timestamp: Some(1_700_000_002),
            server_sent_timestamp: Some(1_700_000_003),
            one_time_extension_status: Some(MessageCappingOneTimeExtensionStatus::Eligible),
            multi_variation_status: Some(MessageCappingMultiVariationStatus::Active),
            capping_status: Some(MessageCappingStatus::FirstWarning),
        };
        let default_disappearing_mode =
            DefaultDisappearingMode::new(604_800).with_timestamp(1_700_000_004);

        let encoded_reachout = encode_stored_reachout_timelock_state(&reachout).unwrap();
        let encoded_capping = encode_stored_message_capping_info(&capping).unwrap();
        let encoded_disappearing =
            encode_stored_default_disappearing_mode(&default_disappearing_mode).unwrap();

        assert_eq!(
            decode_stored_reachout_timelock_state(&encoded_reachout).unwrap(),
            reachout
        );
        assert_eq!(
            decode_stored_message_capping_info(&encoded_capping).unwrap(),
            capping
        );
        assert_eq!(
            decode_stored_default_disappearing_mode(&encoded_disappearing).unwrap(),
            default_disappearing_mode
        );
        assert_eq!(reachout_timelock_store_key(), "account");
        assert_eq!(message_capping_info_store_key(), "new-chat");
        assert_eq!(default_disappearing_mode_store_key(), "account");

        let mut trailing = encoded_capping;
        trailing.push(0);
        assert!(decode_stored_message_capping_info(&trailing).is_err());

        let mut trailing = encoded_disappearing;
        trailing.push(0);
        assert!(decode_stored_default_disappearing_mode(&trailing).is_err());
    }

    #[test]
    fn stored_message_record_rejects_bad_magic_and_trailing_bytes() {
        let encoded = encode_stored_message_update(&MessageUpdate::new(message_key("m1"))).unwrap();
        let mut bad_magic = encoded.clone();
        bad_magic[0] = b'X';
        assert!(decode_stored_message_update(&bad_magic).is_err());

        let mut trailing = encoded;
        trailing.push(0);
        assert!(decode_stored_message_update(&trailing).is_err());
    }

    #[test]
    fn coalesces_message_updates_and_deletes() {
        let key = message_key("m1");
        let mut buffer = EventBuffer::new(EventBufferConfig {
            max_pending_items: 8,
        });

        buffer
            .push(Event::MessagesUpsert(vec![
                MessageEvent::new(key.clone())
                    .with_timestamp(10)
                    .with_field("status", "pending"),
            ]))
            .unwrap();
        buffer
            .push(Event::MessagesUpdate(vec![
                MessageUpdate::new(key.clone())
                    .with_timestamp(11)
                    .with_field("status", "server_ack"),
            ]))
            .unwrap();

        let batch = buffer.flush().unwrap();
        assert_eq!(batch.messages_upsert.len(), 1);
        assert!(batch.messages_update.is_empty());
        assert_eq!(
            batch.messages_upsert[0].fields.get("status").unwrap(),
            "server_ack"
        );
        assert_eq!(batch.messages_upsert[0].timestamp, Some(11));

        buffer
            .push(Event::MessagesUpsert(vec![MessageEvent::new(key.clone())]))
            .unwrap();
        buffer
            .push(Event::MessagesDelete(vec![key.clone()]))
            .unwrap();
        let batch = buffer.flush().unwrap();
        assert!(batch.messages_upsert.is_empty());
        assert_eq!(batch.messages_delete, vec![key]);
    }

    #[test]
    fn coalesces_chat_contact_label_quick_reply_and_misc_events() {
        let key = message_key("m2");
        let mut buffer = EventBuffer::new(EventBufferConfig {
            max_pending_items: 24,
        });

        buffer
            .push(Event::ChatsUpdate(vec![
                ChatEvent::new("123@s.whatsapp.net").with_field("archive", "false"),
                ChatEvent::new("123@s.whatsapp.net").with_field("mute", "60"),
            ]))
            .unwrap();
        buffer
            .push(Event::ContactsUpsert(vec![
                ContactEvent::new("123@s.whatsapp.net").with_field("name", "A"),
            ]))
            .unwrap();
        buffer
            .push(Event::ContactsUpdate(vec![
                ContactEvent::new("123@s.whatsapp.net").with_field("notify", "B"),
            ]))
            .unwrap();
        buffer
            .push(Event::LabelsEdit(vec![
                LabelEvent::new("7").with_field("name", "Old"),
                LabelEvent::new("7").with_field("color", "2"),
            ]))
            .unwrap();
        buffer
            .push(Event::LabelsEdit(vec![
                LabelEvent::new("7").with_field("name", "New"),
            ]))
            .unwrap();
        buffer
            .push(Event::LabelsAssociation(vec![
                LabelAssociationEvent::chat("7", "123@s.whatsapp.net", true),
                LabelAssociationEvent::chat("7", "123@s.whatsapp.net", false),
            ]))
            .unwrap();
        buffer
            .push(Event::QuickRepliesUpdate(vec![
                QuickReplyEvent::new("qr-1").with_field("message", "old"),
                QuickReplyEvent::new("qr-1").with_field("shortcut", "/new"),
            ]))
            .unwrap();
        buffer
            .push(Event::GroupsUpdate(vec![
                GroupUpdateEvent::new("1@g.us").with_field("subject", "old"),
                GroupUpdateEvent::new("1@g.us").with_field("subject", "new"),
            ]))
            .unwrap();
        buffer
            .push(Event::ReceiptsUpdate(vec![
                ReceiptEvent::new(key.clone(), "read").with_timestamp(1),
                ReceiptEvent::new(key.clone(), "read").with_timestamp(2),
            ]))
            .unwrap();
        buffer
            .push(Event::ReactionsUpdate(vec![
                ReactionEvent::new(key.clone(), "456@s.whatsapp.net")
                    .with_text("+")
                    .with_timestamp(1),
                ReactionEvent::new(key.clone(), "456@s.whatsapp.net")
                    .with_text("-")
                    .with_timestamp(2),
            ]))
            .unwrap();
        buffer
            .push(Event::MediaRetry(vec![
                MediaRetryEvent::new(key.clone(), false)
                    .with_encrypted_payload(Bytes::from_static(b"old"), Bytes::from(vec![1u8; 12])),
                MediaRetryEvent::new(key, false).with_error(2, Some("missing".to_owned()), 404),
            ]))
            .unwrap();
        buffer
            .push(Event::BusinessNotificationUpdate(vec![
                BusinessNotificationEvent::new("server@s.whatsapp.net", "biz-1", "product_catalog")
                    .with_field("attr_version", "1"),
                BusinessNotificationEvent::new("server@s.whatsapp.net", "biz-1", "product_catalog")
                    .with_field("child_product_id", "sku-1"),
            ]))
            .unwrap();
        buffer
            .push(Event::PresenceUpdate(vec![
                PresenceEvent::new("123@s.whatsapp.net", "available").with_timestamp(1_700_000_008),
            ]))
            .unwrap();

        let batch = buffer.flush().unwrap();
        assert_eq!(batch.chats_update.len(), 1);
        assert_eq!(
            batch.chats_update[0].fields.get("archive").unwrap(),
            "false"
        );
        assert_eq!(batch.chats_update[0].fields.get("mute").unwrap(), "60");
        assert_eq!(batch.contacts_upsert.len(), 1);
        assert_eq!(batch.contacts_upsert[0].fields.get("notify").unwrap(), "B");
        assert_eq!(batch.labels_edit.len(), 1);
        assert_eq!(batch.labels_edit[0].fields.get("name").unwrap(), "New");
        assert_eq!(batch.labels_edit[0].fields.get("color").unwrap(), "2");
        assert_eq!(batch.labels_association.len(), 1);
        assert!(!batch.labels_association[0].labeled);
        assert_eq!(batch.quick_replies_update.len(), 1);
        assert_eq!(
            batch.quick_replies_update[0].fields.get("message").unwrap(),
            "old"
        );
        assert_eq!(
            batch.quick_replies_update[0]
                .fields
                .get("shortcut")
                .unwrap(),
            "/new"
        );
        assert_eq!(batch.groups_update[0].fields.get("subject").unwrap(), "new");
        assert_eq!(batch.receipts_update[0].timestamp, Some(2));
        assert_eq!(batch.reactions_update[0].text.as_deref(), Some("-"));
        assert_eq!(batch.media_retry.len(), 1);
        assert_eq!(batch.media_retry[0].error_code, Some(2));
        assert_eq!(batch.media_retry[0].status_code, Some(404));
        assert_eq!(batch.business_notifications.len(), 1);
        assert_eq!(batch.business_notifications[0].fields["attr_version"], "1");
        assert_eq!(
            batch.business_notifications[0].fields["child_product_id"],
            "sku-1"
        );
        assert_eq!(batch.presence_update.len(), 1);
        assert_eq!(batch.presence_update[0].presence_type, "available");
    }

    #[test]
    fn enforces_pending_item_limit_without_mutating_state_on_error() {
        let mut buffer = EventBuffer::new(EventBufferConfig {
            max_pending_items: 1,
        });
        buffer
            .push(Event::MessagesUpsert(vec![MessageEvent::new(message_key(
                "m1",
            ))]))
            .unwrap();
        assert!(
            buffer
                .push(Event::MessagesUpsert(vec![MessageEvent::new(message_key(
                    "m2"
                ))]))
                .is_err()
        );

        let batch = buffer.flush().unwrap();
        assert_eq!(batch.messages_upsert.len(), 1);
        assert_eq!(batch.messages_upsert[0].key.id, "m1");
        assert!(buffer.is_empty());
    }

    #[test]
    fn drains_immediate_events_before_batch() {
        let mut buffer = EventBuffer::new(EventBufferConfig {
            max_pending_items: 4,
        });
        buffer
            .push(Event::ConnectionUpdate(ConnectionState::Open))
            .unwrap();
        buffer
            .push(Event::MessagesUpsert(vec![MessageEvent::new(message_key(
                "m1",
            ))]))
            .unwrap();

        let events = buffer.drain_events();
        assert!(matches!(
            events[0],
            Event::ConnectionUpdate(ConnectionState::Open)
        ));
        assert!(matches!(events[1], Event::Batch(_)));
        assert!(buffer.is_empty());
    }

    #[test]
    fn emits_batch_into_event_hub() {
        let hub = EventHub::new(4);
        let mut rx = hub.subscribe();
        let mut buffer = EventBuffer::new(EventBufferConfig {
            max_pending_items: 4,
        });
        buffer
            .push(Event::MessagesUpsert(vec![MessageEvent::new(message_key(
                "m1",
            ))]))
            .unwrap();

        buffer.flush_into(&hub);

        let Event::Batch(batch) = rx.try_recv().unwrap() else {
            panic!("expected batch event");
        };
        assert_eq!(batch.messages_upsert[0].key.id, "m1");
    }
}
