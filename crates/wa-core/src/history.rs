use crate::message::{message_stanza_type, unwrapped_message_content};
use crate::{
    AccountSettingsEvent, CallEvent, ChatEvent, ContactEvent, CoreError, CoreResult,
    DefaultDisappearingMode, EventBatch, GroupUpdateEvent, HistorySetEvent, MessageEvent,
    MessageEventKey, MessageUpdate, ReactionEvent, RecentStickerEvent,
};
#[cfg(feature = "noise")]
use crate::{
    media::{MediaTransfer, MediaTransport},
    message::UploadedMedia,
};
use bytes::Bytes;
use flate2::read::ZlibDecoder;
use prost::Message as _;
use std::io::Read as _;
use wa_binary::{JidServer, jid_decode, jid_encode};
use wa_proto::proto::{
    Account, AutoDownloadSettings, AvatarUserSettings, CallLogRecord, Conversation, EventResponse,
    GlobalSettings, HistorySync, MediaVisibility, Message as ProtoMessage, MessageAddOn,
    MessageKey, NotificationSettings, PastParticipant, PastParticipants, PollUpdate, Pushname,
    Reaction, StickerMetadata, WallpaperSettings, WebMessageInfo, call_log_record,
    history_sync::{BotAiWaitListState, HistorySyncType},
    message::{HistorySyncNotification, event_response_message, pin_in_chat_message},
    message_add_on, past_participant,
};

pub const DEFAULT_MAX_HISTORY_INFLATED_BYTES: usize = 128 * 1024 * 1024;
pub const DEFAULT_MAX_HISTORY_CHATS: usize = 50_000;
pub const DEFAULT_MAX_HISTORY_CONTACTS: usize = 100_000;
pub const DEFAULT_MAX_HISTORY_MESSAGES: usize = 100_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HistorySyncDecodeConfig {
    pub max_inflated_bytes: usize,
}

impl Default for HistorySyncDecodeConfig {
    fn default() -> Self {
        Self {
            max_inflated_bytes: DEFAULT_MAX_HISTORY_INFLATED_BYTES,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HistorySyncProcessConfig {
    pub max_chats: usize,
    pub max_contacts: usize,
    pub max_messages: usize,
    pub is_latest: bool,
}

impl Default for HistorySyncProcessConfig {
    fn default() -> Self {
        Self {
            max_chats: DEFAULT_MAX_HISTORY_CHATS,
            max_contacts: DEFAULT_MAX_HISTORY_CONTACTS,
            max_messages: DEFAULT_MAX_HISTORY_MESSAGES,
            is_latest: false,
        }
    }
}

impl HistorySyncProcessConfig {
    #[must_use]
    pub fn latest(mut self, is_latest: bool) -> Self {
        self.is_latest = is_latest;
        self
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HistoryLidPnMapping {
    pub lid_jid: String,
    pub pn_jid: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessedHistorySync {
    pub sync_type: HistorySyncType,
    pub progress: Option<u32>,
    pub chunk_order: Option<u32>,
    pub batch: EventBatch,
    pub lid_pn_mappings: Vec<HistoryLidPnMapping>,
    pub default_disappearing_mode: Option<DefaultDisappearingMode>,
}

#[cfg(feature = "noise")]
pub fn uploaded_media_from_history_sync_notification(
    notification: &HistorySyncNotification,
) -> CoreResult<UploadedMedia> {
    let media_key = required_notification_bytes(notification.media_key.as_ref(), "media key")?;
    let file_sha256 =
        required_notification_bytes(notification.file_sha256.as_ref(), "file SHA-256")?;
    let file_enc_sha256 = required_notification_bytes(
        notification.file_enc_sha256.as_ref(),
        "encrypted file SHA-256",
    )?;
    validate_notification_len("media key", &media_key, 32)?;
    validate_notification_len("file SHA-256", &file_sha256, 32)?;
    validate_notification_len("encrypted file SHA-256", &file_enc_sha256, 32)?;

    let file_length = notification.file_length.ok_or_else(|| {
        CoreError::Payload("history sync notification missing file length".to_owned())
    })?;
    let direct_path = notification
        .direct_path
        .as_deref()
        .filter(|path| !path.is_empty())
        .ok_or_else(|| {
            CoreError::Payload("history sync notification missing direct path".to_owned())
        })?;

    Ok(
        UploadedMedia::new(media_key, file_sha256, file_enc_sha256, file_length)
            .with_direct_path(direct_path.to_owned()),
    )
}

#[cfg(feature = "noise")]
pub async fn download_history_sync_bytes<T>(
    transfer: &MediaTransfer<T>,
    notification: &HistorySyncNotification,
    fallback_host: Option<&str>,
) -> CoreResult<Bytes>
where
    T: MediaTransport,
{
    let media = uploaded_media_from_history_sync_notification(notification)?;
    validate_declared_history_size(&media, transfer.config().max_download_ciphertext_bytes)?;
    let compressed = transfer
        .download_bytes(&media, wa_crypto::MediaKind::HistorySync, fallback_host)
        .await?;
    let actual_len = u64::try_from(compressed.len())
        .map_err(|_| CoreError::Payload("history sync payload length exceeds u64".to_owned()))?;
    if actual_len != media.file_length {
        return Err(CoreError::Payload(format!(
            "history sync payload length mismatch: expected {}, got {actual_len}",
            media.file_length
        )));
    }
    Ok(Bytes::from(compressed))
}

#[cfg(feature = "noise")]
pub async fn download_history_sync<T>(
    transfer: &MediaTransfer<T>,
    notification: &HistorySyncNotification,
    fallback_host: Option<&str>,
    config: HistorySyncDecodeConfig,
) -> CoreResult<HistorySync>
where
    T: MediaTransport,
{
    let compressed = download_history_sync_bytes(transfer, notification, fallback_host).await?;
    decode_compressed_history_sync(&compressed, config)
}

#[cfg(feature = "noise")]
pub async fn download_and_process_history_sync<T>(
    transfer: &MediaTransfer<T>,
    notification: &HistorySyncNotification,
    fallback_host: Option<&str>,
    decode_config: HistorySyncDecodeConfig,
    process_config: HistorySyncProcessConfig,
) -> CoreResult<ProcessedHistorySync>
where
    T: MediaTransport,
{
    let history = decode_history_sync_notification(
        notification,
        Some((transfer, fallback_host)),
        decode_config,
    )
    .await?;
    process_history_sync(&history, process_config)
}

pub fn decode_compressed_history_sync(
    compressed: &[u8],
    config: HistorySyncDecodeConfig,
) -> CoreResult<HistorySync> {
    let inflated = inflate_zlib_bounded(compressed, config.max_inflated_bytes)?;
    decode_history_sync_bytes(&inflated)
}

pub fn decode_history_sync_bytes(bytes: &[u8]) -> CoreResult<HistorySync> {
    HistorySync::decode(bytes).map_err(CoreError::from)
}

pub fn decode_inline_history_sync(
    notification: &HistorySyncNotification,
    config: HistorySyncDecodeConfig,
) -> CoreResult<Option<HistorySync>> {
    notification
        .initial_hist_bootstrap_inline_payload
        .as_deref()
        .map(|payload| decode_compressed_history_sync(payload, config))
        .transpose()
}

pub fn process_inline_history_sync_notification(
    notification: &HistorySyncNotification,
    decode_config: HistorySyncDecodeConfig,
    process_config: HistorySyncProcessConfig,
) -> CoreResult<Option<ProcessedHistorySync>> {
    let Some(history) = decode_inline_history_sync(notification, decode_config)? else {
        return Ok(None);
    };
    process_history_sync(&history, process_config).map(Some)
}

pub fn history_sync_notifications_from_message(
    message: &ProtoMessage,
) -> Vec<HistorySyncNotification> {
    message
        .protocol_message
        .as_deref()
        .and_then(|protocol| protocol.history_sync_notification.as_ref())
        .cloned()
        .into_iter()
        .collect()
}

pub fn history_sync_notifications_from_web_message(
    message: &WebMessageInfo,
) -> Vec<HistorySyncNotification> {
    message
        .message
        .as_ref()
        .map(history_sync_notifications_from_message)
        .unwrap_or_default()
}

pub fn history_sync_notifications_from_message_event(
    event: &MessageEvent,
) -> CoreResult<Vec<HistorySyncNotification>> {
    let Some(payload) = event.payload.as_ref() else {
        return Ok(Vec::new());
    };

    let mut notifications = Vec::new();
    let message_decode = ProtoMessage::decode(payload.as_ref());
    if let Ok(message) = message_decode.as_ref() {
        push_unique_history_sync_notifications(
            &mut notifications,
            history_sync_notifications_from_message(message),
        );
    }

    if notifications.is_empty() || event.fields.contains_key("history_sync_type") {
        match WebMessageInfo::decode(payload.as_ref()) {
            Ok(message) => {
                push_unique_history_sync_notifications(
                    &mut notifications,
                    history_sync_notifications_from_web_message(&message),
                );
            }
            Err(err) if message_decode.is_err() => return Err(CoreError::from(err)),
            Err(_) => {}
        }
    }

    Ok(notifications)
}

fn push_unique_history_sync_notifications(
    notifications: &mut Vec<HistorySyncNotification>,
    incoming: Vec<HistorySyncNotification>,
) {
    for notification in incoming {
        if !notifications
            .iter()
            .any(|existing| existing == &notification)
        {
            notifications.push(notification);
        }
    }
}

#[cfg(feature = "noise")]
pub async fn decode_history_sync_notification<T>(
    notification: &HistorySyncNotification,
    transfer: Option<(&MediaTransfer<T>, Option<&str>)>,
    config: HistorySyncDecodeConfig,
) -> CoreResult<HistorySync>
where
    T: MediaTransport,
{
    if let Some(history) = decode_inline_history_sync(notification, config)? {
        return Ok(history);
    }

    let (transfer, fallback_host) = transfer.ok_or_else(|| {
        CoreError::Payload(
            "history sync notification requires media transfer for external payload".to_owned(),
        )
    })?;
    download_history_sync(transfer, notification, fallback_host, config).await
}

pub fn process_history_sync(
    history: &HistorySync,
    config: HistorySyncProcessConfig,
) -> CoreResult<ProcessedHistorySync> {
    let sync_type = HistorySyncType::try_from(history.sync_type).map_err(|_| {
        CoreError::Protocol(format!("unknown history sync type: {}", history.sync_type))
    })?;
    let mut batch = EventBatch::default();
    let mut history_event = HistorySetEvent {
        is_latest: config.is_latest,
        ..HistorySetEvent::default()
    };
    let mut mappings = Vec::new();
    let default_disappearing_mode =
        history_default_disappearing_mode(history.global_settings.as_ref())?;

    collect_direct_mappings(history, &mut mappings)?;

    match sync_type {
        HistorySyncType::InitialBootstrap
        | HistorySyncType::Full
        | HistorySyncType::Recent
        | HistorySyncType::OnDemand => {
            for conversation in &history.conversations {
                add_conversation(
                    conversation,
                    sync_type,
                    &mut history_event,
                    &mut batch.messages_update,
                    &mut batch.reactions_update,
                    &mut mappings,
                    config,
                )?;
            }
            for message in &history.status_v3_messages {
                push_history_message_event(
                    HistoryMessageOutputs {
                        messages: &mut history_event.messages,
                        updates: &mut batch.messages_update,
                        reactions: &mut batch.reactions_update,
                    },
                    message,
                    None,
                    None,
                    sync_type,
                    config.max_messages,
                )?;
            }
        }
        HistorySyncType::InitialStatusV3 => {
            for message in &history.status_v3_messages {
                push_history_message_event(
                    HistoryMessageOutputs {
                        messages: &mut history_event.messages,
                        updates: &mut batch.messages_update,
                        reactions: &mut batch.reactions_update,
                    },
                    message,
                    None,
                    None,
                    sync_type,
                    config.max_messages,
                )?;
            }
        }
        HistorySyncType::PushName => {
            for pushname in &history.pushnames {
                push_pushname_contact(&mut history_event.contacts, pushname, config.max_contacts)?;
            }
        }
        HistorySyncType::NonBlockingData => {
            for pushname in &history.pushnames {
                push_pushname_contact(&mut history_event.contacts, pushname, config.max_contacts)?;
            }
            push_history_account_contacts(
                &mut history_event.contacts,
                &history.accounts,
                config.max_contacts,
            )?;
            for message in &history.status_v3_messages {
                push_history_message_event(
                    HistoryMessageOutputs {
                        messages: &mut history_event.messages,
                        updates: &mut batch.messages_update,
                        reactions: &mut batch.reactions_update,
                    },
                    message,
                    None,
                    None,
                    sync_type,
                    config.max_messages,
                )?;
            }
        }
    }

    push_history_call_log_events(
        &mut batch.calls_update,
        &history.call_log_records,
        config.max_messages,
    )?;
    push_history_past_participant_events(
        &mut batch.groups_update,
        &history.past_participants,
        config.max_chats,
        config.max_messages,
    )?;
    push_history_recent_sticker_events(
        &mut batch.recent_stickers,
        &history.recent_stickers,
        config.max_messages,
    )?;
    push_history_account_settings_event(&mut batch.account_settings, history);

    if history_event.pending_items() > 0 {
        batch.history = Some(history_event);
    }

    Ok(ProcessedHistorySync {
        sync_type,
        progress: history.progress,
        chunk_order: history.chunk_order,
        batch,
        lid_pn_mappings: mappings,
        default_disappearing_mode,
    })
}

fn add_conversation(
    conversation: &Conversation,
    sync_type: HistorySyncType,
    history_event: &mut HistorySetEvent,
    updates: &mut Vec<MessageUpdate>,
    reactions: &mut Vec<ReactionEvent>,
    mappings: &mut Vec<HistoryLidPnMapping>,
    config: HistorySyncProcessConfig,
) -> CoreResult<()> {
    let chat_jid = validate_jid("history chat JID", &conversation.id)?.to_owned();
    push_chat_event(
        &mut history_event.chats,
        conversation,
        &chat_jid,
        config.max_chats,
    )?;
    push_conversation_contact(
        &mut history_event.contacts,
        conversation,
        &chat_jid,
        config.max_contacts,
    )?;
    collect_conversation_mappings(conversation, &chat_jid, mappings)?;

    for item in &conversation.messages {
        let message = item.message.as_ref().ok_or_else(|| {
            CoreError::Protocol("history sync message item missing message".to_owned())
        })?;
        push_history_message_event(
            HistoryMessageOutputs {
                messages: &mut history_event.messages,
                updates,
                reactions,
            },
            message,
            Some(&chat_jid),
            item.msg_order_id,
            sync_type,
            config.max_messages,
        )?;
    }

    Ok(())
}

fn push_chat_event(
    chats: &mut Vec<ChatEvent>,
    conversation: &Conversation,
    chat_jid: &str,
    max_chats: usize,
) -> CoreResult<()> {
    ensure_capacity(chats.len(), max_chats, "history chats")?;
    let mut event = ChatEvent::new(chat_jid.to_owned());
    event = add_opt_field(event, "name", conversation.name.as_deref());
    event = add_opt_field(event, "display_name", conversation.display_name.as_deref());
    event = add_opt_field(event, "username", conversation.username.as_deref());
    event = add_opt_field(event, "pn_jid", conversation.pn_jid.as_deref());
    event = add_opt_field(event, "lid_jid", conversation.lid_jid.as_deref());
    event = add_opt_field(event, "account_lid", conversation.account_lid.as_deref());
    event = add_opt_number_field(event, "last_msg_timestamp", conversation.last_msg_timestamp);
    event = add_opt_number_field(
        event,
        "conversation_timestamp",
        conversation.conversation_timestamp,
    );
    event = add_opt_number_field(event, "unread_count", conversation.unread_count);
    event = add_opt_number_field(
        event,
        "unread_mention_count",
        conversation.unread_mention_count,
    );
    event = add_opt_number_field(
        event,
        "ephemeral_expiration",
        conversation.ephemeral_expiration,
    );
    event = add_opt_number_field(event, "pinned", conversation.pinned);
    event = add_opt_number_field(event, "mute_end_time", conversation.mute_end_time);
    event = add_opt_bool_field(event, "archived", conversation.archived);
    event = add_opt_bool_field(event, "read_only", conversation.read_only);
    event = add_opt_bool_field(event, "marked_as_unread", conversation.marked_as_unread);
    event = add_opt_bool_field(
        event,
        "end_of_history_transfer",
        conversation.end_of_history_transfer,
    );
    chats.push(event);
    Ok(())
}

fn push_conversation_contact(
    contacts: &mut Vec<ContactEvent>,
    conversation: &Conversation,
    chat_jid: &str,
    max_contacts: usize,
) -> CoreResult<()> {
    ensure_capacity(contacts.len(), max_contacts, "history contacts")?;
    let mut event = ContactEvent::new(chat_jid.to_owned());
    let name = conversation
        .display_name
        .as_deref()
        .or(conversation.name.as_deref())
        .or(conversation.username.as_deref());
    event = add_opt_field(event, "name", name);
    event = add_opt_field(event, "username", conversation.username.as_deref());
    event = add_opt_field(
        event,
        "lid_jid",
        conversation
            .lid_jid
            .as_deref()
            .or(conversation.account_lid.as_deref()),
    );
    event = add_opt_field(event, "pn_jid", conversation.pn_jid.as_deref());
    contacts.push(event);
    Ok(())
}

fn push_pushname_contact(
    contacts: &mut Vec<ContactEvent>,
    pushname: &Pushname,
    max_contacts: usize,
) -> CoreResult<()> {
    ensure_capacity(contacts.len(), max_contacts, "history contacts")?;
    let jid = pushname
        .id
        .as_deref()
        .ok_or_else(|| CoreError::Protocol("history push name missing JID".to_owned()))?;
    validate_jid("history push name JID", jid)?;
    let mut event = ContactEvent::new(jid.to_owned());
    event = add_opt_field(event, "notify", pushname.pushname.as_deref());
    contacts.push(event);
    Ok(())
}

fn push_history_account_contacts(
    contacts: &mut Vec<ContactEvent>,
    accounts: &[Account],
    max_contacts: usize,
) -> CoreResult<()> {
    for account in accounts {
        let Some(event) = history_account_contact_event(account)? else {
            continue;
        };
        ensure_capacity(contacts.len(), max_contacts, "history contacts")?;
        contacts.push(event);
    }
    Ok(())
}

fn history_account_contact_event(account: &Account) -> CoreResult<Option<ContactEvent>> {
    let Some(lid) = account.lid.as_deref() else {
        return Ok(None);
    };
    let Some(lid_jid) = normalize_history_account_lid(lid)? else {
        return Ok(None);
    };

    let mut event = ContactEvent::new(lid_jid.clone())
        .with_field("source", "history_account")
        .with_field("lid_jid", lid_jid);
    if account.is_username_deleted == Some(true) {
        event = event
            .with_field("username", "")
            .with_field("username_deleted", "true")
            .with_field("is_username_deleted", "true");
    } else {
        event = add_opt_field(event, "username", account.username.as_deref());
        event = add_opt_bool_field(event, "is_username_deleted", account.is_username_deleted);
    }
    event = add_opt_field(event, "country_code", account.country_code.as_deref());
    Ok(Some(event))
}

fn normalize_history_account_lid(lid: &str) -> CoreResult<Option<String>> {
    let lid = lid.trim();
    if lid.is_empty() {
        return Ok(None);
    }
    if lid.contains('@') {
        let decoded = jid_decode(lid)
            .ok_or_else(|| CoreError::Protocol(format!("invalid history account LID: {lid}")))?;
        if !matches!(decoded.server, JidServer::Lid | JidServer::HostedLid) {
            return Err(CoreError::Protocol(format!(
                "history account LID must use LID domain: {lid}"
            )));
        }
        return Ok(Some(jid_encode(decoded.user, decoded.server, None, None)));
    }

    let jid = jid_encode(lid, JidServer::Lid, None, None);
    let decoded = jid_decode(&jid).ok_or_else(|| {
        CoreError::Protocol(format!("invalid history account bare LID user: {lid}"))
    })?;
    if decoded.user != lid || decoded.device.is_some() || decoded.agent.is_some() {
        return Err(CoreError::Protocol(format!(
            "invalid history account bare LID user: {lid}"
        )));
    }
    Ok(Some(jid))
}

fn push_history_recent_sticker_events(
    stickers: &mut Vec<RecentStickerEvent>,
    records: &[StickerMetadata],
    max_stickers: usize,
) -> CoreResult<()> {
    for record in records {
        let Some(event) = history_recent_sticker_event(record)? else {
            continue;
        };
        ensure_capacity(stickers.len(), max_stickers, "history recent stickers")?;
        stickers.push(event);
    }
    Ok(())
}

fn history_recent_sticker_event(
    sticker: &StickerMetadata,
) -> CoreResult<Option<RecentStickerEvent>> {
    let Some(id) = history_recent_sticker_id(sticker) else {
        return Ok(None);
    };
    let mut event = RecentStickerEvent::new(id).with_field("source", "history_recent_sticker");
    if let Some(file_sha256) = non_empty_history_bytes(sticker.file_sha256.as_ref()) {
        event = event
            .with_file_sha256(file_sha256.clone())
            .with_field("file_sha256_hex", bytes_to_hex(file_sha256.as_ref()));
    }
    if let Some(file_enc_sha256) = non_empty_history_bytes(sticker.file_enc_sha256.as_ref()) {
        event = event
            .with_file_enc_sha256(file_enc_sha256.clone())
            .with_field(
                "file_enc_sha256_hex",
                bytes_to_hex(file_enc_sha256.as_ref()),
            );
    }
    if let Some(media_key) = non_empty_history_bytes(sticker.media_key.as_ref()) {
        event = event.with_media_key(media_key.clone());
    }
    event = add_opt_field(event, "url", sticker.url.as_deref());
    event = add_opt_field(event, "mimetype", sticker.mimetype.as_deref());
    event = add_opt_field(event, "direct_path", sticker.direct_path.as_deref());
    event = add_opt_field(event, "image_hash", sticker.image_hash.as_deref());
    event = add_opt_number_field(event, "height", sticker.height);
    event = add_opt_number_field(event, "width", sticker.width);
    event = add_opt_number_field(event, "file_length", sticker.file_length);
    event = add_opt_number_field(event, "last_sticker_sent_ts", sticker.last_sticker_sent_ts);
    event = add_opt_bool_field(event, "is_lottie", sticker.is_lottie);
    event = add_opt_bool_field(event, "is_avatar_sticker", sticker.is_avatar_sticker);
    if let Some(weight) = sticker.weight {
        event = event.with_field("weight", weight.to_string());
    }
    Ok(Some(event))
}

fn history_recent_sticker_id(sticker: &StickerMetadata) -> Option<String> {
    non_empty_history_bytes(sticker.file_sha256.as_ref())
        .map(|value| format!("file_sha256:{}", bytes_to_hex(value.as_ref())))
        .or_else(|| {
            non_empty_history_bytes(sticker.file_enc_sha256.as_ref())
                .map(|value| format!("file_enc_sha256:{}", bytes_to_hex(value.as_ref())))
        })
        .or_else(|| non_empty_prefixed("direct_path", sticker.direct_path.as_deref()))
        .or_else(|| non_empty_prefixed("image_hash", sticker.image_hash.as_deref()))
        .or_else(|| non_empty_prefixed("url", sticker.url.as_deref()))
}

fn non_empty_history_bytes(bytes: Option<&Bytes>) -> Option<&Bytes> {
    bytes.filter(|bytes| !bytes.is_empty())
}

fn non_empty_prefixed(prefix: &str, value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| format!("{prefix}:{value}"))
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn push_history_account_settings_event(
    events: &mut Vec<AccountSettingsEvent>,
    history: &HistorySync,
) {
    let Some(event) = history_account_settings_event(history) else {
        return;
    };
    events.push(event);
}

fn history_account_settings_event(history: &HistorySync) -> Option<AccountSettingsEvent> {
    let mut event = AccountSettingsEvent::new("history_sync").with_field("source", "history_sync");

    if let Some(settings) = history.global_settings.as_ref() {
        event = add_global_settings_fields(event, settings);
    }
    event = add_opt_number_field(
        event,
        "thread_ds_timeframe_offset",
        history.thread_ds_timeframe_offset,
    );
    event = add_opt_field(
        event,
        "companion_meta_nonce",
        history.companion_meta_nonce.as_deref(),
    );
    event = add_history_secret_presence(
        event,
        "thread_id_user_secret",
        history.thread_id_user_secret.as_ref(),
    );
    event = add_history_secret_presence(
        event,
        "shareable_chat_identifier_encryption_key",
        history.shareable_chat_identifier_encryption_key.as_ref(),
    );
    if let Some(state) = history.ai_wait_list_state {
        let value = BotAiWaitListState::try_from(state).map_or_else(
            |_| format!("UNKNOWN_{state}"),
            |state| state.as_str_name().to_owned(),
        );
        event = event.with_field("ai_wait_list_state", value);
    }

    (event.fields.len() > 1).then_some(event)
}

fn add_global_settings_fields(
    mut event: AccountSettingsEvent,
    settings: &GlobalSettings,
) -> AccountSettingsEvent {
    if let Some(value) = settings.media_visibility {
        let value = MediaVisibility::try_from(value).map_or_else(
            |_| format!("UNKNOWN_{value}"),
            |value| value.as_str_name().to_owned(),
        );
        event = event.with_field("media_visibility", value);
    }
    event = add_wallpaper_settings_fields(
        event,
        "light_theme_wallpaper",
        settings.light_theme_wallpaper.as_ref(),
    );
    event = add_wallpaper_settings_fields(
        event,
        "dark_theme_wallpaper",
        settings.dark_theme_wallpaper.as_ref(),
    );
    event = add_auto_download_settings_fields(
        event,
        "auto_download_wifi",
        settings.auto_download_wi_fi.as_ref(),
    );
    event = add_auto_download_settings_fields(
        event,
        "auto_download_cellular",
        settings.auto_download_cellular.as_ref(),
    );
    event = add_auto_download_settings_fields(
        event,
        "auto_download_roaming",
        settings.auto_download_roaming.as_ref(),
    );
    event = add_opt_bool_field(
        event,
        "show_individual_notifications_preview",
        settings.show_individual_notifications_preview,
    );
    event = add_opt_bool_field(
        event,
        "show_group_notifications_preview",
        settings.show_group_notifications_preview,
    );
    event = add_opt_number_field(
        event,
        "disappearing_mode_duration",
        settings.disappearing_mode_duration,
    );
    event = add_opt_number_field(
        event,
        "disappearing_mode_timestamp",
        settings.disappearing_mode_timestamp,
    );
    event = add_avatar_user_settings_fields(event, settings.avatar_user_settings.as_ref());
    event = add_opt_number_field(event, "font_size", settings.font_size);
    event = add_opt_bool_field(
        event,
        "security_notifications",
        settings.security_notifications,
    );
    event = add_opt_bool_field(event, "auto_unarchive_chats", settings.auto_unarchive_chats);
    event = add_opt_number_field(event, "video_quality_mode", settings.video_quality_mode);
    event = add_opt_number_field(event, "photo_quality_mode", settings.photo_quality_mode);
    event = add_notification_settings_fields(
        event,
        "individual_notification",
        settings.individual_notification_settings.as_ref(),
    );
    event = add_notification_settings_fields(
        event,
        "group_notification",
        settings.group_notification_settings.as_ref(),
    );
    add_opt_number_field(
        event,
        "chat_db_lid_migration_timestamp",
        settings.chat_db_lid_migration_timestamp,
    )
}

fn add_wallpaper_settings_fields(
    mut event: AccountSettingsEvent,
    prefix: &str,
    settings: Option<&WallpaperSettings>,
) -> AccountSettingsEvent {
    let Some(settings) = settings else {
        return event;
    };
    event = add_opt_field(
        event,
        &format!("{prefix}_filename"),
        settings.filename.as_deref(),
    );
    add_opt_number_field(event, &format!("{prefix}_opacity"), settings.opacity)
}

fn add_auto_download_settings_fields(
    mut event: AccountSettingsEvent,
    prefix: &str,
    settings: Option<&AutoDownloadSettings>,
) -> AccountSettingsEvent {
    let Some(settings) = settings else {
        return event;
    };
    event = add_opt_bool_field(event, &format!("{prefix}_images"), settings.download_images);
    event = add_opt_bool_field(event, &format!("{prefix}_audio"), settings.download_audio);
    event = add_opt_bool_field(event, &format!("{prefix}_video"), settings.download_video);
    add_opt_bool_field(
        event,
        &format!("{prefix}_documents"),
        settings.download_documents,
    )
}

fn add_avatar_user_settings_fields(
    mut event: AccountSettingsEvent,
    settings: Option<&AvatarUserSettings>,
) -> AccountSettingsEvent {
    let Some(settings) = settings else {
        return event;
    };
    event = add_opt_field(event, "avatar_fbid", settings.fbid.as_deref());
    if settings
        .password
        .as_deref()
        .is_some_and(|value| !value.is_empty())
    {
        event = event.with_field("avatar_password_present", "true");
    }
    event
}

fn add_notification_settings_fields(
    mut event: AccountSettingsEvent,
    prefix: &str,
    settings: Option<&NotificationSettings>,
) -> AccountSettingsEvent {
    let Some(settings) = settings else {
        return event;
    };
    event = add_opt_field(
        event,
        &format!("{prefix}_message_vibrate"),
        settings.message_vibrate.as_deref(),
    );
    event = add_opt_field(
        event,
        &format!("{prefix}_message_popup"),
        settings.message_popup.as_deref(),
    );
    event = add_opt_field(
        event,
        &format!("{prefix}_message_light"),
        settings.message_light.as_deref(),
    );
    event = add_opt_bool_field(
        event,
        &format!("{prefix}_low_priority_notifications"),
        settings.low_priority_notifications,
    );
    event = add_opt_bool_field(
        event,
        &format!("{prefix}_reactions_muted"),
        settings.reactions_muted,
    );
    add_opt_field(
        event,
        &format!("{prefix}_call_vibrate"),
        settings.call_vibrate.as_deref(),
    )
}

fn add_history_secret_presence(
    mut event: AccountSettingsEvent,
    prefix: &str,
    bytes: Option<&Bytes>,
) -> AccountSettingsEvent {
    let Some(bytes) = bytes else {
        return event;
    };
    event = event.with_field(format!("{prefix}_present"), "true");
    event.with_field(format!("{prefix}_len"), bytes.len().to_string())
}

struct HistoryMessageOutputs<'a> {
    messages: &'a mut Vec<MessageEvent>,
    updates: &'a mut Vec<MessageUpdate>,
    reactions: &'a mut Vec<ReactionEvent>,
}

fn push_history_message_event(
    outputs: HistoryMessageOutputs<'_>,
    message: &WebMessageInfo,
    fallback_remote_jid: Option<&str>,
    msg_order_id: Option<u64>,
    sync_type: HistorySyncType,
    max_messages: usize,
) -> CoreResult<()> {
    ensure_capacity(outputs.messages.len(), max_messages, "history messages")?;
    let key = message
        .key
        .as_ref()
        .ok_or_else(|| CoreError::Protocol("history message missing key".to_owned()))?;
    let remote_jid = key
        .remote_jid
        .as_deref()
        .filter(|jid| !jid.is_empty())
        .or(fallback_remote_jid)
        .ok_or_else(|| CoreError::Protocol("history message missing remote JID".to_owned()))?;
    validate_jid("history message remote JID", remote_jid)?;
    if let Some(participant) = key.participant.as_deref() {
        validate_jid("history message participant JID", participant)?;
    }
    let id = key
        .id
        .as_deref()
        .filter(|id| !id.is_empty())
        .ok_or_else(|| CoreError::Protocol("history message missing id".to_owned()))?;

    let target_key = MessageEventKey::new(
        remote_jid.to_owned(),
        id.to_owned(),
        key.participant.clone(),
    );
    let mut event = MessageEvent::new(target_key.clone())
        .with_payload(Bytes::from(message.encode_to_vec()))
        .with_field("history_sync_type", sync_type.as_str_name());

    if let Some(timestamp) = message.message_timestamp {
        event = event.with_timestamp(timestamp);
    }
    if let Some(from_me) = key.from_me {
        event = event.with_field("from_me", from_me.to_string());
    }
    if let Some(push_name) = &message.push_name {
        event = event.with_field("push_name", push_name.clone());
    }
    if let Some(status) = message.status {
        event = event.with_field("status", status.to_string());
    }
    if let Some(stub_type) = message.message_stub_type {
        event = event.with_field("message_stub_type", stub_type.to_string());
    }
    if let Some(msg_order_id) = msg_order_id {
        event = event.with_field("history_order_id", msg_order_id.to_string());
    }

    outputs.messages.push(event);
    push_history_web_message_updates(
        outputs.updates,
        outputs.reactions,
        message,
        &target_key,
        max_messages,
    )?;
    Ok(())
}

fn push_history_web_message_updates(
    updates: &mut Vec<MessageUpdate>,
    reactions: &mut Vec<ReactionEvent>,
    message: &WebMessageInfo,
    target_key: &MessageEventKey,
    max_updates: usize,
) -> CoreResult<()> {
    for reaction in &message.reactions {
        ensure_capacity(reactions.len(), max_updates, "history reactions")?;
        reactions.push(history_reaction_event(target_key, reaction)?);
    }
    for poll in &message.poll_updates {
        ensure_capacity(updates.len(), max_updates, "history message updates")?;
        updates.push(history_poll_update(poll)?);
    }
    for event_response in &message.event_responses {
        ensure_capacity(updates.len(), max_updates, "history message updates")?;
        updates.push(history_event_response_update(event_response)?);
    }
    for add_on in &message.message_add_ons {
        ensure_capacity(updates.len(), max_updates, "history message updates")?;
        updates.push(history_message_add_on_update(add_on)?);
    }
    Ok(())
}

fn history_reaction_event(
    target_key: &MessageEventKey,
    reaction: &Reaction,
) -> CoreResult<ReactionEvent> {
    let actor_key = reaction
        .key
        .as_ref()
        .ok_or_else(|| CoreError::Protocol("history reaction missing author key".to_owned()))?;
    let from_jid = actor_key
        .participant
        .as_deref()
        .filter(|jid| !jid.is_empty())
        .or_else(|| {
            actor_key
                .remote_jid
                .as_deref()
                .filter(|jid| !jid.is_empty())
        })
        .ok_or_else(|| CoreError::Protocol("history reaction missing author JID".to_owned()))?;
    validate_jid("history reaction author JID", from_jid)?;

    let mut event = ReactionEvent::new(target_key.clone(), from_jid.to_owned());
    if let Some(text) = reaction.text.as_ref() {
        event = event.with_text(text.clone());
    }
    if let Some(timestamp_ms) = reaction.sender_timestamp_ms {
        event = event.with_timestamp(non_negative_i64_to_u64(
            timestamp_ms,
            "history reaction sender timestamp",
        )?);
    }
    Ok(event)
}

fn history_poll_update(poll: &PollUpdate) -> CoreResult<MessageUpdate> {
    let key = poll
        .poll_update_message_key
        .as_ref()
        .ok_or_else(|| CoreError::Protocol("history poll update missing target key".to_owned()))
        .and_then(history_message_event_key_from_proto)?;
    let mut update = MessageUpdate::new(key)
        .with_field("source", "history_poll_update")
        .with_field("poll_update", "true")
        .with_field("vote_present", poll.vote.is_some().to_string())
        .with_field("unread", poll.unread.unwrap_or(false).to_string());
    if let Some(timestamp_ms) = poll.sender_timestamp_ms {
        update = update.with_timestamp(non_negative_i64_to_u64(
            timestamp_ms,
            "history poll update sender timestamp",
        )?);
    }
    if let Some(server_timestamp_ms) = poll.server_timestamp_ms {
        update = update.with_field(
            "server_timestamp_ms",
            non_negative_i64_to_u64(server_timestamp_ms, "history poll update server timestamp")?
                .to_string(),
        );
    }
    if let Some(vote) = poll.vote.as_ref() {
        update = update.with_field(
            "selected_options_count",
            vote.selected_options.len().to_string(),
        );
    }
    Ok(update)
}

fn history_event_response_update(response: &EventResponse) -> CoreResult<MessageUpdate> {
    let key = response
        .event_response_message_key
        .as_ref()
        .ok_or_else(|| CoreError::Protocol("history event response missing target key".to_owned()))
        .and_then(history_message_event_key_from_proto)?;
    let mut update = MessageUpdate::new(key)
        .with_field("source", "history_event_response")
        .with_field("event_response", "true")
        .with_field("unread", response.unread.unwrap_or(false).to_string())
        .with_field(
            "response_present",
            response.event_response_message.is_some().to_string(),
        );
    if let Some(timestamp_ms) = response.timestamp_ms {
        update = update.with_timestamp(non_negative_i64_to_u64(
            timestamp_ms,
            "history event response timestamp",
        )?);
    }
    if let Some(response_message) = response.event_response_message.as_ref() {
        update = update.with_field(
            "response",
            match event_response_message::EventResponseType::try_from(
                response_message.response.unwrap_or_default(),
            )
            .ok()
            {
                Some(event_response_message::EventResponseType::Going) => "going",
                Some(event_response_message::EventResponseType::NotGoing) => "not_going",
                Some(event_response_message::EventResponseType::Maybe) => "maybe",
                Some(event_response_message::EventResponseType::Unknown) | None => "unknown",
            },
        );
        if let Some(extra_guest_count) = response_message.extra_guest_count {
            update = update.with_field("extra_guest_count", extra_guest_count.to_string());
        }
        if let Some(response_timestamp_ms) = response_message.timestamp_ms {
            update = update.with_field(
                "response_timestamp_ms",
                non_negative_i64_to_u64(
                    response_timestamp_ms,
                    "history event response message timestamp",
                )?
                .to_string(),
            );
        }
    }
    Ok(update)
}

fn history_message_add_on_update(add_on: &MessageAddOn) -> CoreResult<MessageUpdate> {
    let key = history_message_add_on_target_key(add_on)?;
    let mut update = MessageUpdate::new(key)
        .with_field("source", "history_message_add_on")
        .with_field(
            "add_on_type",
            history_message_add_on_type_name(add_on.message_add_on_type),
        )
        .with_field(
            "add_on_message_present",
            add_on.message_add_on.is_some().to_string(),
        )
        .with_field(
            "legacy_message_present",
            add_on.legacy_message.is_some().to_string(),
        );
    if let Some(timestamp_ms) = add_on.sender_timestamp_ms {
        update = update.with_timestamp(non_negative_i64_to_u64(
            timestamp_ms,
            "history message add-on sender timestamp",
        )?);
    }
    if let Some(server_timestamp_ms) = add_on.server_timestamp_ms {
        update = update.with_field(
            "server_timestamp_ms",
            non_negative_i64_to_u64(
                server_timestamp_ms,
                "history message add-on server timestamp",
            )?
            .to_string(),
        );
    }
    if let Some(status) = add_on.status {
        update = update.with_field("status", status.to_string());
    }
    if let Some(context) = add_on.add_on_context_info.as_ref() {
        if let Some(duration) = context.message_add_on_duration_in_secs {
            update = update.with_field("add_on_duration_secs", duration.to_string());
        }
        if let Some(expiry_type) = context.message_add_on_expiry_type {
            update = update.with_field("add_on_expiry_type", expiry_type.to_string());
        }
    }
    if let Some(message) = add_on.message_add_on.as_ref() {
        update = update.with_field("add_on_stanza_type", message_stanza_type(message));
        let message_content = unwrapped_message_content(message);
        if let Some(poll) = message_content.poll_update_message.as_ref() {
            update = update
                .with_field("poll_update", "true")
                .with_field("vote_encrypted", poll.vote.is_some().to_string())
                .with_field("metadata_present", poll.metadata.is_some().to_string());
            if let Some(vote) = poll.vote.as_ref() {
                if let Some(payload) = vote.enc_payload.as_ref() {
                    update = update
                        .with_field("encrypted_vote_payload_bytes", payload.len().to_string());
                }
                if let Some(iv) = vote.enc_iv.as_ref() {
                    update = update.with_field("encrypted_vote_iv_bytes", iv.len().to_string());
                }
            }
        }
        if let Some(event_response) = message_content.enc_event_response_message.as_ref() {
            update = update.with_field("event_response", "true").with_field(
                "response_encrypted",
                event_response.enc_payload.is_some().to_string(),
            );
            if let Some(payload) = event_response.enc_payload.as_ref() {
                update = update.with_field(
                    "encrypted_event_response_payload_bytes",
                    payload.len().to_string(),
                );
            }
            if let Some(iv) = event_response.enc_iv.as_ref() {
                update =
                    update.with_field("encrypted_event_response_iv_bytes", iv.len().to_string());
            }
        }
        if let Some(pin) = message_content.pin_in_chat_message.as_ref() {
            update = update.with_field(
                "pin_action",
                match pin_in_chat_message::Type::try_from(pin.r#type.unwrap_or_default()).ok() {
                    Some(pin_in_chat_message::Type::PinForAll) => "pin",
                    Some(pin_in_chat_message::Type::UnpinForAll) => "unpin",
                    _ => "unknown",
                },
            );
        }
        if message_content.reaction_message.is_some() {
            update = update.with_field("reaction", "true");
        }
    }
    if let Some(legacy) = add_on.legacy_message.as_ref() {
        if let Some(vote) = legacy.poll_vote.as_ref() {
            update = update.with_field("poll_update", "true").with_field(
                "selected_options_count",
                vote.selected_options.len().to_string(),
            );
        }
        if let Some(response) = legacy.event_response_message.as_ref() {
            update = apply_event_response_message_fields(update, response)?;
        }
    }
    Ok(update)
}

fn history_message_add_on_target_key(add_on: &MessageAddOn) -> CoreResult<MessageEventKey> {
    if let Some(key) = add_on.message_add_on_key.as_ref() {
        return history_message_event_key_from_proto(key);
    }
    if let Some(message) = add_on.message_add_on.as_ref() {
        let message_content = unwrapped_message_content(message);
        if let Some(poll) = message_content.poll_update_message.as_ref()
            && let Some(key) = poll.poll_creation_message_key.as_ref()
        {
            return history_message_event_key_from_proto(key);
        }
        if let Some(event_response) = message_content.enc_event_response_message.as_ref()
            && let Some(key) = event_response.event_creation_message_key.as_ref()
        {
            return history_message_event_key_from_proto(key);
        }
        if let Some(reaction) = message_content.reaction_message.as_ref()
            && let Some(key) = reaction.key.as_ref()
        {
            return history_message_event_key_from_proto(key);
        }
        if let Some(pin) = message_content.pin_in_chat_message.as_ref()
            && let Some(key) = pin.key.as_ref()
        {
            return history_message_event_key_from_proto(key);
        }
    }
    Err(CoreError::Protocol(
        "history message add-on missing target key".to_owned(),
    ))
}

fn history_message_add_on_type_name(add_on_type: Option<i32>) -> &'static str {
    match message_add_on::MessageAddOnType::try_from(add_on_type.unwrap_or_default()).ok() {
        Some(message_add_on::MessageAddOnType::Reaction) => "reaction",
        Some(message_add_on::MessageAddOnType::EventResponse) => "event_response",
        Some(message_add_on::MessageAddOnType::PollUpdate) => "poll_update",
        Some(message_add_on::MessageAddOnType::PinInChat) => "pin_in_chat",
        Some(message_add_on::MessageAddOnType::Undefined) | None => "undefined",
    }
}

fn apply_event_response_message_fields(
    mut update: MessageUpdate,
    response: &wa_proto::proto::message::EventResponseMessage,
) -> CoreResult<MessageUpdate> {
    update = update.with_field("event_response", "true").with_field(
        "response",
        match event_response_message::EventResponseType::try_from(
            response.response.unwrap_or_default(),
        )
        .ok()
        {
            Some(event_response_message::EventResponseType::Going) => "going",
            Some(event_response_message::EventResponseType::NotGoing) => "not_going",
            Some(event_response_message::EventResponseType::Maybe) => "maybe",
            Some(event_response_message::EventResponseType::Unknown) | None => "unknown",
        },
    );
    if let Some(extra_guest_count) = response.extra_guest_count {
        update = update.with_field("extra_guest_count", extra_guest_count.to_string());
    }
    if let Some(response_timestamp_ms) = response.timestamp_ms {
        update = update.with_field(
            "response_timestamp_ms",
            non_negative_i64_to_u64(
                response_timestamp_ms,
                "history event response message timestamp",
            )?
            .to_string(),
        );
    }
    Ok(update)
}

fn push_history_call_log_events(
    calls: &mut Vec<CallEvent>,
    records: &[CallLogRecord],
    max_calls: usize,
) -> CoreResult<()> {
    for (index, record) in records.iter().enumerate() {
        ensure_capacity(calls.len(), max_calls, "history call logs")?;
        calls.push(history_call_log_event(record, index)?);
    }
    Ok(())
}

fn history_call_log_event(record: &CallLogRecord, index: usize) -> CoreResult<CallEvent> {
    let from = history_call_log_from_jid(record)?;
    let id = history_call_log_id(record, index);
    let mut event =
        CallEvent::new(id, from, "history_log").with_field("source", "history_call_log");

    if let Some(call_id) = record.call_id.as_deref().filter(|value| !value.is_empty()) {
        event = event.with_call_id(call_id.to_owned());
    }
    if let Some(participant) = history_call_log_single_participant(record)? {
        event = event.with_participant(participant);
    }
    if let Some(start_time) = record.start_time {
        let start_time = non_negative_i64_to_u64(start_time, "history call log start time")?;
        event = event
            .with_timestamp(start_time)
            .with_field("start_time", start_time.to_string());
    }

    event = add_opt_enum_field(event, "call_result", record.call_result, call_result_name);
    event = add_opt_enum_field(event, "call_type", record.call_type, call_type_name);
    event = add_opt_enum_field(
        event,
        "silence_reason",
        record.silence_reason,
        silence_reason_name,
    );
    event = add_opt_i64_field(
        event,
        "duration",
        record.duration,
        "history call log duration",
    )?;
    event = add_opt_bool_field(event, "is_dnd_mode", record.is_dnd_mode);
    event = add_opt_bool_field(event, "is_incoming", record.is_incoming);
    event = add_opt_bool_field(event, "is_video", record.is_video);
    event = add_opt_bool_field(event, "is_call_link", record.is_call_link);
    event = add_opt_field(event, "call_link_token", record.call_link_token.as_deref());
    event = add_opt_field(
        event,
        "scheduled_call_id",
        record.scheduled_call_id.as_deref(),
    );
    event = add_opt_field(
        event,
        "call_creator_jid",
        record.call_creator_jid.as_deref(),
    );
    event = add_opt_field(event, "group_jid", record.group_jid.as_deref());

    if !record.participants.is_empty() {
        event = event
            .with_field("participants_count", record.participants.len().to_string())
            .with_field(
                "participants",
                history_call_log_participants_json(&record.participants)?,
            );
    }

    Ok(event)
}

fn history_call_log_from_jid(record: &CallLogRecord) -> CoreResult<String> {
    for (label, jid) in [
        ("history call log group JID", record.group_jid.as_deref()),
        (
            "history call log creator JID",
            record.call_creator_jid.as_deref(),
        ),
    ] {
        if let Some(jid) = jid.filter(|value| !value.is_empty()) {
            validate_jid(label, jid)?;
            return Ok(jid.to_owned());
        }
    }
    for participant in &record.participants {
        if let Some(jid) = participant
            .user_jid
            .as_deref()
            .filter(|value| !value.is_empty())
        {
            validate_jid("history call log participant JID", jid)?;
            return Ok(jid.to_owned());
        }
    }
    Err(CoreError::Protocol(
        "history call log missing group, creator, or participant JID".to_owned(),
    ))
}

fn history_call_log_id(record: &CallLogRecord, index: usize) -> String {
    for value in [
        record.call_id.as_deref(),
        record.scheduled_call_id.as_deref(),
        record.call_link_token.as_deref(),
    ] {
        if let Some(value) = value.filter(|value| !value.is_empty()) {
            return value.to_owned();
        }
    }
    format!(
        "history-call-{index}-{}",
        record.start_time.unwrap_or_default()
    )
}

fn history_call_log_single_participant(record: &CallLogRecord) -> CoreResult<Option<String>> {
    let mut participants = record
        .participants
        .iter()
        .filter_map(|participant| participant.user_jid.as_deref())
        .filter(|jid| !jid.is_empty());
    let Some(first) = participants.next() else {
        return Ok(None);
    };
    validate_jid("history call log participant JID", first)?;
    if participants.next().is_some() {
        return Ok(None);
    }
    Ok(Some(first.to_owned()))
}

fn history_call_log_participants_json(
    participants: &[call_log_record::ParticipantInfo],
) -> CoreResult<String> {
    let mut values = Vec::with_capacity(participants.len());
    for participant in participants {
        let mut value = serde_json::Map::new();
        if let Some(jid) = participant
            .user_jid
            .as_deref()
            .filter(|jid| !jid.is_empty())
        {
            validate_jid("history call log participant JID", jid)?;
            value.insert("jid".to_owned(), serde_json::Value::String(jid.to_owned()));
        }
        if let Some(result) = participant.call_result {
            value.insert(
                "callResult".to_owned(),
                serde_json::Value::String(call_result_name(result).to_owned()),
            );
        }
        values.push(serde_json::Value::Object(value));
    }
    serde_json::to_string(&values).map_err(|err| {
        CoreError::Protocol(format!(
            "failed to encode history call log participants: {err}"
        ))
    })
}

fn add_opt_enum_field(
    event: CallEvent,
    key: &'static str,
    value: Option<i32>,
    name: fn(i32) -> &'static str,
) -> CallEvent {
    match value {
        Some(value) => event.with_field(key, name(value)),
        None => event,
    }
}

fn add_opt_i64_field(
    event: CallEvent,
    key: &'static str,
    value: Option<i64>,
    label: &'static str,
) -> CoreResult<CallEvent> {
    match value {
        Some(value) => {
            Ok(event.with_field(key, non_negative_i64_to_u64(value, label)?.to_string()))
        }
        None => Ok(event),
    }
}

fn call_result_name(value: i32) -> &'static str {
    call_log_record::CallResult::try_from(value).map_or("UNKNOWN", |value| value.as_str_name())
}

fn call_type_name(value: i32) -> &'static str {
    call_log_record::CallType::try_from(value).map_or("UNKNOWN", |value| value.as_str_name())
}

fn silence_reason_name(value: i32) -> &'static str {
    call_log_record::SilenceReason::try_from(value).map_or("UNKNOWN", |value| value.as_str_name())
}

fn push_history_past_participant_events(
    groups: &mut Vec<GroupUpdateEvent>,
    records: &[PastParticipants],
    max_groups: usize,
    max_participants: usize,
) -> CoreResult<()> {
    let mut participant_count = 0usize;
    for record in records {
        let Some(event) =
            history_past_participants_event(record, max_participants, &mut participant_count)?
        else {
            continue;
        };
        ensure_capacity(groups.len(), max_groups, "history past participant groups")?;
        groups.push(event);
    }
    Ok(())
}

fn history_past_participants_event(
    record: &PastParticipants,
    max_participants: usize,
    participant_count: &mut usize,
) -> CoreResult<Option<GroupUpdateEvent>> {
    if record.past_participants.is_empty() {
        return Ok(None);
    }

    let group_jid = record
        .group_jid
        .as_deref()
        .filter(|jid| !jid.is_empty())
        .ok_or_else(|| {
            CoreError::Protocol("history past participants missing group JID".to_owned())
        })
        .and_then(|jid| validate_jid("history past participant group JID", jid))?;

    let mut leave = Vec::new();
    let mut remove = Vec::new();
    let mut unknown = Vec::new();
    let mut all_reasons = Vec::new();
    let mut all_timestamps = Vec::new();

    for participant in &record.past_participants {
        ensure_capacity(
            *participant_count,
            max_participants,
            "history past participants",
        )?;
        *participant_count += 1;
        let entry = history_past_participant_entry(participant)?;
        all_reasons.push(format!("{}={}", entry.jid, entry.reason));
        if let Some(timestamp) = entry.timestamp {
            all_timestamps.push(format!("{}={timestamp}", entry.jid));
        }
        match entry.reason {
            "LEFT" => leave.push(entry),
            "REMOVED" => remove.push(entry),
            _ => unknown.push(entry),
        }
    }

    let mut event = GroupUpdateEvent::new(group_jid)
        .with_field("source", "history_past_participants")
        .with_field(
            "past_participants_count",
            record.past_participants.len().to_string(),
        );
    event = add_past_participant_fields(event, "leave", &leave);
    event = add_past_participant_fields(event, "remove", &remove);
    event = add_past_participant_fields(event, "past", &unknown);
    if !all_reasons.is_empty() {
        event = event.with_field("past_participant_reasons", all_reasons.join(","));
    }
    if !all_timestamps.is_empty() {
        event = event.with_field("past_participant_timestamps", all_timestamps.join(","));
    }
    Ok(Some(event))
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct HistoryPastParticipantEntry {
    jid: String,
    reason: &'static str,
    timestamp: Option<u64>,
}

fn history_past_participant_entry(
    participant: &PastParticipant,
) -> CoreResult<HistoryPastParticipantEntry> {
    let jid = participant
        .user_jid
        .as_deref()
        .filter(|jid| !jid.is_empty())
        .ok_or_else(|| CoreError::Protocol("history past participant missing JID".to_owned()))
        .and_then(|jid| validate_jid("history past participant JID", jid))?;
    Ok(HistoryPastParticipantEntry {
        jid: jid.to_owned(),
        reason: past_participant_reason_name(participant.leave_reason),
        timestamp: participant.leave_ts,
    })
}

fn add_past_participant_fields(
    mut event: GroupUpdateEvent,
    action: &'static str,
    entries: &[HistoryPastParticipantEntry],
) -> GroupUpdateEvent {
    if entries.is_empty() {
        return event;
    }
    let prefix = format!("participants_{action}");
    event = event
        .with_field(
            prefix.clone(),
            entries
                .iter()
                .map(|entry| entry.jid.as_str())
                .collect::<Vec<_>>()
                .join(","),
        )
        .with_field(format!("{prefix}_count"), entries.len().to_string());
    let timestamps = entries
        .iter()
        .filter_map(|entry| {
            entry
                .timestamp
                .map(|timestamp| format!("{}={timestamp}", entry.jid))
        })
        .collect::<Vec<_>>();
    if !timestamps.is_empty() {
        event = event.with_field(format!("{prefix}_timestamps"), timestamps.join(","));
    }
    event
}

fn past_participant_reason_name(value: Option<i32>) -> &'static str {
    value
        .and_then(|value| past_participant::LeaveReason::try_from(value).ok())
        .map_or("UNKNOWN", |value| value.as_str_name())
}

fn history_message_event_key_from_proto(key: &MessageKey) -> CoreResult<MessageEventKey> {
    let remote_jid = key
        .remote_jid
        .as_deref()
        .ok_or_else(|| CoreError::Protocol("history update target missing remote JID".to_owned()))
        .and_then(|jid| validate_jid("history update target remote JID", jid))?;
    let id = key
        .id
        .as_deref()
        .filter(|id| !id.is_empty())
        .ok_or_else(|| CoreError::Protocol("history update target missing id".to_owned()))?;
    let participant = match key.participant.as_deref() {
        Some(participant) if !participant.is_empty() => {
            validate_jid("history update target participant JID", participant)?;
            Some(participant.to_owned())
        }
        _ => None,
    };
    Ok(MessageEventKey::new(remote_jid, id, participant))
}

fn history_default_disappearing_mode(
    settings: Option<&GlobalSettings>,
) -> CoreResult<Option<DefaultDisappearingMode>> {
    let Some(settings) = settings else {
        return Ok(None);
    };
    let Some(duration) = settings.disappearing_mode_duration else {
        return Ok(None);
    };
    let duration = u32::try_from(duration).map_err(|_| {
        CoreError::Protocol("history global settings disappearing duration is negative".to_owned())
    })?;
    let mut mode = DefaultDisappearingMode::new(duration);
    if let Some(timestamp) = settings.disappearing_mode_timestamp {
        let timestamp = u64::try_from(timestamp).map_err(|_| {
            CoreError::Protocol(
                "history global settings disappearing timestamp is negative".to_owned(),
            )
        })?;
        mode = mode.with_timestamp(timestamp);
    }
    Ok(Some(mode))
}

fn collect_direct_mappings(
    history: &HistorySync,
    mappings: &mut Vec<HistoryLidPnMapping>,
) -> CoreResult<()> {
    for mapping in &history.phone_number_to_lid_mappings {
        let (Some(pn_jid), Some(lid_jid)) = (&mapping.pn_jid, &mapping.lid_jid) else {
            continue;
        };
        push_mapping(mappings, lid_jid, pn_jid)?;
    }
    Ok(())
}

fn collect_conversation_mappings(
    conversation: &Conversation,
    chat_jid: &str,
    mappings: &mut Vec<HistoryLidPnMapping>,
) -> CoreResult<()> {
    if let Some(pn_jid) = conversation.pn_jid.as_deref()
        && (conversation
            .lid_jid
            .as_deref()
            .is_some_and(|lid| lid == chat_jid)
            || conversation
                .account_lid
                .as_deref()
                .is_some_and(|lid| lid == chat_jid)
            || is_lid_jid(chat_jid))
    {
        push_mapping(mappings, chat_jid, pn_jid)?;
    }
    if let Some(lid_jid) = conversation
        .lid_jid
        .as_deref()
        .or(conversation.account_lid.as_deref())
        && is_pn_jid(chat_jid)
    {
        push_mapping(mappings, lid_jid, chat_jid)?;
    }
    Ok(())
}

fn push_mapping(
    mappings: &mut Vec<HistoryLidPnMapping>,
    lid_jid: &str,
    pn_jid: &str,
) -> CoreResult<()> {
    validate_jid("history LID mapping", lid_jid)?;
    validate_jid("history PN mapping", pn_jid)?;
    if mappings
        .iter()
        .any(|mapping| mapping.lid_jid == lid_jid && mapping.pn_jid == pn_jid)
    {
        return Ok(());
    }
    mappings.push(HistoryLidPnMapping {
        lid_jid: lid_jid.to_owned(),
        pn_jid: pn_jid.to_owned(),
    });
    Ok(())
}

fn inflate_zlib_bounded(compressed: &[u8], max_bytes: usize) -> CoreResult<Bytes> {
    if max_bytes == 0 {
        return Err(CoreError::Payload(
            "history sync inflate limit must be greater than zero".to_owned(),
        ));
    }
    let mut decoder = ZlibDecoder::new(compressed);
    let mut output = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        let read = decoder
            .read(&mut chunk)
            .map_err(|err| CoreError::Payload(format!("failed to inflate history sync: {err}")))?;
        if read == 0 {
            break;
        }
        if output.len().saturating_add(read) > max_bytes {
            return Err(CoreError::Payload(format!(
                "inflated history sync exceeds configured limit: {} bytes exceeds {max_bytes}",
                output.len().saturating_add(read)
            )));
        }
        output.extend_from_slice(&chunk[..read]);
    }
    Ok(Bytes::from(output))
}

#[cfg(feature = "noise")]
fn required_notification_bytes(bytes: Option<&Bytes>, label: &str) -> CoreResult<Bytes> {
    bytes
        .cloned()
        .filter(|bytes| !bytes.is_empty())
        .ok_or_else(|| CoreError::Payload(format!("history sync notification missing {label}")))
}

#[cfg(feature = "noise")]
fn validate_notification_len(label: &str, bytes: &[u8], expected: usize) -> CoreResult<()> {
    if bytes.len() != expected {
        return Err(CoreError::Payload(format!(
            "history sync notification {label} must be {expected} bytes"
        )));
    }
    Ok(())
}

#[cfg(feature = "noise")]
fn validate_declared_history_size(media: &UploadedMedia, max_download: usize) -> CoreResult<()> {
    if max_download == 0 {
        return Err(CoreError::Payload(
            "history sync download size limit must be greater than zero".to_owned(),
        ));
    }
    let declared_len = usize::try_from(media.file_length)
        .map_err(|_| CoreError::Payload("history sync declared size exceeds usize".to_owned()))?;
    if declared_len > max_download {
        return Err(CoreError::Payload(format!(
            "history sync declared size exceeds configured limit: {declared_len} bytes exceeds {max_download}"
        )));
    }
    Ok(())
}

fn add_opt_field<T>(event: T, key: &str, value: Option<&str>) -> T
where
    T: FieldEvent,
{
    if let Some(value) = value.filter(|value| !value.is_empty()) {
        event.with_field_value(key, value.to_owned())
    } else {
        event
    }
}

fn add_opt_number_field<T, N>(event: T, key: &str, value: Option<N>) -> T
where
    T: FieldEvent,
    N: ToString,
{
    if let Some(value) = value {
        event.with_field_value(key, value.to_string())
    } else {
        event
    }
}

fn add_opt_bool_field<T>(event: T, key: &str, value: Option<bool>) -> T
where
    T: FieldEvent,
{
    if let Some(value) = value {
        event.with_field_value(key, value.to_string())
    } else {
        event
    }
}

trait FieldEvent: Sized {
    fn with_field_value(self, key: &str, value: String) -> Self;
}

impl FieldEvent for ChatEvent {
    fn with_field_value(self, key: &str, value: String) -> Self {
        self.with_field(key, value)
    }
}

impl FieldEvent for ContactEvent {
    fn with_field_value(self, key: &str, value: String) -> Self {
        self.with_field(key, value)
    }
}

impl FieldEvent for CallEvent {
    fn with_field_value(self, key: &str, value: String) -> Self {
        self.with_field(key, value)
    }
}

impl FieldEvent for RecentStickerEvent {
    fn with_field_value(self, key: &str, value: String) -> Self {
        self.with_field(key, value)
    }
}

impl FieldEvent for AccountSettingsEvent {
    fn with_field_value(self, key: &str, value: String) -> Self {
        self.with_field(key, value)
    }
}

fn ensure_capacity(current: usize, max: usize, label: &str) -> CoreResult<()> {
    if current >= max {
        return Err(CoreError::Payload(format!(
            "{label} exceeds configured item limit: {current} items reaches {max}"
        )));
    }
    Ok(())
}

fn validate_jid<'a>(label: &str, jid: &'a str) -> CoreResult<&'a str> {
    if jid.is_empty() {
        return Err(CoreError::Protocol(format!("{label} must not be empty")));
    }
    jid_decode(jid).ok_or_else(|| CoreError::Protocol(format!("invalid {label}: {jid}")))?;
    Ok(jid)
}

fn non_negative_i64_to_u64(value: i64, label: &str) -> CoreResult<u64> {
    u64::try_from(value).map_err(|_| CoreError::Protocol(format!("{label} must be non-negative")))
}

fn is_lid_jid(jid: &str) -> bool {
    jid_decode(jid)
        .is_some_and(|decoded| matches!(decoded.server, JidServer::Lid | JidServer::HostedLid))
}

fn is_pn_jid(jid: &str) -> bool {
    jid_decode(jid)
        .is_some_and(|decoded| matches!(decoded.server, JidServer::SWhatsAppNet | JidServer::CUs))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "noise")]
    use async_trait::async_trait;
    use flate2::{Compression, write::ZlibEncoder};
    #[cfg(feature = "noise")]
    use std::collections::BTreeMap;
    use std::io::Write as _;
    #[cfg(feature = "noise")]
    use std::sync::{Arc, Mutex};
    use wa_proto::proto::{HistorySyncMsg, Message, MessageKey, Reaction, WebMessageInfo};

    #[test]
    fn decodes_inline_history_sync_and_processes_event_batch() {
        let history = sample_history_sync();
        let compressed = compress_history(&history);
        let notification = HistorySyncNotification {
            initial_hist_bootstrap_inline_payload: Some(compressed),
            ..Default::default()
        };

        let decoded = decode_inline_history_sync(&notification, HistorySyncDecodeConfig::default())
            .unwrap()
            .unwrap();
        let processed =
            process_history_sync(&decoded, HistorySyncProcessConfig::default().latest(true))
                .unwrap();

        assert_eq!(processed.sync_type, HistorySyncType::InitialBootstrap);
        assert_eq!(processed.progress, Some(50));
        assert_eq!(
            processed.lid_pn_mappings,
            vec![HistoryLidPnMapping {
                lid_jid: "123@lid".to_owned(),
                pn_jid: "123@s.whatsapp.net".to_owned()
            }]
        );
        let history = processed.batch.history.unwrap();
        assert!(history.is_latest);
        assert_eq!(history.chats.len(), 1);
        assert_eq!(history.contacts.len(), 1);
        assert_eq!(history.messages.len(), 1);
        assert_eq!(history.chats[0].jid, "123@s.whatsapp.net");
        assert_eq!(history.chats[0].fields["display_name"], "Alice");
        assert_eq!(history.contacts[0].fields["name"], "Alice");
        assert_eq!(history.messages[0].key.remote_jid, "123@s.whatsapp.net");
        assert_eq!(history.messages[0].key.id, "msg-1");
        assert!(
            history.messages[0]
                .payload
                .as_ref()
                .is_some_and(|payload| !payload.is_empty())
        );
        assert_eq!(
            history.messages[0].fields["history_sync_type"],
            "INITIAL_BOOTSTRAP"
        );
    }

    #[test]
    fn processes_inline_history_sync_notification_without_transfer() {
        let history = sample_history_sync();
        let notification = HistorySyncNotification {
            initial_hist_bootstrap_inline_payload: Some(compress_history(&history)),
            ..Default::default()
        };

        let processed = process_inline_history_sync_notification(
            &notification,
            HistorySyncDecodeConfig::default(),
            HistorySyncProcessConfig::default().latest(true),
        )
        .unwrap()
        .unwrap();

        assert_eq!(processed.sync_type, HistorySyncType::InitialBootstrap);
        assert_eq!(processed.progress, Some(50));
        let history = processed.batch.history.as_ref().unwrap();
        assert!(history.is_latest);
        assert_eq!(history.messages[0].key.id, "msg-1");

        assert!(
            process_inline_history_sync_notification(
                &HistorySyncNotification::default(),
                HistorySyncDecodeConfig::default(),
                HistorySyncProcessConfig::default(),
            )
            .unwrap()
            .is_none()
        );
    }

    #[test]
    fn extracts_history_sync_notifications_from_message_event_payload_formats() {
        let notification = HistorySyncNotification {
            direct_path: Some("/history/sync".to_owned()),
            file_length: Some(7),
            sync_type: Some(wa_proto::proto::message::HistorySyncType::InitialBootstrap as i32),
            ..Default::default()
        };
        let protocol_message = Message {
            protocol_message: Some(Box::new(wa_proto::proto::message::ProtocolMessage {
                r#type: Some(
                    wa_proto::proto::message::protocol_message::Type::HistorySyncNotification
                        as i32,
                ),
                history_sync_notification: Some(notification.clone()),
                ..Default::default()
            })),
            ..Default::default()
        };
        let key = MessageEventKey::new("123@s.whatsapp.net", "history-notify", None);
        let bare_event = MessageEvent::new(key.clone())
            .with_payload(Bytes::from(protocol_message.encode_to_vec()));

        assert_eq!(
            history_sync_notifications_from_message_event(&bare_event).unwrap(),
            vec![notification.clone()]
        );

        let web_message = WebMessageInfo {
            message: Some(protocol_message),
            ..Default::default()
        };
        let web_event = MessageEvent::new(key)
            .with_payload(Bytes::from(web_message.encode_to_vec()))
            .with_field("history_sync_type", "INITIAL_BOOTSTRAP");

        assert_eq!(
            history_sync_notifications_from_message_event(&web_event).unwrap(),
            vec![notification]
        );
    }

    #[test]
    fn processes_history_web_message_poll_and_event_updates() {
        let poll_key = MessageKey {
            remote_jid: Some("123@g.us".to_owned()),
            from_me: Some(false),
            id: Some("poll-creation-1".to_owned()),
            participant: Some("456@s.whatsapp.net".to_owned()),
        };
        let event_key = MessageKey {
            remote_jid: Some("123@g.us".to_owned()),
            from_me: Some(false),
            id: Some("event-creation-1".to_owned()),
            participant: Some("456@s.whatsapp.net".to_owned()),
        };
        let history = HistorySync {
            sync_type: HistorySyncType::InitialBootstrap as i32,
            conversations: vec![Conversation {
                id: "123@g.us".to_owned(),
                messages: vec![HistorySyncMsg {
                    msg_order_id: Some(8),
                    message: Some(WebMessageInfo {
                        key: Some(MessageKey {
                            remote_jid: Some("123@g.us".to_owned()),
                            from_me: Some(false),
                            id: Some("history-wrapper-1".to_owned()),
                            participant: Some("789@s.whatsapp.net".to_owned()),
                        }),
                        message_timestamp: Some(1_700_000_010),
                        poll_updates: vec![PollUpdate {
                            poll_update_message_key: Some(poll_key.clone()),
                            vote: Some(wa_proto::proto::message::PollVoteMessage {
                                selected_options: vec![Bytes::from_static(b"option-a")],
                            }),
                            sender_timestamp_ms: Some(1_700_000_011_123),
                            server_timestamp_ms: Some(1_700_000_011_456),
                            unread: Some(true),
                        }],
                        event_responses: vec![EventResponse {
                            event_response_message_key: Some(event_key.clone()),
                            timestamp_ms: Some(1_700_000_012_123),
                            event_response_message: Some(
                                wa_proto::proto::message::EventResponseMessage {
                                    response: Some(
                                        event_response_message::EventResponseType::Going as i32,
                                    ),
                                    timestamp_ms: Some(1_700_000_012_456),
                                    extra_guest_count: Some(2),
                                },
                            ),
                            unread: Some(false),
                        }],
                        ..Default::default()
                    }),
                }],
                ..Default::default()
            }],
            ..Default::default()
        };

        let processed =
            process_history_sync(&history, HistorySyncProcessConfig::default()).unwrap();
        let history = processed.batch.history.as_ref().unwrap();
        assert_eq!(history.messages.len(), 1);
        assert_eq!(history.messages[0].key.id, "history-wrapper-1");
        assert_eq!(processed.batch.messages_update.len(), 2);

        let poll_update = &processed.batch.messages_update[0];
        assert_eq!(
            poll_update.key,
            history_message_event_key_from_proto(&poll_key).unwrap()
        );
        assert_eq!(poll_update.timestamp, Some(1_700_000_011_123));
        assert_eq!(poll_update.fields["source"], "history_poll_update");
        assert_eq!(poll_update.fields["poll_update"], "true");
        assert_eq!(poll_update.fields["vote_present"], "true");
        assert_eq!(poll_update.fields["selected_options_count"], "1");
        assert_eq!(poll_update.fields["unread"], "true");
        assert_eq!(poll_update.fields["server_timestamp_ms"], "1700000011456");

        let event_update = &processed.batch.messages_update[1];
        assert_eq!(
            event_update.key,
            history_message_event_key_from_proto(&event_key).unwrap()
        );
        assert_eq!(event_update.timestamp, Some(1_700_000_012_123));
        assert_eq!(event_update.fields["source"], "history_event_response");
        assert_eq!(event_update.fields["event_response"], "true");
        assert_eq!(event_update.fields["response_present"], "true");
        assert_eq!(event_update.fields["response"], "going");
        assert_eq!(event_update.fields["extra_guest_count"], "2");
        assert_eq!(
            event_update.fields["response_timestamp_ms"],
            "1700000012456"
        );
        assert_eq!(event_update.fields["unread"], "false");
    }

    #[test]
    fn processes_history_web_message_message_add_ons() {
        let poll_key = MessageKey {
            remote_jid: Some("123@g.us".to_owned()),
            from_me: Some(false),
            id: Some("poll-creation-1".to_owned()),
            participant: Some("456@s.whatsapp.net".to_owned()),
        };
        let event_key = MessageKey {
            remote_jid: Some("123@g.us".to_owned()),
            from_me: Some(false),
            id: Some("event-creation-1".to_owned()),
            participant: Some("456@s.whatsapp.net".to_owned()),
        };
        let pin_key = MessageKey {
            remote_jid: Some("123@g.us".to_owned()),
            from_me: Some(false),
            id: Some("pin-target-1".to_owned()),
            participant: Some("456@s.whatsapp.net".to_owned()),
        };
        let history = HistorySync {
            sync_type: HistorySyncType::InitialBootstrap as i32,
            conversations: vec![Conversation {
                id: "123@g.us".to_owned(),
                messages: vec![HistorySyncMsg {
                    msg_order_id: Some(10),
                    message: Some(WebMessageInfo {
                        key: Some(MessageKey {
                            remote_jid: Some("123@g.us".to_owned()),
                            from_me: Some(false),
                            id: Some("history-wrapper-2".to_owned()),
                            participant: Some("789@s.whatsapp.net".to_owned()),
                        }),
                        message_timestamp: Some(1_700_000_013),
                        message_add_ons: vec![
                            MessageAddOn {
                                message_add_on_type: Some(
                                    message_add_on::MessageAddOnType::PollUpdate as i32,
                                ),
                                sender_timestamp_ms: Some(1_700_000_014_123),
                                server_timestamp_ms: Some(1_700_000_014_456),
                                add_on_context_info: Some(
                                    wa_proto::proto::MessageAddOnContextInfo {
                                        message_add_on_duration_in_secs: Some(3600),
                                        message_add_on_expiry_type: Some(1),
                                    },
                                ),
                                message_add_on_key: Some(poll_key.clone()),
                                legacy_message: Some(wa_proto::proto::LegacyMessage {
                                    poll_vote: Some(wa_proto::proto::message::PollVoteMessage {
                                        selected_options: vec![
                                            Bytes::from_static(b"option-a"),
                                            Bytes::from_static(b"option-b"),
                                        ],
                                    }),
                                    ..Default::default()
                                }),
                                ..Default::default()
                            },
                            MessageAddOn {
                                message_add_on_type: Some(
                                    message_add_on::MessageAddOnType::EventResponse as i32,
                                ),
                                sender_timestamp_ms: Some(1_700_000_015_123),
                                message_add_on_key: Some(event_key.clone()),
                                legacy_message: Some(wa_proto::proto::LegacyMessage {
                                    event_response_message: Some(
                                        wa_proto::proto::message::EventResponseMessage {
                                            response: Some(
                                                event_response_message::EventResponseType::Maybe
                                                    as i32,
                                            ),
                                            timestamp_ms: Some(1_700_000_015_456),
                                            extra_guest_count: Some(1),
                                        },
                                    ),
                                    ..Default::default()
                                }),
                                ..Default::default()
                            },
                            MessageAddOn {
                                message_add_on_type: Some(
                                    message_add_on::MessageAddOnType::PollUpdate as i32,
                                ),
                                sender_timestamp_ms: Some(1_700_000_016_123),
                                message_add_on: Some(Message {
                                    view_once_message: Some(Box::new(
                                        wa_proto::proto::message::FutureProofMessage {
                                            message: Some(Box::new(Message {
                                                poll_update_message: Some(
                                                    wa_proto::proto::message::PollUpdateMessage {
                                                        poll_creation_message_key: Some(
                                                            poll_key.clone(),
                                                        ),
                                                        vote: Some(
                                                            wa_proto::proto::message::PollEncValue {
                                                                enc_payload: Some(
                                                                    Bytes::from_static(
                                                                        b"wrapped-vote",
                                                                    ),
                                                                ),
                                                                enc_iv: Some(Bytes::from_static(
                                                                    b"wrapped-iv",
                                                                )),
                                                            },
                                                        ),
                                                        metadata: Some(Default::default()),
                                                        sender_timestamp_ms: Some(
                                                            1_700_000_016_456,
                                                        ),
                                                    },
                                                ),
                                                ..Default::default()
                                            })),
                                        },
                                    )),
                                    ..Default::default()
                                }),
                                ..Default::default()
                            },
                            MessageAddOn {
                                message_add_on_type: Some(
                                    message_add_on::MessageAddOnType::PinInChat as i32,
                                ),
                                sender_timestamp_ms: Some(1_700_000_017_123),
                                message_add_on: Some(Message {
                                    view_once_message: Some(Box::new(
                                        wa_proto::proto::message::FutureProofMessage {
                                            message: Some(Box::new(Message {
                                                pin_in_chat_message: Some(
                                                    wa_proto::proto::message::PinInChatMessage {
                                                        key: Some(pin_key.clone()),
                                                        r#type: Some(
                                                            pin_in_chat_message::Type::PinForAll
                                                                as i32,
                                                        ),
                                                        sender_timestamp_ms: Some(
                                                            1_700_000_017_456,
                                                        ),
                                                    },
                                                ),
                                                ..Default::default()
                                            })),
                                        },
                                    )),
                                    ..Default::default()
                                }),
                                ..Default::default()
                            },
                        ],
                        ..Default::default()
                    }),
                }],
                ..Default::default()
            }],
            ..Default::default()
        };

        let processed =
            process_history_sync(&history, HistorySyncProcessConfig::default()).unwrap();
        let history = processed.batch.history.as_ref().unwrap();
        assert_eq!(history.messages.len(), 1);
        assert_eq!(history.messages[0].key.id, "history-wrapper-2");
        assert_eq!(processed.batch.messages_update.len(), 4);

        let poll_update = &processed.batch.messages_update[0];
        assert_eq!(
            poll_update.key,
            history_message_event_key_from_proto(&poll_key).unwrap()
        );
        assert_eq!(poll_update.timestamp, Some(1_700_000_014_123));
        assert_eq!(poll_update.fields["source"], "history_message_add_on");
        assert_eq!(poll_update.fields["add_on_type"], "poll_update");
        assert_eq!(poll_update.fields["poll_update"], "true");
        assert_eq!(poll_update.fields["selected_options_count"], "2");
        assert_eq!(poll_update.fields["legacy_message_present"], "true");
        assert_eq!(poll_update.fields["add_on_duration_secs"], "3600");
        assert_eq!(poll_update.fields["add_on_expiry_type"], "1");
        assert_eq!(poll_update.fields["server_timestamp_ms"], "1700000014456");

        let event_update = &processed.batch.messages_update[1];
        assert_eq!(
            event_update.key,
            history_message_event_key_from_proto(&event_key).unwrap()
        );
        assert_eq!(event_update.timestamp, Some(1_700_000_015_123));
        assert_eq!(event_update.fields["source"], "history_message_add_on");
        assert_eq!(event_update.fields["add_on_type"], "event_response");
        assert_eq!(event_update.fields["event_response"], "true");
        assert_eq!(event_update.fields["response"], "maybe");
        assert_eq!(event_update.fields["extra_guest_count"], "1");
        assert_eq!(
            event_update.fields["response_timestamp_ms"],
            "1700000015456"
        );

        let wrapped_poll_update = &processed.batch.messages_update[2];
        assert_eq!(
            wrapped_poll_update.key,
            history_message_event_key_from_proto(&poll_key).unwrap()
        );
        assert_eq!(wrapped_poll_update.timestamp, Some(1_700_000_016_123));
        assert_eq!(
            wrapped_poll_update.fields["source"],
            "history_message_add_on"
        );
        assert_eq!(wrapped_poll_update.fields["add_on_stanza_type"], "poll");
        assert_eq!(wrapped_poll_update.fields["poll_update"], "true");
        assert_eq!(wrapped_poll_update.fields["vote_encrypted"], "true");
        assert_eq!(
            wrapped_poll_update.fields["encrypted_vote_payload_bytes"],
            "12"
        );
        assert_eq!(wrapped_poll_update.fields["encrypted_vote_iv_bytes"], "10");

        let wrapped_pin_update = &processed.batch.messages_update[3];
        assert_eq!(
            wrapped_pin_update.key,
            history_message_event_key_from_proto(&pin_key).unwrap()
        );
        assert_eq!(wrapped_pin_update.timestamp, Some(1_700_000_017_123));
        assert_eq!(
            wrapped_pin_update.fields["source"],
            "history_message_add_on"
        );
        assert_eq!(wrapped_pin_update.fields["add_on_type"], "pin_in_chat");
        assert_eq!(wrapped_pin_update.fields["add_on_stanza_type"], "text");
        assert_eq!(wrapped_pin_update.fields["pin_action"], "pin");
    }

    #[test]
    fn processes_history_web_message_reactions() {
        let target_key = MessageKey {
            remote_jid: Some("123@g.us".to_owned()),
            from_me: Some(false),
            id: Some("target-1".to_owned()),
            participant: Some("456@s.whatsapp.net".to_owned()),
        };
        let history = HistorySync {
            sync_type: HistorySyncType::InitialBootstrap as i32,
            conversations: vec![Conversation {
                id: "123@g.us".to_owned(),
                messages: vec![HistorySyncMsg {
                    msg_order_id: Some(11),
                    message: Some(WebMessageInfo {
                        key: Some(target_key.clone()),
                        message_timestamp: Some(1_700_000_016),
                        reactions: vec![Reaction {
                            key: Some(MessageKey {
                                remote_jid: Some("123@g.us".to_owned()),
                                from_me: Some(false),
                                id: Some("reaction-1".to_owned()),
                                participant: Some("789@s.whatsapp.net".to_owned()),
                            }),
                            text: Some("+".to_owned()),
                            sender_timestamp_ms: Some(1_700_000_016_123),
                            unread: Some(true),
                            ..Default::default()
                        }],
                        ..Default::default()
                    }),
                }],
                ..Default::default()
            }],
            ..Default::default()
        };

        let processed =
            process_history_sync(&history, HistorySyncProcessConfig::default()).unwrap();
        let history = processed.batch.history.as_ref().unwrap();
        assert_eq!(history.messages.len(), 1);
        assert_eq!(history.messages[0].key.id, "target-1");
        assert!(processed.batch.messages_update.is_empty());
        assert_eq!(processed.batch.reactions_update.len(), 1);

        let reaction = &processed.batch.reactions_update[0];
        assert_eq!(
            reaction.key,
            history_message_event_key_from_proto(&target_key).unwrap()
        );
        assert_eq!(reaction.from_jid, "789@s.whatsapp.net");
        assert_eq!(reaction.text.as_deref(), Some("+"));
        assert_eq!(reaction.timestamp, Some(1_700_000_016_123));
    }

    #[test]
    fn processes_push_name_history_sync() {
        let history = HistorySync {
            sync_type: HistorySyncType::PushName as i32,
            pushnames: vec![Pushname {
                id: Some("123@s.whatsapp.net".to_owned()),
                pushname: Some("Alice".to_owned()),
            }],
            ..Default::default()
        };

        let processed =
            process_history_sync(&history, HistorySyncProcessConfig::default()).unwrap();
        let history = processed.batch.history.unwrap();
        assert_eq!(history.contacts.len(), 1);
        assert_eq!(history.contacts[0].jid, "123@s.whatsapp.net");
        assert_eq!(history.contacts[0].fields["notify"], "Alice");
    }

    #[test]
    fn processes_non_blocking_history_pushnames_statuses_and_lid_mappings() {
        let history = HistorySync {
            sync_type: HistorySyncType::NonBlockingData as i32,
            pushnames: vec![Pushname {
                id: Some("123@s.whatsapp.net".to_owned()),
                pushname: Some("Alice".to_owned()),
            }],
            status_v3_messages: vec![WebMessageInfo {
                key: Some(MessageKey {
                    remote_jid: Some("status@broadcast".to_owned()),
                    from_me: Some(false),
                    id: Some("status-1".to_owned()),
                    participant: Some("123@s.whatsapp.net".to_owned()),
                }),
                message: Some(Message {
                    conversation: Some("status update".to_owned()),
                    ..Default::default()
                }),
                message_timestamp: Some(1_700_000_020),
                push_name: Some("Alice".to_owned()),
                ..Default::default()
            }],
            phone_number_to_lid_mappings: vec![wa_proto::proto::PhoneNumberToLidMapping {
                pn_jid: Some("123@s.whatsapp.net".to_owned()),
                lid_jid: Some("123@lid".to_owned()),
            }],
            global_settings: Some(GlobalSettings {
                media_visibility: Some(MediaVisibility::On as i32),
                light_theme_wallpaper: Some(WallpaperSettings {
                    filename: Some("light.jpg".to_owned()),
                    opacity: Some(80),
                }),
                dark_theme_wallpaper: Some(WallpaperSettings {
                    filename: Some("dark.jpg".to_owned()),
                    opacity: Some(70),
                }),
                auto_download_wi_fi: Some(AutoDownloadSettings {
                    download_images: Some(true),
                    download_audio: Some(false),
                    download_video: Some(true),
                    download_documents: Some(false),
                }),
                auto_download_cellular: Some(AutoDownloadSettings {
                    download_images: Some(false),
                    download_audio: Some(true),
                    download_video: Some(false),
                    download_documents: Some(true),
                }),
                auto_download_roaming: Some(AutoDownloadSettings {
                    download_images: Some(false),
                    download_audio: Some(false),
                    download_video: Some(false),
                    download_documents: Some(false),
                }),
                show_individual_notifications_preview: Some(true),
                show_group_notifications_preview: Some(false),
                disappearing_mode_duration: Some(86_400),
                disappearing_mode_timestamp: Some(1_700_000_060),
                avatar_user_settings: Some(AvatarUserSettings {
                    fbid: Some("fbid-1".to_owned()),
                    password: Some("secret".to_owned()),
                }),
                font_size: Some(2),
                security_notifications: Some(true),
                auto_unarchive_chats: Some(false),
                video_quality_mode: Some(1),
                photo_quality_mode: Some(2),
                individual_notification_settings: Some(NotificationSettings {
                    message_vibrate: Some("short".to_owned()),
                    message_popup: Some("always".to_owned()),
                    message_light: Some("white".to_owned()),
                    low_priority_notifications: Some(true),
                    reactions_muted: Some(false),
                    call_vibrate: Some("long".to_owned()),
                }),
                group_notification_settings: Some(NotificationSettings {
                    message_vibrate: Some("default".to_owned()),
                    message_popup: Some("never".to_owned()),
                    message_light: Some("green".to_owned()),
                    low_priority_notifications: Some(false),
                    reactions_muted: Some(true),
                    call_vibrate: Some("short".to_owned()),
                }),
                chat_db_lid_migration_timestamp: Some(1_700_000_080),
                ..Default::default()
            }),
            accounts: vec![
                Account {
                    lid: Some("456".to_owned()),
                    username: Some("alice_handle".to_owned()),
                    country_code: Some("1".to_owned()),
                    is_username_deleted: Some(false),
                },
                Account {
                    lid: Some("789@lid".to_owned()),
                    username: Some("old_handle".to_owned()),
                    country_code: Some("55".to_owned()),
                    is_username_deleted: Some(true),
                },
            ],
            recent_stickers: vec![StickerMetadata {
                url: Some("https://mmg.whatsapp.net/sticker".to_owned()),
                file_sha256: Some(Bytes::from_static(&[1, 2, 3])),
                file_enc_sha256: Some(Bytes::from_static(&[4, 5, 6])),
                media_key: Some(Bytes::from_static(&[7; 32])),
                mimetype: Some("image/webp".to_owned()),
                height: Some(512),
                width: Some(512),
                direct_path: Some("/v/t62.15575/sticker".to_owned()),
                file_length: Some(1234),
                weight: Some(0.75),
                last_sticker_sent_ts: Some(1_700_000_070),
                is_lottie: Some(false),
                image_hash: Some("hash-1".to_owned()),
                is_avatar_sticker: Some(true),
            }],
            call_log_records: vec![CallLogRecord {
                call_result: Some(call_log_record::CallResult::Missed as i32),
                silence_reason: Some(call_log_record::SilenceReason::Privacy as i32),
                duration: Some(42),
                start_time: Some(1_700_000_030),
                is_incoming: Some(true),
                is_video: Some(true),
                call_id: Some("call-1".to_owned()),
                call_creator_jid: Some("123@s.whatsapp.net".to_owned()),
                group_jid: Some("456@g.us".to_owned()),
                participants: vec![
                    call_log_record::ParticipantInfo {
                        user_jid: Some("123@s.whatsapp.net".to_owned()),
                        call_result: Some(call_log_record::CallResult::Missed as i32),
                    },
                    call_log_record::ParticipantInfo {
                        user_jid: Some("789@s.whatsapp.net".to_owned()),
                        call_result: Some(call_log_record::CallResult::Connected as i32),
                    },
                ],
                call_type: Some(call_log_record::CallType::Regular as i32),
                ..Default::default()
            }],
            past_participants: vec![PastParticipants {
                group_jid: Some("456@g.us".to_owned()),
                past_participants: vec![
                    PastParticipant {
                        user_jid: Some("123@s.whatsapp.net".to_owned()),
                        leave_reason: Some(past_participant::LeaveReason::Left as i32),
                        leave_ts: Some(1_700_000_040),
                    },
                    PastParticipant {
                        user_jid: Some("789@s.whatsapp.net".to_owned()),
                        leave_reason: Some(past_participant::LeaveReason::Removed as i32),
                        leave_ts: Some(1_700_000_050),
                    },
                ],
            }],
            thread_id_user_secret: Some(Bytes::from_static(&[8, 9, 10, 11])),
            thread_ds_timeframe_offset: Some(15),
            ai_wait_list_state: Some(BotAiWaitListState::AiAvailable as i32),
            companion_meta_nonce: Some("nonce-1".to_owned()),
            shareable_chat_identifier_encryption_key: Some(Bytes::from_static(&[12, 13, 14])),
            ..Default::default()
        };

        let processed =
            process_history_sync(&history, HistorySyncProcessConfig::default()).unwrap();
        assert_eq!(processed.sync_type, HistorySyncType::NonBlockingData);
        assert_eq!(processed.lid_pn_mappings.len(), 1);
        assert_eq!(processed.lid_pn_mappings[0].lid_jid, "123@lid");
        assert_eq!(processed.lid_pn_mappings[0].pn_jid, "123@s.whatsapp.net");
        assert_eq!(
            processed.default_disappearing_mode,
            Some(DefaultDisappearingMode::new(86_400).with_timestamp(1_700_000_060))
        );

        let event = processed.batch.history.as_ref().unwrap();
        assert_eq!(event.contacts.len(), 3);
        assert_eq!(event.contacts[0].jid, "123@s.whatsapp.net");
        assert_eq!(event.contacts[0].fields["notify"], "Alice");
        assert_eq!(event.contacts[1].jid, "456@lid");
        assert_eq!(event.contacts[1].fields["source"], "history_account");
        assert_eq!(event.contacts[1].fields["lid_jid"], "456@lid");
        assert_eq!(event.contacts[1].fields["username"], "alice_handle");
        assert_eq!(event.contacts[1].fields["country_code"], "1");
        assert_eq!(event.contacts[1].fields["is_username_deleted"], "false");
        assert_eq!(event.contacts[2].jid, "789@lid");
        assert_eq!(event.contacts[2].fields["source"], "history_account");
        assert_eq!(event.contacts[2].fields["lid_jid"], "789@lid");
        assert_eq!(event.contacts[2].fields["username"], "");
        assert_eq!(event.contacts[2].fields["username_deleted"], "true");
        assert_eq!(event.contacts[2].fields["is_username_deleted"], "true");
        assert_eq!(event.contacts[2].fields["country_code"], "55");
        assert_eq!(event.messages.len(), 1);
        assert_eq!(event.messages[0].key.remote_jid, "status@broadcast");
        assert_eq!(
            event.messages[0].key.participant.as_deref(),
            Some("123@s.whatsapp.net")
        );
        assert_eq!(event.messages[0].key.id, "status-1");
        assert_eq!(event.messages[0].timestamp, Some(1_700_000_020));
        assert_eq!(
            event.messages[0].fields["history_sync_type"],
            "NON_BLOCKING_DATA"
        );
        assert_eq!(event.messages[0].fields["push_name"], "Alice");

        assert_eq!(processed.batch.recent_stickers.len(), 1);
        let sticker = &processed.batch.recent_stickers[0];
        assert_eq!(sticker.id, "file_sha256:010203");
        assert_eq!(sticker.file_sha256.as_deref(), Some(&[1, 2, 3][..]));
        assert_eq!(sticker.file_enc_sha256.as_deref(), Some(&[4, 5, 6][..]));
        assert_eq!(sticker.media_key.as_deref(), Some(&[7; 32][..]));
        assert_eq!(sticker.fields["source"], "history_recent_sticker");
        assert_eq!(sticker.fields["file_sha256_hex"], "010203");
        assert_eq!(sticker.fields["file_enc_sha256_hex"], "040506");
        assert_eq!(sticker.fields["mimetype"], "image/webp");
        assert_eq!(sticker.fields["height"], "512");
        assert_eq!(sticker.fields["width"], "512");
        assert_eq!(sticker.fields["direct_path"], "/v/t62.15575/sticker");
        assert_eq!(sticker.fields["file_length"], "1234");
        assert_eq!(sticker.fields["weight"], "0.75");
        assert_eq!(sticker.fields["last_sticker_sent_ts"], "1700000070");
        assert_eq!(sticker.fields["image_hash"], "hash-1");
        assert_eq!(sticker.fields["is_lottie"], "false");
        assert_eq!(sticker.fields["is_avatar_sticker"], "true");

        assert_eq!(processed.batch.account_settings.len(), 1);
        let settings = &processed.batch.account_settings[0];
        assert_eq!(settings.id, "history_sync");
        assert_eq!(settings.fields["source"], "history_sync");
        assert_eq!(settings.fields["media_visibility"], "ON");
        assert_eq!(
            settings.fields["light_theme_wallpaper_filename"],
            "light.jpg"
        );
        assert_eq!(settings.fields["light_theme_wallpaper_opacity"], "80");
        assert_eq!(settings.fields["dark_theme_wallpaper_filename"], "dark.jpg");
        assert_eq!(settings.fields["dark_theme_wallpaper_opacity"], "70");
        assert_eq!(settings.fields["auto_download_wifi_images"], "true");
        assert_eq!(settings.fields["auto_download_wifi_audio"], "false");
        assert_eq!(settings.fields["auto_download_cellular_documents"], "true");
        assert_eq!(settings.fields["auto_download_roaming_video"], "false");
        assert_eq!(
            settings.fields["show_individual_notifications_preview"],
            "true"
        );
        assert_eq!(settings.fields["show_group_notifications_preview"], "false");
        assert_eq!(settings.fields["disappearing_mode_duration"], "86400");
        assert_eq!(settings.fields["disappearing_mode_timestamp"], "1700000060");
        assert_eq!(settings.fields["avatar_fbid"], "fbid-1");
        assert_eq!(settings.fields["avatar_password_present"], "true");
        assert!(!settings.fields.contains_key("avatar_password"));
        assert_eq!(settings.fields["font_size"], "2");
        assert_eq!(settings.fields["security_notifications"], "true");
        assert_eq!(settings.fields["auto_unarchive_chats"], "false");
        assert_eq!(settings.fields["video_quality_mode"], "1");
        assert_eq!(settings.fields["photo_quality_mode"], "2");
        assert_eq!(
            settings.fields["individual_notification_message_vibrate"],
            "short"
        );
        assert_eq!(
            settings.fields["individual_notification_message_popup"],
            "always"
        );
        assert_eq!(
            settings.fields["individual_notification_message_light"],
            "white"
        );
        assert_eq!(
            settings.fields["individual_notification_low_priority_notifications"],
            "true"
        );
        assert_eq!(
            settings.fields["individual_notification_reactions_muted"],
            "false"
        );
        assert_eq!(
            settings.fields["individual_notification_call_vibrate"],
            "long"
        );
        assert_eq!(
            settings.fields["group_notification_message_vibrate"],
            "default"
        );
        assert_eq!(settings.fields["group_notification_message_popup"], "never");
        assert_eq!(settings.fields["group_notification_message_light"], "green");
        assert_eq!(
            settings.fields["group_notification_low_priority_notifications"],
            "false"
        );
        assert_eq!(
            settings.fields["group_notification_reactions_muted"],
            "true"
        );
        assert_eq!(settings.fields["group_notification_call_vibrate"], "short");
        assert_eq!(
            settings.fields["chat_db_lid_migration_timestamp"],
            "1700000080"
        );
        assert_eq!(settings.fields["thread_id_user_secret_present"], "true");
        assert_eq!(settings.fields["thread_id_user_secret_len"], "4");
        assert_eq!(settings.fields["thread_ds_timeframe_offset"], "15");
        assert_eq!(settings.fields["ai_wait_list_state"], "AI_AVAILABLE");
        assert_eq!(settings.fields["companion_meta_nonce"], "nonce-1");
        assert_eq!(
            settings.fields["shareable_chat_identifier_encryption_key_present"],
            "true"
        );
        assert_eq!(
            settings.fields["shareable_chat_identifier_encryption_key_len"],
            "3"
        );

        assert_eq!(processed.batch.calls_update.len(), 1);
        let call = &processed.batch.calls_update[0];
        assert_eq!(call.id, "call-1");
        assert_eq!(call.from, "456@g.us");
        assert_eq!(call.event_type, "history_log");
        assert_eq!(call.call_id.as_deref(), Some("call-1"));
        assert_eq!(call.timestamp, Some(1_700_000_030));
        assert_eq!(call.fields["source"], "history_call_log");
        assert_eq!(call.fields["call_result"], "MISSED");
        assert_eq!(call.fields["call_type"], "REGULAR");
        assert_eq!(call.fields["silence_reason"], "PRIVACY");
        assert_eq!(call.fields["duration"], "42");
        assert_eq!(call.fields["is_incoming"], "true");
        assert_eq!(call.fields["is_video"], "true");
        assert_eq!(call.fields["call_creator_jid"], "123@s.whatsapp.net");
        assert_eq!(call.fields["group_jid"], "456@g.us");
        assert_eq!(call.fields["participants_count"], "2");
        let participants: serde_json::Value =
            serde_json::from_str(&call.fields["participants"]).unwrap();
        assert_eq!(participants[0]["jid"], "123@s.whatsapp.net");
        assert_eq!(participants[0]["callResult"], "MISSED");
        assert_eq!(participants[1]["jid"], "789@s.whatsapp.net");
        assert_eq!(participants[1]["callResult"], "CONNECTED");

        assert_eq!(processed.batch.groups_update.len(), 1);
        let group = &processed.batch.groups_update[0];
        assert_eq!(group.jid, "456@g.us");
        assert_eq!(group.fields["source"], "history_past_participants");
        assert_eq!(group.fields["past_participants_count"], "2");
        assert_eq!(group.fields["participants_leave"], "123@s.whatsapp.net");
        assert_eq!(group.fields["participants_leave_count"], "1");
        assert_eq!(
            group.fields["participants_leave_timestamps"],
            "123@s.whatsapp.net=1700000040"
        );
        assert_eq!(group.fields["participants_remove"], "789@s.whatsapp.net");
        assert_eq!(group.fields["participants_remove_count"], "1");
        assert_eq!(
            group.fields["participants_remove_timestamps"],
            "789@s.whatsapp.net=1700000050"
        );
        assert_eq!(
            group.fields["past_participant_reasons"],
            "123@s.whatsapp.net=LEFT,789@s.whatsapp.net=REMOVED"
        );
        assert_eq!(
            group.fields["past_participant_timestamps"],
            "123@s.whatsapp.net=1700000040,789@s.whatsapp.net=1700000050"
        );
    }

    #[test]
    fn rejects_invalid_history_global_settings_disappearing_mode() {
        let history = HistorySync {
            sync_type: HistorySyncType::NonBlockingData as i32,
            global_settings: Some(GlobalSettings {
                disappearing_mode_duration: Some(-1),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(process_history_sync(&history, HistorySyncProcessConfig::default()).is_err());

        let history = HistorySync {
            sync_type: HistorySyncType::NonBlockingData as i32,
            global_settings: Some(GlobalSettings {
                disappearing_mode_duration: Some(86_400),
                disappearing_mode_timestamp: Some(-1),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(process_history_sync(&history, HistorySyncProcessConfig::default()).is_err());
    }

    #[test]
    fn rejects_invalid_history_account_lids() {
        let history = HistorySync {
            sync_type: HistorySyncType::NonBlockingData as i32,
            accounts: vec![Account {
                lid: Some("123@s.whatsapp.net".to_owned()),
                ..Default::default()
            }],
            ..Default::default()
        };
        assert!(process_history_sync(&history, HistorySyncProcessConfig::default()).is_err());

        let history = HistorySync {
            sync_type: HistorySyncType::NonBlockingData as i32,
            accounts: vec![Account {
                lid: Some("bad:7".to_owned()),
                ..Default::default()
            }],
            ..Default::default()
        };
        assert!(process_history_sync(&history, HistorySyncProcessConfig::default()).is_err());
    }

    #[test]
    fn enforces_history_sync_decode_and_process_limits() {
        let history = sample_history_sync();
        let compressed = compress_history(&history);
        assert!(
            decode_compressed_history_sync(
                &compressed,
                HistorySyncDecodeConfig {
                    max_inflated_bytes: 1
                }
            )
            .is_err()
        );
        assert!(
            process_history_sync(
                &history,
                HistorySyncProcessConfig {
                    max_chats: 0,
                    ..HistorySyncProcessConfig::default()
                }
            )
            .is_err()
        );
    }

    #[cfg(feature = "noise")]
    #[tokio::test]
    async fn downloads_decrypts_inflates_and_processes_history_sync() {
        let history = sample_history_sync();
        let compressed = compress_history(&history);
        let encrypted = wa_crypto::encrypt_media_bytes_with_key(
            &compressed,
            wa_crypto::MediaKind::HistorySync,
            &[5u8; 32],
        )
        .unwrap();
        let notification = history_notification_from_encrypted(&encrypted, "/history/sync");
        let transport = HistoryTransport::default();
        transport.add_download(
            "https://history.test/history/sync",
            encrypted.ciphertext_with_mac.clone(),
        );
        let transfer = crate::media::MediaTransfer::new(transport.clone());

        let decoded = download_history_sync(
            &transfer,
            &notification,
            Some("history.test"),
            HistorySyncDecodeConfig::default(),
        )
        .await
        .unwrap();
        assert_eq!(decoded.conversations.len(), 1);

        let processed = download_and_process_history_sync(
            &transfer,
            &notification,
            Some("history.test"),
            HistorySyncDecodeConfig::default(),
            HistorySyncProcessConfig::default(),
        )
        .await
        .unwrap();
        assert_eq!(processed.batch.history.unwrap().messages.len(), 1);
        assert_eq!(
            transport.download_urls.lock().unwrap().as_slice(),
            &[
                "https://history.test/history/sync".to_owned(),
                "https://history.test/history/sync".to_owned(),
            ]
        );
    }

    #[cfg(feature = "noise")]
    #[tokio::test]
    async fn rejects_invalid_history_sync_notification_metadata() {
        let compressed = compress_history(&sample_history_sync());
        let encrypted = wa_crypto::encrypt_media_bytes_with_key(
            &compressed,
            wa_crypto::MediaKind::HistorySync,
            &[5u8; 32],
        )
        .unwrap();
        let notification = history_notification_from_encrypted(&encrypted, "/history/sync");
        let mut missing_path = notification.clone();
        missing_path.direct_path = None;
        assert!(uploaded_media_from_history_sync_notification(&missing_path).is_err());

        let transport = HistoryTransport::default();
        let transfer = crate::media::MediaTransfer::with_config(
            transport.clone(),
            crate::media::MediaTransferConfig {
                max_upload_plaintext_bytes: 1024,
                max_download_ciphertext_bytes: compressed.len() - 1,
            },
        );
        assert!(
            download_history_sync_bytes(&transfer, &notification, Some("history.test"))
                .await
                .is_err()
        );
        assert!(transport.download_urls.lock().unwrap().is_empty());
    }

    fn sample_history_sync() -> HistorySync {
        HistorySync {
            sync_type: HistorySyncType::InitialBootstrap as i32,
            progress: Some(50),
            chunk_order: Some(2),
            phone_number_to_lid_mappings: vec![wa_proto::proto::PhoneNumberToLidMapping {
                pn_jid: Some("123@s.whatsapp.net".to_owned()),
                lid_jid: Some("123@lid".to_owned()),
            }],
            conversations: vec![Conversation {
                id: "123@s.whatsapp.net".to_owned(),
                display_name: Some("Alice".to_owned()),
                pn_jid: Some("123@s.whatsapp.net".to_owned()),
                lid_jid: Some("123@lid".to_owned()),
                unread_count: Some(2),
                messages: vec![HistorySyncMsg {
                    msg_order_id: Some(7),
                    message: Some(WebMessageInfo {
                        key: Some(MessageKey {
                            remote_jid: Some("123@s.whatsapp.net".to_owned()),
                            from_me: Some(false),
                            id: Some("msg-1".to_owned()),
                            participant: None,
                        }),
                        message: Some(Message {
                            conversation: Some("hello".to_owned()),
                            ..Default::default()
                        }),
                        message_timestamp: Some(1_700_000_000),
                        push_name: Some("Alice".to_owned()),
                        ..Default::default()
                    }),
                }],
                ..Default::default()
            }],
            ..Default::default()
        }
    }

    fn compress_history(history: &HistorySync) -> Bytes {
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&history.encode_to_vec()).unwrap();
        Bytes::from(encoder.finish().unwrap())
    }

    #[cfg(feature = "noise")]
    fn history_notification_from_encrypted(
        encrypted: &wa_crypto::EncryptedMedia,
        direct_path: &str,
    ) -> HistorySyncNotification {
        HistorySyncNotification {
            file_sha256: Some(encrypted.file_sha256.clone()),
            file_length: Some(encrypted.file_length),
            media_key: Some(Bytes::copy_from_slice(encrypted.media_key.expose())),
            file_enc_sha256: Some(encrypted.file_enc_sha256.clone()),
            direct_path: Some(direct_path.to_owned()),
            sync_type: Some(wa_proto::proto::message::HistorySyncType::InitialBootstrap as i32),
            chunk_order: Some(1),
            progress: Some(50),
            ..Default::default()
        }
    }

    #[cfg(feature = "noise")]
    #[derive(Clone, Default)]
    struct HistoryTransport {
        downloads: Arc<Mutex<BTreeMap<String, Bytes>>>,
        download_urls: Arc<Mutex<Vec<String>>>,
    }

    #[cfg(feature = "noise")]
    impl HistoryTransport {
        fn add_download(&self, url: impl Into<String>, bytes: Bytes) {
            self.downloads.lock().unwrap().insert(url.into(), bytes);
        }
    }

    #[cfg(feature = "noise")]
    #[async_trait]
    impl crate::media::MediaTransport for HistoryTransport {
        async fn upload_media(
            &self,
            _request: crate::media::MediaUploadRequest,
        ) -> CoreResult<crate::media::UploadedMediaLocation> {
            Err(CoreError::Payload(
                "history transport does not upload".to_owned(),
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
