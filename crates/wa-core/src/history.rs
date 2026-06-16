use crate::{
    ChatEvent, ContactEvent, CoreError, CoreResult, EventBatch, HistorySetEvent, MessageEvent,
    MessageEventKey,
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
use wa_binary::{JidServer, jid_decode};
use wa_proto::proto::{
    Conversation, HistorySync, Pushname, WebMessageInfo, history_sync::HistorySyncType,
    message::HistorySyncNotification,
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
                    &mut mappings,
                    config,
                )?;
            }
            for message in &history.status_v3_messages {
                push_history_message_event(
                    &mut history_event.messages,
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
                    &mut history_event.messages,
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
        HistorySyncType::NonBlockingData => {}
    }

    if history_event.pending_items() > 0 {
        batch.history = Some(history_event);
    }

    Ok(ProcessedHistorySync {
        sync_type,
        progress: history.progress,
        chunk_order: history.chunk_order,
        batch,
        lid_pn_mappings: mappings,
    })
}

fn add_conversation(
    conversation: &Conversation,
    sync_type: HistorySyncType,
    history_event: &mut HistorySetEvent,
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
            &mut history_event.messages,
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

fn push_history_message_event(
    messages: &mut Vec<MessageEvent>,
    message: &WebMessageInfo,
    fallback_remote_jid: Option<&str>,
    msg_order_id: Option<u64>,
    sync_type: HistorySyncType,
    max_messages: usize,
) -> CoreResult<()> {
    ensure_capacity(messages.len(), max_messages, "history messages")?;
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

    let mut event = MessageEvent::new(MessageEventKey::new(
        remote_jid.to_owned(),
        id.to_owned(),
        key.participant.clone(),
    ))
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

    messages.push(event);
    Ok(())
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
    #[cfg(feature = "noise")]
    use flate2::{Compression, write::ZlibEncoder};
    #[cfg(feature = "noise")]
    use std::collections::BTreeMap;
    #[cfg(feature = "noise")]
    use std::io::Write as _;
    #[cfg(feature = "noise")]
    use std::sync::{Arc, Mutex};
    use wa_proto::proto::{HistorySyncMsg, Message, MessageKey};

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
