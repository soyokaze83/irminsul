#[cfg(feature = "noise")]
use crate::message::future_proof_inner_message;
use crate::message::unwrapped_message_content;
use crate::{
    AccountUpdate, AppStateCollection, BlocklistAction, BlocklistUpdateEvent,
    BusinessNotificationEvent, CallEvent, ContactEvent, CoreError, CoreResult,
    DecodedInboundMessage, DefaultDisappearingMode, Event, EventBatch, EventBuffer,
    GroupUpdateEvent, InboundAck, InboundMessageDecryptor, InboundMessageInfo, InboundNotification,
    InboundReceipt, LidMappingEvent, MediaRetryEvent, MediaRetryUpdate, MessageEvent,
    MessageEventKey, MessageUpdate, NackReason, NewsletterParticipantUpdateEvent,
    NewsletterReactionEvent, NewsletterSettingsUpdateEvent, NewsletterViewEvent,
    PLACEHOLDER_NO_MESSAGE_FOUND_ERROR_TEXT, PlaceholderResendRequest, PresenceEvent,
    ReactionEvent, ReceiptEvent, build_ack_node, build_nack_node, decode_inbound_message,
    decode_inbound_message_info, encode_message, message_stanza_type,
    parse_account_update_notification, parse_inbound_ack, parse_inbound_notification,
    parse_inbound_receipt, parse_media_retry_update, parse_newsletter_linked_profile_notification,
    parse_newsletter_notification_updates, placeholder_resend_request_from_web_message,
};
use bytes::Bytes;
use prost::Message as ProstMessage;
use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};
use wa_binary::{BinaryNode, BinaryNodeContent, jid_decode, jid_normalized_user};
#[cfg(feature = "noise")]
use wa_proto::proto::message::event_response_message;
use wa_proto::proto::{
    Message, MessageKey, WebMessageInfo,
    message::{
        Call as ProtoCall, PlaceholderMessage, ProtocolMessage, pin_in_chat_message,
        placeholder_message::PlaceholderType, protocol_message,
    },
    web_message_info::StubType,
};

pub const DEFAULT_OFFLINE_NODE_YIELD_EVERY: usize = 32;
#[cfg(feature = "noise")]
const MAX_DECRYPTED_POLL_OPTION_HASH_FIELDS: usize = 32;

#[cfg(feature = "noise")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PollEventMessageSecret {
    pub creator_jid: String,
    pub message_secret: Bytes,
}

#[cfg(feature = "noise")]
impl PollEventMessageSecret {
    pub fn new(
        creator_jid: impl Into<String>,
        message_secret: impl Into<Bytes>,
    ) -> CoreResult<Self> {
        let creator_jid = creator_jid.into();
        validate_jid("poll/event creator JID", &creator_jid)?;
        let message_secret = message_secret.into();
        if message_secret.len() != 32 {
            return Err(CoreError::Payload(
                "poll/event message secret must be 32 bytes".to_owned(),
            ));
        }
        Ok(Self {
            creator_jid,
            message_secret,
        })
    }
}

#[cfg(feature = "noise")]
pub type PollEventMessageSecrets = BTreeMap<MessageEventKey, PollEventMessageSecret>;

#[cfg(feature = "noise")]
pub fn poll_event_message_secret_from_event(
    event: &MessageEvent,
) -> CoreResult<Option<PollEventMessageSecret>> {
    let Some(payload) = event.payload.as_ref() else {
        return Ok(None);
    };
    let message = <Message as ProstMessage>::decode(payload.as_ref())?;
    let Some(message_secret) = poll_event_creation_message_secret(&message) else {
        return Ok(None);
    };
    let creator_jid = event
        .fields
        .get("author")
        .filter(|jid| !jid.is_empty())
        .cloned()
        .or_else(|| event.key.participant.clone())
        .unwrap_or_else(|| event.key.remote_jid.clone());
    PollEventMessageSecret::new(creator_jid, message_secret.clone()).map(Some)
}

#[cfg(feature = "noise")]
fn poll_event_creation_message_secret(message: &Message) -> Option<&Bytes> {
    if !message_has_poll_or_event_creation(message) {
        return None;
    }
    let mut current = message;
    let mut saw_creation = false;
    for _ in 0..=5 {
        saw_creation |= message_has_direct_poll_or_event_creation(current);
        if saw_creation
            && let Some(secret) = current
                .message_context_info
                .as_ref()
                .and_then(|context| context.message_secret.as_ref())
        {
            return Some(secret);
        }
        current = future_proof_inner_message(current)?;
    }
    None
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InboundNodeAction {
    Message,
    Receipt,
    Ack,
    Notification,
    Call,
    Presence,
    Ignored,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InboundNodeProcessing {
    pub action: InboundNodeAction,
    pub response: Option<BinaryNode>,
    pub event_count: usize,
    pub error: Option<String>,
}

impl InboundNodeProcessing {
    #[must_use]
    pub fn ignored() -> Self {
        Self {
            action: InboundNodeAction::Ignored,
            response: None,
            event_count: 0,
            error: None,
        }
    }

    #[must_use]
    pub fn handled(
        action: InboundNodeAction,
        response: Option<BinaryNode>,
        event_count: usize,
    ) -> Self {
        Self {
            action,
            response,
            event_count,
            error: None,
        }
    }

    #[must_use]
    pub fn handled_with_error(
        action: InboundNodeAction,
        response: Option<BinaryNode>,
        error: impl ToString,
    ) -> Self {
        Self {
            action,
            response,
            event_count: 0,
            error: Some(error.to_string()),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OfflineNodeProcessing {
    pub child_count: usize,
    pub results: Vec<InboundNodeProcessing>,
    pub yielded_count: usize,
}

#[derive(Clone, Debug, PartialEq)]
pub struct PlaceholderUnavailableMessage {
    pub web_message: WebMessageInfo,
    pub request: PlaceholderResendRequest,
    pub category: Option<String>,
    pub unavailable_type: Option<String>,
}

impl OfflineNodeProcessing {
    #[must_use]
    pub fn event_count(&self) -> usize {
        self.results.iter().map(|result| result.event_count).sum()
    }

    #[must_use]
    pub fn response_count(&self) -> usize {
        self.results
            .iter()
            .filter(|result| result.response.is_some())
            .count()
    }
}

pub async fn process_inbound_node<D>(
    node: &BinaryNode,
    own_jid: &str,
    own_lid: Option<&str>,
    local_ack_jid: Option<&str>,
    decryptor: &D,
    buffer: &mut EventBuffer,
) -> CoreResult<InboundNodeProcessing>
where
    D: InboundMessageDecryptor,
{
    match node.tag.as_str() {
        "message" => {
            process_message_node(node, own_jid, own_lid, local_ack_jid, decryptor, buffer).await
        }
        "receipt" => process_receipt_node(node, local_ack_jid, buffer),
        "ack" => process_ack_node(node, buffer),
        "notification" => process_notification_node(node, local_ack_jid, buffer),
        "call" => process_call_node(node, local_ack_jid, buffer),
        "presence" | "chatstate" => process_presence_node(node, buffer),
        _ => Ok(InboundNodeProcessing::ignored()),
    }
}

pub async fn process_offline_node<D>(
    node: &BinaryNode,
    own_jid: &str,
    own_lid: Option<&str>,
    local_ack_jid: Option<&str>,
    decryptor: &D,
    buffer: &mut EventBuffer,
    yield_every: usize,
) -> CoreResult<OfflineNodeProcessing>
where
    D: InboundMessageDecryptor,
{
    if node.tag != "offline" {
        return Err(CoreError::Protocol(format!(
            "expected offline node, got {}",
            node.tag
        )));
    }

    let children = child_nodes(node);
    let mut results = Vec::with_capacity(children.len());
    let mut yielded_count = 0usize;
    for (index, child) in children.iter().enumerate() {
        results.push(
            process_inbound_node(child, own_jid, own_lid, local_ack_jid, decryptor, buffer).await?,
        );
        if yield_every != 0 && (index + 1) % yield_every == 0 && index + 1 < children.len() {
            yielded_count += 1;
            tokio::task::yield_now().await;
        }
    }

    Ok(OfflineNodeProcessing {
        child_count: children.len(),
        results,
        yielded_count,
    })
}

async fn process_message_node<D>(
    node: &BinaryNode,
    own_jid: &str,
    own_lid: Option<&str>,
    local_ack_jid: Option<&str>,
    decryptor: &D,
    buffer: &mut EventBuffer,
) -> CoreResult<InboundNodeProcessing>
where
    D: InboundMessageDecryptor,
{
    if is_unavailable_absent_message_node(node) {
        if let Some(placeholder) = placeholder_unavailable_message_from_node(
            node,
            own_jid,
            own_lid,
            current_unix_timestamp(),
        )? {
            let event = message_event_from_placeholder_unavailable(&placeholder)?;
            let batch = EventBatch {
                messages_upsert: vec![event],
                ..EventBatch::default()
            };
            let event_count = batch.pending_items();
            buffer.push(Event::Batch(Box::new(batch)))?;
            return Ok(InboundNodeProcessing::handled(
                InboundNodeAction::Message,
                Some(build_ack_node(node, local_ack_jid, None)?),
                event_count,
            ));
        }
        return Ok(InboundNodeProcessing::handled(
            InboundNodeAction::Message,
            Some(build_ack_node(node, local_ack_jid, None)?),
            0,
        ));
    }

    match decode_inbound_message(node, own_jid, own_lid, decryptor).await {
        Ok(decoded) => {
            let event_count = push_decoded_message_to_buffer(buffer, &decoded)?;
            Ok(InboundNodeProcessing::handled(
                InboundNodeAction::Message,
                Some(build_ack_node(node, local_ack_jid, None)?),
                event_count,
            ))
        }
        Err(err) => Ok(InboundNodeProcessing::handled_with_error(
            InboundNodeAction::Message,
            Some(build_nack_node(
                node,
                local_ack_jid,
                NackReason::ParsingError,
            )?),
            err,
        )),
    }
}

fn process_receipt_node(
    node: &BinaryNode,
    local_ack_jid: Option<&str>,
    buffer: &mut EventBuffer,
) -> CoreResult<InboundNodeProcessing> {
    let response = Some(build_ack_node(node, local_ack_jid, None)?);
    match parse_inbound_receipt(node) {
        Ok(receipt) => {
            let batch = match event_batch_from_inbound_receipt_node(node, &receipt) {
                Ok(batch) => batch,
                Err(err) => {
                    return Ok(InboundNodeProcessing::handled_with_error(
                        InboundNodeAction::Receipt,
                        response,
                        err,
                    ));
                }
            };
            let event_count = batch.pending_items();
            if !batch.is_empty() {
                buffer.push(Event::Batch(Box::new(batch)))?;
            }
            Ok(InboundNodeProcessing::handled(
                InboundNodeAction::Receipt,
                response,
                event_count,
            ))
        }
        Err(err) => Ok(InboundNodeProcessing::handled_with_error(
            InboundNodeAction::Receipt,
            response,
            err,
        )),
    }
}

fn process_ack_node(
    node: &BinaryNode,
    buffer: &mut EventBuffer,
) -> CoreResult<InboundNodeProcessing> {
    let ack = match parse_inbound_ack(node) {
        Ok(ack) => ack,
        Err(err) => {
            return Ok(InboundNodeProcessing::handled_with_error(
                InboundNodeAction::Ack,
                None,
                err,
            ));
        }
    };
    let batch = match event_batch_from_inbound_ack(&ack) {
        Ok(batch) => batch,
        Err(err) => {
            return Ok(InboundNodeProcessing::handled_with_error(
                InboundNodeAction::Ack,
                None,
                err,
            ));
        }
    };
    let event_count = batch.pending_items();
    if !batch.is_empty() {
        buffer.push(Event::Batch(Box::new(batch)))?;
    }
    Ok(InboundNodeProcessing::handled(
        InboundNodeAction::Ack,
        None,
        event_count,
    ))
}

fn process_notification_node(
    node: &BinaryNode,
    local_ack_jid: Option<&str>,
    buffer: &mut EventBuffer,
) -> CoreResult<InboundNodeProcessing> {
    let response = Some(build_ack_node(node, local_ack_jid, None)?);
    match parse_inbound_notification(node) {
        Ok(notification) => {
            buffer.push(Event::Node(node.clone()))?;
            let mut event_count = usize::from(!notification.id.is_empty());
            if let Some(batch) = event_batch_from_notification_node(node, &notification)? {
                event_count += batch.pending_items();
                buffer.push(Event::Batch(Box::new(batch)))?;
            }
            if let Some(batch) =
                event_batch_from_media_retry_notification_node(node, &notification)?
            {
                event_count += batch.pending_items();
                buffer.push(Event::Batch(Box::new(batch)))?;
            }
            if let Some(event) =
                account_update_event_from_notification_node(node, current_unix_timestamp())?
            {
                event_count += 1;
                buffer.push(event)?;
            }
            if let Some(mode) =
                default_disappearing_mode_from_notification_node(node, &notification)?
            {
                event_count += 1;
                buffer.push(Event::DefaultDisappearingModeUpdate(mode))?;
            }
            let blocklist_updates =
                blocklist_update_events_from_notification_node(node, &notification)?;
            if !blocklist_updates.is_empty() {
                event_count += blocklist_updates.len();
                buffer.push(Event::BlocklistUpdate(blocklist_updates))?;
            }
            let server_sync_collections =
                server_sync_collections_from_notification_node(node, &notification)?;
            if !server_sync_collections.is_empty() {
                event_count += server_sync_collections.len();
                buffer.push(Event::ServerSyncCollections(server_sync_collections))?;
            }
            let lid_mappings = lid_mapping_events_from_newsletter_notification_node(node)?;
            if !lid_mappings.is_empty() {
                event_count += lid_mappings.len();
                buffer.push(Event::LidMappingUpdate(lid_mappings))?;
            }
            let business_events =
                business_notification_events_from_notification_node(node, &notification)?;
            if !business_events.is_empty() {
                event_count += business_events.len();
                buffer.push(Event::BusinessNotificationUpdate(business_events))?;
            }
            let newsletter_events =
                newsletter_update_events_from_notification_node(node, &notification)?;
            event_count += newsletter_events
                .iter()
                .map(newsletter_update_event_count)
                .sum::<usize>();
            for event in newsletter_events {
                buffer.push(event)?;
            }
            let mex_newsletter_events =
                newsletter_mex_update_events_from_notification_node(node, &notification)?;
            event_count += mex_newsletter_events
                .iter()
                .map(newsletter_update_event_count)
                .sum::<usize>();
            for event in mex_newsletter_events {
                buffer.push(event)?;
            }
            Ok(InboundNodeProcessing::handled(
                InboundNodeAction::Notification,
                response,
                event_count,
            ))
        }
        Err(err) => Ok(InboundNodeProcessing::handled_with_error(
            InboundNodeAction::Notification,
            response,
            err,
        )),
    }
}

fn process_call_node(
    node: &BinaryNode,
    local_ack_jid: Option<&str>,
    buffer: &mut EventBuffer,
) -> CoreResult<InboundNodeProcessing> {
    let response = Some(build_ack_node(node, local_ack_jid, None)?);
    match call_events_from_node(node) {
        Ok(calls) => {
            let event_count = calls.len();
            if !calls.is_empty() {
                buffer.push(Event::CallsUpdate(calls))?;
            }
            Ok(InboundNodeProcessing::handled(
                InboundNodeAction::Call,
                response,
                event_count,
            ))
        }
        Err(err) => Ok(InboundNodeProcessing::handled_with_error(
            InboundNodeAction::Call,
            response,
            err,
        )),
    }
}

fn process_presence_node(
    node: &BinaryNode,
    buffer: &mut EventBuffer,
) -> CoreResult<InboundNodeProcessing> {
    match presence_event_from_node(node) {
        Ok(Some(event)) => {
            buffer.push(Event::PresenceUpdate(vec![event]))?;
            Ok(InboundNodeProcessing::handled(
                InboundNodeAction::Presence,
                None,
                1,
            ))
        }
        Ok(None) => Ok(InboundNodeProcessing::handled(
            InboundNodeAction::Presence,
            None,
            0,
        )),
        Err(err) => Ok(InboundNodeProcessing::handled_with_error(
            InboundNodeAction::Presence,
            None,
            err,
        )),
    }
}

pub fn account_update_event_from_notification_node(
    node: &BinaryNode,
    now_seconds: u64,
) -> CoreResult<Option<Event>> {
    let Some(update) = parse_account_update_notification(node, now_seconds)? else {
        return Ok(None);
    };
    Ok(Some(match update {
        AccountUpdate::ReachoutTimelock(state) => Event::ReachoutTimelockUpdate(state),
        AccountUpdate::MessageCapping(info) => Event::MessageCappingUpdate(info),
    }))
}

pub fn blocklist_update_events_from_notification_node(
    node: &BinaryNode,
    notification: &InboundNotification,
) -> CoreResult<Vec<BlocklistUpdateEvent>> {
    if notification.notification_type.as_deref() != Some("account_sync") {
        return Ok(Vec::new());
    }
    let Some(blocklist) = child_node(node, "blocklist") else {
        return Ok(Vec::new());
    };
    child_nodes(blocklist)
        .iter()
        .filter(|item| item.tag == "item")
        .map(|item| {
            let jid = required_text(
                "account sync blocklist JID",
                item.attrs.get("jid").map(String::as_str),
            )?;
            validate_jid("account sync blocklist JID", &jid)?;
            let action = if item.attrs.get("action").map(String::as_str) == Some("block") {
                BlocklistAction::Block
            } else {
                BlocklistAction::Unblock
            };
            Ok(BlocklistUpdateEvent::new(jid, action))
        })
        .collect()
}

pub fn default_disappearing_mode_from_notification_node(
    node: &BinaryNode,
    notification: &InboundNotification,
) -> CoreResult<Option<DefaultDisappearingMode>> {
    if notification.notification_type.as_deref() != Some("account_sync") {
        return Ok(None);
    }
    let Some(mode_node) = child_node(node, "disappearing_mode") else {
        return Ok(None);
    };
    let duration = required_text(
        "account sync disappearing mode duration",
        mode_node.attrs.get("duration").map(String::as_str),
    )?;
    let duration_seconds = duration.parse::<u32>().map_err(|err| {
        CoreError::Protocol(format!(
            "invalid account sync disappearing mode duration: {err}"
        ))
    })?;
    let mut mode = DefaultDisappearingMode::new(duration_seconds);
    if let Some(timestamp) =
        optional_u64_attr(mode_node, "t", "account sync disappearing mode timestamp")?
    {
        mode = mode.with_timestamp(timestamp);
    }
    Ok(Some(mode))
}

pub fn server_sync_collections_from_notification_node(
    node: &BinaryNode,
    notification: &InboundNotification,
) -> CoreResult<Vec<AppStateCollection>> {
    if notification.notification_type.as_deref() != Some("server_sync") {
        return Ok(Vec::new());
    }
    let mut collections = Vec::new();
    for collection in child_nodes(node)
        .iter()
        .filter(|child| child.tag == "collection")
    {
        let name = required_text(
            "server sync collection name",
            collection.attrs.get("name").map(String::as_str),
        )?;
        let collection = AppStateCollection::from_name(&name)?;
        if !collections.contains(&collection) {
            collections.push(collection);
        }
    }
    Ok(collections)
}

pub fn lid_mapping_events_from_newsletter_notification_node(
    node: &BinaryNode,
) -> CoreResult<Vec<LidMappingEvent>> {
    parse_newsletter_linked_profile_notification(node).map(|mappings| {
        mappings
            .into_iter()
            .map(|mapping| LidMappingEvent::new(mapping.lid_jid, mapping.pn_jid))
            .collect()
    })
}

pub fn business_notification_events_from_notification_node(
    node: &BinaryNode,
    notification: &InboundNotification,
) -> CoreResult<Vec<BusinessNotificationEvent>> {
    if notification.notification_type.as_deref() == Some("server_sync") {
        return Ok(Vec::new());
    }
    let mut events = Vec::new();
    for child in child_nodes(node)
        .iter()
        .filter(|child| is_business_notification_child(&child.tag))
    {
        let mut event = BusinessNotificationEvent::new(
            notification.from.clone(),
            notification.id.clone(),
            child.tag.clone(),
        );
        if let Some(notification_type) = &notification.notification_type {
            event = event.with_field("notification_type", notification_type.clone());
        }
        if let Some(timestamp) = notification.timestamp {
            event = event.with_field("timestamp", timestamp.to_string());
        }
        if let Some(participant) = &notification.participant {
            event = event.with_field("actor", participant.clone());
        }
        if let Some(actor_pn) = optional_jid_field(
            "business notification actor PN",
            first_non_empty_attr(node, BUSINESS_NOTIFICATION_ACTOR_PN_ATTRS),
        )? {
            event = event.with_field("actor_pn", actor_pn);
        }
        if let Some(actor_username) =
            first_non_empty_attr(node, BUSINESS_NOTIFICATION_ACTOR_USERNAME_ATTRS)
        {
            event = event.with_field("actor_username", actor_username.to_owned());
        }
        copy_business_notification_node_fields(child, "attr", &mut event.fields)?;
        copy_business_notification_child_fields(child, &mut event.fields, 2)?;
        events.push(event);
    }
    Ok(events)
}

const BUSINESS_NOTIFICATION_ACTOR_PN_ATTRS: &[&str] = &[
    "participant_pn",
    "participantPn",
    "sender_pn",
    "senderPn",
    "phone_number",
    "phoneNumber",
    "pn",
    "pn_jid",
    "pnJid",
];
const BUSINESS_NOTIFICATION_ACTOR_USERNAME_ATTRS: &[&str] = &[
    "participant_username",
    "participantUsername",
    "sender_username",
    "senderUsername",
    "username",
];

fn is_business_notification_child(tag: &str) -> bool {
    matches!(
        tag,
        "business_profile"
            | "business_profile_update"
            | "profile"
            | "profile_update"
            | "product_catalog"
            | "product_catalog_add"
            | "product_catalog_edit"
            | "product_catalog_delete"
            | "product_catalog_update"
            | "catalog"
            | "catalog_update"
            | "collections"
            | "collections_update"
            | "collection"
            | "collection_add"
            | "collection_edit"
            | "collection_delete"
            | "collection_update"
            | "order"
            | "order_update"
            | "order_status_update"
            | "product"
            | "product_add"
            | "product_edit"
            | "product_delete"
            | "product_update"
            | "cart"
            | "cart_update"
            | "cover_photo"
    )
}

fn copy_business_notification_child_fields(
    node: &BinaryNode,
    fields: &mut BTreeMap<String, String>,
    depth: usize,
) -> CoreResult<()> {
    if depth == 0 {
        return Ok(());
    }
    for child in child_nodes(node) {
        let prefix = format!("child_{}", field_key(&child.tag));
        fields.insert(prefix.clone(), "true".to_owned());
        copy_business_notification_node_fields(child, &prefix, fields)?;
        copy_business_notification_descendant_fields(child, &prefix, fields, depth - 1)?;
    }
    Ok(())
}

fn copy_business_notification_descendant_fields(
    node: &BinaryNode,
    prefix: &str,
    fields: &mut BTreeMap<String, String>,
    depth: usize,
) -> CoreResult<()> {
    if depth == 0 {
        return Ok(());
    }
    for child in child_nodes(node) {
        let child_prefix = format!("{prefix}_child_{}", field_key(&child.tag));
        fields.insert(child_prefix.clone(), "true".to_owned());
        copy_business_notification_node_fields(child, &child_prefix, fields)?;
        copy_business_notification_descendant_fields(child, &child_prefix, fields, depth - 1)?;
    }
    Ok(())
}

fn copy_business_notification_node_fields(
    node: &BinaryNode,
    prefix: &str,
    fields: &mut BTreeMap<String, String>,
) -> CoreResult<()> {
    for (key, value) in &node.attrs {
        if !value.is_empty() {
            fields.insert(format!("{prefix}_{}", field_key(key)), value.clone());
        }
    }
    if let Some(text) = node_text(node).filter(|value| !value.is_empty()) {
        fields.insert(format!("{prefix}_text"), text);
    } else if let Some(bytes) = node_raw_bytes(node)? {
        fields.insert(format!("{prefix}_bytes_hex"), bytes_hex(bytes));
    }
    Ok(())
}

fn node_raw_bytes(node: &BinaryNode) -> CoreResult<Option<&[u8]>> {
    match node.content.as_ref() {
        Some(BinaryNodeContent::Bytes(bytes)) => Ok(Some(bytes.as_ref())),
        Some(BinaryNodeContent::Text(_)) | Some(BinaryNodeContent::Nodes(_)) | None => Ok(None),
    }
}

fn field_key(key: &str) -> String {
    key.replace('-', "_")
}

fn bytes_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

pub fn call_events_from_node(node: &BinaryNode) -> CoreResult<Vec<CallEvent>> {
    if node.tag != "call" {
        return Err(CoreError::Protocol(format!(
            "expected call node, got {}",
            node.tag
        )));
    }

    let id = required_text("call stanza id", node.attrs.get("id").map(String::as_str))?;
    let from = required_jid(
        "call sender JID",
        node.attrs.get("from").map(String::as_str),
    )?;
    let participant = optional_jid_field(
        "call participant JID",
        node.attrs.get("participant").map(String::as_str),
    )?;
    let timestamp = optional_u64_attr(node, "t", "call timestamp")?;
    let mut events = Vec::new();
    for child in child_nodes(node) {
        let mut event = CallEvent::new(&id, &from, &child.tag);
        if let Some(call_id) = first_non_empty_attr(child, &["call-id", "call_id", "id"]) {
            event = event.with_call_id(call_id);
        }
        if let Some(participant) = participant.clone() {
            event = event.with_participant(participant);
        }
        if let Some(timestamp) = timestamp {
            event = event.with_timestamp(timestamp);
        }
        event = enrich_call_event_with_baileys_metadata(event, node, child);
        for (key, value) in &child.attrs {
            if !value.is_empty() {
                event = event.with_field(key.clone(), value.clone());
            }
        }
        for nested in child_nodes(child) {
            event = event.with_field(format!("child_{}", nested.tag), "true");
            for (key, value) in &nested.attrs {
                if !value.is_empty() {
                    event = event.with_field(
                        format!("child_{}_{}", nested.tag, key.replace('-', "_")),
                        value.clone(),
                    );
                }
            }
        }
        events.push(event);
    }

    Ok(events)
}

pub fn call_message_events_from_call_events(calls: &[CallEvent]) -> CoreResult<Vec<MessageEvent>> {
    let mut out = Vec::new();
    for call in calls {
        if let Some(event) = message_event_from_call_event(call)? {
            out.push(event);
        }
    }
    Ok(out)
}

pub fn presence_event_from_node(node: &BinaryNode) -> CoreResult<Option<PresenceEvent>> {
    if !matches!(node.tag.as_str(), "presence" | "chatstate") {
        return Err(CoreError::Protocol(format!(
            "expected presence or chatstate node, got {}",
            node.tag
        )));
    }

    let presence_type = presence_type_from_node(node);
    if presence_type == "subscribe" {
        return Ok(None);
    }

    let from = required_jid(
        "presence/chatstate sender JID",
        node.attrs.get("from").map(String::as_str),
    )?;
    let participant = optional_jid_field(
        "presence/chatstate participant JID",
        node.attrs.get("participant").map(String::as_str),
    )?;
    let mut event = PresenceEvent::new(from, presence_type);
    if let Some(participant) = participant {
        event = event.with_participant(participant);
    }
    if let Some(timestamp) = optional_u64_attr(node, "t", "presence timestamp")? {
        event = event.with_timestamp(timestamp);
    } else if let Some(last_seen) = optional_u64_attr(node, "last", "presence last seen")? {
        event = event.with_timestamp(last_seen);
    }

    for (key, value) in &node.attrs {
        if !matches!(key.as_str(), "from" | "participant" | "type" | "t" | "last")
            && !value.is_empty()
        {
            event = event.with_field(key.clone(), value.clone());
        }
    }
    if let Some(last_seen) = node.attrs.get("last").filter(|value| !value.is_empty()) {
        event = event.with_field("last", last_seen.clone());
    }
    for child in child_nodes(node) {
        event = event.with_field(format!("child_{}", child.tag), "true");
        for (key, value) in &child.attrs {
            if !value.is_empty() {
                event = event.with_field(
                    format!("child_{}_{}", child.tag, key.replace('-', "_")),
                    value.clone(),
                );
            }
        }
    }

    Ok(Some(event))
}

fn presence_type_from_node(node: &BinaryNode) -> String {
    if let Some(presence_type) = node.attrs.get("type").filter(|value| !value.is_empty()) {
        return presence_type.clone();
    }
    let Some(child) = child_nodes(node).first() else {
        return "available".to_owned();
    };
    if child.tag == "composing"
        && child
            .attrs
            .get("media")
            .is_some_and(|value| value == "audio")
    {
        return "recording".to_owned();
    }
    child.tag.clone()
}

fn message_event_from_call_event(call: &CallEvent) -> CoreResult<Option<MessageEvent>> {
    let is_group = call_bool_field(call, "is_group");
    if call.event_type != "timeout" && !(call.event_type == "offer" && is_group) {
        return Ok(None);
    }

    let message_id = call
        .call_id
        .as_deref()
        .filter(|value| !value.is_empty())
        .unwrap_or(call.id.as_str());
    let mut event = MessageEvent::new(MessageEventKey::new(
        call.from.clone(),
        message_id.to_owned(),
        None,
    ))
    .with_field(
        "kind",
        if call_bool_field(call, "offline") {
            "append"
        } else {
            "notify"
        },
    )
    .with_field("source", "call_event")
    .with_field("call_status", call.event_type.clone())
    .with_field("call_id", message_id.to_owned())
    .with_field("from_me", "false");

    if let Some(timestamp) = call.timestamp {
        event = event.with_timestamp(timestamp);
    }
    for key in [
        "is_video",
        "is_group",
        "caller_pn",
        "call_from",
        "group_jid",
        "offline",
    ] {
        if let Some(value) = call.fields.get(key).filter(|value| !value.is_empty()) {
            event = event.with_field(key, value.clone());
        }
    }

    if call.event_type == "timeout" {
        let (stub_type, stub_name) = missed_call_stub_type(
            call_bool_field(call, "is_group"),
            call_bool_field(call, "is_video"),
        );
        return Ok(Some(
            event
                .with_field("message_stub_type", stub_type.to_string())
                .with_field("stub_type", stub_name),
        ));
    }

    let message = Message {
        call: Some(Box::new(ProtoCall {
            call_key: Some(bytes::Bytes::copy_from_slice(message_id.as_bytes())),
            ..ProtoCall::default()
        })),
        ..Message::default()
    };
    Ok(Some(
        event
            .with_payload(encode_message(&message)?)
            .with_field("payload_kind", "call"),
    ))
}

fn call_bool_field(call: &CallEvent, key: &str) -> bool {
    matches!(call.fields.get(key).map(String::as_str), Some("true" | "1"))
}

fn missed_call_stub_type(is_group: bool, is_video: bool) -> (i32, &'static str) {
    match (is_group, is_video) {
        (true, true) => (
            StubType::CallMissedGroupVideo as i32,
            "call_missed_group_video",
        ),
        (true, false) => (
            StubType::CallMissedGroupVoice as i32,
            "call_missed_group_voice",
        ),
        (false, true) => (StubType::CallMissedVideo as i32, "call_missed_video"),
        (false, false) => (StubType::CallMissedVoice as i32, "call_missed_voice"),
    }
}

fn enrich_call_event_with_baileys_metadata(
    mut event: CallEvent,
    node: &BinaryNode,
    child: &BinaryNode,
) -> CallEvent {
    if node
        .attrs
        .get("offline")
        .is_some_and(|value| !value.is_empty())
    {
        event = event.with_field("offline", "true");
    }
    if let Some(call_from) = first_non_empty_attr(child, &["from", "call-creator"]) {
        event = event.with_field("call_from", call_from.to_owned());
    }
    if let Some(caller_pn) = first_non_empty_attr(child, &["caller_pn", "caller-pn"]) {
        event = event.with_field("caller_pn", caller_pn.to_owned());
    }

    if child.tag == "offer" {
        let is_video = has_child_node(child, "video");
        let is_group = child
            .attrs
            .get("type")
            .is_some_and(|value| value == "group")
            || child
                .attrs
                .get("group-jid")
                .is_some_and(|value| !value.is_empty());
        event = event
            .with_field("is_video", is_video.to_string())
            .with_field("is_group", is_group.to_string());
        if let Some(group_jid) = first_non_empty_attr(child, &["group-jid", "group_jid"]) {
            event = event.with_field("group_jid", group_jid.to_owned());
        }
    }

    if child.tag == "relaylatency"
        && let Some(latency_ms) =
            first_non_empty_attr(child, &["latency", "latency_ms", "latency-ms"])
                .and_then(parse_non_negative_u64)
    {
        event = event.with_field("latency_ms", latency_ms.to_string());
    }

    event
}

pub fn newsletter_update_events_from_notification_node(
    node: &BinaryNode,
    notification: &InboundNotification,
) -> CoreResult<Vec<Event>> {
    if !notification.from.ends_with("@newsletter") {
        return Ok(Vec::new());
    }

    let mut events = Vec::new();
    for child in child_nodes(node) {
        match child.tag.as_str() {
            "reaction" => {
                events.push(Event::NewsletterReactionUpdate(vec![
                    newsletter_reaction_event_from_child(&notification.from, child)?,
                ]));
            }
            "view" => {
                events.push(Event::NewsletterViewUpdate(vec![
                    newsletter_view_event_from_child(&notification.from, child)?,
                ]));
            }
            "participant" => {
                events.push(Event::NewsletterParticipantsUpdate(vec![
                    newsletter_participant_event_from_child(
                        &notification.from,
                        notification,
                        child,
                    )?,
                ]));
            }
            "update" => {
                if let Some(event) = newsletter_settings_event_from_child(&notification.from, child)
                {
                    events.push(Event::NewsletterSettingsUpdate(vec![event]));
                }
            }
            "message" => {
                if let Some(event) = newsletter_message_event_from_child(&notification.from, child)?
                {
                    events.push(Event::MessagesUpsert(vec![event]));
                }
            }
            _ => {}
        }
    }
    Ok(events)
}

pub fn newsletter_mex_update_events_from_notification_node(
    node: &BinaryNode,
    notification: &InboundNotification,
) -> CoreResult<Vec<Event>> {
    parse_newsletter_notification_updates(node).map(|updates| {
        updates
            .into_iter()
            .map(|update| match update {
                crate::NewsletterNotificationUpdate::Settings(update) => {
                    Event::NewsletterSettingsUpdate(vec![NewsletterSettingsUpdateEvent {
                        id: update.jid,
                        fields: update.fields,
                    }])
                }
                crate::NewsletterNotificationUpdate::Participant(update) => {
                    Event::NewsletterParticipantsUpdate(vec![
                        NewsletterParticipantUpdateEvent::new(
                            update.jid,
                            notification.from.clone(),
                            update.user_jid,
                            update.action,
                            update.new_role,
                        ),
                    ])
                }
            })
            .collect()
    })
}

pub fn event_batch_from_group_notification_node(
    node: &BinaryNode,
    notification: &InboundNotification,
) -> CoreResult<Option<EventBatch>> {
    let Some(update) = group_update_event_from_notification_node(node, notification)? else {
        return Ok(None);
    };
    Ok(Some(EventBatch {
        groups_update: vec![update],
        ..EventBatch::default()
    }))
}

pub fn group_message_events_from_group_update_events(
    groups: &[GroupUpdateEvent],
) -> CoreResult<Vec<MessageEvent>> {
    let mut out = Vec::new();
    for group in groups {
        if let Some(event) = message_event_from_group_update_event(group)? {
            out.push(event);
        }
    }
    Ok(out)
}

fn message_event_from_group_update_event(
    group: &GroupUpdateEvent,
) -> CoreResult<Option<MessageEvent>> {
    let Some(notification_id) = group
        .fields
        .get("notification_id")
        .filter(|value| !value.is_empty())
    else {
        return Ok(None);
    };
    let Some(stub) = group_notification_stub_from_update(group)? else {
        return Ok(None);
    };

    let mut event = MessageEvent::new(MessageEventKey::new(
        group.jid.clone(),
        notification_id.clone(),
        group
            .fields
            .get("actor")
            .filter(|value| !value.is_empty())
            .cloned(),
    ))
    .with_field("kind", "notify")
    .with_field("source", "group_notification")
    .with_field("from_me", "false")
    .with_field("notification_id", notification_id.clone())
    .with_field("message_stub_type", (stub.stub_type as i32).to_string())
    .with_field("stub_type", stub.stub_name);

    if let Some(timestamp) = group
        .fields
        .get("timestamp")
        .and_then(|value| value.parse::<u64>().ok())
    {
        event = event.with_timestamp(timestamp);
    }
    if let Some(notification_type) = group.fields.get("notification_type") {
        event = event.with_field("notification_type", notification_type.clone());
    }
    if group.fields.get("offline").map(String::as_str) == Some("true") {
        event = event
            .with_field("kind", "append")
            .with_field("offline", "true");
    }
    if let Some(payload) = stub.payload {
        event = event
            .with_payload(payload)
            .with_field("payload_kind", "protocol_message");
    }
    if let Some(parameters) = stub.parameters {
        event = event.with_field("message_stub_parameters", parameters);
    }

    Ok(Some(event))
}

struct GroupNotificationStub {
    stub_type: StubType,
    stub_name: &'static str,
    parameters: Option<String>,
    payload: Option<Bytes>,
}

fn group_notification_stub_from_update(
    group: &GroupUpdateEvent,
) -> CoreResult<Option<GroupNotificationStub>> {
    let fields = &group.fields;
    if fields.get("group_created").map(String::as_str) == Some("true") {
        return Ok(Some(group_notification_stub(
            StubType::GroupCreate,
            "group_create",
            group_stub_parameters(fields.get("subject").map(String::as_str))?,
        )));
    }
    if let Some(picture) = fields.get("picture").map(String::as_str) {
        return Ok(Some(group_notification_stub(
            StubType::GroupChangeIcon,
            "group_change_icon",
            if picture == "changed" {
                group_stub_parameters(fields.get("picture_id").map(String::as_str))?
            } else {
                None
            },
        )));
    }
    if let Some(subject) = fields.get("subject").map(String::as_str) {
        return Ok(Some(group_notification_stub(
            StubType::GroupChangeSubject,
            "group_change_subject",
            group_stub_parameters(Some(subject))?,
        )));
    }
    if fields.contains_key("description") || fields.contains_key("description_deleted") {
        return Ok(Some(group_notification_stub(
            StubType::GroupChangeDescription,
            "group_change_description",
            group_stub_parameters(fields.get("description").map(String::as_str))?,
        )));
    }
    if let Some(parameters) = participant_action_stub_parameters(fields, "participants_add", false)?
    {
        return Ok(Some(group_notification_stub(
            StubType::GroupParticipantAdd,
            "group_participant_add",
            Some(parameters),
        )));
    }
    if let Some(parameters) =
        participant_action_stub_parameters(fields, "participants_remove", true)?
    {
        let (stub_type, stub_name) = if fields
            .get("participants_remove_is_leave")
            .map(String::as_str)
            == Some("true")
        {
            (StubType::GroupParticipantLeave, "group_participant_leave")
        } else {
            (StubType::GroupParticipantRemove, "group_participant_remove")
        };
        return Ok(Some(group_notification_stub(
            stub_type,
            stub_name,
            Some(parameters),
        )));
    }
    if let Some(parameters) =
        participant_action_stub_parameters(fields, "participants_leave", true)?
    {
        return Ok(Some(group_notification_stub(
            StubType::GroupParticipantLeave,
            "group_participant_leave",
            Some(parameters),
        )));
    }
    if let Some(parameters) =
        participant_action_stub_parameters(fields, "participants_promote", false)?
    {
        return Ok(Some(group_notification_stub(
            StubType::GroupParticipantPromote,
            "group_participant_promote",
            Some(parameters),
        )));
    }
    if let Some(parameters) =
        participant_action_stub_parameters(fields, "participants_demote", false)?
    {
        return Ok(Some(group_notification_stub(
            StubType::GroupParticipantDemote,
            "group_participant_demote",
            Some(parameters),
        )));
    }
    if let Some(parameters) =
        participant_action_stub_parameters(fields, "participants_modify", false)?
    {
        return Ok(Some(group_notification_stub(
            StubType::GroupParticipantChangeNumber,
            "group_participant_change_number",
            Some(parameters),
        )));
    }
    if let Some(parameters) =
        membership_request_stub_parameters(fields, "join_requests", "requested", true)?
    {
        return Ok(Some(group_notification_stub(
            StubType::GroupMembershipJoinApprovalRequest,
            "group_membership_join_approval_request",
            Some(parameters),
        )));
    }
    if let Some(parameters) =
        membership_request_stub_parameters(fields, "join_requests_created", "created", true)?
    {
        return Ok(Some(group_notification_stub(
            StubType::GroupMembershipJoinApprovalRequestNonAdminAdd,
            "group_membership_join_approval_request_non_admin_add",
            Some(parameters),
        )));
    }
    if let Some(parameters) =
        membership_request_stub_parameters(fields, "join_requests_revoked", "revoked", false)?
    {
        return Ok(Some(group_notification_stub(
            StubType::GroupMembershipJoinApprovalRequestNonAdminAdd,
            "group_membership_join_approval_request_non_admin_add",
            Some(parameters),
        )));
    }
    if let Some(parameters) =
        participant_action_stub_parameters(fields, "participants_invite", false)?
    {
        return Ok(Some(group_notification_stub(
            StubType::GroupParticipantInvite,
            "group_participant_invite",
            Some(parameters),
        )));
    }
    if let Some(parameters) =
        participant_action_stub_parameters(fields, "participants_accept", false)?
    {
        return Ok(Some(group_notification_stub(
            StubType::GroupParticipantAccept,
            "group_participant_accept",
            Some(parameters),
        )));
    }
    if let Some(announce) = fields.get("announce").map(String::as_str) {
        return Ok(Some(group_notification_stub(
            StubType::GroupChangeAnnounce,
            "group_change_announce",
            group_stub_parameters(Some(if announce == "true" { "on" } else { "off" }))?,
        )));
    }
    if let Some(restrict) = fields.get("restrict").map(String::as_str) {
        return Ok(Some(group_notification_stub(
            StubType::GroupChangeRestrict,
            "group_change_restrict",
            group_stub_parameters(Some(if restrict == "true" { "on" } else { "off" }))?,
        )));
    }
    if fields.get("invite_updated").map(String::as_str) == Some("true") {
        return Ok(Some(group_notification_stub(
            StubType::GroupChangeInviteLink,
            "group_change_invite_link",
            group_stub_parameters(fields.get("invite_code").map(String::as_str))?,
        )));
    }
    if fields.get("invite_revoked").map(String::as_str) == Some("true") {
        return Ok(Some(group_notification_stub(
            StubType::GroupChangeInviteLink,
            "group_change_invite_link",
            group_stub_parameters(fields.get("invite_code").map(String::as_str))?,
        )));
    }
    if let Some(mode) = fields.get("member_add_mode").map(String::as_str) {
        return Ok(Some(group_notification_stub(
            StubType::GroupMemberAddMode,
            "group_member_add_mode",
            group_stub_parameters(Some(mode))?,
        )));
    }
    if let Some(mode) = fields.get("join_approval_mode").map(String::as_str) {
        return Ok(Some(group_notification_stub(
            StubType::GroupMembershipJoinApprovalMode,
            "group_membership_join_approval_mode",
            group_stub_parameters(Some(mode))?,
        )));
    }
    if let Some(duration) = fields.get("ephemeral_duration").map(String::as_str) {
        let duration = duration.parse::<u32>().map_err(|err| {
            CoreError::Protocol(format!(
                "invalid group notification ephemeral duration {duration}: {err}"
            ))
        })?;
        let duration_parameter = duration.to_string();
        return Ok(Some(group_notification_stub_with_payload(
            StubType::ChangeEphemeralSetting,
            "change_ephemeral_setting",
            group_stub_parameters(Some(&duration_parameter))?,
            encode_message(&Message {
                protocol_message: Some(Box::new(ProtocolMessage {
                    r#type: Some(protocol_message::Type::EphemeralSetting as i32),
                    ephemeral_expiration: Some(duration),
                    ..ProtocolMessage::default()
                })),
                ..Message::default()
            })?,
        )));
    }

    Ok(None)
}

fn group_notification_stub(
    stub_type: StubType,
    stub_name: &'static str,
    parameters: Option<String>,
) -> GroupNotificationStub {
    GroupNotificationStub {
        stub_type,
        stub_name,
        parameters,
        payload: None,
    }
}

fn group_notification_stub_with_payload(
    stub_type: StubType,
    stub_name: &'static str,
    parameters: Option<String>,
    payload: Bytes,
) -> GroupNotificationStub {
    GroupNotificationStub {
        stub_type,
        stub_name,
        parameters,
        payload: Some(payload),
    }
}

fn group_stub_parameters(value: Option<&str>) -> CoreResult<Option<String>> {
    let Some(value) = value.filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    serde_json::to_string(&vec![value])
        .map(Some)
        .map_err(|err| {
            CoreError::Protocol(format!(
                "failed to encode group notification stub parameters: {err}"
            ))
        })
}

fn participant_action_stub_parameters(
    fields: &BTreeMap<String, String>,
    prefix: &str,
    allow_empty: bool,
) -> CoreResult<Option<String>> {
    let participants = group_stub_participant_list(fields, prefix);
    if participants.is_empty() && !allow_empty {
        return Ok(None);
    }
    if participants.is_empty() {
        return Ok(None);
    }

    let phone_numbers = group_stub_metadata_map(fields, prefix, "phone_numbers");
    let lids = group_stub_metadata_map(fields, prefix, "lids");
    let usernames = group_stub_metadata_map(fields, prefix, "usernames");
    let roles = group_stub_metadata_map(fields, prefix, "roles");
    let mut parameters = Vec::with_capacity(participants.len());
    for participant in participants {
        let mut value = serde_json::Map::new();
        value.insert(
            "id".to_owned(),
            serde_json::Value::String(participant.clone()),
        );
        if let Some(phone_number) = phone_numbers.get(&participant) {
            value.insert(
                "phoneNumber".to_owned(),
                serde_json::Value::String((*phone_number).to_owned()),
            );
        }
        if let Some(lid) = lids.get(&participant) {
            value.insert(
                "lid".to_owned(),
                serde_json::Value::String((*lid).to_owned()),
            );
        }
        if let Some(username) = usernames.get(&participant) {
            value.insert(
                "username".to_owned(),
                serde_json::Value::String((*username).to_owned()),
            );
        }
        if let Some(role) = roles.get(&participant) {
            value.insert(
                "admin".to_owned(),
                serde_json::Value::String((*role).to_owned()),
            );
        }
        parameters.push(
            serde_json::to_string(&serde_json::Value::Object(value)).map_err(|err| {
                CoreError::Protocol(format!(
                    "failed to encode group notification participant stub: {err}"
                ))
            })?,
        );
    }

    serde_json::to_string(&parameters).map(Some).map_err(|err| {
        CoreError::Protocol(format!(
            "failed to encode group notification participant parameters: {err}"
        ))
    })
}

fn membership_request_stub_parameters(
    fields: &BTreeMap<String, String>,
    prefix: &str,
    default_outcome: &str,
    include_method: bool,
) -> CoreResult<Option<String>> {
    let participants = group_stub_participant_list(fields, prefix);
    let Some(participant) = participants.first() else {
        return Ok(None);
    };

    let phone_numbers = group_stub_metadata_map(fields, prefix, "phone_numbers");
    let lids = group_stub_metadata_map(fields, prefix, "lids");
    let usernames = group_stub_metadata_map(fields, prefix, "usernames");
    let outcomes = group_stub_metadata_map(fields, prefix, "outcomes");
    let methods = group_stub_metadata_map(fields, prefix, "methods");

    let mut participant_value = serde_json::Map::new();
    if let Some(lid) = lids.get(participant).copied().or_else(|| {
        participant
            .ends_with("@lid")
            .then_some(participant.as_str())
    }) {
        participant_value.insert("lid".to_owned(), serde_json::Value::String(lid.to_owned()));
    }
    if let Some(phone_number) = phone_numbers
        .get(participant)
        .copied()
        .or_else(|| (!participant.ends_with("@lid")).then_some(participant.as_str()))
    {
        participant_value.insert(
            "pn".to_owned(),
            serde_json::Value::String(phone_number.to_owned()),
        );
    }
    if let Some(username) = usernames.get(participant).copied() {
        participant_value.insert(
            "username".to_owned(),
            serde_json::Value::String(username.to_owned()),
        );
    }

    let mut parameters = Vec::with_capacity(if include_method { 3 } else { 2 });
    parameters.push(
        serde_json::to_string(&serde_json::Value::Object(participant_value)).map_err(|err| {
            CoreError::Protocol(format!(
                "failed to encode group membership request participant stub: {err}"
            ))
        })?,
    );
    parameters.push(
        outcomes
            .get(participant)
            .copied()
            .unwrap_or(default_outcome)
            .to_owned(),
    );
    if include_method && let Some(method) = methods.get(participant).copied() {
        parameters.push(method.to_owned());
    }

    serde_json::to_string(&parameters).map(Some).map_err(|err| {
        CoreError::Protocol(format!(
            "failed to encode group membership request parameters: {err}"
        ))
    })
}

fn group_stub_participant_list(fields: &BTreeMap<String, String>, prefix: &str) -> Vec<String> {
    fields
        .get(prefix)
        .map(|value| {
            value
                .split(',')
                .filter(|participant| !participant.is_empty())
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn group_stub_metadata_map<'a>(
    fields: &'a BTreeMap<String, String>,
    prefix: &str,
    suffix: &str,
) -> BTreeMap<String, &'a str> {
    fields
        .get(&format!("{prefix}_{suffix}"))
        .map(|value| {
            value
                .split(',')
                .filter_map(|entry| entry.split_once('='))
                .filter(|(jid, value)| !jid.is_empty() && !value.is_empty())
                .map(|(jid, value)| (jid.to_owned(), value))
                .collect()
        })
        .unwrap_or_default()
}

pub fn event_batch_from_notification_node(
    node: &BinaryNode,
    notification: &InboundNotification,
) -> CoreResult<Option<EventBatch>> {
    let mut batch = EventBatch::default();
    if let Some(update) = group_update_event_from_notification_node(node, notification)? {
        batch.groups_update.push(update);
    }
    batch
        .contacts_update
        .extend(contact_update_events_from_picture_notification_node(
            node,
            notification,
        ));
    if batch.is_empty() {
        Ok(None)
    } else {
        Ok(Some(batch))
    }
}

pub fn contact_update_events_from_picture_notification_node(
    node: &BinaryNode,
    notification: &InboundNotification,
) -> Vec<ContactEvent> {
    if notification.notification_type.as_deref() != Some("picture") {
        return Vec::new();
    }
    let set_picture = child_node(node, "set");
    let delete_picture = child_node(node, "delete");
    let selected_picture = set_picture.or(delete_picture);
    let Some(jid) = jid_normalized_user(&notification.from)
        .or_else(|| selected_picture.and_then(|picture| optional_non_empty_attr(picture, "hash")))
    else {
        return Vec::new();
    };
    vec![
        ContactEvent::new(jid)
            .with_field(
                "img_url",
                if set_picture.is_some() {
                    "changed"
                } else {
                    "removed"
                },
            )
            .with_field("source", "picture_notification"),
    ]
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceListNotification {
    pub from: String,
    pub action: String,
    pub device_hash: Option<String>,
    pub devices: Vec<DeviceListNotificationDevice>,
}

impl DeviceListNotification {
    #[must_use]
    pub fn device_jids(&self) -> Vec<String> {
        self.devices
            .iter()
            .map(|device| device.jid.clone())
            .collect()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceListNotificationDevice {
    pub jid: String,
    pub user: String,
    pub server: String,
    pub device: Option<u16>,
}

pub fn device_list_notification_from_node(
    node: &BinaryNode,
    notification: &InboundNotification,
) -> Option<DeviceListNotification> {
    if notification.notification_type.as_deref() != Some("devices") {
        return None;
    }
    let child = child_nodes(node).first()?;
    let action = child.tag.as_str();
    if !matches!(action, "add" | "remove" | "update") {
        return None;
    }
    let devices = child_nodes(child)
        .iter()
        .filter(|device| device.tag == "device")
        .filter_map(|device| {
            let jid = device.attrs.get("jid").filter(|jid| !jid.is_empty())?;
            let decoded = jid_decode(jid)?;
            Some(DeviceListNotificationDevice {
                jid: jid.clone(),
                user: decoded.user,
                server: decoded.server_raw,
                device: decoded.device,
            })
        })
        .collect::<Vec<_>>();
    if devices.is_empty() {
        return None;
    }
    Some(DeviceListNotification {
        from: notification.from.clone(),
        action: action.to_owned(),
        device_hash: optional_non_empty_attr(child, "device_hash"),
        devices,
    })
}

fn newsletter_reaction_event_from_child(
    newsletter_jid: &str,
    child: &BinaryNode,
) -> CoreResult<NewsletterReactionEvent> {
    let server_id = required_text(
        "newsletter reaction message id",
        first_non_empty_attr(child, &["message_id", "server_id"]),
    )?;
    let mut event = NewsletterReactionEvent::new(newsletter_jid, server_id).with_count(1);
    if let Some(code) = child_node(child, "reaction")
        .and_then(|reaction| {
            node_text(reaction)
                .filter(|value| !value.is_empty())
                .or_else(|| first_non_empty_attr(reaction, &["code"]).map(str::to_owned))
        })
        .or_else(|| first_non_empty_attr(child, &["code"]).map(str::to_owned))
    {
        event = event.with_code(code);
    }
    Ok(event)
}

fn newsletter_view_event_from_child(
    newsletter_jid: &str,
    child: &BinaryNode,
) -> CoreResult<NewsletterViewEvent> {
    let server_id = required_text(
        "newsletter view message id",
        first_non_empty_attr(child, &["message_id", "server_id"]),
    )?;
    let count_text = first_non_empty_attr(child, &["count", "view_count", "views"])
        .map(str::to_owned)
        .or_else(|| node_text(child))
        .unwrap_or_else(|| "0".to_owned());
    let count_text = count_text.trim();
    let count = if count_text.is_empty() {
        0
    } else {
        count_text
            .parse::<u64>()
            .map_err(|err| CoreError::Protocol(format!("invalid newsletter view count: {err}")))?
    };
    Ok(NewsletterViewEvent::new(newsletter_jid, server_id, count))
}

fn newsletter_participant_event_from_child(
    newsletter_jid: &str,
    notification: &InboundNotification,
    child: &BinaryNode,
) -> CoreResult<NewsletterParticipantUpdateEvent> {
    let author = required_jid(
        "newsletter participant update author",
        notification.participant.as_deref(),
    )?;
    let user = required_jid(
        "newsletter participant update user",
        child.attrs.get("jid").map(String::as_str),
    )?;
    let action = required_text(
        "newsletter participant update action",
        child.attrs.get("action").map(String::as_str),
    )?;
    let new_role = required_text(
        "newsletter participant update role",
        child.attrs.get("role").map(String::as_str),
    )?;
    Ok(NewsletterParticipantUpdateEvent::new(
        newsletter_jid,
        author,
        user,
        action,
        new_role,
    ))
}

fn newsletter_settings_event_from_child(
    newsletter_jid: &str,
    child: &BinaryNode,
) -> Option<NewsletterSettingsUpdateEvent> {
    let settings = child_node(child, "settings")?;
    let mut event = NewsletterSettingsUpdateEvent::new(newsletter_jid);
    if let Some(name) = child_node(settings, "name")
        .and_then(node_text)
        .filter(|value| !value.is_empty())
    {
        event = event.with_field("name", name);
    }
    if let Some(description) = child_node(settings, "description")
        .and_then(node_text)
        .filter(|value| !value.is_empty())
    {
        event = event.with_field("description", description);
    }
    Some(event)
}

fn newsletter_message_event_from_child(
    newsletter_jid: &str,
    child: &BinaryNode,
) -> CoreResult<Option<MessageEvent>> {
    let Some(plaintext) = child_node(child, "plaintext") else {
        return Ok(None);
    };
    let payload = node_bytes(plaintext, "newsletter plaintext message")?;
    let message = Message::decode(payload)?;
    let message_id = required_text(
        "newsletter message id",
        child
            .attrs
            .get("message_id")
            .or_else(|| child.attrs.get("server_id"))
            .map(String::as_str),
    )?;
    let mut event = MessageEvent::new(MessageEventKey::new(newsletter_jid, message_id, None))
        .with_payload(encode_message(&message)?)
        .with_field("kind", "newsletter")
        .with_field("payload_kind", "plaintext")
        .with_field("source", "newsletter_notification")
        .with_field("from_me", "false");
    if let Some(timestamp) = optional_u64_attr(child, "t", "newsletter message timestamp")? {
        event = event.with_timestamp(timestamp);
    }
    Ok(Some(event))
}

fn newsletter_update_event_count(event: &Event) -> usize {
    match event {
        Event::MessagesUpsert(updates) => updates.len(),
        Event::NewsletterReactionUpdate(updates) => updates.len(),
        Event::NewsletterViewUpdate(updates) => updates.len(),
        Event::NewsletterParticipantsUpdate(updates) => updates.len(),
        Event::NewsletterSettingsUpdate(updates) => updates.len(),
        _ => 1,
    }
}

pub fn group_update_event_from_notification_node(
    node: &BinaryNode,
    notification: &InboundNotification,
) -> CoreResult<Option<GroupUpdateEvent>> {
    if !notification.from.ends_with("@g.us") {
        return Ok(None);
    }

    let mut event = GroupUpdateEvent::new(notification.from.clone())
        .with_field("notification_id", notification.id.clone());
    if let Some(notification_type) = &notification.notification_type {
        event = event.with_field("notification_type", notification_type.clone());
    }
    if let Some(timestamp) = notification.timestamp {
        event = event.with_field("timestamp", timestamp.to_string());
    }
    if let Some(participant) = &notification.participant {
        event = event.with_field("actor", participant.clone());
    }
    if node
        .attrs
        .get("offline")
        .is_some_and(|value| !value.is_empty())
    {
        event = event.with_field("offline", "true");
    }

    let mut recognized = false;
    if notification.notification_type.as_deref() == Some("picture")
        && (child_node(node, "set").is_some()
            || child_node(node, "delete").is_some()
            || child_node(node, "picture").is_none())
    {
        apply_group_notification_picture_notification(node, &mut event)?;
        recognized = true;
    }
    for child in child_nodes(node) {
        recognized |= apply_group_notification_child(node, child, &mut event)?;
    }

    if recognized {
        if let Some(actor_pn) = optional_jid_field(
            "group notification actor PN",
            first_non_empty_attr(node, GROUP_NOTIFICATION_ACTOR_PN_ATTRS),
        )? {
            event = event.with_field("actor_pn", actor_pn);
        }
        if let Some(actor_username) =
            first_non_empty_attr(node, GROUP_NOTIFICATION_ACTOR_USERNAME_ATTRS)
        {
            event = event.with_field("actor_username", actor_username.to_owned());
        }
        Ok(Some(event))
    } else {
        Ok(None)
    }
}

fn apply_group_notification_child(
    node: &BinaryNode,
    child: &BinaryNode,
    event: &mut GroupUpdateEvent,
) -> CoreResult<bool> {
    match child.tag.as_str() {
        "create" => {
            apply_group_notification_create_child(child, event)?;
            Ok(true)
        }
        "subject" => {
            if let Some(subject) = attr_or_text(child, &["subject", "value", "text"]) {
                event.fields.insert("subject".to_owned(), subject);
            }
            copy_optional_attrs(
                child,
                event,
                &[
                    ("participant", "subject_owner"),
                    ("author", "subject_owner"),
                    ("s_t", "subject_time"),
                    ("t", "subject_time"),
                ],
            );
            copy_first_optional_jid_attr(
                child,
                event,
                "group notification subject owner JID",
                &["s_o"],
                "subject_owner",
            )?;
            copy_first_optional_jid_attr(
                child,
                event,
                "group notification subject owner PN",
                &[
                    "participant_pn",
                    "participantPn",
                    "author_pn",
                    "authorPn",
                    "s_o_pn",
                    "sOPn",
                    "phone_number",
                    "phoneNumber",
                    "pn",
                    "pn_jid",
                    "pnJid",
                ],
                "subject_owner_pn",
            )?;
            copy_first_optional_attr(
                child,
                event,
                &[
                    "participant_username",
                    "participantUsername",
                    "author_username",
                    "authorUsername",
                    "s_o_username",
                    "sOUsername",
                    "username",
                ],
                "subject_owner_username",
            );
            Ok(true)
        }
        "description" | "desc" => {
            if let Some(description) = attr_or_text(child, &["description", "value", "text"])
                .or_else(|| child_node(child, "body").and_then(node_text))
                .filter(|value| !value.is_empty())
            {
                event.fields.insert("description".to_owned(), description);
            }
            if matches!(
                child.attrs.get("delete").map(String::as_str),
                Some("true" | "1")
            ) {
                event
                    .fields
                    .insert("description_deleted".to_owned(), "true".to_owned());
            }
            copy_optional_attrs(
                child,
                event,
                &[
                    ("id", "description_id"),
                    ("participant", "description_owner"),
                    ("author", "description_owner"),
                    ("t", "description_time"),
                ],
            );
            copy_first_optional_jid_attr(
                child,
                event,
                "group notification description owner PN",
                GROUP_NOTIFICATION_AUTHOR_PN_ATTRS,
                "description_owner_pn",
            )?;
            copy_first_optional_attr(
                child,
                event,
                GROUP_NOTIFICATION_AUTHOR_USERNAME_ATTRS,
                "description_owner_username",
            );
            Ok(true)
        }
        "announcement" => {
            event
                .fields
                .insert("announce".to_owned(), "true".to_owned());
            Ok(true)
        }
        "not_announcement" => {
            event
                .fields
                .insert("announce".to_owned(), "false".to_owned());
            Ok(true)
        }
        "locked" => {
            event
                .fields
                .insert("restrict".to_owned(), "true".to_owned());
            Ok(true)
        }
        "unlocked" => {
            event
                .fields
                .insert("restrict".to_owned(), "false".to_owned());
            Ok(true)
        }
        "ephemeral" => {
            copy_optional_attrs(child, event, &[("expiration", "ephemeral_duration")]);
            Ok(true)
        }
        "not_ephemeral" => {
            event
                .fields
                .insert("ephemeral_duration".to_owned(), "0".to_owned());
            Ok(true)
        }
        "membership_approval_mode" => {
            if let Some(state) = attr_or_text(child, &["state", "value"]).or_else(|| {
                child_node(child, "group_join")
                    .and_then(|group_join| attr_or_text(group_join, &["state", "value"]))
            }) {
                event.fields.insert("join_approval_mode".to_owned(), state);
            }
            Ok(true)
        }
        "member_add_mode" => {
            if let Some(mode) = attr_or_text(child, &["mode", "value"]) {
                event.fields.insert("member_add_mode".to_owned(), mode);
            }
            Ok(true)
        }
        "parent" => {
            event
                .fields
                .insert("is_community".to_owned(), "true".to_owned());
            copy_optional_attrs(
                child,
                event,
                &[(
                    "default_membership_approval_mode",
                    "default_membership_approval_mode",
                )],
            );
            Ok(true)
        }
        "default_sub_group" => {
            event
                .fields
                .insert("is_community_announce".to_owned(), "true".to_owned());
            Ok(true)
        }
        "linked_parent" => {
            if let Some(parent_jid) = optional_jid_field(
                "group notification linked parent JID",
                child.attrs.get("jid").map(String::as_str),
            )? {
                event.fields.insert("linked_parent".to_owned(), parent_jid);
            }
            Ok(true)
        }
        "invite" => {
            apply_group_notification_invite_child(node, child, event, "invite_updated")?;
            Ok(true)
        }
        "revoke" => {
            apply_group_notification_invite_child(node, child, event, "invite_revoked")?;
            Ok(true)
        }
        "accept" => {
            apply_group_notification_invite_child(node, child, event, "invite_accepted")?;
            Ok(true)
        }
        "membership_approval_requests" | "membership_approval_request" => {
            apply_group_notification_join_requests_child(child, event)?;
            Ok(true)
        }
        "membership_requests_action" => {
            apply_group_notification_join_request_action_child(child, event)?;
            Ok(true)
        }
        "created_membership_requests" => {
            apply_group_notification_membership_request_lifecycle_child(
                node, child, event, "created",
            )?;
            Ok(true)
        }
        "revoked_membership_requests" => {
            apply_group_notification_membership_request_lifecycle_child(
                node, child, event, "revoked",
            )?;
            Ok(true)
        }
        "picture" => {
            apply_group_notification_picture_child(child, event)?;
            Ok(true)
        }
        "add" | "remove" | "promote" | "demote" | "leave" | "modify" => {
            let participants = group_notification_participants(child)?;
            add_group_notification_action_participant_fields(
                node,
                event,
                &child.tag,
                &participants,
            );
            Ok(true)
        }
        _ => Ok(false),
    }
}

fn apply_group_notification_create_child(
    child: &BinaryNode,
    event: &mut GroupUpdateEvent,
) -> CoreResult<()> {
    event
        .fields
        .insert("group_created".to_owned(), "true".to_owned());
    if let Some(group_id) = optional_non_empty_attr(child, "id") {
        event.fields.insert("group_id".to_owned(), group_id);
    }
    if let Some(subject) = attr_or_text(child, &["subject", "value", "text"]) {
        event.fields.insert("subject".to_owned(), subject);
    }
    copy_optional_attrs(
        child,
        event,
        &[
            ("notify", "notify"),
            ("addressing_mode", "addressing_mode"),
            ("s_o_username", "subject_owner_username"),
            ("creator_username", "owner_username"),
            ("creator_country_code", "owner_country_code"),
        ],
    );
    copy_optional_jid_attr(
        child,
        event,
        "group notification create subject owner JID",
        "s_o",
        "subject_owner",
    )?;
    copy_optional_jid_attr(
        child,
        event,
        "group notification create subject owner PN",
        "s_o_pn",
        "subject_owner_pn",
    )?;
    copy_optional_jid_attr(
        child,
        event,
        "group notification create owner JID",
        "creator",
        "owner",
    )?;
    copy_optional_jid_attr(
        child,
        event,
        "group notification create owner PN",
        "creator_pn",
        "owner_pn",
    )?;
    copy_optional_u64_attr(
        child,
        event,
        "s_t",
        "subject_time",
        "group notification create subject timestamp",
    )?;
    copy_optional_u64_attr(
        child,
        event,
        "creation",
        "creation",
        "group notification create timestamp",
    )?;
    copy_optional_u64_attr(
        child,
        event,
        "size",
        "size",
        "group notification create size",
    )?;

    for nested in child_nodes(child)
        .iter()
        .filter(|nested| nested.tag != "participant")
    {
        apply_group_notification_child(child, nested, event)?;
    }
    let participants = group_notification_participants(child)?;
    add_group_notification_snapshot_participant_fields(event, &participants);
    Ok(())
}

fn apply_group_notification_invite_child(
    parent: &BinaryNode,
    child: &BinaryNode,
    event: &mut GroupUpdateEvent,
    action_field: &str,
) -> CoreResult<()> {
    event
        .fields
        .insert(action_field.to_owned(), "true".to_owned());
    if let Some(code) = attr_or_text(child, &["code", "invite_code"]) {
        event.fields.insert("invite_code".to_owned(), code);
    }
    if let Some(expiration) =
        optional_u64_attr(child, "expiration", "group notification invite expiration")?
    {
        event
            .fields
            .insert("invite_expiration".to_owned(), expiration.to_string());
    }
    if let Some(admin) = optional_jid_field(
        "group notification invite admin JID",
        first_non_empty_attr(child, &["admin", "author"]),
    )? {
        event.fields.insert("invite_admin".to_owned(), admin);
    }
    copy_first_optional_jid_attr(
        child,
        event,
        "group notification invite admin PN",
        GROUP_NOTIFICATION_INVITE_ADMIN_PN_ATTRS,
        "invite_admin_pn",
    )?;
    copy_first_optional_attr(
        child,
        event,
        GROUP_NOTIFICATION_INVITE_ADMIN_USERNAME_ATTRS,
        "invite_admin_username",
    );
    let participants = group_notification_invite_participants(parent, child, action_field)?;
    add_group_notification_participant_fields(event, &child.tag, &participants);
    Ok(())
}

fn group_notification_invite_participants(
    parent: &BinaryNode,
    child: &BinaryNode,
    action_field: &str,
) -> CoreResult<Vec<GroupNotificationParticipant>> {
    let mut participants = group_notification_participants(child)?;
    if participants.is_empty()
        && action_field == "invite_accepted"
        && let Some(participant) = group_notification_fallback_participant(
            parent,
            child,
            "group notification accepted invite participant",
        )?
    {
        participants.push(participant);
    }
    Ok(participants)
}

fn apply_group_notification_join_requests_child(
    child: &BinaryNode,
    event: &mut GroupUpdateEvent,
) -> CoreResult<()> {
    let requests = if child.tag == "membership_approval_request" {
        vec![group_notification_join_request(child)?]
    } else {
        child_nodes(child)
            .iter()
            .filter(|request| request.tag == "membership_approval_request")
            .map(group_notification_join_request)
            .collect::<CoreResult<Vec<_>>>()?
    };
    add_group_notification_join_request_fields(event, &requests);
    Ok(())
}

fn apply_group_notification_picture_child(
    child: &BinaryNode,
    event: &mut GroupUpdateEvent,
) -> CoreResult<()> {
    if let Some(set) = child_node(child, "set") {
        apply_group_notification_picture_change_child(set, event, true)
    } else if let Some(delete) = child_node(child, "delete") {
        apply_group_notification_picture_change_child(delete, event, false)
    } else {
        apply_group_notification_picture_change_child(child, event, false)
    }
}

fn apply_group_notification_picture_notification(
    node: &BinaryNode,
    event: &mut GroupUpdateEvent,
) -> CoreResult<()> {
    if let Some(set) = child_node(node, "set") {
        apply_group_notification_picture_change_child(set, event, true)
    } else if let Some(delete) = child_node(node, "delete") {
        apply_group_notification_picture_change_child(delete, event, false)
    } else {
        apply_group_notification_picture_change_child(node, event, false)
    }
}

fn apply_group_notification_picture_change_child(
    picture: &BinaryNode,
    event: &mut GroupUpdateEvent,
    changed: bool,
) -> CoreResult<()> {
    if changed {
        event
            .fields
            .insert("picture".to_owned(), "changed".to_owned());
        event
            .fields
            .insert("picture_changed".to_owned(), "true".to_owned());
    } else {
        event
            .fields
            .insert("picture".to_owned(), "removed".to_owned());
        event
            .fields
            .insert("picture_removed".to_owned(), "true".to_owned());
    }
    copy_optional_attrs(
        picture,
        event,
        &[
            ("id", "picture_id"),
            ("hash", "picture_hash"),
            ("t", "picture_time"),
        ],
    );
    copy_first_optional_attr(
        picture,
        event,
        GROUP_NOTIFICATION_AUTHOR_USERNAME_ATTRS,
        "picture_author_username",
    );
    copy_first_optional_jid_attr(
        picture,
        event,
        "group notification picture author JID",
        &["author", "participant"],
        "picture_author",
    )?;
    copy_first_optional_jid_attr(
        picture,
        event,
        "group notification picture author PN",
        GROUP_NOTIFICATION_AUTHOR_PN_ATTRS,
        "picture_author_pn",
    )?;
    Ok(())
}

fn apply_group_notification_join_request_action_child(
    child: &BinaryNode,
    event: &mut GroupUpdateEvent,
) -> CoreResult<()> {
    for action in child_nodes(child)
        .iter()
        .filter(|action| matches!(action.tag.as_str(), "approve" | "reject"))
    {
        event
            .fields
            .insert(format!("join_requests_{}", action.tag), "true".to_owned());
        let participants = group_notification_participants(action)?;
        add_group_notification_participant_fields_with_prefix(
            event,
            &format!("join_requests_{}", action.tag),
            &participants,
        );
    }
    Ok(())
}

fn apply_group_notification_membership_request_lifecycle_child(
    parent: &BinaryNode,
    child: &BinaryNode,
    event: &mut GroupUpdateEvent,
    action: &str,
) -> CoreResult<()> {
    let prefix = format!("join_requests_{action}");
    event.fields.insert(prefix.clone(), "true".to_owned());
    let participants = group_notification_request_participants(parent, child)?;
    let requested_at = optional_u64_attr(
        child,
        "t",
        "group notification membership request timestamp",
    )?
    .map(|value| value.to_string());
    add_group_notification_participant_fields_with_prefix(event, &prefix, &participants);
    insert_group_participant_owned_metadata_field(event, &prefix, "methods", &participants, |_| {
        first_non_empty_attr(child, GROUP_NOTIFICATION_REQUEST_METHOD_ATTRS).map(str::to_owned)
    });
    insert_group_participant_owned_metadata_field(
        event,
        &prefix,
        "requested_at",
        &participants,
        |_| requested_at.clone(),
    );
    if action == "created" {
        insert_group_participant_static_metadata_field(
            event,
            &prefix,
            "outcomes",
            &participants,
            "created",
        );
    } else {
        insert_group_participant_owned_metadata_field(
            event,
            &prefix,
            "outcomes",
            &participants,
            |participant| {
                Some(
                    if group_notification_same_actor(parent, &participant.jid) {
                        "revoked"
                    } else {
                        "rejected"
                    }
                    .to_owned(),
                )
            },
        );
    }
    Ok(())
}

fn insert_group_participant_owned_metadata_field<F>(
    event: &mut GroupUpdateEvent,
    prefix: &str,
    suffix: &str,
    participants: &[GroupNotificationParticipant],
    mut value: F,
) where
    F: FnMut(&GroupNotificationParticipant) -> Option<String>,
{
    let mappings = participants
        .iter()
        .filter_map(|participant| {
            value(participant).map(|value| format!("{}={value}", participant.jid))
        })
        .collect::<Vec<_>>();
    if !mappings.is_empty() {
        event
            .fields
            .insert(format!("{prefix}_{suffix}"), mappings.join(","));
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct GroupNotificationParticipant {
    jid: String,
    role: Option<String>,
    error: Option<String>,
    status: Option<String>,
    lid: Option<String>,
    phone_number: Option<String>,
    username: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct GroupNotificationJoinRequest {
    jid: String,
    lid: Option<String>,
    phone_number: Option<String>,
    username: Option<String>,
    requested_at: Option<String>,
    request_method: Option<String>,
}

const GROUP_NOTIFICATION_PARTICIPANT_LID_ATTRS: &[&str] = &[
    "lid",
    "lid_jid",
    "lidJid",
    "participant_lid",
    "participantLid",
];
const GROUP_NOTIFICATION_ACTOR_LID_ATTRS: &[&str] = &[
    "participant_lid",
    "participantLid",
    "sender_lid",
    "senderLid",
    "lid_jid",
    "lidJid",
];
const GROUP_NOTIFICATION_PARTICIPANT_PN_ATTRS: &[&str] = &[
    "phone_number",
    "phoneNumber",
    "pn",
    "pn_jid",
    "pnJid",
    "participant_pn",
    "participantPn",
];
const GROUP_NOTIFICATION_PARTICIPANT_USERNAME_ATTRS: &[&str] =
    &["participant_username", "participantUsername", "username"];
const GROUP_NOTIFICATION_REQUEST_METHOD_ATTRS: &[&str] =
    &["request_method", "requestMethod", "method"];
const GROUP_NOTIFICATION_ACTOR_PN_ATTRS: &[&str] = &[
    "participant_pn",
    "participantPn",
    "sender_pn",
    "senderPn",
    "phone_number",
    "phoneNumber",
    "pn",
    "pn_jid",
    "pnJid",
];
const GROUP_NOTIFICATION_ACTOR_USERNAME_ATTRS: &[&str] = &[
    "participant_username",
    "participantUsername",
    "sender_username",
    "senderUsername",
    "username",
];
const GROUP_NOTIFICATION_AUTHOR_PN_ATTRS: &[&str] = &[
    "author_pn",
    "authorPn",
    "participant_pn",
    "participantPn",
    "phone_number",
    "phoneNumber",
    "pn",
    "pn_jid",
    "pnJid",
];
const GROUP_NOTIFICATION_AUTHOR_USERNAME_ATTRS: &[&str] = &[
    "author_username",
    "authorUsername",
    "participant_username",
    "participantUsername",
    "username",
];
const GROUP_NOTIFICATION_INVITE_ADMIN_PN_ATTRS: &[&str] = &[
    "admin_pn",
    "adminPn",
    "author_pn",
    "authorPn",
    "participant_pn",
    "participantPn",
    "phone_number",
    "phoneNumber",
    "pn",
    "pn_jid",
    "pnJid",
];
const GROUP_NOTIFICATION_INVITE_ADMIN_USERNAME_ATTRS: &[&str] = &[
    "admin_username",
    "adminUsername",
    "author_username",
    "authorUsername",
    "participant_username",
    "participantUsername",
    "username",
];

fn group_notification_participants(
    node: &BinaryNode,
) -> CoreResult<Vec<GroupNotificationParticipant>> {
    child_nodes(node)
        .iter()
        .filter(|child| child.tag == "participant")
        .map(|participant| {
            let jid = required_text(
                "group notification participant JID",
                participant.attrs.get("jid").map(String::as_str),
            )?;
            validate_jid("group notification participant JID", &jid)?;
            Ok(GroupNotificationParticipant {
                jid,
                role: optional_non_empty_attr(participant, "type"),
                error: optional_non_empty_attr(participant, "error"),
                status: optional_non_empty_attr(participant, "status"),
                lid: optional_jid_field(
                    "group notification participant LID",
                    first_non_empty_attr(participant, GROUP_NOTIFICATION_PARTICIPANT_LID_ATTRS),
                )?,
                phone_number: optional_jid_field(
                    "group notification participant phone number",
                    first_non_empty_attr(participant, GROUP_NOTIFICATION_PARTICIPANT_PN_ATTRS),
                )?,
                username: first_non_empty_attr(
                    participant,
                    GROUP_NOTIFICATION_PARTICIPANT_USERNAME_ATTRS,
                )
                .map(str::to_owned),
            })
        })
        .collect()
}

fn group_notification_request_participants(
    parent: &BinaryNode,
    child: &BinaryNode,
) -> CoreResult<Vec<GroupNotificationParticipant>> {
    let mut participants = group_notification_participants(child)?;
    if participants.is_empty()
        && let Some(participant) = group_notification_request_fallback_participant(parent, child)?
    {
        participants.push(participant);
    }
    Ok(participants)
}

fn group_notification_request_fallback_participant(
    parent: &BinaryNode,
    child: &BinaryNode,
) -> CoreResult<Option<GroupNotificationParticipant>> {
    group_notification_fallback_participant(
        parent,
        child,
        "group notification membership request participant",
    )
}

fn group_notification_fallback_participant(
    parent: &BinaryNode,
    child: &BinaryNode,
    label: &str,
) -> CoreResult<Option<GroupNotificationParticipant>> {
    let Some(jid) = first_non_empty_attr(child, &["jid", "participant"])
        .or_else(|| first_non_empty_attr(parent, &["participant"]))
    else {
        return Ok(None);
    };
    validate_jid(&format!("{label} JID"), jid)?;
    Ok(Some(GroupNotificationParticipant {
        jid: jid.to_owned(),
        role: optional_non_empty_attr(child, "type"),
        error: optional_non_empty_attr(child, "error"),
        status: optional_non_empty_attr(child, "status"),
        lid: optional_jid_field(
            &format!("{label} LID"),
            first_non_empty_attr(child, GROUP_NOTIFICATION_PARTICIPANT_LID_ATTRS)
                .or_else(|| first_non_empty_attr(parent, GROUP_NOTIFICATION_ACTOR_LID_ATTRS)),
        )?,
        phone_number: optional_jid_field(
            &format!("{label} phone number"),
            first_non_empty_attr(child, GROUP_NOTIFICATION_PARTICIPANT_PN_ATTRS)
                .or_else(|| first_non_empty_attr(parent, GROUP_NOTIFICATION_ACTOR_PN_ATTRS)),
        )?,
        username: first_non_empty_attr(child, GROUP_NOTIFICATION_PARTICIPANT_USERNAME_ATTRS)
            .or_else(|| first_non_empty_attr(parent, GROUP_NOTIFICATION_ACTOR_USERNAME_ATTRS))
            .map(str::to_owned),
    }))
}

fn group_notification_join_request(node: &BinaryNode) -> CoreResult<GroupNotificationJoinRequest> {
    let jid = required_text(
        "group notification join request JID",
        first_non_empty_attr(node, &["jid", "participant"]),
    )?;
    validate_jid("group notification join request JID", &jid)?;
    Ok(GroupNotificationJoinRequest {
        jid,
        lid: optional_jid_field(
            "group notification join request LID",
            first_non_empty_attr(node, GROUP_NOTIFICATION_PARTICIPANT_LID_ATTRS),
        )?,
        phone_number: optional_jid_field(
            "group notification join request phone number",
            first_non_empty_attr(node, GROUP_NOTIFICATION_PARTICIPANT_PN_ATTRS),
        )?,
        username: first_non_empty_attr(node, GROUP_NOTIFICATION_PARTICIPANT_USERNAME_ATTRS)
            .map(str::to_owned),
        requested_at: optional_u64_attr(node, "t", "group notification join request timestamp")?
            .map(|value| value.to_string()),
        request_method: first_non_empty_attr(node, GROUP_NOTIFICATION_REQUEST_METHOD_ATTRS)
            .map(str::to_owned),
    })
}

fn add_group_notification_participant_fields(
    event: &mut GroupUpdateEvent,
    action: &str,
    participants: &[GroupNotificationParticipant],
) {
    add_group_notification_participant_fields_with_prefix(
        event,
        &format!("participants_{action}"),
        participants,
    );
}

fn add_group_notification_action_participant_fields(
    parent: &BinaryNode,
    event: &mut GroupUpdateEvent,
    action: &str,
    participants: &[GroupNotificationParticipant],
) {
    add_group_notification_participant_fields(event, action, participants);
    if action == "remove" && group_notification_remove_is_leave(parent, participants) {
        event
            .fields
            .insert("participants_remove_is_leave".to_owned(), "true".to_owned());
        add_group_notification_participant_fields(event, "leave", participants);
    }
}

fn group_notification_remove_is_leave(
    parent: &BinaryNode,
    participants: &[GroupNotificationParticipant],
) -> bool {
    participants
        .first()
        .filter(|_| participants.len() == 1)
        .is_some_and(|participant| group_notification_participant_is_actor(parent, participant))
}

fn group_notification_participant_is_actor(
    parent: &BinaryNode,
    participant: &GroupNotificationParticipant,
) -> bool {
    let actor_jids = [
        first_non_empty_attr(parent, &["participant"]),
        first_non_empty_attr(parent, GROUP_NOTIFICATION_ACTOR_PN_ATTRS),
    ];
    let participant_jids = [
        Some(participant.jid.as_str()),
        participant.phone_number.as_deref(),
        participant.lid.as_deref(),
    ];
    actor_jids.iter().flatten().any(|actor| {
        participant_jids
            .iter()
            .flatten()
            .any(|candidate| same_jid_user(actor, candidate))
    })
}

fn add_group_notification_snapshot_participant_fields(
    event: &mut GroupUpdateEvent,
    participants: &[GroupNotificationParticipant],
) {
    add_group_notification_participant_fields_with_prefix(event, "participants", participants);
    let admins = participants
        .iter()
        .filter(|participant| participant.role.as_deref() == Some("admin"))
        .map(|participant| participant.jid.as_str())
        .collect::<Vec<_>>();
    if !admins.is_empty() {
        event
            .fields
            .insert("participants_admins".to_owned(), admins.join(","));
        event.fields.insert(
            "participants_admins_count".to_owned(),
            admins.len().to_string(),
        );
    }
    let superadmins = participants
        .iter()
        .filter(|participant| participant.role.as_deref() == Some("superadmin"))
        .map(|participant| participant.jid.as_str())
        .collect::<Vec<_>>();
    if !superadmins.is_empty() {
        event
            .fields
            .insert("participants_superadmins".to_owned(), superadmins.join(","));
        event.fields.insert(
            "participants_superadmins_count".to_owned(),
            superadmins.len().to_string(),
        );
    }
}

fn add_group_notification_participant_fields_with_prefix(
    event: &mut GroupUpdateEvent,
    prefix: &str,
    participants: &[GroupNotificationParticipant],
) {
    if participants.is_empty() {
        return;
    }

    event.fields.insert(
        prefix.to_owned(),
        participants
            .iter()
            .map(|participant| participant.jid.as_str())
            .collect::<Vec<_>>()
            .join(","),
    );
    event
        .fields
        .insert(format!("{prefix}_count"), participants.len().to_string());
    insert_group_participant_metadata_field(event, prefix, "roles", participants, |participant| {
        participant.role.as_deref()
    });
    insert_group_participant_metadata_field(event, prefix, "errors", participants, |participant| {
        participant.error.as_deref()
    });
    insert_group_participant_metadata_field(
        event,
        prefix,
        "statuses",
        participants,
        |participant| participant.status.as_deref(),
    );
    insert_group_participant_metadata_field(event, prefix, "lids", participants, |participant| {
        participant.lid.as_deref()
    });
    insert_group_participant_metadata_field(
        event,
        prefix,
        "phone_numbers",
        participants,
        |participant| participant.phone_number.as_deref(),
    );
    insert_group_participant_metadata_field(
        event,
        prefix,
        "usernames",
        participants,
        |participant| participant.username.as_deref(),
    );
}

fn insert_group_participant_metadata_field<F>(
    event: &mut GroupUpdateEvent,
    prefix: &str,
    suffix: &str,
    participants: &[GroupNotificationParticipant],
    mut value: F,
) where
    F: FnMut(&GroupNotificationParticipant) -> Option<&str>,
{
    let mappings = participants
        .iter()
        .filter_map(|participant| {
            value(participant).map(|value| format!("{}={value}", participant.jid))
        })
        .collect::<Vec<_>>();
    if !mappings.is_empty() {
        event
            .fields
            .insert(format!("{prefix}_{suffix}"), mappings.join(","));
    }
}

fn insert_group_participant_static_metadata_field(
    event: &mut GroupUpdateEvent,
    prefix: &str,
    suffix: &str,
    participants: &[GroupNotificationParticipant],
    value: &str,
) {
    insert_group_participant_owned_metadata_field(event, prefix, suffix, participants, |_| {
        Some(value.to_owned())
    });
}

fn group_notification_same_actor(parent: &BinaryNode, jid: &str) -> bool {
    first_non_empty_attr(parent, &["participant"])
        .or_else(|| first_non_empty_attr(parent, GROUP_NOTIFICATION_ACTOR_PN_ATTRS))
        .is_some_and(|actor| same_jid_user(actor, jid))
}

fn add_group_notification_join_request_fields(
    event: &mut GroupUpdateEvent,
    requests: &[GroupNotificationJoinRequest],
) {
    if requests.is_empty() {
        return;
    }

    event.fields.insert(
        "join_requests".to_owned(),
        requests
            .iter()
            .map(|request| request.jid.as_str())
            .collect::<Vec<_>>()
            .join(","),
    );
    event
        .fields
        .insert("join_requests_count".to_owned(), requests.len().to_string());
    insert_group_join_request_metadata_field(event, "lids", requests, |request| {
        request.lid.as_deref()
    });
    insert_group_join_request_metadata_field(event, "phone_numbers", requests, |request| {
        request.phone_number.as_deref()
    });
    insert_group_join_request_metadata_field(event, "usernames", requests, |request| {
        request.username.as_deref()
    });
    insert_group_join_request_metadata_field(event, "requested_at", requests, |request| {
        request.requested_at.as_deref()
    });
    insert_group_join_request_metadata_field(event, "methods", requests, |request| {
        request.request_method.as_deref()
    });
}

fn insert_group_join_request_metadata_field<F>(
    event: &mut GroupUpdateEvent,
    suffix: &str,
    requests: &[GroupNotificationJoinRequest],
    mut value: F,
) where
    F: FnMut(&GroupNotificationJoinRequest) -> Option<&str>,
{
    let mappings = requests
        .iter()
        .filter_map(|request| value(request).map(|value| format!("{}={value}", request.jid)))
        .collect::<Vec<_>>();
    if !mappings.is_empty() {
        event
            .fields
            .insert(format!("join_requests_{suffix}"), mappings.join(","));
    }
}

fn optional_non_empty_attr(node: &BinaryNode, key: &str) -> Option<String> {
    node.attrs
        .get(key)
        .filter(|value| !value.is_empty())
        .cloned()
}

fn copy_optional_attrs(node: &BinaryNode, event: &mut GroupUpdateEvent, attrs: &[(&str, &str)]) {
    for (source, target) in attrs {
        if let Some(value) = node.attrs.get(*source)
            && !value.is_empty()
        {
            event.fields.insert((*target).to_owned(), value.clone());
        }
    }
}

fn copy_optional_jid_attr(
    node: &BinaryNode,
    event: &mut GroupUpdateEvent,
    label: &str,
    source: &str,
    target: &str,
) -> CoreResult<()> {
    if let Some(jid) = optional_jid_field(label, node.attrs.get(source).map(String::as_str))? {
        event.fields.insert(target.to_owned(), jid);
    }
    Ok(())
}

fn copy_first_optional_jid_attr(
    node: &BinaryNode,
    event: &mut GroupUpdateEvent,
    label: &str,
    sources: &[&str],
    target: &str,
) -> CoreResult<()> {
    if event.fields.contains_key(target) {
        return Ok(());
    }
    if let Some(jid) = optional_jid_field(label, first_non_empty_attr(node, sources))? {
        event.fields.insert(target.to_owned(), jid);
    }
    Ok(())
}

fn copy_first_optional_attr(
    node: &BinaryNode,
    event: &mut GroupUpdateEvent,
    sources: &[&str],
    target: &str,
) {
    if event.fields.contains_key(target) {
        return;
    }
    if let Some(value) = first_non_empty_attr(node, sources) {
        event.fields.insert(target.to_owned(), value.to_owned());
    }
}

fn copy_optional_u64_attr(
    node: &BinaryNode,
    event: &mut GroupUpdateEvent,
    source: &str,
    target: &str,
    label: &str,
) -> CoreResult<()> {
    if let Some(value) = optional_u64_attr(node, source, label)? {
        event.fields.insert(target.to_owned(), value.to_string());
    }
    Ok(())
}

fn attr_or_text(node: &BinaryNode, attrs: &[&str]) -> Option<String> {
    attrs
        .iter()
        .find_map(|attr| {
            node.attrs
                .get(*attr)
                .filter(|value| !value.is_empty())
                .cloned()
        })
        .or_else(|| node_text(node).filter(|value| !value.is_empty()))
}

pub fn message_event_key_from_proto_key(key: &MessageKey) -> CoreResult<MessageEventKey> {
    let remote_jid = required_jid("message remote JID", key.remote_jid.as_deref())?;
    let id = required_text("message id", key.id.as_deref())?;
    let participant = match key.participant.as_deref() {
        Some(participant) if !participant.is_empty() => {
            validate_jid("message participant JID", participant)?;
            Some(participant.to_owned())
        }
        _ => None,
    };

    Ok(MessageEventKey::new(remote_jid, id, participant))
}

pub fn message_event_from_decoded(decoded: &DecodedInboundMessage) -> CoreResult<MessageEvent> {
    let key = message_event_key_from_proto_key(&decoded.info.key)?;
    let payload = decoded.last_message().ok_or_else(|| {
        CoreError::Protocol("decoded inbound message has no message payload".to_owned())
    })?;
    let mut event = MessageEvent::new(key)
        .with_payload(encode_message(payload)?)
        .with_field("kind", decoded.info.kind.as_str())
        .with_field("author", decoded.info.author.clone())
        .with_field("sender", decoded.info.sender.clone())
        .with_field(
            "from_me",
            decoded.info.key.from_me.unwrap_or(false).to_string(),
        )
        .with_field("payload_count", decoded.payloads.len().to_string())
        .with_field(
            "encrypted_payload_count",
            decoded
                .payloads
                .iter()
                .filter(|payload| !matches!(payload.kind, crate::InboundPayloadKind::Plaintext))
                .count()
                .to_string(),
        )
        .with_field(
            "device_sent_unwrapped",
            decoded
                .payloads
                .iter()
                .any(|payload| payload.device_sent_unwrapped)
                .to_string(),
        )
        .with_field(
            "sender_key_distribution_count",
            decoded
                .payloads
                .iter()
                .map(|payload| payload.sender_key_distribution_count)
                .sum::<usize>()
                .to_string(),
        );

    if let Some(timestamp) = decoded.info.timestamp {
        event = event.with_timestamp(timestamp);
    }
    if let Some(category) = &decoded.info.category {
        event = event.with_field("category", category.clone());
    }
    if let Some(push_name) = &decoded.info.push_name {
        event = event.with_field("push_name", push_name.clone());
    }
    if let Some(sender_alt) = &decoded.info.addressing.sender_alt {
        event = event.with_field("sender_alt", sender_alt.clone());
    }
    if let Some(recipient_alt) = &decoded.info.addressing.recipient_alt {
        event = event.with_field("recipient_alt", recipient_alt.clone());
    }
    event = event.with_field(
        "addressing_mode",
        decoded.info.addressing.mode.as_wire_str(),
    );

    if let Some(last_payload) = decoded.payloads.last() {
        event = event.with_field("payload_kind", last_payload.kind.as_str());
    }

    Ok(event)
}

pub fn placeholder_unavailable_message_from_node(
    node: &BinaryNode,
    own_jid: &str,
    own_lid: Option<&str>,
    now_secs: u64,
) -> CoreResult<Option<PlaceholderUnavailableMessage>> {
    if !is_unavailable_absent_message_node(node) {
        return Ok(None);
    }

    let info = decode_inbound_message_info(node, own_jid, own_lid)?;
    let unavailable_type = child_node(node, "unavailable")
        .and_then(|node| node.attrs.get("type"))
        .filter(|value| !value.is_empty())
        .cloned();
    let placeholder_message = Message {
        placeholder_message: Some(PlaceholderMessage {
            r#type: Some(PlaceholderType::MaskLinkedDevices as i32),
        }),
        ..Message::default()
    };
    let web_message = WebMessageInfo {
        key: Some(info.key.clone()),
        message: Some(placeholder_message),
        message_timestamp: info.timestamp,
        participant: info.key.participant.clone(),
        push_name: info.push_name.clone(),
        message_stub_type: Some(StubType::Ciphertext as i32),
        message_stub_parameters: vec![PLACEHOLDER_NO_MESSAGE_FOUND_ERROR_TEXT.to_owned()],
        ..WebMessageInfo::default()
    };
    let Some(request) = placeholder_resend_request_from_web_message(
        &web_message,
        info.category.as_deref(),
        unavailable_type.as_deref(),
        now_secs,
    )?
    else {
        return Ok(None);
    };
    Ok(Some(PlaceholderUnavailableMessage {
        web_message,
        request,
        category: info.category,
        unavailable_type,
    }))
}

pub fn message_event_from_placeholder_unavailable(
    placeholder: &PlaceholderUnavailableMessage,
) -> CoreResult<MessageEvent> {
    let key = placeholder
        .web_message
        .key
        .as_ref()
        .ok_or_else(|| CoreError::Protocol("placeholder unavailable missing key".to_owned()))
        .and_then(message_event_key_from_proto_key)?;
    let mut event = MessageEvent::new(key)
        .with_field("kind", "placeholder_unavailable")
        .with_field("source", "unavailable_message")
        .with_field("stub_reason", PLACEHOLDER_NO_MESSAGE_FOUND_ERROR_TEXT);

    if let Some(payload) = placeholder.web_message.message.as_ref() {
        event = event.with_payload(encode_message(payload)?);
    }
    if let Some(timestamp) = placeholder.web_message.message_timestamp {
        event = event.with_timestamp(timestamp);
    }
    if let Some(stub_type) = placeholder.web_message.message_stub_type {
        event = event.with_field("message_stub_type", stub_type.to_string());
    }
    if let Some(category) = &placeholder.category {
        event = event.with_field("category", category.clone());
    }
    if let Some(unavailable_type) = &placeholder.unavailable_type {
        event = event.with_field("unavailable_type", unavailable_type.clone());
    }
    if let Some(participant) = &placeholder.web_message.participant {
        event = event.with_field("participant", participant.clone());
    }
    if let Some(push_name) = &placeholder.web_message.push_name {
        event = event.with_field("push_name", push_name.clone());
    }

    Ok(event)
}

fn is_unavailable_absent_message_node(node: &BinaryNode) -> bool {
    node.tag == "message"
        && has_child_node(node, "unavailable")
        && !has_child_node(node, "plaintext")
        && !has_child_node(node, "enc")
}

pub fn placeholder_resend_events_from_message(message: &Message) -> CoreResult<Vec<MessageEvent>> {
    let Some(protocol) = message.protocol_message.as_ref() else {
        return Ok(Vec::new());
    };
    if protocol.r#type
        != Some(
            wa_proto::proto::message::protocol_message::Type::PeerDataOperationRequestResponseMessage
                as i32,
        )
    {
        return Ok(Vec::new());
    }
    let Some(response) = protocol
        .peer_data_operation_request_response_message
        .as_ref()
    else {
        return Ok(Vec::new());
    };

    let mut events = Vec::new();
    for result in &response.peer_data_operation_result {
        let Some(bytes) = result
            .placeholder_message_resend_response
            .as_ref()
            .and_then(|response| response.web_message_info_bytes.as_ref())
        else {
            continue;
        };
        let web_message = WebMessageInfo::decode(bytes.clone())?;
        events.push(message_event_from_placeholder_response(
            &web_message,
            response.stanza_id.as_deref(),
        )?);
    }
    Ok(events)
}

fn message_event_from_placeholder_response(
    message: &WebMessageInfo,
    request_id: Option<&str>,
) -> CoreResult<MessageEvent> {
    let key = message
        .key
        .as_ref()
        .ok_or_else(|| CoreError::Protocol("placeholder response missing message key".to_owned()))
        .and_then(message_event_key_from_proto_key)?;
    let mut event = MessageEvent::new(key)
        .with_field("kind", "placeholder_resend")
        .with_field("source", "peer_data_operation_response");

    if let Some(payload) = message.message.as_ref() {
        event = event.with_payload(encode_message(payload)?);
    }
    if let Some(timestamp) = message.message_timestamp {
        event = event.with_timestamp(timestamp);
    }
    if let Some(request_id) = request_id.filter(|value| !value.is_empty()) {
        event = event.with_field("request_id", request_id.to_owned());
    }
    if let Some(key) = message.key.as_ref()
        && let Some(from_me) = key.from_me
    {
        event = event.with_field("from_me", from_me.to_string());
    }
    if let Some(push_name) = &message.push_name {
        event = event.with_field("push_name", push_name.clone());
    }
    if let Some(participant) = &message.participant {
        event = event.with_field("participant", participant.clone());
    }
    if let Some(verified_biz_name) = &message.verified_biz_name {
        event = event.with_field("verified_biz_name", verified_biz_name.clone());
    }
    if let Some(status) = message.status {
        event = event.with_field("status", status.to_string());
    }
    if let Some(stub_type) = message.message_stub_type {
        event = event.with_field("message_stub_type", stub_type.to_string());
    }
    Ok(event)
}

pub fn event_batch_from_decoded_message(decoded: &DecodedInboundMessage) -> CoreResult<EventBatch> {
    let message = decoded.last_message().ok_or_else(|| {
        CoreError::Protocol("decoded inbound message has no message payload".to_owned())
    })?;
    let mut messages_upsert = vec![message_event_from_decoded(decoded)?];
    messages_upsert.extend(placeholder_resend_events_from_message(message)?);
    let reactions_update = reaction_events_from_decoded_message(decoded, message)?;
    let messages_update = message_updates_from_decoded_message(decoded, message)?;
    let messages_delete = message_deletes_from_decoded_message(message)?;
    Ok(EventBatch {
        messages_upsert,
        messages_update,
        messages_delete,
        reactions_update,
        ..EventBatch::default()
    })
}

#[cfg(feature = "noise")]
pub fn event_batch_from_decoded_message_with_poll_event_secrets(
    decoded: &DecodedInboundMessage,
    secrets: &PollEventMessageSecrets,
) -> CoreResult<EventBatch> {
    let message = decoded.last_message().ok_or_else(|| {
        CoreError::Protocol("decoded inbound message has no message payload".to_owned())
    })?;
    let mut messages_upsert = vec![message_event_from_decoded(decoded)?];
    messages_upsert.extend(placeholder_resend_events_from_message(message)?);
    let reactions_update = reaction_events_from_decoded_message(decoded, message)?;
    let messages_update =
        message_updates_from_decoded_message_with_poll_event_secrets(decoded, message, secrets)?;
    let messages_delete = message_deletes_from_decoded_message(message)?;
    Ok(EventBatch {
        messages_upsert,
        messages_update,
        messages_delete,
        reactions_update,
        ..EventBatch::default()
    })
}

pub fn reaction_events_from_decoded_message(
    decoded: &DecodedInboundMessage,
    message: &Message,
) -> CoreResult<Vec<ReactionEvent>> {
    let message_content = unwrapped_message_content(message);
    let Some(reaction) = message_content.reaction_message.as_ref() else {
        return Ok(Vec::new());
    };
    let key = reaction
        .key
        .as_ref()
        .ok_or_else(|| CoreError::Protocol("reaction message missing target key".to_owned()))
        .and_then(message_event_key_from_proto_key)?;
    validate_jid("reaction author JID", &decoded.info.author)?;
    let mut event = ReactionEvent::new(key, decoded.info.author.clone());
    if let Some(text) = &reaction.text {
        event = event.with_text(text.clone());
    }
    if let Some(timestamp_ms) = reaction.sender_timestamp_ms {
        let timestamp_ms = u64::try_from(timestamp_ms).map_err(|_| {
            CoreError::Protocol("reaction sender timestamp must be non-negative".to_owned())
        })?;
        event = event.with_timestamp(timestamp_ms);
    }
    Ok(vec![event])
}

pub fn message_updates_from_decoded_message(
    decoded: &DecodedInboundMessage,
    message: &Message,
) -> CoreResult<Vec<MessageUpdate>> {
    let mut updates = Vec::new();
    let message_content = unwrapped_message_content(message);
    if let Some(protocol) = message_content.protocol_message.as_ref()
        && protocol.r#type == Some(protocol_message::Type::MessageEdit as i32)
    {
        let key = protocol
            .key
            .as_ref()
            .ok_or_else(|| CoreError::Protocol("message edit missing target key".to_owned()))
            .and_then(message_event_key_from_proto_key)?;
        let mut update = MessageUpdate::new(key)
            .with_field("source", "protocol_message")
            .with_field("protocol_type", "message_edit");
        if let Some(timestamp_ms) = protocol.timestamp_ms {
            update = update.with_timestamp(non_negative_i64_to_u64(
                timestamp_ms,
                "message edit timestamp",
            )?);
        }
        if let Some(edited) = protocol.edited_message.as_deref() {
            update = update
                .with_field("edited_message", "true")
                .with_field("edited_stanza_type", message_stanza_type(edited));
        } else {
            update = update.with_field("edited_message", "false");
        }
        updates.push(update);
    }

    if let Some(poll) = message_content.poll_update_message.as_ref() {
        let key = poll
            .poll_creation_message_key
            .as_ref()
            .ok_or_else(|| CoreError::Protocol("poll update missing target key".to_owned()))
            .and_then(message_event_key_from_proto_key)?;
        validate_jid("poll update voter JID", &decoded.info.author)?;
        let mut update = MessageUpdate::new(key)
            .with_field("source", "poll_update_message")
            .with_field("poll_update", "true")
            .with_field("voter_jid", decoded.info.author.clone())
            .with_field(
                "update_message_remote_jid",
                decoded.info.key.remote_jid.clone().unwrap_or_default(),
            )
            .with_field(
                "update_message_id",
                decoded.info.key.id.clone().unwrap_or_default(),
            )
            .with_field("vote_encrypted", poll.vote.is_some().to_string())
            .with_field("metadata_present", poll.metadata.is_some().to_string());
        if let Some(participant) = decoded.info.key.participant.as_ref() {
            update = update.with_field("update_message_participant", participant.clone());
        }
        if let Some(timestamp_ms) = poll.sender_timestamp_ms {
            update = update.with_timestamp(non_negative_i64_to_u64(
                timestamp_ms,
                "poll update sender timestamp",
            )?);
        }
        if let Some(vote) = poll.vote.as_ref() {
            if let Some(payload) = vote.enc_payload.as_ref() {
                update =
                    update.with_field("encrypted_vote_payload_bytes", payload.len().to_string());
            }
            if let Some(iv) = vote.enc_iv.as_ref() {
                update = update.with_field("encrypted_vote_iv_bytes", iv.len().to_string());
            }
        }
        updates.push(update);
    }

    if let Some(event_response) = message_content.enc_event_response_message.as_ref() {
        let key = event_response
            .event_creation_message_key
            .as_ref()
            .ok_or_else(|| CoreError::Protocol("event response missing target key".to_owned()))
            .and_then(message_event_key_from_proto_key)?;
        validate_jid("event response responder JID", &decoded.info.author)?;
        let mut update = MessageUpdate::new(key)
            .with_field("source", "enc_event_response_message")
            .with_field("event_response", "true")
            .with_field("responder_jid", decoded.info.author.clone())
            .with_field(
                "update_message_remote_jid",
                decoded.info.key.remote_jid.clone().unwrap_or_default(),
            )
            .with_field(
                "update_message_id",
                decoded.info.key.id.clone().unwrap_or_default(),
            )
            .with_field(
                "response_encrypted",
                event_response.enc_payload.is_some().to_string(),
            );
        if let Some(participant) = decoded.info.key.participant.as_ref() {
            update = update.with_field("update_message_participant", participant.clone());
        }
        if let Some(payload) = event_response.enc_payload.as_ref() {
            update = update.with_field(
                "encrypted_event_response_payload_bytes",
                payload.len().to_string(),
            );
        }
        if let Some(iv) = event_response.enc_iv.as_ref() {
            update = update.with_field("encrypted_event_response_iv_bytes", iv.len().to_string());
        }
        updates.push(update);
    }

    if let Some(pin) = message_content.pin_in_chat_message.as_ref() {
        let key = pin
            .key
            .as_ref()
            .ok_or_else(|| CoreError::Protocol("pin message missing target key".to_owned()))
            .and_then(message_event_key_from_proto_key)?;
        let mut update = MessageUpdate::new(key)
            .with_field("source", "pin_in_chat_message")
            .with_field(
                "pin_action",
                match pin_in_chat_message::Type::try_from(pin.r#type.unwrap_or_default()).ok() {
                    Some(pin_in_chat_message::Type::PinForAll) => "pin",
                    Some(pin_in_chat_message::Type::UnpinForAll) => "unpin",
                    _ => "unknown",
                },
            );
        if let Some(timestamp_ms) = pin.sender_timestamp_ms {
            update = update.with_timestamp(non_negative_i64_to_u64(
                timestamp_ms,
                "pin sender timestamp",
            )?);
        }
        updates.push(update);
    }
    Ok(updates)
}

#[cfg(feature = "noise")]
pub fn message_updates_from_decoded_message_with_poll_event_secrets(
    decoded: &DecodedInboundMessage,
    message: &Message,
    secrets: &PollEventMessageSecrets,
) -> CoreResult<Vec<MessageUpdate>> {
    let mut updates = message_updates_from_decoded_message(decoded, message)?;
    annotate_poll_event_updates_with_secrets(&mut updates, decoded, message, secrets)?;
    Ok(updates)
}

#[cfg(feature = "noise")]
fn annotate_poll_event_updates_with_secrets(
    updates: &mut [MessageUpdate],
    decoded: &DecodedInboundMessage,
    message: &Message,
    secrets: &PollEventMessageSecrets,
) -> CoreResult<()> {
    let message_content = unwrapped_message_content(message);
    if let Some(poll) = message_content.poll_update_message.as_ref() {
        let key = poll
            .poll_creation_message_key
            .as_ref()
            .ok_or_else(|| CoreError::Protocol("poll update missing target key".to_owned()))
            .and_then(message_event_key_from_proto_key)?;
        if let Some(secret) = secrets.get(&key)
            && let Some(update) = update_for_key_and_source(updates, &key, "poll_update_message")
            && let Some(vote) = poll.vote.as_ref()
        {
            update.fields.insert(
                "poll_secret_creator_jid".to_owned(),
                secret.creator_jid.clone(),
            );
            let message_id = poll
                .poll_creation_message_key
                .as_ref()
                .and_then(|key| key.id.as_deref())
                .unwrap_or_default();
            match crate::decrypt_poll_vote_message(
                vote,
                message_id,
                &secret.creator_jid,
                &decoded.info.author,
                &secret.message_secret,
            ) {
                Ok(vote) => annotate_decrypted_poll_vote(update, &vote),
                Err(error) => {
                    update
                        .fields
                        .insert("vote_decrypted".to_owned(), "false".to_owned());
                    update
                        .fields
                        .insert("vote_decrypt_error".to_owned(), error.to_string());
                }
            }
        }
    }

    if let Some(event_response) = message_content.enc_event_response_message.as_ref() {
        let key = event_response
            .event_creation_message_key
            .as_ref()
            .ok_or_else(|| CoreError::Protocol("event response missing target key".to_owned()))
            .and_then(message_event_key_from_proto_key)?;
        if let Some(secret) = secrets.get(&key)
            && let Some(update) =
                update_for_key_and_source(updates, &key, "enc_event_response_message")
        {
            update.fields.insert(
                "event_secret_creator_jid".to_owned(),
                secret.creator_jid.clone(),
            );
            let message_id = event_response
                .event_creation_message_key
                .as_ref()
                .and_then(|key| key.id.as_deref())
                .unwrap_or_default();
            match crate::decrypt_event_response_message(
                event_response,
                message_id,
                &secret.creator_jid,
                &decoded.info.author,
                &secret.message_secret,
            ) {
                Ok(response) => annotate_decrypted_event_response(update, &response),
                Err(error) => {
                    update
                        .fields
                        .insert("response_decrypted".to_owned(), "false".to_owned());
                    update
                        .fields
                        .insert("response_decrypt_error".to_owned(), error.to_string());
                }
            }
        }
    }

    Ok(())
}

#[cfg(feature = "noise")]
fn annotate_decrypted_poll_vote(
    update: &mut MessageUpdate,
    vote: &wa_proto::proto::message::PollVoteMessage,
) {
    update
        .fields
        .insert("vote_decrypted".to_owned(), "true".to_owned());
    update.fields.insert(
        "selected_options_count".to_owned(),
        vote.selected_options.len().to_string(),
    );
    let hashes = vote
        .selected_options
        .iter()
        .take(MAX_DECRYPTED_POLL_OPTION_HASH_FIELDS)
        .map(|hash| lower_hex(hash))
        .collect::<Vec<_>>();
    if !hashes.is_empty() {
        update
            .fields
            .insert("selected_option_hashes_hex".to_owned(), hashes.join(","));
    }
    if vote.selected_options.len() > MAX_DECRYPTED_POLL_OPTION_HASH_FIELDS {
        update.fields.insert(
            "selected_option_hashes_truncated".to_owned(),
            "true".to_owned(),
        );
    }
}

#[cfg(feature = "noise")]
fn annotate_decrypted_event_response(
    update: &mut MessageUpdate,
    response: &wa_proto::proto::message::EventResponseMessage,
) {
    update
        .fields
        .insert("response_decrypted".to_owned(), "true".to_owned());
    update.fields.insert(
        "response".to_owned(),
        event_response_type_name(response.response).to_owned(),
    );
    if let Some(extra_guest_count) = response.extra_guest_count {
        update.fields.insert(
            "extra_guest_count".to_owned(),
            extra_guest_count.to_string(),
        );
    }
    if let Some(timestamp_ms) = response.timestamp_ms {
        match non_negative_i64_to_u64(timestamp_ms, "event response timestamp") {
            Ok(timestamp_ms) => {
                update
                    .fields
                    .insert("response_timestamp_ms".to_owned(), timestamp_ms.to_string());
            }
            Err(error) => {
                update
                    .fields
                    .insert("response_timestamp_error".to_owned(), error.to_string());
            }
        }
    }
}

#[cfg(feature = "noise")]
fn update_for_key_and_source<'a>(
    updates: &'a mut [MessageUpdate],
    key: &MessageEventKey,
    source: &str,
) -> Option<&'a mut MessageUpdate> {
    updates.iter_mut().find(|update| {
        update.key == *key
            && update
                .fields
                .get("source")
                .is_some_and(|value| value == source)
    })
}

pub fn message_deletes_from_decoded_message(message: &Message) -> CoreResult<Vec<MessageEventKey>> {
    let message_content = unwrapped_message_content(message);
    let Some(protocol) = message_content.protocol_message.as_ref() else {
        return Ok(Vec::new());
    };
    if protocol.r#type != Some(protocol_message::Type::Revoke as i32) {
        return Ok(Vec::new());
    }
    let key = protocol
        .key
        .as_ref()
        .ok_or_else(|| CoreError::Protocol("message revoke missing target key".to_owned()))
        .and_then(message_event_key_from_proto_key)?;
    Ok(vec![key])
}

pub fn push_decoded_message_to_buffer(
    buffer: &mut EventBuffer,
    decoded: &DecodedInboundMessage,
) -> CoreResult<usize> {
    let batch = event_batch_from_decoded_message(decoded)?;
    let count = batch.pending_items();
    if !batch.is_empty() {
        buffer.push(Event::Batch(Box::new(batch)))?;
    }
    Ok(count)
}

pub fn receipt_events_from_inbound(receipt: &InboundReceipt) -> CoreResult<Vec<ReceiptEvent>> {
    let remote_jid = receipt
        .recipient
        .as_deref()
        .unwrap_or(receipt.from.as_str());
    validate_jid("receipt remote JID", remote_jid)?;
    if let Some(participant) = receipt.participant.as_deref() {
        validate_jid("receipt participant JID", participant)?;
    }

    receipt
        .message_ids
        .iter()
        .map(|id| {
            let id = required_text("receipt message id", Some(id.as_str()))?;
            let key = MessageEventKey::new(remote_jid, id, receipt.participant.clone());
            let mut event = ReceiptEvent::new(key, receipt.kind.as_event_type());
            if let Some(participant) = receipt.participant.clone() {
                event = event.with_participant(participant);
            }
            if let Some(timestamp) = receipt.timestamp {
                event = event.with_timestamp(timestamp);
            }
            Ok(event)
        })
        .collect()
}

pub fn event_batch_from_inbound_receipt(receipt: &InboundReceipt) -> CoreResult<EventBatch> {
    Ok(EventBatch {
        receipts_update: receipt_events_from_inbound(receipt)?,
        ..EventBatch::default()
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ReceiptMessageRef {
    id: String,
    remote_jid: String,
    participant: Option<String>,
    timestamp: Option<u64>,
}

pub fn receipt_events_from_inbound_node(
    node: &BinaryNode,
    receipt: &InboundReceipt,
) -> CoreResult<Vec<ReceiptEvent>> {
    receipt_message_refs_from_node(node, receipt)?
        .into_iter()
        .map(|message| {
            let id = required_text("receipt message id", Some(message.id.as_str()))?;
            validate_jid("receipt remote JID", &message.remote_jid)?;
            if let Some(participant) = message.participant.as_deref() {
                validate_jid("receipt participant JID", participant)?;
            }
            let mut event = ReceiptEvent::new(
                MessageEventKey::new(message.remote_jid, id, message.participant.clone()),
                receipt.kind.as_event_type(),
            );
            if let Some(participant) = message.participant {
                event = event.with_participant(participant);
            }
            if let Some(timestamp) = message.timestamp {
                event = event.with_timestamp(timestamp);
            }
            Ok(event)
        })
        .collect()
}

fn receipt_message_refs_from_node(
    node: &BinaryNode,
    receipt: &InboundReceipt,
) -> CoreResult<Vec<ReceiptMessageRef>> {
    let default_remote_jid = receipt
        .recipient
        .as_deref()
        .unwrap_or(receipt.from.as_str())
        .to_owned();
    validate_jid("receipt remote JID", &default_remote_jid)?;
    if let Some(participant) = receipt.participant.as_deref() {
        validate_jid("receipt participant JID", participant)?;
    }

    let mut messages = vec![ReceiptMessageRef {
        id: receipt.id.clone(),
        remote_jid: default_remote_jid.clone(),
        participant: receipt.participant.clone(),
        timestamp: receipt.timestamp,
    }];

    for list in child_nodes(node).iter().filter(|child| child.tag == "list") {
        for item in child_nodes(list).iter().filter(|child| child.tag == "item") {
            let id = required_text(
                "receipt list item id",
                item.attrs.get("id").map(String::as_str),
            )?;
            let remote_jid = optional_jid_field(
                "receipt list item recipient JID",
                item.attrs.get("recipient").map(String::as_str),
            )?
            .unwrap_or_else(|| default_remote_jid.clone());
            let participant = optional_jid_field(
                "receipt list item participant JID",
                item.attrs.get("participant").map(String::as_str),
            )?
            .or_else(|| receipt.participant.clone());
            let timestamp =
                optional_u64_attr(item, "t", "receipt list item timestamp")?.or(receipt.timestamp);
            messages.push(ReceiptMessageRef {
                id,
                remote_jid,
                participant,
                timestamp,
            });
        }
    }

    Ok(messages)
}

pub fn media_retry_event_from_update(update: &MediaRetryUpdate) -> CoreResult<MediaRetryEvent> {
    let key = message_event_key_from_proto_key(&update.key)?;
    let mut event = MediaRetryEvent::new(key, update.key.from_me.unwrap_or(false));

    match (&update.media, &update.error) {
        (Some(payload), None) => {
            event = event.with_encrypted_payload(payload.ciphertext.clone(), payload.iv.clone());
        }
        (None, Some(error)) => {
            event = event.with_error(error.code, error.text.clone(), error.status_code);
        }
        (None, None) => {
            return Err(CoreError::Protocol(
                "media retry update missing payload or error".to_owned(),
            ));
        }
        (Some(_), Some(_)) => {
            return Err(CoreError::Protocol(
                "media retry update contains both payload and error".to_owned(),
            ));
        }
    }

    Ok(event)
}

pub fn event_batch_from_media_retry_update(update: &MediaRetryUpdate) -> CoreResult<EventBatch> {
    Ok(EventBatch {
        media_retry: vec![media_retry_event_from_update(update)?],
        ..EventBatch::default()
    })
}

pub fn event_batch_from_media_retry_notification_node(
    node: &BinaryNode,
    notification: &InboundNotification,
) -> CoreResult<Option<EventBatch>> {
    if notification.notification_type.as_deref() != Some("mediaretry") {
        return Ok(None);
    }
    parse_media_retry_update(node)
        .and_then(|update| event_batch_from_media_retry_update(&update))
        .map(Some)
}

pub fn event_batch_from_inbound_receipt_node(
    node: &BinaryNode,
    receipt: &InboundReceipt,
) -> CoreResult<EventBatch> {
    let mut batch = EventBatch {
        receipts_update: receipt_events_from_inbound_node(node, receipt)?,
        ..EventBatch::default()
    };
    if has_child_node(node, "rmr") {
        let update = parse_media_retry_update(node)?;
        batch
            .media_retry
            .push(media_retry_event_from_update(&update)?);
    }
    Ok(batch)
}

pub fn message_updates_from_ack(ack: &InboundAck) -> CoreResult<Vec<MessageUpdate>> {
    if ack.class != "message" {
        return Ok(Vec::new());
    }

    let remote_jid = ack
        .from
        .as_deref()
        .or(ack.recipient.as_deref())
        .or(ack.to.as_deref())
        .ok_or_else(|| CoreError::Protocol("message ACK missing remote JID".to_owned()))?;
    validate_jid("message ACK remote JID", remote_jid)?;
    if let Some(participant) = ack.participant.as_deref() {
        validate_jid("message ACK participant JID", participant)?;
    }

    let mut fields = BTreeMap::new();
    fields.insert("ack_class".to_owned(), ack.class.clone());
    fields.insert("from_me".to_owned(), "true".to_owned());
    if let Some(ack_type) = &ack.ack_type {
        fields.insert("ack_type".to_owned(), ack_type.clone());
    }
    if let Some(participant_hash) = &ack.participant_hash {
        fields.insert("participant_hash".to_owned(), participant_hash.clone());
    }
    if let Some(recipient) = &ack.recipient {
        fields.insert("recipient".to_owned(), recipient.clone());
    }
    if let Some(error_code) = ack.error_code {
        fields.insert("status".to_owned(), "error".to_owned());
        fields.insert("ack_error_code".to_owned(), error_code.to_string());
    } else {
        fields.insert("status".to_owned(), "server_ack".to_owned());
    }

    let mut update = MessageUpdate::new(MessageEventKey::new(
        remote_jid,
        ack.id.clone(),
        ack.participant.clone(),
    ));
    for (key, value) in fields {
        update = update.with_field(key, value);
    }
    Ok(vec![update])
}

pub fn event_batch_from_inbound_ack(ack: &InboundAck) -> CoreResult<EventBatch> {
    Ok(EventBatch {
        messages_update: message_updates_from_ack(ack)?,
        ..EventBatch::default()
    })
}

pub fn message_info_fields(info: &InboundMessageInfo) -> BTreeMap<String, String> {
    let mut fields = BTreeMap::new();
    fields.insert("kind".to_owned(), info.kind.as_str().to_owned());
    fields.insert("author".to_owned(), info.author.clone());
    fields.insert("sender".to_owned(), info.sender.clone());
    fields.insert(
        "from_me".to_owned(),
        info.key.from_me.unwrap_or(false).to_string(),
    );
    fields.insert(
        "addressing_mode".to_owned(),
        info.addressing.mode.as_wire_str().to_owned(),
    );
    if let Some(category) = &info.category {
        fields.insert("category".to_owned(), category.clone());
    }
    if let Some(push_name) = &info.push_name {
        fields.insert("push_name".to_owned(), push_name.clone());
    }
    if let Some(sender_alt) = &info.addressing.sender_alt {
        fields.insert("sender_alt".to_owned(), sender_alt.clone());
    }
    if let Some(recipient_alt) = &info.addressing.recipient_alt {
        fields.insert("recipient_alt".to_owned(), recipient_alt.clone());
    }
    fields
}

fn required_jid(label: &str, value: Option<&str>) -> CoreResult<String> {
    let value = required_text(label, value)?;
    validate_jid(label, &value)?;
    Ok(value)
}

fn required_text(label: &str, value: Option<&str>) -> CoreResult<String> {
    let value = value.ok_or_else(|| CoreError::Protocol(format!("{label} is missing")))?;
    if value.is_empty() {
        return Err(CoreError::Protocol(format!("{label} must not be empty")));
    }
    Ok(value.to_owned())
}

fn optional_jid_field(label: &str, value: Option<&str>) -> CoreResult<Option<String>> {
    let Some(value) = value.filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    validate_jid(label, value)?;
    Ok(Some(value.to_owned()))
}

fn first_non_empty_attr<'a>(node: &'a BinaryNode, keys: &[&str]) -> Option<&'a str> {
    keys.iter().find_map(|key| {
        node.attrs
            .get(*key)
            .map(String::as_str)
            .filter(|value| !value.is_empty())
    })
}

fn validate_jid(label: &str, value: &str) -> CoreResult<()> {
    let Some(jid) = jid_decode(value) else {
        return Err(CoreError::Protocol(format!("invalid {label}: {value}")));
    };
    if jid.user.is_empty() || jid.server_raw.is_empty() {
        return Err(CoreError::Protocol(format!("invalid {label}: {value}")));
    }
    Ok(())
}

fn same_jid_user(left: &str, right: &str) -> bool {
    jid_decode(left)
        .zip(jid_decode(right))
        .is_some_and(|(left, right)| left.user == right.user)
}

fn current_unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

fn has_child_node(node: &BinaryNode, tag: &str) -> bool {
    matches!(
        &node.content,
        Some(BinaryNodeContent::Nodes(children)) if children.iter().any(|child| child.tag == tag)
    )
}

fn child_nodes(node: &BinaryNode) -> &[BinaryNode] {
    match &node.content {
        Some(BinaryNodeContent::Nodes(children)) => children,
        _ => &[],
    }
}

fn child_node<'a>(node: &'a BinaryNode, tag: &str) -> Option<&'a BinaryNode> {
    child_nodes(node).iter().find(|child| child.tag == tag)
}

fn node_bytes<'a>(node: &'a BinaryNode, label: &str) -> CoreResult<&'a [u8]> {
    match node.content.as_ref() {
        Some(BinaryNodeContent::Bytes(bytes)) => Ok(bytes.as_ref()),
        Some(BinaryNodeContent::Text(text)) => Ok(text.as_bytes()),
        Some(BinaryNodeContent::Nodes(_)) => Err(CoreError::Protocol(format!(
            "{label} content must be bytes or text"
        ))),
        None => Err(CoreError::Protocol(format!("{label} content is missing"))),
    }
}

fn node_text(node: &BinaryNode) -> Option<String> {
    match node.content.as_ref()? {
        BinaryNodeContent::Text(value) => Some(value.clone()),
        BinaryNodeContent::Bytes(value) => String::from_utf8(value.to_vec()).ok(),
        BinaryNodeContent::Nodes(_) => None,
    }
}

fn optional_u64_attr(node: &BinaryNode, key: &str, label: &str) -> CoreResult<Option<u64>> {
    let Some(value) = node.attrs.get(key).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    value
        .parse::<u64>()
        .map(Some)
        .map_err(|err| CoreError::Protocol(format!("invalid {label}: {err}")))
}

fn parse_non_negative_u64(value: &str) -> Option<u64> {
    value.parse::<u64>().ok()
}

fn non_negative_i64_to_u64(value: i64, label: &str) -> CoreResult<u64> {
    u64::try_from(value).map_err(|_| CoreError::Protocol(format!("{label} must be non-negative")))
}

#[cfg(feature = "noise")]
fn event_response_type_name(response: Option<i32>) -> &'static str {
    match event_response_message::EventResponseType::try_from(response.unwrap_or_default()).ok() {
        Some(event_response_message::EventResponseType::Going) => "going",
        Some(event_response_message::EventResponseType::NotGoing) => "not_going",
        Some(event_response_message::EventResponseType::Maybe) => "maybe",
        Some(event_response_message::EventResponseType::Unknown) | None => "unknown",
    }
}

#[cfg(feature = "noise")]
fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(feature = "noise")]
fn message_has_poll_or_event_creation(message: &Message) -> bool {
    let mut current = message;
    for _ in 0..=5 {
        if message_has_direct_poll_or_event_creation(current) {
            return true;
        }
        let Some(inner) = future_proof_inner_message(current) else {
            return false;
        };
        current = inner;
    }
    false
}

#[cfg(feature = "noise")]
fn message_has_direct_poll_or_event_creation(message: &Message) -> bool {
    message.poll_creation_message.is_some()
        || message.poll_creation_message_v2.is_some()
        || message.poll_creation_message_v3.is_some()
        || message.poll_creation_message_v4.is_some()
        || message.poll_creation_message_v5.is_some()
        || message.event_message.is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AddressingContext, AddressingMode, DecodedInboundPayload, InboundMessageInfo,
        InboundMessageKind, InboundPayloadKind, InboundReceiptKind, MediaRetryError,
        MediaRetryPayload,
    };
    use async_trait::async_trait;
    use bytes::Bytes;
    use prost::Message as ProstMessage;
    use wa_proto::proto::Message;

    #[test]
    fn maps_decoded_message_to_upsert_event() {
        let decoded = DecodedInboundMessage {
            info: InboundMessageInfo {
                key: MessageKey {
                    remote_jid: Some("123@s.whatsapp.net".to_owned()),
                    from_me: Some(false),
                    id: Some("msg-1".to_owned()),
                    participant: None,
                },
                kind: InboundMessageKind::Chat,
                author: "123@s.whatsapp.net".to_owned(),
                sender: "123@s.whatsapp.net".to_owned(),
                category: Some("peer".to_owned()),
                push_name: Some("Alice".to_owned()),
                timestamp: Some(10),
                addressing: AddressingContext {
                    mode: AddressingMode::PhoneNumber,
                    sender_alt: Some("abc@lid".to_owned()),
                    recipient_alt: None,
                },
            },
            payloads: vec![DecodedInboundPayload {
                kind: InboundPayloadKind::Plaintext,
                message: text_message("hello"),
                device_sent_unwrapped: false,
                sender_key_distribution_count: 0,
            }],
        };

        let event = message_event_from_decoded(&decoded).unwrap();
        assert_eq!(event.key.remote_jid, "123@s.whatsapp.net");
        assert_eq!(event.key.id, "msg-1");
        assert_eq!(event.timestamp, Some(10));
        assert_eq!(event.fields["kind"], "chat");
        assert_eq!(event.fields["author"], "123@s.whatsapp.net");
        assert_eq!(event.fields["sender_alt"], "abc@lid");
        assert_eq!(event.fields["payload_kind"], "plaintext");
        assert_eq!(event.fields["payload_count"], "1");
        assert_eq!(event.fields["encrypted_payload_count"], "0");

        let payload = event.payload.unwrap();
        let decoded_message = Message::decode(payload).unwrap();
        assert_eq!(decoded_message.conversation.as_deref(), Some("hello"));
    }

    #[test]
    fn maps_decoded_reaction_message_to_reaction_update_event() {
        let target_key = MessageKey {
            remote_jid: Some("123@g.us".to_owned()),
            from_me: Some(false),
            id: Some("target-1".to_owned()),
            participant: Some("456@s.whatsapp.net".to_owned()),
        };
        let reaction_message = Message {
            reaction_message: Some(wa_proto::proto::message::ReactionMessage {
                key: Some(target_key.clone()),
                text: Some("+".to_owned()),
                sender_timestamp_ms: Some(1_700_000_005_123),
                ..Default::default()
            }),
            ..Message::default()
        };
        let decoded = DecodedInboundMessage {
            info: InboundMessageInfo {
                key: MessageKey {
                    remote_jid: Some("123@g.us".to_owned()),
                    from_me: Some(false),
                    id: Some("reaction-1".to_owned()),
                    participant: Some("789@s.whatsapp.net".to_owned()),
                },
                kind: InboundMessageKind::Group,
                author: "789@s.whatsapp.net".to_owned(),
                sender: "123@g.us".to_owned(),
                category: None,
                push_name: None,
                timestamp: Some(1_700_000_005),
                addressing: AddressingContext {
                    mode: AddressingMode::PhoneNumber,
                    sender_alt: None,
                    recipient_alt: None,
                },
            },
            payloads: vec![DecodedInboundPayload {
                kind: InboundPayloadKind::Plaintext,
                message: reaction_message.clone(),
                device_sent_unwrapped: false,
                sender_key_distribution_count: 0,
            }],
        };

        let batch = event_batch_from_decoded_message(&decoded).unwrap();
        assert_eq!(batch.messages_upsert.len(), 1);
        assert_eq!(batch.messages_upsert[0].key.id, "reaction-1");
        assert_eq!(batch.messages_upsert[0].fields["payload_kind"], "plaintext");
        assert_eq!(batch.reactions_update.len(), 1);
        let reaction = &batch.reactions_update[0];
        assert_eq!(reaction.key.remote_jid, "123@g.us");
        assert_eq!(reaction.key.id, "target-1");
        assert_eq!(
            reaction.key.participant.as_deref(),
            Some("456@s.whatsapp.net")
        );
        assert_eq!(reaction.from_jid, "789@s.whatsapp.net");
        assert_eq!(reaction.text.as_deref(), Some("+"));
        assert_eq!(reaction.timestamp, Some(1_700_000_005_123));

        let mut wrapped = decoded.clone();
        wrapped.info.key.id = Some("wrapped-reaction-1".to_owned());
        wrapped.payloads[0].message = Message {
            view_once_message: Some(Box::new(wa_proto::proto::message::FutureProofMessage {
                message: Some(Box::new(reaction_message)),
            })),
            ..Message::default()
        };
        let batch = event_batch_from_decoded_message(&wrapped).unwrap();
        assert_eq!(batch.reactions_update.len(), 1);
        assert_eq!(batch.reactions_update[0].key.id, "target-1");
        assert_eq!(batch.reactions_update[0].text.as_deref(), Some("+"));
        assert_eq!(batch.messages_upsert[0].key.id, "wrapped-reaction-1");
    }

    #[test]
    fn maps_decoded_poll_update_message_to_message_update_event() {
        let target_key = MessageKey {
            remote_jid: Some("123@g.us".to_owned()),
            from_me: Some(false),
            id: Some("poll-creation-1".to_owned()),
            participant: Some("456@s.whatsapp.net".to_owned()),
        };
        let poll_update_message = Message {
            poll_update_message: Some(wa_proto::proto::message::PollUpdateMessage {
                poll_creation_message_key: Some(target_key.clone()),
                vote: Some(wa_proto::proto::message::PollEncValue {
                    enc_payload: Some(Bytes::from_static(b"encrypted-vote")),
                    enc_iv: Some(Bytes::from_static(b"vote-iv")),
                }),
                metadata: Some(Default::default()),
                sender_timestamp_ms: Some(1_700_000_007_123),
            }),
            ..Message::default()
        };
        let decoded = DecodedInboundMessage {
            info: InboundMessageInfo {
                key: MessageKey {
                    remote_jid: Some("123@g.us".to_owned()),
                    from_me: Some(false),
                    id: Some("poll-update-1".to_owned()),
                    participant: Some("789@s.whatsapp.net".to_owned()),
                },
                kind: InboundMessageKind::Group,
                author: "789@s.whatsapp.net".to_owned(),
                sender: "123@g.us".to_owned(),
                category: None,
                push_name: None,
                timestamp: Some(1_700_000_007),
                addressing: AddressingContext {
                    mode: AddressingMode::PhoneNumber,
                    sender_alt: None,
                    recipient_alt: None,
                },
            },
            payloads: vec![DecodedInboundPayload {
                kind: InboundPayloadKind::Plaintext,
                message: poll_update_message.clone(),
                device_sent_unwrapped: false,
                sender_key_distribution_count: 0,
            }],
        };

        let batch = event_batch_from_decoded_message(&decoded).unwrap();
        assert_eq!(batch.messages_upsert.len(), 1);
        assert_eq!(batch.messages_upsert[0].key.id, "poll-update-1");
        assert_eq!(batch.messages_update.len(), 1);
        let update = &batch.messages_update[0];
        assert_eq!(
            update.key,
            message_event_key_from_proto_key(&target_key).unwrap()
        );
        assert_eq!(update.timestamp, Some(1_700_000_007_123));
        assert_eq!(update.fields["source"], "poll_update_message");
        assert_eq!(update.fields["poll_update"], "true");
        assert_eq!(update.fields["voter_jid"], "789@s.whatsapp.net");
        assert_eq!(update.fields["vote_encrypted"], "true");
        assert_eq!(update.fields["metadata_present"], "true");
        assert_eq!(update.fields["encrypted_vote_payload_bytes"], "14");
        assert_eq!(update.fields["encrypted_vote_iv_bytes"], "7");

        let payload = batch.messages_upsert[0].payload.clone().unwrap();
        let decoded_message = Message::decode(payload).unwrap();
        assert!(decoded_message.poll_update_message.is_some());

        let mut wrapped = decoded.clone();
        wrapped.info.key.id = Some("wrapped-poll-update-1".to_owned());
        wrapped.payloads[0].message = Message {
            view_once_message: Some(Box::new(wa_proto::proto::message::FutureProofMessage {
                message: Some(Box::new(poll_update_message)),
            })),
            ..Message::default()
        };

        let batch = event_batch_from_decoded_message(&wrapped).unwrap();
        assert_eq!(batch.messages_update.len(), 1);
        let update = &batch.messages_update[0];
        assert_eq!(
            update.key,
            message_event_key_from_proto_key(&target_key).unwrap()
        );
        assert_eq!(update.fields["source"], "poll_update_message");
        assert_eq!(update.fields["vote_encrypted"], "true");
        assert_eq!(batch.messages_upsert[0].key.id, "wrapped-poll-update-1");
    }

    #[test]
    fn maps_decoded_event_response_message_to_message_update_event() {
        let target_key = MessageKey {
            remote_jid: Some("123@g.us".to_owned()),
            from_me: Some(false),
            id: Some("event-creation-1".to_owned()),
            participant: Some("456@s.whatsapp.net".to_owned()),
        };
        let event_response_message = Message {
            enc_event_response_message: Some(wa_proto::proto::message::EncEventResponseMessage {
                event_creation_message_key: Some(target_key.clone()),
                enc_payload: Some(Bytes::from_static(b"encrypted-rsvp")),
                enc_iv: Some(Bytes::from_static(b"rsvp-iv")),
            }),
            ..Message::default()
        };
        let decoded = DecodedInboundMessage {
            info: InboundMessageInfo {
                key: MessageKey {
                    remote_jid: Some("123@g.us".to_owned()),
                    from_me: Some(false),
                    id: Some("event-response-1".to_owned()),
                    participant: Some("789@s.whatsapp.net".to_owned()),
                },
                kind: InboundMessageKind::Group,
                author: "789@s.whatsapp.net".to_owned(),
                sender: "123@g.us".to_owned(),
                category: None,
                push_name: None,
                timestamp: Some(1_700_000_008),
                addressing: AddressingContext {
                    mode: AddressingMode::PhoneNumber,
                    sender_alt: None,
                    recipient_alt: None,
                },
            },
            payloads: vec![DecodedInboundPayload {
                kind: InboundPayloadKind::Plaintext,
                message: event_response_message,
                device_sent_unwrapped: false,
                sender_key_distribution_count: 0,
            }],
        };

        let batch = event_batch_from_decoded_message(&decoded).unwrap();
        assert_eq!(batch.messages_upsert.len(), 1);
        assert_eq!(batch.messages_upsert[0].key.id, "event-response-1");
        assert_eq!(batch.messages_update.len(), 1);
        let update = &batch.messages_update[0];
        assert_eq!(
            update.key,
            message_event_key_from_proto_key(&target_key).unwrap()
        );
        assert_eq!(update.timestamp, None);
        assert_eq!(update.fields["source"], "enc_event_response_message");
        assert_eq!(update.fields["event_response"], "true");
        assert_eq!(update.fields["responder_jid"], "789@s.whatsapp.net");
        assert_eq!(update.fields["response_encrypted"], "true");
        assert_eq!(
            update.fields["encrypted_event_response_payload_bytes"],
            "14"
        );
        assert_eq!(update.fields["encrypted_event_response_iv_bytes"], "7");

        let payload = batch.messages_upsert[0].payload.clone().unwrap();
        let decoded_message = Message::decode(payload).unwrap();
        assert!(decoded_message.enc_event_response_message.is_some());
    }

    #[cfg(feature = "noise")]
    #[test]
    fn decrypts_poll_and_event_response_updates_with_creation_secrets() {
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
        let poll_secret = Bytes::from(vec![7u8; 32]);
        let event_secret = Bytes::from(vec![8u8; 32]);
        let poll_update = crate::build_poll_update_message(
            crate::build_encrypted_poll_update_content_with_iv(
                crate::PollVoteContent::from_option_names(
                    poll_key.clone(),
                    ["Ship"],
                    poll_secret.clone(),
                    "456@s.whatsapp.net",
                    "789:1@s.whatsapp.net",
                )
                .unwrap()
                .with_sender_timestamp_ms(1_700_000_007_123),
                Bytes::from_static(b"poll-vote-iv"),
            )
            .unwrap(),
        )
        .unwrap()
        .poll_update_message;
        let event_response = crate::build_event_response_message(
            crate::build_encrypted_event_response_content_with_iv(
                crate::EventResponsePayload::new(
                    event_key.clone(),
                    crate::EventResponseKind::Maybe,
                    event_secret.clone(),
                    "456@s.whatsapp.net",
                    "789:1@s.whatsapp.net",
                )
                .with_timestamp_ms(1_700_000_008_123)
                .with_extra_guest_count(2),
                Bytes::from_static(b"event-rsvpiv"),
            )
            .unwrap(),
        )
        .unwrap()
        .enc_event_response_message;
        let decoded = DecodedInboundMessage {
            info: InboundMessageInfo {
                key: MessageKey {
                    remote_jid: Some("123@g.us".to_owned()),
                    from_me: Some(false),
                    id: Some("poll-event-update-1".to_owned()),
                    participant: Some("789@s.whatsapp.net".to_owned()),
                },
                kind: InboundMessageKind::Group,
                author: "789@s.whatsapp.net".to_owned(),
                sender: "123@g.us".to_owned(),
                category: None,
                push_name: None,
                timestamp: Some(1_700_000_008),
                addressing: AddressingContext {
                    mode: AddressingMode::PhoneNumber,
                    sender_alt: None,
                    recipient_alt: None,
                },
            },
            payloads: vec![DecodedInboundPayload {
                kind: InboundPayloadKind::Plaintext,
                message: Message {
                    poll_update_message: poll_update,
                    enc_event_response_message: event_response,
                    ..Message::default()
                },
                device_sent_unwrapped: false,
                sender_key_distribution_count: 0,
            }],
        };
        let mut secrets = PollEventMessageSecrets::new();
        secrets.insert(
            message_event_key_from_proto_key(&poll_key).unwrap(),
            PollEventMessageSecret::new("456@s.whatsapp.net", poll_secret).unwrap(),
        );
        secrets.insert(
            message_event_key_from_proto_key(&event_key).unwrap(),
            PollEventMessageSecret::new("456@s.whatsapp.net", event_secret).unwrap(),
        );

        let batch =
            event_batch_from_decoded_message_with_poll_event_secrets(&decoded, &secrets).unwrap();
        assert_eq!(batch.messages_update.len(), 2);
        let poll_update = &batch.messages_update[0];
        assert_eq!(poll_update.fields["source"], "poll_update_message");
        assert_eq!(poll_update.fields["vote_decrypted"], "true");
        assert_eq!(poll_update.fields["selected_options_count"], "1");
        assert_eq!(
            poll_update.fields["selected_option_hashes_hex"],
            lower_hex(&wa_crypto::sha256_hash(b"Ship"))
        );
        assert_eq!(
            poll_update.fields["poll_secret_creator_jid"],
            "456@s.whatsapp.net"
        );

        let event_update = &batch.messages_update[1];
        assert_eq!(event_update.fields["source"], "enc_event_response_message");
        assert_eq!(event_update.fields["response_decrypted"], "true");
        assert_eq!(event_update.fields["response"], "maybe");
        assert_eq!(
            event_update.fields["response_timestamp_ms"],
            "1700000008123"
        );
        assert_eq!(event_update.fields["extra_guest_count"], "2");
        assert_eq!(
            event_update.fields["event_secret_creator_jid"],
            "456@s.whatsapp.net"
        );

        let mut wrong_secrets = PollEventMessageSecrets::new();
        wrong_secrets.insert(
            message_event_key_from_proto_key(&poll_key).unwrap(),
            PollEventMessageSecret::new("456@s.whatsapp.net", Bytes::from(vec![1u8; 32])).unwrap(),
        );
        let wrong_batch =
            event_batch_from_decoded_message_with_poll_event_secrets(&decoded, &wrong_secrets)
                .unwrap();
        assert_eq!(wrong_batch.messages_update.len(), 2);
        assert_eq!(
            wrong_batch.messages_update[0].fields["vote_decrypted"],
            "false"
        );
        assert!(
            wrong_batch.messages_update[0]
                .fields
                .contains_key("vote_decrypt_error")
        );
        assert!(
            !wrong_batch.messages_update[1]
                .fields
                .contains_key("response_decrypted")
        );
    }

    #[cfg(feature = "noise")]
    #[test]
    fn extracts_poll_event_creation_secret_from_stored_message_event() {
        let poll_secret = Bytes::from(vec![7u8; 32]);
        let event = MessageEvent::new(MessageEventKey::new(
            "123@g.us",
            "poll-creation-1",
            Some("456@s.whatsapp.net".to_owned()),
        ))
        .with_payload(
            crate::encode_message(
                &crate::build_poll_message(crate::PollContent::new(
                    "Deploy?",
                    ["Ship", "Hold"],
                    1,
                    poll_secret.clone(),
                ))
                .unwrap(),
            )
            .unwrap(),
        )
        .with_field("author", "456@s.whatsapp.net");
        let secret = poll_event_message_secret_from_event(&event)
            .unwrap()
            .unwrap();
        assert_eq!(secret.creator_jid, "456@s.whatsapp.net");
        assert_eq!(secret.message_secret, poll_secret);

        let wrapped_poll_secret = Bytes::from(vec![8u8; 32]);
        let wrapped_poll = MessageEvent::new(MessageEventKey::new(
            "123@g.us",
            "wrapped-poll-creation-1",
            Some("456@s.whatsapp.net".to_owned()),
        ))
        .with_payload(
            crate::encode_message(
                &crate::build_view_once_message(crate::MessageContent::poll(
                    crate::PollContent::new(
                        "Wrapped deploy?",
                        ["Ship", "Hold"],
                        1,
                        wrapped_poll_secret.clone(),
                    ),
                ))
                .unwrap(),
            )
            .unwrap(),
        )
        .with_field("author", "456@s.whatsapp.net");
        let secret = poll_event_message_secret_from_event(&wrapped_poll)
            .unwrap()
            .unwrap();
        assert_eq!(secret.creator_jid, "456@s.whatsapp.net");
        assert_eq!(secret.message_secret, wrapped_poll_secret);

        let text = MessageEvent::new(MessageEventKey::new("123@s.whatsapp.net", "text-1", None))
            .with_payload(
                crate::encode_message(&crate::build_text_message("hello").unwrap()).unwrap(),
            )
            .with_field("author", "123@s.whatsapp.net");
        assert!(
            poll_event_message_secret_from_event(&text)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn maps_decoded_protocol_messages_to_update_and_delete_events() {
        let target_key = MessageKey {
            remote_jid: Some("123@g.us".to_owned()),
            from_me: Some(true),
            id: Some("target-1".to_owned()),
            participant: Some("456@s.whatsapp.net".to_owned()),
        };
        let base_info = InboundMessageInfo {
            key: MessageKey {
                remote_jid: Some("123@g.us".to_owned()),
                from_me: Some(false),
                id: Some("protocol-1".to_owned()),
                participant: Some("789@s.whatsapp.net".to_owned()),
            },
            kind: InboundMessageKind::Group,
            author: "789@s.whatsapp.net".to_owned(),
            sender: "123@g.us".to_owned(),
            category: None,
            push_name: None,
            timestamp: Some(1_700_000_006),
            addressing: AddressingContext {
                mode: AddressingMode::PhoneNumber,
                sender_alt: None,
                recipient_alt: None,
            },
        };

        let edit = DecodedInboundMessage {
            info: base_info.clone(),
            payloads: vec![DecodedInboundPayload {
                kind: InboundPayloadKind::Plaintext,
                message: Message {
                    protocol_message: Some(Box::new(wa_proto::proto::message::ProtocolMessage {
                        key: Some(target_key.clone()),
                        r#type: Some(protocol_message::Type::MessageEdit as i32),
                        edited_message: Some(Box::new(text_message("edited"))),
                        timestamp_ms: Some(1_700_000_006_123),
                        ..Default::default()
                    })),
                    ..Message::default()
                },
                device_sent_unwrapped: false,
                sender_key_distribution_count: 0,
            }],
        };
        let edit_batch = event_batch_from_decoded_message(&edit).unwrap();
        assert_eq!(edit_batch.messages_upsert.len(), 1);
        assert_eq!(edit_batch.messages_upsert[0].key.id, "protocol-1");
        assert_eq!(edit_batch.messages_update.len(), 1);
        assert_eq!(edit_batch.messages_update[0].key.id, "target-1");
        assert_eq!(
            edit_batch.messages_update[0].key.participant.as_deref(),
            Some("456@s.whatsapp.net")
        );
        assert_eq!(
            edit_batch.messages_update[0].timestamp,
            Some(1_700_000_006_123)
        );
        assert_eq!(
            edit_batch.messages_update[0].fields["protocol_type"],
            "message_edit"
        );
        assert_eq!(
            edit_batch.messages_update[0].fields["edited_stanza_type"],
            "text"
        );

        let delete = DecodedInboundMessage {
            info: InboundMessageInfo {
                key: MessageKey {
                    id: Some("protocol-2".to_owned()),
                    ..base_info.key.clone()
                },
                ..base_info.clone()
            },
            payloads: vec![DecodedInboundPayload {
                kind: InboundPayloadKind::Plaintext,
                message: Message {
                    protocol_message: Some(Box::new(wa_proto::proto::message::ProtocolMessage {
                        key: Some(target_key.clone()),
                        r#type: Some(protocol_message::Type::Revoke as i32),
                        ..Default::default()
                    })),
                    ..Message::default()
                },
                device_sent_unwrapped: false,
                sender_key_distribution_count: 0,
            }],
        };
        let delete_batch = event_batch_from_decoded_message(&delete).unwrap();
        assert_eq!(delete_batch.messages_upsert.len(), 1);
        assert_eq!(delete_batch.messages_upsert[0].key.id, "protocol-2");
        assert_eq!(
            delete_batch.messages_delete,
            vec![message_event_key_from_proto_key(&target_key).unwrap()]
        );

        let pin = DecodedInboundMessage {
            info: InboundMessageInfo {
                key: MessageKey {
                    id: Some("pin-1".to_owned()),
                    ..base_info.key.clone()
                },
                ..base_info.clone()
            },
            payloads: vec![DecodedInboundPayload {
                kind: InboundPayloadKind::Plaintext,
                message: Message {
                    pin_in_chat_message: Some(wa_proto::proto::message::PinInChatMessage {
                        key: Some(target_key.clone()),
                        r#type: Some(pin_in_chat_message::Type::PinForAll as i32),
                        sender_timestamp_ms: Some(1_700_000_006_456),
                    }),
                    ..Message::default()
                },
                device_sent_unwrapped: false,
                sender_key_distribution_count: 0,
            }],
        };
        let pin_batch = event_batch_from_decoded_message(&pin).unwrap();
        assert_eq!(pin_batch.messages_upsert.len(), 1);
        assert_eq!(pin_batch.messages_update.len(), 1);
        assert_eq!(pin_batch.messages_update[0].key.id, "target-1");
        assert_eq!(
            pin_batch.messages_update[0].timestamp,
            Some(1_700_000_006_456)
        );
        assert_eq!(
            pin_batch.messages_update[0].fields["source"],
            "pin_in_chat_message"
        );
        assert_eq!(pin_batch.messages_update[0].fields["pin_action"], "pin");

        let wrapped_delete = DecodedInboundMessage {
            info: InboundMessageInfo {
                key: MessageKey {
                    id: Some("wrapped-protocol-2".to_owned()),
                    ..base_info.key.clone()
                },
                ..base_info.clone()
            },
            payloads: vec![DecodedInboundPayload {
                kind: InboundPayloadKind::Plaintext,
                message: Message {
                    view_once_message: Some(Box::new(
                        wa_proto::proto::message::FutureProofMessage {
                            message: Some(Box::new(Message {
                                protocol_message: Some(Box::new(
                                    wa_proto::proto::message::ProtocolMessage {
                                        key: Some(target_key.clone()),
                                        r#type: Some(protocol_message::Type::Revoke as i32),
                                        ..Default::default()
                                    },
                                )),
                                ..Message::default()
                            })),
                        },
                    )),
                    ..Message::default()
                },
                device_sent_unwrapped: false,
                sender_key_distribution_count: 0,
            }],
        };
        let wrapped_delete_batch = event_batch_from_decoded_message(&wrapped_delete).unwrap();
        assert_eq!(
            wrapped_delete_batch.messages_delete,
            vec![message_event_key_from_proto_key(&target_key).unwrap()]
        );

        let wrapped_pin = DecodedInboundMessage {
            info: InboundMessageInfo {
                key: MessageKey {
                    id: Some("wrapped-pin-1".to_owned()),
                    ..base_info.key
                },
                ..base_info
            },
            payloads: vec![DecodedInboundPayload {
                kind: InboundPayloadKind::Plaintext,
                message: Message {
                    view_once_message: Some(Box::new(
                        wa_proto::proto::message::FutureProofMessage {
                            message: Some(Box::new(Message {
                                pin_in_chat_message: Some(
                                    wa_proto::proto::message::PinInChatMessage {
                                        key: Some(target_key),
                                        r#type: Some(pin_in_chat_message::Type::UnpinForAll as i32),
                                        sender_timestamp_ms: Some(1_700_000_006_789),
                                    },
                                ),
                                ..Message::default()
                            })),
                        },
                    )),
                    ..Message::default()
                },
                device_sent_unwrapped: false,
                sender_key_distribution_count: 0,
            }],
        };
        let wrapped_pin_batch = event_batch_from_decoded_message(&wrapped_pin).unwrap();
        assert_eq!(wrapped_pin_batch.messages_update.len(), 1);
        assert_eq!(wrapped_pin_batch.messages_update[0].key.id, "target-1");
        assert_eq!(
            wrapped_pin_batch.messages_update[0].fields["pin_action"],
            "unpin"
        );
    }

    #[test]
    fn pushes_decoded_message_to_event_buffer() {
        let decoded = DecodedInboundMessage {
            info: InboundMessageInfo {
                key: MessageKey {
                    remote_jid: Some("123@g.us".to_owned()),
                    from_me: Some(true),
                    id: Some("g1".to_owned()),
                    participant: Some("999@s.whatsapp.net".to_owned()),
                },
                kind: InboundMessageKind::Group,
                author: "999@s.whatsapp.net".to_owned(),
                sender: "123@g.us".to_owned(),
                category: None,
                push_name: None,
                timestamp: None,
                addressing: AddressingContext {
                    mode: AddressingMode::PhoneNumber,
                    sender_alt: None,
                    recipient_alt: None,
                },
            },
            payloads: vec![DecodedInboundPayload {
                kind: InboundPayloadKind::Encrypted(crate::InboundCiphertextType::SenderKey),
                message: text_message("group"),
                device_sent_unwrapped: true,
                sender_key_distribution_count: 1,
            }],
        };
        let mut buffer = EventBuffer::new(crate::EventBufferConfig {
            max_pending_items: 4,
        });

        push_decoded_message_to_buffer(&mut buffer, &decoded).unwrap();
        let batch = buffer.flush().unwrap();

        assert_eq!(batch.messages_upsert.len(), 1);
        assert_eq!(batch.messages_upsert[0].key.remote_jid, "123@g.us");
        assert_eq!(
            batch.messages_upsert[0].key.participant.as_deref(),
            Some("999@s.whatsapp.net")
        );
        assert_eq!(batch.messages_upsert[0].fields["payload_kind"], "skmsg");
        assert_eq!(
            batch.messages_upsert[0].fields["device_sent_unwrapped"],
            "true"
        );
        assert_eq!(
            batch.messages_upsert[0].fields["sender_key_distribution_count"],
            "1"
        );
    }

    #[test]
    fn maps_placeholder_resend_response_to_extra_upsert_event() {
        let real_message = Message {
            conversation: Some("recovered".to_owned()),
            ..Message::default()
        };
        let web_message = wa_proto::proto::WebMessageInfo {
            key: Some(MessageKey {
                remote_jid: Some("123@s.whatsapp.net".to_owned()),
                from_me: Some(false),
                id: Some("missing-1".to_owned()),
                participant: None,
            }),
            message: Some(real_message.clone()),
            message_timestamp: Some(44),
            push_name: Some("Alice".to_owned()),
            ..wa_proto::proto::WebMessageInfo::default()
        };
        let response_message = Message {
            protocol_message: Some(Box::new(wa_proto::proto::message::ProtocolMessage {
                r#type: Some(
                    wa_proto::proto::message::protocol_message::Type::PeerDataOperationRequestResponseMessage
                        as i32,
                ),
                peer_data_operation_request_response_message: Some(
                    wa_proto::proto::message::PeerDataOperationRequestResponseMessage {
                        peer_data_operation_request_type: Some(
                            wa_proto::proto::message::PeerDataOperationRequestType::PlaceholderMessageResend
                                as i32,
                        ),
                        stanza_id: Some("pdo-1".to_owned()),
                        peer_data_operation_result: vec![
                            wa_proto::proto::message::peer_data_operation_request_response_message::PeerDataOperationResult {
                                placeholder_message_resend_response: Some(
                                    wa_proto::proto::message::peer_data_operation_request_response_message::peer_data_operation_result::PlaceholderMessageResendResponse {
                                        web_message_info_bytes: Some(Bytes::from(web_message.encode_to_vec())),
                                    },
                                ),
                                ..Default::default()
                            },
                        ],
                    },
                ),
                ..Default::default()
            })),
            ..Message::default()
        };
        let decoded = DecodedInboundMessage {
            info: InboundMessageInfo {
                key: MessageKey {
                    remote_jid: Some("999@s.whatsapp.net".to_owned()),
                    from_me: Some(true),
                    id: Some("pdo-1".to_owned()),
                    participant: None,
                },
                kind: InboundMessageKind::Chat,
                author: "999@s.whatsapp.net".to_owned(),
                sender: "999@s.whatsapp.net".to_owned(),
                category: Some("peer".to_owned()),
                push_name: None,
                timestamp: Some(45),
                addressing: AddressingContext {
                    mode: AddressingMode::PhoneNumber,
                    sender_alt: None,
                    recipient_alt: None,
                },
            },
            payloads: vec![DecodedInboundPayload {
                kind: InboundPayloadKind::Plaintext,
                message: response_message.clone(),
                device_sent_unwrapped: false,
                sender_key_distribution_count: 0,
            }],
        };

        let events = placeholder_resend_events_from_message(&response_message).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].key.id, "missing-1");
        assert_eq!(events[0].timestamp, Some(44));
        assert_eq!(events[0].fields["kind"], "placeholder_resend");
        assert_eq!(events[0].fields["source"], "peer_data_operation_response");
        assert_eq!(events[0].fields["request_id"], "pdo-1");
        assert_eq!(events[0].fields["push_name"], "Alice");
        let recovered = Message::decode(events[0].payload.clone().unwrap()).unwrap();
        assert_eq!(recovered, real_message);

        let batch = event_batch_from_decoded_message(&decoded).unwrap();
        assert_eq!(batch.messages_upsert.len(), 2);
        assert_eq!(batch.messages_upsert[0].key.id, "pdo-1");
        assert_eq!(batch.messages_upsert[1], events[0]);
    }

    #[test]
    fn maps_receipts_to_receipt_events() {
        let receipt = InboundReceipt {
            id: "m1".to_owned(),
            from: "123@g.us".to_owned(),
            recipient: None,
            participant: Some("456@s.whatsapp.net".to_owned()),
            kind: InboundReceiptKind::Read,
            timestamp: Some(20),
            message_ids: vec!["m1".to_owned(), "m2".to_owned()],
        };

        let events = receipt_events_from_inbound(&receipt).unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].key.remote_jid, "123@g.us");
        assert_eq!(events[0].key.id, "m1");
        assert_eq!(
            events[0].key.participant.as_deref(),
            Some("456@s.whatsapp.net")
        );
        assert_eq!(events[0].receipt_type, "read");
        assert_eq!(events[0].timestamp, Some(20));
        assert_eq!(events[1].key.id, "m2");
    }

    #[test]
    fn maps_media_retry_update_to_typed_event() {
        let payload = MediaRetryPayload::new(
            Bytes::from_static(b"ciphertext"),
            Bytes::from(vec![9u8; 12]),
        );
        let update = MediaRetryUpdate {
            key: MessageKey {
                remote_jid: Some("123@s.whatsapp.net".to_owned()),
                from_me: Some(false),
                id: Some("msg-1".to_owned()),
                participant: Some("456@s.whatsapp.net".to_owned()),
            },
            media: Some(payload.clone()),
            error: None,
        };

        let event = media_retry_event_from_update(&update).unwrap();
        assert_eq!(event.key.remote_jid, "123@s.whatsapp.net");
        assert_eq!(event.key.id, "msg-1");
        assert_eq!(event.key.participant.as_deref(), Some("456@s.whatsapp.net"));
        assert!(!event.from_me);
        assert_eq!(event.encrypted_payload, Some(payload.ciphertext));
        assert_eq!(event.iv, Some(payload.iv));
        assert_eq!(event.error_code, None);

        let error_update = MediaRetryUpdate {
            key: MessageKey {
                remote_jid: Some("123@s.whatsapp.net".to_owned()),
                from_me: Some(true),
                id: Some("msg-2".to_owned()),
                participant: None,
            },
            media: None,
            error: Some(MediaRetryError {
                code: 2,
                text: Some("missing".to_owned()),
                status_code: 404,
            }),
        };
        let event = media_retry_event_from_update(&error_update).unwrap();
        assert!(event.from_me);
        assert_eq!(event.encrypted_payload, None);
        assert_eq!(event.error_code, Some(2));
        assert_eq!(event.error_text.as_deref(), Some("missing"));
        assert_eq!(event.status_code, Some(404));
    }

    #[test]
    fn maps_message_acks_to_updates() {
        let ack = InboundAck {
            id: "m1".to_owned(),
            class: "message".to_owned(),
            from: Some("123@s.whatsapp.net".to_owned()),
            to: None,
            participant: None,
            recipient: None,
            ack_type: Some("text".to_owned()),
            error_code: None,
            participant_hash: Some("2:abc".to_owned()),
        };

        let updates = message_updates_from_ack(&ack).unwrap();
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].key.remote_jid, "123@s.whatsapp.net");
        assert_eq!(updates[0].key.id, "m1");
        assert_eq!(updates[0].fields["status"], "server_ack");
        assert_eq!(updates[0].fields["ack_type"], "text");
        assert_eq!(updates[0].fields["participant_hash"], "2:abc");

        let recipient_ack = InboundAck {
            from: None,
            to: Some("999@s.whatsapp.net".to_owned()),
            recipient: Some("123@s.whatsapp.net".to_owned()),
            ..ack.clone()
        };
        let updates = message_updates_from_ack(&recipient_ack).unwrap();
        assert_eq!(updates[0].key.remote_jid, "123@s.whatsapp.net");
        assert_eq!(updates[0].fields["recipient"], "123@s.whatsapp.net");

        let error_ack = InboundAck {
            error_code: Some(crate::ACK_ERROR_SMAX_INVALID),
            ..ack
        };
        let updates = message_updates_from_ack(&error_ack).unwrap();
        assert_eq!(updates[0].fields["status"], "error");
        assert_eq!(updates[0].fields["ack_error_code"], "479");
    }

    #[test]
    fn ignores_non_message_acks_for_message_updates() {
        let ack = InboundAck {
            id: "n1".to_owned(),
            class: "notification".to_owned(),
            from: Some("123@s.whatsapp.net".to_owned()),
            to: None,
            participant: None,
            recipient: None,
            ack_type: None,
            error_code: None,
            participant_hash: None,
        };

        assert!(message_updates_from_ack(&ack).unwrap().is_empty());
    }

    #[test]
    fn rejects_malformed_event_inputs() {
        assert!(
            message_event_key_from_proto_key(&MessageKey {
                remote_jid: Some("invalid".to_owned()),
                from_me: Some(false),
                id: Some("m1".to_owned()),
                participant: None,
            })
            .is_err()
        );
        assert!(
            receipt_events_from_inbound(&InboundReceipt {
                id: "m1".to_owned(),
                from: "123@s.whatsapp.net".to_owned(),
                recipient: None,
                participant: None,
                kind: InboundReceiptKind::Delivery,
                timestamp: None,
                message_ids: vec!["".to_owned()],
            })
            .is_err()
        );
    }

    #[tokio::test]
    async fn processes_message_node_to_upsert_event_and_ack() {
        let message = BinaryNode::new("message")
            .with_attr("id", "msg-1")
            .with_attr("from", "123@s.whatsapp.net")
            .with_attr("type", "text")
            .with_content(vec![
                BinaryNode::new("plaintext").with_content(encode_proto(&text_message("hello"))),
            ]);
        let mut buffer = test_buffer();

        let result = process_inbound_node(
            &message,
            "999@s.whatsapp.net",
            Some("own@lid"),
            Some("999:2@s.whatsapp.net"),
            &PassthroughDecryptor,
            &mut buffer,
        )
        .await
        .unwrap();

        assert_eq!(result.action, InboundNodeAction::Message);
        assert_eq!(result.event_count, 1);
        assert!(result.error.is_none());
        let ack = result.response.unwrap();
        assert_eq!(ack.tag, "ack");
        assert_eq!(ack.attrs["id"], "msg-1");
        assert_eq!(ack.attrs["class"], "message");
        assert_eq!(ack.attrs["to"], "123@s.whatsapp.net");
        assert_eq!(ack.attrs["from"], "999:2@s.whatsapp.net");

        let batch = buffer.flush().unwrap();
        assert_eq!(batch.messages_upsert.len(), 1);
        assert_eq!(
            batch.messages_upsert[0].key.remote_jid,
            "123@s.whatsapp.net"
        );
        assert_eq!(batch.messages_upsert[0].key.id, "msg-1");
        let payload = batch.messages_upsert[0].payload.clone().unwrap();
        let decoded = Message::decode(payload).unwrap();
        assert_eq!(decoded.conversation.as_deref(), Some("hello"));
    }

    #[tokio::test]
    async fn processes_unavailable_placeholder_message_to_stub_event_and_ack() {
        let now = current_unix_timestamp();
        let message = BinaryNode::new("message")
            .with_attr("id", "missing-1")
            .with_attr("from", "123@s.whatsapp.net")
            .with_attr("t", now.to_string())
            .with_content(vec![
                BinaryNode::new("unavailable").with_attr("type", "temporary_unavailable"),
            ]);
        let mut buffer = test_buffer();

        let result = process_inbound_node(
            &message,
            "999@s.whatsapp.net",
            Some("own@lid"),
            Some("999:2@s.whatsapp.net"),
            &PassthroughDecryptor,
            &mut buffer,
        )
        .await
        .unwrap();

        assert_eq!(result.action, InboundNodeAction::Message);
        assert_eq!(result.event_count, 1);
        assert!(result.error.is_none());
        let ack = result.response.unwrap();
        assert_eq!(ack.tag, "ack");
        assert_eq!(ack.attrs["id"], "missing-1");
        assert_eq!(ack.attrs["class"], "message");
        assert_eq!(ack.attrs["to"], "123@s.whatsapp.net");
        assert_eq!(ack.attrs["from"], "999:2@s.whatsapp.net");

        let batch = buffer.flush().unwrap();
        assert_eq!(batch.messages_upsert.len(), 1);
        let event = &batch.messages_upsert[0];
        assert_eq!(event.key.remote_jid, "123@s.whatsapp.net");
        assert_eq!(event.key.id, "missing-1");
        assert_eq!(event.timestamp, Some(now));
        assert_eq!(event.fields["kind"], "placeholder_unavailable");
        assert_eq!(event.fields["source"], "unavailable_message");
        assert_eq!(event.fields["unavailable_type"], "temporary_unavailable");
        assert_eq!(
            event.fields["stub_reason"],
            PLACEHOLDER_NO_MESSAGE_FOUND_ERROR_TEXT
        );
        let payload = event.payload.clone().unwrap();
        let decoded = Message::decode(payload).unwrap();
        assert!(decoded.placeholder_message.is_some());
    }

    #[tokio::test]
    async fn skips_excluded_unavailable_placeholder_message_with_ack() {
        let now = current_unix_timestamp();
        let message = BinaryNode::new("message")
            .with_attr("id", "missing-bot")
            .with_attr("from", "123@s.whatsapp.net")
            .with_attr("t", now.to_string())
            .with_content(vec![
                BinaryNode::new("unavailable").with_attr("type", "bot_unavailable_fanout"),
            ]);
        let mut buffer = test_buffer();

        let result = process_inbound_node(
            &message,
            "999@s.whatsapp.net",
            Some("own@lid"),
            Some("999:2@s.whatsapp.net"),
            &PassthroughDecryptor,
            &mut buffer,
        )
        .await
        .unwrap();

        assert_eq!(result.action, InboundNodeAction::Message);
        assert_eq!(result.event_count, 0);
        assert!(result.error.is_none());
        let ack = result.response.unwrap();
        assert_eq!(ack.tag, "ack");
        assert_eq!(ack.attrs["id"], "missing-bot");
        assert_eq!(ack.attrs["class"], "message");
        assert!(buffer.flush().is_none());
    }

    #[tokio::test]
    async fn processes_offline_node_children_with_fair_yielding() {
        let offline = BinaryNode::new("offline").with_content(vec![
            BinaryNode::new("message")
                .with_attr("id", "offline-1")
                .with_attr("from", "123@s.whatsapp.net")
                .with_attr("type", "text")
                .with_content(vec![
                    BinaryNode::new("plaintext").with_content(encode_proto(&text_message("one"))),
                ]),
            BinaryNode::new("message")
                .with_attr("id", "offline-2")
                .with_attr("from", "456@s.whatsapp.net")
                .with_attr("type", "text")
                .with_content(vec![
                    BinaryNode::new("plaintext").with_content(encode_proto(&text_message("two"))),
                ]),
        ]);
        let mut buffer = test_buffer();

        let result = process_offline_node(
            &offline,
            "999@s.whatsapp.net",
            Some("own@lid"),
            Some("999:2@s.whatsapp.net"),
            &PassthroughDecryptor,
            &mut buffer,
            1,
        )
        .await
        .unwrap();

        assert_eq!(result.child_count, 2);
        assert_eq!(result.results.len(), 2);
        assert_eq!(result.yielded_count, 1);
        assert_eq!(result.event_count(), 2);
        assert_eq!(result.response_count(), 2);
        for result in &result.results {
            assert_eq!(result.action, InboundNodeAction::Message);
            assert!(result.error.is_none());
            assert_eq!(result.response.as_ref().unwrap().tag, "ack");
        }

        let batch = buffer.flush().unwrap();
        assert_eq!(batch.messages_upsert.len(), 2);
        assert_eq!(batch.messages_upsert[0].key.id, "offline-1");
        assert_eq!(batch.messages_upsert[1].key.id, "offline-2");
    }

    #[tokio::test]
    async fn processes_malformed_message_node_to_nack() {
        let message = BinaryNode::new("message")
            .with_attr("id", "bad-1")
            .with_attr("from", "123@s.whatsapp.net");
        let mut buffer = test_buffer();

        let result = process_inbound_node(
            &message,
            "999@s.whatsapp.net",
            None,
            Some("999@s.whatsapp.net"),
            &PassthroughDecryptor,
            &mut buffer,
        )
        .await
        .unwrap();

        assert_eq!(result.action, InboundNodeAction::Message);
        assert_eq!(result.event_count, 0);
        assert!(result.error.is_some());
        let nack = result.response.unwrap();
        assert_eq!(nack.tag, "ack");
        assert_eq!(nack.attrs["id"], "bad-1");
        assert_eq!(nack.attrs["error"], crate::NACK_PARSING_ERROR.to_string());
        assert!(buffer.is_empty());
    }

    #[tokio::test]
    async fn processes_receipt_node_to_receipt_events_and_ack() {
        let receipt = BinaryNode::new("receipt")
            .with_attr("id", "m1")
            .with_attr("from", "123@s.whatsapp.net")
            .with_attr("type", "read")
            .with_attr("t", "20")
            .with_content(vec![
                BinaryNode::new("list")
                    .with_content(vec![BinaryNode::new("item").with_attr("id", "m2")]),
            ]);
        let mut buffer = test_buffer();

        let result = process_inbound_node(
            &receipt,
            "999@s.whatsapp.net",
            None,
            Some("999@s.whatsapp.net"),
            &PassthroughDecryptor,
            &mut buffer,
        )
        .await
        .unwrap();

        assert_eq!(result.action, InboundNodeAction::Receipt);
        assert_eq!(result.event_count, 2);
        assert!(result.error.is_none());
        let ack = result.response.unwrap();
        assert_eq!(ack.tag, "ack");
        assert_eq!(ack.attrs["class"], "receipt");
        assert_eq!(ack.attrs["to"], "123@s.whatsapp.net");

        let batch = buffer.flush().unwrap();
        assert_eq!(batch.receipts_update.len(), 2);
        assert_eq!(batch.receipts_update[0].key.id, "m1");
        assert_eq!(batch.receipts_update[1].key.id, "m2");
        assert_eq!(batch.receipts_update[0].receipt_type, "read");
    }

    #[tokio::test]
    async fn processes_receipt_list_item_metadata_to_distinct_events() {
        let list = BinaryNode::new("list").with_content(vec![
            BinaryNode::new("item")
                .with_attr("id", "m2")
                .with_attr("participant", "222@s.whatsapp.net")
                .with_attr("t", "21"),
            BinaryNode::new("item").with_attr("id", "m3"),
        ]);
        let receipt = BinaryNode::new("receipt")
            .with_attr("id", "m1")
            .with_attr("from", "123@g.us")
            .with_attr("participant", "111@s.whatsapp.net")
            .with_attr("type", "read")
            .with_attr("t", "20")
            .with_content(vec![list]);
        let mut buffer = test_buffer();

        let result = process_inbound_node(
            &receipt,
            "999@s.whatsapp.net",
            None,
            Some("999@s.whatsapp.net"),
            &PassthroughDecryptor,
            &mut buffer,
        )
        .await
        .unwrap();

        assert_eq!(result.action, InboundNodeAction::Receipt);
        assert_eq!(result.event_count, 3);
        assert!(result.error.is_none());
        let batch = buffer.flush().unwrap();
        assert_eq!(batch.receipts_update.len(), 3);
        assert_eq!(batch.receipts_update[0].key.id, "m1");
        assert_eq!(
            batch.receipts_update[0].key.participant.as_deref(),
            Some("111@s.whatsapp.net")
        );
        assert_eq!(batch.receipts_update[0].timestamp, Some(20));
        assert_eq!(batch.receipts_update[1].key.id, "m2");
        assert_eq!(
            batch.receipts_update[1].key.participant.as_deref(),
            Some("222@s.whatsapp.net")
        );
        assert_eq!(
            batch.receipts_update[1].participant.as_deref(),
            Some("222@s.whatsapp.net")
        );
        assert_eq!(batch.receipts_update[1].timestamp, Some(21));
        assert_eq!(batch.receipts_update[2].key.id, "m3");
        assert_eq!(
            batch.receipts_update[2].key.participant.as_deref(),
            Some("111@s.whatsapp.net")
        );
        assert_eq!(batch.receipts_update[2].timestamp, Some(20));
    }

    #[tokio::test]
    async fn processes_media_retry_receipt_to_retry_event_and_ack() {
        let receipt = BinaryNode::new("receipt")
            .with_attr("id", "msg-1")
            .with_attr("from", "999@s.whatsapp.net")
            .with_attr("type", "server-error")
            .with_content(vec![
                BinaryNode::new("rmr")
                    .with_attr("jid", "123@s.whatsapp.net")
                    .with_attr("from_me", "false")
                    .with_attr("participant", "456@s.whatsapp.net"),
                BinaryNode::new("encrypt").with_content(vec![
                    BinaryNode::new("enc_p").with_content(Bytes::from_static(b"retry-payload")),
                    BinaryNode::new("enc_iv").with_content(Bytes::from(vec![7u8; 12])),
                ]),
            ]);
        let mut buffer = test_buffer();

        let result = process_inbound_node(
            &receipt,
            "999@s.whatsapp.net",
            None,
            Some("999@s.whatsapp.net"),
            &PassthroughDecryptor,
            &mut buffer,
        )
        .await
        .unwrap();

        assert_eq!(result.action, InboundNodeAction::Receipt);
        assert_eq!(result.event_count, 2);
        assert!(result.error.is_none());
        let ack = result.response.unwrap();
        assert_eq!(ack.tag, "ack");
        assert_eq!(ack.attrs["class"], "receipt");
        assert_eq!(ack.attrs["to"], "999@s.whatsapp.net");

        let batch = buffer.flush().unwrap();
        assert_eq!(batch.receipts_update.len(), 1);
        assert_eq!(batch.media_retry.len(), 1);
        let retry = &batch.media_retry[0];
        assert_eq!(retry.key.remote_jid, "123@s.whatsapp.net");
        assert_eq!(retry.key.id, "msg-1");
        assert_eq!(retry.key.participant.as_deref(), Some("456@s.whatsapp.net"));
        assert_eq!(
            retry.encrypted_payload.as_deref(),
            Some(b"retry-payload".as_slice())
        );
        assert_eq!(retry.iv.as_deref(), Some(&[7u8; 12][..]));
    }

    #[tokio::test]
    async fn processes_media_retry_notification_to_retry_event_and_ack() {
        let notification = BinaryNode::new("notification")
            .with_attr("id", "msg-2")
            .with_attr("from", "999@s.whatsapp.net")
            .with_attr("type", "mediaretry")
            .with_content(vec![
                BinaryNode::new("rmr")
                    .with_attr("jid", "123@s.whatsapp.net")
                    .with_attr("from_me", "false")
                    .with_attr("participant", "456@s.whatsapp.net"),
                BinaryNode::new("encrypt").with_content(vec![
                    BinaryNode::new("enc_p").with_content(Bytes::from_static(b"retry-payload")),
                    BinaryNode::new("enc_iv").with_content(Bytes::from(vec![7u8; 12])),
                ]),
            ]);
        let mut buffer = test_buffer();

        let result = process_inbound_node(
            &notification,
            "999@s.whatsapp.net",
            None,
            Some("999@s.whatsapp.net"),
            &PassthroughDecryptor,
            &mut buffer,
        )
        .await
        .unwrap();

        assert_eq!(result.action, InboundNodeAction::Notification);
        assert_eq!(result.event_count, 2);
        assert!(result.error.is_none());
        let ack = result.response.unwrap();
        assert_eq!(ack.tag, "ack");
        assert_eq!(ack.attrs["class"], "notification");
        assert_eq!(ack.attrs["to"], "999@s.whatsapp.net");

        let events = buffer.drain_events();
        assert_eq!(events.len(), 2);
        assert!(matches!(&events[0], Event::Node(node) if node == &notification));
        let Event::Batch(batch) = &events[1] else {
            panic!("expected media retry event batch");
        };
        assert_eq!(batch.media_retry.len(), 1);
        let retry = &batch.media_retry[0];
        assert_eq!(retry.key.remote_jid, "123@s.whatsapp.net");
        assert_eq!(retry.key.id, "msg-2");
        assert_eq!(retry.key.participant.as_deref(), Some("456@s.whatsapp.net"));
        assert_eq!(
            retry.encrypted_payload.as_deref(),
            Some(b"retry-payload".as_slice())
        );
        assert_eq!(retry.iv.as_deref(), Some(&[7u8; 12][..]));
    }

    #[tokio::test]
    async fn processes_ack_node_to_message_updates_without_response() {
        let ack = BinaryNode::new("ack")
            .with_attr("id", "m1")
            .with_attr("class", "message")
            .with_attr("from", "123@s.whatsapp.net")
            .with_attr("type", "text");
        let mut buffer = test_buffer();

        let result = process_inbound_node(
            &ack,
            "999@s.whatsapp.net",
            None,
            Some("999@s.whatsapp.net"),
            &PassthroughDecryptor,
            &mut buffer,
        )
        .await
        .unwrap();

        assert_eq!(result.action, InboundNodeAction::Ack);
        assert_eq!(result.event_count, 1);
        assert!(result.response.is_none());
        assert!(result.error.is_none());
        let batch = buffer.flush().unwrap();
        assert_eq!(batch.messages_update.len(), 1);
        assert_eq!(batch.messages_update[0].key.id, "m1");
        assert_eq!(batch.messages_update[0].fields["status"], "server_ack");
    }

    #[tokio::test]
    async fn processes_malformed_ack_node_to_handled_error() {
        let ack = BinaryNode::new("ack")
            .with_attr("id", "m1")
            .with_attr("class", "message")
            .with_attr("from", "123@s.whatsapp.net")
            .with_attr("error", "nan");
        let mut buffer = test_buffer();

        let result = process_inbound_node(
            &ack,
            "999@s.whatsapp.net",
            None,
            Some("999@s.whatsapp.net"),
            &PassthroughDecryptor,
            &mut buffer,
        )
        .await
        .unwrap();

        assert_eq!(result.action, InboundNodeAction::Ack);
        assert_eq!(result.event_count, 0);
        assert!(result.response.is_none());
        assert!(result.error.is_some());
        assert!(buffer.is_empty());
    }

    #[tokio::test]
    async fn offline_processing_continues_after_malformed_ack() {
        let bad_ack = BinaryNode::new("ack")
            .with_attr("id", "bad-ack")
            .with_attr("class", "message")
            .with_attr("from", "123@s.whatsapp.net")
            .with_attr("error", "nan");
        let receipt = BinaryNode::new("receipt")
            .with_attr("id", "m1")
            .with_attr("from", "123@s.whatsapp.net")
            .with_attr("type", "read");
        let offline = BinaryNode::new("offline").with_content(vec![bad_ack, receipt]);
        let mut buffer = test_buffer();

        let result = process_offline_node(
            &offline,
            "999@s.whatsapp.net",
            None,
            Some("999@s.whatsapp.net"),
            &PassthroughDecryptor,
            &mut buffer,
            1,
        )
        .await
        .unwrap();

        assert_eq!(result.child_count, 2);
        assert_eq!(result.yielded_count, 1);
        assert_eq!(result.results[0].action, InboundNodeAction::Ack);
        assert!(result.results[0].error.is_some());
        assert!(result.results[0].response.is_none());
        assert_eq!(result.results[1].action, InboundNodeAction::Receipt);
        assert!(result.results[1].error.is_none());
        assert_eq!(result.response_count(), 1);
        assert_eq!(result.event_count(), 1);
        let batch = buffer.flush().unwrap();
        assert_eq!(batch.receipts_update.len(), 1);
        assert_eq!(batch.receipts_update[0].key.id, "m1");
    }

    #[tokio::test]
    async fn processes_notification_node_to_immediate_event_and_ack() {
        let notification = BinaryNode::new("notification")
            .with_attr("id", "n1")
            .with_attr("from", "123@s.whatsapp.net")
            .with_attr("type", "devices");
        let mut buffer = test_buffer();

        let result = process_inbound_node(
            &notification,
            "999@s.whatsapp.net",
            None,
            Some("999@s.whatsapp.net"),
            &PassthroughDecryptor,
            &mut buffer,
        )
        .await
        .unwrap();

        assert_eq!(result.action, InboundNodeAction::Notification);
        assert_eq!(result.event_count, 1);
        assert!(result.error.is_none());
        let ack = result.response.unwrap();
        assert_eq!(ack.tag, "ack");
        assert_eq!(ack.attrs["class"], "notification");

        let events = buffer.drain_events();
        assert_eq!(events.len(), 1);
        assert!(matches!(&events[0], Event::Node(node) if node == &notification));
    }

    #[tokio::test]
    async fn processes_picture_notification_to_contact_update_batch() {
        let notification = BinaryNode::new("notification")
            .with_attr("id", "picture-1")
            .with_attr("from", "123:4@c.us")
            .with_attr("type", "picture")
            .with_content(vec![BinaryNode::new("set").with_attr("hash", "hash-1")]);
        let mut buffer = test_buffer();

        let result = process_inbound_node(
            &notification,
            "999@s.whatsapp.net",
            None,
            Some("999@s.whatsapp.net"),
            &PassthroughDecryptor,
            &mut buffer,
        )
        .await
        .unwrap();

        assert_eq!(result.action, InboundNodeAction::Notification);
        assert_eq!(result.event_count, 2);
        assert!(result.error.is_none());
        let ack = result.response.unwrap();
        assert_eq!(ack.tag, "ack");
        assert_eq!(ack.attrs["class"], "notification");
        assert_eq!(ack.attrs["to"], "123:4@c.us");

        let events = buffer.drain_events();
        assert_eq!(events.len(), 2);
        assert!(matches!(&events[0], Event::Node(node) if node == &notification));
        let Event::Batch(batch) = &events[1] else {
            panic!("expected contact update batch");
        };
        assert_eq!(batch.contacts_update.len(), 1);
        assert_eq!(batch.contacts_update[0].jid, "123@s.whatsapp.net");
        assert_eq!(batch.contacts_update[0].fields["img_url"], "changed");
    }

    #[tokio::test]
    async fn processes_call_node_to_call_events_and_ack() {
        let call = BinaryNode::new("call")
            .with_attr("id", "call-stanza-1")
            .with_attr("from", "123@s.whatsapp.net")
            .with_attr("participant", "456@s.whatsapp.net")
            .with_attr("t", "1700000007")
            .with_content(vec![
                BinaryNode::new("offer")
                    .with_attr("call-id", "call-1")
                    .with_attr("call-creator", "123@s.whatsapp.net")
                    .with_content(vec![BinaryNode::new("audio")]),
            ]);
        let mut buffer = test_buffer();

        let result = process_inbound_node(
            &call,
            "999@s.whatsapp.net",
            None,
            Some("999@s.whatsapp.net"),
            &PassthroughDecryptor,
            &mut buffer,
        )
        .await
        .unwrap();

        assert_eq!(result.action, InboundNodeAction::Call);
        assert_eq!(result.event_count, 1);
        assert!(result.error.is_none());
        let ack = result.response.unwrap();
        assert_eq!(ack.tag, "ack");
        assert_eq!(ack.attrs["class"], "call");
        assert_eq!(ack.attrs["id"], "call-stanza-1");
        assert_eq!(ack.attrs["to"], "123@s.whatsapp.net");
        assert_eq!(ack.attrs["participant"], "456@s.whatsapp.net");

        let batch = buffer.flush().unwrap();
        assert_eq!(batch.calls_update.len(), 1);
        let event = &batch.calls_update[0];
        assert_eq!(event.id, "call-stanza-1");
        assert_eq!(event.from, "123@s.whatsapp.net");
        assert_eq!(event.event_type, "offer");
        assert_eq!(event.call_id.as_deref(), Some("call-1"));
        assert_eq!(event.participant.as_deref(), Some("456@s.whatsapp.net"));
        assert_eq!(event.timestamp, Some(1_700_000_007));
        assert_eq!(event.fields["call-creator"], "123@s.whatsapp.net");
        assert_eq!(event.fields["child_audio"], "true");
    }

    #[test]
    fn maps_call_offer_and_relay_latency_metadata() {
        let call = BinaryNode::new("call")
            .with_attr("id", "call-stanza-2")
            .with_attr("from", "123@g.us")
            .with_attr("participant", "456@s.whatsapp.net")
            .with_attr("t", "1700000007")
            .with_attr("offline", "1")
            .with_content(vec![
                BinaryNode::new("offer")
                    .with_attr("call-id", "call-2")
                    .with_attr("from", "456@s.whatsapp.net")
                    .with_attr("caller_pn", "456@s.whatsapp.net")
                    .with_attr("type", "group")
                    .with_attr("group-jid", "123@g.us")
                    .with_content(vec![BinaryNode::new("video")]),
                BinaryNode::new("relaylatency")
                    .with_attr("call-id", "call-2")
                    .with_attr("call-creator", "456@s.whatsapp.net")
                    .with_attr("latency-ms", "321"),
            ]);

        let events = call_events_from_node(&call).unwrap();
        assert_eq!(events.len(), 2);
        let offer = &events[0];
        assert_eq!(offer.event_type, "offer");
        assert_eq!(offer.fields["offline"], "true");
        assert_eq!(offer.fields["call_from"], "456@s.whatsapp.net");
        assert_eq!(offer.fields["caller_pn"], "456@s.whatsapp.net");
        assert_eq!(offer.fields["is_video"], "true");
        assert_eq!(offer.fields["is_group"], "true");
        assert_eq!(offer.fields["group_jid"], "123@g.us");

        let latency = &events[1];
        assert_eq!(latency.event_type, "relaylatency");
        assert_eq!(latency.fields["call_from"], "456@s.whatsapp.net");
        assert_eq!(latency.fields["latency_ms"], "321");
    }

    #[test]
    fn maps_presence_nodes_to_typed_events() {
        let presence = BinaryNode::new("presence")
            .with_attr("from", "123@g.us")
            .with_attr("participant", "456@s.whatsapp.net")
            .with_attr("type", "available")
            .with_attr("last", "1700000006")
            .with_attr("name", "Alice")
            .with_content(vec![
                BinaryNode::new("composing").with_attr("media", "text"),
            ]);

        let event = presence_event_from_node(&presence).unwrap().unwrap();
        assert_eq!(event.jid, "123@g.us");
        assert_eq!(event.participant.as_deref(), Some("456@s.whatsapp.net"));
        assert_eq!(event.presence_type, "available");
        assert_eq!(event.timestamp, Some(1_700_000_006));
        assert_eq!(event.fields["last"], "1700000006");
        assert_eq!(event.fields["name"], "Alice");
        assert_eq!(event.fields["child_composing"], "true");
        assert_eq!(event.fields["child_composing_media"], "text");

        let child_type = BinaryNode::new("presence")
            .with_attr("from", "123@s.whatsapp.net")
            .with_content(vec![BinaryNode::new("unavailable")]);
        assert_eq!(
            presence_event_from_node(&child_type)
                .unwrap()
                .unwrap()
                .presence_type,
            "unavailable"
        );

        let subscribe = BinaryNode::new("presence")
            .with_attr("from", "123@s.whatsapp.net")
            .with_attr("type", "subscribe");
        assert!(presence_event_from_node(&subscribe).unwrap().is_none());

        let invalid = BinaryNode::new("presence").with_attr("from", "not-a-jid");
        assert!(presence_event_from_node(&invalid).is_err());
    }

    #[test]
    fn maps_chatstate_nodes_to_typed_presence_events() {
        let recording = BinaryNode::new("chatstate")
            .with_attr("from", "123@g.us")
            .with_attr("to", "999@s.whatsapp.net")
            .with_attr("participant", "456@s.whatsapp.net")
            .with_attr("t", "1700000008")
            .with_content(vec![
                BinaryNode::new("composing").with_attr("media", "audio"),
            ]);

        let event = presence_event_from_node(&recording).unwrap().unwrap();
        assert_eq!(event.jid, "123@g.us");
        assert_eq!(event.participant.as_deref(), Some("456@s.whatsapp.net"));
        assert_eq!(event.presence_type, "recording");
        assert_eq!(event.timestamp, Some(1_700_000_008));
        assert_eq!(event.fields["to"], "999@s.whatsapp.net");
        assert_eq!(event.fields["child_composing"], "true");
        assert_eq!(event.fields["child_composing_media"], "audio");

        let paused = BinaryNode::new("chatstate")
            .with_attr("from", "123@s.whatsapp.net")
            .with_content(vec![BinaryNode::new("paused")]);
        assert_eq!(
            presence_event_from_node(&paused)
                .unwrap()
                .unwrap()
                .presence_type,
            "paused"
        );
    }

    #[tokio::test]
    async fn processes_presence_node_to_typed_event_without_ack() {
        let presence = BinaryNode::new("presence")
            .with_attr("from", "123@s.whatsapp.net")
            .with_attr("type", "available")
            .with_attr("t", "1700000007");
        let mut buffer = test_buffer();

        let result = process_inbound_node(
            &presence,
            "999@s.whatsapp.net",
            None,
            Some("999@s.whatsapp.net"),
            &PassthroughDecryptor,
            &mut buffer,
        )
        .await
        .unwrap();

        assert_eq!(result.action, InboundNodeAction::Presence);
        assert_eq!(result.event_count, 1);
        assert!(result.response.is_none());
        assert!(result.error.is_none());

        let batch = buffer.flush().unwrap();
        assert_eq!(batch.presence_update.len(), 1);
        assert_eq!(batch.presence_update[0].jid, "123@s.whatsapp.net");
        assert_eq!(batch.presence_update[0].presence_type, "available");
        assert_eq!(batch.presence_update[0].timestamp, Some(1_700_000_007));
    }

    #[tokio::test]
    async fn processes_chatstate_node_to_typed_presence_event_without_ack() {
        let chatstate = BinaryNode::new("chatstate")
            .with_attr("from", "123@g.us")
            .with_attr("to", "999@s.whatsapp.net")
            .with_attr("participant", "456@s.whatsapp.net")
            .with_content(vec![
                BinaryNode::new("composing").with_attr("media", "audio"),
            ]);
        let mut buffer = test_buffer();

        let result = process_inbound_node(
            &chatstate,
            "999@s.whatsapp.net",
            None,
            Some("999@s.whatsapp.net"),
            &PassthroughDecryptor,
            &mut buffer,
        )
        .await
        .unwrap();

        assert_eq!(result.action, InboundNodeAction::Presence);
        assert_eq!(result.event_count, 1);
        assert!(result.response.is_none());
        assert!(result.error.is_none());

        let batch = buffer.flush().unwrap();
        assert_eq!(batch.presence_update.len(), 1);
        assert_eq!(batch.presence_update[0].jid, "123@g.us");
        assert_eq!(
            batch.presence_update[0].participant.as_deref(),
            Some("456@s.whatsapp.net")
        );
        assert_eq!(batch.presence_update[0].presence_type, "recording");
    }

    #[test]
    fn maps_call_events_to_missed_and_group_call_message_events() {
        let call = BinaryNode::new("call")
            .with_attr("id", "call-stanza-3")
            .with_attr("from", "123@g.us")
            .with_attr("t", "1700000008")
            .with_attr("offline", "1")
            .with_content(vec![
                BinaryNode::new("offer")
                    .with_attr("call-id", "call-3")
                    .with_attr("from", "456@s.whatsapp.net")
                    .with_attr("caller_pn", "456@s.whatsapp.net")
                    .with_attr("type", "group")
                    .with_content(vec![BinaryNode::new("video")]),
            ]);
        let mut calls = call_events_from_node(&call).unwrap();
        calls.push(
            CallEvent::new("call-timeout-stanza", "123@g.us", "timeout")
                .with_call_id("call-3")
                .with_timestamp(1_700_000_009)
                .with_field("is_video", "true")
                .with_field("is_group", "true")
                .with_field("offline", "true")
                .with_field("caller_pn", "456@s.whatsapp.net"),
        );

        let messages = call_message_events_from_call_events(&calls).unwrap();
        assert_eq!(messages.len(), 2);

        let offer = &messages[0];
        assert_eq!(offer.key.remote_jid, "123@g.us");
        assert_eq!(offer.key.id, "call-3");
        assert_eq!(offer.timestamp, Some(1_700_000_008));
        assert_eq!(offer.fields["kind"], "append");
        assert_eq!(offer.fields["source"], "call_event");
        assert_eq!(offer.fields["call_status"], "offer");
        assert_eq!(offer.fields["payload_kind"], "call");
        let decoded = Message::decode(offer.payload.clone().unwrap()).unwrap();
        assert_eq!(
            decoded.call.unwrap().call_key.as_deref(),
            Some(b"call-3".as_slice())
        );

        let missed = &messages[1];
        assert_eq!(missed.key.remote_jid, "123@g.us");
        assert_eq!(missed.key.id, "call-3");
        assert_eq!(missed.timestamp, Some(1_700_000_009));
        assert_eq!(missed.fields["kind"], "append");
        assert_eq!(missed.fields["call_status"], "timeout");
        assert_eq!(
            missed.fields["message_stub_type"],
            (StubType::CallMissedGroupVideo as i32).to_string()
        );
        assert_eq!(missed.fields["stub_type"], "call_missed_group_video");
        assert!(missed.payload.is_none());
    }

    #[test]
    fn maps_account_update_notifications_to_typed_events() {
        let reachout = BinaryNode::new("notification")
            .with_attr("id", "n1")
            .with_attr("from", "123@s.whatsapp.net")
            .with_content(vec![BinaryNode::new("update")
                .with_attr("op_name", "NotificationUserReachoutTimelockUpdate")
                .with_content(
                    br#"{"data":{"xwa2_notify_account_reachout_timelock":{"is_active":true,"enforcement_type":"WEB_COMPANION_ONLY"}}}"#.to_vec(),
                )]);
        let event = account_update_event_from_notification_node(&reachout, 1_000)
            .unwrap()
            .unwrap();
        assert_eq!(
            event,
            Event::ReachoutTimelockUpdate(crate::ReachoutTimelockState {
                is_active: true,
                time_enforcement_ends: Some(1_060),
                enforcement_type: crate::ReachoutTimelockEnforcementType::WebCompanionOnly,
            })
        );

        let capping = BinaryNode::new("notification")
            .with_attr("id", "n2")
            .with_attr("from", "123@s.whatsapp.net")
            .with_content(vec![BinaryNode::new("update")
                .with_attr("op_name", "MessageCappingInfoNotification")
                .with_content(
                    br#"{"data":{"xwa2_notify_new_chat_messages_capping_info_update":{"total_quota":"10","used_quota":"8","capping_status":"SECOND_WARNING"}}}"#.to_vec(),
                )]);
        let event = account_update_event_from_notification_node(&capping, 1_000)
            .unwrap()
            .unwrap();
        assert_eq!(
            event,
            Event::MessageCappingUpdate(crate::MessageCappingInfo {
                total_quota: Some(10),
                used_quota: Some(8),
                capping_status: Some(crate::MessageCappingStatus::SecondWarning),
                ..crate::MessageCappingInfo::default()
            })
        );
    }

    #[test]
    fn maps_account_sync_blocklist_notifications_to_typed_events() {
        let notification = BinaryNode::new("notification")
            .with_attr("id", "blocklist-1")
            .with_attr("from", "server@s.whatsapp.net")
            .with_attr("type", "account_sync")
            .with_content(vec![BinaryNode::new("blocklist").with_content(vec![
                BinaryNode::new("item")
                    .with_attr("jid", "111@s.whatsapp.net")
                    .with_attr("action", "block"),
                BinaryNode::new("item")
                    .with_attr("jid", "222@lid")
                    .with_attr("action", "unblock"),
            ])]);
        let parsed = parse_inbound_notification(&notification).unwrap();
        let events =
            blocklist_update_events_from_notification_node(&notification, &parsed).unwrap();

        assert_eq!(
            events,
            vec![
                BlocklistUpdateEvent::new("111@s.whatsapp.net", BlocklistAction::Block),
                BlocklistUpdateEvent::new("222@lid", BlocklistAction::Unblock),
            ]
        );

        let remove_alias = BinaryNode::new("notification")
            .with_attr("id", "blocklist-remove")
            .with_attr("from", "server@s.whatsapp.net")
            .with_attr("type", "account_sync")
            .with_content(vec![BinaryNode::new("blocklist").with_content(vec![
                BinaryNode::new("item")
                    .with_attr("jid", "333@lid")
                    .with_attr("action", "remove"),
            ])]);
        let parsed = parse_inbound_notification(&remove_alias).unwrap();
        let events =
            blocklist_update_events_from_notification_node(&remove_alias, &parsed).unwrap();
        assert_eq!(
            events,
            vec![BlocklistUpdateEvent::new(
                "333@lid",
                BlocklistAction::Unblock
            )]
        );

        let invalid_jid = BinaryNode::new("notification")
            .with_attr("id", "blocklist-invalid")
            .with_attr("from", "server@s.whatsapp.net")
            .with_attr("type", "account_sync")
            .with_content(vec![BinaryNode::new("blocklist").with_content(vec![
                BinaryNode::new("item")
                    .with_attr("jid", "not-a-jid")
                    .with_attr("action", "block"),
            ])]);
        let parsed = parse_inbound_notification(&invalid_jid).unwrap();
        assert!(blocklist_update_events_from_notification_node(&invalid_jid, &parsed).is_err());

        let unrelated = BinaryNode::new("notification")
            .with_attr("id", "blocklist-unrelated")
            .with_attr("from", "server@s.whatsapp.net")
            .with_attr("type", "devices")
            .with_content(vec![BinaryNode::new("blocklist")]);
        let parsed = parse_inbound_notification(&unrelated).unwrap();
        assert!(
            blocklist_update_events_from_notification_node(&unrelated, &parsed)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn maps_account_sync_disappearing_mode_notifications_to_typed_events() {
        let notification = BinaryNode::new("notification")
            .with_attr("id", "disappearing-mode-1")
            .with_attr("from", "server@s.whatsapp.net")
            .with_attr("type", "account_sync")
            .with_content(vec![
                BinaryNode::new("disappearing_mode")
                    .with_attr("duration", "604800")
                    .with_attr("t", "1700000000"),
            ]);
        let parsed = parse_inbound_notification(&notification).unwrap();
        let mode = default_disappearing_mode_from_notification_node(&notification, &parsed)
            .unwrap()
            .unwrap();
        assert_eq!(
            mode,
            DefaultDisappearingMode::new(604_800).with_timestamp(1_700_000_000)
        );

        let invalid_duration = BinaryNode::new("notification")
            .with_attr("id", "disappearing-mode-invalid")
            .with_attr("from", "server@s.whatsapp.net")
            .with_attr("type", "account_sync")
            .with_content(vec![
                BinaryNode::new("disappearing_mode").with_attr("duration", "not-a-number"),
            ]);
        let parsed = parse_inbound_notification(&invalid_duration).unwrap();
        assert!(
            default_disappearing_mode_from_notification_node(&invalid_duration, &parsed).is_err()
        );

        let unrelated = BinaryNode::new("notification")
            .with_attr("id", "disappearing-mode-unrelated")
            .with_attr("from", "server@s.whatsapp.net")
            .with_attr("type", "devices")
            .with_content(vec![
                BinaryNode::new("disappearing_mode").with_attr("duration", "604800"),
            ]);
        let parsed = parse_inbound_notification(&unrelated).unwrap();
        assert!(
            default_disappearing_mode_from_notification_node(&unrelated, &parsed)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn maps_server_sync_notifications_to_app_state_collections() {
        let notification = BinaryNode::new("notification")
            .with_attr("id", "server-sync-1")
            .with_attr("from", "server@s.whatsapp.net")
            .with_attr("type", "server_sync")
            .with_content(vec![
                BinaryNode::new("collection").with_attr("name", "regular"),
                BinaryNode::new("collection").with_attr("name", "regular_low"),
                BinaryNode::new("collection").with_attr("name", "regular"),
            ]);
        let parsed = parse_inbound_notification(&notification).unwrap();
        let collections =
            server_sync_collections_from_notification_node(&notification, &parsed).unwrap();
        assert_eq!(
            collections,
            vec![AppStateCollection::Regular, AppStateCollection::RegularLow]
        );
        assert!(
            business_notification_events_from_notification_node(&notification, &parsed)
                .unwrap()
                .is_empty()
        );

        let invalid_collection = BinaryNode::new("notification")
            .with_attr("id", "server-sync-invalid")
            .with_attr("from", "server@s.whatsapp.net")
            .with_attr("type", "server_sync")
            .with_content(vec![
                BinaryNode::new("collection").with_attr("name", "not-a-collection"),
            ]);
        let parsed = parse_inbound_notification(&invalid_collection).unwrap();
        assert_eq!(
            server_sync_collections_from_notification_node(&invalid_collection, &parsed)
                .unwrap_err()
                .to_string(),
            "protocol error: unknown app-state collection: not-a-collection"
        );

        let unrelated = BinaryNode::new("notification")
            .with_attr("id", "server-sync-unrelated")
            .with_attr("from", "server@s.whatsapp.net")
            .with_attr("type", "account_sync")
            .with_content(vec![
                BinaryNode::new("collection").with_attr("name", "regular"),
            ]);
        let parsed = parse_inbound_notification(&unrelated).unwrap();
        assert!(
            server_sync_collections_from_notification_node(&unrelated, &parsed)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn maps_newsletter_linked_profile_notifications_to_lid_mapping_events() {
        let notification = BinaryNode::new("notification")
            .with_attr("id", "n-linked")
            .with_attr("from", "server@s.whatsapp.net")
            .with_attr("type", "mex")
            .with_content(vec![BinaryNode::new("update")
                .with_attr("op_name", "NotificationLinkedProfilesUpdates")
                .with_content(
                    br#"{"data":{"xwa2_notify_linked_profiles":{"jid":"abc@lid","added_profiles":[{"pn":"123@s.whatsapp.net"},"456@c.us"]}}}"#.to_vec(),
                )]);
        let mappings = lid_mapping_events_from_newsletter_notification_node(&notification).unwrap();
        assert_eq!(
            mappings,
            vec![
                LidMappingEvent::new("abc@lid", "123@s.whatsapp.net"),
                LidMappingEvent::new("abc@lid", "456@s.whatsapp.net"),
            ]
        );
    }

    #[tokio::test]
    async fn processes_account_update_notification_to_typed_event_and_ack() {
        let notification = BinaryNode::new("notification")
            .with_attr("id", "n1")
            .with_attr("from", "123@s.whatsapp.net")
            .with_attr("type", "mex")
            .with_content(vec![BinaryNode::new("update")
                .with_attr("op_name", "MessageCappingInfoNotification")
                .with_content(
                    br#"{"data":{"xwa2_notify_new_chat_messages_capping_info_update":{"total_quota":10,"used_quota":9,"capping_status":"CAPPED"}}}"#.to_vec(),
                )]);
        let mut buffer = test_buffer();

        let result = process_inbound_node(
            &notification,
            "999@s.whatsapp.net",
            None,
            Some("999@s.whatsapp.net"),
            &PassthroughDecryptor,
            &mut buffer,
        )
        .await
        .unwrap();

        assert_eq!(result.action, InboundNodeAction::Notification);
        assert_eq!(result.event_count, 2);
        assert!(result.error.is_none());
        let ack = result.response.unwrap();
        assert_eq!(ack.tag, "ack");
        assert_eq!(ack.attrs["class"], "notification");
        assert_eq!(ack.attrs["to"], "123@s.whatsapp.net");

        let events = buffer.drain_events();
        assert_eq!(events.len(), 2);
        assert!(matches!(&events[0], Event::Node(node) if node == &notification));
        assert!(matches!(
            &events[1],
            Event::MessageCappingUpdate(info)
                if info.total_quota == Some(10)
                    && info.used_quota == Some(9)
                    && info.capping_status == Some(crate::MessageCappingStatus::Capped)
        ));
    }

    #[tokio::test]
    async fn processes_account_sync_blocklist_notification_to_typed_event_and_ack() {
        let notification = BinaryNode::new("notification")
            .with_attr("id", "blocklist-sync-1")
            .with_attr("from", "server@s.whatsapp.net")
            .with_attr("type", "account_sync")
            .with_content(vec![BinaryNode::new("blocklist").with_content(vec![
                BinaryNode::new("item")
                    .with_attr("jid", "111@s.whatsapp.net")
                    .with_attr("action", "block"),
                BinaryNode::new("item")
                    .with_attr("jid", "222@lid")
                    .with_attr("action", "unblock"),
            ])]);
        let mut buffer = test_buffer();

        let result = process_inbound_node(
            &notification,
            "999@s.whatsapp.net",
            None,
            Some("999@s.whatsapp.net"),
            &PassthroughDecryptor,
            &mut buffer,
        )
        .await
        .unwrap();

        assert_eq!(result.action, InboundNodeAction::Notification);
        assert_eq!(result.event_count, 3);
        assert!(result.error.is_none());
        let ack = result.response.unwrap();
        assert_eq!(ack.tag, "ack");
        assert_eq!(ack.attrs["class"], "notification");
        assert_eq!(ack.attrs["to"], "server@s.whatsapp.net");

        let events = buffer.drain_events();
        assert_eq!(events.len(), 2);
        assert!(matches!(&events[0], Event::Node(node) if node == &notification));
        assert_eq!(
            events[1],
            Event::BlocklistUpdate(vec![
                BlocklistUpdateEvent::new("111@s.whatsapp.net", BlocklistAction::Block),
                BlocklistUpdateEvent::new("222@lid", BlocklistAction::Unblock),
            ])
        );
    }

    #[tokio::test]
    async fn processes_account_sync_disappearing_mode_notification_to_typed_event_and_ack() {
        let notification = BinaryNode::new("notification")
            .with_attr("id", "disappearing-sync-1")
            .with_attr("from", "server@s.whatsapp.net")
            .with_attr("type", "account_sync")
            .with_content(vec![
                BinaryNode::new("disappearing_mode")
                    .with_attr("duration", "86400")
                    .with_attr("t", "1700000001"),
            ]);
        let mut buffer = test_buffer();

        let result = process_inbound_node(
            &notification,
            "999@s.whatsapp.net",
            None,
            Some("999@s.whatsapp.net"),
            &PassthroughDecryptor,
            &mut buffer,
        )
        .await
        .unwrap();

        assert_eq!(result.action, InboundNodeAction::Notification);
        assert_eq!(result.event_count, 2);
        assert!(result.error.is_none());
        let ack = result.response.unwrap();
        assert_eq!(ack.tag, "ack");
        assert_eq!(ack.attrs["class"], "notification");
        assert_eq!(ack.attrs["to"], "server@s.whatsapp.net");

        let events = buffer.drain_events();
        assert_eq!(events.len(), 2);
        assert!(matches!(&events[0], Event::Node(node) if node == &notification));
        assert_eq!(
            events[1],
            Event::DefaultDisappearingModeUpdate(
                DefaultDisappearingMode::new(86_400).with_timestamp(1_700_000_001)
            )
        );
    }

    #[tokio::test]
    async fn processes_server_sync_notification_to_collections_event_and_ack() {
        let notification = BinaryNode::new("notification")
            .with_attr("id", "server-sync-1")
            .with_attr("from", "server@s.whatsapp.net")
            .with_attr("type", "server_sync")
            .with_content(vec![
                BinaryNode::new("collection").with_attr("name", "regular"),
                BinaryNode::new("collection").with_attr("name", "critical_block"),
                BinaryNode::new("collection").with_attr("name", "regular"),
            ]);
        let mut buffer = test_buffer();

        let result = process_inbound_node(
            &notification,
            "999@s.whatsapp.net",
            None,
            Some("999@s.whatsapp.net"),
            &PassthroughDecryptor,
            &mut buffer,
        )
        .await
        .unwrap();

        assert_eq!(result.action, InboundNodeAction::Notification);
        assert_eq!(result.event_count, 3);
        assert!(result.error.is_none());
        let ack = result.response.unwrap();
        assert_eq!(ack.tag, "ack");
        assert_eq!(ack.attrs["class"], "notification");
        assert_eq!(ack.attrs["to"], "server@s.whatsapp.net");

        let events = buffer.drain_events();
        assert_eq!(events.len(), 2);
        assert!(matches!(&events[0], Event::Node(node) if node == &notification));
        assert_eq!(
            events[1],
            Event::ServerSyncCollections(vec![
                AppStateCollection::Regular,
                AppStateCollection::CriticalBlock,
            ])
        );
    }

    #[tokio::test]
    async fn processes_newsletter_linked_profile_notification_to_typed_event_and_ack() {
        let notification = BinaryNode::new("notification")
            .with_attr("id", "n-linked")
            .with_attr("from", "server@s.whatsapp.net")
            .with_attr("type", "mex")
            .with_content(vec![BinaryNode::new("update")
                .with_attr("op_name", "NotificationLinkedProfilesUpdates")
                .with_content(
                    br#"{"data":{"xwa2_notify_linked_profiles":{"jid":"abc@lid","added_profiles":[{"pn":"123@s.whatsapp.net"}]}}}"#.to_vec(),
                )]);
        let mut buffer = test_buffer();

        let result = process_inbound_node(
            &notification,
            "999@s.whatsapp.net",
            None,
            Some("999@s.whatsapp.net"),
            &PassthroughDecryptor,
            &mut buffer,
        )
        .await
        .unwrap();

        assert_eq!(result.action, InboundNodeAction::Notification);
        assert_eq!(result.event_count, 2);
        assert!(result.error.is_none());
        let ack = result.response.unwrap();
        assert_eq!(ack.tag, "ack");
        assert_eq!(ack.attrs["class"], "notification");
        assert_eq!(ack.attrs["to"], "server@s.whatsapp.net");

        let events = buffer.drain_events();
        assert_eq!(events.len(), 2);
        assert!(matches!(&events[0], Event::Node(node) if node == &notification));
        assert!(matches!(
            &events[1],
            Event::LidMappingUpdate(mappings)
                if mappings == &vec![LidMappingEvent::new("abc@lid", "123@s.whatsapp.net")]
        ));
    }

    #[test]
    fn maps_business_notifications_to_typed_events() {
        let notification = BinaryNode::new("notification")
            .with_attr("id", "biz-1")
            .with_attr("from", "server@s.whatsapp.net")
            .with_attr("type", "business")
            .with_attr("participant", "111@s.whatsapp.net")
            .with_attr("participant_pn", "111@s.whatsapp.net")
            .with_attr("participant_username", "actor-one")
            .with_attr("t", "1700000010")
            .with_content(vec![
                BinaryNode::new("business_profile")
                    .with_attr("version", "3")
                    .with_content(vec![
                        BinaryNode::new("profile")
                            .with_attr("jid", "222@s.whatsapp.net")
                            .with_content(vec![
                                BinaryNode::new("description").with_content("Open daily"),
                            ]),
                    ]),
                BinaryNode::new("product_catalog")
                    .with_attr("catalog_id", "cat-1")
                    .with_content(vec![
                        BinaryNode::new("product")
                            .with_attr("id", "sku-1")
                            .with_content(vec![BinaryNode::new("name").with_content("Widget")]),
                    ]),
            ]);
        let parsed = parse_inbound_notification(&notification).unwrap();
        let events =
            business_notification_events_from_notification_node(&notification, &parsed).unwrap();

        assert_eq!(events.len(), 2);
        assert_eq!(events[0].from, "server@s.whatsapp.net");
        assert_eq!(events[0].notification_id, "biz-1");
        assert_eq!(events[0].event_type, "business_profile");
        assert_eq!(events[0].fields["notification_type"], "business");
        assert_eq!(events[0].fields["timestamp"], "1700000010");
        assert_eq!(events[0].fields["actor"], "111@s.whatsapp.net");
        assert_eq!(events[0].fields["actor_pn"], "111@s.whatsapp.net");
        assert_eq!(events[0].fields["actor_username"], "actor-one");
        assert_eq!(events[0].fields["attr_version"], "3");
        assert_eq!(events[0].fields["child_profile_jid"], "222@s.whatsapp.net");
        assert_eq!(
            events[0].fields["child_profile_child_description_text"],
            "Open daily"
        );
        assert_eq!(events[1].event_type, "product_catalog");
        assert_eq!(events[1].fields["actor_pn"], "111@s.whatsapp.net");
        assert_eq!(events[1].fields["actor_username"], "actor-one");
        assert_eq!(events[1].fields["attr_catalog_id"], "cat-1");
        assert_eq!(events[1].fields["child_product_id"], "sku-1");
        assert_eq!(events[1].fields["child_product_child_name_text"], "Widget");

        let alias_notification = BinaryNode::new("notification")
            .with_attr("id", "biz-alias-children")
            .with_attr("from", "server@s.whatsapp.net")
            .with_attr("type", "business")
            .with_attr("participant", "111@lid")
            .with_attr("phoneNumber", "111@s.whatsapp.net")
            .with_attr("senderUsername", "actor-two")
            .with_attr("t", "1700000011")
            .with_content(vec![
                BinaryNode::new("business_profile_update")
                    .with_attr("profile-id", "profile-1")
                    .with_content(vec![
                        BinaryNode::new("profile").with_attr("jid", "222@s.whatsapp.net"),
                    ]),
                BinaryNode::new("product_catalog_update")
                    .with_attr("catalog-id", "cat-2")
                    .with_content(vec![
                        BinaryNode::new("product")
                            .with_attr("id", "sku-2")
                            .with_attr("retailer-id", "ret-2")
                            .with_content(vec![
                                BinaryNode::new("name").with_content("Alias Widget"),
                            ]),
                    ]),
                BinaryNode::new("collection_update")
                    .with_attr("collection-id", "featured")
                    .with_content(vec![
                        BinaryNode::new("collection")
                            .with_attr("id", "featured")
                            .with_content(vec![BinaryNode::new("name").with_content("Featured")]),
                    ]),
                BinaryNode::new("order_status_update")
                    .with_attr("order-id", "order-1")
                    .with_attr("status", "shipped")
                    .with_content(vec![BinaryNode::new("note").with_content("Packed")]),
                BinaryNode::new("cart_update")
                    .with_attr("cart-id", "cart-1")
                    .with_content(vec![BinaryNode::new("item").with_attr("sku", "sku-2")]),
            ]);
        let parsed = parse_inbound_notification(&alias_notification).unwrap();
        let alias_events =
            business_notification_events_from_notification_node(&alias_notification, &parsed)
                .unwrap();
        assert_eq!(alias_events.len(), 5);
        assert_eq!(alias_events[0].event_type, "business_profile_update");
        assert_eq!(alias_events[0].fields["actor"], "111@lid");
        assert_eq!(alias_events[0].fields["actor_pn"], "111@s.whatsapp.net");
        assert_eq!(alias_events[0].fields["actor_username"], "actor-two");
        assert_eq!(alias_events[0].fields["attr_profile_id"], "profile-1");
        assert_eq!(
            alias_events[0].fields["child_profile_jid"],
            "222@s.whatsapp.net"
        );
        assert_eq!(alias_events[1].event_type, "product_catalog_update");
        assert_eq!(alias_events[1].fields["attr_catalog_id"], "cat-2");
        assert_eq!(alias_events[1].fields["child_product_id"], "sku-2");
        assert_eq!(alias_events[1].fields["child_product_retailer_id"], "ret-2");
        assert_eq!(
            alias_events[1].fields["child_product_child_name_text"],
            "Alias Widget"
        );
        assert_eq!(alias_events[2].event_type, "collection_update");
        assert_eq!(alias_events[2].fields["attr_collection_id"], "featured");
        assert_eq!(alias_events[2].fields["child_collection_id"], "featured");
        assert_eq!(
            alias_events[2].fields["child_collection_child_name_text"],
            "Featured"
        );
        assert_eq!(alias_events[3].event_type, "order_status_update");
        assert_eq!(alias_events[3].fields["attr_order_id"], "order-1");
        assert_eq!(alias_events[3].fields["attr_status"], "shipped");
        assert_eq!(alias_events[3].fields["child_note_text"], "Packed");
        assert_eq!(alias_events[4].event_type, "cart_update");
        assert_eq!(alias_events[4].fields["attr_cart_id"], "cart-1");
        assert_eq!(alias_events[4].fields["child_item_sku"], "sku-2");

        let invalid_actor_pn = BinaryNode::new("notification")
            .with_attr("id", "biz-invalid-actor-pn")
            .with_attr("from", "server@s.whatsapp.net")
            .with_attr("type", "business")
            .with_attr("participant_pn", "not-a-jid")
            .with_content(vec![BinaryNode::new("product_catalog")]);
        let parsed = parse_inbound_notification(&invalid_actor_pn).unwrap();
        assert!(
            business_notification_events_from_notification_node(&invalid_actor_pn, &parsed)
                .is_err()
        );

        let unrelated = BinaryNode::new("notification")
            .with_attr("id", "other")
            .with_attr("from", "server@s.whatsapp.net")
            .with_content(vec![BinaryNode::new("devices")]);
        let parsed = parse_inbound_notification(&unrelated).unwrap();
        assert!(
            business_notification_events_from_notification_node(&unrelated, &parsed)
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn processes_business_notification_to_typed_event_and_ack() {
        let notification = BinaryNode::new("notification")
            .with_attr("id", "biz-2")
            .with_attr("from", "server@s.whatsapp.net")
            .with_attr("type", "business")
            .with_content(vec![
                BinaryNode::new("product_catalog_delete")
                    .with_attr("deleted_count", "2")
                    .with_content(vec![BinaryNode::new("product").with_attr("id", "sku-1")]),
            ]);
        let mut buffer = test_buffer();

        let result = process_inbound_node(
            &notification,
            "999@s.whatsapp.net",
            None,
            Some("999@s.whatsapp.net"),
            &PassthroughDecryptor,
            &mut buffer,
        )
        .await
        .unwrap();

        assert_eq!(result.action, InboundNodeAction::Notification);
        assert_eq!(result.event_count, 2);
        assert!(result.error.is_none());
        let ack = result.response.unwrap();
        assert_eq!(ack.tag, "ack");
        assert_eq!(ack.attrs["class"], "notification");
        assert_eq!(ack.attrs["to"], "server@s.whatsapp.net");

        let events = buffer.drain_events();
        assert_eq!(events.len(), 2);
        assert!(matches!(&events[0], Event::Node(node) if node == &notification));
        let Event::Batch(batch) = &events[1] else {
            panic!("expected business notification batch");
        };
        assert_eq!(batch.business_notifications.len(), 1);
        assert_eq!(
            batch.business_notifications[0].event_type,
            "product_catalog_delete"
        );
        assert_eq!(
            batch.business_notifications[0].fields["attr_deleted_count"],
            "2"
        );
        assert_eq!(
            batch.business_notifications[0].fields["child_product_id"],
            "sku-1"
        );
    }

    #[tokio::test]
    async fn processes_business_notification_alias_children_to_typed_batch_and_ack() {
        let notification = BinaryNode::new("notification")
            .with_attr("id", "biz-alias-batch")
            .with_attr("from", "server@s.whatsapp.net")
            .with_attr("type", "business")
            .with_attr("participant", "111@lid")
            .with_attr("phoneNumber", "111@s.whatsapp.net")
            .with_content(vec![
                BinaryNode::new("product_catalog_update")
                    .with_attr("catalog-id", "cat-2")
                    .with_content(vec![BinaryNode::new("product").with_attr("id", "sku-2")]),
                BinaryNode::new("cart_update")
                    .with_attr("cart-id", "cart-1")
                    .with_content(vec![BinaryNode::new("item").with_attr("sku", "sku-2")]),
            ]);
        let mut buffer = test_buffer();

        let result = process_inbound_node(
            &notification,
            "999@s.whatsapp.net",
            None,
            Some("999@s.whatsapp.net"),
            &PassthroughDecryptor,
            &mut buffer,
        )
        .await
        .unwrap();

        assert_eq!(result.action, InboundNodeAction::Notification);
        assert_eq!(result.event_count, 3);
        assert!(result.error.is_none());
        let ack = result.response.unwrap();
        assert_eq!(ack.tag, "ack");
        assert_eq!(ack.attrs["class"], "notification");
        assert_eq!(ack.attrs["to"], "server@s.whatsapp.net");

        let events = buffer.drain_events();
        assert_eq!(events.len(), 2);
        assert!(matches!(&events[0], Event::Node(node) if node == &notification));
        let Event::Batch(batch) = &events[1] else {
            panic!("expected business notification batch");
        };
        assert_eq!(batch.business_notifications.len(), 2);
        let product = batch
            .business_notifications
            .iter()
            .find(|event| event.event_type == "product_catalog_update")
            .unwrap();
        assert_eq!(product.fields["actor_pn"], "111@s.whatsapp.net");
        assert_eq!(product.fields["attr_catalog_id"], "cat-2");
        assert_eq!(product.fields["child_product_id"], "sku-2");
        let cart = batch
            .business_notifications
            .iter()
            .find(|event| event.event_type == "cart_update")
            .unwrap();
        assert_eq!(cart.fields["attr_cart_id"], "cart-1");
        assert_eq!(cart.fields["child_item_sku"], "sku-2");
    }

    #[test]
    fn maps_newsletter_mex_settings_and_admin_notifications_to_typed_events() {
        let settings = BinaryNode::new("notification")
            .with_attr("id", "n-settings")
            .with_attr("from", "server@s.whatsapp.net")
            .with_attr("type", "mex")
            .with_content(vec![BinaryNode::new("update")
                .with_attr("op_name", "NotificationNewsletterUpdate")
                .with_content(
                    br#"{"updates":[{"jid":"abc@newsletter","settings":{"name":{"text":"Updates"},"description":"Daily notes"}}]}"#.to_vec(),
                )]);
        let parsed = parse_inbound_notification(&settings).unwrap();
        let events =
            newsletter_mex_update_events_from_notification_node(&settings, &parsed).unwrap();
        assert_eq!(events.len(), 1);
        let Event::NewsletterSettingsUpdate(updates) = &events[0] else {
            panic!("expected newsletter settings update");
        };
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].id, "abc@newsletter");
        assert_eq!(updates[0].fields["name"], "Updates");
        assert_eq!(updates[0].fields["description"], "Daily notes");

        let promote =
            BinaryNode::new("notification")
                .with_attr("id", "n-promote")
                .with_attr("from", "server@s.whatsapp.net")
                .with_attr("type", "mex")
                .with_content(vec![BinaryNode::new("update")
                .with_attr("op_name", "NotificationNewsletterAdminPromote")
                .with_content(
                    br#"{"updates":[{"jid":"abc@newsletter","user":"222@s.whatsapp.net"}]}"#
                        .to_vec(),
                )]);
        let parsed = parse_inbound_notification(&promote).unwrap();
        let events =
            newsletter_mex_update_events_from_notification_node(&promote, &parsed).unwrap();
        assert_eq!(
            events,
            vec![Event::NewsletterParticipantsUpdate(vec![
                NewsletterParticipantUpdateEvent::new(
                    "abc@newsletter",
                    "server@s.whatsapp.net",
                    "222@s.whatsapp.net",
                    "promote",
                    "ADMIN"
                )
            ])]
        );

        let nested_promote = BinaryNode::new("notification")
            .with_attr("id", "n-promote-nested")
            .with_attr("from", "server@s.whatsapp.net")
            .with_attr("type", "mex")
            .with_content(vec![BinaryNode::new("update").with_content(
                br#"{"data":{"NotificationNewsletterAdminPromote":{"updates":[{"newsletterId":"abc@newsletter","participant_jid":"333@s.whatsapp.net"}]}}}"#.to_vec(),
            )]);
        let parsed = parse_inbound_notification(&nested_promote).unwrap();
        let events =
            newsletter_mex_update_events_from_notification_node(&nested_promote, &parsed).unwrap();
        assert_eq!(
            events,
            vec![Event::NewsletterParticipantsUpdate(vec![
                NewsletterParticipantUpdateEvent::new(
                    "abc@newsletter",
                    "server@s.whatsapp.net",
                    "333@s.whatsapp.net",
                    "promote",
                    "ADMIN"
                )
            ])]
        );
    }

    #[tokio::test]
    async fn processes_newsletter_mex_settings_notification_to_typed_event_and_ack() {
        let notification = BinaryNode::new("notification")
            .with_attr("id", "n-settings")
            .with_attr("from", "server@s.whatsapp.net")
            .with_attr("type", "mex")
            .with_content(vec![BinaryNode::new("update")
                .with_attr("op_name", "NotificationNewsletterUpdate")
                .with_content(
                    br#"{"updates":[{"jid":"abc@newsletter","settings":{"name":{"text":"Updates"},"description":"Daily notes"}}]}"#.to_vec(),
                )]);
        let mut buffer = test_buffer();

        let result = process_inbound_node(
            &notification,
            "999@s.whatsapp.net",
            None,
            Some("999@s.whatsapp.net"),
            &PassthroughDecryptor,
            &mut buffer,
        )
        .await
        .unwrap();

        assert_eq!(result.action, InboundNodeAction::Notification);
        assert_eq!(result.event_count, 2);
        assert!(result.error.is_none());
        let ack = result.response.unwrap();
        assert_eq!(ack.tag, "ack");
        assert_eq!(ack.attrs["class"], "notification");
        assert_eq!(ack.attrs["to"], "server@s.whatsapp.net");

        let events = buffer.drain_events();
        assert_eq!(events.len(), 2);
        assert!(matches!(&events[0], Event::Node(node) if node == &notification));
        let Event::NewsletterSettingsUpdate(updates) = &events[1] else {
            panic!("expected newsletter settings update");
        };
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].id, "abc@newsletter");
        assert_eq!(updates[0].fields["name"], "Updates");
        assert_eq!(updates[0].fields["description"], "Daily notes");
    }

    #[tokio::test]
    async fn processes_newsletter_mex_admin_promote_notification_to_typed_event_and_ack() {
        let notification =
            BinaryNode::new("notification")
                .with_attr("id", "n-promote")
                .with_attr("from", "server@s.whatsapp.net")
                .with_attr("type", "mex")
                .with_content(vec![BinaryNode::new("update")
                .with_attr("op_name", "NotificationNewsletterAdminPromote")
                .with_content(
                    br#"{"updates":[{"jid":"abc@newsletter","user":"222@s.whatsapp.net"}]}"#
                        .to_vec(),
                )]);
        let mut buffer = test_buffer();

        let result = process_inbound_node(
            &notification,
            "999@s.whatsapp.net",
            None,
            Some("999@s.whatsapp.net"),
            &PassthroughDecryptor,
            &mut buffer,
        )
        .await
        .unwrap();

        assert_eq!(result.action, InboundNodeAction::Notification);
        assert_eq!(result.event_count, 2);
        assert!(result.error.is_none());
        let ack = result.response.unwrap();
        assert_eq!(ack.tag, "ack");
        assert_eq!(ack.attrs["class"], "notification");
        assert_eq!(ack.attrs["to"], "server@s.whatsapp.net");

        let events = buffer.drain_events();
        assert_eq!(events.len(), 2);
        assert!(matches!(&events[0], Event::Node(node) if node == &notification));
        assert!(matches!(
            &events[1],
            Event::NewsletterParticipantsUpdate(updates)
                if updates == &vec![NewsletterParticipantUpdateEvent::new(
                    "abc@newsletter",
                    "server@s.whatsapp.net",
                    "222@s.whatsapp.net",
                    "promote",
                    "ADMIN"
                )]
        ));
    }

    #[test]
    fn maps_newsletter_reaction_and_view_notifications_to_typed_events() {
        let notification = BinaryNode::new("notification")
            .with_attr("id", "n-news")
            .with_attr("from", "abc@newsletter")
            .with_attr("participant", "111@s.whatsapp.net")
            .with_attr("type", "newsletter")
            .with_content(vec![
                BinaryNode::new("reaction")
                    .with_attr("message_id", "server-1")
                    .with_content(vec![BinaryNode::new("reaction").with_content("+")]),
                BinaryNode::new("view")
                    .with_attr("message_id", "server-2")
                    .with_content("42"),
                BinaryNode::new("participant")
                    .with_attr("jid", "222@s.whatsapp.net")
                    .with_attr("action", "promote")
                    .with_attr("role", "ADMIN"),
                BinaryNode::new("update").with_content(vec![
                    BinaryNode::new("settings").with_content(vec![
                        BinaryNode::new("name").with_content("Updates"),
                        BinaryNode::new("description").with_content("Daily notes"),
                    ]),
                ]),
                BinaryNode::new("message")
                    .with_attr("message_id", "server-3")
                    .with_attr("t", "1700000000")
                    .with_content(vec![BinaryNode::new("plaintext").with_content(
                        Bytes::from(text_message("newsletter text").encode_to_vec()),
                    )]),
                BinaryNode::new("reaction")
                    .with_attr("server_id", "server-4")
                    .with_content(vec![BinaryNode::new("reaction").with_attr("code", "!")]),
                BinaryNode::new("view")
                    .with_attr("server_id", "server-5")
                    .with_attr("count", "99"),
            ]);
        let parsed = parse_inbound_notification(&notification).unwrap();
        let events =
            newsletter_update_events_from_notification_node(&notification, &parsed).unwrap();

        assert_eq!(events.len(), 7);
        assert!(matches!(
            &events[0],
            Event::NewsletterReactionUpdate(updates)
                if updates == &vec![NewsletterReactionEvent::new("abc@newsletter", "server-1")
                    .with_code("+")
                    .with_count(1)]
        ));
        assert!(matches!(
            &events[1],
            Event::NewsletterViewUpdate(updates)
                if updates == &vec![NewsletterViewEvent::new("abc@newsletter", "server-2", 42)]
        ));
        assert!(matches!(
            &events[2],
            Event::NewsletterParticipantsUpdate(updates)
                if updates == &vec![NewsletterParticipantUpdateEvent::new(
                    "abc@newsletter",
                    "111@s.whatsapp.net",
                    "222@s.whatsapp.net",
                    "promote",
                    "ADMIN"
                )]
        ));
        let Event::NewsletterSettingsUpdate(updates) = &events[3] else {
            panic!("expected newsletter settings update");
        };
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].id, "abc@newsletter");
        assert_eq!(updates[0].fields["name"], "Updates");
        assert_eq!(updates[0].fields["description"], "Daily notes");
        let Event::MessagesUpsert(messages) = &events[4] else {
            panic!("expected newsletter message upsert");
        };
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].key.remote_jid, "abc@newsletter");
        assert_eq!(messages[0].key.id, "server-3");
        assert_eq!(messages[0].timestamp, Some(1_700_000_000));
        assert_eq!(messages[0].fields["kind"], "newsletter");
        assert_eq!(messages[0].fields["payload_kind"], "plaintext");
        let decoded = Message::decode(messages[0].payload.clone().unwrap()).unwrap();
        assert_eq!(decoded.conversation.as_deref(), Some("newsletter text"));
        assert!(matches!(
            &events[5],
            Event::NewsletterReactionUpdate(updates)
                if updates == &vec![NewsletterReactionEvent::new("abc@newsletter", "server-4")
                    .with_code("!")
                    .with_count(1)]
        ));
        assert!(matches!(
            &events[6],
            Event::NewsletterViewUpdate(updates)
                if updates == &vec![NewsletterViewEvent::new("abc@newsletter", "server-5", 99)]
        ));

        let non_newsletter = BinaryNode::new("notification")
            .with_attr("id", "n-news")
            .with_attr("from", "123@s.whatsapp.net")
            .with_content(vec![
                BinaryNode::new("view")
                    .with_attr("message_id", "server-2")
                    .with_content("42"),
            ]);
        let parsed = parse_inbound_notification(&non_newsletter).unwrap();
        assert!(
            newsletter_update_events_from_notification_node(&non_newsletter, &parsed)
                .unwrap()
                .is_empty()
        );

        let invalid = BinaryNode::new("notification")
            .with_attr("id", "n-news")
            .with_attr("from", "abc@newsletter")
            .with_content(vec![
                BinaryNode::new("view")
                    .with_attr("message_id", "server-2")
                    .with_content("not-a-number"),
            ]);
        let parsed = parse_inbound_notification(&invalid).unwrap();
        assert!(newsletter_update_events_from_notification_node(&invalid, &parsed).is_err());
    }

    #[tokio::test]
    async fn processes_newsletter_reaction_and_view_notification_to_typed_events_and_ack() {
        let notification = BinaryNode::new("notification")
            .with_attr("id", "n-news")
            .with_attr("from", "abc@newsletter")
            .with_attr("participant", "111@s.whatsapp.net")
            .with_attr("type", "newsletter")
            .with_content(vec![
                BinaryNode::new("reaction")
                    .with_attr("message_id", "server-1")
                    .with_content(vec![BinaryNode::new("reaction").with_content("+")]),
                BinaryNode::new("view")
                    .with_attr("message_id", "server-2")
                    .with_content("42"),
                BinaryNode::new("participant")
                    .with_attr("jid", "222@s.whatsapp.net")
                    .with_attr("action", "promote")
                    .with_attr("role", "ADMIN"),
                BinaryNode::new("update").with_content(vec![
                    BinaryNode::new("settings").with_content(vec![
                        BinaryNode::new("name").with_content("Updates"),
                        BinaryNode::new("description").with_content("Daily notes"),
                    ]),
                ]),
                BinaryNode::new("message")
                    .with_attr("message_id", "server-3")
                    .with_attr("t", "1700000000")
                    .with_content(vec![BinaryNode::new("plaintext").with_content(
                        Bytes::from(text_message("newsletter text").encode_to_vec()),
                    )]),
            ]);
        let mut buffer = test_buffer();

        let result = process_inbound_node(
            &notification,
            "999@s.whatsapp.net",
            None,
            Some("999@s.whatsapp.net"),
            &PassthroughDecryptor,
            &mut buffer,
        )
        .await
        .unwrap();

        assert_eq!(result.action, InboundNodeAction::Notification);
        assert_eq!(result.event_count, 6);
        assert!(result.error.is_none());
        let ack = result.response.unwrap();
        assert_eq!(ack.tag, "ack");
        assert_eq!(ack.attrs["class"], "notification");
        assert_eq!(ack.attrs["to"], "abc@newsletter");
        assert_eq!(ack.attrs["id"], "n-news");

        let events = buffer.drain_events();
        assert_eq!(events.len(), 6);
        assert!(matches!(&events[0], Event::Node(node) if node == &notification));
        assert!(matches!(
            &events[1],
            Event::NewsletterReactionUpdate(updates)
                if updates == &vec![NewsletterReactionEvent::new("abc@newsletter", "server-1")
                    .with_code("+")
                    .with_count(1)]
        ));
        assert!(matches!(
            &events[2],
            Event::NewsletterViewUpdate(updates)
                if updates == &vec![NewsletterViewEvent::new("abc@newsletter", "server-2", 42)]
        ));
        assert!(matches!(
            &events[3],
            Event::NewsletterParticipantsUpdate(updates)
                if updates == &vec![NewsletterParticipantUpdateEvent::new(
                    "abc@newsletter",
                    "111@s.whatsapp.net",
                    "222@s.whatsapp.net",
                    "promote",
                    "ADMIN"
                )]
        ));
        let Event::NewsletterSettingsUpdate(updates) = &events[4] else {
            panic!("expected newsletter settings update");
        };
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].id, "abc@newsletter");
        assert_eq!(updates[0].fields["name"], "Updates");
        assert_eq!(updates[0].fields["description"], "Daily notes");
        let Event::Batch(batch) = &events[5] else {
            panic!("expected newsletter message batch");
        };
        assert_eq!(batch.messages_upsert.len(), 1);
        assert_eq!(batch.messages_upsert[0].key.remote_jid, "abc@newsletter");
        assert_eq!(batch.messages_upsert[0].key.id, "server-3");
        assert_eq!(batch.messages_upsert[0].timestamp, Some(1_700_000_000));
        assert_eq!(batch.messages_upsert[0].fields["kind"], "newsletter");
        assert_eq!(batch.messages_upsert[0].fields["payload_kind"], "plaintext");
        let decoded = Message::decode(batch.messages_upsert[0].payload.clone().unwrap()).unwrap();
        assert_eq!(decoded.conversation.as_deref(), Some("newsletter text"));
    }

    #[test]
    fn maps_group_notification_to_group_update_event() {
        let notification = BinaryNode::new("notification")
            .with_attr("id", "g1")
            .with_attr("from", "123@g.us")
            .with_attr("type", "w:gp2")
            .with_attr("participant", "456@s.whatsapp.net")
            .with_attr("t", "1700000000")
            .with_content(vec![
                BinaryNode::new("subject")
                    .with_attr("participant", "456@s.whatsapp.net")
                    .with_attr("s_t", "1700000001")
                    .with_content("New subject"),
                BinaryNode::new("description")
                    .with_attr("id", "desc-1")
                    .with_attr("participant", "789@s.whatsapp.net")
                    .with_content("New description"),
                BinaryNode::new("announcement"),
                BinaryNode::new("locked"),
                BinaryNode::new("ephemeral").with_attr("expiration", "86400"),
                BinaryNode::new("add").with_content(vec![
                    BinaryNode::new("participant").with_attr("jid", "111@s.whatsapp.net"),
                    BinaryNode::new("participant").with_attr("jid", "222@s.whatsapp.net"),
                ]),
            ]);
        let parsed = parse_inbound_notification(&notification).unwrap();
        let event = group_update_event_from_notification_node(&notification, &parsed)
            .unwrap()
            .unwrap();

        assert_eq!(event.jid, "123@g.us");
        assert_eq!(event.fields["notification_id"], "g1");
        assert_eq!(event.fields["notification_type"], "w:gp2");
        assert_eq!(event.fields["actor"], "456@s.whatsapp.net");
        assert_eq!(event.fields["timestamp"], "1700000000");
        assert_eq!(event.fields["subject"], "New subject");
        assert_eq!(event.fields["subject_owner"], "456@s.whatsapp.net");
        assert_eq!(event.fields["subject_time"], "1700000001");
        assert_eq!(event.fields["description"], "New description");
        assert_eq!(event.fields["description_id"], "desc-1");
        assert_eq!(event.fields["description_owner"], "789@s.whatsapp.net");
        assert_eq!(event.fields["announce"], "true");
        assert_eq!(event.fields["restrict"], "true");
        assert_eq!(event.fields["ephemeral_duration"], "86400");
        assert_eq!(
            event.fields["participants_add"],
            "111@s.whatsapp.net,222@s.whatsapp.net"
        );
        assert_eq!(event.fields["participants_add_count"], "2");

        let non_group = BinaryNode::new("notification")
            .with_attr("id", "n1")
            .with_attr("from", "123@s.whatsapp.net")
            .with_content(vec![BinaryNode::new("subject").with_content("ignored")]);
        let parsed = parse_inbound_notification(&non_group).unwrap();
        assert!(
            group_update_event_from_notification_node(&non_group, &parsed)
                .unwrap()
                .is_none()
        );

        let offline_notification = BinaryNode::new("notification")
            .with_attr("id", "g-offline")
            .with_attr("from", "123@g.us")
            .with_attr("type", "w:gp2")
            .with_attr("participant", "456@s.whatsapp.net")
            .with_attr("offline", "1")
            .with_content(vec![
                BinaryNode::new("ephemeral").with_attr("expiration", "86400"),
            ]);
        let parsed = parse_inbound_notification(&offline_notification).unwrap();
        let event = group_update_event_from_notification_node(&offline_notification, &parsed)
            .unwrap()
            .unwrap();
        assert_eq!(event.fields["offline"], "true");
    }

    #[test]
    fn maps_group_updates_to_group_notification_message_stubs() {
        let notification = BinaryNode::new("notification")
            .with_attr("id", "g-stub-add")
            .with_attr("from", "123@g.us")
            .with_attr("type", "w:gp2")
            .with_attr("participant", "111@s.whatsapp.net")
            .with_attr("t", "1700000000")
            .with_content(vec![BinaryNode::new("add").with_content(vec![
                BinaryNode::new("participant")
                    .with_attr("jid", "222@lid")
                    .with_attr("phone_number", "222@s.whatsapp.net")
                    .with_attr("participant_username", "two")
                    .with_attr("type", "admin"),
            ])]);
        let parsed = parse_inbound_notification(&notification).unwrap();
        let batch = event_batch_from_group_notification_node(&notification, &parsed)
            .unwrap()
            .unwrap();
        let subject = GroupUpdateEvent::new("123@g.us")
            .with_field("notification_id", "g-stub-subject")
            .with_field("notification_type", "w:gp2")
            .with_field("actor", "111@s.whatsapp.net")
            .with_field("timestamp", "1700000001")
            .with_field("subject", "New subject");
        let ephemeral = GroupUpdateEvent::new("123@g.us")
            .with_field("notification_id", "g-stub-ephemeral")
            .with_field("notification_type", "w:gp2")
            .with_field("actor", "111@s.whatsapp.net")
            .with_field("timestamp", "1700000002")
            .with_field("ephemeral_duration", "86400")
            .with_field("offline", "true");
        let invite_notification = BinaryNode::new("notification")
            .with_attr("id", "g-stub-invite")
            .with_attr("from", "123@g.us")
            .with_attr("type", "w:gp2")
            .with_attr("participant", "111@s.whatsapp.net")
            .with_attr("t", "1700000003")
            .with_content(vec![
                BinaryNode::new("invite")
                    .with_attr("code", "invite-code")
                    .with_content(vec![
                        BinaryNode::new("participant").with_attr("jid", "333@s.whatsapp.net"),
                    ]),
            ]);
        let parsed_invite = parse_inbound_notification(&invite_notification).unwrap();
        let invite_batch =
            event_batch_from_group_notification_node(&invite_notification, &parsed_invite)
                .unwrap()
                .unwrap();
        let accept_notification = BinaryNode::new("notification")
            .with_attr("id", "g-stub-accept")
            .with_attr("from", "123@g.us")
            .with_attr("type", "w:gp2")
            .with_attr("participant", "333@lid")
            .with_attr("participant_pn", "333@s.whatsapp.net")
            .with_attr("participantUsername", "three")
            .with_attr("t", "1700000004")
            .with_content(vec![
                BinaryNode::new("accept").with_attr("code", "accepted-code"),
            ]);
        let parsed_accept = parse_inbound_notification(&accept_notification).unwrap();
        let accept_batch =
            event_batch_from_group_notification_node(&accept_notification, &parsed_accept)
                .unwrap()
                .unwrap();
        let revoke_notification = BinaryNode::new("notification")
            .with_attr("id", "g-stub-revoke")
            .with_attr("from", "123@g.us")
            .with_attr("type", "w:gp2")
            .with_attr("participant", "111@s.whatsapp.net")
            .with_attr("t", "1700000005")
            .with_content(vec![
                BinaryNode::new("revoke").with_attr("code", "old-code"),
            ]);
        let parsed_revoke = parse_inbound_notification(&revoke_notification).unwrap();
        let revoke_batch =
            event_batch_from_group_notification_node(&revoke_notification, &parsed_revoke)
                .unwrap()
                .unwrap();
        let mut groups = batch.groups_update.clone();
        groups.push(subject);
        groups.push(ephemeral);
        groups.extend(invite_batch.groups_update);
        groups.extend(accept_batch.groups_update);
        groups.extend(revoke_batch.groups_update);

        let messages = group_message_events_from_group_update_events(&groups).unwrap();

        assert_eq!(messages.len(), 6);
        let add = &messages[0];
        assert_eq!(add.key.remote_jid, "123@g.us");
        assert_eq!(add.key.id, "g-stub-add");
        assert_eq!(add.key.participant.as_deref(), Some("111@s.whatsapp.net"));
        assert_eq!(add.timestamp, Some(1700000000));
        assert_eq!(add.fields["source"], "group_notification");
        assert_eq!(add.fields["kind"], "notify");
        assert_eq!(
            add.fields["message_stub_type"],
            (StubType::GroupParticipantAdd as i32).to_string()
        );
        assert_eq!(add.fields["stub_type"], "group_participant_add");
        let parameters: Vec<String> =
            serde_json::from_str(&add.fields["message_stub_parameters"]).unwrap();
        assert_eq!(parameters.len(), 1);
        let participant: serde_json::Value = serde_json::from_str(&parameters[0]).unwrap();
        assert_eq!(participant["id"], "222@lid");
        assert_eq!(participant["phoneNumber"], "222@s.whatsapp.net");
        assert_eq!(participant["username"], "two");
        assert_eq!(participant["admin"], "admin");

        let subject = &messages[1];
        assert_eq!(subject.key.id, "g-stub-subject");
        assert_eq!(subject.timestamp, Some(1700000001));
        assert_eq!(
            subject.fields["message_stub_type"],
            (StubType::GroupChangeSubject as i32).to_string()
        );
        assert_eq!(subject.fields["stub_type"], "group_change_subject");
        assert_eq!(
            subject.fields["message_stub_parameters"],
            r#"["New subject"]"#
        );

        let ephemeral = &messages[2];
        assert_eq!(ephemeral.key.id, "g-stub-ephemeral");
        assert_eq!(ephemeral.timestamp, Some(1700000002));
        assert_eq!(ephemeral.fields["kind"], "append");
        assert_eq!(ephemeral.fields["offline"], "true");
        assert_eq!(
            ephemeral.fields["message_stub_type"],
            (StubType::ChangeEphemeralSetting as i32).to_string()
        );
        assert_eq!(ephemeral.fields["stub_type"], "change_ephemeral_setting");
        assert_eq!(ephemeral.fields["message_stub_parameters"], r#"["86400"]"#);
        assert_eq!(ephemeral.fields["payload_kind"], "protocol_message");
        let decoded = Message::decode(ephemeral.payload.clone().unwrap()).unwrap();
        let protocol = decoded.protocol_message.unwrap();
        assert_eq!(
            protocol.r#type,
            Some(protocol_message::Type::EphemeralSetting as i32)
        );
        assert_eq!(protocol.ephemeral_expiration, Some(86_400));

        let invite = &messages[3];
        assert_eq!(invite.key.id, "g-stub-invite");
        assert_eq!(invite.timestamp, Some(1700000003));
        assert_eq!(
            invite.fields["message_stub_type"],
            (StubType::GroupParticipantInvite as i32).to_string()
        );
        assert_eq!(invite.fields["stub_type"], "group_participant_invite");
        let parameters: Vec<String> =
            serde_json::from_str(&invite.fields["message_stub_parameters"]).unwrap();
        assert_eq!(parameters, vec![r#"{"id":"333@s.whatsapp.net"}"#]);

        let accept = &messages[4];
        assert_eq!(accept.key.id, "g-stub-accept");
        assert_eq!(accept.timestamp, Some(1700000004));
        assert_eq!(
            accept.fields["message_stub_type"],
            (StubType::GroupParticipantAccept as i32).to_string()
        );
        assert_eq!(accept.fields["stub_type"], "group_participant_accept");
        let parameters: Vec<String> =
            serde_json::from_str(&accept.fields["message_stub_parameters"]).unwrap();
        assert_eq!(parameters.len(), 1);
        let participant: serde_json::Value = serde_json::from_str(&parameters[0]).unwrap();
        assert_eq!(participant["id"], "333@lid");
        assert_eq!(participant["phoneNumber"], "333@s.whatsapp.net");
        assert_eq!(participant["username"], "three");

        let revoke = &messages[5];
        assert_eq!(revoke.key.id, "g-stub-revoke");
        assert_eq!(revoke.timestamp, Some(1700000005));
        assert_eq!(
            revoke.fields["message_stub_type"],
            (StubType::GroupChangeInviteLink as i32).to_string()
        );
        assert_eq!(revoke.fields["stub_type"], "group_change_invite_link");
        assert_eq!(revoke.fields["message_stub_parameters"], r#"["old-code"]"#);
    }

    #[test]
    fn maps_group_membership_request_lifecycle_to_message_stubs() {
        let pending_notification = BinaryNode::new("notification")
            .with_attr("id", "g-stub-membership-request")
            .with_attr("from", "123@g.us")
            .with_attr("type", "w:gp2")
            .with_attr("participant", "111@s.whatsapp.net")
            .with_attr("t", "1700000002")
            .with_content(vec![
                BinaryNode::new("membership_approval_requests").with_content(vec![
                    BinaryNode::new("membership_approval_request")
                        .with_attr("jid", "222@s.whatsapp.net")
                        .with_attr("username", "two")
                        .with_attr("requestMethod", "invite_link")
                        .with_attr("t", "1699999999"),
                ]),
            ]);
        let parsed = parse_inbound_notification(&pending_notification).unwrap();
        let batch = event_batch_from_group_notification_node(&pending_notification, &parsed)
            .unwrap()
            .unwrap();
        let messages = group_message_events_from_group_update_events(&batch.groups_update).unwrap();

        assert_eq!(messages.len(), 1);
        let pending = &messages[0];
        assert_eq!(pending.key.remote_jid, "123@g.us");
        assert_eq!(pending.key.id, "g-stub-membership-request");
        assert_eq!(
            pending.key.participant.as_deref(),
            Some("111@s.whatsapp.net")
        );
        assert_eq!(pending.timestamp, Some(1700000002));
        assert_eq!(
            pending.fields["message_stub_type"],
            (StubType::GroupMembershipJoinApprovalRequest as i32).to_string()
        );
        assert_eq!(
            pending.fields["stub_type"],
            "group_membership_join_approval_request"
        );
        let parameters: Vec<String> =
            serde_json::from_str(&pending.fields["message_stub_parameters"]).unwrap();
        assert_eq!(parameters.len(), 3);
        let participant: serde_json::Value = serde_json::from_str(&parameters[0]).unwrap();
        assert_eq!(participant["pn"], "222@s.whatsapp.net");
        assert_eq!(participant["username"], "two");
        assert_eq!(parameters[1], "requested");
        assert_eq!(parameters[2], "invite_link");

        let created_notification = BinaryNode::new("notification")
            .with_attr("id", "g-stub-membership-created")
            .with_attr("from", "123@g.us")
            .with_attr("type", "w:gp2")
            .with_attr("participant", "111@lid")
            .with_attr("participant_pn", "111@s.whatsapp.net")
            .with_attr("t", "1700000003")
            .with_content(vec![
                BinaryNode::new("created_membership_requests")
                    .with_attr("requestMethod", "non_admin_add")
                    .with_attr("participantUsername", "one"),
            ]);
        let parsed = parse_inbound_notification(&created_notification).unwrap();
        let batch = event_batch_from_group_notification_node(&created_notification, &parsed)
            .unwrap()
            .unwrap();
        let messages = group_message_events_from_group_update_events(&batch.groups_update).unwrap();

        assert_eq!(messages.len(), 1);
        let created = &messages[0];
        assert_eq!(created.key.remote_jid, "123@g.us");
        assert_eq!(created.key.id, "g-stub-membership-created");
        assert_eq!(created.key.participant.as_deref(), Some("111@lid"));
        assert_eq!(created.timestamp, Some(1700000003));
        assert_eq!(
            created.fields["message_stub_type"],
            (StubType::GroupMembershipJoinApprovalRequestNonAdminAdd as i32).to_string()
        );
        assert_eq!(
            created.fields["stub_type"],
            "group_membership_join_approval_request_non_admin_add"
        );
        let parameters: Vec<String> =
            serde_json::from_str(&created.fields["message_stub_parameters"]).unwrap();
        assert_eq!(parameters.len(), 3);
        let participant: serde_json::Value = serde_json::from_str(&parameters[0]).unwrap();
        assert_eq!(participant["lid"], "111@lid");
        assert_eq!(participant["pn"], "111@s.whatsapp.net");
        assert_eq!(participant["username"], "one");
        assert_eq!(parameters[1], "created");
        assert_eq!(parameters[2], "non_admin_add");

        let revoked_notification = BinaryNode::new("notification")
            .with_attr("id", "g-stub-membership-revoked")
            .with_attr("from", "123@g.us")
            .with_attr("type", "w:gp2")
            .with_attr("participant", "222@lid")
            .with_attr("participant_pn", "222@s.whatsapp.net")
            .with_attr("participant_username", "two")
            .with_attr("t", "1700000004")
            .with_content(vec![BinaryNode::new("revoked_membership_requests")]);
        let parsed = parse_inbound_notification(&revoked_notification).unwrap();
        let batch = event_batch_from_group_notification_node(&revoked_notification, &parsed)
            .unwrap()
            .unwrap();
        let messages = group_message_events_from_group_update_events(&batch.groups_update).unwrap();

        assert_eq!(messages.len(), 1);
        let revoked = &messages[0];
        assert_eq!(revoked.key.id, "g-stub-membership-revoked");
        assert_eq!(revoked.timestamp, Some(1700000004));
        let parameters: Vec<String> =
            serde_json::from_str(&revoked.fields["message_stub_parameters"]).unwrap();
        assert_eq!(parameters.len(), 2);
        let participant: serde_json::Value = serde_json::from_str(&parameters[0]).unwrap();
        assert_eq!(participant["lid"], "222@lid");
        assert_eq!(participant["pn"], "222@s.whatsapp.net");
        assert_eq!(participant["username"], "two");
        assert_eq!(parameters[1], "revoked");

        let rejected_notification = BinaryNode::new("notification")
            .with_attr("id", "g-stub-membership-rejected")
            .with_attr("from", "123@g.us")
            .with_attr("type", "w:gp2")
            .with_attr("participant", "222@lid")
            .with_attr("participant_pn", "222@s.whatsapp.net")
            .with_attr("t", "1700000005")
            .with_content(vec![
                BinaryNode::new("revoked_membership_requests").with_content(vec![
                    BinaryNode::new("participant")
                        .with_attr("jid", "333@lid")
                        .with_attr("phone_number", "333@s.whatsapp.net")
                        .with_attr("participant_username", "three"),
                ]),
            ]);
        let parsed = parse_inbound_notification(&rejected_notification).unwrap();
        let batch = event_batch_from_group_notification_node(&rejected_notification, &parsed)
            .unwrap()
            .unwrap();
        let messages = group_message_events_from_group_update_events(&batch.groups_update).unwrap();

        assert_eq!(messages.len(), 1);
        let rejected = &messages[0];
        assert_eq!(rejected.key.id, "g-stub-membership-rejected");
        assert_eq!(rejected.timestamp, Some(1700000005));
        let parameters: Vec<String> =
            serde_json::from_str(&rejected.fields["message_stub_parameters"]).unwrap();
        assert_eq!(parameters.len(), 2);
        let participant: serde_json::Value = serde_json::from_str(&parameters[0]).unwrap();
        assert_eq!(participant["lid"], "333@lid");
        assert_eq!(participant["pn"], "333@s.whatsapp.net");
        assert_eq!(participant["username"], "three");
        assert_eq!(parameters[1], "rejected");
    }

    #[test]
    fn maps_group_notification_actor_alias_metadata() {
        let notification = BinaryNode::new("notification")
            .with_attr("id", "g-actor-aliases")
            .with_attr("from", "123@g.us")
            .with_attr("type", "w:gp2")
            .with_attr("participant", "111@lid")
            .with_attr("participant_pn", "111@s.whatsapp.net")
            .with_attr("participant_username", "actor-one")
            .with_content(vec![
                BinaryNode::new("subject").with_content("Actor aliases"),
            ]);
        let parsed = parse_inbound_notification(&notification).unwrap();
        let event = group_update_event_from_notification_node(&notification, &parsed)
            .unwrap()
            .unwrap();

        assert_eq!(event.fields["actor"], "111@lid");
        assert_eq!(event.fields["actor_pn"], "111@s.whatsapp.net");
        assert_eq!(event.fields["actor_username"], "actor-one");
        assert_eq!(event.fields["subject"], "Actor aliases");

        let sender_aliases = BinaryNode::new("notification")
            .with_attr("id", "g-sender-aliases")
            .with_attr("from", "123@g.us")
            .with_attr("type", "w:gp2")
            .with_attr("sender_pn", "222@s.whatsapp.net")
            .with_attr("sender_username", "actor-two")
            .with_content(vec![BinaryNode::new("announcement")]);
        let parsed = parse_inbound_notification(&sender_aliases).unwrap();
        let event = group_update_event_from_notification_node(&sender_aliases, &parsed)
            .unwrap()
            .unwrap();

        assert_eq!(event.fields["actor_pn"], "222@s.whatsapp.net");
        assert_eq!(event.fields["actor_username"], "actor-two");
        assert!(!event.fields.contains_key("actor"));

        let invalid_actor_pn = BinaryNode::new("notification")
            .with_attr("id", "g-invalid-actor-pn")
            .with_attr("from", "123@g.us")
            .with_attr("type", "w:gp2")
            .with_attr("participant_pn", "not-a-jid")
            .with_content(vec![BinaryNode::new("subject").with_content("bad")]);
        let parsed = parse_inbound_notification(&invalid_actor_pn).unwrap();
        assert!(group_update_event_from_notification_node(&invalid_actor_pn, &parsed).is_err());

        let unknown_with_invalid_alias = BinaryNode::new("notification")
            .with_attr("id", "g-unknown-invalid-actor-pn")
            .with_attr("from", "123@g.us")
            .with_attr("type", "w:gp2")
            .with_attr("participant_pn", "not-a-jid")
            .with_content(vec![BinaryNode::new("unknown")]);
        let parsed = parse_inbound_notification(&unknown_with_invalid_alias).unwrap();
        assert!(
            group_update_event_from_notification_node(&unknown_with_invalid_alias, &parsed)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn maps_group_notification_picture_change_forms() {
        let set_notification = BinaryNode::new("notification")
            .with_attr("id", "g-picture-set")
            .with_attr("from", "123@g.us")
            .with_attr("type", "picture")
            .with_attr("participant", "111@lid")
            .with_attr("participant_pn", "111@s.whatsapp.net")
            .with_attr("participant_username", "actor-one")
            .with_content(vec![
                BinaryNode::new("set")
                    .with_attr("id", "pic-1")
                    .with_attr("hash", "hash-1")
                    .with_attr("author", "111@lid")
                    .with_attr("author_pn", "111@s.whatsapp.net")
                    .with_attr("author_username", "actor-one")
                    .with_attr("t", "1700000300"),
            ]);
        let parsed = parse_inbound_notification(&set_notification).unwrap();
        let event = group_update_event_from_notification_node(&set_notification, &parsed)
            .unwrap()
            .unwrap();

        assert_eq!(event.jid, "123@g.us");
        assert_eq!(event.fields["notification_type"], "picture");
        assert_eq!(event.fields["actor"], "111@lid");
        assert_eq!(event.fields["actor_pn"], "111@s.whatsapp.net");
        assert_eq!(event.fields["actor_username"], "actor-one");
        assert_eq!(event.fields["picture"], "changed");
        assert_eq!(event.fields["picture_changed"], "true");
        assert_eq!(event.fields["picture_id"], "pic-1");
        assert_eq!(event.fields["picture_hash"], "hash-1");
        assert_eq!(event.fields["picture_time"], "1700000300");
        assert_eq!(event.fields["picture_author"], "111@lid");
        assert_eq!(event.fields["picture_author_pn"], "111@s.whatsapp.net");
        assert_eq!(event.fields["picture_author_username"], "actor-one");
        assert!(!event.fields.contains_key("picture_removed"));

        let delete_notification = BinaryNode::new("notification")
            .with_attr("id", "g-picture-delete")
            .with_attr("from", "123@g.us")
            .with_attr("type", "picture")
            .with_attr("participant", "222@lid")
            .with_content(vec![
                BinaryNode::new("delete")
                    .with_attr("hash", "old-hash")
                    .with_attr("author", "222@lid")
                    .with_attr("phoneNumber", "222@s.whatsapp.net")
                    .with_attr("participantUsername", "actor-two"),
            ]);
        let parsed = parse_inbound_notification(&delete_notification).unwrap();
        let event = group_update_event_from_notification_node(&delete_notification, &parsed)
            .unwrap()
            .unwrap();

        assert_eq!(event.fields["picture"], "removed");
        assert_eq!(event.fields["picture_removed"], "true");
        assert_eq!(event.fields["picture_hash"], "old-hash");
        assert_eq!(event.fields["picture_author"], "222@lid");
        assert_eq!(event.fields["picture_author_pn"], "222@s.whatsapp.net");
        assert_eq!(event.fields["picture_author_username"], "actor-two");
        assert!(!event.fields.contains_key("picture_changed"));

        let invalid_author = BinaryNode::new("notification")
            .with_attr("id", "g-picture-invalid-author")
            .with_attr("from", "123@g.us")
            .with_attr("type", "picture")
            .with_content(vec![
                BinaryNode::new("set").with_attr("author", "not-a-jid"),
            ]);
        let parsed = parse_inbound_notification(&invalid_author).unwrap();
        assert!(group_update_event_from_notification_node(&invalid_author, &parsed).is_err());
    }

    #[test]
    fn maps_picture_notifications_to_contact_updates() {
        let user_picture = BinaryNode::new("notification")
            .with_attr("id", "p-user")
            .with_attr("from", "123:4@c.us")
            .with_attr("type", "picture")
            .with_content(vec![
                BinaryNode::new("set")
                    .with_attr("hash", "hash-user")
                    .with_attr("author", "123@s.whatsapp.net"),
            ]);
        let parsed = parse_inbound_notification(&user_picture).unwrap();
        let batch = event_batch_from_notification_node(&user_picture, &parsed)
            .unwrap()
            .unwrap();

        assert!(batch.groups_update.is_empty());
        assert_eq!(batch.contacts_update.len(), 1);
        assert_eq!(batch.contacts_update[0].jid, "123@s.whatsapp.net");
        assert_eq!(batch.contacts_update[0].fields["img_url"], "changed");
        assert_eq!(
            batch.contacts_update[0].fields["source"],
            "picture_notification"
        );

        let group_picture = BinaryNode::new("notification")
            .with_attr("id", "p-group")
            .with_attr("from", "456@g.us")
            .with_attr("type", "picture")
            .with_content(vec![
                BinaryNode::new("delete").with_attr("hash", "hash-group"),
            ]);
        let parsed = parse_inbound_notification(&group_picture).unwrap();
        let batch = event_batch_from_notification_node(&group_picture, &parsed)
            .unwrap()
            .unwrap();

        assert_eq!(batch.groups_update.len(), 1);
        assert_eq!(batch.groups_update[0].fields["picture"], "removed");
        assert_eq!(batch.contacts_update.len(), 1);
        assert_eq!(batch.contacts_update[0].jid, "456@g.us");
        assert_eq!(batch.contacts_update[0].fields["img_url"], "removed");

        let unrelated = BinaryNode::new("notification")
            .with_attr("id", "p-unrelated")
            .with_attr("from", "456@s.whatsapp.net")
            .with_attr("type", "w:gp2")
            .with_content(vec![BinaryNode::new("subject").with_content("ignored")]);
        let parsed = parse_inbound_notification(&unrelated).unwrap();
        assert!(
            contact_update_events_from_picture_notification_node(&unrelated, &parsed).is_empty()
        );
    }

    #[test]
    fn parses_device_list_notifications() {
        let notification = BinaryNode::new("notification")
            .with_attr("id", "devices-1")
            .with_attr("from", "123@s.whatsapp.net")
            .with_attr("type", "devices")
            .with_content(vec![
                BinaryNode::new("remove")
                    .with_attr("device_hash", "hash-1")
                    .with_content(vec![
                        BinaryNode::new("device").with_attr("jid", "123:7@s.whatsapp.net"),
                        BinaryNode::new("device").with_attr("jid", "bad-jid"),
                        BinaryNode::new("device"),
                    ]),
            ]);
        let parsed = parse_inbound_notification(&notification).unwrap();
        let update = device_list_notification_from_node(&notification, &parsed).unwrap();

        assert_eq!(update.from, "123@s.whatsapp.net");
        assert_eq!(update.action, "remove");
        assert_eq!(update.device_hash.as_deref(), Some("hash-1"));
        assert_eq!(update.device_jids(), vec!["123:7@s.whatsapp.net"]);
        assert_eq!(
            update.devices,
            vec![DeviceListNotificationDevice {
                jid: "123:7@s.whatsapp.net".to_owned(),
                user: "123".to_owned(),
                server: "s.whatsapp.net".to_owned(),
                device: Some(7),
            }]
        );

        let update_notification = BinaryNode::new("notification")
            .with_attr("id", "devices-2")
            .with_attr("from", "123@s.whatsapp.net")
            .with_attr("type", "devices")
            .with_content(vec![BinaryNode::new("update").with_content(vec![
                BinaryNode::new("device").with_attr("jid", "123@s.whatsapp.net"),
            ])]);
        let parsed = parse_inbound_notification(&update_notification).unwrap();
        let update = device_list_notification_from_node(&update_notification, &parsed).unwrap();

        assert_eq!(update.action, "update");
        assert_eq!(update.devices[0].device, None);

        let invalid_only = BinaryNode::new("notification")
            .with_attr("id", "devices-invalid")
            .with_attr("from", "123@s.whatsapp.net")
            .with_attr("type", "devices")
            .with_content(vec![BinaryNode::new("remove").with_content(vec![
                BinaryNode::new("device").with_attr("jid", "bad-jid"),
            ])]);
        let parsed = parse_inbound_notification(&invalid_only).unwrap();
        assert!(device_list_notification_from_node(&invalid_only, &parsed).is_none());

        let unrelated = BinaryNode::new("notification")
            .with_attr("id", "devices-unrelated")
            .with_attr("from", "123@s.whatsapp.net")
            .with_attr("type", "w:gp2")
            .with_content(vec![BinaryNode::new("remove").with_content(vec![
                BinaryNode::new("device").with_attr("jid", "123:7@s.whatsapp.net"),
            ])]);
        let parsed = parse_inbound_notification(&unrelated).unwrap();
        assert!(device_list_notification_from_node(&unrelated, &parsed).is_none());
    }

    #[test]
    fn maps_group_notification_create_metadata_snapshot() {
        let notification = BinaryNode::new("notification")
            .with_attr("id", "g-create")
            .with_attr("from", "123@g.us")
            .with_attr("type", "w:gp2")
            .with_attr("participant", "111@lid")
            .with_content(vec![
                BinaryNode::new("create")
                    .with_attr("id", "123")
                    .with_attr("subject", "Launch")
                    .with_attr("notify", "Launch Team")
                    .with_attr("addressing_mode", "lid")
                    .with_attr("s_o", "111@lid")
                    .with_attr("s_o_pn", "111@s.whatsapp.net")
                    .with_attr("s_o_username", "owner-user")
                    .with_attr("s_t", "1700000100")
                    .with_attr("creation", "1700000000")
                    .with_attr("creator", "111@lid")
                    .with_attr("creator_pn", "111@s.whatsapp.net")
                    .with_attr("creator_username", "owner-user")
                    .with_attr("creator_country_code", "1")
                    .with_attr("size", "2")
                    .with_content(vec![
                        BinaryNode::new("description")
                            .with_attr("id", "desc-create")
                            .with_attr("participant", "111@lid")
                            .with_content(vec![
                                BinaryNode::new("body").with_content("Created group"),
                            ]),
                        BinaryNode::new("announcement"),
                        BinaryNode::new("locked"),
                        BinaryNode::new("ephemeral").with_attr("expiration", "86400"),
                        BinaryNode::new("linked_parent").with_attr("jid", "999@g.us"),
                        BinaryNode::new("participant")
                            .with_attr("jid", "111@lid")
                            .with_attr("type", "superadmin")
                            .with_attr("phone_number", "111@s.whatsapp.net")
                            .with_attr("participant_username", "one"),
                        BinaryNode::new("participant")
                            .with_attr("jid", "222@lid")
                            .with_attr("type", "admin")
                            .with_attr("phone_number", "222@s.whatsapp.net")
                            .with_attr("username", "two"),
                    ]),
            ]);
        let parsed = parse_inbound_notification(&notification).unwrap();
        let event = group_update_event_from_notification_node(&notification, &parsed)
            .unwrap()
            .unwrap();

        assert_eq!(event.jid, "123@g.us");
        assert_eq!(event.fields["group_created"], "true");
        assert_eq!(event.fields["group_id"], "123");
        assert_eq!(event.fields["notify"], "Launch Team");
        assert_eq!(event.fields["addressing_mode"], "lid");
        assert_eq!(event.fields["subject"], "Launch");
        assert_eq!(event.fields["subject_owner"], "111@lid");
        assert_eq!(event.fields["subject_owner_pn"], "111@s.whatsapp.net");
        assert_eq!(event.fields["subject_owner_username"], "owner-user");
        assert_eq!(event.fields["subject_time"], "1700000100");
        assert_eq!(event.fields["creation"], "1700000000");
        assert_eq!(event.fields["owner"], "111@lid");
        assert_eq!(event.fields["owner_pn"], "111@s.whatsapp.net");
        assert_eq!(event.fields["owner_username"], "owner-user");
        assert_eq!(event.fields["owner_country_code"], "1");
        assert_eq!(event.fields["size"], "2");
        assert_eq!(event.fields["description"], "Created group");
        assert_eq!(event.fields["description_id"], "desc-create");
        assert_eq!(event.fields["description_owner"], "111@lid");
        assert_eq!(event.fields["announce"], "true");
        assert_eq!(event.fields["restrict"], "true");
        assert_eq!(event.fields["ephemeral_duration"], "86400");
        assert_eq!(event.fields["linked_parent"], "999@g.us");
        assert_eq!(event.fields["participants"], "111@lid,222@lid");
        assert_eq!(event.fields["participants_count"], "2");
        assert_eq!(
            event.fields["participants_roles"],
            "111@lid=superadmin,222@lid=admin"
        );
        assert_eq!(
            event.fields["participants_phone_numbers"],
            "111@lid=111@s.whatsapp.net,222@lid=222@s.whatsapp.net"
        );
        assert_eq!(
            event.fields["participants_usernames"],
            "111@lid=one,222@lid=two"
        );
        assert_eq!(event.fields["participants_admins"], "222@lid");
        assert_eq!(event.fields["participants_admins_count"], "1");
        assert_eq!(event.fields["participants_superadmins"], "111@lid");
        assert_eq!(event.fields["participants_superadmins_count"], "1");

        let invalid_owner = BinaryNode::new("notification")
            .with_attr("id", "g-create-invalid-owner")
            .with_attr("from", "123@g.us")
            .with_attr("type", "w:gp2")
            .with_content(vec![
                BinaryNode::new("create").with_attr("creator", "not-a-jid"),
            ]);
        let parsed = parse_inbound_notification(&invalid_owner).unwrap();
        assert!(group_update_event_from_notification_node(&invalid_owner, &parsed).is_err());

        let invalid_size = BinaryNode::new("notification")
            .with_attr("id", "g-create-invalid-size")
            .with_attr("from", "123@g.us")
            .with_attr("type", "w:gp2")
            .with_content(vec![BinaryNode::new("create").with_attr("size", "many")]);
        let parsed = parse_inbound_notification(&invalid_size).unwrap();
        assert!(group_update_event_from_notification_node(&invalid_size, &parsed).is_err());
    }

    #[test]
    fn maps_group_notification_description_delete_form() {
        let notification = BinaryNode::new("notification")
            .with_attr("id", "g-desc-delete")
            .with_attr("from", "123@g.us")
            .with_attr("type", "w:gp2")
            .with_content(vec![
                BinaryNode::new("description")
                    .with_attr("id", "desc-old")
                    .with_attr("participant", "789@s.whatsapp.net")
                    .with_attr("delete", "true")
                    .with_attr("t", "1700000002"),
            ]);
        let parsed = parse_inbound_notification(&notification).unwrap();
        let event = group_update_event_from_notification_node(&notification, &parsed)
            .unwrap()
            .unwrap();

        assert_eq!(event.jid, "123@g.us");
        assert_eq!(event.fields["description_deleted"], "true");
        assert_eq!(event.fields["description_id"], "desc-old");
        assert_eq!(event.fields["description_owner"], "789@s.whatsapp.net");
        assert_eq!(event.fields["description_time"], "1700000002");
        assert!(!event.fields.contains_key("description"));
    }

    #[test]
    fn maps_group_notification_description_body_forms() {
        let notification = BinaryNode::new("notification")
            .with_attr("id", "g-desc-body")
            .with_attr("from", "123@g.us")
            .with_attr("type", "w:gp2")
            .with_content(vec![
                BinaryNode::new("description")
                    .with_attr("id", "desc-new")
                    .with_attr("participant", "789@s.whatsapp.net")
                    .with_attr("t", "1700000003")
                    .with_content(vec![
                        BinaryNode::new("body").with_content("Body description"),
                    ]),
            ]);
        let parsed = parse_inbound_notification(&notification).unwrap();
        let event = group_update_event_from_notification_node(&notification, &parsed)
            .unwrap()
            .unwrap();

        assert_eq!(event.jid, "123@g.us");
        assert_eq!(event.fields["description"], "Body description");
        assert_eq!(event.fields["description_id"], "desc-new");
        assert_eq!(event.fields["description_owner"], "789@s.whatsapp.net");
        assert_eq!(event.fields["description_time"], "1700000003");

        let desc_alias = BinaryNode::new("notification")
            .with_attr("id", "g-desc-alias-body")
            .with_attr("from", "123@g.us")
            .with_attr("type", "w:gp2")
            .with_content(vec![BinaryNode::new("desc").with_content(vec![
                BinaryNode::new("body").with_content(Bytes::from_static(b"Byte body")),
            ])]);
        let parsed = parse_inbound_notification(&desc_alias).unwrap();
        let event = group_update_event_from_notification_node(&desc_alias, &parsed)
            .unwrap()
            .unwrap();

        assert_eq!(event.fields["description"], "Byte body");
    }

    #[test]
    fn maps_group_notification_owner_alias_metadata() {
        let notification = BinaryNode::new("notification")
            .with_attr("id", "g-owner-aliases")
            .with_attr("from", "123@g.us")
            .with_attr("type", "w:gp2")
            .with_content(vec![
                BinaryNode::new("subject")
                    .with_attr("author", "111@lid")
                    .with_attr("author_pn", "111@s.whatsapp.net")
                    .with_attr("author_username", "one")
                    .with_attr("s_t", "1700000200")
                    .with_content("Alias subject"),
                BinaryNode::new("description")
                    .with_attr("id", "desc-alias")
                    .with_attr("participant", "222@lid")
                    .with_attr("participant_pn", "222@s.whatsapp.net")
                    .with_attr("participant_username", "two")
                    .with_content(vec![BinaryNode::new("body").with_content("Alias body")]),
            ]);
        let parsed = parse_inbound_notification(&notification).unwrap();
        let event = group_update_event_from_notification_node(&notification, &parsed)
            .unwrap()
            .unwrap();

        assert_eq!(event.fields["subject"], "Alias subject");
        assert_eq!(event.fields["subject_owner"], "111@lid");
        assert_eq!(event.fields["subject_owner_pn"], "111@s.whatsapp.net");
        assert_eq!(event.fields["subject_owner_username"], "one");
        assert_eq!(event.fields["subject_time"], "1700000200");
        assert_eq!(event.fields["description"], "Alias body");
        assert_eq!(event.fields["description_id"], "desc-alias");
        assert_eq!(event.fields["description_owner"], "222@lid");
        assert_eq!(event.fields["description_owner_pn"], "222@s.whatsapp.net");
        assert_eq!(event.fields["description_owner_username"], "two");

        let s_o_fallback = BinaryNode::new("notification")
            .with_attr("id", "g-subject-so")
            .with_attr("from", "123@g.us")
            .with_attr("type", "w:gp2")
            .with_content(vec![
                BinaryNode::new("subject")
                    .with_attr("s_o", "333@lid")
                    .with_attr("sOPn", "333@s.whatsapp.net")
                    .with_attr("sOUsername", "three")
                    .with_content("Subject owner fallback"),
            ]);
        let parsed = parse_inbound_notification(&s_o_fallback).unwrap();
        let event = group_update_event_from_notification_node(&s_o_fallback, &parsed)
            .unwrap()
            .unwrap();

        assert_eq!(event.fields["subject_owner"], "333@lid");
        assert_eq!(event.fields["subject_owner_pn"], "333@s.whatsapp.net");
        assert_eq!(event.fields["subject_owner_username"], "three");

        let invalid_subject_pn = BinaryNode::new("notification")
            .with_attr("id", "g-subject-invalid-pn")
            .with_attr("from", "123@g.us")
            .with_attr("type", "w:gp2")
            .with_content(vec![
                BinaryNode::new("subject")
                    .with_attr("author_pn", "not-a-jid")
                    .with_content("bad"),
            ]);
        let parsed = parse_inbound_notification(&invalid_subject_pn).unwrap();
        assert!(group_update_event_from_notification_node(&invalid_subject_pn, &parsed).is_err());

        let invalid_description_pn = BinaryNode::new("notification")
            .with_attr("id", "g-description-invalid-pn")
            .with_attr("from", "123@g.us")
            .with_attr("type", "w:gp2")
            .with_content(vec![
                BinaryNode::new("description")
                    .with_attr("participant_pn", "not-a-jid")
                    .with_content("bad"),
            ]);
        let parsed = parse_inbound_notification(&invalid_description_pn).unwrap();
        assert!(
            group_update_event_from_notification_node(&invalid_description_pn, &parsed).is_err()
        );
    }

    #[test]
    fn maps_group_notification_setting_edge_forms() {
        let notification = BinaryNode::new("notification")
            .with_attr("id", "g2")
            .with_attr("from", "123@g.us")
            .with_attr("type", "w:gp2")
            .with_content(vec![
                BinaryNode::new("not_ephemeral"),
                BinaryNode::new("member_add_mode").with_content("all_member_add"),
                BinaryNode::new("membership_approval_mode").with_content(vec![
                    BinaryNode::new("group_join").with_attr("state", "off"),
                ]),
            ]);
        let parsed = parse_inbound_notification(&notification).unwrap();
        let event = group_update_event_from_notification_node(&notification, &parsed)
            .unwrap()
            .unwrap();

        assert_eq!(event.jid, "123@g.us");
        assert_eq!(event.fields["ephemeral_duration"], "0");
        assert_eq!(event.fields["member_add_mode"], "all_member_add");
        assert_eq!(event.fields["join_approval_mode"], "off");
    }

    #[test]
    fn maps_group_notification_community_linkage_forms() {
        let notification = BinaryNode::new("notification")
            .with_attr("id", "g-community")
            .with_attr("from", "123@g.us")
            .with_attr("type", "w:gp2")
            .with_content(vec![
                BinaryNode::new("parent")
                    .with_attr("default_membership_approval_mode", "request_required"),
                BinaryNode::new("default_sub_group"),
                BinaryNode::new("linked_parent").with_attr("jid", "999@g.us"),
            ]);
        let parsed = parse_inbound_notification(&notification).unwrap();
        let event = group_update_event_from_notification_node(&notification, &parsed)
            .unwrap()
            .unwrap();

        assert_eq!(event.jid, "123@g.us");
        assert_eq!(event.fields["is_community"], "true");
        assert_eq!(
            event.fields["default_membership_approval_mode"],
            "request_required"
        );
        assert_eq!(event.fields["is_community_announce"], "true");
        assert_eq!(event.fields["linked_parent"], "999@g.us");

        let invalid_parent = BinaryNode::new("notification")
            .with_attr("id", "g-community-invalid")
            .with_attr("from", "123@g.us")
            .with_attr("type", "w:gp2")
            .with_content(vec![
                BinaryNode::new("linked_parent").with_attr("jid", "not-a-jid"),
            ]);
        let parsed = parse_inbound_notification(&invalid_parent).unwrap();
        assert!(group_update_event_from_notification_node(&invalid_parent, &parsed).is_err());
    }

    #[test]
    fn maps_group_notification_participant_metadata() {
        let notification = BinaryNode::new("notification")
            .with_attr("id", "g3")
            .with_attr("from", "123@g.us")
            .with_attr("type", "w:gp2")
            .with_content(vec![BinaryNode::new("promote").with_content(vec![
                BinaryNode::new("participant")
                    .with_attr("jid", "111@s.whatsapp.net")
                    .with_attr("type", "admin")
                    .with_attr("lid", "111@lid")
                    .with_attr("phone_number", "111@s.whatsapp.net")
                    .with_attr("participant_username", "one"),
                BinaryNode::new("participant")
                    .with_attr("jid", "222@s.whatsapp.net")
                    .with_attr("status", "409")
                    .with_attr("error", "403")
                    .with_attr("username", "two"),
            ])]);
        let parsed = parse_inbound_notification(&notification).unwrap();
        let event = group_update_event_from_notification_node(&notification, &parsed)
            .unwrap()
            .unwrap();

        assert_eq!(
            event.fields["participants_promote"],
            "111@s.whatsapp.net,222@s.whatsapp.net"
        );
        assert_eq!(event.fields["participants_promote_count"], "2");
        assert_eq!(
            event.fields["participants_promote_roles"],
            "111@s.whatsapp.net=admin"
        );
        assert_eq!(
            event.fields["participants_promote_statuses"],
            "222@s.whatsapp.net=409"
        );
        assert_eq!(
            event.fields["participants_promote_errors"],
            "222@s.whatsapp.net=403"
        );
        assert_eq!(
            event.fields["participants_promote_lids"],
            "111@s.whatsapp.net=111@lid"
        );
        assert_eq!(
            event.fields["participants_promote_phone_numbers"],
            "111@s.whatsapp.net=111@s.whatsapp.net"
        );
        assert_eq!(
            event.fields["participants_promote_usernames"],
            "111@s.whatsapp.net=one,222@s.whatsapp.net=two"
        );
    }

    #[test]
    fn maps_group_notification_baileys_participant_alias_attributes() {
        let notification = BinaryNode::new("notification")
            .with_attr("id", "g-participant-aliases")
            .with_attr("from", "123@g.us")
            .with_attr("type", "w:gp2")
            .with_attr("senderPn", "444@s.whatsapp.net")
            .with_attr("senderUsername", "actor-four")
            .with_content(vec![BinaryNode::new("promote").with_content(vec![
                BinaryNode::new("participant")
                    .with_attr("jid", "111@lid")
                    .with_attr("type", "admin")
                    .with_attr("lidJid", "111@lid")
                    .with_attr("phoneNumber", "111@s.whatsapp.net")
                    .with_attr("participantUsername", "one"),
                BinaryNode::new("participant")
                    .with_attr("jid", "222@lid")
                    .with_attr("participantLid", "222@lid")
                    .with_attr("pn", "222@s.whatsapp.net")
                    .with_attr("username", "two"),
            ])]);
        let parsed = parse_inbound_notification(&notification).unwrap();
        let event = group_update_event_from_notification_node(&notification, &parsed)
            .unwrap()
            .unwrap();

        assert_eq!(event.fields["actor_pn"], "444@s.whatsapp.net");
        assert_eq!(event.fields["actor_username"], "actor-four");
        assert_eq!(event.fields["participants_promote"], "111@lid,222@lid");
        assert_eq!(
            event.fields["participants_promote_lids"],
            "111@lid=111@lid,222@lid=222@lid"
        );
        assert_eq!(
            event.fields["participants_promote_phone_numbers"],
            "111@lid=111@s.whatsapp.net,222@lid=222@s.whatsapp.net"
        );
        assert_eq!(
            event.fields["participants_promote_usernames"],
            "111@lid=one,222@lid=two"
        );

        let fallback = BinaryNode::new("notification")
            .with_attr("id", "g-membership-created-aliases")
            .with_attr("from", "123@g.us")
            .with_attr("type", "w:gp2")
            .with_attr("participant", "333@lid")
            .with_content(vec![
                BinaryNode::new("created_membership_requests")
                    .with_attr("lid_jid", "333@lid")
                    .with_attr("pnJid", "333@s.whatsapp.net")
                    .with_attr("participantUsername", "three"),
            ]);
        let parsed = parse_inbound_notification(&fallback).unwrap();
        let event = group_update_event_from_notification_node(&fallback, &parsed)
            .unwrap()
            .unwrap();

        assert_eq!(event.fields["join_requests_created"], "333@lid");
        assert_eq!(
            event.fields["join_requests_created_lids"],
            "333@lid=333@lid"
        );
        assert_eq!(
            event.fields["join_requests_created_phone_numbers"],
            "333@lid=333@s.whatsapp.net"
        );
        assert_eq!(
            event.fields["join_requests_created_usernames"],
            "333@lid=three"
        );
    }

    #[test]
    fn maps_group_notification_leave_and_modify_participants() {
        let notification = BinaryNode::new("notification")
            .with_attr("id", "g-participant-edge")
            .with_attr("from", "123@g.us")
            .with_attr("type", "w:gp2")
            .with_content(vec![
                BinaryNode::new("leave").with_content(vec![
                    BinaryNode::new("participant")
                        .with_attr("jid", "111@s.whatsapp.net")
                        .with_attr("status", "200"),
                ]),
                BinaryNode::new("modify").with_content(vec![
                    BinaryNode::new("participant")
                        .with_attr("jid", "222@s.whatsapp.net")
                        .with_attr("lid", "222@lid")
                        .with_attr("phone_number", "222@s.whatsapp.net")
                        .with_attr("participant_username", "two"),
                ]),
            ]);
        let parsed = parse_inbound_notification(&notification).unwrap();
        let event = group_update_event_from_notification_node(&notification, &parsed)
            .unwrap()
            .unwrap();

        assert_eq!(event.fields["participants_leave"], "111@s.whatsapp.net");
        assert_eq!(event.fields["participants_leave_count"], "1");
        assert_eq!(
            event.fields["participants_leave_statuses"],
            "111@s.whatsapp.net=200"
        );
        assert_eq!(event.fields["participants_modify"], "222@s.whatsapp.net");
        assert_eq!(event.fields["participants_modify_count"], "1");
        assert_eq!(
            event.fields["participants_modify_lids"],
            "222@s.whatsapp.net=222@lid"
        );
        assert_eq!(
            event.fields["participants_modify_phone_numbers"],
            "222@s.whatsapp.net=222@s.whatsapp.net"
        );
        assert_eq!(
            event.fields["participants_modify_usernames"],
            "222@s.whatsapp.net=two"
        );

        let invalid = BinaryNode::new("notification")
            .with_attr("id", "g-participant-edge-invalid")
            .with_attr("from", "123@g.us")
            .with_attr("type", "w:gp2")
            .with_content(vec![BinaryNode::new("modify").with_content(vec![
                BinaryNode::new("participant").with_attr("jid", "not-a-jid"),
            ])]);
        let parsed = parse_inbound_notification(&invalid).unwrap();
        assert!(group_update_event_from_notification_node(&invalid, &parsed).is_err());
    }

    #[test]
    fn maps_group_notification_self_remove_as_leave() {
        let notification = BinaryNode::new("notification")
            .with_attr("id", "g-self-remove")
            .with_attr("from", "123@g.us")
            .with_attr("type", "w:gp2")
            .with_attr("participant", "111@lid")
            .with_content(vec![BinaryNode::new("remove").with_content(vec![
                BinaryNode::new("participant")
                    .with_attr("jid", "111@lid")
                    .with_attr("phone_number", "111@s.whatsapp.net")
                    .with_attr("participant_username", "one"),
            ])]);
        let parsed = parse_inbound_notification(&notification).unwrap();
        let event = group_update_event_from_notification_node(&notification, &parsed)
            .unwrap()
            .unwrap();

        assert_eq!(event.fields["participants_remove"], "111@lid");
        assert_eq!(event.fields["participants_remove_is_leave"], "true");
        assert_eq!(event.fields["participants_leave"], "111@lid");
        assert_eq!(event.fields["participants_leave_count"], "1");
        assert_eq!(
            event.fields["participants_leave_phone_numbers"],
            "111@lid=111@s.whatsapp.net"
        );
        assert_eq!(event.fields["participants_leave_usernames"], "111@lid=one");

        let pn_actor = BinaryNode::new("notification")
            .with_attr("id", "g-self-remove-pn")
            .with_attr("from", "123@g.us")
            .with_attr("type", "w:gp2")
            .with_attr("participant_pn", "222@s.whatsapp.net")
            .with_content(vec![BinaryNode::new("remove").with_content(vec![
                BinaryNode::new("participant")
                    .with_attr("jid", "opaque@lid")
                    .with_attr("phone_number", "222@s.whatsapp.net"),
            ])]);
        let parsed = parse_inbound_notification(&pn_actor).unwrap();
        let event = group_update_event_from_notification_node(&pn_actor, &parsed)
            .unwrap()
            .unwrap();

        assert_eq!(event.fields["participants_remove"], "opaque@lid");
        assert_eq!(event.fields["participants_remove_is_leave"], "true");
        assert_eq!(event.fields["participants_leave"], "opaque@lid");
        assert_eq!(
            event.fields["participants_leave_phone_numbers"],
            "opaque@lid=222@s.whatsapp.net"
        );

        let multi_remove = BinaryNode::new("notification")
            .with_attr("id", "g-multi-remove")
            .with_attr("from", "123@g.us")
            .with_attr("type", "w:gp2")
            .with_attr("participant", "111@lid")
            .with_content(vec![BinaryNode::new("remove").with_content(vec![
                BinaryNode::new("participant").with_attr("jid", "111@lid"),
                BinaryNode::new("participant").with_attr("jid", "222@lid"),
            ])]);
        let parsed = parse_inbound_notification(&multi_remove).unwrap();
        let event = group_update_event_from_notification_node(&multi_remove, &parsed)
            .unwrap()
            .unwrap();

        assert_eq!(event.fields["participants_remove"], "111@lid,222@lid");
        assert!(!event.fields.contains_key("participants_remove_is_leave"));
        assert!(!event.fields.contains_key("participants_leave"));
    }

    #[test]
    fn maps_group_notification_invite_lifecycle_forms() {
        let invite_notification = BinaryNode::new("notification")
            .with_attr("id", "g-invite")
            .with_attr("from", "123@g.us")
            .with_attr("type", "w:gp2")
            .with_content(vec![
                BinaryNode::new("invite")
                    .with_attr("code", "new-code")
                    .with_attr("expiration", "1700000300")
                    .with_attr("admin", "111@lid")
                    .with_attr("adminPn", "111@s.whatsapp.net")
                    .with_attr("adminUsername", "one"),
            ]);
        let parsed = parse_inbound_notification(&invite_notification).unwrap();
        let event = group_update_event_from_notification_node(&invite_notification, &parsed)
            .unwrap()
            .unwrap();

        assert_eq!(event.fields["invite_updated"], "true");
        assert_eq!(event.fields["invite_code"], "new-code");
        assert_eq!(event.fields["invite_expiration"], "1700000300");
        assert_eq!(event.fields["invite_admin"], "111@lid");
        assert_eq!(event.fields["invite_admin_pn"], "111@s.whatsapp.net");
        assert_eq!(event.fields["invite_admin_username"], "one");

        let revoke_notification = BinaryNode::new("notification")
            .with_attr("id", "g-revoke")
            .with_attr("from", "123@g.us")
            .with_attr("type", "w:gp2")
            .with_content(vec![BinaryNode::new("revoke").with_content(vec![
                BinaryNode::new("participant")
                    .with_attr("jid", "222@s.whatsapp.net")
                    .with_attr("status", "200"),
            ])]);
        let parsed = parse_inbound_notification(&revoke_notification).unwrap();
        let event = group_update_event_from_notification_node(&revoke_notification, &parsed)
            .unwrap()
            .unwrap();

        assert_eq!(event.fields["invite_revoked"], "true");
        assert_eq!(event.fields["participants_revoke"], "222@s.whatsapp.net");
        assert_eq!(event.fields["participants_revoke_count"], "1");
        assert_eq!(
            event.fields["participants_revoke_statuses"],
            "222@s.whatsapp.net=200"
        );

        let accept_notification = BinaryNode::new("notification")
            .with_attr("id", "g-accept")
            .with_attr("from", "123@g.us")
            .with_attr("type", "w:gp2")
            .with_content(vec![
                BinaryNode::new("accept")
                    .with_attr("code", "v4-code")
                    .with_attr("expiration", "1700000400")
                    .with_attr("admin", "111@s.whatsapp.net")
                    .with_attr("author_pn", "111@s.whatsapp.net")
                    .with_attr("author_username", "one")
                    .with_content(vec![
                        BinaryNode::new("participant").with_attr("jid", "333@s.whatsapp.net"),
                    ]),
            ]);
        let parsed = parse_inbound_notification(&accept_notification).unwrap();
        let event = group_update_event_from_notification_node(&accept_notification, &parsed)
            .unwrap()
            .unwrap();

        assert_eq!(event.fields["invite_accepted"], "true");
        assert_eq!(event.fields["invite_code"], "v4-code");
        assert_eq!(event.fields["invite_expiration"], "1700000400");
        assert_eq!(event.fields["invite_admin"], "111@s.whatsapp.net");
        assert_eq!(event.fields["invite_admin_pn"], "111@s.whatsapp.net");
        assert_eq!(event.fields["invite_admin_username"], "one");
        assert_eq!(event.fields["participants_accept"], "333@s.whatsapp.net");

        let fallback_accept_notification = BinaryNode::new("notification")
            .with_attr("id", "g-accept-fallback")
            .with_attr("from", "123@g.us")
            .with_attr("type", "w:gp2")
            .with_attr("participant", "333@lid")
            .with_attr("participant_pn", "333@s.whatsapp.net")
            .with_attr("participantUsername", "three")
            .with_content(vec![
                BinaryNode::new("accept")
                    .with_attr("code", "fallback-code")
                    .with_attr("admin", "111@s.whatsapp.net"),
            ]);
        let parsed = parse_inbound_notification(&fallback_accept_notification).unwrap();
        let event =
            group_update_event_from_notification_node(&fallback_accept_notification, &parsed)
                .unwrap()
                .unwrap();

        assert_eq!(event.fields["invite_accepted"], "true");
        assert_eq!(event.fields["invite_code"], "fallback-code");
        assert_eq!(event.fields["participants_accept"], "333@lid");
        assert_eq!(event.fields["participants_accept_count"], "1");
        assert_eq!(
            event.fields["participants_accept_phone_numbers"],
            "333@lid=333@s.whatsapp.net"
        );
        assert_eq!(
            event.fields["participants_accept_usernames"],
            "333@lid=three"
        );

        let invalid_expiration = BinaryNode::new("notification")
            .with_attr("id", "g-invite-invalid-expiration")
            .with_attr("from", "123@g.us")
            .with_attr("type", "w:gp2")
            .with_content(vec![
                BinaryNode::new("invite").with_attr("expiration", "soon"),
            ]);
        let parsed = parse_inbound_notification(&invalid_expiration).unwrap();
        assert!(group_update_event_from_notification_node(&invalid_expiration, &parsed).is_err());

        let invalid_admin = BinaryNode::new("notification")
            .with_attr("id", "g-invite-invalid-admin")
            .with_attr("from", "123@g.us")
            .with_attr("type", "w:gp2")
            .with_content(vec![
                BinaryNode::new("accept").with_attr("admin", "not-a-jid"),
            ]);
        let parsed = parse_inbound_notification(&invalid_admin).unwrap();
        assert!(group_update_event_from_notification_node(&invalid_admin, &parsed).is_err());

        let invalid_admin_pn = BinaryNode::new("notification")
            .with_attr("id", "g-invite-invalid-admin-pn")
            .with_attr("from", "123@g.us")
            .with_attr("type", "w:gp2")
            .with_content(vec![
                BinaryNode::new("invite").with_attr("admin_pn", "not-a-jid"),
            ]);
        let parsed = parse_inbound_notification(&invalid_admin_pn).unwrap();
        assert!(group_update_event_from_notification_node(&invalid_admin_pn, &parsed).is_err());
    }

    #[test]
    fn maps_group_notification_join_request_forms() {
        let requests_notification = BinaryNode::new("notification")
            .with_attr("id", "g-join-requests")
            .with_attr("from", "123@g.us")
            .with_attr("type", "w:gp2")
            .with_content(vec![
                BinaryNode::new("membership_approval_requests").with_content(vec![
                    BinaryNode::new("membership_approval_request")
                        .with_attr("jid", "111@s.whatsapp.net")
                        .with_attr("lidJid", "111@lid")
                        .with_attr("phoneNumber", "111@s.whatsapp.net")
                        .with_attr("participantUsername", "one")
                        .with_attr("t", "1700000500")
                        .with_attr("requestMethod", "invite_link"),
                    BinaryNode::new("membership_approval_request")
                        .with_attr("jid", "")
                        .with_attr("participant", "222@s.whatsapp.net")
                        .with_attr("lid_jid", "222@lid")
                        .with_attr("pn", "222@s.whatsapp.net")
                        .with_attr("username", "two")
                        .with_attr("method", "non_admin_add"),
                ]),
            ]);
        let parsed = parse_inbound_notification(&requests_notification).unwrap();
        let event = group_update_event_from_notification_node(&requests_notification, &parsed)
            .unwrap()
            .unwrap();

        assert_eq!(
            event.fields["join_requests"],
            "111@s.whatsapp.net,222@s.whatsapp.net"
        );
        assert_eq!(event.fields["join_requests_count"], "2");
        assert_eq!(
            event.fields["join_requests_lids"],
            "111@s.whatsapp.net=111@lid,222@s.whatsapp.net=222@lid"
        );
        assert_eq!(
            event.fields["join_requests_phone_numbers"],
            "111@s.whatsapp.net=111@s.whatsapp.net,222@s.whatsapp.net=222@s.whatsapp.net"
        );
        assert_eq!(
            event.fields["join_requests_usernames"],
            "111@s.whatsapp.net=one,222@s.whatsapp.net=two"
        );
        assert_eq!(
            event.fields["join_requests_requested_at"],
            "111@s.whatsapp.net=1700000500"
        );
        assert_eq!(
            event.fields["join_requests_methods"],
            "111@s.whatsapp.net=invite_link,222@s.whatsapp.net=non_admin_add"
        );

        let action_notification = BinaryNode::new("notification")
            .with_attr("id", "g-join-action")
            .with_attr("from", "123@g.us")
            .with_attr("type", "w:gp2")
            .with_content(vec![
                BinaryNode::new("membership_requests_action").with_content(vec![
                    BinaryNode::new("approve").with_content(vec![
                        BinaryNode::new("participant")
                            .with_attr("jid", "111@s.whatsapp.net")
                            .with_attr("status", "200"),
                    ]),
                    BinaryNode::new("reject").with_content(vec![
                        BinaryNode::new("participant")
                            .with_attr("jid", "222@s.whatsapp.net")
                            .with_attr("error", "403"),
                    ]),
                ]),
            ]);
        let parsed = parse_inbound_notification(&action_notification).unwrap();
        let event = group_update_event_from_notification_node(&action_notification, &parsed)
            .unwrap()
            .unwrap();

        assert_eq!(event.fields["join_requests_approve"], "111@s.whatsapp.net");
        assert_eq!(event.fields["join_requests_approve_count"], "1");
        assert_eq!(
            event.fields["join_requests_approve_statuses"],
            "111@s.whatsapp.net=200"
        );
        assert_eq!(event.fields["join_requests_reject"], "222@s.whatsapp.net");
        assert_eq!(event.fields["join_requests_reject_count"], "1");
        assert_eq!(
            event.fields["join_requests_reject_errors"],
            "222@s.whatsapp.net=403"
        );

        let singular_notification = BinaryNode::new("notification")
            .with_attr("id", "g-join-request")
            .with_attr("from", "123@g.us")
            .with_attr("type", "w:gp2")
            .with_content(vec![
                BinaryNode::new("membership_approval_request")
                    .with_attr("jid", "333@s.whatsapp.net")
                    .with_attr("t", "1700000600"),
            ]);
        let parsed = parse_inbound_notification(&singular_notification).unwrap();
        let event = group_update_event_from_notification_node(&singular_notification, &parsed)
            .unwrap()
            .unwrap();

        assert_eq!(event.fields["join_requests"], "333@s.whatsapp.net");
        assert_eq!(event.fields["join_requests_count"], "1");
        assert_eq!(
            event.fields["join_requests_requested_at"],
            "333@s.whatsapp.net=1700000600"
        );

        let invalid_timestamp = BinaryNode::new("notification")
            .with_attr("id", "g-join-request-invalid-timestamp")
            .with_attr("from", "123@g.us")
            .with_attr("type", "w:gp2")
            .with_content(vec![
                BinaryNode::new("membership_approval_requests").with_content(vec![
                    BinaryNode::new("membership_approval_request")
                        .with_attr("jid", "111@s.whatsapp.net")
                        .with_attr("t", "later"),
                ]),
            ]);
        let parsed = parse_inbound_notification(&invalid_timestamp).unwrap();
        assert!(group_update_event_from_notification_node(&invalid_timestamp, &parsed).is_err());

        let invalid_participant = BinaryNode::new("notification")
            .with_attr("id", "g-join-action-invalid-participant")
            .with_attr("from", "123@g.us")
            .with_attr("type", "w:gp2")
            .with_content(vec![
                BinaryNode::new("membership_requests_action").with_content(vec![
                    BinaryNode::new("approve").with_content(vec![
                        BinaryNode::new("participant").with_attr("jid", "not-a-jid"),
                    ]),
                ]),
            ]);
        let parsed = parse_inbound_notification(&invalid_participant).unwrap();
        assert!(group_update_event_from_notification_node(&invalid_participant, &parsed).is_err());
    }

    #[test]
    fn maps_group_notification_membership_request_lifecycle_forms() {
        let created_notification = BinaryNode::new("notification")
            .with_attr("id", "g-membership-created")
            .with_attr("from", "123@g.us")
            .with_attr("type", "w:gp2")
            .with_attr("participant", "111@lid")
            .with_attr("participant_pn", "111@s.whatsapp.net")
            .with_attr("participant_username", "one")
            .with_content(vec![
                BinaryNode::new("created_membership_requests")
                    .with_attr("requestMethod", "non_admin_add")
                    .with_attr("t", "1700000700"),
            ]);
        let parsed = parse_inbound_notification(&created_notification).unwrap();
        let event = group_update_event_from_notification_node(&created_notification, &parsed)
            .unwrap()
            .unwrap();

        assert_eq!(event.fields["actor"], "111@lid");
        assert_eq!(event.fields["join_requests_created"], "111@lid");
        assert_eq!(event.fields["join_requests_created_count"], "1");
        assert_eq!(
            event.fields["join_requests_created_phone_numbers"],
            "111@lid=111@s.whatsapp.net"
        );
        assert_eq!(
            event.fields["join_requests_created_usernames"],
            "111@lid=one"
        );
        assert_eq!(
            event.fields["join_requests_created_methods"],
            "111@lid=non_admin_add"
        );
        assert_eq!(
            event.fields["join_requests_created_requested_at"],
            "111@lid=1700000700"
        );
        assert_eq!(
            event.fields["join_requests_created_outcomes"],
            "111@lid=created"
        );

        let revoked_notification = BinaryNode::new("notification")
            .with_attr("id", "g-membership-revoked")
            .with_attr("from", "123@g.us")
            .with_attr("type", "w:gp2")
            .with_attr("participant", "222@lid")
            .with_attr("participant_pn", "222@s.whatsapp.net")
            .with_content(vec![
                BinaryNode::new("revoked_membership_requests")
                    .with_attr("method", "admin_review")
                    .with_attr("t", "1700000800")
                    .with_content(vec![
                        BinaryNode::new("participant")
                            .with_attr("jid", "222@lid")
                            .with_attr("phone_number", "222@s.whatsapp.net")
                            .with_attr("error", "409"),
                        BinaryNode::new("participant")
                            .with_attr("jid", "333@lid")
                            .with_attr("phone_number", "333@s.whatsapp.net")
                            .with_attr("status", "200")
                            .with_attr("username", "three"),
                    ]),
            ]);
        let parsed = parse_inbound_notification(&revoked_notification).unwrap();
        let event = group_update_event_from_notification_node(&revoked_notification, &parsed)
            .unwrap()
            .unwrap();

        assert_eq!(event.fields["join_requests_revoked"], "222@lid,333@lid");
        assert_eq!(event.fields["join_requests_revoked_count"], "2");
        assert_eq!(
            event.fields["join_requests_revoked_phone_numbers"],
            "222@lid=222@s.whatsapp.net,333@lid=333@s.whatsapp.net"
        );
        assert_eq!(event.fields["join_requests_revoked_errors"], "222@lid=409");
        assert_eq!(
            event.fields["join_requests_revoked_statuses"],
            "333@lid=200"
        );
        assert_eq!(
            event.fields["join_requests_revoked_usernames"],
            "333@lid=three"
        );
        assert_eq!(
            event.fields["join_requests_revoked_methods"],
            "222@lid=admin_review,333@lid=admin_review"
        );
        assert_eq!(
            event.fields["join_requests_revoked_requested_at"],
            "222@lid=1700000800,333@lid=1700000800"
        );
        assert_eq!(
            event.fields["join_requests_revoked_outcomes"],
            "222@lid=revoked,333@lid=rejected"
        );

        let invalid_timestamp = BinaryNode::new("notification")
            .with_attr("id", "g-membership-invalid-t")
            .with_attr("from", "123@g.us")
            .with_attr("type", "w:gp2")
            .with_attr("participant", "111@lid")
            .with_content(vec![
                BinaryNode::new("created_membership_requests").with_attr("t", "later"),
            ]);
        let parsed = parse_inbound_notification(&invalid_timestamp).unwrap();
        assert!(group_update_event_from_notification_node(&invalid_timestamp, &parsed).is_err());

        let invalid_phone_number = BinaryNode::new("notification")
            .with_attr("id", "g-membership-invalid-pn")
            .with_attr("from", "123@g.us")
            .with_attr("type", "w:gp2")
            .with_attr("participant", "111@lid")
            .with_attr("participant_pn", "not-a-jid")
            .with_content(vec![BinaryNode::new("created_membership_requests")]);
        let parsed = parse_inbound_notification(&invalid_phone_number).unwrap();
        assert!(group_update_event_from_notification_node(&invalid_phone_number, &parsed).is_err());
    }

    #[tokio::test]
    async fn processes_group_notification_to_group_update_event_and_ack() {
        let notification = BinaryNode::new("notification")
            .with_attr("id", "g1")
            .with_attr("from", "123@g.us")
            .with_attr("type", "w:gp2")
            .with_content(vec![
                BinaryNode::new("not_announcement"),
                BinaryNode::new("remove").with_content(vec![
                    BinaryNode::new("participant").with_attr("jid", "111@s.whatsapp.net"),
                ]),
            ]);
        let mut buffer = test_buffer();

        let result = process_inbound_node(
            &notification,
            "999@s.whatsapp.net",
            None,
            Some("999@s.whatsapp.net"),
            &PassthroughDecryptor,
            &mut buffer,
        )
        .await
        .unwrap();

        assert_eq!(result.action, InboundNodeAction::Notification);
        assert_eq!(result.event_count, 2);
        assert!(result.error.is_none());
        let ack = result.response.unwrap();
        assert_eq!(ack.tag, "ack");
        assert_eq!(ack.attrs["class"], "notification");
        assert_eq!(ack.attrs["to"], "123@g.us");

        let events = buffer.drain_events();
        assert_eq!(events.len(), 2);
        assert!(matches!(&events[0], Event::Node(node) if node == &notification));
        let Event::Batch(batch) = &events[1] else {
            panic!("expected group update batch");
        };
        assert_eq!(batch.groups_update.len(), 1);
        assert_eq!(batch.groups_update[0].jid, "123@g.us");
        assert_eq!(batch.groups_update[0].fields["announce"], "false");
        assert_eq!(
            batch.groups_update[0].fields["participants_remove"],
            "111@s.whatsapp.net"
        );
    }

    #[tokio::test]
    async fn ignores_unhandled_node_tags() {
        let mut buffer = test_buffer();
        let result = process_inbound_node(
            &BinaryNode::new("iq"),
            "999@s.whatsapp.net",
            None,
            Some("999@s.whatsapp.net"),
            &PassthroughDecryptor,
            &mut buffer,
        )
        .await
        .unwrap();

        assert_eq!(result, InboundNodeProcessing::ignored());
        assert!(buffer.is_empty());
    }

    fn text_message(text: &str) -> Message {
        Message {
            conversation: Some(text.to_owned()),
            ..Message::default()
        }
    }

    fn encode_proto(message: &Message) -> Bytes {
        let mut out = Vec::new();
        ProstMessage::encode(message, &mut out).unwrap();
        Bytes::from(out)
    }

    fn test_buffer() -> EventBuffer {
        EventBuffer::new(crate::EventBufferConfig {
            max_pending_items: 8,
        })
    }

    struct PassthroughDecryptor;

    #[async_trait]
    impl InboundMessageDecryptor for PassthroughDecryptor {
        async fn decrypt_inbound_message(
            &self,
            payload: crate::InboundEncryptedPayload,
        ) -> CoreResult<Bytes> {
            Ok(payload.ciphertext)
        }
    }
}
