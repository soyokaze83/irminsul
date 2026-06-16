use crate::{
    AccountUpdate, CallEvent, CoreError, CoreResult, DecodedInboundMessage, Event, EventBatch,
    EventBuffer, GroupUpdateEvent, InboundAck, InboundMessageDecryptor, InboundMessageInfo,
    InboundNotification, InboundReceipt, LidMappingEvent, MediaRetryEvent, MediaRetryUpdate,
    MessageEvent, MessageEventKey, MessageUpdate, NackReason, NewsletterParticipantUpdateEvent,
    NewsletterReactionEvent, NewsletterSettingsUpdateEvent, NewsletterViewEvent,
    PLACEHOLDER_NO_MESSAGE_FOUND_ERROR_TEXT, PlaceholderResendRequest, ReceiptEvent,
    build_ack_node, build_nack_node, decode_inbound_message, decode_inbound_message_info,
    encode_message, parse_account_update_notification, parse_inbound_ack,
    parse_inbound_notification, parse_inbound_receipt, parse_media_retry_update,
    parse_newsletter_linked_profile_notification, parse_newsletter_notification_updates,
    placeholder_resend_request_from_web_message,
};
use prost::Message as ProstMessage;
use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};
use wa_binary::{BinaryNode, BinaryNodeContent, jid_decode};
use wa_proto::proto::{
    Message, MessageKey, WebMessageInfo,
    message::{PlaceholderMessage, placeholder_message::PlaceholderType},
    web_message_info::StubType,
};

pub const DEFAULT_OFFLINE_NODE_YIELD_EVERY: usize = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InboundNodeAction {
    Message,
    Receipt,
    Ack,
    Notification,
    Call,
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
    let ack = parse_inbound_ack(node)?;
    let batch = event_batch_from_inbound_ack(&ack)?;
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
            if let Some(batch) = event_batch_from_group_notification_node(node, &notification)? {
                event_count += batch.pending_items();
                buffer.push(Event::Batch(Box::new(batch)))?;
            }
            if let Some(event) =
                account_update_event_from_notification_node(node, current_unix_timestamp())?
            {
                event_count += 1;
                buffer.push(event)?;
            }
            let lid_mappings = lid_mapping_events_from_newsletter_notification_node(node)?;
            if !lid_mappings.is_empty() {
                event_count += lid_mappings.len();
                buffer.push(Event::LidMappingUpdate(lid_mappings))?;
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

fn newsletter_reaction_event_from_child(
    newsletter_jid: &str,
    child: &BinaryNode,
) -> CoreResult<NewsletterReactionEvent> {
    let server_id = required_text(
        "newsletter reaction message id",
        child.attrs.get("message_id").map(String::as_str),
    )?;
    let mut event = NewsletterReactionEvent::new(newsletter_jid, server_id).with_count(1);
    if let Some(code) = child_node(child, "reaction")
        .and_then(node_text)
        .filter(|value| !value.is_empty())
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
        child.attrs.get("message_id").map(String::as_str),
    )?;
    let count_text = node_text(child).unwrap_or_else(|| "0".to_owned());
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

    let mut recognized = false;
    for child in child_nodes(node) {
        recognized |= apply_group_notification_child(child, &mut event)?;
    }

    if recognized {
        Ok(Some(event))
    } else {
        Ok(None)
    }
}

fn apply_group_notification_child(
    child: &BinaryNode,
    event: &mut GroupUpdateEvent,
) -> CoreResult<bool> {
    match child.tag.as_str() {
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
            Ok(true)
        }
        "description" | "desc" => {
            if let Some(description) = attr_or_text(child, &["description", "value", "text"]) {
                event.fields.insert("description".to_owned(), description);
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
        "membership_approval_mode" => {
            if let Some(state) = child
                .attrs
                .get("state")
                .or_else(|| child.attrs.get("value"))
            {
                event
                    .fields
                    .insert("join_approval_mode".to_owned(), state.clone());
            }
            Ok(true)
        }
        "member_add_mode" => {
            if let Some(mode) = child.attrs.get("mode").or_else(|| child.attrs.get("value")) {
                event
                    .fields
                    .insert("member_add_mode".to_owned(), mode.clone());
            }
            Ok(true)
        }
        "add" | "remove" | "promote" | "demote" => {
            let participants = group_notification_participants(child)?;
            if !participants.is_empty() {
                event.fields.insert(
                    format!("participants_{}", child.tag),
                    participants.join(","),
                );
                event.fields.insert(
                    format!("participants_{}_count", child.tag),
                    participants.len().to_string(),
                );
            }
            Ok(true)
        }
        _ => Ok(false),
    }
}

fn group_notification_participants(node: &BinaryNode) -> CoreResult<Vec<String>> {
    child_nodes(node)
        .iter()
        .filter(|child| child.tag == "participant")
        .map(|participant| {
            let jid = required_text(
                "group notification participant JID",
                participant.attrs.get("jid").map(String::as_str),
            )?;
            validate_jid("group notification participant JID", &jid)?;
            Ok(jid)
        })
        .collect()
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
    let mut messages_upsert = vec![message_event_from_decoded(decoded)?];
    if let Some(message) = decoded.last_message() {
        messages_upsert.extend(placeholder_resend_events_from_message(message)?);
    }
    Ok(EventBatch {
        messages_upsert,
        ..EventBatch::default()
    })
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

pub fn event_batch_from_inbound_receipt_node(
    node: &BinaryNode,
    receipt: &InboundReceipt,
) -> CoreResult<EventBatch> {
    let mut batch = event_batch_from_inbound_receipt(receipt)?;
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
    keys.iter()
        .find_map(|key| node.attrs.get(*key).map(String::as_str))
        .filter(|value| !value.is_empty())
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
            ]);
        let parsed = parse_inbound_notification(&notification).unwrap();
        let events =
            newsletter_update_events_from_notification_node(&notification, &parsed).unwrap();

        assert_eq!(events.len(), 5);
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
