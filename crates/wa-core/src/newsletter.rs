use crate::event::{MessageEvent, MessageEventKey};
use crate::message::encode_message;
use crate::mex::{DEFAULT_MAX_WMEX_JSON_BYTES, build_wmex_query, parse_wmex_response};
use crate::{CoreError, CoreResult};
use prost::Message as ProstMessage;
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;
use wa_binary::{BinaryNode, BinaryNodeContent, JidServer, jid_decode, jid_normalized_user};
use wa_proto::proto::Message;

pub const MAX_NEWSLETTER_MESSAGE_FETCH_COUNT: u32 = 100;

const QUERY_CREATE: &str = "8823471724422422";
const QUERY_UPDATE_METADATA: &str = "24250201037901610";
const QUERY_METADATA: &str = "6563316087068696";
const QUERY_SUBSCRIBERS: &str = "9783111038412085";
const QUERY_FOLLOW: &str = "24404358912487870";
const QUERY_UNFOLLOW: &str = "9767147403369991";
const QUERY_MUTE: &str = "29766401636284406";
const QUERY_UNMUTE: &str = "9864994326891137";
const QUERY_ADMIN_COUNT: &str = "7130823597031706";
const QUERY_CHANGE_OWNER: &str = "7341777602580933";
const QUERY_DEMOTE: &str = "6551828931592903";
const QUERY_DELETE: &str = "30062808666639665";

const PATH_CREATE: &str = "xwa2_newsletter_create";
const PATH_UPDATE_METADATA: &str = "xwa2_newsletter_update";
const PATH_METADATA: &str = "xwa2_newsletter";
const PATH_SUBSCRIBERS: &str = "xwa2_newsletter_subscribers";
const PATH_FOLLOW: &str = "xwa2_newsletter_join_v2";
const PATH_UNFOLLOW: &str = "xwa2_newsletter_leave_v2";
const PATH_MUTE: &str = "xwa2_newsletter_mute_v2";
const PATH_UNMUTE: &str = "xwa2_newsletter_unmute_v2";
const PATH_ADMIN_COUNT: &str = "xwa2_newsletter_admin";
const PATH_CHANGE_OWNER: &str = "xwa2_newsletter_change_owner";
const PATH_DEMOTE: &str = "xwa2_newsletter_demote";
const PATH_DELETE: &str = "xwa2_newsletter_delete_v2";
const PATH_NOTIFY_LINKED_PROFILES: &str = "xwa2_notify_linked_profiles";

const OP_LINKED_PROFILE_UPDATES: &str = "NotificationLinkedProfilesUpdates";
const OP_NEWSLETTER_UPDATE: &str = "NotificationNewsletterUpdate";
const OP_NEWSLETTER_ADMIN_PROMOTE: &str = "NotificationNewsletterAdminPromote";

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NewsletterMetadataLookup {
    Invite(String),
    Jid(String),
}

impl NewsletterMetadataLookup {
    #[must_use]
    pub fn invite(code: impl Into<String>) -> Self {
        Self::Invite(code.into())
    }

    #[must_use]
    pub fn jid(jid: impl Into<String>) -> Self {
        Self::Jid(jid.into())
    }

    fn validate(&self) -> CoreResult<(&'static str, &str)> {
        match self {
            Self::Invite(code) => Ok(("INVITE", validate_non_empty("newsletter invite", code)?)),
            Self::Jid(jid) => Ok(("JID", validate_newsletter_jid(jid)?)),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NewsletterAction {
    Follow,
    Unfollow,
    Mute,
    Unmute,
    Delete,
}

impl NewsletterAction {
    fn query_id(self) -> &'static str {
        match self {
            Self::Follow => QUERY_FOLLOW,
            Self::Unfollow => QUERY_UNFOLLOW,
            Self::Mute => QUERY_MUTE,
            Self::Unmute => QUERY_UNMUTE,
            Self::Delete => QUERY_DELETE,
        }
    }

    fn data_path(self) -> &'static str {
        match self {
            Self::Follow => PATH_FOLLOW,
            Self::Unfollow => PATH_UNFOLLOW,
            Self::Mute => PATH_MUTE,
            Self::Unmute => PATH_UNMUTE,
            Self::Delete => PATH_DELETE,
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NewsletterMetadataUpdate {
    pub name: Option<String>,
    pub description: Option<String>,
    pub picture_base64: Option<String>,
}

impl NewsletterMetadataUpdate {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    #[must_use]
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    #[must_use]
    pub fn with_picture_base64(mut self, picture: impl Into<String>) -> Self {
        self.picture_base64 = Some(picture.into());
        self
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.name.is_none() && self.description.is_none() && self.picture_base64.is_none()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NewsletterVerification {
    Verified,
    Unverified,
    Unknown(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NewsletterMuteState {
    On,
    Off,
    Unknown(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NewsletterViewerRole {
    Admin,
    Guest,
    Owner,
    Subscriber,
    Unknown(String),
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NewsletterPicture {
    pub id: Option<String>,
    pub direct_path: Option<String>,
    pub media_key: Option<String>,
    pub url: Option<String>,
    pub kind: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NewsletterReactionCount {
    pub code: String,
    pub count: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NewsletterThreadMetadata {
    pub creation_time: Option<u64>,
    pub name: Option<String>,
    pub description: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NewsletterMetadata {
    pub id: String,
    pub owner: Option<String>,
    pub name: Option<String>,
    pub description: Option<String>,
    pub invite: Option<String>,
    pub creation_time: Option<u64>,
    pub subscribers: Option<u64>,
    pub picture: Option<NewsletterPicture>,
    pub preview: Option<NewsletterPicture>,
    pub verification: Option<NewsletterVerification>,
    pub reaction_codes: Vec<NewsletterReactionCount>,
    pub mute_state: Option<NewsletterMuteState>,
    pub viewer_role: Option<NewsletterViewerRole>,
    pub thread_metadata: Option<NewsletterThreadMetadata>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NewsletterLiveUpdateSubscription {
    pub duration: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NewsletterLinkedProfileMapping {
    pub lid_jid: String,
    pub pn_jid: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NewsletterSettingsNotification {
    pub jid: String,
    pub fields: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NewsletterParticipantNotification {
    pub jid: String,
    pub user_jid: String,
    pub action: String,
    pub new_role: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NewsletterNotificationUpdate {
    Settings(NewsletterSettingsNotification),
    Participant(NewsletterParticipantNotification),
}

pub fn build_newsletter_create_query(
    name: &str,
    description: Option<&str>,
    tag: impl Into<String>,
) -> CoreResult<BinaryNode> {
    let name = validate_non_empty("newsletter name", name)?;
    let variables = json!({
        "input": {
            "name": name,
            "description": description
        }
    });
    build_wmex_query(variables, QUERY_CREATE, tag)
}

pub fn build_newsletter_metadata_query(
    lookup: NewsletterMetadataLookup,
    tag: impl Into<String>,
) -> CoreResult<BinaryNode> {
    let (lookup_type, key) = lookup.validate()?;
    let variables = json!({
        "fetch_creation_time": true,
        "fetch_full_image": true,
        "fetch_viewer_metadata": true,
        "input": {
            "key": key,
            "type": lookup_type
        }
    });
    build_wmex_query(variables, QUERY_METADATA, tag)
}

pub fn build_newsletter_metadata_update_query(
    jid: &str,
    update: NewsletterMetadataUpdate,
    tag: impl Into<String>,
) -> CoreResult<BinaryNode> {
    let jid = validate_newsletter_jid(jid)?;
    if update.is_empty() {
        return Err(CoreError::Payload(
            "newsletter metadata update must include at least one field".to_owned(),
        ));
    }

    let mut updates = Map::new();
    if let Some(name) = update.name {
        updates.insert(
            "name".to_owned(),
            Value::String(validate_non_empty("newsletter name", &name)?.to_owned()),
        );
    }
    if let Some(description) = update.description {
        updates.insert("description".to_owned(), Value::String(description));
    }
    if let Some(picture) = update.picture_base64 {
        updates.insert("picture".to_owned(), Value::String(picture));
    }
    updates.insert("settings".to_owned(), Value::Null);

    build_wmex_query(
        json!({
            "newsletter_id": jid,
            "updates": Value::Object(updates)
        }),
        QUERY_UPDATE_METADATA,
        tag,
    )
}

pub fn build_newsletter_subscribers_query(
    jid: &str,
    tag: impl Into<String>,
) -> CoreResult<BinaryNode> {
    build_newsletter_id_query(jid, QUERY_SUBSCRIBERS, tag)
}

pub fn build_newsletter_admin_count_query(
    jid: &str,
    tag: impl Into<String>,
) -> CoreResult<BinaryNode> {
    build_newsletter_id_query(jid, QUERY_ADMIN_COUNT, tag)
}

pub fn build_newsletter_action_query(
    jid: &str,
    action: NewsletterAction,
    tag: impl Into<String>,
) -> CoreResult<BinaryNode> {
    build_newsletter_id_query(jid, action.query_id(), tag)
}

pub fn build_newsletter_change_owner_query(
    jid: &str,
    new_owner_jid: &str,
    tag: impl Into<String>,
) -> CoreResult<BinaryNode> {
    let jid = validate_newsletter_jid(jid)?;
    let new_owner_jid = validate_account_jid("new newsletter owner JID", new_owner_jid)?;
    build_wmex_query(
        json!({
            "newsletter_id": jid,
            "user_id": new_owner_jid
        }),
        QUERY_CHANGE_OWNER,
        tag,
    )
}

pub fn build_newsletter_demote_query(
    jid: &str,
    user_jid: &str,
    tag: impl Into<String>,
) -> CoreResult<BinaryNode> {
    let jid = validate_newsletter_jid(jid)?;
    let user_jid = validate_account_jid("newsletter demotion user JID", user_jid)?;
    build_wmex_query(
        json!({
            "newsletter_id": jid,
            "user_id": user_jid
        }),
        QUERY_DEMOTE,
        tag,
    )
}

pub fn build_newsletter_message_updates_query(
    jid: &str,
    count: u32,
    since: Option<u64>,
    after: Option<u64>,
    tag: impl Into<String>,
) -> CoreResult<BinaryNode> {
    let jid = validate_newsletter_jid(jid)?;
    if count == 0 || count > MAX_NEWSLETTER_MESSAGE_FETCH_COUNT {
        return Err(CoreError::Payload(format!(
            "newsletter message update count must be between 1 and {MAX_NEWSLETTER_MESSAGE_FETCH_COUNT}"
        )));
    }

    let mut updates = BinaryNode::new("message_updates").with_attr("count", count.to_string());
    if let Some(since) = since {
        updates = updates.with_attr("since", since.to_string());
    }
    if let Some(after) = after {
        updates = updates.with_attr("after", after.to_string());
    }

    Ok(BinaryNode::new("iq")
        .with_attr("id", tag.into())
        .with_attr("type", "get")
        .with_attr("xmlns", "newsletter")
        .with_attr("to", jid)
        .with_content(vec![updates]))
}

pub fn build_newsletter_live_updates_query(
    jid: &str,
    tag: impl Into<String>,
) -> CoreResult<BinaryNode> {
    let jid = validate_newsletter_jid(jid)?;
    Ok(BinaryNode::new("iq")
        .with_attr("id", tag.into())
        .with_attr("type", "set")
        .with_attr("xmlns", "newsletter")
        .with_attr("to", jid)
        .with_content(vec![
            BinaryNode::new("live_updates").with_content(Vec::<BinaryNode>::new()),
        ]))
}

pub fn build_newsletter_reaction_node(
    jid: &str,
    server_id: &str,
    reaction: Option<&str>,
    tag: impl Into<String>,
) -> CoreResult<BinaryNode> {
    let jid = validate_newsletter_jid(jid)?;
    let server_id = validate_non_empty("newsletter message server id", server_id)?;

    let mut node = BinaryNode::new("message")
        .with_attr("to", jid)
        .with_attr("type", "reaction")
        .with_attr("server_id", server_id)
        .with_attr("id", tag.into());
    let reaction_node = if let Some(reaction) = reaction {
        BinaryNode::new("reaction")
            .with_attr("code", validate_non_empty("newsletter reaction", reaction)?)
    } else {
        node = node.with_attr("edit", "7");
        BinaryNode::new("reaction")
    };

    Ok(node.with_content(vec![reaction_node]))
}

pub fn parse_newsletter_create_result(node: &BinaryNode) -> CoreResult<NewsletterMetadata> {
    let value = parse_wmex_response(node, PATH_CREATE)?;
    parse_newsletter_metadata_value(&value)
}

pub fn parse_newsletter_metadata_result(
    node: &BinaryNode,
) -> CoreResult<Option<NewsletterMetadata>> {
    let value = parse_wmex_response(node, PATH_METADATA)?;
    newsletter_metadata_from_value(&value)
}

pub fn parse_newsletter_metadata_update_result(node: &BinaryNode) -> CoreResult<()> {
    parse_wmex_response(node, PATH_UPDATE_METADATA)?;
    Ok(())
}

pub fn parse_newsletter_subscriber_count_result(node: &BinaryNode) -> CoreResult<u64> {
    let value = parse_wmex_response(node, PATH_SUBSCRIBERS)?;
    required_u64_field(&value, "subscribers")
}

pub fn parse_newsletter_admin_count_result(node: &BinaryNode) -> CoreResult<u64> {
    let value = parse_wmex_response(node, PATH_ADMIN_COUNT)?;
    required_u64_field(&value, "admin_count")
}

pub fn parse_newsletter_action_result(
    node: &BinaryNode,
    action: NewsletterAction,
) -> CoreResult<()> {
    parse_wmex_response(node, action.data_path())?;
    Ok(())
}

pub fn parse_newsletter_change_owner_result(node: &BinaryNode) -> CoreResult<()> {
    parse_wmex_response(node, PATH_CHANGE_OWNER)?;
    Ok(())
}

pub fn parse_newsletter_demote_result(node: &BinaryNode) -> CoreResult<()> {
    parse_wmex_response(node, PATH_DEMOTE)?;
    Ok(())
}

pub fn parse_newsletter_reaction_result(node: &BinaryNode) -> CoreResult<()> {
    if node.tag != "message" && node.tag != "iq" {
        return Err(CoreError::Protocol(format!(
            "newsletter reaction response must be message or iq, got {}",
            node.tag
        )));
    }
    match node.attrs.get("type").map(String::as_str) {
        Some("result") => Ok(()),
        Some("error") => Err(CoreError::Protocol(format!(
            "newsletter reaction failed{}",
            stanza_error_suffix(node)
        ))),
        Some(value) => Err(CoreError::Protocol(format!(
            "unexpected newsletter reaction response type: {value}"
        ))),
        None => Err(CoreError::Protocol(
            "newsletter reaction response missing type".to_owned(),
        )),
    }
}

pub fn parse_newsletter_message_updates_result(
    node: &BinaryNode,
    jid: &str,
) -> CoreResult<Vec<MessageEvent>> {
    let jid = validate_newsletter_jid(jid)?;
    let messages = child_node(node, "message_updates")
        .map(child_nodes)
        .unwrap_or_else(|| child_nodes(node));
    let mut events = Vec::new();
    for child in messages.iter().filter(|child| child.tag == "message") {
        if events.len() >= MAX_NEWSLETTER_MESSAGE_FETCH_COUNT as usize {
            return Err(CoreError::Payload(format!(
                "newsletter message update result exceeds {MAX_NEWSLETTER_MESSAGE_FETCH_COUNT} messages"
            )));
        }
        if let Some(event) = newsletter_message_event_from_fetch_child(jid, child)? {
            events.push(event);
        }
    }
    Ok(events)
}

pub fn parse_newsletter_live_update_subscription(
    node: &BinaryNode,
) -> Option<NewsletterLiveUpdateSubscription> {
    let duration = child_node(node, "live_updates")?
        .attrs
        .get("duration")
        .filter(|duration| !duration.trim().is_empty())?
        .clone();
    Some(NewsletterLiveUpdateSubscription { duration })
}

pub fn parse_newsletter_linked_profile_notification(
    node: &BinaryNode,
) -> CoreResult<Vec<NewsletterLinkedProfileMapping>> {
    let Some(update) = child_node(node, "update") else {
        return Ok(Vec::new());
    };
    if !matches!(
        update.content,
        Some(BinaryNodeContent::Bytes(_)) | Some(BinaryNodeContent::Text(_))
    ) {
        return Ok(Vec::new());
    }
    let value = notification_json(update)?;
    let operation = string_field(&value, "operation").or_else(|| {
        update
            .attrs
            .get("op_name")
            .filter(|value| !value.is_empty())
            .cloned()
    });
    if operation.as_deref() != Some(OP_LINKED_PROFILE_UPDATES) {
        return Ok(Vec::new());
    }

    let updates = linked_profile_updates(&value)?;
    let mut mappings = Vec::new();
    for update in updates {
        let Some(lid) = string_field(update, "jid") else {
            continue;
        };
        let lid = validate_lid_jid(&lid)?;
        let Some(profiles) = update.get("added_profiles").and_then(Value::as_array) else {
            continue;
        };
        for profile in profiles {
            if let Some(pn) = linked_profile_pn(profile) {
                mappings.push(NewsletterLinkedProfileMapping {
                    lid_jid: lid.clone(),
                    pn_jid: validate_pn_jid(&pn)?,
                });
            }
        }
    }

    Ok(mappings)
}

fn newsletter_message_event_from_fetch_child(
    newsletter_jid: &str,
    child: &BinaryNode,
) -> CoreResult<Option<MessageEvent>> {
    let Some(plaintext) = child_node(child, "plaintext") else {
        return Ok(None);
    };
    let payload = node_bytes(plaintext, "newsletter fetched plaintext message")?;
    let message = Message::decode(payload).map_err(|err| {
        CoreError::Protocol(format!("invalid newsletter message protobuf: {err}"))
    })?;
    let message_id = child
        .attrs
        .get("message_id")
        .or_else(|| child.attrs.get("server_id"))
        .or_else(|| child.attrs.get("id"))
        .map(String::as_str);
    let message_id = validate_non_empty(
        "newsletter fetched message id",
        message_id.ok_or_else(|| {
            CoreError::Protocol("newsletter fetched message id is missing".to_owned())
        })?,
    )?;

    let mut event = MessageEvent::new(MessageEventKey::new(
        newsletter_jid,
        message_id.to_owned(),
        None,
    ))
    .with_payload(encode_message(&message)?)
    .with_field("kind", "newsletter")
    .with_field("payload_kind", "plaintext")
    .with_field("source", "newsletter_fetch")
    .with_field(
        "from_me",
        child
            .attrs
            .get("from_me")
            .or_else(|| child.attrs.get("fromMe"))
            .map(String::as_str)
            .unwrap_or("false"),
    );
    let timestamp = match optional_u64_attr(child, "t", "newsletter fetched message timestamp")? {
        Some(timestamp) => Some(timestamp),
        None => optional_u64_attr(child, "timestamp", "newsletter fetched message timestamp")?,
    };
    if let Some(timestamp) = timestamp {
        event = event.with_timestamp(timestamp);
    }
    Ok(Some(event))
}

pub fn parse_newsletter_notification_updates(
    node: &BinaryNode,
) -> CoreResult<Vec<NewsletterNotificationUpdate>> {
    let Some(update) = child_node(node, "update") else {
        return Ok(Vec::new());
    };
    if !matches!(
        update.content,
        Some(BinaryNodeContent::Bytes(_)) | Some(BinaryNodeContent::Text(_))
    ) {
        return Ok(Vec::new());
    }
    let value = notification_json(update)?;
    let operation = notification_operation(update, &value);
    match operation.as_deref() {
        Some(OP_NEWSLETTER_UPDATE) => parse_newsletter_settings_notifications(&value),
        Some(OP_NEWSLETTER_ADMIN_PROMOTE) => {
            parse_newsletter_participant_promote_notifications(&value)
        }
        _ => Ok(Vec::new()),
    }
}

fn build_newsletter_id_query(
    jid: &str,
    query_id: &'static str,
    tag: impl Into<String>,
) -> CoreResult<BinaryNode> {
    let jid = validate_newsletter_jid(jid)?;
    build_wmex_query(json!({ "newsletter_id": jid }), query_id, tag)
}

fn newsletter_metadata_from_value(value: &Value) -> CoreResult<Option<NewsletterMetadata>> {
    if value.get("id").and_then(Value::as_str).is_some() {
        return parse_newsletter_metadata_value(value).map(Some);
    }

    if let Some(result) = value.get("result")
        && result.get("id").and_then(Value::as_str).is_some()
    {
        return parse_newsletter_metadata_value(result).map(Some);
    }

    Ok(None)
}

fn parse_newsletter_metadata_value(value: &Value) -> CoreResult<NewsletterMetadata> {
    let id = required_string_field(value, "id")?;
    let thread = value.get("thread_metadata");
    let viewer = value.get("viewer_metadata");

    Ok(NewsletterMetadata {
        id,
        owner: string_field(value, "owner"),
        name: string_field(value, "name")
            .or_else(|| thread.and_then(|node| text_field(node, "name"))),
        description: string_field(value, "description")
            .or_else(|| thread.and_then(|node| text_field(node, "description"))),
        invite: string_field(value, "invite")
            .or_else(|| thread.and_then(|node| string_field(node, "invite"))),
        creation_time: u64_field(value, "creation_time")
            .or_else(|| thread.and_then(|node| u64_field(node, "creation_time"))),
        subscribers: u64_field(value, "subscribers")
            .or_else(|| thread.and_then(|node| u64_field(node, "subscribers_count"))),
        picture: value
            .get("picture")
            .or_else(|| thread.and_then(|node| node.get("picture")))
            .and_then(parse_picture),
        preview: value
            .get("preview")
            .or_else(|| thread.and_then(|node| node.get("preview")))
            .and_then(parse_picture),
        verification: string_field(value, "verification")
            .or_else(|| thread.and_then(|node| string_field(node, "verification")))
            .map(|value| match value.as_str() {
                "VERIFIED" => NewsletterVerification::Verified,
                "UNVERIFIED" => NewsletterVerification::Unverified,
                _ => NewsletterVerification::Unknown(value),
            }),
        reaction_codes: parse_reaction_counts(value.get("reaction_codes")),
        mute_state: string_field(value, "mute_state")
            .or_else(|| viewer.and_then(|node| string_field(node, "mute")))
            .map(|value| match value.as_str() {
                "ON" => NewsletterMuteState::On,
                "OFF" => NewsletterMuteState::Off,
                _ => NewsletterMuteState::Unknown(value),
            }),
        viewer_role: viewer
            .and_then(|node| string_field(node, "role"))
            .map(|value| match value.as_str() {
                "ADMIN" => NewsletterViewerRole::Admin,
                "GUEST" => NewsletterViewerRole::Guest,
                "OWNER" => NewsletterViewerRole::Owner,
                "SUBSCRIBER" => NewsletterViewerRole::Subscriber,
                _ => NewsletterViewerRole::Unknown(value),
            }),
        thread_metadata: thread.map(parse_thread_metadata),
    })
}

fn parse_thread_metadata(value: &Value) -> NewsletterThreadMetadata {
    NewsletterThreadMetadata {
        creation_time: u64_field(value, "creation_time"),
        name: text_field(value, "name"),
        description: text_field(value, "description"),
    }
}

fn parse_picture(value: &Value) -> Option<NewsletterPicture> {
    if !value.is_object() {
        return None;
    }

    let picture = NewsletterPicture {
        id: string_field(value, "id"),
        direct_path: string_field(value, "directPath")
            .or_else(|| string_field(value, "direct_path")),
        media_key: string_field(value, "mediaKey").or_else(|| string_field(value, "media_key")),
        url: string_field(value, "url"),
        kind: string_field(value, "type"),
    };

    if picture.id.is_none()
        && picture.direct_path.is_none()
        && picture.media_key.is_none()
        && picture.url.is_none()
        && picture.kind.is_none()
    {
        None
    } else {
        Some(picture)
    }
}

fn parse_reaction_counts(value: Option<&Value>) -> Vec<NewsletterReactionCount> {
    let Some(items) = value.and_then(Value::as_array) else {
        return Vec::new();
    };

    items
        .iter()
        .filter_map(|item| {
            let code = string_field(item, "code")?;
            let count = u64_field(item, "count")?;
            Some(NewsletterReactionCount { code, count })
        })
        .collect()
}

fn linked_profile_updates(value: &Value) -> CoreResult<Vec<&Value>> {
    if let Some(updates) = value.get("updates").and_then(Value::as_array) {
        return Ok(updates.iter().collect());
    }
    let data = value.get("data").and_then(Value::as_object);
    if let Some(payload) = data.and_then(|data| data.get(PATH_NOTIFY_LINKED_PROFILES)) {
        return Ok(match payload {
            Value::Array(updates) => updates.iter().collect(),
            Value::Object(_) => vec![payload],
            _ => Vec::new(),
        });
    }
    Err(CoreError::Protocol(
        "newsletter linked-profile notification missing updates".to_owned(),
    ))
}

fn notification_updates<'a>(value: &'a Value, label: &str) -> CoreResult<Vec<&'a Value>> {
    value
        .get("updates")
        .and_then(Value::as_array)
        .map(|updates| updates.iter().collect())
        .ok_or_else(|| CoreError::Protocol(format!("{label} missing updates")))
}

fn parse_newsletter_settings_notifications(
    value: &Value,
) -> CoreResult<Vec<NewsletterNotificationUpdate>> {
    let mut out = Vec::new();
    for update in notification_updates(value, "newsletter settings notification")? {
        let Some(jid) = string_field(update, "jid") else {
            continue;
        };
        let jid = validate_newsletter_jid(&jid)?.to_owned();
        let Some(settings) = update.get("settings").and_then(Value::as_object) else {
            continue;
        };
        let fields = settings_fields(settings);
        if fields.is_empty() {
            continue;
        }
        out.push(NewsletterNotificationUpdate::Settings(
            NewsletterSettingsNotification { jid, fields },
        ));
    }
    Ok(out)
}

fn parse_newsletter_participant_promote_notifications(
    value: &Value,
) -> CoreResult<Vec<NewsletterNotificationUpdate>> {
    let mut out = Vec::new();
    for update in notification_updates(value, "newsletter admin promotion notification")? {
        let Some(jid) = string_field(update, "jid") else {
            continue;
        };
        let Some(user) = string_field(update, "user") else {
            continue;
        };
        let jid = validate_newsletter_jid(&jid)?.to_owned();
        let user_jid = validate_account_jid("newsletter promoted user JID", &user)?.to_owned();
        out.push(NewsletterNotificationUpdate::Participant(
            NewsletterParticipantNotification {
                jid,
                user_jid,
                action: "promote".to_owned(),
                new_role: "ADMIN".to_owned(),
            },
        ));
    }
    Ok(out)
}

fn settings_fields(settings: &Map<String, Value>) -> BTreeMap<String, String> {
    settings
        .iter()
        .filter_map(|(key, value)| setting_field_value(value).map(|value| (key.clone(), value)))
        .collect()
}

fn setting_field_value(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        Value::Object(object) => object
            .get("text")
            .and_then(Value::as_str)
            .map(str::to_owned),
        Value::Null | Value::Array(_) => None,
    }
}

fn stanza_error_suffix(node: &BinaryNode) -> String {
    let code = node.attrs.get("code").or_else(|| node.attrs.get("error"));
    let text = node.attrs.get("text").or_else(|| node.attrs.get("reason"));
    match (code, text) {
        (Some(code), Some(text)) if !code.is_empty() && !text.is_empty() => {
            format!(" with code {code}: {text}")
        }
        (Some(code), _) if !code.is_empty() => format!(" with code {code}"),
        (_, Some(text)) if !text.is_empty() => format!(": {text}"),
        _ => String::new(),
    }
}

fn linked_profile_pn(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => Some(value.clone()),
        Value::Object(object) => object
            .get("pn")
            .or_else(|| object.get("jid"))
            .and_then(Value::as_str)
            .map(str::to_owned),
        _ => None,
    }
}

fn notification_operation(node: &BinaryNode, value: &Value) -> Option<String> {
    string_field(value, "operation").or_else(|| {
        node.attrs
            .get("op_name")
            .filter(|value| !value.is_empty())
            .cloned()
    })
}

fn notification_json(node: &BinaryNode) -> CoreResult<Value> {
    let bytes = node_bytes(node, "newsletter notification update")?;
    if bytes.len() > DEFAULT_MAX_WMEX_JSON_BYTES {
        return Err(CoreError::Payload(format!(
            "newsletter notification exceeds configured JSON limit: {} bytes exceeds {DEFAULT_MAX_WMEX_JSON_BYTES}",
            bytes.len()
        )));
    }
    let value: Value = serde_json::from_slice(bytes).map_err(|err| {
        CoreError::Protocol(format!("invalid newsletter notification JSON: {err}"))
    })?;
    if let Some(errors) = value.get("errors").and_then(Value::as_array)
        && !errors.is_empty()
    {
        return Err(CoreError::Protocol(
            "newsletter notification includes errors".to_owned(),
        ));
    }
    Ok(value)
}

fn required_string_field(value: &Value, key: &str) -> CoreResult<String> {
    string_field(value, key)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| CoreError::Protocol(format!("newsletter metadata missing {key}")))
}

fn required_u64_field(value: &Value, key: &str) -> CoreResult<u64> {
    u64_field(value, key)
        .ok_or_else(|| CoreError::Protocol(format!("newsletter response missing {key}")))
}

fn string_field(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(Value::as_str).map(str::to_owned)
}

fn text_field(value: &Value, key: &str) -> Option<String> {
    match value.get(key)? {
        Value::String(value) => Some(value.clone()),
        Value::Object(_) => value
            .get(key)
            .and_then(|node| node.get("text"))
            .and_then(Value::as_str)
            .map(str::to_owned),
        _ => None,
    }
}

fn u64_field(value: &Value, key: &str) -> Option<u64> {
    match value.get(key)? {
        Value::Number(number) => number.as_u64(),
        Value::String(value) => value.parse().ok(),
        _ => None,
    }
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
            "{label} content must be JSON bytes or text"
        ))),
        None => Err(CoreError::Protocol(format!("{label} content is missing"))),
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

fn validate_newsletter_jid(jid: &str) -> CoreResult<&str> {
    let decoded = jid_decode(jid)
        .ok_or_else(|| CoreError::Protocol(format!("invalid newsletter JID: {jid}")))?;
    if decoded.server != JidServer::Newsletter {
        return Err(CoreError::Protocol(format!(
            "newsletter JID must use newsletter server: {jid}"
        )));
    }
    Ok(jid)
}

fn validate_account_jid<'a>(label: &str, jid: &'a str) -> CoreResult<&'a str> {
    let decoded =
        jid_decode(jid).ok_or_else(|| CoreError::Protocol(format!("invalid {label}: {jid}")))?;
    if matches!(
        decoded.server,
        JidServer::GUs | JidServer::Broadcast | JidServer::Newsletter | JidServer::Call
    ) {
        return Err(CoreError::Protocol(format!(
            "{label} must be an account or device JID: {jid}"
        )));
    }
    Ok(jid)
}

fn validate_lid_jid(jid: &str) -> CoreResult<String> {
    let decoded = jid_decode(jid)
        .ok_or_else(|| CoreError::Protocol(format!("invalid linked profile LID JID: {jid}")))?;
    if !matches!(decoded.server, JidServer::Lid | JidServer::HostedLid) {
        return Err(CoreError::Protocol(format!(
            "linked profile LID must use LID server: {jid}"
        )));
    }
    Ok(jid_normalized_user(jid).unwrap_or_else(|| jid.to_owned()))
}

fn validate_pn_jid(jid: &str) -> CoreResult<String> {
    let decoded = jid_decode(jid)
        .ok_or_else(|| CoreError::Protocol(format!("invalid linked profile PN JID: {jid}")))?;
    if matches!(
        decoded.server,
        JidServer::GUs
            | JidServer::Broadcast
            | JidServer::Newsletter
            | JidServer::Call
            | JidServer::Lid
            | JidServer::HostedLid
    ) {
        return Err(CoreError::Protocol(format!(
            "linked profile PN must use an account server: {jid}"
        )));
    }
    Ok(jid_normalized_user(jid).unwrap_or_else(|| jid.to_owned()))
}

fn validate_non_empty<'a>(label: &str, value: &'a str) -> CoreResult<&'a str> {
    if value.trim().is_empty() {
        return Err(CoreError::Protocol(format!("{label} must not be empty")));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message as ProstMessage;
    use serde_json::Value;
    use wa_proto::proto::Message;

    #[test]
    fn builds_wmex_newsletter_queries() {
        let metadata =
            build_newsletter_metadata_query(NewsletterMetadataLookup::jid("abc@newsletter"), "q-1")
                .unwrap();
        assert_eq!(metadata.attrs["xmlns"], "w:mex");
        assert_eq!(metadata.attrs["to"], "s.whatsapp.net");
        let (query_id, variables) = wmex_query_parts(&metadata);
        assert_eq!(query_id, QUERY_METADATA);
        assert_eq!(variables["input"]["key"], "abc@newsletter");
        assert_eq!(variables["input"]["type"], "JID");
        assert_eq!(variables["fetch_full_image"], true);

        let follow =
            build_newsletter_action_query("abc@newsletter", NewsletterAction::Follow, "q-2")
                .unwrap();
        let (query_id, variables) = wmex_query_parts(&follow);
        assert_eq!(query_id, QUERY_FOLLOW);
        assert_eq!(variables["newsletter_id"], "abc@newsletter");

        let update = NewsletterMetadataUpdate::new()
            .with_name("New name")
            .with_picture_base64("");
        let update_node =
            build_newsletter_metadata_update_query("abc@newsletter", update, "q-3").unwrap();
        let (query_id, variables) = wmex_query_parts(&update_node);
        assert_eq!(query_id, QUERY_UPDATE_METADATA);
        assert_eq!(variables["updates"]["name"], "New name");
        assert_eq!(variables["updates"]["picture"], "");
        assert_eq!(variables["updates"]["settings"], Value::Null);
    }

    #[test]
    fn builds_direct_newsletter_queries() {
        let messages = build_newsletter_message_updates_query(
            "abc@newsletter",
            20,
            Some(100),
            Some(200),
            "q-4",
        )
        .unwrap();
        assert_eq!(messages.attrs["xmlns"], "newsletter");
        assert_eq!(messages.attrs["type"], "get");
        let updates = child_node(&messages, "message_updates").unwrap();
        assert_eq!(updates.attrs["count"], "20");
        assert_eq!(updates.attrs["since"], "100");
        assert_eq!(updates.attrs["after"], "200");

        let live = build_newsletter_live_updates_query("abc@newsletter", "q-5").unwrap();
        assert_eq!(live.attrs["type"], "set");
        assert!(child_node(&live, "live_updates").is_some());

        let react =
            build_newsletter_reaction_node("abc@newsletter", "server-1", Some("+"), "q-6").unwrap();
        assert_eq!(react.tag, "message");
        assert_eq!(react.attrs["type"], "reaction");
        assert_eq!(react.attrs["server_id"], "server-1");
        assert_eq!(child_node(&react, "reaction").unwrap().attrs["code"], "+");

        let clear =
            build_newsletter_reaction_node("abc@newsletter", "server-1", None, "q-7").unwrap();
        assert_eq!(clear.attrs["edit"], "7");
        assert!(
            !child_node(&clear, "reaction")
                .unwrap()
                .attrs
                .contains_key("code")
        );
    }

    #[test]
    fn parses_metadata_and_counts() {
        let metadata_response = wmex_response(
            PATH_METADATA,
            r#"{
                "result": {
                    "id": "abc@newsletter",
                    "thread_metadata": {
                        "creation_time": "1700000000",
                        "name": { "text": "Channel" },
                        "description": { "text": "Updates" },
                        "invite": "invite-code",
                        "picture": { "id": "pic", "direct_path": "/p" },
                        "preview": { "id": "preview", "direct_path": "/small" },
                        "subscribers_count": "42",
                        "verification": "VERIFIED"
                    },
                    "viewer_metadata": {
                        "mute": "OFF",
                        "role": "SUBSCRIBER"
                    },
                    "reaction_codes": [{ "code": "+", "count": 3 }]
                }
            }"#,
        );
        let metadata = parse_newsletter_metadata_result(&metadata_response)
            .unwrap()
            .unwrap();
        assert_eq!(metadata.id, "abc@newsletter");
        assert_eq!(metadata.name.as_deref(), Some("Channel"));
        assert_eq!(metadata.description.as_deref(), Some("Updates"));
        assert_eq!(metadata.creation_time, Some(1_700_000_000));
        assert_eq!(metadata.subscribers, Some(42));
        assert_eq!(metadata.picture.unwrap().direct_path.as_deref(), Some("/p"));
        assert_eq!(
            metadata.verification,
            Some(NewsletterVerification::Verified)
        );
        assert_eq!(metadata.mute_state, Some(NewsletterMuteState::Off));
        assert_eq!(metadata.viewer_role, Some(NewsletterViewerRole::Subscriber));
        assert_eq!(metadata.reaction_codes[0].count, 3);

        let create_response = wmex_response(
            PATH_CREATE,
            r#"{
                "id": "created@newsletter",
                "thread_metadata": {
                    "name": { "text": "Created" },
                    "creation_time": "170",
                    "subscribers_count": "0"
                },
                "viewer_metadata": { "mute": "ON", "role": "OWNER" }
            }"#,
        );
        let created = parse_newsletter_create_result(&create_response).unwrap();
        assert_eq!(created.name.as_deref(), Some("Created"));
        assert_eq!(created.mute_state, Some(NewsletterMuteState::On));
        assert_eq!(created.viewer_role, Some(NewsletterViewerRole::Owner));

        let subscribers = wmex_response(PATH_SUBSCRIBERS, r#"{ "subscribers": 12 }"#);
        assert_eq!(
            parse_newsletter_subscriber_count_result(&subscribers).unwrap(),
            12
        );
        let admins = wmex_response(PATH_ADMIN_COUNT, r#"{ "admin_count": "2" }"#);
        assert_eq!(parse_newsletter_admin_count_result(&admins).unwrap(), 2);
    }

    #[test]
    fn parses_newsletter_message_update_results_to_message_events() {
        let response = BinaryNode::new("iq").with_content(vec![
            BinaryNode::new("message_updates").with_content(vec![
                BinaryNode::new("message")
                    .with_attr("message_id", "server-1")
                    .with_attr("t", "1700000000")
                    .with_content(vec![
                        BinaryNode::new("plaintext")
                            .with_content(text_message("first").encode_to_vec()),
                    ]),
                BinaryNode::new("ignored"),
                BinaryNode::new("message")
                    .with_attr("server_id", "server-2")
                    .with_attr("timestamp", "1700000001")
                    .with_attr("from_me", "true")
                    .with_content(vec![
                        BinaryNode::new("plaintext")
                            .with_content(text_message("second").encode_to_vec()),
                    ]),
                BinaryNode::new("message").with_attr("server_id", "skipped"),
            ]),
        ]);

        let events = parse_newsletter_message_updates_result(&response, "abc@newsletter").unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].key.remote_jid, "abc@newsletter");
        assert_eq!(events[0].key.id, "server-1");
        assert_eq!(events[0].timestamp, Some(1_700_000_000));
        assert_eq!(events[0].fields["kind"], "newsletter");
        assert_eq!(events[0].fields["payload_kind"], "plaintext");
        assert_eq!(events[0].fields["source"], "newsletter_fetch");
        assert_eq!(events[0].fields["from_me"], "false");
        let decoded = Message::decode(events[0].payload.clone().unwrap()).unwrap();
        assert_eq!(decoded.conversation.as_deref(), Some("first"));

        assert_eq!(events[1].key.id, "server-2");
        assert_eq!(events[1].timestamp, Some(1_700_000_001));
        assert_eq!(events[1].fields["from_me"], "true");
        let decoded = Message::decode(events[1].payload.clone().unwrap()).unwrap();
        assert_eq!(decoded.conversation.as_deref(), Some("second"));
    }

    #[test]
    fn parses_newsletter_reaction_results() {
        let ok = BinaryNode::new("message").with_attr("type", "result");
        assert!(parse_newsletter_reaction_result(&ok).is_ok());

        let error = BinaryNode::new("message")
            .with_attr("type", "error")
            .with_attr("code", "403")
            .with_attr("text", "denied");
        assert!(matches!(
            parse_newsletter_reaction_result(&error),
            Err(CoreError::Protocol(message))
                if message == "newsletter reaction failed with code 403: denied"
        ));

        let invalid = BinaryNode::new("notification").with_attr("type", "result");
        assert!(parse_newsletter_reaction_result(&invalid).is_err());
    }

    #[test]
    fn validates_newsletter_message_update_results() {
        let invalid_proto = BinaryNode::new("iq").with_content(vec![
            BinaryNode::new("message_updates").with_content(vec![
                BinaryNode::new("message")
                    .with_attr("message_id", "server-1")
                    .with_content(vec![BinaryNode::new("plaintext").with_content(vec![0xff])]),
            ]),
        ]);
        assert!(parse_newsletter_message_updates_result(&invalid_proto, "abc@newsletter").is_err());

        let missing_id = BinaryNode::new("iq").with_content(vec![
            BinaryNode::new("message_updates").with_content(vec![
                BinaryNode::new("message").with_content(vec![
                    BinaryNode::new("plaintext")
                        .with_content(text_message("missing").encode_to_vec()),
                ]),
            ]),
        ]);
        assert!(parse_newsletter_message_updates_result(&missing_id, "abc@newsletter").is_err());

        let oversized = BinaryNode::new("iq").with_content(vec![
            BinaryNode::new("message_updates").with_content(
                (0..=MAX_NEWSLETTER_MESSAGE_FETCH_COUNT)
                    .map(|index| {
                        BinaryNode::new("message")
                            .with_attr("message_id", format!("server-{index}"))
                            .with_content(vec![
                                BinaryNode::new("plaintext")
                                    .with_content(text_message("overflow").encode_to_vec()),
                            ])
                    })
                    .collect::<Vec<_>>(),
            ),
        ]);
        assert!(parse_newsletter_message_updates_result(&oversized, "abc@newsletter").is_err());
        assert!(parse_newsletter_message_updates_result(&oversized, "123@s.whatsapp.net").is_err());
    }

    #[test]
    fn parses_live_update_duration_and_validates_inputs() {
        let response = BinaryNode::new("iq").with_content(vec![
            BinaryNode::new("live_updates").with_attr("duration", "3600"),
        ]);
        assert_eq!(
            parse_newsletter_live_update_subscription(&response),
            Some(NewsletterLiveUpdateSubscription {
                duration: "3600".to_owned()
            })
        );

        assert!(
            build_newsletter_action_query("123@s.whatsapp.net", NewsletterAction::Mute, "q")
                .is_err()
        );
        assert!(
            build_newsletter_message_updates_query(
                "abc@newsletter",
                MAX_NEWSLETTER_MESSAGE_FETCH_COUNT + 1,
                None,
                None,
                "q"
            )
            .is_err()
        );
        assert!(
            build_newsletter_metadata_update_query(
                "abc@newsletter",
                NewsletterMetadataUpdate::new(),
                "q"
            )
            .is_err()
        );
    }

    #[test]
    fn parses_linked_profile_notifications() {
        let notification = BinaryNode::new("notification").with_content(vec![
            BinaryNode::new("update")
                .with_attr("op_name", OP_LINKED_PROFILE_UPDATES)
                .with_content(
                    br#"{"data":{"xwa2_notify_linked_profiles":{"jid":"abc:7@lid","added_profiles":["123@c.us",{"pn":"456@s.whatsapp.net"},{"jid":"789@s.whatsapp.net"}]}}}"#.to_vec(),
                ),
        ]);
        let mappings = parse_newsletter_linked_profile_notification(&notification).unwrap();
        assert_eq!(
            mappings,
            vec![
                NewsletterLinkedProfileMapping {
                    lid_jid: "abc@lid".to_owned(),
                    pn_jid: "123@s.whatsapp.net".to_owned(),
                },
                NewsletterLinkedProfileMapping {
                    lid_jid: "abc@lid".to_owned(),
                    pn_jid: "456@s.whatsapp.net".to_owned(),
                },
                NewsletterLinkedProfileMapping {
                    lid_jid: "abc@lid".to_owned(),
                    pn_jid: "789@s.whatsapp.net".to_owned(),
                },
            ]
        );

        let notification = BinaryNode::new("notification").with_content(vec![
            BinaryNode::new("update").with_content(
                br#"{"operation":"NotificationLinkedProfilesUpdates","updates":[{"jid":"def@hosted.lid","added_profiles":[{"jid":"321@s.whatsapp.net"}]}]}"#.to_vec(),
            ),
        ]);
        let mappings = parse_newsletter_linked_profile_notification(&notification).unwrap();
        assert_eq!(
            mappings,
            vec![NewsletterLinkedProfileMapping {
                lid_jid: "def@hosted.lid".to_owned(),
                pn_jid: "321@s.whatsapp.net".to_owned(),
            }]
        );

        let ignored = BinaryNode::new("notification").with_content(vec![
            BinaryNode::new("update")
                .with_attr("op_name", "OtherOperation")
                .with_content(br#"{"updates":[]}"#.to_vec()),
        ]);
        assert!(
            parse_newsletter_linked_profile_notification(&ignored)
                .unwrap()
                .is_empty()
        );

        let settings_update = BinaryNode::new("notification").with_content(vec![
            BinaryNode::new("update").with_content(vec![
                BinaryNode::new("settings")
                    .with_content(vec![BinaryNode::new("name").with_content("Updates")]),
            ]),
        ]);
        assert!(
            parse_newsletter_linked_profile_notification(&settings_update)
                .unwrap()
                .is_empty()
        );

        let invalid = BinaryNode::new("notification").with_content(vec![
            BinaryNode::new("update")
                .with_attr("op_name", OP_LINKED_PROFILE_UPDATES)
                .with_content(
                    br#"{"updates":[{"jid":"123@s.whatsapp.net","added_profiles":["456@s.whatsapp.net"]}]}"#.to_vec(),
                ),
        ]);
        assert!(parse_newsletter_linked_profile_notification(&invalid).is_err());
    }

    #[test]
    fn parses_newsletter_mex_update_notifications() {
        let settings = BinaryNode::new("notification").with_content(vec![
            BinaryNode::new("update")
                .with_attr("op_name", OP_NEWSLETTER_UPDATE)
                .with_content(
                    br#"{"updates":[{"jid":"abc@newsletter","settings":{"name":{"text":"Updates"},"description":"Daily notes","muted":true,"revision":7,"ignored":null}}]}"#.to_vec(),
                ),
        ]);
        let updates = parse_newsletter_notification_updates(&settings).unwrap();
        assert_eq!(updates.len(), 1);
        let NewsletterNotificationUpdate::Settings(update) = &updates[0] else {
            panic!("expected newsletter settings update");
        };
        assert_eq!(update.jid, "abc@newsletter");
        assert_eq!(update.fields["name"], "Updates");
        assert_eq!(update.fields["description"], "Daily notes");
        assert_eq!(update.fields["muted"], "true");
        assert_eq!(update.fields["revision"], "7");
        assert!(!update.fields.contains_key("ignored"));

        let promote = BinaryNode::new("notification").with_content(vec![
            BinaryNode::new("update").with_content(
                br#"{"operation":"NotificationNewsletterAdminPromote","updates":[{"jid":"abc@newsletter","user":"222@s.whatsapp.net"}]}"#.to_vec(),
            ),
        ]);
        let updates = parse_newsletter_notification_updates(&promote).unwrap();
        assert_eq!(
            updates,
            vec![NewsletterNotificationUpdate::Participant(
                NewsletterParticipantNotification {
                    jid: "abc@newsletter".to_owned(),
                    user_jid: "222@s.whatsapp.net".to_owned(),
                    action: "promote".to_owned(),
                    new_role: "ADMIN".to_owned(),
                }
            )]
        );

        let ignored = BinaryNode::new("notification").with_content(vec![
            BinaryNode::new("update")
                .with_attr("op_name", "OtherOperation")
                .with_content(br#"{"updates":[]}"#.to_vec()),
        ]);
        assert!(
            parse_newsletter_notification_updates(&ignored)
                .unwrap()
                .is_empty()
        );

        let direct_settings_update = BinaryNode::new("notification").with_content(vec![
            BinaryNode::new("update").with_content(vec![
                BinaryNode::new("settings")
                    .with_content(vec![BinaryNode::new("name").with_content("Updates")]),
            ]),
        ]);
        assert!(
            parse_newsletter_notification_updates(&direct_settings_update)
                .unwrap()
                .is_empty()
        );

        let invalid = BinaryNode::new("notification").with_content(vec![
            BinaryNode::new("update")
                .with_attr("op_name", OP_NEWSLETTER_ADMIN_PROMOTE)
                .with_content(
                    br#"{"updates":[{"jid":"abc@newsletter","user":"bad@newsletter"}]}"#.to_vec(),
                ),
        ]);
        assert!(parse_newsletter_notification_updates(&invalid).is_err());
    }

    fn wmex_query_parts(node: &BinaryNode) -> (&str, Value) {
        let query = child_node(node, "query").unwrap();
        let bytes = match query.content.as_ref().unwrap() {
            BinaryNodeContent::Bytes(bytes) => bytes.as_ref(),
            BinaryNodeContent::Text(text) => text.as_bytes(),
            BinaryNodeContent::Nodes(_) => panic!("unexpected query nodes"),
        };
        let value: Value = serde_json::from_slice(bytes).unwrap();
        (query.attrs["query_id"].as_str(), value["variables"].clone())
    }

    fn wmex_response(path: &str, payload: &str) -> BinaryNode {
        BinaryNode::new("iq")
            .with_content(vec![BinaryNode::new("result").with_content(
                format!(r#"{{"data":{{"{path}":{payload}}}}}"#).into_bytes(),
            )])
    }

    fn text_message(text: &str) -> Message {
        Message {
            conversation: Some(text.to_owned()),
            ..Message::default()
        }
    }
}
