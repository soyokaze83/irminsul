use crate::{CoreError, CoreResult};
use bytes::Bytes;
use std::collections::BTreeMap;
use wa_binary::jid::S_WHATSAPP_NET;
use wa_binary::{
    BinaryNode, BinaryNodeContent, JidServer, jid_decode, jid_encode, jid_normalized_user,
};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum PrivacyCategory {
    Messages,
    CallAdd,
    LastSeen,
    Online,
    Profile,
    Status,
    ReadReceipts,
    GroupAdd,
}

impl PrivacyCategory {
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Messages => "messages",
            Self::CallAdd => "calladd",
            Self::LastSeen => "last",
            Self::Online => "online",
            Self::Profile => "profile",
            Self::Status => "status",
            Self::ReadReceipts => "readreceipts",
            Self::GroupAdd => "groupadd",
        }
    }

    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "messages" => Some(Self::Messages),
            "calladd" => Some(Self::CallAdd),
            "last" => Some(Self::LastSeen),
            "online" => Some(Self::Online),
            "profile" => Some(Self::Profile),
            "status" => Some(Self::Status),
            "readreceipts" => Some(Self::ReadReceipts),
            "groupadd" => Some(Self::GroupAdd),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrivacyValue {
    All,
    Contacts,
    ContactBlacklist,
    None,
    MatchLastSeen,
    Known,
}

impl PrivacyValue {
    #[must_use]
    pub fn value(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Contacts => "contacts",
            Self::ContactBlacklist => "contact_blacklist",
            Self::None => "none",
            Self::MatchLastSeen => "match_last_seen",
            Self::Known => "known",
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PrivacySettings {
    pub known: BTreeMap<PrivacyCategory, String>,
    pub unknown: BTreeMap<String, String>,
}

impl PrivacySettings {
    #[must_use]
    pub fn get(&self, category: PrivacyCategory) -> Option<&str> {
        self.known.get(&category).map(String::as_str)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProfilePictureType {
    Preview,
    Image,
}

impl ProfilePictureType {
    #[must_use]
    pub fn value(self) -> &'static str {
        match self {
            Self::Preview => "preview",
            Self::Image => "image",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PresenceState {
    Available,
    Unavailable,
    Composing,
    Recording,
    Paused,
}

impl PresenceState {
    #[must_use]
    pub fn value(self) -> &'static str {
        match self {
            Self::Available => "available",
            Self::Unavailable => "unavailable",
            Self::Composing => "composing",
            Self::Recording => "recording",
            Self::Paused => "paused",
        }
    }

    #[must_use]
    pub fn is_online_presence(self) -> bool {
        matches!(self, Self::Available | Self::Unavailable)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlocklistAction {
    Block,
    Unblock,
}

impl BlocklistAction {
    #[must_use]
    pub fn value(self) -> &'static str {
        match self {
            Self::Block => "block",
            Self::Unblock => "unblock",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccountJidKind {
    PhoneNumber,
    Lid,
    Other,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccountMutationKind {
    PrivacySetting,
    DefaultDisappearingMode,
    ProfileStatus,
    ProfilePicture,
    Blocklist,
}

impl AccountMutationKind {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::PrivacySetting => "privacy setting mutation",
            Self::DefaultDisappearingMode => "default disappearing-mode mutation",
            Self::ProfileStatus => "profile status mutation",
            Self::ProfilePicture => "profile picture mutation",
            Self::Blocklist => "blocklist mutation",
        }
    }
}

pub fn build_privacy_settings_query(tag: impl Into<String>) -> BinaryNode {
    iq_node("privacy", "get", tag, vec![BinaryNode::new("privacy")])
}

pub fn build_privacy_update_query(
    category: PrivacyCategory,
    value: PrivacyValue,
    tag: impl Into<String>,
) -> BinaryNode {
    iq_node(
        "privacy",
        "set",
        tag,
        vec![BinaryNode::new("privacy").with_content(vec![
            BinaryNode::new("category")
                .with_attr("name", category.name())
                .with_attr("value", value.value()),
        ])],
    )
}

pub fn parse_privacy_settings(node: &BinaryNode) -> PrivacySettings {
    let mut settings = PrivacySettings::default();
    let Some(privacy) = child_node(node, "privacy") else {
        return settings;
    };
    for category in child_nodes(privacy)
        .iter()
        .filter(|child| child.tag == "category")
    {
        let Some(name) = category.attrs.get("name") else {
            continue;
        };
        let Some(value) = category.attrs.get("value") else {
            continue;
        };
        if let Some(category) = PrivacyCategory::from_name(name) {
            settings.known.insert(category, value.clone());
        } else {
            settings.unknown.insert(name.clone(), value.clone());
        }
    }
    settings
}

pub fn build_default_disappearing_mode_query(
    duration_seconds: u32,
    tag: impl Into<String>,
) -> BinaryNode {
    iq_node(
        "disappearing_mode",
        "set",
        tag,
        vec![
            BinaryNode::new("disappearing_mode")
                .with_attr("duration", duration_seconds.to_string()),
        ],
    )
}

pub fn build_profile_status_update_query(
    status: impl AsRef<str>,
    tag: impl Into<String>,
) -> CoreResult<BinaryNode> {
    let status = validate_non_empty("profile status", status.as_ref())?;
    Ok(iq_node(
        "status",
        "set",
        tag,
        vec![BinaryNode::new("status").with_content(Bytes::from(status.as_bytes().to_vec()))],
    ))
}

pub fn build_profile_picture_url_query(
    target_jid: impl AsRef<str>,
    picture_type: ProfilePictureType,
    tag: impl Into<String>,
) -> CoreResult<BinaryNode> {
    let target = normalize_target_jid(target_jid.as_ref())?;
    Ok(BinaryNode::new("iq")
        .with_attr("id", tag.into())
        .with_attr("target", target)
        .with_attr("to", S_WHATSAPP_NET)
        .with_attr("type", "get")
        .with_attr("xmlns", "w:profile:picture")
        .with_content(vec![
            BinaryNode::new("picture")
                .with_attr("type", picture_type.value())
                .with_attr("query", "url"),
        ]))
}

pub fn parse_profile_picture_url(node: &BinaryNode) -> Option<String> {
    child_node(node, "picture").and_then(|picture| picture.attrs.get("url").cloned())
}

pub fn parse_profile_picture_mutation_result(node: &BinaryNode) -> CoreResult<()> {
    parse_account_mutation_result(node, AccountMutationKind::ProfilePicture)
}

pub fn parse_account_mutation_result(
    node: &BinaryNode,
    mutation: AccountMutationKind,
) -> CoreResult<()> {
    let label = mutation.label();
    if node.tag != "iq" {
        return Err(CoreError::Protocol(format!(
            "{label} response must be iq, got {}",
            node.tag,
        )));
    }
    match node.attrs.get("type").map(String::as_str) {
        Some("result") => Ok(()),
        Some("error") => Err(CoreError::Protocol(format!(
            "{label} failed{}",
            stanza_error_suffix(node),
        ))),
        Some(value) => Err(CoreError::Protocol(format!(
            "unexpected {label} response type: {value}"
        ))),
        None => Err(CoreError::Protocol(format!(
            "{label} response missing type"
        ))),
    }
}

pub fn build_profile_picture_update_query(
    target_jid: Option<&str>,
    image: impl Into<Bytes>,
    tag: impl Into<String>,
) -> CoreResult<BinaryNode> {
    let image = image.into();
    if image.is_empty() {
        return Err(CoreError::Payload(
            "profile picture update image must not be empty".to_owned(),
        ));
    }
    let mut node = profile_picture_set_iq(tag);
    if let Some(target) = target_jid {
        node = node.with_attr("target", normalize_target_jid(target)?);
    }
    Ok(node.with_content(vec![
        BinaryNode::new("picture")
            .with_attr("type", "image")
            .with_content(image),
    ]))
}

pub fn build_profile_picture_remove_query(
    target_jid: Option<&str>,
    tag: impl Into<String>,
) -> CoreResult<BinaryNode> {
    let mut node = profile_picture_set_iq(tag);
    if let Some(target) = target_jid {
        node = node.with_attr("target", normalize_target_jid(target)?);
    }
    Ok(node)
}

pub fn build_blocklist_query(tag: impl Into<String>) -> BinaryNode {
    BinaryNode::new("iq")
        .with_attr("id", tag.into())
        .with_attr("xmlns", "blocklist")
        .with_attr("to", S_WHATSAPP_NET)
        .with_attr("type", "get")
}

pub fn parse_blocklist(node: &BinaryNode) -> Vec<String> {
    child_node(node, "list")
        .map(|list| {
            child_nodes(list)
                .iter()
                .filter(|child| child.tag == "item")
                .filter_map(|item| item.attrs.get("jid").cloned())
                .collect()
        })
        .unwrap_or_default()
}

pub fn build_blocklist_update_query(
    lid_jid: impl AsRef<str>,
    action: BlocklistAction,
    pn_jid: Option<&str>,
    tag: impl Into<String>,
) -> CoreResult<BinaryNode> {
    let lid_jid = validate_lid_jid(lid_jid.as_ref())?;
    let mut item = BinaryNode::new("item")
        .with_attr("action", action.value())
        .with_attr("jid", lid_jid);
    if action == BlocklistAction::Block {
        let pn_jid = pn_jid.ok_or_else(|| {
            CoreError::Protocol("blocklist block action requires a PN JID".to_owned())
        })?;
        item = item.with_attr("pn_jid", validate_pn_jid(pn_jid)?);
    }
    Ok(iq_node("blocklist", "set", tag, vec![item]))
}

pub fn build_presence_update_node(
    state: PresenceState,
    display_name: impl AsRef<str>,
) -> CoreResult<BinaryNode> {
    if !state.is_online_presence() {
        return Err(CoreError::Protocol(
            "presence update node only supports available or unavailable".to_owned(),
        ));
    }
    let display_name = validate_non_empty("presence display name", display_name.as_ref())?;
    Ok(BinaryNode::new("presence")
        .with_attr("name", display_name.replace('@', ""))
        .with_attr("type", state.value()))
}

pub fn build_chat_state_node(
    state: PresenceState,
    own_jid: impl AsRef<str>,
    own_lid: Option<&str>,
    to_jid: impl AsRef<str>,
) -> CoreResult<BinaryNode> {
    if state.is_online_presence() {
        return Err(CoreError::Protocol(
            "chat state node does not support available or unavailable".to_owned(),
        ));
    }
    let to_jid = validate_jid("chat state target JID", to_jid.as_ref())?;
    let decoded_to = jid_decode(to_jid)
        .ok_or_else(|| CoreError::Protocol(format!("invalid chat state target JID: {to_jid}")))?;
    let from = if decoded_to.server == JidServer::Lid {
        own_lid.ok_or_else(|| {
            CoreError::Protocol("chat state to LID target requires own LID".to_owned())
        })?
    } else {
        own_jid.as_ref()
    };
    validate_jid("chat state sender JID", from)?;

    let state_node = if state == PresenceState::Recording {
        BinaryNode::new("composing").with_attr("media", "audio")
    } else {
        BinaryNode::new(state.value())
    };

    Ok(BinaryNode::new("chatstate")
        .with_attr("from", from)
        .with_attr("to", to_jid)
        .with_content(vec![state_node]))
}

pub fn build_presence_subscribe_node(
    to_jid: impl AsRef<str>,
    tag: impl Into<String>,
) -> CoreResult<BinaryNode> {
    let to_jid = validate_jid("presence subscribe JID", to_jid.as_ref())?;
    Ok(BinaryNode::new("presence")
        .with_attr("to", to_jid)
        .with_attr("id", tag.into())
        .with_attr("type", "subscribe"))
}

pub fn account_jid_kind(jid: impl AsRef<str>) -> CoreResult<AccountJidKind> {
    let jid = normalize_target_jid(jid.as_ref())?;
    let decoded = jid_decode(&jid)
        .ok_or_else(|| CoreError::Protocol(format!("invalid account JID: {jid}")))?;
    Ok(match decoded.server {
        JidServer::SWhatsAppNet | JidServer::Hosted => AccountJidKind::PhoneNumber,
        JidServer::Lid | JidServer::HostedLid => AccountJidKind::Lid,
        _ => AccountJidKind::Other,
    })
}

pub fn normalize_account_jid(jid: impl AsRef<str>) -> CoreResult<String> {
    normalize_target_jid(jid.as_ref())
}

pub fn pn_user_jid(user: impl AsRef<str>) -> CoreResult<String> {
    let user = validate_non_empty("PN user", user.as_ref())?;
    Ok(jid_encode(user, JidServer::SWhatsAppNet, None, None))
}

pub fn lid_user_jid(user: impl AsRef<str>) -> CoreResult<String> {
    let user = validate_non_empty("LID user", user.as_ref())?;
    Ok(jid_encode(user, JidServer::Lid, None, None))
}

fn iq_node(
    xmlns: &'static str,
    query_type: &'static str,
    tag: impl Into<String>,
    content: Vec<BinaryNode>,
) -> BinaryNode {
    BinaryNode::new("iq")
        .with_attr("id", tag.into())
        .with_attr("xmlns", xmlns)
        .with_attr("to", S_WHATSAPP_NET)
        .with_attr("type", query_type)
        .with_content(content)
}

fn profile_picture_set_iq(tag: impl Into<String>) -> BinaryNode {
    BinaryNode::new("iq")
        .with_attr("id", tag.into())
        .with_attr("to", S_WHATSAPP_NET)
        .with_attr("type", "set")
        .with_attr("xmlns", "w:profile:picture")
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

fn normalize_target_jid(jid: &str) -> CoreResult<String> {
    validate_jid("target JID", jid)?;
    jid_normalized_user(jid)
        .ok_or_else(|| CoreError::Protocol(format!("invalid target JID: {jid}")))
}

fn validate_lid_jid(jid: &str) -> CoreResult<&str> {
    let decoded =
        jid_decode(jid).ok_or_else(|| CoreError::Protocol(format!("invalid LID JID: {jid}")))?;
    if !matches!(decoded.server, JidServer::Lid | JidServer::HostedLid) {
        return Err(CoreError::Protocol(format!(
            "blocklist update JID must use LID domain: {jid}"
        )));
    }
    Ok(jid)
}

fn validate_pn_jid(jid: &str) -> CoreResult<&str> {
    let decoded =
        jid_decode(jid).ok_or_else(|| CoreError::Protocol(format!("invalid PN JID: {jid}")))?;
    if !matches!(decoded.server, JidServer::SWhatsAppNet | JidServer::Hosted) {
        return Err(CoreError::Protocol(format!(
            "blocklist PN JID must use PN domain: {jid}"
        )));
    }
    Ok(jid)
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

fn child_nodes(node: &BinaryNode) -> &[BinaryNode] {
    match &node.content {
        Some(BinaryNodeContent::Nodes(children)) => children,
        _ => &[],
    }
}

fn child_node<'a>(node: &'a BinaryNode, tag: &str) -> Option<&'a BinaryNode> {
    child_nodes(node).iter().find(|child| child.tag == tag)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_and_parses_privacy_settings() {
        let query = build_privacy_settings_query("q-1");
        assert_eq!(query.attrs["xmlns"], "privacy");
        assert_eq!(query.attrs["type"], "get");
        assert!(child_node(&query, "privacy").is_some());

        let update =
            build_privacy_update_query(PrivacyCategory::Online, PrivacyValue::MatchLastSeen, "q-2");
        let privacy = child_node(&update, "privacy").unwrap();
        let category = child_node(privacy, "category").unwrap();
        assert_eq!(category.attrs["name"], "online");
        assert_eq!(category.attrs["value"], "match_last_seen");

        let response =
            BinaryNode::new("iq").with_content(vec![BinaryNode::new("privacy").with_content(
                vec![
                BinaryNode::new("category")
                    .with_attr("name", "last")
                    .with_attr("value", "contacts"),
                BinaryNode::new("category")
                    .with_attr("name", "custom")
                    .with_attr("value", "value"),
            ],
            )]);
        let settings = parse_privacy_settings(&response);
        assert_eq!(settings.get(PrivacyCategory::LastSeen), Some("contacts"));
        assert_eq!(settings.unknown["custom"], "value");
    }

    #[test]
    fn builds_profile_queries_and_parses_url() {
        let status = build_profile_status_update_query("available", "q-3").unwrap();
        assert_eq!(status.attrs["xmlns"], "status");
        assert_eq!(
            child_node(&status, "status")
                .unwrap()
                .content
                .as_ref()
                .unwrap(),
            &BinaryNodeContent::Bytes(Bytes::from_static(b"available"))
        );

        let picture =
            build_profile_picture_url_query("123@c.us", ProfilePictureType::Image, "q-4").unwrap();
        assert_eq!(picture.attrs["target"], "123@s.whatsapp.net");
        assert_eq!(picture.attrs["xmlns"], "w:profile:picture");
        let picture_child = child_node(&picture, "picture").unwrap();
        assert_eq!(picture_child.attrs["type"], "image");
        assert_eq!(picture_child.attrs["query"], "url");

        let update = build_profile_picture_update_query(
            Some("123@s.whatsapp.net"),
            Bytes::from_static(b"jpeg"),
            "q-5",
        )
        .unwrap();
        assert_eq!(update.attrs["target"], "123@s.whatsapp.net");
        assert!(child_node(&update, "picture").is_some());

        let remove = build_profile_picture_remove_query(Some("123@c.us"), "q-6").unwrap();
        assert_eq!(remove.attrs["target"], "123@s.whatsapp.net");
        assert!(remove.content.is_none());

        let response = BinaryNode::new("iq").with_content(vec![
            BinaryNode::new("picture").with_attr("url", "https://example.invalid/p.jpg"),
        ]);
        assert_eq!(
            parse_profile_picture_url(&response).as_deref(),
            Some("https://example.invalid/p.jpg")
        );

        let result = BinaryNode::new("iq").with_attr("type", "result");
        assert!(parse_profile_picture_mutation_result(&result).is_ok());

        let error = BinaryNode::new("iq")
            .with_attr("type", "error")
            .with_attr("code", "403")
            .with_attr("text", "denied");
        assert!(matches!(
            parse_profile_picture_mutation_result(&error),
            Err(CoreError::Protocol(message))
                if message == "profile picture mutation failed with code 403: denied"
        ));

        let invalid = BinaryNode::new("message").with_attr("type", "result");
        assert!(parse_profile_picture_mutation_result(&invalid).is_err());
    }

    #[test]
    fn parses_account_mutation_results() {
        let result = BinaryNode::new("iq").with_attr("type", "result");
        assert!(
            parse_account_mutation_result(&result, AccountMutationKind::PrivacySetting).is_ok()
        );
        assert!(
            parse_account_mutation_result(&result, AccountMutationKind::DefaultDisappearingMode)
                .is_ok()
        );
        assert!(parse_account_mutation_result(&result, AccountMutationKind::ProfileStatus).is_ok());
        assert!(parse_account_mutation_result(&result, AccountMutationKind::Blocklist).is_ok());

        let error = BinaryNode::new("iq")
            .with_attr("type", "error")
            .with_attr("code", "403")
            .with_attr("text", "denied");
        assert!(matches!(
            parse_account_mutation_result(&error, AccountMutationKind::ProfileStatus),
            Err(CoreError::Protocol(message))
                if message == "profile status mutation failed with code 403: denied"
        ));

        let invalid = BinaryNode::new("message").with_attr("type", "result");
        assert!(matches!(
            parse_account_mutation_result(&invalid, AccountMutationKind::Blocklist),
            Err(CoreError::Protocol(message))
                if message == "blocklist mutation response must be iq, got message"
        ));
    }

    #[test]
    fn builds_blocklist_queries() {
        let query = build_blocklist_query("q-7");
        assert_eq!(query.attrs["xmlns"], "blocklist");
        assert_eq!(query.attrs["type"], "get");

        let response =
            BinaryNode::new("iq").with_content(vec![BinaryNode::new("list").with_content(vec![
                BinaryNode::new("item").with_attr("jid", "abc@lid"),
                BinaryNode::new("item").with_attr("jid", "def@lid"),
            ])]);
        assert_eq!(parse_blocklist(&response), vec!["abc@lid", "def@lid"]);

        let update = build_blocklist_update_query(
            "abc@lid",
            BlocklistAction::Block,
            Some("123@s.whatsapp.net"),
            "q-8",
        )
        .unwrap();
        let item = child_node(&update, "item").unwrap();
        assert_eq!(item.attrs["action"], "block");
        assert_eq!(item.attrs["jid"], "abc@lid");
        assert_eq!(item.attrs["pn_jid"], "123@s.whatsapp.net");

        let unblock =
            build_blocklist_update_query("abc@lid", BlocklistAction::Unblock, None, "q-9").unwrap();
        assert!(
            !child_node(&unblock, "item")
                .unwrap()
                .attrs
                .contains_key("pn_jid")
        );
    }

    #[test]
    fn classifies_and_builds_account_jids() {
        assert_eq!(
            account_jid_kind("123@c.us").unwrap(),
            AccountJidKind::PhoneNumber
        );
        assert_eq!(account_jid_kind("abc@lid").unwrap(), AccountJidKind::Lid);
        assert_eq!(
            normalize_account_jid("123@c.us").unwrap(),
            "123@s.whatsapp.net"
        );
        assert_eq!(pn_user_jid("123").unwrap(), "123@s.whatsapp.net");
        assert_eq!(lid_user_jid("abc").unwrap(), "abc@lid");
    }

    #[test]
    fn builds_presence_nodes() {
        let online = build_presence_update_node(PresenceState::Available, "A@B").unwrap();
        assert_eq!(online.tag, "presence");
        assert_eq!(online.attrs["name"], "AB");
        assert_eq!(online.attrs["type"], "available");

        let recording = build_chat_state_node(
            PresenceState::Recording,
            "123@s.whatsapp.net",
            Some("abc@lid"),
            "456@lid",
        )
        .unwrap();
        assert_eq!(recording.tag, "chatstate");
        assert_eq!(recording.attrs["from"], "abc@lid");
        assert_eq!(recording.attrs["to"], "456@lid");
        let composing = child_node(&recording, "composing").unwrap();
        assert_eq!(composing.attrs["media"], "audio");

        let paused = build_chat_state_node(
            PresenceState::Paused,
            "123@s.whatsapp.net",
            None,
            "456@s.whatsapp.net",
        )
        .unwrap();
        assert!(child_node(&paused, "paused").is_some());

        let subscribe = build_presence_subscribe_node("456@s.whatsapp.net", "q-10").unwrap();
        assert_eq!(subscribe.tag, "presence");
        assert_eq!(subscribe.attrs["type"], "subscribe");
        assert_eq!(subscribe.attrs["id"], "q-10");
    }

    #[test]
    fn validates_presence_and_blocklist_inputs() {
        assert!(build_presence_update_node(PresenceState::Composing, "name").is_err());
        assert!(
            build_chat_state_node(
                PresenceState::Composing,
                "123@s.whatsapp.net",
                None,
                "abc@lid"
            )
            .is_err()
        );
        assert!(
            build_blocklist_update_query(
                "123@s.whatsapp.net",
                BlocklistAction::Block,
                Some("456@s.whatsapp.net"),
                "q"
            )
            .is_err()
        );
    }
}
