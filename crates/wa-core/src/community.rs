use crate::group::{
    GroupInviteV4, GroupJoinApprovalMode, GroupJoinRequest, GroupJoinRequestAction,
    GroupJoinRequestActionResult, GroupMemberAddMode, GroupMetadata, GroupParticipantAction,
    GroupParticipantActionResult, GroupSettingUpdate, parse_group_invite_code,
    parse_group_invite_v4_accept_result, parse_group_invite_v4_result,
    parse_group_join_request_action_result, parse_group_join_requests, parse_group_metadata,
    parse_group_participant_action_result,
};
use crate::{CoreError, CoreResult};
use bytes::Bytes;
use wa_binary::{
    BinaryNode, BinaryNodeContent, JidServer, jid_decode, jid_encode, jid_normalized_user,
};

pub const COMMUNITY_QUERY_XMLNS: &str = "w:g2";
pub const COMMUNITY_COLLECTION_JID: &str = "@g.us";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommunityLinkedGroup {
    pub jid: String,
    pub subject: Option<String>,
    pub creation: Option<u64>,
    pub owner: Option<String>,
    pub size: Option<usize>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommunityLinkedGroups {
    pub community_jid: String,
    pub is_community: bool,
    pub linked_groups: Vec<CommunityLinkedGroup>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommunityMutationKind {
    Leave,
    Subject,
    Description,
    LinkGroup,
    UnlinkGroup,
    Ephemeral,
    Setting,
    MemberAddMode,
    JoinApprovalMode,
}

impl CommunityMutationKind {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Leave => "community leave mutation",
            Self::Subject => "community subject mutation",
            Self::Description => "community description mutation",
            Self::LinkGroup => "community link-group mutation",
            Self::UnlinkGroup => "community unlink-group mutation",
            Self::Ephemeral => "community ephemeral mutation",
            Self::Setting => "community setting mutation",
            Self::MemberAddMode => "community member-add-mode mutation",
            Self::JoinApprovalMode => "community join-approval-mode mutation",
        }
    }
}

pub fn build_community_metadata_query(
    community_jid: impl AsRef<str>,
    tag: impl Into<String>,
) -> CoreResult<BinaryNode> {
    let community_jid = validate_group_jid(community_jid.as_ref())?;
    Ok(community_iq(
        community_jid,
        "get",
        tag,
        vec![BinaryNode::new("query").with_attr("request", "interactive")],
    ))
}

pub fn build_community_participating_query(tag: impl Into<String>) -> BinaryNode {
    community_iq(
        COMMUNITY_COLLECTION_JID,
        "get",
        tag,
        vec![BinaryNode::new("participating").with_content(vec![
            BinaryNode::new("participants"),
            BinaryNode::new("description"),
        ])],
    )
}

pub fn build_community_create_query(
    subject: impl AsRef<str>,
    description: impl AsRef<str>,
    description_id: impl AsRef<str>,
    tag: impl Into<String>,
) -> CoreResult<BinaryNode> {
    let subject = validate_non_empty("community subject", subject.as_ref())?;
    let description_id = validate_non_empty("community description id", description_id.as_ref())?;
    Ok(community_iq(
        COMMUNITY_COLLECTION_JID,
        "set",
        tag,
        vec![
            BinaryNode::new("create")
                .with_attr("subject", subject)
                .with_content(vec![
                    BinaryNode::new("description")
                        .with_attr("id", description_id)
                        .with_content(vec![BinaryNode::new("body").with_content(
                            Bytes::copy_from_slice(description.as_ref().as_bytes()),
                        )]),
                    BinaryNode::new("parent")
                        .with_attr("default_membership_approval_mode", "request_required"),
                    BinaryNode::new("allow_non_admin_sub_group_creation"),
                    BinaryNode::new("create_general_chat"),
                ]),
        ],
    ))
}

pub fn build_community_create_group_query<I, T>(
    subject: impl AsRef<str>,
    participants: I,
    parent_community_jid: impl AsRef<str>,
    creation_key: impl AsRef<str>,
    tag: impl Into<String>,
) -> CoreResult<BinaryNode>
where
    I: IntoIterator<Item = T>,
    T: AsRef<str>,
{
    let subject = validate_non_empty("community subgroup subject", subject.as_ref())?;
    let parent_community_jid = validate_group_jid(parent_community_jid.as_ref())?;
    let creation_key =
        validate_non_empty("community subgroup creation key", creation_key.as_ref())?;
    let mut children = participant_nodes(participants)?;
    if children.is_empty() {
        return Err(CoreError::Protocol(
            "community subgroup create must include at least one participant".to_owned(),
        ));
    }
    children.push(BinaryNode::new("linked_parent").with_attr("jid", parent_community_jid));

    Ok(community_iq(
        COMMUNITY_COLLECTION_JID,
        "set",
        tag,
        vec![
            BinaryNode::new("create")
                .with_attr("subject", subject)
                .with_attr("key", creation_key)
                .with_content(children),
        ],
    ))
}

pub fn build_community_leave_query(
    community_id: impl AsRef<str>,
    tag: impl Into<String>,
) -> CoreResult<BinaryNode> {
    let community_id = validate_community_id(community_id.as_ref())?;
    Ok(community_iq(
        COMMUNITY_COLLECTION_JID,
        "set",
        tag,
        vec![BinaryNode::new("leave").with_content(vec![
            BinaryNode::new("community").with_attr("id", community_id),
        ])],
    ))
}

pub fn build_community_subject_query(
    community_jid: impl AsRef<str>,
    subject: impl AsRef<str>,
    tag: impl Into<String>,
) -> CoreResult<BinaryNode> {
    let community_jid = validate_group_jid(community_jid.as_ref())?;
    let subject = validate_non_empty("community subject", subject.as_ref())?;
    Ok(community_iq(
        community_jid,
        "set",
        tag,
        vec![BinaryNode::new("subject").with_content(Bytes::copy_from_slice(subject.as_bytes()))],
    ))
}

pub fn build_community_link_group_query(
    group_jid: impl AsRef<str>,
    parent_community_jid: impl AsRef<str>,
    tag: impl Into<String>,
) -> CoreResult<BinaryNode> {
    let group_jid = validate_group_jid(group_jid.as_ref())?;
    let parent_community_jid = validate_group_jid(parent_community_jid.as_ref())?;
    Ok(community_iq(
        parent_community_jid,
        "set",
        tag,
        vec![BinaryNode::new("links").with_content(vec![
                BinaryNode::new("link")
                    .with_attr("link_type", "sub_group")
                    .with_content(vec![BinaryNode::new("group").with_attr("jid", group_jid)]),
            ])],
    ))
}

pub fn build_community_unlink_group_query(
    group_jid: impl AsRef<str>,
    parent_community_jid: impl AsRef<str>,
    tag: impl Into<String>,
) -> CoreResult<BinaryNode> {
    let group_jid = validate_group_jid(group_jid.as_ref())?;
    let parent_community_jid = validate_group_jid(parent_community_jid.as_ref())?;
    Ok(community_iq(
        parent_community_jid,
        "set",
        tag,
        vec![
            BinaryNode::new("unlink")
                .with_attr("unlink_type", "sub_group")
                .with_content(vec![BinaryNode::new("group").with_attr("jid", group_jid)]),
        ],
    ))
}

pub fn build_community_linked_groups_query(
    community_jid: impl AsRef<str>,
    tag: impl Into<String>,
) -> CoreResult<BinaryNode> {
    let community_jid = validate_group_jid(community_jid.as_ref())?;
    Ok(community_iq(
        community_jid,
        "get",
        tag,
        vec![BinaryNode::new("sub_groups")],
    ))
}

pub fn build_community_participants_query<I, T>(
    community_jid: impl AsRef<str>,
    action: GroupParticipantAction,
    participants: I,
    tag: impl Into<String>,
) -> CoreResult<BinaryNode>
where
    I: IntoIterator<Item = T>,
    T: AsRef<str>,
{
    let community_jid = validate_group_jid(community_jid.as_ref())?;
    let participant_nodes = participant_nodes(participants)?;
    if participant_nodes.is_empty() {
        return Err(CoreError::Protocol(
            "community participant update must include at least one participant".to_owned(),
        ));
    }
    let mut action_node = BinaryNode::new(action.tag()).with_content(participant_nodes);
    if action == GroupParticipantAction::Remove {
        action_node = action_node.with_attr("linked_groups", "true");
    }
    Ok(community_iq(community_jid, "set", tag, vec![action_node]))
}

pub fn build_community_description_query(
    community_jid: impl AsRef<str>,
    description: Option<&str>,
    previous_description_id: Option<&str>,
    new_description_id: Option<&str>,
    tag: impl Into<String>,
) -> CoreResult<BinaryNode> {
    let community_jid = validate_group_jid(community_jid.as_ref())?;
    let mut description_node = BinaryNode::new("description");
    if let Some(previous) = previous_description_id.filter(|value| !value.is_empty()) {
        description_node = description_node.with_attr("prev", previous);
    }
    if let Some(description) = description {
        let description = validate_non_empty("community description", description)?;
        let new_id = validate_non_empty(
            "new community description id",
            new_description_id.ok_or_else(|| {
                CoreError::Protocol(
                    "community description update requires a new description id".to_owned(),
                )
            })?,
        )?;
        description_node = description_node.with_attr("id", new_id).with_content(vec![
            BinaryNode::new("body").with_content(Bytes::copy_from_slice(description.as_bytes())),
        ]);
    } else {
        description_node = description_node.with_attr("delete", "true");
    }
    Ok(community_iq(
        community_jid,
        "set",
        tag,
        vec![description_node],
    ))
}

pub fn build_community_invite_code_query(
    community_jid: impl AsRef<str>,
    tag: impl Into<String>,
) -> CoreResult<BinaryNode> {
    let community_jid = validate_group_jid(community_jid.as_ref())?;
    Ok(community_iq(
        community_jid,
        "get",
        tag,
        vec![BinaryNode::new("invite")],
    ))
}

pub fn build_community_revoke_invite_query(
    community_jid: impl AsRef<str>,
    tag: impl Into<String>,
) -> CoreResult<BinaryNode> {
    let community_jid = validate_group_jid(community_jid.as_ref())?;
    Ok(community_iq(
        community_jid,
        "set",
        tag,
        vec![BinaryNode::new("invite")],
    ))
}

pub fn build_community_accept_invite_query(
    code: impl AsRef<str>,
    tag: impl Into<String>,
) -> CoreResult<BinaryNode> {
    let code = validate_non_empty("community invite code", code.as_ref())?;
    Ok(community_iq(
        COMMUNITY_COLLECTION_JID,
        "set",
        tag,
        vec![BinaryNode::new("invite").with_attr("code", code)],
    ))
}

pub fn build_community_invite_info_query(
    code: impl AsRef<str>,
    tag: impl Into<String>,
) -> CoreResult<BinaryNode> {
    let code = validate_non_empty("community invite code", code.as_ref())?;
    Ok(community_iq(
        COMMUNITY_COLLECTION_JID,
        "get",
        tag,
        vec![BinaryNode::new("invite").with_attr("code", code)],
    ))
}

pub fn build_community_revoke_invite_v4_query(
    community_jid: impl AsRef<str>,
    invited_jid: impl AsRef<str>,
    tag: impl Into<String>,
) -> CoreResult<BinaryNode> {
    let community_jid = validate_group_jid(community_jid.as_ref())?;
    let invited_jid = validate_participant_jid(invited_jid.as_ref())?;
    Ok(community_iq(
        community_jid,
        "set",
        tag,
        vec![BinaryNode::new("revoke").with_content(vec![
            BinaryNode::new("participant").with_attr("jid", invited_jid),
        ])],
    ))
}

pub fn build_community_accept_invite_v4_query(
    invite: &GroupInviteV4,
    tag: impl Into<String>,
) -> CoreResult<BinaryNode> {
    Ok(community_iq(
        &invite.group_jid,
        "set",
        tag,
        vec![
            BinaryNode::new("accept")
                .with_attr("code", invite.invite_code.clone())
                .with_attr("expiration", invite.invite_expiration.to_string())
                .with_attr("admin", invite.inviter_jid.clone()),
        ],
    ))
}

pub fn build_community_ephemeral_query(
    community_jid: impl AsRef<str>,
    duration_seconds: u32,
    tag: impl Into<String>,
) -> CoreResult<BinaryNode> {
    let community_jid = validate_group_jid(community_jid.as_ref())?;
    let node = if duration_seconds == 0 {
        BinaryNode::new("not_ephemeral")
    } else {
        BinaryNode::new("ephemeral").with_attr("expiration", duration_seconds.to_string())
    };
    Ok(community_iq(community_jid, "set", tag, vec![node]))
}

pub fn build_community_setting_query(
    community_jid: impl AsRef<str>,
    setting: GroupSettingUpdate,
    tag: impl Into<String>,
) -> CoreResult<BinaryNode> {
    let community_jid = validate_group_jid(community_jid.as_ref())?;
    Ok(community_iq(
        community_jid,
        "set",
        tag,
        vec![BinaryNode::new(setting.tag())],
    ))
}

pub fn build_community_member_add_mode_query(
    community_jid: impl AsRef<str>,
    mode: GroupMemberAddMode,
    tag: impl Into<String>,
) -> CoreResult<BinaryNode> {
    let community_jid = validate_group_jid(community_jid.as_ref())?;
    Ok(community_iq(
        community_jid,
        "set",
        tag,
        vec![BinaryNode::new("member_add_mode").with_content(mode.protocol_value())],
    ))
}

pub fn build_community_join_approval_mode_query(
    community_jid: impl AsRef<str>,
    mode: GroupJoinApprovalMode,
    tag: impl Into<String>,
) -> CoreResult<BinaryNode> {
    let community_jid = validate_group_jid(community_jid.as_ref())?;
    Ok(community_iq(
        community_jid,
        "set",
        tag,
        vec![
            BinaryNode::new("membership_approval_mode").with_content(vec![
                BinaryNode::new("community_join").with_attr("state", mode.state()),
            ]),
        ],
    ))
}

pub fn build_community_join_request_list_query(
    community_jid: impl AsRef<str>,
    tag: impl Into<String>,
) -> CoreResult<BinaryNode> {
    let community_jid = validate_group_jid(community_jid.as_ref())?;
    Ok(community_iq(
        community_jid,
        "get",
        tag,
        vec![BinaryNode::new("membership_approval_requests")],
    ))
}

pub fn build_community_join_request_action_query<I, T>(
    community_jid: impl AsRef<str>,
    participants: I,
    action: GroupJoinRequestAction,
    tag: impl Into<String>,
) -> CoreResult<BinaryNode>
where
    I: IntoIterator<Item = T>,
    T: AsRef<str>,
{
    let community_jid = validate_group_jid(community_jid.as_ref())?;
    let participant_nodes = participant_nodes(participants)?;
    if participant_nodes.is_empty() {
        return Err(CoreError::Protocol(
            "community join request update must include at least one participant".to_owned(),
        ));
    }
    Ok(community_iq(
        community_jid,
        "set",
        tag,
        vec![
            BinaryNode::new("membership_requests_action").with_content(vec![
                BinaryNode::new(action.tag()).with_content(participant_nodes),
            ]),
        ],
    ))
}

pub fn parse_community_metadata(node: &BinaryNode) -> CoreResult<GroupMetadata> {
    let community = community_node_from_result(node)?;
    parse_community_node(community)
}

pub fn parse_community_create_result_jid(node: &BinaryNode) -> CoreResult<Option<String>> {
    if let Some(error) = error_from_result(node) {
        return Err(error);
    }
    if let Some(id) = create_result_child_id(node, "group", "group")? {
        return community_jid_from_id(id).map(Some);
    }
    if let Some(community) = child_node(node, "community")
        && community.content.is_none()
        && !community.attrs.contains_key("subject")
    {
        let id = create_result_node_id(community, "community")?;
        return community_jid_from_id(id).map(Some);
    }
    if let Some(id) = node.attrs.get("from").or_else(|| node.attrs.get("jid")) {
        return community_jid_from_id(id).map(Some);
    }
    Ok(None)
}

fn create_result_child_id<'a>(
    node: &'a BinaryNode,
    tag: &str,
    label: &str,
) -> CoreResult<Option<&'a str>> {
    child_node(node, tag)
        .map(|child| create_result_node_id(child, label))
        .transpose()
}

fn create_result_node_id<'a>(node: &'a BinaryNode, label: &str) -> CoreResult<&'a str> {
    node.attrs
        .get("jid")
        .or_else(|| node.attrs.get("id"))
        .map(String::as_str)
        .ok_or_else(|| CoreError::Protocol(format!("community create response {label} missing id")))
}

pub fn parse_community_participating_result(node: &BinaryNode) -> CoreResult<Vec<GroupMetadata>> {
    if let Some(error) = error_from_result(node) {
        return Err(error);
    }
    let Some(communities_node) = first_child_node(node, &["communities", "groups"]) else {
        return Ok(Vec::new());
    };
    child_nodes(communities_node)
        .iter()
        .filter(|child| child.tag == "community" || child.tag == "group")
        .map(parse_community_node)
        .collect()
}

pub fn parse_community_linked_groups(node: &BinaryNode) -> CoreResult<Vec<CommunityLinkedGroup>> {
    if let Some(error) = error_from_result(node) {
        return Err(error);
    }
    let Some(sub_groups) = first_child_node(node, &["sub_groups", "linked_groups", "groups"])
    else {
        return Ok(Vec::new());
    };
    child_nodes(sub_groups)
        .iter()
        .filter(|child| {
            child.tag == "group" || child.tag == "community" || child.tag == "linked_group"
        })
        .map(parse_linked_group)
        .collect()
}

pub fn parse_community_join_requests(node: &BinaryNode) -> CoreResult<Vec<GroupJoinRequest>> {
    parse_group_join_requests(node)
}

pub fn parse_community_join_request_action_result(
    node: &BinaryNode,
    action: GroupJoinRequestAction,
) -> CoreResult<GroupJoinRequestActionResult> {
    parse_group_join_request_action_result(node, action)
}

pub fn parse_community_participant_action_result(
    node: &BinaryNode,
    action: GroupParticipantAction,
) -> CoreResult<GroupParticipantActionResult> {
    parse_group_participant_action_result(node, action)
}

pub fn parse_community_invite_code(node: &BinaryNode) -> CoreResult<Option<String>> {
    parse_group_invite_code(node)
}

pub fn parse_community_invite_info_result(node: &BinaryNode) -> CoreResult<GroupMetadata> {
    if node.tag == "group" || child_node(node, "group").is_some() {
        parse_group_metadata(node)
    } else {
        parse_community_metadata(node)
    }
}

pub fn parse_community_accept_invite_result(node: &BinaryNode) -> CoreResult<Option<String>> {
    if let Some(error) = error_from_result(node) {
        return Err(error);
    }
    child_node(node, "community")
        .and_then(|community| {
            community
                .attrs
                .get("jid")
                .or_else(|| community.attrs.get("id"))
        })
        .or_else(|| node.attrs.get("jid"))
        .map(|jid| community_jid_from_id(jid))
        .transpose()
}

pub fn parse_community_invite_v4_result(node: &BinaryNode) -> CoreResult<bool> {
    parse_group_invite_v4_result(node)
}

pub fn parse_community_invite_v4_accept_result(node: &BinaryNode) -> CoreResult<Option<String>> {
    parse_group_invite_v4_accept_result(node)
}

pub fn parse_community_mutation_result(
    node: &BinaryNode,
    mutation: CommunityMutationKind,
) -> CoreResult<()> {
    let label = mutation.label();
    if node.tag != "iq" {
        return Err(CoreError::Protocol(format!(
            "{label} response must be iq, got {}",
            node.tag
        )));
    }
    if let Some(error) = error_from_result(node) {
        return Err(CoreError::Protocol(format!(
            "{label} failed{}",
            community_error_suffix(&error)
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

fn community_iq(
    to: impl Into<String>,
    query_type: &'static str,
    tag: impl Into<String>,
    content: Vec<BinaryNode>,
) -> BinaryNode {
    BinaryNode::new("iq")
        .with_attr("id", tag.into())
        .with_attr("to", to.into())
        .with_attr("type", query_type)
        .with_attr("xmlns", COMMUNITY_QUERY_XMLNS)
        .with_content(content)
}

fn parse_community_node(community: &BinaryNode) -> CoreResult<GroupMetadata> {
    let mut group_like = community.clone();
    group_like.tag = "group".to_owned();
    let mut metadata = parse_group_metadata(&group_like)?;
    if child_node(community, "default_sub_community").is_some() {
        metadata.is_community_announce = true;
    }
    Ok(metadata)
}

fn parse_linked_group(node: &BinaryNode) -> CoreResult<CommunityLinkedGroup> {
    let id = node
        .attrs
        .get("jid")
        .or_else(|| node.attrs.get("id"))
        .ok_or_else(|| CoreError::Protocol("linked community group missing id".to_owned()))?;
    let jid = if id.contains('@') {
        id.clone()
    } else {
        jid_encode(id, JidServer::GUs, None, None)
    };
    validate_group_jid(&jid)?;
    Ok(CommunityLinkedGroup {
        jid,
        subject: node.attrs.get("subject").cloned(),
        creation: optional_u64_attr(node, "creation")?,
        owner: node
            .attrs
            .get("creator")
            .map(|jid| normalize_jid(jid))
            .transpose()?,
        size: optional_usize_attr(node, "size")?,
    })
}

fn community_jid_from_id(id: &str) -> CoreResult<String> {
    let jid = if id.contains('@') {
        id.to_owned()
    } else {
        jid_encode(id, JidServer::GUs, None, None)
    };
    validate_group_jid(&jid)?;
    Ok(jid)
}

fn community_node_from_result(node: &BinaryNode) -> CoreResult<&BinaryNode> {
    if node.tag == "community" {
        return Ok(node);
    }
    if let Some(community) = child_node(node, "community") {
        return Ok(community);
    }
    if let Some(error) = error_from_result(node) {
        return Err(error);
    }
    Err(CoreError::Protocol(
        "community metadata response missing community node".to_owned(),
    ))
}

fn participant_nodes<I, T>(participants: I) -> CoreResult<Vec<BinaryNode>>
where
    I: IntoIterator<Item = T>,
    T: AsRef<str>,
{
    participants
        .into_iter()
        .map(|participant| {
            let participant = validate_participant_jid(participant.as_ref())?;
            Ok(BinaryNode::new("participant").with_attr("jid", participant))
        })
        .collect()
}

fn error_from_result(node: &BinaryNode) -> Option<CoreError> {
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
        .unwrap_or("community query failed");
    Some(CoreError::Protocol(format!(
        "community query failed ({code}): {text}"
    )))
}

fn community_error_suffix(error: &CoreError) -> String {
    match error {
        CoreError::Protocol(message) if !message.is_empty() => format!(": {message}"),
        _ => String::new(),
    }
}

fn validate_group_jid(jid: &str) -> CoreResult<&str> {
    let decoded =
        jid_decode(jid).ok_or_else(|| CoreError::Protocol(format!("invalid group JID: {jid}")))?;
    if decoded.server != JidServer::GUs {
        return Err(CoreError::Protocol(format!(
            "group JID must use group server: {jid}"
        )));
    }
    Ok(jid)
}

fn validate_participant_jid(jid: &str) -> CoreResult<&str> {
    let decoded = jid_decode(jid)
        .ok_or_else(|| CoreError::Protocol(format!("invalid participant JID: {jid}")))?;
    if matches!(
        decoded.server,
        JidServer::GUs | JidServer::Broadcast | JidServer::Newsletter | JidServer::Call
    ) {
        return Err(CoreError::Protocol(format!(
            "participant JID must be an account or device JID: {jid}"
        )));
    }
    Ok(jid)
}

fn validate_community_id(id: &str) -> CoreResult<&str> {
    let id = validate_non_empty("community id", id)?;
    if id.contains('@') {
        validate_group_jid(id)?;
    }
    Ok(id)
}

fn validate_non_empty<'a>(label: &str, value: &'a str) -> CoreResult<&'a str> {
    if value.trim().is_empty() {
        return Err(CoreError::Protocol(format!("{label} must not be empty")));
    }
    Ok(value)
}

fn normalize_jid(jid: &str) -> CoreResult<String> {
    jid_decode(jid).ok_or_else(|| CoreError::Protocol(format!("invalid JID: {jid}")))?;
    Ok(jid_normalized_user(jid).unwrap_or_else(|| jid.to_owned()))
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

fn first_child_node<'a>(node: &'a BinaryNode, tags: &[&str]) -> Option<&'a BinaryNode> {
    tags.iter().find_map(|tag| child_node(node, tag))
}

fn optional_u64_attr(node: &BinaryNode, attr: &str) -> CoreResult<Option<u64>> {
    node.attrs
        .get(attr)
        .map(|value| {
            value.parse::<u64>().map_err(|err| {
                CoreError::Protocol(format!("invalid community attribute {attr}: {err}"))
            })
        })
        .transpose()
}

fn optional_usize_attr(node: &BinaryNode, attr: &str) -> CoreResult<Option<usize>> {
    node.attrs
        .get(attr)
        .map(|value| {
            value.parse::<usize>().map_err(|err| {
                CoreError::Protocol(format!("invalid community attribute {attr}: {err}"))
            })
        })
        .transpose()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_core_community_iqs() {
        let metadata = build_community_metadata_query("123@g.us", "q-1").unwrap();
        assert_eq!(metadata.attrs["to"], "123@g.us");
        assert_eq!(metadata.attrs["type"], "get");
        assert_eq!(metadata.attrs["xmlns"], COMMUNITY_QUERY_XMLNS);
        assert_eq!(
            child_node(&metadata, "query").unwrap().attrs["request"],
            "interactive"
        );

        let participating = build_community_participating_query("q-2");
        assert_eq!(participating.attrs["to"], COMMUNITY_COLLECTION_JID);
        assert!(child_node(&participating, "participating").is_some());

        let create = build_community_create_query("Updates", "Daily", "desc-1", "q-3").unwrap();
        assert_eq!(create.attrs["to"], COMMUNITY_COLLECTION_JID);
        let create_node = child_node(&create, "create").unwrap();
        assert_eq!(create_node.attrs["subject"], "Updates");
        assert!(child_node(create_node, "parent").is_some());
        assert!(child_node(create_node, "allow_non_admin_sub_group_creation").is_some());
        assert!(child_node(create_node, "create_general_chat").is_some());

        let subgroup = build_community_create_group_query(
            "Announcements",
            ["111@s.whatsapp.net"],
            "123@g.us",
            "key-1",
            "q-4",
        )
        .unwrap();
        let subgroup_create = child_node(&subgroup, "create").unwrap();
        assert_eq!(subgroup_create.attrs["key"], "key-1");
        assert_eq!(
            child_node(subgroup_create, "linked_parent").unwrap().attrs["jid"],
            "123@g.us"
        );

        let leave = build_community_leave_query("123@g.us", "q-5").unwrap();
        let leave_node = child_node(&leave, "leave").unwrap();
        assert_eq!(
            child_node(leave_node, "community").unwrap().attrs["id"],
            "123@g.us"
        );
    }

    #[test]
    fn builds_community_links_membership_invites_and_settings() {
        let link = build_community_link_group_query("456@g.us", "123@g.us", "q-1").unwrap();
        let link_node = child_node(child_node(&link, "links").unwrap(), "link").unwrap();
        assert_eq!(link_node.attrs["link_type"], "sub_group");
        assert_eq!(
            child_node(link_node, "group").unwrap().attrs["jid"],
            "456@g.us"
        );

        let unlink = build_community_unlink_group_query("456@g.us", "123@g.us", "q-2").unwrap();
        let unlink_node = child_node(&unlink, "unlink").unwrap();
        assert_eq!(unlink_node.attrs["unlink_type"], "sub_group");

        let linked = build_community_linked_groups_query("123@g.us", "q-3").unwrap();
        assert!(child_node(&linked, "sub_groups").is_some());

        let participants = build_community_participants_query(
            "123@g.us",
            GroupParticipantAction::Remove,
            ["111@s.whatsapp.net"],
            "q-4",
        )
        .unwrap();
        let remove = child_node(&participants, "remove").unwrap();
        assert_eq!(remove.attrs["linked_groups"], "true");

        let approval =
            build_community_join_approval_mode_query("123@g.us", GroupJoinApprovalMode::On, "q-5")
                .unwrap();
        let mode = child_node(&approval, "membership_approval_mode").unwrap();
        assert_eq!(
            child_node(mode, "community_join").unwrap().attrs["state"],
            "on"
        );

        let invite = build_community_accept_invite_query("code", "q-6").unwrap();
        assert_eq!(invite.attrs["to"], COMMUNITY_COLLECTION_JID);
        assert_eq!(child_node(&invite, "invite").unwrap().attrs["code"], "code");
        assert_eq!(
            parse_community_accept_invite_result(
                &BinaryNode::new("iq")
                    .with_attr("type", "result")
                    .with_content(vec![
                        BinaryNode::new("community").with_attr("jid", "123@g.us"),
                    ])
            )
            .unwrap()
            .as_deref(),
            Some("123@g.us")
        );
        assert_eq!(
            parse_community_accept_invite_result(
                &BinaryNode::new("iq")
                    .with_attr("type", "result")
                    .with_content(vec![BinaryNode::new("community").with_attr("id", "456")])
            )
            .unwrap()
            .as_deref(),
            Some("456@g.us")
        );
        assert!(
            parse_community_accept_invite_result(
                &BinaryNode::new("iq")
                    .with_attr("type", "result")
                    .with_content(vec![
                        BinaryNode::new("community").with_attr("jid", "111@s.whatsapp.net"),
                    ])
            )
            .is_err()
        );
        assert_eq!(
            parse_community_create_result_jid(
                &BinaryNode::new("iq")
                    .with_attr("type", "result")
                    .with_content(vec![BinaryNode::new("group").with_attr("id", "456")])
            )
            .unwrap()
            .as_deref(),
            Some("456@g.us")
        );
        assert_eq!(
            parse_community_create_result_jid(
                &BinaryNode::new("iq")
                    .with_attr("type", "result")
                    .with_content(vec![BinaryNode::new("group").with_attr("jid", "789@g.us")])
            )
            .unwrap()
            .as_deref(),
            Some("789@g.us")
        );
        assert!(
            parse_community_create_result_jid(
                &BinaryNode::new("iq")
                    .with_attr("type", "result")
                    .with_content(vec![
                        BinaryNode::new("group").with_attr("jid", "111@s.whatsapp.net")
                    ])
            )
            .is_err()
        );
        assert!(
            parse_community_create_result_jid(
                &BinaryNode::new("iq")
                    .with_attr("type", "result")
                    .with_content(vec![BinaryNode::new("group")])
            )
            .is_err()
        );
        assert_eq!(
            parse_community_create_result_jid(
                &BinaryNode::new("iq")
                    .with_attr("type", "result")
                    .with_content(vec![BinaryNode::new("community").with_attr("id", "654")])
            )
            .unwrap()
            .as_deref(),
            Some("654@g.us")
        );
        assert_eq!(
            parse_community_create_result_jid(
                &BinaryNode::new("iq")
                    .with_attr("type", "result")
                    .with_attr("from", "987@g.us")
            )
            .unwrap()
            .as_deref(),
            Some("987@g.us")
        );
        assert_eq!(
            parse_community_create_result_jid(
                &BinaryNode::new("iq")
                    .with_attr("type", "result")
                    .with_attr("jid", "988@g.us")
            )
            .unwrap()
            .as_deref(),
            Some("988@g.us")
        );
        assert_eq!(
            parse_community_create_result_jid(
                &BinaryNode::new("iq")
                    .with_attr("type", "result")
                    .with_content(vec![
                        BinaryNode::new("community")
                            .with_attr("id", "555")
                            .with_attr("subject", "Full metadata")
                            .with_content(vec![BinaryNode::new("parent")])
                    ])
            )
            .unwrap(),
            None
        );
        assert!(
            parse_community_create_result_jid(
                &BinaryNode::new("iq")
                    .with_attr("type", "result")
                    .with_content(vec![BinaryNode::new("community")])
            )
            .is_err()
        );
        assert!(
            parse_community_create_result_jid(
                &BinaryNode::new("iq")
                    .with_attr("type", "result")
                    .with_attr("from", "111@s.whatsapp.net")
            )
            .is_err()
        );
        assert_eq!(
            parse_community_create_result_jid(&BinaryNode::new("iq").with_attr("type", "result"))
                .unwrap(),
            None
        );

        let v4 = GroupInviteV4::new("123@g.us", "code", 1700, "111@s.whatsapp.net").unwrap();
        let accept_v4 = build_community_accept_invite_v4_query(&v4, "q-7").unwrap();
        assert_eq!(accept_v4.attrs["to"], "123@g.us");
        assert_eq!(
            child_node(&accept_v4, "accept").unwrap().attrs["admin"],
            "111@s.whatsapp.net"
        );
    }

    #[test]
    fn parses_community_metadata_participating_and_linked_groups() {
        let response = BinaryNode::new("iq").with_content(vec![
            BinaryNode::new("community")
                .with_attr("id", "123")
                .with_attr("subject", "Updates")
                .with_attr("creator", "111@c.us")
                .with_content(vec![
                    BinaryNode::new("parent"),
                    BinaryNode::new("default_sub_community"),
                    BinaryNode::new("addressing_mode").with_content("lid"),
                    BinaryNode::new("description")
                        .with_attr("id", "desc-1")
                        .with_content(vec![BinaryNode::new("body").with_content("Daily")]),
                    BinaryNode::new("participant")
                        .with_attr("jid", "111@s.whatsapp.net")
                        .with_attr("type", "superadmin"),
                ]),
        ]);
        let metadata = parse_community_metadata(&response).unwrap();
        assert_eq!(metadata.jid, "123@g.us");
        assert_eq!(metadata.subject.as_deref(), Some("Updates"));
        assert_eq!(metadata.description.as_deref(), Some("Daily"));
        assert_eq!(
            metadata.addressing_mode,
            crate::group::GroupAddressingMode::Lid
        );
        assert!(metadata.is_community);
        assert!(metadata.is_community_announce);
        assert_eq!(metadata.participants.len(), 1);

        let participating =
            BinaryNode::new("iq").with_content(vec![BinaryNode::new("communities").with_content(
                vec![
                BinaryNode::new("community")
                    .with_attr("id", "123")
                    .with_attr("subject", "One")
                    .with_content(vec![BinaryNode::new("parent")]),
            ],
            )]);
        let communities = parse_community_participating_result(&participating).unwrap();
        assert_eq!(communities.len(), 1);
        assert_eq!(communities[0].subject.as_deref(), Some("One"));

        let group_wrapped_participating =
            BinaryNode::new("iq").with_content(vec![BinaryNode::new("groups").with_content(vec![
                BinaryNode::new("group")
                    .with_attr("id", "124")
                    .with_attr("subject", "Group-shaped community")
                    .with_content(vec![
                        BinaryNode::new("parent"),
                        BinaryNode::new("default_sub_group"),
                        BinaryNode::new("participant")
                            .with_attr("jid", "222@s.whatsapp.net")
                            .with_attr("type", "admin"),
                    ]),
            ])]);
        let communities =
            parse_community_participating_result(&group_wrapped_participating).unwrap();
        assert_eq!(communities.len(), 1);
        assert_eq!(communities[0].jid, "124@g.us");
        assert_eq!(
            communities[0].subject.as_deref(),
            Some("Group-shaped community")
        );
        assert!(communities[0].is_community);
        assert!(communities[0].is_community_announce);
        assert_eq!(communities[0].participants.len(), 1);

        let linked =
            BinaryNode::new("iq").with_content(vec![BinaryNode::new("sub_groups").with_content(
                vec![
                BinaryNode::new("group")
                    .with_attr("id", "456")
                    .with_attr("subject", "Chat")
                    .with_attr("creator", "222@c.us")
                    .with_attr("creation", "10")
                    .with_attr("size", "7"),
            ],
            )]);
        let groups = parse_community_linked_groups(&linked).unwrap();
        assert_eq!(groups[0].jid, "456@g.us");
        assert_eq!(groups[0].subject.as_deref(), Some("Chat"));
        assert_eq!(groups[0].owner.as_deref(), Some("222@s.whatsapp.net"));
        assert_eq!(groups[0].creation, Some(10));
        assert_eq!(groups[0].size, Some(7));

        let linked_alias = BinaryNode::new("iq").with_content(vec![
            BinaryNode::new("linked_groups").with_content(vec![
                BinaryNode::new("linked_group")
                    .with_attr("jid", "457@g.us")
                    .with_attr("subject", "Alias Chat")
                    .with_attr("creator", "223@c.us")
                    .with_attr("creation", "11")
                    .with_attr("size", "8"),
            ]),
        ]);
        let groups = parse_community_linked_groups(&linked_alias).unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].jid, "457@g.us");
        assert_eq!(groups[0].subject.as_deref(), Some("Alias Chat"));
        assert_eq!(groups[0].owner.as_deref(), Some("223@s.whatsapp.net"));
        assert_eq!(groups[0].creation, Some(11));
        assert_eq!(groups[0].size, Some(8));

        let groups_alias =
            BinaryNode::new("iq").with_content(vec![BinaryNode::new("groups").with_content(vec![
                BinaryNode::new("community")
                    .with_attr("id", "458")
                    .with_attr("subject", "Community Alias")
                    .with_attr("creator", "224@c.us"),
            ])]);
        let groups = parse_community_linked_groups(&groups_alias).unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].jid, "458@g.us");
        assert_eq!(groups[0].subject.as_deref(), Some("Community Alias"));
        assert_eq!(groups[0].owner.as_deref(), Some("224@s.whatsapp.net"));

        let community_invite_info = BinaryNode::new("iq").with_content(vec![
            BinaryNode::new("community")
                .with_attr("id", "459")
                .with_attr("subject", "Invite Community")
                .with_content(vec![BinaryNode::new("parent")]),
        ]);
        let invite_info = parse_community_invite_info_result(&community_invite_info).unwrap();
        assert_eq!(invite_info.jid, "459@g.us");
        assert_eq!(invite_info.subject.as_deref(), Some("Invite Community"));
        assert!(invite_info.is_community);

        let group_invite_info = BinaryNode::new("iq").with_content(vec![
            BinaryNode::new("group")
                .with_attr("id", "460")
                .with_attr("subject", "Group-shaped invite")
                .with_attr("addressing_mode", "lid")
                .with_content(vec![
                    BinaryNode::new("parent"),
                    BinaryNode::new("participant")
                        .with_attr("jid", "225@s.whatsapp.net")
                        .with_attr("type", "admin"),
                ]),
        ]);
        let invite_info = parse_community_invite_info_result(&group_invite_info).unwrap();
        assert_eq!(invite_info.jid, "460@g.us");
        assert_eq!(invite_info.subject.as_deref(), Some("Group-shaped invite"));
        assert_eq!(
            invite_info.addressing_mode,
            crate::group::GroupAddressingMode::Lid
        );
        assert!(invite_info.is_community);
        assert_eq!(invite_info.participants.len(), 1);

        let error = BinaryNode::new("iq")
            .with_attr("type", "error")
            .with_attr("code", "404")
            .with_attr("text", "missing");
        assert!(parse_community_invite_info_result(&error).is_err());
    }

    #[test]
    fn parses_community_mutation_results() {
        let result = BinaryNode::new("iq").with_attr("type", "result");
        for mutation in [
            CommunityMutationKind::Leave,
            CommunityMutationKind::Subject,
            CommunityMutationKind::Description,
            CommunityMutationKind::LinkGroup,
            CommunityMutationKind::UnlinkGroup,
            CommunityMutationKind::Ephemeral,
            CommunityMutationKind::Setting,
            CommunityMutationKind::MemberAddMode,
            CommunityMutationKind::JoinApprovalMode,
        ] {
            assert!(parse_community_mutation_result(&result, mutation).is_ok());
        }

        let attr_error = BinaryNode::new("iq")
            .with_attr("type", "error")
            .with_attr("code", "403")
            .with_attr("text", "denied");
        assert!(matches!(
            parse_community_mutation_result(&attr_error, CommunityMutationKind::Setting),
            Err(CoreError::Protocol(message))
                if message == "community setting mutation failed: community query failed (403): denied"
        ));

        let child_error = BinaryNode::new("iq")
            .with_attr("type", "result")
            .with_content(vec![
                BinaryNode::new("error")
                    .with_attr("code", "500")
                    .with_attr("text", "server rejected update"),
            ]);
        assert!(matches!(
            parse_community_mutation_result(&child_error, CommunityMutationKind::LinkGroup),
            Err(CoreError::Protocol(message))
                if message == "community link-group mutation failed: community query failed (500): server rejected update"
        ));

        let invalid = BinaryNode::new("message").with_attr("type", "result");
        assert!(matches!(
            parse_community_mutation_result(&invalid, CommunityMutationKind::Leave),
            Err(CoreError::Protocol(message))
                if message == "community leave mutation response must be iq, got message"
        ));
    }

    #[test]
    fn validates_community_inputs() {
        assert!(build_community_metadata_query("123@s.whatsapp.net", "q").is_err());
        assert!(build_community_create_query("", "Daily", "desc", "q").is_err());
        assert!(build_community_create_query("Updates", "Daily", "", "q").is_err());
        assert!(
            build_community_create_group_query("Chat", ["111@g.us"], "123@g.us", "key", "q")
                .is_err()
        );
        assert!(build_community_link_group_query("456@s.whatsapp.net", "123@g.us", "q").is_err());
        assert!(build_community_accept_invite_query("", "q").is_err());
    }
}
