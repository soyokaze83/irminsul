use crate::{CoreError, CoreResult};
use bytes::Bytes;
use wa_binary::{
    BinaryNode, BinaryNodeContent, JidServer, jid_decode, jid_encode, jid_normalized_user,
};

const GROUP_QUERY_XMLNS: &str = "w:g2";
const GROUP_COLLECTION_JID: &str = "@g.us";
const SUCCESS_STATUS: u16 = 200;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GroupAddressingMode {
    PhoneNumber,
    Lid,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GroupParticipantRole {
    Member,
    Admin,
    SuperAdmin,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupParticipant {
    pub jid: String,
    pub phone_number: Option<String>,
    pub lid: Option<String>,
    pub username: Option<String>,
    pub role: GroupParticipantRole,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupMetadata {
    pub jid: String,
    pub notify: Option<String>,
    pub addressing_mode: GroupAddressingMode,
    pub subject: Option<String>,
    pub subject_owner: Option<String>,
    pub subject_owner_pn: Option<String>,
    pub subject_owner_username: Option<String>,
    pub subject_time: Option<u64>,
    pub size: Option<usize>,
    pub creation: Option<u64>,
    pub owner: Option<String>,
    pub owner_pn: Option<String>,
    pub owner_username: Option<String>,
    pub owner_country_code: Option<String>,
    pub description: Option<String>,
    pub description_id: Option<String>,
    pub description_owner: Option<String>,
    pub description_owner_pn: Option<String>,
    pub description_owner_username: Option<String>,
    pub description_time: Option<u64>,
    pub linked_parent: Option<String>,
    pub restrict: bool,
    pub announce: bool,
    pub is_community: bool,
    pub is_community_announce: bool,
    pub join_approval_mode: bool,
    pub member_add_mode_all: bool,
    pub ephemeral_duration: Option<u32>,
    pub participants: Vec<GroupParticipant>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GroupParticipantAction {
    Add,
    Remove,
    Promote,
    Demote,
}

impl GroupParticipantAction {
    #[must_use]
    pub fn tag(self) -> &'static str {
        match self {
            Self::Add => "add",
            Self::Remove => "remove",
            Self::Promote => "promote",
            Self::Demote => "demote",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupParticipantChange {
    pub jid: String,
    pub status: u16,
    pub error_code: Option<u16>,
    pub content: Option<BinaryNode>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupParticipantActionResult {
    pub group_jid: Option<String>,
    pub action: GroupParticipantAction,
    pub participants: Vec<GroupParticipantChange>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GroupSettingUpdate {
    Announcement,
    NotAnnouncement,
    Locked,
    Unlocked,
}

impl GroupSettingUpdate {
    #[must_use]
    pub fn tag(self) -> &'static str {
        match self {
            Self::Announcement => "announcement",
            Self::NotAnnouncement => "not_announcement",
            Self::Locked => "locked",
            Self::Unlocked => "unlocked",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GroupMemberAddMode {
    AdminOnly,
    AllMembers,
}

impl GroupMemberAddMode {
    #[must_use]
    pub fn protocol_value(self) -> &'static str {
        match self {
            Self::AdminOnly => "admin_add",
            Self::AllMembers => "all_member_add",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GroupJoinApprovalMode {
    On,
    Off,
}

impl GroupJoinApprovalMode {
    #[must_use]
    pub fn state(self) -> &'static str {
        match self {
            Self::On => "on",
            Self::Off => "off",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GroupJoinRequestAction {
    Approve,
    Reject,
}

impl GroupJoinRequestAction {
    #[must_use]
    pub fn tag(self) -> &'static str {
        match self {
            Self::Approve => "approve",
            Self::Reject => "reject",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GroupMutationKind {
    Leave,
    Subject,
    Description,
    Ephemeral,
    Setting,
    MemberAddMode,
    JoinApprovalMode,
}

impl GroupMutationKind {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Leave => "group leave mutation",
            Self::Subject => "group subject mutation",
            Self::Description => "group description mutation",
            Self::Ephemeral => "group ephemeral mutation",
            Self::Setting => "group setting mutation",
            Self::MemberAddMode => "group member-add-mode mutation",
            Self::JoinApprovalMode => "group join-approval-mode mutation",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupJoinRequest {
    pub jid: String,
    pub phone_number: Option<String>,
    pub lid: Option<String>,
    pub username: Option<String>,
    pub requested_at: Option<u64>,
    pub request_method: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupJoinRequestActionResult {
    pub action: GroupJoinRequestAction,
    pub participants: Vec<GroupParticipantChange>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupInviteV4 {
    pub group_jid: String,
    pub invite_code: String,
    pub invite_expiration: u64,
    pub inviter_jid: String,
}

impl GroupInviteV4 {
    pub fn new(
        group_jid: impl AsRef<str>,
        invite_code: impl AsRef<str>,
        invite_expiration: u64,
        inviter_jid: impl AsRef<str>,
    ) -> CoreResult<Self> {
        Ok(Self {
            group_jid: validate_group_jid(group_jid.as_ref())?.to_owned(),
            invite_code: validate_non_empty("group v4 invite code", invite_code.as_ref())?
                .to_owned(),
            invite_expiration,
            inviter_jid: validate_participant_jid(inviter_jid.as_ref())?.to_owned(),
        })
    }
}

pub fn build_group_metadata_query(
    group_jid: impl AsRef<str>,
    tag: impl Into<String>,
) -> CoreResult<BinaryNode> {
    let group_jid = validate_group_jid(group_jid.as_ref())?;
    Ok(group_iq(
        group_jid,
        "get",
        tag,
        vec![BinaryNode::new("query").with_attr("request", "interactive")],
    ))
}

pub fn build_group_participating_query(tag: impl Into<String>) -> BinaryNode {
    group_iq(
        GROUP_COLLECTION_JID,
        "get",
        tag,
        vec![BinaryNode::new("participating").with_content(vec![
            BinaryNode::new("participants"),
            BinaryNode::new("description"),
        ])],
    )
}

pub fn build_group_create_query<I, T>(
    subject: impl AsRef<str>,
    participants: I,
    creation_key: impl AsRef<str>,
    tag: impl Into<String>,
) -> CoreResult<BinaryNode>
where
    I: IntoIterator<Item = T>,
    T: AsRef<str>,
{
    let subject = validate_non_empty("group subject", subject.as_ref())?;
    let creation_key = validate_non_empty("group creation key", creation_key.as_ref())?;
    let participant_nodes = participant_nodes(participants)?;
    if participant_nodes.is_empty() {
        return Err(CoreError::Protocol(
            "group create must include at least one participant".to_owned(),
        ));
    }

    Ok(group_iq(
        GROUP_COLLECTION_JID,
        "set",
        tag,
        vec![
            BinaryNode::new("create")
                .with_attr("subject", subject)
                .with_attr("key", creation_key)
                .with_content(participant_nodes),
        ],
    ))
}

pub fn build_group_leave_query(
    group_jid: impl AsRef<str>,
    tag: impl Into<String>,
) -> CoreResult<BinaryNode> {
    let group_jid = validate_group_jid(group_jid.as_ref())?;
    Ok(group_iq(
        GROUP_COLLECTION_JID,
        "set",
        tag,
        vec![
            BinaryNode::new("leave")
                .with_content(vec![BinaryNode::new("group").with_attr("id", group_jid)]),
        ],
    ))
}

pub fn build_group_subject_query(
    group_jid: impl AsRef<str>,
    subject: impl AsRef<str>,
    tag: impl Into<String>,
) -> CoreResult<BinaryNode> {
    let group_jid = validate_group_jid(group_jid.as_ref())?;
    let subject = validate_non_empty("group subject", subject.as_ref())?;
    Ok(group_iq(
        group_jid,
        "set",
        tag,
        vec![BinaryNode::new("subject").with_content(Bytes::from(subject.as_bytes().to_vec()))],
    ))
}

pub fn build_group_description_query(
    group_jid: impl AsRef<str>,
    description: Option<&str>,
    previous_description_id: Option<&str>,
    new_description_id: Option<&str>,
    tag: impl Into<String>,
) -> CoreResult<BinaryNode> {
    let group_jid = validate_group_jid(group_jid.as_ref())?;
    let mut description_node = BinaryNode::new("description");
    if let Some(previous) = previous_description_id.filter(|value| !value.is_empty()) {
        description_node = description_node.with_attr("prev", previous);
    }

    if let Some(description) = description {
        let description = validate_non_empty("group description", description)?;
        let new_id = validate_non_empty(
            "new group description id",
            new_description_id.ok_or_else(|| {
                CoreError::Protocol(
                    "group description update requires a new description id".to_owned(),
                )
            })?,
        )?;
        description_node = description_node.with_attr("id", new_id).with_content(vec![
            BinaryNode::new("body").with_content(Bytes::from(description.as_bytes().to_vec())),
        ]);
    } else {
        description_node = description_node.with_attr("delete", "true");
    }

    Ok(group_iq(group_jid, "set", tag, vec![description_node]))
}

pub fn build_group_participants_query<I, T>(
    group_jid: impl AsRef<str>,
    action: GroupParticipantAction,
    participants: I,
    tag: impl Into<String>,
) -> CoreResult<BinaryNode>
where
    I: IntoIterator<Item = T>,
    T: AsRef<str>,
{
    let group_jid = validate_group_jid(group_jid.as_ref())?;
    let participant_nodes = participant_nodes(participants)?;
    if participant_nodes.is_empty() {
        return Err(CoreError::Protocol(
            "group participant update must include at least one participant".to_owned(),
        ));
    }
    Ok(group_iq(
        group_jid,
        "set",
        tag,
        vec![BinaryNode::new(action.tag()).with_content(participant_nodes)],
    ))
}

pub fn build_group_invite_code_query(
    group_jid: impl AsRef<str>,
    tag: impl Into<String>,
) -> CoreResult<BinaryNode> {
    let group_jid = validate_group_jid(group_jid.as_ref())?;
    Ok(group_iq(
        group_jid,
        "get",
        tag,
        vec![BinaryNode::new("invite")],
    ))
}

pub fn build_group_revoke_invite_query(
    group_jid: impl AsRef<str>,
    tag: impl Into<String>,
) -> CoreResult<BinaryNode> {
    let group_jid = validate_group_jid(group_jid.as_ref())?;
    Ok(group_iq(
        group_jid,
        "set",
        tag,
        vec![BinaryNode::new("invite")],
    ))
}

pub fn build_group_accept_invite_query(
    code: impl AsRef<str>,
    tag: impl Into<String>,
) -> CoreResult<BinaryNode> {
    let code = validate_non_empty("group invite code", code.as_ref())?;
    Ok(group_iq(
        GROUP_COLLECTION_JID,
        "set",
        tag,
        vec![BinaryNode::new("invite").with_attr("code", code)],
    ))
}

pub fn build_group_invite_info_query(
    code: impl AsRef<str>,
    tag: impl Into<String>,
) -> CoreResult<BinaryNode> {
    let code = validate_non_empty("group invite code", code.as_ref())?;
    Ok(group_iq(
        GROUP_COLLECTION_JID,
        "get",
        tag,
        vec![BinaryNode::new("invite").with_attr("code", code)],
    ))
}

pub fn build_group_revoke_invite_v4_query(
    group_jid: impl AsRef<str>,
    invited_jid: impl AsRef<str>,
    tag: impl Into<String>,
) -> CoreResult<BinaryNode> {
    let group_jid = validate_group_jid(group_jid.as_ref())?;
    let invited_jid = validate_participant_jid(invited_jid.as_ref())?;
    Ok(group_iq(
        group_jid,
        "set",
        tag,
        vec![BinaryNode::new("revoke").with_content(vec![
            BinaryNode::new("participant").with_attr("jid", invited_jid),
        ])],
    ))
}

pub fn build_group_accept_invite_v4_query(
    invite: &GroupInviteV4,
    tag: impl Into<String>,
) -> CoreResult<BinaryNode> {
    Ok(group_iq(
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

pub fn build_group_ephemeral_query(
    group_jid: impl AsRef<str>,
    duration_seconds: u32,
    tag: impl Into<String>,
) -> CoreResult<BinaryNode> {
    let group_jid = validate_group_jid(group_jid.as_ref())?;
    let node = if duration_seconds == 0 {
        BinaryNode::new("not_ephemeral")
    } else {
        BinaryNode::new("ephemeral").with_attr("expiration", duration_seconds.to_string())
    };
    Ok(group_iq(group_jid, "set", tag, vec![node]))
}

pub fn build_group_setting_query(
    group_jid: impl AsRef<str>,
    setting: GroupSettingUpdate,
    tag: impl Into<String>,
) -> CoreResult<BinaryNode> {
    let group_jid = validate_group_jid(group_jid.as_ref())?;
    Ok(group_iq(
        group_jid,
        "set",
        tag,
        vec![BinaryNode::new(setting.tag())],
    ))
}

pub fn build_group_member_add_mode_query(
    group_jid: impl AsRef<str>,
    mode: GroupMemberAddMode,
    tag: impl Into<String>,
) -> CoreResult<BinaryNode> {
    let group_jid = validate_group_jid(group_jid.as_ref())?;
    Ok(group_iq(
        group_jid,
        "set",
        tag,
        vec![BinaryNode::new("member_add_mode").with_content(mode.protocol_value())],
    ))
}

pub fn build_group_join_approval_mode_query(
    group_jid: impl AsRef<str>,
    mode: GroupJoinApprovalMode,
    tag: impl Into<String>,
) -> CoreResult<BinaryNode> {
    let group_jid = validate_group_jid(group_jid.as_ref())?;
    Ok(group_iq(
        group_jid,
        "set",
        tag,
        vec![
            BinaryNode::new("membership_approval_mode").with_content(vec![
                BinaryNode::new("group_join").with_attr("state", mode.state()),
            ]),
        ],
    ))
}

pub fn build_group_join_request_list_query(
    group_jid: impl AsRef<str>,
    tag: impl Into<String>,
) -> CoreResult<BinaryNode> {
    let group_jid = validate_group_jid(group_jid.as_ref())?;
    Ok(group_iq(
        group_jid,
        "get",
        tag,
        vec![BinaryNode::new("membership_approval_requests")],
    ))
}

pub fn build_group_join_request_action_query<I, T>(
    group_jid: impl AsRef<str>,
    participants: I,
    action: GroupJoinRequestAction,
    tag: impl Into<String>,
) -> CoreResult<BinaryNode>
where
    I: IntoIterator<Item = T>,
    T: AsRef<str>,
{
    let group_jid = validate_group_jid(group_jid.as_ref())?;
    let participant_nodes = participant_nodes(participants)?;
    if participant_nodes.is_empty() {
        return Err(CoreError::Protocol(
            "group join request update must include at least one participant".to_owned(),
        ));
    }
    Ok(group_iq(
        group_jid,
        "set",
        tag,
        vec![
            BinaryNode::new("membership_requests_action").with_content(vec![
                BinaryNode::new(action.tag()).with_content(participant_nodes),
            ]),
        ],
    ))
}

pub fn parse_group_metadata(node: &BinaryNode) -> CoreResult<GroupMetadata> {
    let group = group_node_from_result(node)?;
    parse_group_node(group)
}

pub fn parse_group_participating_result(node: &BinaryNode) -> CoreResult<Vec<GroupMetadata>> {
    if let Some(error) = error_from_result(node) {
        return Err(error);
    }
    let Some(groups_node) = child_node(node, "groups") else {
        return Ok(Vec::new());
    };
    child_nodes(groups_node)
        .iter()
        .filter(|child| child.tag == "group")
        .map(parse_group_node)
        .collect()
}

pub fn parse_group_participant_action_result(
    node: &BinaryNode,
    action: GroupParticipantAction,
) -> CoreResult<GroupParticipantActionResult> {
    if let Some(error) = error_from_result(node) {
        return Err(error);
    }
    let action_node = child_node(node, action.tag());
    let participants = action_node
        .map(|node| parse_participant_changes(node, true))
        .transpose()?
        .unwrap_or_default();
    Ok(GroupParticipantActionResult {
        group_jid: node.attrs.get("from").cloned(),
        action,
        participants,
    })
}

pub fn parse_group_invite_code(node: &BinaryNode) -> CoreResult<Option<String>> {
    if let Some(error) = error_from_result(node) {
        return Err(error);
    }
    Ok(child_node(node, "invite").and_then(|invite| invite.attrs.get("code").cloned()))
}

pub fn parse_group_accept_invite_result(node: &BinaryNode) -> CoreResult<Option<String>> {
    if let Some(error) = error_from_result(node) {
        return Err(error);
    }
    child_node(node, "group")
        .and_then(|group| group.attrs.get("jid").or_else(|| group.attrs.get("id")))
        .or_else(|| node.attrs.get("jid"))
        .map(|jid| group_jid_from_id(jid))
        .transpose()
}

pub fn parse_group_invite_v4_accept_result(node: &BinaryNode) -> CoreResult<Option<String>> {
    if let Some(error) = error_from_result(node) {
        return Err(error);
    }
    if node
        .attrs
        .get("type")
        .is_some_and(|value| value != "result")
    {
        return Ok(None);
    }
    node.attrs
        .get("from")
        .or_else(|| node.attrs.get("jid"))
        .or_else(|| child_node(node, "group").and_then(|group| group.attrs.get("jid")))
        .or_else(|| child_node(node, "group").and_then(|group| group.attrs.get("id")))
        .map(|jid| group_jid_from_id(jid))
        .transpose()
}

pub fn parse_group_invite_v4_result(node: &BinaryNode) -> CoreResult<bool> {
    if let Some(error) = error_from_result(node) {
        return Err(error);
    }
    Ok(node.attrs.get("type").is_none_or(|value| value == "result"))
}

pub fn parse_group_mutation_result(
    node: &BinaryNode,
    mutation: GroupMutationKind,
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
            group_error_suffix(&error)
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

pub fn parse_group_join_requests(node: &BinaryNode) -> CoreResult<Vec<GroupJoinRequest>> {
    if let Some(error) = error_from_result(node) {
        return Err(error);
    }
    let Some(requests_node) = child_node(node, "membership_approval_requests") else {
        return Ok(Vec::new());
    };
    child_nodes(requests_node)
        .iter()
        .filter(|child| child.tag == "membership_approval_request")
        .map(|request| {
            let jid = request
                .attrs
                .get("jid")
                .or_else(|| request.attrs.get("participant"))
                .ok_or_else(|| CoreError::Protocol("group join request missing JID".to_owned()))?;
            validate_participant_jid(jid)?;
            Ok(GroupJoinRequest {
                jid: jid.clone(),
                phone_number: attr_participant_jid_alias(
                    request,
                    &["phone_number", "phoneNumber", "pn", "pn_jid", "pnJid"],
                )?,
                lid: attr_participant_jid_alias(request, &["lid", "lid_jid", "lidJid"])?,
                username: attr_alias(
                    request,
                    &["participant_username", "participantUsername", "username"],
                ),
                requested_at: optional_u64_attr(request, "t")?,
                request_method: attr_alias(request, &["request_method", "requestMethod", "method"]),
            })
        })
        .collect()
}

pub fn parse_group_join_request_action_result(
    node: &BinaryNode,
    action: GroupJoinRequestAction,
) -> CoreResult<GroupJoinRequestActionResult> {
    if let Some(error) = error_from_result(node) {
        return Err(error);
    }
    let action_node = child_node(node, "membership_requests_action")
        .and_then(|wrapper| child_node(wrapper, action.tag()));
    let participants = action_node
        .map(|node| parse_participant_changes(node, false))
        .transpose()?
        .unwrap_or_default();
    Ok(GroupJoinRequestActionResult {
        action,
        participants,
    })
}

fn group_iq(
    to: impl Into<String>,
    query_type: &'static str,
    tag: impl Into<String>,
    content: Vec<BinaryNode>,
) -> BinaryNode {
    BinaryNode::new("iq")
        .with_attr("id", tag.into())
        .with_attr("to", to.into())
        .with_attr("type", query_type)
        .with_attr("xmlns", GROUP_QUERY_XMLNS)
        .with_content(content)
}

fn parse_group_node(group: &BinaryNode) -> CoreResult<GroupMetadata> {
    let id = group.attrs.get("id").ok_or_else(|| {
        CoreError::Protocol("group metadata response missing group id".to_owned())
    })?;
    let group_jid = group_jid_from_id(id)?;

    let description_node = child_node(group, "description");
    let description = description_node.and_then(|node| child_text(node, "body"));
    let description_id = description_node.and_then(|node| node.attrs.get("id").cloned());
    let description_owner = description_node
        .and_then(|node| node.attrs.get("participant"))
        .map(|jid| normalize_jid(jid))
        .transpose()?;
    let description_owner_pn = description_node
        .and_then(|node| node.attrs.get("participant_pn"))
        .map(|jid| normalize_jid(jid))
        .transpose()?;
    let description_owner_username =
        description_node.and_then(|node| node.attrs.get("participant_username").cloned());
    let description_time = description_node
        .map(|node| optional_u64_attr(node, "t"))
        .transpose()?
        .flatten();

    let participants = child_nodes(group)
        .iter()
        .filter(|child| child.tag == "participant")
        .map(parse_group_participant)
        .collect::<CoreResult<Vec<_>>>()?;

    let size = optional_usize_attr(group, "size")?.or(Some(participants.len()));
    let ephemeral_duration = child_node(group, "ephemeral")
        .map(|node| optional_u32_attr(node, "expiration"))
        .transpose()?
        .flatten();
    let addressing_mode = group
        .attrs
        .get("addressing_mode")
        .cloned()
        .or_else(|| child_node(group, "addressing_mode").and_then(node_text));

    Ok(GroupMetadata {
        jid: group_jid,
        notify: group.attrs.get("notify").cloned(),
        addressing_mode: if addressing_mode.as_deref() == Some("lid") {
            GroupAddressingMode::Lid
        } else {
            GroupAddressingMode::PhoneNumber
        },
        subject: group.attrs.get("subject").cloned(),
        subject_owner: group.attrs.get("s_o").cloned(),
        subject_owner_pn: group.attrs.get("s_o_pn").cloned(),
        subject_owner_username: group.attrs.get("s_o_username").cloned(),
        subject_time: optional_u64_attr(group, "s_t")?,
        size,
        creation: optional_u64_attr(group, "creation")?,
        owner: group
            .attrs
            .get("creator")
            .map(|jid| normalize_jid(jid))
            .transpose()?,
        owner_pn: group
            .attrs
            .get("creator_pn")
            .map(|jid| normalize_jid(jid))
            .transpose()?,
        owner_username: group.attrs.get("creator_username").cloned(),
        owner_country_code: group.attrs.get("creator_country_code").cloned(),
        description,
        description_id,
        description_owner,
        description_owner_pn,
        description_owner_username,
        description_time,
        linked_parent: child_node(group, "linked_parent")
            .and_then(|node| node.attrs.get("jid"))
            .map(|jid| {
                validate_group_jid(jid)?;
                Ok::<String, CoreError>(jid.clone())
            })
            .transpose()?,
        restrict: child_node(group, "locked").is_some(),
        announce: child_node(group, "announcement").is_some(),
        is_community: child_node(group, "parent").is_some(),
        is_community_announce: child_node(group, "default_sub_group").is_some(),
        join_approval_mode: child_node(group, "membership_approval_mode").is_some(),
        member_add_mode_all: child_node(group, "member_add_mode")
            .and_then(node_text)
            .is_some_and(|value| value == "all_member_add"),
        ephemeral_duration,
        participants,
    })
}

fn parse_group_participant(node: &BinaryNode) -> CoreResult<GroupParticipant> {
    let jid = node
        .attrs
        .get("jid")
        .ok_or_else(|| CoreError::Protocol("group participant missing JID".to_owned()))?;
    validate_participant_jid(jid)?;
    Ok(GroupParticipant {
        jid: jid.clone(),
        phone_number: attr_participant_jid_alias(
            node,
            &["phone_number", "phoneNumber", "pn", "pn_jid", "pnJid"],
        )?,
        lid: attr_participant_jid_alias(node, &["lid", "lid_jid", "lidJid"])?,
        username: attr_alias(
            node,
            &["participant_username", "participantUsername", "username"],
        ),
        role: match node.attrs.get("type").map(String::as_str) {
            Some("superadmin") => GroupParticipantRole::SuperAdmin,
            Some("admin") => GroupParticipantRole::Admin,
            _ => GroupParticipantRole::Member,
        },
    })
}

fn parse_participant_changes(
    node: &BinaryNode,
    include_content: bool,
) -> CoreResult<Vec<GroupParticipantChange>> {
    child_nodes(node)
        .iter()
        .filter(|child| child.tag == "participant")
        .map(|participant| {
            let jid = participant.attrs.get("jid").ok_or_else(|| {
                CoreError::Protocol("group participant result missing JID".to_owned())
            })?;
            validate_participant_jid(jid)?;
            let error_code = optional_u16_attr(participant, "error")?;
            let status = error_code
                .or(optional_u16_attr(participant, "status")?)
                .unwrap_or(SUCCESS_STATUS);
            Ok(GroupParticipantChange {
                jid: jid.clone(),
                status,
                error_code,
                content: include_content.then(|| (*participant).clone()),
            })
        })
        .collect()
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

fn group_jid_from_id(id: &str) -> CoreResult<String> {
    let jid = if id.contains('@') {
        id.to_owned()
    } else {
        jid_encode(id, JidServer::GUs, None, None)
    };
    validate_group_jid(&jid)?;
    Ok(jid)
}

fn group_node_from_result(node: &BinaryNode) -> CoreResult<&BinaryNode> {
    if node.tag == "group" {
        return Ok(node);
    }
    if let Some(group) = child_node(node, "group") {
        return Ok(group);
    }
    if let Some(error) = error_from_result(node) {
        return Err(error);
    }
    Err(CoreError::Protocol(
        "group metadata response missing group node".to_owned(),
    ))
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
        .unwrap_or("group query failed");
    Some(CoreError::Protocol(format!(
        "group query failed ({code}): {text}"
    )))
}

fn group_error_suffix(error: &CoreError) -> String {
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

fn child_text(node: &BinaryNode, child_tag: &str) -> Option<String> {
    child_node(node, child_tag).and_then(node_text)
}

fn attr_alias(node: &BinaryNode, attrs: &[&str]) -> Option<String> {
    attrs.iter().find_map(|attr| node.attrs.get(*attr).cloned())
}

fn attr_participant_jid_alias(node: &BinaryNode, attrs: &[&str]) -> CoreResult<Option<String>> {
    attr_alias(node, attrs)
        .map(|jid| {
            validate_participant_jid(&jid)?;
            Ok(jid)
        })
        .transpose()
}

fn node_text(node: &BinaryNode) -> Option<String> {
    match node.content.as_ref()? {
        BinaryNodeContent::Text(value) => Some(value.clone()),
        BinaryNodeContent::Bytes(value) => {
            std::str::from_utf8(value.as_ref()).ok().map(str::to_owned)
        }
        BinaryNodeContent::Nodes(_) => None,
    }
}

fn optional_u16_attr(node: &BinaryNode, attr: &str) -> CoreResult<Option<u16>> {
    node.attrs
        .get(attr)
        .map(|value| {
            value.parse::<u16>().map_err(|err| {
                CoreError::Protocol(format!("invalid group attribute {attr}: {err}"))
            })
        })
        .transpose()
}

fn optional_u32_attr(node: &BinaryNode, attr: &str) -> CoreResult<Option<u32>> {
    node.attrs
        .get(attr)
        .map(|value| {
            value.parse::<u32>().map_err(|err| {
                CoreError::Protocol(format!("invalid group attribute {attr}: {err}"))
            })
        })
        .transpose()
}

fn optional_u64_attr(node: &BinaryNode, attr: &str) -> CoreResult<Option<u64>> {
    node.attrs
        .get(attr)
        .map(|value| {
            value.parse::<u64>().map_err(|err| {
                CoreError::Protocol(format!("invalid group attribute {attr}: {err}"))
            })
        })
        .transpose()
}

fn optional_usize_attr(node: &BinaryNode, attr: &str) -> CoreResult<Option<usize>> {
    node.attrs
        .get(attr)
        .map(|value| {
            value.parse::<usize>().map_err(|err| {
                CoreError::Protocol(format!("invalid group attribute {attr}: {err}"))
            })
        })
        .transpose()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_metadata_and_create_queries() {
        let metadata = build_group_metadata_query("123@g.us", "q-1").unwrap();
        assert_eq!(metadata.attrs["id"], "q-1");
        assert_eq!(metadata.attrs["to"], "123@g.us");
        assert_eq!(metadata.attrs["type"], "get");
        assert_eq!(metadata.attrs["xmlns"], GROUP_QUERY_XMLNS);
        let query = child_node(&metadata, "query").unwrap();
        assert_eq!(query.attrs["request"], "interactive");

        let create = build_group_create_query(
            "Planning",
            ["111@s.whatsapp.net", "222@lid"],
            "msg-1",
            "q-2",
        )
        .unwrap();
        assert_eq!(create.attrs["to"], GROUP_COLLECTION_JID);
        let create_node = child_node(&create, "create").unwrap();
        assert_eq!(create_node.attrs["subject"], "Planning");
        assert_eq!(create_node.attrs["key"], "msg-1");
        assert_eq!(child_nodes(create_node).len(), 2);
    }

    #[test]
    fn builds_update_and_settings_queries() {
        let subject = build_group_subject_query("123@g.us", "New subject", "q-3").unwrap();
        let subject_node = child_node(&subject, "subject").unwrap();
        assert_eq!(node_text(subject_node).as_deref(), Some("New subject"));

        let description = build_group_description_query(
            "123@g.us",
            Some("New description"),
            Some("old"),
            Some("new"),
            "q-4",
        )
        .unwrap();
        let description_node = child_node(&description, "description").unwrap();
        assert_eq!(description_node.attrs["prev"], "old");
        assert_eq!(description_node.attrs["id"], "new");
        assert_eq!(
            child_text(description_node, "body").as_deref(),
            Some("New description")
        );

        let delete =
            build_group_description_query("123@g.us", None, Some("old"), None, "q-5").unwrap();
        let delete_node = child_node(&delete, "description").unwrap();
        assert_eq!(delete_node.attrs["delete"], "true");
        assert_eq!(delete_node.attrs["prev"], "old");

        let setting =
            build_group_setting_query("123@g.us", GroupSettingUpdate::Locked, "q-6").unwrap();
        assert!(child_node(&setting, "locked").is_some());

        let add_mode =
            build_group_member_add_mode_query("123@g.us", GroupMemberAddMode::AllMembers, "q-7")
                .unwrap();
        assert_eq!(
            child_node(&add_mode, "member_add_mode")
                .and_then(node_text)
                .as_deref(),
            Some("all_member_add")
        );

        let approval =
            build_group_join_approval_mode_query("123@g.us", GroupJoinApprovalMode::On, "q-8")
                .unwrap();
        let mode = child_node(&approval, "membership_approval_mode").unwrap();
        assert_eq!(child_node(mode, "group_join").unwrap().attrs["state"], "on");

        let revoke =
            build_group_revoke_invite_v4_query("123@g.us", "111@s.whatsapp.net", "q-9").unwrap();
        assert_eq!(revoke.attrs["to"], "123@g.us");
        assert_eq!(revoke.attrs["type"], "set");
        let revoke_node = child_node(&revoke, "revoke").unwrap();
        assert_eq!(
            child_node(revoke_node, "participant").unwrap().attrs["jid"],
            "111@s.whatsapp.net"
        );

        let invite = GroupInviteV4::new(
            "123@g.us",
            "invite-code",
            1_700_000_000,
            "222@s.whatsapp.net",
        )
        .unwrap();
        let accept = build_group_accept_invite_v4_query(&invite, "q-10").unwrap();
        assert_eq!(accept.attrs["to"], "123@g.us");
        let accept_node = child_node(&accept, "accept").unwrap();
        assert_eq!(accept_node.attrs["code"], "invite-code");
        assert_eq!(accept_node.attrs["expiration"], "1700000000");
        assert_eq!(accept_node.attrs["admin"], "222@s.whatsapp.net");
    }

    #[test]
    fn parses_group_metadata() {
        let node = BinaryNode::new("iq").with_content(vec![
            BinaryNode::new("group")
                .with_attr("id", "123")
                .with_attr("subject", "Team")
                .with_attr("s_t", "11")
                .with_attr("creation", "10")
                .with_attr("creator", "111@c.us")
                .with_attr("size", "2")
                .with_attr("addressing_mode", "lid")
                .with_content(vec![
                    BinaryNode::new("description")
                        .with_attr("id", "desc-1")
                        .with_attr("participant", "111@s.whatsapp.net")
                        .with_attr("t", "12")
                        .with_content(vec![
                            BinaryNode::new("body").with_content(Bytes::from_static(b"hello")),
                        ]),
                    BinaryNode::new("locked"),
                    BinaryNode::new("announcement"),
                    BinaryNode::new("membership_approval_mode"),
                    BinaryNode::new("member_add_mode").with_content("all_member_add"),
                    BinaryNode::new("ephemeral").with_attr("expiration", "86400"),
                    BinaryNode::new("participant")
                        .with_attr("jid", "111@s.whatsapp.net")
                        .with_attr("type", "admin")
                        .with_attr("lid", "abc@lid"),
                    BinaryNode::new("participant")
                        .with_attr("jid", "222@lid")
                        .with_attr("phoneNumber", "222@s.whatsapp.net")
                        .with_attr("lid_jid", "222@lid")
                        .with_attr("participantUsername", "two"),
                ]),
        ]);

        let metadata = parse_group_metadata(&node).unwrap();
        assert_eq!(metadata.jid, "123@g.us");
        assert_eq!(metadata.subject.as_deref(), Some("Team"));
        assert_eq!(metadata.subject_time, Some(11));
        assert_eq!(metadata.creation, Some(10));
        assert_eq!(metadata.owner.as_deref(), Some("111@s.whatsapp.net"));
        assert_eq!(metadata.description.as_deref(), Some("hello"));
        assert_eq!(metadata.description_id.as_deref(), Some("desc-1"));
        assert_eq!(metadata.description_time, Some(12));
        assert_eq!(metadata.addressing_mode, GroupAddressingMode::Lid);
        assert!(metadata.restrict);
        assert!(metadata.announce);
        assert!(metadata.join_approval_mode);
        assert!(metadata.member_add_mode_all);
        assert_eq!(metadata.ephemeral_duration, Some(86400));
        assert_eq!(metadata.participants.len(), 2);
        assert_eq!(metadata.participants[0].role, GroupParticipantRole::Admin);
        assert_eq!(metadata.participants[0].lid.as_deref(), Some("abc@lid"));
        assert_eq!(
            metadata.participants[1].phone_number.as_deref(),
            Some("222@s.whatsapp.net")
        );
        assert_eq!(metadata.participants[1].lid.as_deref(), Some("222@lid"));
        assert_eq!(metadata.participants[1].username.as_deref(), Some("two"));

        let participating_error = BinaryNode::new("iq")
            .with_attr("type", "error")
            .with_attr("code", "503")
            .with_attr("text", "groups unavailable");
        assert!(matches!(
            parse_group_participating_result(&participating_error),
            Err(CoreError::Protocol(message))
                if message == "group query failed (503): groups unavailable"
        ));

        let invalid_participant_alias = BinaryNode::new("iq").with_content(vec![
            BinaryNode::new("group")
                .with_attr("id", "123")
                .with_content(vec![
                    BinaryNode::new("participant")
                        .with_attr("jid", "111@s.whatsapp.net")
                        .with_attr("phoneNumber", "not-a-jid"),
                ]),
        ]);
        assert!(parse_group_metadata(&invalid_participant_alias).is_err());

        let invalid_linked_parent = BinaryNode::new("iq").with_content(vec![
            BinaryNode::new("group")
                .with_attr("id", "123")
                .with_content(vec![
                    BinaryNode::new("linked_parent").with_attr("jid", "111@s.whatsapp.net"),
                ]),
        ]);
        assert!(parse_group_metadata(&invalid_linked_parent).is_err());
    }

    #[test]
    fn parses_participant_and_join_request_results() {
        let participants =
            BinaryNode::new("iq").with_content(vec![BinaryNode::new("add").with_content(vec![
                BinaryNode::new("participant").with_attr("jid", "111@s.whatsapp.net"),
                BinaryNode::new("participant")
                    .with_attr("jid", "222@s.whatsapp.net")
                    .with_attr("error", "403"),
            ])]);
        let result =
            parse_group_participant_action_result(&participants, GroupParticipantAction::Add)
                .unwrap();
        assert_eq!(result.participants[0].status, SUCCESS_STATUS);
        assert_eq!(result.participants[1].status, 403);
        assert_eq!(result.participants[1].error_code, Some(403));
        assert_eq!(
            result.participants[1]
                .content
                .as_ref()
                .and_then(|node| node.attrs.get("error"))
                .map(String::as_str),
            Some("403")
        );

        let requests = BinaryNode::new("iq").with_content(vec![
            BinaryNode::new("membership_approval_requests").with_content(vec![
                BinaryNode::new("membership_approval_request")
                    .with_attr("jid", "333@s.whatsapp.net")
                    .with_attr("phoneNumber", "333@s.whatsapp.net")
                    .with_attr("lidJid", "333@lid")
                    .with_attr("participantUsername", "three")
                    .with_attr("t", "55")
                    .with_attr("requestMethod", "invite_link"),
            ]),
        ]);
        assert_eq!(
            parse_group_join_requests(&requests).unwrap(),
            vec![GroupJoinRequest {
                jid: "333@s.whatsapp.net".to_owned(),
                phone_number: Some("333@s.whatsapp.net".to_owned()),
                lid: Some("333@lid".to_owned()),
                username: Some("three".to_owned()),
                requested_at: Some(55),
                request_method: Some("invite_link".to_owned()),
            }]
        );
        let invalid_request_alias = BinaryNode::new("iq").with_content(vec![
            BinaryNode::new("membership_approval_requests").with_content(vec![
                BinaryNode::new("membership_approval_request")
                    .with_attr("jid", "333@s.whatsapp.net")
                    .with_attr("lidJid", "not-a-jid"),
            ]),
        ]);
        assert!(parse_group_join_requests(&invalid_request_alias).is_err());

        let action = BinaryNode::new("iq").with_content(vec![
            BinaryNode::new("membership_requests_action").with_content(vec![
                BinaryNode::new("approve").with_content(vec![
                    BinaryNode::new("participant").with_attr("jid", "333@s.whatsapp.net"),
                ]),
            ]),
        ]);
        let action_result =
            parse_group_join_request_action_result(&action, GroupJoinRequestAction::Approve)
                .unwrap();
        assert_eq!(action_result.participants.len(), 1);
        assert_eq!(action_result.participants[0].status, SUCCESS_STATUS);
        assert!(action_result.participants[0].content.is_none());

        assert!(
            parse_group_invite_v4_result(
                &BinaryNode::new("iq")
                    .with_attr("type", "result")
                    .with_content(vec![BinaryNode::new("accept")])
            )
            .unwrap()
        );
        assert!(
            parse_group_invite_v4_result(
                &BinaryNode::new("iq")
                    .with_attr("type", "result")
                    .with_content(vec![BinaryNode::new("revoke")])
            )
            .unwrap()
        );
        assert_eq!(
            parse_group_invite_v4_accept_result(
                &BinaryNode::new("iq")
                    .with_attr("type", "result")
                    .with_attr("from", "123@g.us")
                    .with_content(vec![BinaryNode::new("accept")])
            )
            .unwrap()
            .as_deref(),
            Some("123@g.us")
        );
        assert_eq!(
            parse_group_invite_v4_accept_result(
                &BinaryNode::new("iq")
                    .with_attr("type", "result")
                    .with_content(vec![BinaryNode::new("group").with_attr("id", "456")])
            )
            .unwrap()
            .as_deref(),
            Some("456@g.us")
        );
        assert!(
            parse_group_invite_v4_accept_result(
                &BinaryNode::new("iq")
                    .with_attr("type", "result")
                    .with_attr("from", "111@s.whatsapp.net")
            )
            .is_err()
        );
    }

    #[test]
    fn parses_group_mutation_results() {
        let result = BinaryNode::new("iq").with_attr("type", "result");
        for mutation in [
            GroupMutationKind::Leave,
            GroupMutationKind::Subject,
            GroupMutationKind::Description,
            GroupMutationKind::Ephemeral,
            GroupMutationKind::Setting,
            GroupMutationKind::MemberAddMode,
            GroupMutationKind::JoinApprovalMode,
        ] {
            assert!(parse_group_mutation_result(&result, mutation).is_ok());
        }

        let attr_error = BinaryNode::new("iq")
            .with_attr("type", "error")
            .with_attr("code", "403")
            .with_attr("text", "denied");
        assert!(matches!(
            parse_group_mutation_result(&attr_error, GroupMutationKind::Setting),
            Err(CoreError::Protocol(message))
                if message == "group setting mutation failed: group query failed (403): denied"
        ));

        let child_error = BinaryNode::new("iq")
            .with_attr("type", "result")
            .with_content(vec![
                BinaryNode::new("error")
                    .with_attr("code", "500")
                    .with_attr("text", "server rejected update"),
            ]);
        assert!(matches!(
            parse_group_mutation_result(&child_error, GroupMutationKind::Ephemeral),
            Err(CoreError::Protocol(message))
                if message == "group ephemeral mutation failed: group query failed (500): server rejected update"
        ));

        let invalid = BinaryNode::new("message").with_attr("type", "result");
        assert!(matches!(
            parse_group_mutation_result(&invalid, GroupMutationKind::Leave),
            Err(CoreError::Protocol(message))
                if message == "group leave mutation response must be iq, got message"
        ));
    }

    #[test]
    fn rejects_invalid_group_and_participant_jids() {
        assert!(build_group_metadata_query("123@s.whatsapp.net", "q-1").is_err());
        assert!(
            build_group_participants_query(
                "123@g.us",
                GroupParticipantAction::Add,
                ["other@g.us"],
                "q-2"
            )
            .is_err()
        );
        assert!(GroupInviteV4::new("123@s.whatsapp.net", "code", 1, "111@s.whatsapp.net").is_err());
        assert!(GroupInviteV4::new("123@g.us", "", 1, "111@s.whatsapp.net").is_err());
        assert!(GroupInviteV4::new("123@g.us", "code", 1, "111@g.us").is_err());
        assert!(build_group_revoke_invite_v4_query("123@g.us", "111@g.us", "q-3").is_err());
    }
}
