#![no_main]

use libfuzzer_sys::fuzz_target;
use wa_binary::{BinaryNode, decode_binary_node};
use wa_core::{
    CommunityMutationKind, GroupJoinRequestAction, GroupParticipantAction,
    parse_community_accept_invite_result, parse_community_create_result_jid,
    parse_community_invite_code, parse_community_invite_info_result,
    parse_community_invite_v4_result, parse_community_join_request_action_result,
    parse_community_join_requests, parse_community_linked_groups, parse_community_metadata,
    parse_community_mutation_result, parse_community_participant_action_result,
    parse_community_participating_result,
};

const MAX_INPUT_LEN: usize = 64 * 1024;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_LEN {
        return;
    }

    if let Ok(node) = decode_binary_node(data) {
        drive_community_parsers(&node);
    }

    let node = structured_community_node(data);
    drive_community_parsers(&node);
});

fn drive_community_parsers(node: &BinaryNode) {
    let _ = parse_community_metadata(node);
    let _ = parse_community_participating_result(node);
    let _ = parse_community_linked_groups(node);
    let _ = parse_community_join_requests(node);
    let _ = parse_community_invite_code(node);
    let _ = parse_community_invite_info_result(node);
    let _ = parse_community_accept_invite_result(node);
    let _ = parse_community_create_result_jid(node);
    let _ = parse_community_invite_v4_result(node);

    for action in [
        GroupParticipantAction::Add,
        GroupParticipantAction::Remove,
        GroupParticipantAction::Promote,
        GroupParticipantAction::Demote,
    ] {
        let _ = parse_community_participant_action_result(node, action);
    }
    for action in [
        GroupJoinRequestAction::Approve,
        GroupJoinRequestAction::Reject,
    ] {
        let _ = parse_community_join_request_action_result(node, action);
    }
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
        let _ = parse_community_mutation_result(node, mutation);
    }
}

fn structured_community_node(data: &[u8]) -> BinaryNode {
    match data.first().copied().unwrap_or_default() % 9 {
        0 => metadata_result(data),
        1 => participating_result(data),
        2 => linked_groups_result(data),
        3 => join_requests_result(data),
        4 => participant_action_result(data),
        5 => join_request_action_result(data),
        6 => invite_result(data),
        7 => create_result(data),
        _ => mutation_result(data),
    }
}

fn metadata_result(data: &[u8]) -> BinaryNode {
    BinaryNode::new("iq").with_content(vec![community_node(data, 1)])
}

fn participating_result(data: &[u8]) -> BinaryNode {
    let wrapper = if data.get(1).copied().unwrap_or_default().is_multiple_of(2) {
        "communities"
    } else {
        "groups"
    };
    let first = if wrapper == "groups" {
        group_community_node(data, 1)
    } else {
        community_node(data, 1)
    };
    BinaryNode::new("iq").with_content(vec![
        BinaryNode::new(wrapper).with_content(vec![first, community_node(data, 2)]),
    ])
}

fn linked_groups_result(data: &[u8]) -> BinaryNode {
    let wrapper = match data.get(1).copied().unwrap_or_default() % 3 {
        0 => "sub_groups",
        1 => "linked_groups",
        _ => "groups",
    };
    let first_tag = if wrapper == "linked_groups" {
        "linked_group"
    } else {
        "group"
    };
    let second_tag = if wrapper == "groups" {
        "community"
    } else {
        "group"
    };
    BinaryNode::new("iq").with_content(vec![BinaryNode::new(wrapper).with_content(vec![
        BinaryNode::new(first_tag)
            .with_attr("id", group_id(data.get(1).copied().unwrap_or_default()))
            .with_attr("subject", fuzz_text(data))
            .with_attr("creator", account_jid(data.get(2).copied().unwrap_or_default()))
            .with_attr("creation", fuzz_number(data.get(3).copied().unwrap_or_default()))
            .with_attr("size", fuzz_number(data.get(4).copied().unwrap_or_default())),
        BinaryNode::new(second_tag)
            .with_attr("jid", group_jid(data.get(5).copied().unwrap_or_default()))
            .with_attr("subject", fuzz_text(data)),
    ])])
}

fn join_requests_result(data: &[u8]) -> BinaryNode {
    BinaryNode::new("iq").with_content(vec![
        BinaryNode::new("membership_approval_requests").with_content(vec![
            BinaryNode::new("membership_approval_request")
                .with_attr("jid", account_jid(data.get(1).copied().unwrap_or_default()))
                .with_attr("t", fuzz_number(data.get(2).copied().unwrap_or_default()))
                .with_attr("request_method", request_method(data)),
            BinaryNode::new("membership_approval_request").with_attr(
                "participant",
                account_jid(data.get(3).copied().unwrap_or_default()),
            ),
        ]),
    ])
}

fn participant_action_result(data: &[u8]) -> BinaryNode {
    let action = participant_action(data);
    BinaryNode::new("iq")
        .with_attr("from", group_jid(data.get(1).copied().unwrap_or_default()))
        .with_content(vec![BinaryNode::new(action).with_content(vec![
            participant_node(data.get(2).copied().unwrap_or_default()),
            participant_node(data.get(3).copied().unwrap_or_default()),
        ])])
}

fn join_request_action_result(data: &[u8]) -> BinaryNode {
    let action = join_action(data);
    BinaryNode::new("iq").with_content(vec![
        BinaryNode::new("membership_requests_action").with_content(vec![
            BinaryNode::new(action).with_content(vec![
                participant_node(data.get(1).copied().unwrap_or_default()),
                participant_node(data.get(2).copied().unwrap_or_default()),
            ]),
        ]),
    ])
}

fn invite_result(data: &[u8]) -> BinaryNode {
    match data.get(1).copied().unwrap_or_default() % 3 {
        0 => BinaryNode::new("iq").with_content(vec![
            BinaryNode::new("invite").with_attr("code", fuzz_id("invite", data, 2)),
        ]),
        1 => BinaryNode::new("iq").with_content(vec![
            BinaryNode::new("group")
                .with_attr("jid", group_jid(data.get(2).copied().unwrap_or_default())),
        ]),
        _ => BinaryNode::new("iq").with_attr("type", "result"),
    }
}

fn create_result(data: &[u8]) -> BinaryNode {
    match data.get(1).copied().unwrap_or_default() % 5 {
        0 => BinaryNode::new("iq").with_content(vec![
            BinaryNode::new("group")
                .with_attr("id", group_id(data.get(2).copied().unwrap_or_default())),
        ]),
        1 => BinaryNode::new("iq").with_content(vec![
            BinaryNode::new("community")
                .with_attr("id", group_id(data.get(2).copied().unwrap_or_default())),
        ]),
        2 => BinaryNode::new("iq")
            .with_attr("type", "result")
            .with_attr("from", group_jid(data.get(2).copied().unwrap_or_default())),
        3 => BinaryNode::new("iq")
            .with_attr("type", "result")
            .with_attr("jid", group_jid(data.get(2).copied().unwrap_or_default())),
        _ => BinaryNode::new("iq").with_content(vec![community_node(data, 2)]),
    }
}

fn mutation_result(data: &[u8]) -> BinaryNode {
    match data.get(1).copied().unwrap_or_default() % 4 {
        0 => BinaryNode::new("iq").with_attr("type", "result"),
        1 => BinaryNode::new("iq")
            .with_attr("type", "error")
            .with_attr(
                "code",
                fuzz_number(data.get(2).copied().unwrap_or_default()),
            )
            .with_attr("text", fuzz_text(data)),
        2 => BinaryNode::new("iq")
            .with_attr("type", "result")
            .with_content(vec![
                BinaryNode::new("error")
                    .with_attr(
                        "code",
                        fuzz_number(data.get(2).copied().unwrap_or_default()),
                    )
                    .with_attr("text", fuzz_text(data)),
            ]),
        _ => BinaryNode::new("message").with_attr("type", "result"),
    }
}

fn community_node(data: &[u8], offset: usize) -> BinaryNode {
    BinaryNode::new("community")
        .with_attr(
            "id",
            group_id(data.get(offset).copied().unwrap_or_default()),
        )
        .with_attr("subject", fuzz_text(data))
        .with_attr(
            "creator",
            account_jid(data.get(offset + 1).copied().unwrap_or_default()),
        )
        .with_content(vec![
            BinaryNode::new("parent"),
            BinaryNode::new("default_sub_community"),
            BinaryNode::new("description")
                .with_attr("id", fuzz_id("desc", data, offset + 2))
                .with_content(vec![BinaryNode::new("body").with_content(fuzz_text(data))]),
            BinaryNode::new("participant")
                .with_attr(
                    "jid",
                    account_jid(data.get(offset + 3).copied().unwrap_or_default()),
                )
                .with_attr("type", participant_role(data)),
        ])
}

fn group_community_node(data: &[u8], offset: usize) -> BinaryNode {
    let mut node = community_node(data, offset);
    node.tag = "group".to_owned();
    node
}

fn participant_node(byte: u8) -> BinaryNode {
    BinaryNode::new("participant")
        .with_attr("jid", account_jid(byte))
        .with_attr("status", fuzz_number(byte.wrapping_add(1)))
        .with_attr("error", fuzz_number(byte.wrapping_add(2)))
}

fn group_id(byte: u8) -> String {
    match byte % 4 {
        0 => format!("{}", 1000 + u16::from(byte)),
        1 => group_jid(byte),
        2 => String::new(),
        _ => format!("bad-group-{byte}"),
    }
}

fn group_jid(byte: u8) -> String {
    match byte % 4 {
        0 | 1 => format!("{}@g.us", 2000 + u16::from(byte)),
        2 => format!("{}@s.whatsapp.net", 3000 + u16::from(byte)),
        _ => format!("not-a-group-{byte}"),
    }
}

fn account_jid(byte: u8) -> String {
    match byte % 5 {
        0 => format!("{}@s.whatsapp.net", 100 + u16::from(byte)),
        1 => format!("{}@c.us", 200 + u16::from(byte)),
        2 => format!("{}@lid", 300 + u16::from(byte)),
        3 => String::new(),
        _ => format!("not-a-jid-{byte}"),
    }
}

fn fuzz_id(prefix: &str, data: &[u8], index: usize) -> String {
    let byte = data.get(index).copied().unwrap_or_default();
    if byte.is_multiple_of(7) {
        String::new()
    } else {
        format!("{prefix}-{byte}")
    }
}

fn fuzz_text(data: &[u8]) -> String {
    let text = data
        .iter()
        .skip(8)
        .take(40)
        .filter_map(|byte| {
            let ch = char::from(*byte);
            (ch.is_ascii_alphanumeric() || ch == ' ').then_some(ch)
        })
        .collect::<String>();
    if text.trim().is_empty() {
        "Community".to_owned()
    } else {
        text
    }
}

fn fuzz_number(byte: u8) -> String {
    if byte.is_multiple_of(6) {
        "not-a-number".to_owned()
    } else {
        u32::from(byte).saturating_mul(10).to_string()
    }
}

fn participant_action(data: &[u8]) -> &'static str {
    match data.get(4).copied().unwrap_or_default() % 4 {
        0 => "add",
        1 => "remove",
        2 => "promote",
        _ => "demote",
    }
}

fn join_action(data: &[u8]) -> &'static str {
    if data.get(5).copied().unwrap_or_default().is_multiple_of(2) {
        "approve"
    } else {
        "reject"
    }
}

fn participant_role(data: &[u8]) -> &'static str {
    match data.get(6).copied().unwrap_or_default() % 4 {
        0 => "admin",
        1 => "superadmin",
        2 => "member",
        _ => "",
    }
}

fn request_method(data: &[u8]) -> &'static str {
    match data.get(7).copied().unwrap_or_default() % 3 {
        0 => "invite_link",
        1 => "non_admin_add",
        _ => "",
    }
}
