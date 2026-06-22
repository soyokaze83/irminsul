#![no_main]

use libfuzzer_sys::fuzz_target;
use wa_binary::{BinaryNode, decode_binary_node};
use wa_core::{
    event_batch_from_group_notification_node, group_message_events_from_group_update_events,
    group_update_event_from_notification_node, parse_inbound_notification,
};

const MAX_INPUT_LEN: usize = 64 * 1024;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_LEN {
        return;
    }

    if let Ok(node) = decode_binary_node(data) {
        drive_group_notification_parsers(&node);
    }

    let node = structured_group_notification(data);
    drive_group_notification_parsers(&node);
});

fn drive_group_notification_parsers(node: &BinaryNode) {
    let Ok(notification) = parse_inbound_notification(node) else {
        return;
    };

    let _ = group_update_event_from_notification_node(node, &notification);
    if let Ok(Some(batch)) = event_batch_from_group_notification_node(node, &notification) {
        let _ = group_message_events_from_group_update_events(&batch.groups_update);
    }
}

fn structured_group_notification(data: &[u8]) -> BinaryNode {
    let case = data.first().copied().unwrap_or_default() % 15;
    let actor = fuzz_jid(data.get(1).copied().unwrap_or_default());
    let participant = fuzz_jid(data.get(2).copied().unwrap_or_default());
    let secondary = fuzz_jid(data.get(3).copied().unwrap_or_default());
    let text = fuzz_text(data);
    let timestamp = fuzz_number(data.get(4).copied().unwrap_or_default());

    let children = match case {
        0 => vec![
            BinaryNode::new("subject")
                .with_attr("participant", actor.as_str())
                .with_attr("s_t", timestamp.as_str())
                .with_content(text.clone()),
        ],
        1 => vec![
            BinaryNode::new("description")
                .with_attr("id", text.as_str())
                .with_attr("participant", actor.as_str())
                .with_attr(
                    "delete",
                    bool_text(data.get(5).copied().unwrap_or_default()),
                )
                .with_content(text.clone()),
        ],
        2 => vec![BinaryNode::new("add").with_content(vec![
            participant_node(&participant, data.get(5).copied().unwrap_or_default()),
            participant_node(&secondary, data.get(6).copied().unwrap_or_default()),
        ])],
        3 => vec![
            BinaryNode::new("remove").with_content(vec![participant_node(
                &participant,
                data.get(5).copied().unwrap_or_default(),
            )]),
        ],
        4 => vec![
            BinaryNode::new("membership_approval_requests").with_content(vec![
                BinaryNode::new("membership_approval_request")
                    .with_attr("jid", participant.as_str())
                    .with_attr("t", timestamp.as_str())
                    .with_attr(
                        "request_method",
                        method_text(data.get(5).copied().unwrap_or_default()),
                    ),
            ]),
        ],
        5 => vec![
            BinaryNode::new("membership_requests_action").with_content(vec![
                BinaryNode::new("approve").with_content(vec![participant_node(
                    &participant,
                    data.get(5).copied().unwrap_or_default(),
                )]),
                BinaryNode::new("reject").with_content(vec![participant_node(
                    &secondary,
                    data.get(6).copied().unwrap_or_default(),
                )]),
            ]),
        ],
        6 => vec![
            BinaryNode::new("created_membership_requests")
                .with_attr("participant", participant.as_str())
                .with_attr("participant_pn", secondary.as_str())
                .with_attr(
                    "request_method",
                    method_text(data.get(5).copied().unwrap_or_default()),
                )
                .with_attr("t", timestamp.as_str()),
        ],
        7 => vec![
            BinaryNode::new("revoked_membership_requests").with_content(vec![participant_node(
                &participant,
                data.get(5).copied().unwrap_or_default(),
            )]),
        ],
        8 => vec![
            BinaryNode::new("invite")
                .with_attr("code", text.as_str())
                .with_attr("expiration", timestamp.as_str())
                .with_attr("admin", actor.as_str())
                .with_content(vec![participant_node(
                    &participant,
                    data.get(5).copied().unwrap_or_default(),
                )]),
        ],
        9 => vec![
            BinaryNode::new("accept")
                .with_attr("code", text.as_str())
                .with_attr("admin", actor.as_str())
                .with_content(vec![participant_node(
                    &participant,
                    data.get(5).copied().unwrap_or_default(),
                )]),
        ],
        10 => vec![
            BinaryNode::new("revoke")
                .with_attr("code", text.as_str())
                .with_content(vec![participant_node(
                    &participant,
                    data.get(5).copied().unwrap_or_default(),
                )]),
        ],
        11 => vec![BinaryNode::new("picture").with_content(vec![
            BinaryNode::new(if data.get(5).copied().unwrap_or_default() % 2 == 0 {
                "set"
            } else {
                "delete"
            })
            .with_attr("id", text.as_str())
            .with_attr("author", actor.as_str()),
        ])],
        12 => vec![
            BinaryNode::new("parent").with_attr(
                "default_membership_approval_mode",
                bool_text(data.get(5).copied().unwrap_or_default()),
            ),
            BinaryNode::new("default_sub_group"),
            BinaryNode::new("linked_parent").with_attr("jid", secondary.as_str()),
        ],
        13 => vec![
            BinaryNode::new("ephemeral").with_attr("expiration", timestamp.as_str()),
            BinaryNode::new("member_add_mode")
                .with_content(mode_text(data.get(5).copied().unwrap_or_default())),
            BinaryNode::new("membership_approval_mode").with_content(vec![
                BinaryNode::new("group_join")
                    .with_attr("state", bool_text(data.get(6).copied().unwrap_or_default())),
            ]),
        ],
        _ => vec![
            BinaryNode::new("leave").with_content(vec![participant_node(
                &participant,
                data.get(5).copied().unwrap_or_default(),
            )]),
            BinaryNode::new("modify").with_content(vec![participant_node(
                &secondary,
                data.get(6).copied().unwrap_or_default(),
            )]),
        ],
    };

    BinaryNode::new("notification")
        .with_attr("id", format!("fuzz-{}", data.len()))
        .with_attr("from", "123@g.us")
        .with_attr("type", "w:gp2")
        .with_attr("participant", actor)
        .with_attr("t", timestamp)
        .with_content(children)
}

fn participant_node(jid: &str, byte: u8) -> BinaryNode {
    BinaryNode::new("participant")
        .with_attr("jid", jid)
        .with_attr("status", fuzz_number(byte))
        .with_attr("error", fuzz_number(byte.wrapping_add(1)))
        .with_attr("type", role_text(byte))
        .with_attr("phone_number", fuzz_jid(byte.wrapping_add(2)))
        .with_attr("lid", fuzz_lid(byte.wrapping_add(3)))
        .with_attr("participant_username", format!("user{byte}"))
}

fn fuzz_jid(byte: u8) -> String {
    match byte % 5 {
        0 => format!("{}@s.whatsapp.net", 100 + u16::from(byte)),
        1 => format!("{}@lid", 200 + u16::from(byte)),
        2 => format!("{}@g.us", 300 + u16::from(byte)),
        3 => String::new(),
        _ => format!("not-a-jid-{byte}"),
    }
}

fn fuzz_lid(byte: u8) -> String {
    if byte.is_multiple_of(3) {
        String::new()
    } else {
        format!("{}@lid", 400 + u16::from(byte))
    }
}

fn fuzz_text(data: &[u8]) -> String {
    let bytes = data.iter().skip(7).take(48).copied().collect::<Vec<_>>();
    String::from_utf8_lossy(&bytes)
        .chars()
        .filter(|ch| !ch.is_control())
        .take(32)
        .collect()
}

fn fuzz_number(byte: u8) -> String {
    u32::from(byte).saturating_mul(1000).to_string()
}

fn bool_text(byte: u8) -> &'static str {
    if byte.is_multiple_of(2) {
        "true"
    } else {
        "false"
    }
}

fn method_text(byte: u8) -> &'static str {
    match byte % 3 {
        0 => "invite_link",
        1 => "non_admin_add",
        _ => "",
    }
}

fn mode_text(byte: u8) -> &'static str {
    match byte % 3 {
        0 => "all_member_add",
        1 => "admin_add",
        _ => "",
    }
}

fn role_text(byte: u8) -> &'static str {
    match byte % 4 {
        0 => "admin",
        1 => "superadmin",
        2 => "",
        _ => "member",
    }
}
