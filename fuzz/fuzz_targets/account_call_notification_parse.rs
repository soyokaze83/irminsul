#![no_main]

use libfuzzer_sys::fuzz_target;
use wa_binary::{BinaryNode, decode_binary_node};
use wa_core::{
    account_update_event_from_notification_node, blocklist_update_events_from_notification_node,
    call_events_from_node, call_message_events_from_call_events,
    default_disappearing_mode_from_notification_node, device_list_notification_from_node,
    event_batch_from_notification_node, parse_account_update_notification,
    parse_inbound_notification, presence_event_from_node,
    server_sync_collections_from_notification_node,
};

const MAX_INPUT_LEN: usize = 64 * 1024;
const NOW_SECONDS: u64 = 1_700_000_000;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_LEN {
        return;
    }

    if let Ok(node) = decode_binary_node(data) {
        drive_account_call_parsers(&node);
    }

    let notification = structured_account_notification(data);
    drive_account_call_parsers(&notification);

    let call = structured_call_node(data);
    drive_account_call_parsers(&call);

    let presence = structured_presence_node(data);
    drive_account_call_parsers(&presence);

    let chatstate = structured_chatstate_node(data);
    drive_account_call_parsers(&chatstate);
});

fn drive_account_call_parsers(node: &BinaryNode) {
    let _ = parse_account_update_notification(node, NOW_SECONDS);
    let _ = account_update_event_from_notification_node(node, NOW_SECONDS);

    if let Ok(notification) = parse_inbound_notification(node) {
        let _ = blocklist_update_events_from_notification_node(node, &notification);
        let _ = default_disappearing_mode_from_notification_node(node, &notification);
        let _ = server_sync_collections_from_notification_node(node, &notification);
        let _ = device_list_notification_from_node(node, &notification);
        let _ = event_batch_from_notification_node(node, &notification);
    }

    if let Ok(calls) = call_events_from_node(node) {
        let _ = call_message_events_from_call_events(&calls);
    }
    let _ = presence_event_from_node(node);
}

fn structured_account_notification(data: &[u8]) -> BinaryNode {
    let case = data.first().copied().unwrap_or_default() % 8;
    let from = valid_account_jid(data.get(1).copied().unwrap_or_default());
    let participant = fuzz_account_jid(data.get(2).copied().unwrap_or_default());
    let timestamp = fuzz_number(data.get(3).copied().unwrap_or_default());
    let id = fuzz_id("account", data, 4);

    let (notification_type, children) = match case {
        0 => (
            "mex",
            vec![
                BinaryNode::new("update")
                    .with_attr("op_name", "NotificationUserReachoutTimelockUpdate")
                    .with_content(reachout_json(data).into_bytes()),
            ],
        ),
        1 => (
            "mex",
            vec![
                BinaryNode::new("update")
                    .with_attr("op_name", "MessageCappingInfoNotification")
                    .with_content(capping_json(data).into_bytes()),
            ],
        ),
        2 => (
            "account_sync",
            vec![BinaryNode::new("blocklist").with_content(vec![
                    BinaryNode::new("item")
                        .with_attr(
                            "jid",
                            fuzz_account_jid(data.get(5).copied().unwrap_or_default()),
                        )
                        .with_attr(
                            "action",
                            blocklist_action(data.get(6).copied().unwrap_or_default()),
                        ),
                    BinaryNode::new("item")
                        .with_attr(
                            "jid",
                            fuzz_account_jid(data.get(7).copied().unwrap_or_default()),
                        )
                        .with_attr(
                            "action",
                            blocklist_action(data.get(8).copied().unwrap_or_default()),
                        ),
                ])],
        ),
        3 => (
            "account_sync",
            vec![
                BinaryNode::new("disappearing_mode")
                    .with_attr(
                        "duration",
                        disappearing_duration(data.get(5).copied().unwrap_or_default()),
                    )
                    .with_attr("t", fuzz_number(data.get(6).copied().unwrap_or_default())),
            ],
        ),
        4 => (
            "server_sync",
            vec![
                BinaryNode::new("collection").with_attr(
                    "name",
                    collection_name(data.get(5).copied().unwrap_or_default()),
                ),
                BinaryNode::new("collection").with_attr(
                    "name",
                    collection_name(data.get(6).copied().unwrap_or_default()),
                ),
            ],
        ),
        5 => (
            "devices",
            vec![
                BinaryNode::new(device_action(data.get(5).copied().unwrap_or_default()))
                    .with_attr("device_hash", fuzz_id("hash", data, 6))
                    .with_content(vec![
                        BinaryNode::new("device").with_attr(
                            "jid",
                            valid_device_jid(data.get(7).copied().unwrap_or_default()),
                        ),
                        BinaryNode::new("device").with_attr(
                            "jid",
                            fuzz_account_jid(data.get(8).copied().unwrap_or_default()),
                        ),
                        BinaryNode::new("device").with_attr("jid", fuzz_id("bad-device", data, 9)),
                    ]),
            ],
        ),
        6 => (
            "picture",
            vec![
                BinaryNode::new(
                    if data.get(5).copied().unwrap_or_default().is_multiple_of(2) {
                        "set"
                    } else {
                        "delete"
                    },
                )
                .with_attr(
                    "hash",
                    valid_account_jid(data.get(6).copied().unwrap_or_default()),
                ),
            ],
        ),
        _ => (
            "account_sync",
            vec![
                BinaryNode::new("blocklist").with_content(vec![
                    BinaryNode::new("item")
                        .with_attr("jid", fuzz_id("invalid", data, 5))
                        .with_attr(
                            "action",
                            blocklist_action(data.get(6).copied().unwrap_or_default()),
                        ),
                ]),
                BinaryNode::new("disappearing_mode")
                    .with_attr("duration", fuzz_text(data))
                    .with_attr("t", timestamp.as_str()),
            ],
        ),
    };

    BinaryNode::new("notification")
        .with_attr("id", id)
        .with_attr("from", from)
        .with_attr("participant", participant)
        .with_attr("type", notification_type)
        .with_attr("t", timestamp)
        .with_content(children)
}

fn structured_call_node(data: &[u8]) -> BinaryNode {
    let case = data.first().copied().unwrap_or_default() % 6;
    let caller = if data.get(1).copied().unwrap_or_default().is_multiple_of(3) {
        valid_group_jid(data.get(2).copied().unwrap_or_default())
    } else {
        valid_account_jid(data.get(2).copied().unwrap_or_default())
    };
    let participant = valid_account_jid(data.get(3).copied().unwrap_or_default());
    let group = valid_group_jid(data.get(4).copied().unwrap_or_default());
    let timestamp = fuzz_number(data.get(5).copied().unwrap_or_default());
    let call_id = fuzz_id("call", data, 6);

    let children = match case {
        0 => vec![
            BinaryNode::new("offer")
                .with_attr("call-id", call_id.as_str())
                .with_attr("from", participant.as_str())
                .with_attr("caller_pn", participant.as_str())
                .with_content(vec![media_child(data.get(7).copied().unwrap_or_default())]),
        ],
        1 => vec![
            BinaryNode::new("offer")
                .with_attr("call-id", call_id.as_str())
                .with_attr("from", participant.as_str())
                .with_attr("caller-pn", participant.as_str())
                .with_attr("type", "group")
                .with_attr("group-jid", group.as_str())
                .with_content(vec![BinaryNode::new("video")]),
        ],
        2 => vec![
            BinaryNode::new("timeout")
                .with_attr("call-id", call_id.as_str())
                .with_attr(
                    "is_group",
                    bool_text(data.get(7).copied().unwrap_or_default()),
                )
                .with_attr(
                    "is_video",
                    bool_text(data.get(8).copied().unwrap_or_default()),
                )
                .with_attr(
                    "offline",
                    bool_text(data.get(9).copied().unwrap_or_default()),
                )
                .with_attr("caller_pn", participant.as_str()),
        ],
        3 => vec![
            BinaryNode::new("relaylatency")
                .with_attr("call-id", call_id.as_str())
                .with_attr("call-creator", participant.as_str())
                .with_attr(
                    "latency-ms",
                    fuzz_number(data.get(7).copied().unwrap_or_default()),
                ),
        ],
        4 => vec![
            BinaryNode::new("accept")
                .with_attr("call-id", call_id.as_str())
                .with_attr("from", participant.as_str()),
            BinaryNode::new("terminate")
                .with_attr("call_id", call_id.as_str())
                .with_attr(
                    "reason",
                    termination_reason(data.get(7).copied().unwrap_or_default()),
                ),
        ],
        _ => vec![
            BinaryNode::new("offer")
                .with_attr("id", call_id.as_str())
                .with_attr("from", participant.as_str())
                .with_attr("group_jid", group.as_str())
                .with_content(vec![BinaryNode::new("audio"), BinaryNode::new("video")]),
            BinaryNode::new("timeout")
                .with_attr("call_id", call_id.as_str())
                .with_attr("is_group", "true")
                .with_attr("is_video", "true"),
        ],
    };

    BinaryNode::new("call")
        .with_attr("id", fuzz_id("call-stanza", data, 10))
        .with_attr("from", caller)
        .with_attr("participant", participant)
        .with_attr("t", timestamp)
        .with_attr(
            "offline",
            bool_text(data.get(11).copied().unwrap_or_default()),
        )
        .with_content(children)
}

fn structured_presence_node(data: &[u8]) -> BinaryNode {
    let case = data.first().copied().unwrap_or_default() % 6;
    let from = if data.get(1).copied().unwrap_or_default().is_multiple_of(2) {
        valid_group_jid(data.get(2).copied().unwrap_or_default())
    } else {
        valid_account_jid(data.get(2).copied().unwrap_or_default())
    };
    let participant = fuzz_account_jid(data.get(3).copied().unwrap_or_default());
    let mut node = BinaryNode::new("presence")
        .with_attr("from", from)
        .with_attr("participant", participant)
        .with_attr(
            "last",
            fuzz_number(data.get(4).copied().unwrap_or_default()),
        )
        .with_attr("t", fuzz_number(data.get(5).copied().unwrap_or_default()))
        .with_attr("name", fuzz_text(data));

    match case {
        0 => node = node.with_attr("type", "available"),
        1 => node = node.with_attr("type", "unavailable"),
        2 => node = node.with_attr("type", "subscribe"),
        3 => {
            node = node.with_content(vec![
                BinaryNode::new("composing").with_attr("media", "text"),
            ])
        }
        4 => {
            node = node.with_content(vec![
                BinaryNode::new("composing").with_attr("media", "audio"),
            ])
        }
        _ => node = node.with_content(vec![BinaryNode::new("paused")]),
    }
    node
}

fn structured_chatstate_node(data: &[u8]) -> BinaryNode {
    let case = data.first().copied().unwrap_or_default() % 4;
    let chat = if data.get(1).copied().unwrap_or_default().is_multiple_of(2) {
        valid_group_jid(data.get(2).copied().unwrap_or_default())
    } else {
        valid_account_jid(data.get(2).copied().unwrap_or_default())
    };
    let to = valid_account_jid(data.get(3).copied().unwrap_or_default());
    let participant = fuzz_account_jid(data.get(4).copied().unwrap_or_default());
    let child = match case {
        0 => BinaryNode::new("composing").with_attr("media", "text"),
        1 => BinaryNode::new("composing").with_attr("media", "audio"),
        2 => BinaryNode::new("paused"),
        _ => BinaryNode::new("unknown").with_attr("media", fuzz_text(data)),
    };
    BinaryNode::new("chatstate")
        .with_attr("from", chat)
        .with_attr("to", to)
        .with_attr("participant", participant)
        .with_attr("t", fuzz_number(data.get(5).copied().unwrap_or_default()))
        .with_content(vec![child])
}

fn reachout_json(data: &[u8]) -> String {
    format!(
        r#"{{"data":{{"xwa2_notify_account_reachout_timelock":{{"is_active":{},"time_enforcement_ends":"{}","enforcement_type":"{}"}}}}}}"#,
        json_bool(data.get(5).copied().unwrap_or_default()),
        fuzz_number(data.get(6).copied().unwrap_or_default()),
        enforcement_type(data.get(7).copied().unwrap_or_default())
    )
}

fn capping_json(data: &[u8]) -> String {
    format!(
        r#"{{"data":{{"xwa2_notify_new_chat_messages_capping_info_update":{{"total_quota":"{}","used_quota":{},"one_time_extension_status":"{}","multi_variation_status":"{}","capping_status":"{}"}}}}}}"#,
        fuzz_number(data.get(5).copied().unwrap_or_default()),
        fuzz_number(data.get(6).copied().unwrap_or_default()),
        extension_status(data.get(7).copied().unwrap_or_default()),
        variation_status(data.get(8).copied().unwrap_or_default()),
        capping_status(data.get(9).copied().unwrap_or_default())
    )
}

fn valid_account_jid(byte: u8) -> String {
    match byte % 4 {
        0 => format!("{}@s.whatsapp.net", 100 + u16::from(byte)),
        1 => format!("{}@c.us", 200 + u16::from(byte)),
        2 => format!("{}@lid", 300 + u16::from(byte)),
        _ => format!("{}:7@s.whatsapp.net", 400 + u16::from(byte)),
    }
}

fn fuzz_account_jid(byte: u8) -> String {
    match byte % 6 {
        0..=3 => valid_account_jid(byte),
        4 => String::new(),
        _ => format!("not-a-jid-{byte}"),
    }
}

fn valid_group_jid(byte: u8) -> String {
    format!("{}@g.us", 900 + u16::from(byte))
}

fn valid_device_jid(byte: u8) -> String {
    format!(
        "{}:{}@s.whatsapp.net",
        500 + u16::from(byte),
        1 + u16::from(byte % 15)
    )
}

fn fuzz_id(prefix: &str, data: &[u8], index: usize) -> String {
    let byte = data.get(index).copied().unwrap_or_default();
    if byte.is_multiple_of(17) {
        String::new()
    } else {
        format!("{prefix}-{byte}")
    }
}

fn fuzz_text(data: &[u8]) -> String {
    let text = data
        .iter()
        .skip(12)
        .take(40)
        .filter_map(|byte| {
            let ch = char::from(*byte);
            (ch.is_ascii_alphanumeric() || ch == ' ').then_some(ch)
        })
        .collect::<String>();
    if text.trim().is_empty() {
        "account update".to_owned()
    } else {
        text
    }
}

fn fuzz_number(byte: u8) -> String {
    if byte.is_multiple_of(13) {
        "not-a-number".to_owned()
    } else {
        (u64::from(byte) * 31).to_string()
    }
}

fn json_bool(byte: u8) -> &'static str {
    if byte.is_multiple_of(2) {
        "true"
    } else {
        "false"
    }
}

fn bool_text(byte: u8) -> &'static str {
    if byte.is_multiple_of(2) {
        "true"
    } else {
        "false"
    }
}

fn blocklist_action(byte: u8) -> &'static str {
    match byte % 4 {
        0 => "block",
        1 => "unblock",
        2 => "remove",
        _ => "",
    }
}

fn disappearing_duration(byte: u8) -> String {
    match byte % 5 {
        0 => "0".to_owned(),
        1 => "86400".to_owned(),
        2 => "604800".to_owned(),
        3 => "7776000".to_owned(),
        _ => "bad-duration".to_owned(),
    }
}

fn collection_name(byte: u8) -> &'static str {
    match byte % 8 {
        0 => "regular",
        1 => "regular_high",
        2 => "regular_low",
        3 => "critical_block",
        4 => "critical_unblock",
        5 => "critical_unblock_low",
        6 => "critical_identity",
        _ => "unknown_collection",
    }
}

fn device_action(byte: u8) -> &'static str {
    match byte % 4 {
        0 => "add",
        1 => "remove",
        2 => "update",
        _ => "replace",
    }
}

fn media_child(byte: u8) -> BinaryNode {
    match byte % 3 {
        0 => BinaryNode::new("audio"),
        1 => BinaryNode::new("video"),
        _ => BinaryNode::new("enc").with_attr("v", fuzz_number(byte)),
    }
}

fn termination_reason(byte: u8) -> &'static str {
    match byte % 4 {
        0 => "timeout",
        1 => "reject",
        2 => "busy",
        _ => "unknown",
    }
}

fn enforcement_type(byte: u8) -> &'static str {
    match byte % 3 {
        0 => "WEB_COMPANION_ONLY",
        1 => "ALL_DEVICES",
        _ => "unknown",
    }
}

fn extension_status(byte: u8) -> &'static str {
    match byte % 4 {
        0 => "AVAILABLE",
        1 => "USED",
        2 => "NOT_AVAILABLE",
        _ => "unknown",
    }
}

fn variation_status(byte: u8) -> &'static str {
    match byte % 4 {
        0 => "CONTROL",
        1 => "TREATMENT",
        2 => "HOLDOUT",
        _ => "unknown",
    }
}

fn capping_status(byte: u8) -> &'static str {
    match byte % 4 {
        0 => "FIRST_WARNING",
        1 => "SECOND_WARNING",
        2 => "CAPPED",
        _ => "UNCAPPED",
    }
}
