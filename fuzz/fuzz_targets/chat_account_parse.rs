#![no_main]

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use wa_binary::{BinaryNode, decode_binary_node};
use wa_core::{
    AccountMutationKind, BlocklistAction, PresenceState, PrivacyCategory, PrivacyValue,
    ProfilePictureType, account_jid_kind, build_blocklist_query, build_blocklist_update_query,
    build_chat_state_node, build_default_disappearing_mode_query, build_presence_subscribe_node,
    build_presence_update_node, build_privacy_settings_query, build_privacy_update_query,
    build_profile_picture_remove_query, build_profile_picture_update_query,
    build_profile_picture_url_query, build_profile_status_update_query, lid_user_jid,
    normalize_account_jid, parse_account_mutation_result, parse_blocklist, parse_privacy_settings,
    parse_profile_picture_mutation_result, parse_profile_picture_url, pn_user_jid,
};

const MAX_INPUT_LEN: usize = 64 * 1024;
const OWN_JID: &str = "12345@s.whatsapp.net";
const OWN_LID: &str = "abc123@lid";

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_LEN {
        return;
    }

    if let Ok(node) = decode_binary_node(data) {
        drive_chat_account_parsers(&node);
    }

    for node in [
        structured_privacy_settings(data),
        structured_profile_picture(data),
        structured_blocklist(data),
        structured_mutation_result(data),
    ] {
        drive_chat_account_parsers(&node);
    }

    drive_chat_account_builders(data);
});

fn drive_chat_account_parsers(node: &BinaryNode) {
    let _ = parse_privacy_settings(node);
    let _ = parse_profile_picture_url(node);
    let _ = parse_profile_picture_mutation_result(node);
    let _ = parse_blocklist(node);

    for mutation in [
        AccountMutationKind::PrivacySetting,
        AccountMutationKind::DefaultDisappearingMode,
        AccountMutationKind::ProfileStatus,
        AccountMutationKind::ProfilePicture,
        AccountMutationKind::Blocklist,
    ] {
        let _ = parse_account_mutation_result(node, mutation);
    }
}

fn drive_chat_account_builders(data: &[u8]) {
    let tag = fuzz_id("chat", data, 0);
    let category = privacy_category(data.get(1).copied().unwrap_or_default());
    let value = privacy_value(data.get(2).copied().unwrap_or_default());

    drive_chat_account_parsers(&build_privacy_settings_query(tag.clone()));
    drive_chat_account_parsers(&build_privacy_update_query(category, value, tag.clone()));
    drive_chat_account_parsers(&build_default_disappearing_mode_query(
        duration(data.get(3).copied().unwrap_or_default()),
        tag.clone(),
    ));

    let status = fuzz_text(data, 4);
    if let Ok(node) = build_profile_status_update_query(&status, tag.clone()) {
        drive_chat_account_parsers(&node);
    }

    let target = target_jid(data.get(5).copied().unwrap_or_default());
    if let Ok(node) =
        build_profile_picture_url_query(&target, profile_picture_type(data), tag.clone())
    {
        drive_chat_account_parsers(&node);
    }

    let optional_target = optional_target_jid(data.get(6).copied().unwrap_or_default());
    if let Ok(node) = build_profile_picture_update_query(
        optional_target.as_deref(),
        token_bytes(data, 7),
        tag.clone(),
    ) {
        drive_chat_account_parsers(&node);
    }
    if let Ok(node) = build_profile_picture_remove_query(optional_target.as_deref(), tag.clone()) {
        drive_chat_account_parsers(&node);
    }

    drive_chat_account_parsers(&build_blocklist_query(tag.clone()));
    let lid = lid_jid(data.get(8).copied().unwrap_or_default());
    let pn = optional_pn_jid(data.get(9).copied().unwrap_or_default());
    if let Ok(node) = build_blocklist_update_query(
        &lid,
        blocklist_action(data.get(10).copied().unwrap_or_default()),
        pn.as_deref(),
        tag.clone(),
    ) {
        drive_chat_account_parsers(&node);
    }

    for state in [
        PresenceState::Available,
        PresenceState::Unavailable,
        PresenceState::Composing,
        PresenceState::Recording,
        PresenceState::Paused,
    ] {
        if let Ok(node) = build_presence_update_node(state, &status) {
            drive_chat_account_parsers(&node);
        }
        if let Ok(node) = build_chat_state_node(state, OWN_JID, Some(OWN_LID), &target) {
            drive_chat_account_parsers(&node);
        }
    }
    if let Ok(node) = build_presence_subscribe_node(&target, tag) {
        drive_chat_account_parsers(&node);
    }

    let _ = account_jid_kind(&target);
    let _ = normalize_account_jid(&target);
    let user = fuzz_user(data, 11);
    let _ = pn_user_jid(&user);
    let _ = lid_user_jid(&user);
}

fn structured_privacy_settings(data: &[u8]) -> BinaryNode {
    BinaryNode::new("iq")
        .with_attr(
            "type",
            response_type(data.get(1).copied().unwrap_or_default()),
        )
        .with_attr("xmlns", "privacy")
        .with_content(vec![BinaryNode::new("privacy").with_content(vec![
            BinaryNode::new("category")
                .with_attr(
                    "name",
                    privacy_category(data.get(2).copied().unwrap_or_default()).name(),
                )
                .with_attr(
                    "value",
                    privacy_value(data.get(3).copied().unwrap_or_default()).value(),
                ),
            BinaryNode::new("category")
                .with_attr("name", fuzz_id("unknown-category", data, 4))
                .with_attr("value", fuzz_text(data, 5)),
            BinaryNode::new("category").with_attr("name", fuzz_text(data, 6)),
        ])])
}

fn structured_profile_picture(data: &[u8]) -> BinaryNode {
    match data.first().copied().unwrap_or_default() % 4 {
        0 => BinaryNode::new("iq")
            .with_attr("type", "result")
            .with_content(vec![
                BinaryNode::new("picture")
                    .with_attr("url", profile_url(data))
                    .with_attr("id", fuzz_id("picture", data, 1)),
            ]),
        1 => BinaryNode::new("iq")
            .with_attr("type", "error")
            .with_attr(
                "code",
                fuzz_number(data.get(1).copied().unwrap_or_default()),
            )
            .with_attr("text", fuzz_text(data, 2)),
        2 => BinaryNode::new("iq")
            .with_attr("type", "result")
            .with_content(vec![
                BinaryNode::new("picture")
                    .with_attr("type", profile_picture_type(data).value())
                    .with_content(token_bytes(data, 3)),
            ]),
        _ => BinaryNode::new("message").with_attr("type", "result"),
    }
}

fn structured_blocklist(data: &[u8]) -> BinaryNode {
    BinaryNode::new("iq")
        .with_attr(
            "type",
            response_type(data.get(1).copied().unwrap_or_default()),
        )
        .with_attr("xmlns", "blocklist")
        .with_content(vec![BinaryNode::new("list").with_content(vec![
            BinaryNode::new("item")
                .with_attr("jid", lid_jid(data.get(2).copied().unwrap_or_default()))
                .with_attr(
                    "action",
                    blocklist_action(data.get(3).copied().unwrap_or_default()).value(),
                ),
            BinaryNode::new("item")
                .with_attr("jid", target_jid(data.get(4).copied().unwrap_or_default())),
            BinaryNode::new("item")
                .with_attr("pn_jid", pn_jid(data.get(5).copied().unwrap_or_default())),
        ])])
}

fn structured_mutation_result(data: &[u8]) -> BinaryNode {
    match data.first().copied().unwrap_or_default() % 5 {
        0 => BinaryNode::new("iq").with_attr("type", "result"),
        1 => BinaryNode::new("iq")
            .with_attr("type", "error")
            .with_attr(
                "code",
                fuzz_number(data.get(1).copied().unwrap_or_default()),
            )
            .with_attr("text", fuzz_text(data, 2)),
        2 => BinaryNode::new("iq")
            .with_attr("type", "error")
            .with_attr(
                "error",
                fuzz_number(data.get(1).copied().unwrap_or_default()),
            )
            .with_attr("reason", fuzz_text(data, 2)),
        3 => BinaryNode::new("iq").with_attr("type", fuzz_text(data, 3)),
        _ => BinaryNode::new("notification").with_attr("type", "result"),
    }
}

fn privacy_category(byte: u8) -> PrivacyCategory {
    match byte % 8 {
        0 => PrivacyCategory::Messages,
        1 => PrivacyCategory::CallAdd,
        2 => PrivacyCategory::LastSeen,
        3 => PrivacyCategory::Online,
        4 => PrivacyCategory::Profile,
        5 => PrivacyCategory::Status,
        6 => PrivacyCategory::ReadReceipts,
        _ => PrivacyCategory::GroupAdd,
    }
}

fn privacy_value(byte: u8) -> PrivacyValue {
    match byte % 6 {
        0 => PrivacyValue::All,
        1 => PrivacyValue::Contacts,
        2 => PrivacyValue::ContactBlacklist,
        3 => PrivacyValue::None,
        4 => PrivacyValue::MatchLastSeen,
        _ => PrivacyValue::Known,
    }
}

fn profile_picture_type(data: &[u8]) -> ProfilePictureType {
    match data.get(12).copied().unwrap_or_default() % 2 {
        0 => ProfilePictureType::Preview,
        _ => ProfilePictureType::Image,
    }
}

fn blocklist_action(byte: u8) -> BlocklistAction {
    match byte % 2 {
        0 => BlocklistAction::Block,
        _ => BlocklistAction::Unblock,
    }
}

fn response_type(byte: u8) -> &'static str {
    match byte % 5 {
        0 => "result",
        1 => "error",
        2 => "get",
        3 => "set",
        _ => "unexpected",
    }
}

fn duration(byte: u8) -> u32 {
    match byte % 5 {
        0 => 0,
        1 => 86_400,
        2 => 604_800,
        3 => 7_776_000,
        _ => u32::from(byte) * 60,
    }
}

fn optional_target_jid(byte: u8) -> Option<String> {
    match byte % 4 {
        0 => None,
        _ => Some(target_jid(byte)),
    }
}

fn optional_pn_jid(byte: u8) -> Option<String> {
    match byte % 3 {
        0 => None,
        _ => Some(pn_jid(byte)),
    }
}

fn target_jid(byte: u8) -> String {
    match byte % 5 {
        0 => pn_jid(byte),
        1 => format!("{}@c.us", 50_000 + u32::from(byte)),
        2 => lid_jid(byte),
        3 => format!("{}@g.us", 60_000 + u32::from(byte)),
        _ => fuzz_id("invalid-jid", &[byte], 0),
    }
}

fn pn_jid(byte: u8) -> String {
    format!("{}@s.whatsapp.net", 10_000 + u32::from(byte))
}

fn lid_jid(byte: u8) -> String {
    format!("lid-{byte}@lid")
}

fn profile_url(data: &[u8]) -> String {
    format!(
        "https://example.invalid/{}.jpg",
        fuzz_id("profile", data, 13)
    )
}

fn fuzz_user(data: &[u8], offset: usize) -> String {
    match data.get(offset).copied().unwrap_or_default() % 4 {
        0 => String::new(),
        1 => format!(
            "{}",
            70_000 + u32::from(data.get(offset + 1).copied().unwrap_or_default())
        ),
        2 => fuzz_id("user", data, offset + 1),
        _ => fuzz_text(data, offset + 1),
    }
}

fn fuzz_number(byte: u8) -> String {
    match byte % 4 {
        0 => String::new(),
        1 => "0".to_owned(),
        2 => u32::from(byte).to_string(),
        _ => format!("not-a-number-{byte}"),
    }
}

fn fuzz_id(prefix: &str, data: &[u8], offset: usize) -> String {
    let first = data.get(offset).copied().unwrap_or_default();
    let second = data.get(offset + 1).copied().unwrap_or_default();
    format!("{prefix}-{first:02x}{second:02x}")
}

fn fuzz_text(data: &[u8], offset: usize) -> String {
    let Some(remaining) = data.get(offset..) else {
        return String::new();
    };
    let len = remaining.len().min(24);
    String::from_utf8_lossy(&remaining[..len]).into_owned()
}

fn token_bytes(data: &[u8], offset: usize) -> Bytes {
    let start = (offset + 1).min(data.len());
    let len = usize::from(data.get(offset).copied().unwrap_or_default() % 32);
    let end = (start + len).min(data.len());
    let mut bytes = data[start..end].to_vec();
    if bytes.is_empty() {
        bytes.push(data.get(offset).copied().unwrap_or_default());
    }
    Bytes::from(bytes)
}
