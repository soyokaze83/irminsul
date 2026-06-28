#![no_main]

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use wa_binary::{BinaryNode, decode_binary_node};
use wa_core::{
    USyncQuery, USyncUser, bot_profiles_from_result, build_bot_profile_query, build_device_query,
    build_disappearing_mode_query, build_lid_mapping_query, build_on_whatsapp_query,
    build_status_query, disappearing_modes_from_result, extract_device_jids,
    lid_mappings_from_result, on_whatsapp_from_result, parse_usync_result,
    relay_recipients_from_device_jids, statuses_from_result,
};

const MAX_INPUT_LEN: usize = 64 * 1024;
const MY_JID: &str = "999:1@s.whatsapp.net";
const MY_LID: &str = "777@lid";

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_LEN {
        return;
    }

    if let Ok(node) = decode_binary_node(data) {
        drive_usync_parsers(&node);
    }

    drive_usync_parsers(&structured_usync_result(data));
    drive_usync_parsers(&structured_usync_error(data));
    drive_usync_queries(data);
});

fn drive_usync_parsers(node: &BinaryNode) {
    if let Ok(Some(result)) = parse_usync_result(node) {
        let _ = on_whatsapp_from_result(&result);
        let _ = lid_mappings_from_result(&result);
        let _ = statuses_from_result(&result);
        let _ = disappearing_modes_from_result(&result);
        let _ = bot_profiles_from_result(&result);
        if let Ok(devices) = extract_device_jids(&result, MY_JID, Some(MY_LID), true) {
            let _ = relay_recipients_from_device_jids(&devices, MY_JID, Some(MY_LID));
        }
        if let Ok(devices) = extract_device_jids(&result, MY_JID, None, false) {
            let _ = relay_recipients_from_device_jids(&devices, MY_JID, None);
        }
    }
}

fn drive_usync_queries(data: &[u8]) {
    let phone_a = phone_number(data.first().copied().unwrap_or_default());
    let phone_b = phone_number(data.get(1).copied().unwrap_or_default());
    if let Ok(Some(query)) = build_on_whatsapp_query([phone_a.as_str(), phone_b.as_str()]) {
        drive_query(query, data);
    }

    for query in [
        build_lid_mapping_query(jid_candidates(data)),
        build_device_query(jid_candidates(data)),
        build_status_query(jid_candidates(data)),
        build_disappearing_mode_query(jid_candidates(data)),
    ]
    .into_iter()
    .flatten()
    .flatten()
    {
        drive_query(query, data);
    }

    if let Ok(Some(query)) = build_bot_profile_query([(
        account_jid(data.get(2).copied().unwrap_or_default()),
        fuzz_id("persona", data.get(3).copied().unwrap_or_default()),
    )]) {
        drive_query(query, data);
    }

    let query = USyncQuery::new()
        .with_context(context(data.get(4).copied().unwrap_or_default()))
        .with_mode(mode(data.get(5).copied().unwrap_or_default()))
        .with_contact_protocol()
        .with_device_protocol()
        .with_status_protocol()
        .with_disappearing_mode_protocol()
        .with_bot_profile_protocol()
        .with_lid_protocol()
        .with_username_protocol()
        .with_user(
            USyncUser::new()
                .with_id(account_jid(data.get(6).copied().unwrap_or_default()))
                .with_phone(phone_number(data.get(7).copied().unwrap_or_default()))
                .with_lid(lid_jid(data.get(8).copied().unwrap_or_default()))
                .with_username(fuzz_id("user", data.get(9).copied().unwrap_or_default()))
                .with_username_key(fuzz_id("pin", data.get(10).copied().unwrap_or_default()))
                .with_contact_type(contact_type(data.get(11).copied().unwrap_or_default()))
                .with_persona_id(fuzz_id(
                    "persona",
                    data.get(12).copied().unwrap_or_default(),
                )),
        );
    drive_query(query, data);
}

fn drive_query(query: USyncQuery, data: &[u8]) {
    if let Ok(node) = query.to_node(fuzz_id("usync", data.get(13).copied().unwrap_or_default())) {
        let _ = query.parse_result(&structured_usync_result(data));
        drive_usync_parsers(&node);
    }
}

fn structured_usync_result(data: &[u8]) -> BinaryNode {
    BinaryNode::new("iq")
        .with_attr("type", "result")
        .with_attr(
            "id",
            fuzz_id("result", data.first().copied().unwrap_or_default()),
        )
        .with_content(vec![BinaryNode::new("usync").with_content(vec![
            BinaryNode::new("list").with_content(vec![
                user_result(data, 0),
                user_result(data, 16),
                user_result(data, 32),
            ]),
            BinaryNode::new("side_list").with_content(vec![user_result(data, 48)]),
        ])])
}

fn structured_usync_error(data: &[u8]) -> BinaryNode {
    match data.first().copied().unwrap_or_default() % 3 {
        0 => BinaryNode::new("iq")
            .with_attr("type", "error")
            .with_attr("code", number(data.get(1).copied().unwrap_or_default()))
            .with_attr("text", fuzz_text(data, 2)),
        1 => BinaryNode::new("iq")
            .with_attr("type", "result")
            .with_content(vec![
                BinaryNode::new("error")
                    .with_attr("code", number(data.get(1).copied().unwrap_or_default()))
                    .with_attr("text", fuzz_text(data, 2)),
            ]),
        _ => BinaryNode::new("iq").with_attr(
            "type",
            result_type(data.get(1).copied().unwrap_or_default()),
        ),
    }
}

fn user_result(data: &[u8], offset: usize) -> BinaryNode {
    BinaryNode::new("user")
        .with_attr(
            "jid",
            result_jid(data.get(offset).copied().unwrap_or_default()),
        )
        .with_content(vec![
            BinaryNode::new("contact").with_attr(
                "type",
                contact_type(data.get(offset + 1).copied().unwrap_or_default()),
            ),
            devices_node(data, offset + 2),
            status_node(data, offset + 5),
            disappearing_node(data, offset + 7),
            bot_node(data, offset + 9),
            BinaryNode::new("lid").with_attr(
                "val",
                lid_jid(data.get(offset + 13).copied().unwrap_or_default()),
            ),
            BinaryNode::new("username").with_content(fuzz_text(data, offset + 14)),
        ])
}

fn devices_node(data: &[u8], offset: usize) -> BinaryNode {
    BinaryNode::new("devices").with_content(vec![
        BinaryNode::new("device-list").with_content(vec![
            device_node(data.get(offset).copied().unwrap_or_default()),
            device_node(data.get(offset + 1).copied().unwrap_or_default()),
            device_node(data.get(offset + 2).copied().unwrap_or_default()),
        ]),
        BinaryNode::new("key-index-list")
            .with_attr(
                "ts",
                number(data.get(offset + 3).copied().unwrap_or_default()),
            )
            .with_attr(
                "expected_ts",
                optional_number(data.get(offset + 4).copied().unwrap_or_default()),
            )
            .with_content(token_bytes(data, offset + 5)),
    ])
}

fn device_node(byte: u8) -> BinaryNode {
    let mut node = BinaryNode::new("device")
        .with_attr("id", device_id(byte))
        .with_attr("key-index", optional_number(byte.wrapping_add(1)));
    if byte.is_multiple_of(3) {
        node = node.with_attr("is_hosted", "true");
    }
    node
}

fn status_node(data: &[u8], offset: usize) -> BinaryNode {
    let mut node = BinaryNode::new("status").with_attr(
        "t",
        optional_number(data.get(offset).copied().unwrap_or_default()),
    );
    match data.get(offset + 1).copied().unwrap_or_default() % 4 {
        0 => node = node.with_content(fuzz_text(data, offset + 2)),
        1 => node = node.with_content(Bytes::from(fuzz_text(data, offset + 2).into_bytes())),
        2 => node = node.with_attr("code", "401"),
        _ => {}
    }
    node
}

fn disappearing_node(data: &[u8], offset: usize) -> BinaryNode {
    BinaryNode::new("disappearing_mode")
        .with_attr(
            "duration",
            duration(data.get(offset).copied().unwrap_or_default()),
        )
        .with_attr(
            "t",
            optional_number(data.get(offset + 1).copied().unwrap_or_default()),
        )
}

fn bot_node(data: &[u8], offset: usize) -> BinaryNode {
    BinaryNode::new("bot").with_content(vec![
        BinaryNode::new("profile")
            .with_attr(
                "persona_id",
                fuzz_id("persona", data.get(offset).copied().unwrap_or_default()),
            )
            .with_content(vec![
                BinaryNode::new("default"),
                BinaryNode::new("name").with_content(fuzz_text(data, offset + 1)),
                BinaryNode::new("attributes").with_content(fuzz_text(data, offset + 2)),
                BinaryNode::new("description").with_content(fuzz_text(data, offset + 3)),
                BinaryNode::new("category").with_content(fuzz_text(data, offset + 4)),
                BinaryNode::new("commands").with_content(vec![
                    BinaryNode::new("description").with_content(fuzz_text(data, offset + 5)),
                    BinaryNode::new("command").with_content(vec![
                        BinaryNode::new("name").with_content(fuzz_id(
                            "cmd",
                            data.get(offset + 6).copied().unwrap_or_default(),
                        )),
                        BinaryNode::new("description").with_content(fuzz_text(data, offset + 7)),
                    ]),
                ]),
                BinaryNode::new("prompts").with_content(vec![
                    BinaryNode::new("prompt").with_content(vec![
                        BinaryNode::new("emoji").with_content("*"),
                        BinaryNode::new("text").with_content(fuzz_text(data, offset + 8)),
                    ]),
                ]),
            ]),
    ])
}

fn jid_candidates(data: &[u8]) -> Vec<String> {
    vec![
        account_jid(data.get(20).copied().unwrap_or_default()),
        lid_jid(data.get(21).copied().unwrap_or_default()),
        group_jid(data.get(22).copied().unwrap_or_default()),
        result_jid(data.get(23).copied().unwrap_or_default()),
    ]
}

fn result_jid(byte: u8) -> String {
    match byte % 6 {
        0 => account_jid(byte),
        1 => format!("{}:2@s.whatsapp.net", 6000 + u16::from(byte)),
        2 => lid_jid(byte),
        3 => format!("{}@hosted.lid", 7000 + u16::from(byte)),
        4 => String::new(),
        _ => format!("bad-usync-jid-{byte}"),
    }
}

fn account_jid(byte: u8) -> String {
    match byte % 4 {
        0 => format!("{}@s.whatsapp.net", 1000 + u16::from(byte)),
        1 => format!("{}@c.us", 2000 + u16::from(byte)),
        2 => format!("{}@lid", 3000 + u16::from(byte)),
        _ => format!("bad-account-{byte}"),
    }
}

fn lid_jid(byte: u8) -> String {
    if byte.is_multiple_of(3) {
        format!("{}@lid", 4000 + u16::from(byte))
    } else {
        format!("bad-lid-{byte}")
    }
}

fn group_jid(byte: u8) -> String {
    if byte.is_multiple_of(2) {
        format!("{}-{}@g.us", 5000 + u16::from(byte), 6000 + u16::from(byte))
    } else {
        format!("bad-group-{byte}")
    }
}

fn phone_number(byte: u8) -> String {
    match byte % 5 {
        0 => format!("+1555{}", 1000 + u16::from(byte)),
        1 => format!("1 555-{}", 2000 + u16::from(byte)),
        2 => String::new(),
        3 => format!("invalid-{byte}"),
        _ => format!("+{byte}"),
    }
}

fn context(byte: u8) -> &'static str {
    match byte % 3 {
        0 => "interactive",
        1 => "background",
        _ => "",
    }
}

fn mode(byte: u8) -> &'static str {
    match byte % 3 {
        0 => "query",
        1 => "delta",
        _ => "",
    }
}

fn contact_type(byte: u8) -> &'static str {
    match byte % 4 {
        0 => "in",
        1 => "out",
        2 => "",
        _ => "blocked",
    }
}

fn result_type(byte: u8) -> &'static str {
    match byte % 4 {
        0 => "result",
        1 => "error",
        2 => "set",
        _ => "",
    }
}

fn device_id(byte: u8) -> String {
    match byte % 5 {
        0 => "0".to_owned(),
        1 => (1 + u32::from(byte % 8)).to_string(),
        2 => (70_000 + u32::from(byte)).to_string(),
        3 => String::new(),
        _ => "not-a-device-id".to_owned(),
    }
}

fn duration(byte: u8) -> String {
    match byte % 5 {
        0 => "0".to_owned(),
        1 => "86400".to_owned(),
        2 => "604800".to_owned(),
        3 => String::new(),
        _ => "not-a-duration".to_owned(),
    }
}

fn number(byte: u8) -> String {
    if byte.is_multiple_of(5) {
        String::new()
    } else {
        (1_700_000_000u64.saturating_sub(u64::from(byte))).to_string()
    }
}

fn optional_number(byte: u8) -> String {
    if byte.is_multiple_of(4) {
        String::new()
    } else {
        number(byte)
    }
}

fn fuzz_id(prefix: &str, byte: u8) -> String {
    if byte.is_multiple_of(13) {
        String::new()
    } else {
        format!("{prefix}-{byte}")
    }
}

fn fuzz_text(data: &[u8], offset: usize) -> String {
    let text = data
        .iter()
        .skip(offset)
        .take(32)
        .filter_map(|byte| {
            let ch = char::from(*byte);
            (ch.is_ascii_alphanumeric() || ch == ' ' || ch == '_' || ch == '-').then_some(ch)
        })
        .collect::<String>();
    if text.is_empty() {
        fuzz_id("text", offset as u8)
    } else {
        text
    }
}

fn token_bytes(data: &[u8], offset: usize) -> Bytes {
    let mut bytes = data
        .iter()
        .skip(offset)
        .take(32)
        .copied()
        .collect::<Vec<_>>();
    if bytes.is_empty() {
        bytes.push(offset as u8);
    }
    Bytes::from(bytes)
}
