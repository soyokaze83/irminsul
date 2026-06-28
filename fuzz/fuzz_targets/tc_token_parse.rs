#![no_main]

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use wa_binary::{BinaryNode, decode_binary_node};
use wa_core::{
    TcTokenRecord, build_tc_token_issue_query, decode_stored_tc_token, encode_stored_tc_token,
    privacy_token_notification_sender_lid, tc_token_node, tc_token_records_from_issue_result,
    tc_token_records_from_privacy_token_notification,
};

const MAX_INPUT_LEN: usize = 64 * 1024;
const NOW_SECONDS: u64 = 1_700_000_000;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_LEN {
        return;
    }

    if let Ok(node) = decode_binary_node(data) {
        drive_tc_token_node_parsers(&node);
    }

    let issue_result = structured_issue_result(data);
    drive_tc_token_node_parsers(&issue_result);

    let privacy_notification = structured_privacy_notification(data);
    drive_tc_token_node_parsers(&privacy_notification);

    if let Ok(Some(issue_query)) = build_tc_token_issue_query(
        [
            fuzz_account_jid(data.get(12).copied().unwrap_or_default()),
            fuzz_lid_jid(data.get(13).copied().unwrap_or_default()),
            fuzz_group_jid(data.get(14).copied().unwrap_or_default()),
        ],
        timestamp_seconds(data.get(15).copied().unwrap_or(1)),
        fuzz_id("tc-issue", data.get(16).copied().unwrap_or_default()),
    ) {
        drive_tc_token_node_parsers(&issue_query);
    }

    drive_stored_record_parsers(data);
});

fn drive_tc_token_node_parsers(node: &BinaryNode) {
    let fallback = privacy_token_notification_sender_lid(node)
        .or_else(|| node.attrs.get("from").cloned())
        .unwrap_or_else(|| "123@s.whatsapp.net".to_owned());
    let _ = privacy_token_notification_sender_lid(node);
    if let Ok(records) = tc_token_records_from_issue_result(node, Some(&fallback)) {
        drive_records(records);
    }
    if let Ok(records) = tc_token_records_from_privacy_token_notification(node, Some(&fallback)) {
        drive_records(records);
    }
}

fn drive_stored_record_parsers(data: &[u8]) {
    if let Ok(record) = decode_stored_tc_token(data) {
        if let Ok(encoded) = encode_stored_tc_token(&record) {
            let _ = decode_stored_tc_token(&encoded);
        }
        let _ = tc_token_node(&record, NOW_SECONDS);
    }

    let jid = fuzz_account_jid(data.get(17).copied().unwrap_or_default());
    let token = token_bytes(data, 18);
    if let Ok(record) = TcTokenRecord::new(jid, token) {
        let record = record
            .with_timestamp_seconds(timestamp_seconds(data.get(19).copied().unwrap_or_default()));
        if let Ok(encoded) = encode_stored_tc_token(&record) {
            let _ = decode_stored_tc_token(&encoded);
        }
        let _ = tc_token_node(&record, NOW_SECONDS);
    }

    let marker_jid = fuzz_lid_jid(data.get(20).copied().unwrap_or_default());
    if let Ok(marker) = TcTokenRecord::sender_marker(
        marker_jid,
        timestamp_seconds(data.get(21).copied().unwrap_or(1)),
    ) {
        if let Ok(encoded) = encode_stored_tc_token(&marker) {
            let _ = decode_stored_tc_token(&encoded);
        }
        let _ = tc_token_node(&marker, NOW_SECONDS);
    }
}

fn drive_records(records: Vec<TcTokenRecord>) {
    for record in records {
        if let Ok(encoded) = encode_stored_tc_token(&record) {
            let _ = decode_stored_tc_token(&encoded);
        }
        let _ = tc_token_node(&record, NOW_SECONDS);
    }
}

fn structured_issue_result(data: &[u8]) -> BinaryNode {
    let token_a = BinaryNode::new("token")
        .with_attr(
            "jid",
            fuzz_account_jid(data.get(1).copied().unwrap_or_default()),
        )
        .with_attr(
            "t",
            fuzz_timestamp_attr(data.get(2).copied().unwrap_or_default()),
        )
        .with_attr("type", token_type(data.get(3).copied().unwrap_or_default()))
        .with_content(token_bytes(data, 4));
    let token_b = BinaryNode::new("token")
        .with_attr(
            "jid",
            fuzz_lid_jid(data.get(5).copied().unwrap_or_default()),
        )
        .with_attr(
            "t",
            fuzz_timestamp_attr(data.get(6).copied().unwrap_or_default()),
        )
        .with_attr("type", token_type(data.get(7).copied().unwrap_or_default()))
        .with_content(token_bytes(data, 8));

    BinaryNode::new("iq")
        .with_attr(
            "type",
            result_type(data.first().copied().unwrap_or_default()),
        )
        .with_attr("code", fuzz_code(data.get(9).copied().unwrap_or_default()))
        .with_attr(
            "text",
            fuzz_id("tc-error", data.get(10).copied().unwrap_or_default()),
        )
        .with_content(vec![
            BinaryNode::new("tokens").with_content(vec![token_a, token_b]),
            BinaryNode::new("error")
                .with_attr("code", fuzz_code(data.get(11).copied().unwrap_or_default()))
                .with_attr("text", "privacy token error"),
        ])
}

fn structured_privacy_notification(data: &[u8]) -> BinaryNode {
    let mut node = BinaryNode::new("notification")
        .with_attr(
            "id",
            fuzz_id("privacy", data.first().copied().unwrap_or_default()),
        )
        .with_attr(
            "from",
            fuzz_account_jid(data.get(1).copied().unwrap_or_default()),
        )
        .with_attr(
            "type",
            notification_type(data.get(2).copied().unwrap_or_default()),
        )
        .with_attr(
            "sender_lid",
            fuzz_lid_jid(data.get(3).copied().unwrap_or_default()),
        );
    if !data.get(4).copied().unwrap_or_default().is_multiple_of(5) {
        node = node.with_content(vec![BinaryNode::new("tokens").with_content(vec![
            BinaryNode::new("token")
                .with_attr("t", fuzz_timestamp_attr(data.get(5).copied().unwrap_or_default()))
                .with_attr("type", token_type(data.get(6).copied().unwrap_or_default()))
                .with_content(token_bytes(data, 7)),
            BinaryNode::new("token")
                .with_attr("jid", fuzz_account_jid(data.get(8).copied().unwrap_or_default()))
                .with_attr("t", fuzz_timestamp_attr(data.get(9).copied().unwrap_or_default()))
                .with_attr("type", token_type(data.get(10).copied().unwrap_or_default()))
                .with_content(token_bytes(data, 11)),
        ])]);
    }
    node
}

fn fuzz_account_jid(byte: u8) -> String {
    match byte % 6 {
        0 => format!("{}@s.whatsapp.net", 1000 + u16::from(byte)),
        1 => format!("{}@c.us", 2000 + u16::from(byte)),
        2 => fuzz_lid_jid(byte),
        3 => "0@s.whatsapp.net".to_owned(),
        4 => String::new(),
        _ => format!("not-a-jid-{byte}"),
    }
}

fn fuzz_lid_jid(byte: u8) -> String {
    match byte % 5 {
        0 => format!("{}@lid", 3000 + u16::from(byte)),
        1 => format!("{}:7@lid", 4000 + u16::from(byte)),
        2 => format!("{}@hosted.lid", 5000 + u16::from(byte)),
        3 => fuzz_group_jid(byte),
        _ => format!("bad-lid-{byte}"),
    }
}

fn fuzz_group_jid(byte: u8) -> String {
    if byte.is_multiple_of(2) {
        format!("{}-{}@g.us", 6000 + u16::from(byte), 7000 + u16::from(byte))
    } else {
        format!("bad-group-{byte}")
    }
}

fn token_bytes(data: &[u8], offset: usize) -> Bytes {
    let mut bytes = data
        .iter()
        .skip(offset)
        .take(48)
        .copied()
        .collect::<Vec<_>>();
    if bytes.is_empty() {
        bytes.push(offset as u8);
    }
    Bytes::from(bytes)
}

fn timestamp_seconds(byte: u8) -> u64 {
    if byte == 0 {
        1
    } else {
        NOW_SECONDS.saturating_sub(u64::from(byte).saturating_mul(60))
    }
}

fn fuzz_timestamp_attr(byte: u8) -> String {
    match byte % 5 {
        0 => String::new(),
        1 => "0".to_owned(),
        2 => "not-a-number".to_owned(),
        _ => timestamp_seconds(byte).to_string(),
    }
}

fn fuzz_id(prefix: &str, byte: u8) -> String {
    if byte.is_multiple_of(13) {
        String::new()
    } else {
        format!("{prefix}-{byte}")
    }
}

fn fuzz_code(byte: u8) -> String {
    if byte.is_multiple_of(7) {
        String::new()
    } else {
        (400 + u16::from(byte)).to_string()
    }
}

fn result_type(byte: u8) -> &'static str {
    match byte % 4 {
        0 => "result",
        1 => "error",
        2 => "",
        _ => "set",
    }
}

fn notification_type(byte: u8) -> &'static str {
    match byte % 4 {
        0 => "privacy_token",
        1 => "encrypt",
        2 => "",
        _ => "devices",
    }
}

fn token_type(byte: u8) -> &'static str {
    match byte % 4 {
        0 | 1 => "trusted_contact",
        2 => "other",
        _ => "",
    }
}
