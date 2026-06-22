#![no_main]

use libfuzzer_sys::fuzz_target;
use wa_binary::{BinaryNode, decode_binary_node};
use wa_core::{
    lid_mapping_events_from_newsletter_notification_node,
    newsletter_mex_update_events_from_notification_node,
    newsletter_update_events_from_notification_node, parse_inbound_notification,
    parse_newsletter_linked_profile_notification, parse_newsletter_notification_updates,
};

const MAX_INPUT_LEN: usize = 64 * 1024;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_LEN {
        return;
    }

    if let Ok(node) = decode_binary_node(data) {
        drive_newsletter_parsers(&node);
    }

    let newsletter = structured_newsletter_notification(data);
    drive_newsletter_parsers(&newsletter);

    let mex = structured_newsletter_mex_notification(data);
    drive_newsletter_parsers(&mex);
});

fn drive_newsletter_parsers(node: &BinaryNode) {
    let _ = parse_newsletter_linked_profile_notification(node);
    let _ = parse_newsletter_notification_updates(node);
    let _ = lid_mapping_events_from_newsletter_notification_node(node);

    let Ok(notification) = parse_inbound_notification(node) else {
        return;
    };
    let _ = newsletter_update_events_from_notification_node(node, &notification);
    let _ = newsletter_mex_update_events_from_notification_node(node, &notification);
}

fn structured_newsletter_notification(data: &[u8]) -> BinaryNode {
    let case = data.first().copied().unwrap_or_default() % 7;
    let server_id = format!("server-{}", data.len());
    let count = fuzz_number(data.get(1).copied().unwrap_or_default());
    let actor = fuzz_account_jid(data.get(2).copied().unwrap_or_default());
    let user = fuzz_account_jid(data.get(3).copied().unwrap_or_default());
    let text = fuzz_text(data);

    let children = match case {
        0 => vec![
            BinaryNode::new("reaction")
                .with_attr("message_id", server_id.as_str())
                .with_content(vec![BinaryNode::new("reaction").with_content("+")]),
        ],
        1 => vec![
            BinaryNode::new("reaction")
                .with_attr("server_id", server_id.as_str())
                .with_content(vec![
                    BinaryNode::new("reaction").with_attr("code", code_text(data)),
                ]),
        ],
        2 => vec![
            BinaryNode::new("view")
                .with_attr("server_id", server_id.as_str())
                .with_attr("count", count.as_str()),
        ],
        3 => vec![
            BinaryNode::new("view")
                .with_attr("message_id", server_id.as_str())
                .with_content(text.clone()),
        ],
        4 => vec![
            BinaryNode::new("participant")
                .with_attr("jid", user.as_str())
                .with_attr("action", participant_action(data))
                .with_attr("role", participant_role(data)),
        ],
        5 => vec![BinaryNode::new("update").with_content(vec![
            BinaryNode::new("settings").with_content(vec![
                BinaryNode::new("name").with_content(text.clone()),
                BinaryNode::new("description").with_content(text.clone()),
            ]),
        ])],
        _ => vec![
            BinaryNode::new("message")
                .with_attr("server_id", server_id.as_str())
                .with_attr("t", count.as_str())
                .with_content(vec![
                    BinaryNode::new("plaintext").with_content(data.to_vec()),
                ]),
        ],
    };

    BinaryNode::new("notification")
        .with_attr("id", format!("newsletter-{}", data.len()))
        .with_attr("from", "abc@newsletter")
        .with_attr("type", "newsletter")
        .with_attr("participant", actor)
        .with_content(children)
}

fn structured_newsletter_mex_notification(data: &[u8]) -> BinaryNode {
    let case = data.get(4).copied().unwrap_or_default() % 6;
    let newsletter_jid = fuzz_newsletter_jid(data.get(5).copied().unwrap_or_default());
    let user_jid = fuzz_account_jid(data.get(6).copied().unwrap_or_default());
    let lid_jid = fuzz_lid_jid(data.get(7).copied().unwrap_or_default());
    let profile_jid = fuzz_account_jid(data.get(8).copied().unwrap_or_default());
    let text = fuzz_text(data);

    let (op_name, payload) = match case {
        0 => (
            Some("NotificationNewsletterUpdate"),
            format!(
                r#"{{"updates":[{{"jid":"{newsletter_jid}","settings":{{"name":{{"text":"{text}"}},"description":"{text}"}}}}]}}"#
            ),
        ),
        1 => (
            None,
            format!(
                r#"{{"data":{{"xwa2_newsletter_update":{{"updates":[{{"newsletter_id":"{newsletter_jid}","settings":{{"name":"{text}","muted":true}}}}]}}}}}}"#
            ),
        ),
        2 => (
            Some("NotificationNewsletterAdminPromote"),
            format!(r#"{{"updates":[{{"jid":"{newsletter_jid}","user":"{user_jid}"}}]}}"#),
        ),
        3 => (
            None,
            format!(
                r#"{{"data":{{"NotificationNewsletterAdminPromote":{{"updates":[{{"newsletterId":"{newsletter_jid}","participant_jid":"{user_jid}"}}]}}}}}}"#
            ),
        ),
        4 => (
            Some("NotificationLinkedProfilesUpdates"),
            format!(
                r#"{{"data":{{"xwa2_notify_linked_profiles":{{"jid":"{lid_jid}","added_profiles":[{{"pn":"{profile_jid}"}},"{profile_jid}"]}}}}}}"#
            ),
        ),
        _ => (
            Some("NotificationLinkedProfilesUpdates"),
            format!(
                r#"{{"data":{{"xwa2_notify_linked_profiles":{{"updates":[{{"lid":"{lid_jid}","addedProfiles":[{{"phone_number":"{profile_jid}"}}]}}]}}}}}}"#
            ),
        ),
    };

    let mut update = BinaryNode::new("update").with_content(payload.into_bytes());
    if let Some(op_name) = op_name {
        update = update.with_attr("op_name", op_name);
    }

    BinaryNode::new("notification")
        .with_attr("id", format!("newsletter-mex-{}", data.len()))
        .with_attr("from", "server@s.whatsapp.net")
        .with_attr("type", "mex")
        .with_content(vec![update])
}

fn fuzz_newsletter_jid(byte: u8) -> String {
    match byte % 4 {
        0 => "abc@newsletter".to_owned(),
        1 => format!("{}@newsletter", 1000 + u16::from(byte)),
        2 => fuzz_account_jid(byte),
        _ => format!("bad-newsletter-{byte}"),
    }
}

fn fuzz_account_jid(byte: u8) -> String {
    match byte % 5 {
        0 => format!("{}@s.whatsapp.net", 100 + u16::from(byte)),
        1 => format!("{}@c.us", 200 + u16::from(byte)),
        2 => format!("{}@lid", 300 + u16::from(byte)),
        3 => String::new(),
        _ => format!("not-a-jid-{byte}"),
    }
}

fn fuzz_lid_jid(byte: u8) -> String {
    match byte % 4 {
        0 => format!("{}@lid", 400 + u16::from(byte)),
        1 => format!("{}@hosted.lid", 500 + u16::from(byte)),
        2 => fuzz_account_jid(byte),
        _ => format!("bad-lid-{byte}"),
    }
}

fn fuzz_text(data: &[u8]) -> String {
    let text = data
        .iter()
        .skip(9)
        .take(32)
        .filter_map(|byte| {
            let ch = char::from(*byte);
            ch.is_ascii_alphanumeric().then_some(ch)
        })
        .collect::<String>();
    if text.is_empty() {
        "Updates".to_owned()
    } else {
        text
    }
}

fn fuzz_number(byte: u8) -> String {
    if byte.is_multiple_of(7) {
        "not-a-number".to_owned()
    } else {
        u32::from(byte).saturating_mul(100).to_string()
    }
}

fn code_text(data: &[u8]) -> &'static str {
    match data.get(9).copied().unwrap_or_default() % 4 {
        0 => "+",
        1 => "!",
        2 => "",
        _ => "*",
    }
}

fn participant_action(data: &[u8]) -> &'static str {
    match data.get(10).copied().unwrap_or_default() % 3 {
        0 => "promote",
        1 => "demote",
        _ => "",
    }
}

fn participant_role(data: &[u8]) -> &'static str {
    match data.get(11).copied().unwrap_or_default() % 3 {
        0 => "ADMIN",
        1 => "SUBSCRIBER",
        _ => "",
    }
}
