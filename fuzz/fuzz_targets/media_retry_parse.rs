#![no_main]

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use wa_binary::{BinaryNode, decode_binary_node};
use wa_core::receive::event_batch_from_media_retry_notification_node;
use wa_core::{
    MediaRetryCoordinator, MediaRetryPendingEntry, PendingMediaRetry, UploadedMedia,
    apply_media_retry_event, decode_stored_pending_media_retry, encode_stored_pending_media_retry,
    event_batch_from_inbound_receipt_node, event_batch_from_media_retry_update,
    media_retry_event_from_update, parse_inbound_notification, parse_inbound_receipt,
    parse_media_retry_update,
};
use wa_crypto::encrypt_media_retry_notification_with_iv;
use wa_proto::proto::{
    MediaRetryNotification, media_retry_notification::ResultType as MediaRetryResultType,
};

const MAX_INPUT_LEN: usize = 64 * 1024;
const MEDIA_KEY: [u8; 32] = [7u8; 32];
const FILE_SHA256: [u8; 32] = [11u8; 32];
const FILE_ENC_SHA256: [u8; 32] = [13u8; 32];

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_LEN {
        return;
    }

    if let Ok(node) = decode_binary_node(data) {
        drive_media_retry_node(&node);
    }

    drive_media_retry_node(&structured_media_retry_error(data));
    drive_media_retry_node(&structured_media_retry_payload(data));
    if let Some(node) = encrypted_media_retry_notification(data) {
        drive_media_retry_node(&node);
    }

    drive_stored_pending_media_retry(data);
});

fn drive_media_retry_node(node: &BinaryNode) {
    if let Ok(update) = parse_media_retry_update(node) {
        if let Ok(event) = media_retry_event_from_update(&update) {
            drive_media_retry_event(event);
        }
        if let Ok(batch) = event_batch_from_media_retry_update(&update) {
            for event in batch.media_retry {
                drive_media_retry_event(event);
            }
        }
    }

    if let Ok(receipt) = parse_inbound_receipt(node)
        && let Ok(batch) = event_batch_from_inbound_receipt_node(node, &receipt)
    {
        for event in batch.media_retry {
            drive_media_retry_event(event);
        }
    }

    if let Ok(notification) = parse_inbound_notification(node)
        && let Ok(Some(batch)) = event_batch_from_media_retry_notification_node(node, &notification)
    {
        for event in batch.media_retry {
            drive_media_retry_event(event);
        }
    }
}

fn drive_media_retry_event(event: wa_core::MediaRetryEvent) {
    let media = uploaded_media();
    let _ = apply_media_retry_event(&event, &media);

    let coordinator = MediaRetryCoordinator::with_capacity(4);
    if coordinator
        .register(
            event.key.clone(),
            PendingMediaRetry::new(media, wa_crypto::MediaKind::Image)
                .with_fallback_host("media.test"),
        )
        .is_ok()
    {
        let _ = coordinator.apply_retry_event(&event);
    }
}

fn drive_stored_pending_media_retry(data: &[u8]) {
    if let Ok(entry) = decode_stored_pending_media_retry(data)
        && let Ok(encoded) = encode_stored_pending_media_retry(&entry)
    {
        let _ = decode_stored_pending_media_retry(&encoded);
    }

    let entry = MediaRetryPendingEntry::new(
        message_event_key(data),
        PendingMediaRetry::new(
            uploaded_media(),
            media_kind(data.get(19).copied().unwrap_or(0)),
        )
        .with_fallback_host(fallback_host(data.get(20).copied().unwrap_or(0))),
    );
    if let Ok(encoded) = encode_stored_pending_media_retry(&entry) {
        let _ = decode_stored_pending_media_retry(&encoded);
    }
}

fn structured_media_retry_error(data: &[u8]) -> BinaryNode {
    media_retry_node_base(data, "receipt", "server-error").with_content(vec![
        rmr_node(data),
        BinaryNode::new("error")
            .with_attr("code", error_code(data.get(4).copied().unwrap_or_default()))
            .with_attr(
                "text",
                fuzz_id("retry-error", data.get(5).copied().unwrap_or_default()),
            ),
    ])
}

fn structured_media_retry_payload(data: &[u8]) -> BinaryNode {
    let payload = token_bytes(data, 6, 48);
    let iv = fixed_iv(data);
    media_retry_node_base(data, notification_tag(data), notification_type(data)).with_content(vec![
        rmr_node(data),
        BinaryNode::new("encrypt").with_content(vec![
            BinaryNode::new("enc_p").with_content(payload),
            BinaryNode::new("enc_iv").with_content(iv.to_vec()),
        ]),
    ])
}

fn encrypted_media_retry_notification(data: &[u8]) -> Option<BinaryNode> {
    let stanza_id = message_id(data);
    let notification = MediaRetryNotification {
        stanza_id: Some(stanza_id.clone()),
        direct_path: direct_path(data.get(21).copied().unwrap_or_default()),
        result: Some(media_retry_result(data.get(22).copied().unwrap_or_default()) as i32),
        message_secret: message_secret(data),
    };
    let payload = encrypt_media_retry_notification_with_iv(
        &notification,
        &MEDIA_KEY,
        &stanza_id,
        &fixed_iv(data),
    )
    .ok()?;

    Some(
        BinaryNode::new("notification")
            .with_attr("id", stanza_id)
            .with_attr(
                "from",
                account_jid(data.get(1).copied().unwrap_or_default()),
            )
            .with_attr("type", "mediaretry")
            .with_attr("t", timestamp(data.get(2).copied().unwrap_or_default()))
            .with_content(vec![
                rmr_node(data),
                BinaryNode::new("encrypt").with_content(vec![
                    BinaryNode::new("enc_p").with_content(payload.ciphertext),
                    BinaryNode::new("enc_iv").with_content(payload.iv),
                ]),
            ]),
    )
}

fn media_retry_node_base(data: &[u8], tag: &str, retry_type: &str) -> BinaryNode {
    BinaryNode::new(tag)
        .with_attr("id", message_id(data))
        .with_attr(
            "from",
            account_jid(data.get(1).copied().unwrap_or_default()),
        )
        .with_attr("type", retry_type)
        .with_attr("t", timestamp(data.get(2).copied().unwrap_or_default()))
}

fn rmr_node(data: &[u8]) -> BinaryNode {
    let mut node = BinaryNode::new("rmr")
        .with_attr("jid", account_jid(data.get(3).copied().unwrap_or_default()))
        .with_attr(
            "from_me",
            if data.get(4).copied().unwrap_or_default().is_multiple_of(2) {
                "false"
            } else {
                "true"
            },
        );
    if !data.get(5).copied().unwrap_or_default().is_multiple_of(5) {
        node = node.with_attr(
            "participant",
            device_jid(data.get(6).copied().unwrap_or_default()),
        );
    }
    node
}

fn uploaded_media() -> UploadedMedia {
    UploadedMedia::new(
        Bytes::copy_from_slice(&MEDIA_KEY),
        Bytes::copy_from_slice(&FILE_SHA256),
        Bytes::copy_from_slice(&FILE_ENC_SHA256),
        64,
    )
    .with_direct_path("/old/media")
}

fn message_event_key(data: &[u8]) -> wa_core::MessageEventKey {
    wa_core::MessageEventKey::new(
        account_jid(data.get(16).copied().unwrap_or_default()),
        fuzz_id("stored-msg", data.get(17).copied().unwrap_or_default()),
        (!data.get(18).copied().unwrap_or_default().is_multiple_of(3))
            .then(|| device_jid(data.get(18).copied().unwrap_or_default())),
    )
}

fn media_kind(byte: u8) -> wa_crypto::MediaKind {
    match byte % 8 {
        0 => wa_crypto::MediaKind::Image,
        1 => wa_crypto::MediaKind::Video,
        2 => wa_crypto::MediaKind::Gif,
        3 => wa_crypto::MediaKind::Document,
        4 => wa_crypto::MediaKind::Audio,
        5 => wa_crypto::MediaKind::PushToTalk,
        6 => wa_crypto::MediaKind::Sticker,
        _ => wa_crypto::MediaKind::VideoNote,
    }
}

fn media_retry_result(byte: u8) -> MediaRetryResultType {
    match byte % 4 {
        0 => MediaRetryResultType::Success,
        1 => MediaRetryResultType::NotFound,
        2 => MediaRetryResultType::DecryptionError,
        _ => MediaRetryResultType::GeneralError,
    }
}

fn notification_tag(data: &[u8]) -> &'static str {
    if data.first().copied().unwrap_or_default().is_multiple_of(2) {
        "receipt"
    } else {
        "notification"
    }
}

fn notification_type(data: &[u8]) -> &'static str {
    match data.get(1).copied().unwrap_or_default() % 4 {
        0 | 1 => "mediaretry",
        2 => "server-error",
        _ => "",
    }
}

fn account_jid(byte: u8) -> String {
    match byte % 5 {
        0 => format!("{}@s.whatsapp.net", 1000 + u16::from(byte)),
        1 => format!("{}@c.us", 2000 + u16::from(byte)),
        2 => format!("{}@lid", 3000 + u16::from(byte)),
        3 => String::new(),
        _ => format!("bad-jid-{byte}"),
    }
}

fn device_jid(byte: u8) -> String {
    match byte % 4 {
        0 => format!("{}:{}@s.whatsapp.net", 4000 + u16::from(byte), 1 + byte % 4),
        1 => format!("{}:{}@lid", 5000 + u16::from(byte), 1 + byte % 4),
        2 => account_jid(byte),
        _ => format!("bad-device-{byte}"),
    }
}

fn message_id(data: &[u8]) -> String {
    fuzz_id("media-retry", data.first().copied().unwrap_or_default())
}

fn fuzz_id(prefix: &str, byte: u8) -> String {
    if byte.is_multiple_of(17) {
        String::new()
    } else {
        format!("{prefix}-{byte}")
    }
}

fn timestamp(byte: u8) -> String {
    if byte.is_multiple_of(7) {
        String::new()
    } else {
        (1_700_000_000u64.saturating_sub(u64::from(byte))).to_string()
    }
}

fn error_code(byte: u8) -> String {
    match byte % 5 {
        0 => "0".to_owned(),
        1 => "1".to_owned(),
        2 => "2".to_owned(),
        3 => String::new(),
        _ => "not-a-code".to_owned(),
    }
}

fn fixed_iv(data: &[u8]) -> [u8; 12] {
    let mut iv = [0u8; 12];
    for (index, byte) in data.iter().take(12).enumerate() {
        iv[index] = *byte;
    }
    iv
}

fn token_bytes(data: &[u8], offset: usize, max_len: usize) -> Bytes {
    let mut bytes = data
        .iter()
        .skip(offset)
        .take(max_len)
        .copied()
        .collect::<Vec<_>>();
    if bytes.is_empty() {
        bytes.push(offset as u8);
    }
    Bytes::from(bytes)
}

fn direct_path(byte: u8) -> Option<String> {
    match byte % 4 {
        0 | 1 => Some(format!("/media/retry/{byte}")),
        2 => Some(String::new()),
        _ => None,
    }
}

fn message_secret(data: &[u8]) -> Option<Bytes> {
    (!data.get(23).copied().unwrap_or_default().is_multiple_of(4))
        .then(|| token_bytes(data, 24, 32))
}

fn fallback_host(byte: u8) -> String {
    if byte.is_multiple_of(3) {
        "media.test".to_owned()
    } else if byte.is_multiple_of(5) {
        String::new()
    } else {
        format!("media-{byte}.test")
    }
}
