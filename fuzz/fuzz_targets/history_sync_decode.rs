#![no_main]

use libfuzzer_sys::fuzz_target;
use prost::Message as _;
use wa_core::{
    HistorySyncDecodeConfig, HistorySyncProcessConfig, decode_compressed_history_sync,
    decode_history_sync_bytes, process_history_sync,
};
use wa_proto::proto::{
    Account, AutoDownloadSettings, AvatarUserSettings, CallLogRecord, GlobalSettings, HistorySync,
    MediaVisibility, Message as ProtoMessage, MessageKey, NotificationSettings, PastParticipant,
    PastParticipants, PhoneNumberToLidMapping, Pushname, StickerMetadata, WallpaperSettings,
    WebMessageInfo, call_log_record,
    history_sync::{BotAiWaitListState, HistorySyncType},
    past_participant,
};

const MAX_INPUT_LEN: usize = 64 * 1024;
const MAX_INFLATED_LEN: usize = 512 * 1024;
const MAX_EVENTS: usize = 128;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_LEN {
        return;
    }

    if let Ok(history) = decode_history_sync_bytes(data) {
        let _ = process_history_sync(&history, process_config());
        let encoded = history.encode_to_vec();
        let _ = decode_history_sync_bytes(&encoded);
    }

    let decode_config = HistorySyncDecodeConfig {
        max_inflated_bytes: MAX_INFLATED_LEN,
    };
    if let Ok(history) = decode_compressed_history_sync(data, decode_config) {
        let _ = process_history_sync(&history, process_config());
        let encoded = history.encode_to_vec();
        let _ = decode_history_sync_bytes(&encoded);
    }

    exercise_structured_non_blocking_history(data);
});

fn process_config() -> HistorySyncProcessConfig {
    HistorySyncProcessConfig {
        max_chats: MAX_EVENTS,
        max_contacts: MAX_EVENTS,
        max_messages: MAX_EVENTS,
        is_latest: false,
    }
}

fn exercise_structured_non_blocking_history(data: &[u8]) {
    let history = HistorySync {
        sync_type: HistorySyncType::NonBlockingData as i32,
        status_v3_messages: vec![WebMessageInfo {
            key: Some(MessageKey {
                remote_jid: Some("status@broadcast".to_owned()),
                from_me: Some(false),
                id: Some(format!("status-{}", bounded_hex(data, 0, 8, "seed"))),
                participant: Some("123@s.whatsapp.net".to_owned()),
            }),
            message: Some(ProtoMessage {
                conversation: Some(format!("status {}", bounded_hex(data, 8, 12, "body"))),
                ..Default::default()
            }),
            message_timestamp: Some(1_700_000_000 + bounded_u32(data, 20) as u64),
            push_name: Some(format!("push {}", bounded_hex(data, 24, 8, "name"))),
            ..Default::default()
        }],
        pushnames: vec![Pushname {
            id: Some("123@s.whatsapp.net".to_owned()),
            pushname: Some(format!("notify {}", bounded_hex(data, 32, 8, "name"))),
        }],
        phone_number_to_lid_mappings: vec![PhoneNumberToLidMapping {
            pn_jid: Some("123@s.whatsapp.net".to_owned()),
            lid_jid: Some("123@lid".to_owned()),
        }],
        global_settings: Some(GlobalSettings {
            media_visibility: Some(MediaVisibility::On as i32),
            light_theme_wallpaper: Some(WallpaperSettings {
                filename: Some(format!("light{}", bounded_hex(data, 194, 4, "wall"))),
                opacity: Some(bounded_u32(data, 198) % 101),
            }),
            dark_theme_wallpaper: Some(WallpaperSettings {
                filename: Some(format!("dark{}", bounded_hex(data, 202, 4, "wall"))),
                opacity: Some(bounded_u32(data, 206) % 101),
            }),
            auto_download_wi_fi: Some(AutoDownloadSettings {
                download_images: Some(bit(data, 210, 0)),
                download_audio: Some(bit(data, 210, 1)),
                download_video: Some(bit(data, 210, 2)),
                download_documents: Some(bit(data, 210, 3)),
            }),
            auto_download_cellular: Some(AutoDownloadSettings {
                download_images: Some(bit(data, 211, 0)),
                download_audio: Some(bit(data, 211, 1)),
                download_video: Some(bit(data, 211, 2)),
                download_documents: Some(bit(data, 211, 3)),
            }),
            show_individual_notifications_preview: Some(bit(data, 212, 0)),
            show_group_notifications_preview: Some(bit(data, 212, 1)),
            disappearing_mode_duration: Some((bounded_u32(data, 80) % 604_801) as i32),
            disappearing_mode_timestamp: Some(1_700_000_000 + bounded_u32(data, 84) as i64),
            avatar_user_settings: Some(AvatarUserSettings {
                fbid: Some(format!("fbid{}", bounded_hex(data, 213, 4, "avatar"))),
                password: Some(format!("pw{}", bounded_hex(data, 217, 4, "secret"))),
            }),
            font_size: Some((bounded_u32(data, 221) % 4) as i32),
            security_notifications: Some(bit(data, 225, 0)),
            auto_unarchive_chats: Some(bit(data, 225, 1)),
            video_quality_mode: Some((bounded_u32(data, 226) % 3) as i32),
            photo_quality_mode: Some((bounded_u32(data, 230) % 3) as i32),
            individual_notification_settings: Some(NotificationSettings {
                message_vibrate: Some(format!("v{}", bounded_hex(data, 234, 2, "i"))),
                message_popup: Some(format!("p{}", bounded_hex(data, 236, 2, "i"))),
                message_light: Some(format!("l{}", bounded_hex(data, 238, 2, "i"))),
                low_priority_notifications: Some(bit(data, 240, 0)),
                reactions_muted: Some(bit(data, 240, 1)),
                call_vibrate: Some(format!("c{}", bounded_hex(data, 241, 2, "i"))),
            }),
            group_notification_settings: Some(NotificationSettings {
                message_vibrate: Some(format!("v{}", bounded_hex(data, 243, 2, "g"))),
                message_popup: Some(format!("p{}", bounded_hex(data, 245, 2, "g"))),
                message_light: Some(format!("l{}", bounded_hex(data, 247, 2, "g"))),
                low_priority_notifications: Some(bit(data, 249, 0)),
                reactions_muted: Some(bit(data, 249, 1)),
                call_vibrate: Some(format!("c{}", bounded_hex(data, 250, 2, "g"))),
            }),
            chat_db_lid_migration_timestamp: Some(1_700_000_000 + bounded_u32(data, 252) as i64),
            ..Default::default()
        }),
        accounts: vec![
            Account {
                lid: Some(format!("acct{}", bounded_hex(data, 88, 4, "lid"))),
                username: Some(format!("user{}", bounded_hex(data, 92, 4, "name"))),
                country_code: Some((bounded_u32(data, 96) % 999).to_string()),
                is_username_deleted: Some(false),
            },
            Account {
                lid: Some("789@lid".to_owned()),
                username: Some(format!("old{}", bounded_hex(data, 100, 4, "name"))),
                country_code: Some((bounded_u32(data, 104) % 999).to_string()),
                is_username_deleted: Some(true),
            },
        ],
        recent_stickers: vec![StickerMetadata {
            url: Some(format!(
                "https://mmg.whatsapp.net/{}",
                bounded_hex(data, 108, 6, "sticker")
            )),
            file_sha256: Some(prost::bytes::Bytes::from(bounded_bytes(data, 114, 8, 1))),
            file_enc_sha256: Some(prost::bytes::Bytes::from(bounded_bytes(data, 122, 8, 2))),
            media_key: Some(prost::bytes::Bytes::from(bounded_bytes(data, 130, 32, 7))),
            mimetype: Some("image/webp".to_owned()),
            height: Some((bounded_u32(data, 162) % 1024) + 1),
            width: Some((bounded_u32(data, 166) % 1024) + 1),
            direct_path: Some(format!("/sticker/{}", bounded_hex(data, 170, 6, "path"))),
            file_length: Some(u64::from(bounded_u32(data, 176))),
            weight: Some((bounded_u32(data, 180) % 10_000) as f32 / 100.0),
            last_sticker_sent_ts: Some(1_700_000_000 + bounded_u32(data, 184) as i64),
            is_lottie: Some(bit(data, 188, 0)),
            image_hash: Some(format!("hash{}", bounded_hex(data, 189, 4, "img"))),
            is_avatar_sticker: Some(bit(data, 193, 0)),
        }],
        call_log_records: vec![CallLogRecord {
            call_result: Some(call_result(data, 40) as i32),
            silence_reason: Some(silence_reason(data, 41) as i32),
            duration: Some((bounded_u32(data, 42) % 3_600) as i64),
            start_time: Some(1_700_000_000 + bounded_u32(data, 46) as i64),
            is_incoming: Some(bit(data, 50, 0)),
            is_video: Some(bit(data, 50, 1)),
            is_call_link: Some(bit(data, 50, 2)),
            call_id: Some(format!("call-{}", bounded_hex(data, 51, 8, "id"))),
            call_creator_jid: Some("123@s.whatsapp.net".to_owned()),
            group_jid: Some("456@g.us".to_owned()),
            participants: vec![
                call_log_record::ParticipantInfo {
                    user_jid: Some("123@s.whatsapp.net".to_owned()),
                    call_result: Some(call_result(data, 59) as i32),
                },
                call_log_record::ParticipantInfo {
                    user_jid: Some("789@s.whatsapp.net".to_owned()),
                    call_result: Some(call_result(data, 60) as i32),
                },
            ],
            call_type: Some(call_type(data, 61) as i32),
            ..Default::default()
        }],
        past_participants: vec![PastParticipants {
            group_jid: Some("456@g.us".to_owned()),
            past_participants: vec![
                PastParticipant {
                    user_jid: Some("123@s.whatsapp.net".to_owned()),
                    leave_reason: Some(leave_reason(data, 62) as i32),
                    leave_ts: Some(1_700_000_000 + bounded_u32(data, 63) as u64),
                },
                PastParticipant {
                    user_jid: Some("789@s.whatsapp.net".to_owned()),
                    leave_reason: Some(leave_reason(data, 67) as i32),
                    leave_ts: Some(1_700_000_000 + bounded_u32(data, 68) as u64),
                },
            ],
        }],
        progress: Some(bounded_u32(data, 72) % 101),
        chunk_order: Some(bounded_u32(data, 76)),
        thread_id_user_secret: Some(prost::bytes::Bytes::from(bounded_bytes(data, 256, 8, 3))),
        thread_ds_timeframe_offset: Some(bounded_u32(data, 264)),
        ai_wait_list_state: Some(BotAiWaitListState::AiAvailable as i32),
        companion_meta_nonce: Some(format!("nonce{}", bounded_hex(data, 268, 4, "meta"))),
        shareable_chat_identifier_encryption_key: Some(prost::bytes::Bytes::from(bounded_bytes(
            data, 272, 16, 4,
        ))),
        ..Default::default()
    };

    let _ = process_history_sync(&history, process_config());
    let encoded = history.encode_to_vec();
    if let Ok(decoded) = decode_history_sync_bytes(&encoded) {
        let _ = process_history_sync(&decoded, process_config());
    }
}

fn bounded_hex(data: &[u8], offset: usize, max_bytes: usize, fallback: &str) -> String {
    let Some(slice) = data.get(offset..) else {
        return fallback.to_owned();
    };
    if slice.is_empty() {
        return fallback.to_owned();
    }

    let mut out = String::new();
    for byte in slice.iter().take(max_bytes) {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{byte:02x}");
    }
    if out.is_empty() {
        fallback.to_owned()
    } else {
        out
    }
}

fn bounded_u32(data: &[u8], offset: usize) -> u32 {
    let mut bytes = [0_u8; 4];
    if let Some(slice) = data.get(offset..) {
        for (dst, src) in bytes.iter_mut().zip(slice.iter().copied()) {
            *dst = src;
        }
    }
    u32::from_le_bytes(bytes)
}

fn bounded_bytes(data: &[u8], offset: usize, len: usize, fill: u8) -> Vec<u8> {
    let mut bytes = vec![fill; len];
    if let Some(slice) = data.get(offset..) {
        for (dst, src) in bytes.iter_mut().zip(slice.iter().copied()) {
            *dst = src;
        }
    }
    bytes
}

fn bit(data: &[u8], offset: usize, bit: u8) -> bool {
    data.get(offset)
        .is_some_and(|byte| byte & (1_u8 << u32::from(bit)) != 0)
}

fn call_result(data: &[u8], offset: usize) -> call_log_record::CallResult {
    match data.get(offset).copied().unwrap_or_default() % 5 {
        0 => call_log_record::CallResult::Connected,
        1 => call_log_record::CallResult::Rejected,
        2 => call_log_record::CallResult::Cancelled,
        3 => call_log_record::CallResult::Missed,
        _ => call_log_record::CallResult::Failed,
    }
}

fn silence_reason(data: &[u8], offset: usize) -> call_log_record::SilenceReason {
    match data.get(offset).copied().unwrap_or_default() % 3 {
        0 => call_log_record::SilenceReason::None,
        1 => call_log_record::SilenceReason::Scheduled,
        _ => call_log_record::SilenceReason::Privacy,
    }
}

fn call_type(data: &[u8], offset: usize) -> call_log_record::CallType {
    if bit(data, offset, 0) {
        call_log_record::CallType::Regular
    } else {
        call_log_record::CallType::ScheduledCall
    }
}

fn leave_reason(data: &[u8], offset: usize) -> past_participant::LeaveReason {
    if bit(data, offset, 0) {
        past_participant::LeaveReason::Removed
    } else {
        past_participant::LeaveReason::Left
    }
}
