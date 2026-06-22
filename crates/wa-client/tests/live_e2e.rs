use bytes::Bytes;
use std::{env, error::Error, path::PathBuf, time::Duration};
use tokio::time::timeout;
use wa_client::prelude::*;

fn live_enabled() -> bool {
    matches!(
        env::var("WA_LIVE_E2E").as_deref(),
        Ok("1" | "true" | "TRUE" | "yes" | "YES")
    )
}

fn optional_env(name: &str) -> Option<String> {
    env::var(name)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn csv_env(name: &str) -> Vec<String> {
    optional_env(name)
        .map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn bool_env(name: &str, default: bool) -> bool {
    optional_env(name)
        .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(default)
}

fn hex_env(name: &str) -> Result<Option<Vec<u8>>, Box<dyn Error>> {
    let Some(value) = optional_env(name) else {
        return Ok(None);
    };
    let value = value.replace([':', ' ', '-'], "");
    if value.len() % 2 != 0 {
        return Err(format!("{name} must contain an even number of hex characters").into());
    }
    let mut bytes = Vec::with_capacity(value.len() / 2);
    for chunk in value.as_bytes().chunks_exact(2) {
        let hex = std::str::from_utf8(chunk)?;
        bytes.push(u8::from_str_radix(hex, 16)?);
    }
    Ok(Some(bytes))
}

fn media_key_hex(name: &str) -> Result<Option<Vec<u8>>, Box<dyn Error>> {
    fixed_hex_env(name, 32)
}

fn fixed_hex_env(name: &str, expected_len: usize) -> Result<Option<Vec<u8>>, Box<dyn Error>> {
    let Some(bytes) = hex_env(name)? else {
        return Ok(None);
    };
    if bytes.len() != expected_len {
        return Err(format!("{name} must contain {} hex characters", expected_len * 2).into());
    }
    Ok(Some(bytes))
}

fn u64_env(name: &str) -> Result<Option<u64>, Box<dyn Error>> {
    optional_env(name)
        .map(|value| value.parse())
        .transpose()
        .map_err(Into::into)
}

fn u32_env(name: &str) -> Result<Option<u32>, Box<dyn Error>> {
    optional_env(name)
        .map(|value| value.parse())
        .transpose()
        .map_err(Into::into)
}

fn message_secret_env(name: &str, default_fill: u8) -> Result<Bytes, Box<dyn Error>> {
    let Some(bytes) = hex_env(name)? else {
        return Ok(Bytes::from(vec![default_fill; 32]));
    };
    if bytes.len() != 32 {
        return Err(format!("{name} must contain 64 hex characters").into());
    }
    Ok(Bytes::from(bytes))
}

fn message_key_from_env(
    prefix: &str,
    default_remote_jid: &str,
    default_from_me: bool,
) -> Result<Option<MessageKey>, Box<dyn Error>> {
    let id_env = format!("WA_{prefix}_MESSAGE_ID");
    let Some(message_id) = optional_env(&id_env) else {
        return Ok(None);
    };
    let remote_jid_env = format!("WA_{prefix}_REMOTE_JID");
    let remote_jid = optional_env(&remote_jid_env).unwrap_or_else(|| default_remote_jid.to_owned());
    let from_me_env = format!("WA_{prefix}_FROM_ME");
    let participant_env = format!("WA_{prefix}_PARTICIPANT");
    Ok(Some(build_message_key(
        remote_jid,
        bool_env(&from_me_env, default_from_me),
        message_id,
        optional_env(&participant_env),
    )?))
}

fn business_profile_update_from_env() -> BusinessProfileUpdate {
    let mut update = BusinessProfileUpdate::new();
    if let Some(address) = optional_env("WA_BUSINESS_PROFILE_ADDRESS") {
        update = update.with_address(address);
    }
    if let Some(email) = optional_env("WA_BUSINESS_PROFILE_EMAIL") {
        update = update.with_email(email);
    }
    if let Some(description) = optional_env("WA_BUSINESS_PROFILE_DESCRIPTION") {
        update = update.with_description(description);
    }
    let websites = csv_env("WA_BUSINESS_PROFILE_WEBSITES");
    if !websites.is_empty() {
        update = update.with_websites(websites);
    }
    update
}

fn newsletter_lookup_from_env() -> Option<(NewsletterMetadataLookup, Option<String>)> {
    if let Some(jid) = optional_env("WA_NEWSLETTER_JID") {
        return Some((NewsletterMetadataLookup::jid(jid.clone()), Some(jid)));
    }
    optional_env("WA_NEWSLETTER_INVITE")
        .map(|invite| (NewsletterMetadataLookup::invite(invite), None))
}

#[cfg(feature = "http-media")]
fn media_retry_kind_env() -> Result<MediaKind, Box<dyn Error>> {
    let Some(kind) = optional_env("WA_MEDIA_RETRY_KIND") else {
        return Ok(MediaKind::Image);
    };
    match kind.to_ascii_lowercase().as_str() {
        "image" => Ok(MediaKind::Image),
        "video" => Ok(MediaKind::Video),
        "gif" => Ok(MediaKind::Gif),
        "video_note" | "video-note" | "videonote" => Ok(MediaKind::VideoNote),
        "audio" => Ok(MediaKind::Audio),
        "ptt" | "push_to_talk" | "push-to-talk" => Ok(MediaKind::PushToTalk),
        "document" => Ok(MediaKind::Document),
        "sticker" => Ok(MediaKind::Sticker),
        other => Err(format!("unsupported WA_MEDIA_RETRY_KIND {other}").into()),
    }
}

#[cfg(feature = "http-media")]
fn live_media_retry_uploaded_media(media_key: Vec<u8>) -> Result<UploadedMedia, Box<dyn Error>> {
    let file_sha256 = fixed_hex_env("WA_MEDIA_RETRY_FILE_SHA256_HEX", 32)?
        .ok_or("WA_MEDIA_RETRY_FILE_SHA256_HEX is required for response roundtrip validation")?;
    let file_enc_sha256 = fixed_hex_env("WA_MEDIA_RETRY_FILE_ENC_SHA256_HEX", 32)?.ok_or(
        "WA_MEDIA_RETRY_FILE_ENC_SHA256_HEX is required for response roundtrip validation",
    )?;
    let file_length = u64_env("WA_MEDIA_RETRY_FILE_LENGTH")?
        .ok_or("WA_MEDIA_RETRY_FILE_LENGTH is required for response roundtrip validation")?;
    let mut media = UploadedMedia::new(
        Bytes::from(media_key),
        Bytes::from(file_sha256),
        Bytes::from(file_enc_sha256),
        file_length,
    );
    if let Some(url) = optional_env("WA_MEDIA_RETRY_URL") {
        media = media.with_url(url);
    }
    if let Some(direct_path) = optional_env("WA_MEDIA_RETRY_DIRECT_PATH") {
        media = media.with_direct_path(direct_path);
    }
    if let Some(timestamp_ms) = optional_env("WA_MEDIA_RETRY_MEDIA_KEY_TIMESTAMP_MS") {
        media = media.with_media_key_timestamp(timestamp_ms.parse()?);
    }
    Ok(media)
}

fn session_db_path() -> PathBuf {
    env::var_os("WA_SESSION_DB")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(".wa/session.sqlite"))
}

fn duration_env(name: &str, default_secs: u64) -> Result<Duration, Box<dyn Error>> {
    let secs = optional_env(name)
        .map(|value| value.parse())
        .transpose()?
        .unwrap_or(default_secs);
    Ok(Duration::from_secs(secs))
}

fn current_timestamp_ms() -> Result<u64, Box<dyn Error>> {
    let millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_millis()
        .try_into()?;
    Ok(millis)
}

fn timestamp_ms_env(name: &str) -> Result<i64, Box<dyn Error>> {
    optional_env(name)
        .map(|value| value.parse())
        .transpose()?
        .map_or_else(
            || current_timestamp_ms().map(|timestamp_ms| timestamp_ms as i64),
            Ok,
        )
}

fn action_timestamp_ms(name: &str) -> Result<u64, Box<dyn Error>> {
    optional_env(name)
        .map(|value| value.parse())
        .transpose()?
        .map_or_else(current_timestamp_ms, Ok)
}

fn matching_message_count(messages: &[MessageEvent], expected_remote_jid: Option<&str>) -> usize {
    messages
        .iter()
        .filter(|message| {
            expected_remote_jid.is_none_or(|remote_jid| message.key.remote_jid == remote_jid)
        })
        .count()
}

async fn wait_for_live_message_event(
    events: &mut tokio::sync::broadcast::Receiver<Event>,
    receive_timeout: Duration,
    expected_remote_jid: Option<&str>,
) -> Result<usize, Box<dyn Error>> {
    let wait = async {
        loop {
            match events.recv().await? {
                Event::MessagesUpsert(messages) => {
                    let count = matching_message_count(&messages, expected_remote_jid);
                    if count > 0 {
                        return Ok(count);
                    }
                }
                Event::Batch(batch) => {
                    let count = matching_message_count(&batch.messages_upsert, expected_remote_jid);
                    if count > 0 {
                        return Ok(count);
                    }
                }
                Event::ConnectionUpdate(ConnectionState::Closed) => {
                    return Err("connection closed before a live message event arrived".into());
                }
                _ => {}
            }
        }
    };

    timeout(receive_timeout, wait).await.map_err(|_| {
        format!(
            "timed out after {}s waiting for a live message event",
            receive_timeout.as_secs()
        )
    })?
}

#[cfg(feature = "http-media")]
async fn wait_for_live_history_sync_event(
    client: &Client<SqliteAuthStore>,
    transfer: &MediaTransfer<HttpMediaTransport>,
    events: &mut tokio::sync::broadcast::Receiver<Event>,
    history_timeout: Duration,
    fallback_host: Option<&str>,
    process_config: HistorySyncProcessConfig,
) -> Result<usize, Box<dyn Error>> {
    let wait = async {
        loop {
            let event = events.recv().await?;
            match &event {
                Event::MessagesUpsert(_) | Event::Batch(_) => {
                    let processed = client
                        .download_process_and_emit_history_sync_events(
                            transfer,
                            std::slice::from_ref(&event),
                            fallback_host,
                            HistorySyncDecodeConfig::default(),
                            process_config,
                        )
                        .await?;
                    if !processed.is_empty() {
                        return Ok(processed.len());
                    }
                }
                Event::ConnectionUpdate(ConnectionState::Closed) => {
                    return Err::<usize, Box<dyn Error>>(
                        "connection closed before a live history sync event arrived".into(),
                    );
                }
                _ => {}
            }
        }
    };

    timeout(history_timeout, wait).await.map_err(|_| {
        format!(
            "timed out after {}s waiting for a live history sync event",
            history_timeout.as_secs()
        )
    })?
}

#[cfg(feature = "http-media")]
async fn wait_for_live_media_retry_processed_event(
    events: &mut tokio::sync::broadcast::Receiver<Event>,
    receive_timeout: Duration,
) -> Result<MediaRetryBatchOutcome, Box<dyn Error>> {
    let wait = async {
        loop {
            match events.recv().await? {
                Event::MediaRetryProcessed(outcome) if !outcome.is_empty() => return Ok(outcome),
                Event::ConnectionUpdate(ConnectionState::Closed) => {
                    return Err::<MediaRetryBatchOutcome, Box<dyn Error>>(
                        "connection closed before a live media retry response was processed".into(),
                    );
                }
                _ => {}
            }
        }
    };

    timeout(receive_timeout, wait).await.map_err(|_| {
        format!(
            "timed out after {}s waiting for a live media retry response",
            receive_timeout.as_secs()
        )
    })?
}

#[cfg(all(feature = "http-media", feature = "image"))]
fn live_video_thumbnail_options() -> VideoThumbnailOptions {
    let mut options = VideoThumbnailOptions::default();
    if let Some(ffmpeg_path) = optional_env("WA_VIDEO_THUMBNAIL_FFMPEG") {
        options.ffmpeg_path = PathBuf::from(ffmpeg_path);
    }
    if let Some(seek_time) = optional_env("WA_VIDEO_THUMBNAIL_SEEK_TIME") {
        options.seek_time = seek_time;
    }
    options
}

#[cfg(all(feature = "http-media", feature = "image"))]
fn live_document_thumbnail_options() -> Result<PdfThumbnailOptions, Box<dyn Error>> {
    let mut options = PdfThumbnailOptions::default();
    if let Some(pdftoppm_path) = optional_env("WA_DOCUMENT_THUMBNAIL_PDFTOPPM") {
        options.pdftoppm_path = PathBuf::from(pdftoppm_path);
    }
    if let Some(page) = optional_env("WA_DOCUMENT_THUMBNAIL_PAGE") {
        options.page = page.parse()?;
    }
    if let Some(dpi) = optional_env("WA_DOCUMENT_THUMBNAIL_DPI") {
        options.dpi = dpi.parse()?;
    }
    Ok(options)
}

#[cfg(feature = "image")]
fn live_profile_picture_options() -> Result<ProfilePictureOptions, Box<dyn Error>> {
    let mut options = ProfilePictureOptions::default();
    if let Some(size) = optional_env("WA_PROFILE_PICTURE_SIZE") {
        options.image_size = size.parse()?;
    }
    if let Some(size) = optional_env("WA_PROFILE_PICTURE_PREVIEW_SIZE") {
        options.preview_size = size.parse()?;
    }
    if let Some(quality) = optional_env("WA_PROFILE_PICTURE_QUALITY") {
        options.quality = quality.parse()?;
    }
    Ok(options)
}

async fn live_client() -> Result<Client<SqliteAuthStore>, Box<dyn Error>> {
    let store = SqliteAuthStore::open(session_db_path()).await?;
    Ok(Client::builder(store).connect().await?)
}

async fn live_app_state_key_data(
    client: &Client<SqliteAuthStore>,
    key_id: &[u8],
) -> Result<Vec<u8>, Box<dyn Error>> {
    if key_id.is_empty() {
        return Err("WA_APP_STATE_KEY_ID_HEX must not be empty".into());
    }
    let key_data = match hex_env("WA_APP_STATE_KEY_DATA_HEX")? {
        Some(key_data) => key_data,
        None => client
            .load_app_state_sync_key_data(key_id)
            .await?
            .ok_or("WA_APP_STATE_KEY_DATA_HEX is not set and the key ID is not in WA_SESSION_DB")?,
    };
    if key_data.len() != 32 {
        return Err("app-state key data must be 32 bytes".into());
    }
    Ok(key_data)
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires WA_LIVE_E2E=1, WA_SESSION_DB, paired credentials, and WA_TARGET_JID"]
async fn live_text_send_smoke() -> Result<(), Box<dyn Error>> {
    if !live_enabled() {
        return Ok(());
    }
    let Some(target_jid) = optional_env("WA_TARGET_JID") else {
        return Ok(());
    };
    let text = optional_env("WA_TEXT").unwrap_or_else(|| "wa-client live e2e smoke".to_owned());

    let client = live_client().await?;
    let validated = client.connect_websocket().await?;
    let relay = client
        .send_text_with_signal_provider(
            validated.connection(),
            &target_jid,
            text,
            MessageRelayOptions::new(),
        )
        .await?;

    assert!(!relay.message_id.is_empty());
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires WA_LIVE_E2E=1, WA_SESSION_DB, paired credentials, WA_TARGET_JID, WA_CONTACT_DISPLAY_NAME, and WA_CONTACT_VCARD"]
async fn live_contact_send_smoke() -> Result<(), Box<dyn Error>> {
    if !live_enabled() {
        return Ok(());
    }
    let Some(target_jid) = optional_env("WA_TARGET_JID") else {
        return Ok(());
    };
    let Some(display_name) = optional_env("WA_CONTACT_DISPLAY_NAME") else {
        return Ok(());
    };
    let Some(vcard) = optional_env("WA_CONTACT_VCARD") else {
        return Ok(());
    };

    let client = live_client().await?;
    let validated = client.connect_websocket().await?;
    let relay = client
        .send_message_with_signal_provider(
            validated.connection(),
            &target_jid,
            MessageContent::contact(ContactContent::new(display_name, vcard)),
            MessageRelayOptions::new(),
        )
        .await?;

    assert!(!relay.message_id.is_empty());
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires WA_LIVE_E2E=1, WA_SESSION_DB, paired credentials, WA_TARGET_JID, WA_LOCATION_LATITUDE, and WA_LOCATION_LONGITUDE"]
async fn live_location_send_smoke() -> Result<(), Box<dyn Error>> {
    if !live_enabled() {
        return Ok(());
    }
    let Some(target_jid) = optional_env("WA_TARGET_JID") else {
        return Ok(());
    };
    let Some(latitude) = optional_env("WA_LOCATION_LATITUDE") else {
        return Ok(());
    };
    let Some(longitude) = optional_env("WA_LOCATION_LONGITUDE") else {
        return Ok(());
    };
    let mut location = LocationContent::new(latitude.parse()?, longitude.parse()?);
    if let Some(name) = optional_env("WA_LOCATION_NAME") {
        location = location.with_name(name);
    }
    if let Some(address) = optional_env("WA_LOCATION_ADDRESS") {
        location = location.with_address(address);
    }
    if let Some(url) = optional_env("WA_LOCATION_URL") {
        location = location.with_url(url);
    }

    let client = live_client().await?;
    let validated = client.connect_websocket().await?;
    let relay = client
        .send_message_with_signal_provider(
            validated.connection(),
            &target_jid,
            MessageContent::location(location),
            MessageRelayOptions::new(),
        )
        .await?;

    assert!(!relay.message_id.is_empty());
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires WA_LIVE_E2E=1, WA_SESSION_DB, paired credentials, and WA_TARGET_JID"]
async fn live_poll_send_smoke() -> Result<(), Box<dyn Error>> {
    if !live_enabled() {
        return Ok(());
    }
    let Some(target_jid) = optional_env("WA_TARGET_JID") else {
        return Ok(());
    };
    let name = optional_env("WA_POLL_NAME").unwrap_or_else(|| "wa-client poll".to_owned());
    let options = {
        let configured = csv_env("WA_POLL_OPTIONS");
        if configured.is_empty() {
            vec!["Yes".to_owned(), "No".to_owned()]
        } else {
            configured
        }
    };
    let selectable_options_count = optional_env("WA_POLL_SELECTABLE_COUNT")
        .map(|value| value.parse())
        .transpose()?
        .unwrap_or(1);
    let message_secret = message_secret_env("WA_POLL_SECRET_HEX", 0x61)?;

    let client = live_client().await?;
    let validated = client.connect_websocket().await?;
    let relay = client
        .send_poll_with_signal_provider(
            validated.connection(),
            &target_jid,
            PollContent::new(name, options, selectable_options_count, message_secret),
            MessageRelayOptions::new(),
        )
        .await?;

    assert!(!relay.message_id.is_empty());
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires WA_LIVE_E2E=1, WA_SESSION_DB, paired credentials, and WA_TARGET_JID"]
async fn live_event_send_smoke() -> Result<(), Box<dyn Error>> {
    if !live_enabled() {
        return Ok(());
    }
    let Some(target_jid) = optional_env("WA_TARGET_JID") else {
        return Ok(());
    };
    let name = optional_env("WA_EVENT_NAME").unwrap_or_else(|| "wa-client event".to_owned());
    let start_time = optional_env("WA_EVENT_START_UNIX")
        .map(|value| value.parse())
        .transpose()?
        .map_or_else(
            || current_timestamp_ms().map(|timestamp_ms| (timestamp_ms / 1000 + 3600) as i64),
            Ok,
        )?;
    let message_secret = message_secret_env("WA_EVENT_SECRET_HEX", 0x62)?;
    let mut event = EventContent::new(name, start_time, message_secret);
    event.description = optional_env("WA_EVENT_DESCRIPTION");
    event.end_time = optional_env("WA_EVENT_END_UNIX")
        .map(|value| value.parse())
        .transpose()?;
    if let Some(join_link) = optional_env("WA_EVENT_JOIN_LINK") {
        event = event.with_join_link(join_link);
    }

    let client = live_client().await?;
    let validated = client.connect_websocket().await?;
    let relay = client
        .send_event_with_signal_provider(
            validated.connection(),
            &target_jid,
            event,
            MessageRelayOptions::new(),
        )
        .await?;

    assert!(!relay.message_id.is_empty());
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires WA_LIVE_E2E=1, WA_SESSION_DB, paired credentials, WA_TARGET_JID, and WA_REACTION_MESSAGE_ID"]
async fn live_reaction_send_smoke() -> Result<(), Box<dyn Error>> {
    if !live_enabled() {
        return Ok(());
    }
    let Some(target_jid) = optional_env("WA_TARGET_JID") else {
        return Ok(());
    };
    let Some(message_id) = optional_env("WA_REACTION_MESSAGE_ID") else {
        return Ok(());
    };
    let remote_jid =
        optional_env("WA_REACTION_REMOTE_JID").unwrap_or_else(|| target_jid.to_owned());
    let key = build_message_key(
        remote_jid,
        bool_env("WA_REACTION_FROM_ME", false),
        message_id,
        optional_env("WA_REACTION_PARTICIPANT"),
    )?;
    let text = optional_env("WA_REACTION_TEXT").unwrap_or_else(|| "+".to_owned());

    let client = live_client().await?;
    let validated = client.connect_websocket().await?;
    let relay = client
        .send_reaction_with_signal_provider(
            validated.connection(),
            &target_jid,
            ReactionContent::new(key, text),
            MessageRelayOptions::new(),
        )
        .await?;

    assert!(!relay.message_id.is_empty());
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires WA_LIVE_E2E=1, WA_SESSION_DB, paired credentials, WA_TARGET_JID, and WA_EDIT_MESSAGE_ID"]
async fn live_edit_send_smoke() -> Result<(), Box<dyn Error>> {
    if !live_enabled() {
        return Ok(());
    }
    let Some(target_jid) = optional_env("WA_TARGET_JID") else {
        return Ok(());
    };
    let Some(key) = message_key_from_env("EDIT", &target_jid, true)? else {
        return Ok(());
    };
    let text = optional_env("WA_EDIT_TEXT").unwrap_or_else(|| "edited from wa-client".to_owned());
    let edit = EditContent {
        key,
        message: build_text_message(text)?,
        timestamp_ms: Some(timestamp_ms_env("WA_EDIT_TIMESTAMP_MS")?),
    };

    let client = live_client().await?;
    let validated = client.connect_websocket().await?;
    let relay = client
        .send_edit_with_signal_provider(
            validated.connection(),
            &target_jid,
            edit,
            MessageRelayOptions::new(),
        )
        .await?;

    assert!(!relay.message_id.is_empty());
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires WA_LIVE_E2E=1, WA_SESSION_DB, paired credentials, WA_TARGET_JID, and WA_DELETE_MESSAGE_ID"]
async fn live_delete_send_smoke() -> Result<(), Box<dyn Error>> {
    if !live_enabled() {
        return Ok(());
    }
    let Some(target_jid) = optional_env("WA_TARGET_JID") else {
        return Ok(());
    };
    let Some(key) = message_key_from_env("DELETE", &target_jid, true)? else {
        return Ok(());
    };

    let client = live_client().await?;
    let validated = client.connect_websocket().await?;
    let relay = client
        .send_delete_with_signal_provider(
            validated.connection(),
            &target_jid,
            DeleteContent { key },
            MessageRelayOptions::new(),
        )
        .await?;

    assert!(!relay.message_id.is_empty());
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires WA_LIVE_E2E=1, WA_SESSION_DB, paired credentials, WA_TARGET_JID, and WA_PIN_MESSAGE_ID"]
async fn live_pin_message_send_smoke() -> Result<(), Box<dyn Error>> {
    if !live_enabled() {
        return Ok(());
    }
    let Some(target_jid) = optional_env("WA_TARGET_JID") else {
        return Ok(());
    };
    let Some(key) = message_key_from_env("PIN", &target_jid, true)? else {
        return Ok(());
    };
    let action = match optional_env("WA_PIN_ACTION")
        .unwrap_or_else(|| "pin".to_owned())
        .as_str()
    {
        "pin" | "PIN" | "Pin" => PinAction::Pin,
        "unpin" | "UNPIN" | "Unpin" => PinAction::Unpin,
        other => return Err(format!("unsupported WA_PIN_ACTION={other}; use pin or unpin").into()),
    };
    let pin = PinContent {
        key,
        action,
        sender_timestamp_ms: Some(timestamp_ms_env("WA_PIN_TIMESTAMP_MS")?),
    };

    let client = live_client().await?;
    let validated = client.connect_websocket().await?;
    let relay = client
        .send_pin_with_signal_provider(
            validated.connection(),
            &target_jid,
            pin,
            MessageRelayOptions::new(),
        )
        .await?;

    assert!(!relay.message_id.is_empty());
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires WA_LIVE_E2E=1, WA_SESSION_DB, paired credentials, and an inbound message before WA_RECEIVE_TIMEOUT_SECS"]
async fn live_signal_receive_smoke() -> Result<(), Box<dyn Error>> {
    if !live_enabled() {
        return Ok(());
    }
    let receive_timeout = duration_env("WA_RECEIVE_TIMEOUT_SECS", 60)?;
    let expected_remote_jid = optional_env("WA_RECEIVE_REMOTE_JID");

    let client = live_client().await?;
    let mut events = client.subscribe();
    let validated = client.connect_websocket().await?;
    let mut processor = client.spawn_incoming_processor_with_signal_provider(
        validated.into_connection(),
        EventBufferConfig::default(),
    )?;

    let received =
        wait_for_live_message_event(&mut events, receive_timeout, expected_remote_jid.as_deref())
            .await;
    processor.abort();

    assert!(received? > 0);
    Ok(())
}

#[cfg(feature = "http-media")]
#[tokio::test(flavor = "current_thread")]
#[ignore = "requires WA_LIVE_E2E=1, WA_SESSION_DB, paired credentials, http-media, and a history sync notification before WA_HISTORY_SYNC_TIMEOUT_SECS"]
async fn live_history_sync_smoke() -> Result<(), Box<dyn Error>> {
    if !live_enabled() {
        return Ok(());
    }
    let history_timeout = duration_env("WA_HISTORY_SYNC_TIMEOUT_SECS", 180)?;
    let fallback_host = optional_env("WA_HISTORY_SYNC_FALLBACK_HOST");
    let process_config =
        HistorySyncProcessConfig::default().latest(bool_env("WA_HISTORY_SYNC_LATEST", true));

    let client = live_client().await?;
    let mut events = client.subscribe();
    let validated = client.connect_websocket().await?;
    let connection = validated.into_connection();
    let media_connection = client.fetch_media_connection_info(&connection).await?;
    let transfer = MediaTransfer::new(HttpMediaTransport::new(media_connection));
    let mut processor = client
        .spawn_incoming_processor_with_signal_provider(connection, EventBufferConfig::default())?;

    let processed = wait_for_live_history_sync_event(
        &client,
        &transfer,
        &mut events,
        history_timeout,
        fallback_host.as_deref(),
        process_config,
    )
    .await;
    processor.abort();

    assert!(processed? > 0);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires WA_LIVE_E2E=1, WA_SESSION_DB, paired credentials, WA_CHAT_PIN_JID, WA_APP_STATE_KEY_ID_HEX, and stored or explicit app-state key data; mutates chat pin state"]
async fn live_chat_pin_smoke() -> Result<(), Box<dyn Error>> {
    if !live_enabled() {
        return Ok(());
    }
    let Some(chat_jid) = optional_env("WA_CHAT_PIN_JID") else {
        return Ok(());
    };
    let Some(key_id) = hex_env("WA_APP_STATE_KEY_ID_HEX")? else {
        return Ok(());
    };
    let pinned = bool_env("WA_CHAT_PINNED", true);
    let timestamp_ms = action_timestamp_ms("WA_CHAT_PIN_TIMESTAMP_MS")?;

    let client = live_client().await?;
    let key_data = live_app_state_key_data(&client, &key_id).await?;
    let previous = client
        .load_app_state_patch_state(AppStateCollection::RegularLow)
        .await?;
    let upload = AppStateMutationUpload::new(&previous, &key_id, &key_data);
    let validated = client.connect_websocket().await?;

    let outcome = client
        .set_chat_pinned_and_apply(
            validated.connection(),
            &chat_jid,
            pinned,
            timestamp_ms,
            upload,
        )
        .await?;

    assert_eq!(outcome.bundle.collection, AppStateCollection::RegularLow);
    assert_eq!(outcome.batch.chats_update.len(), 1);
    assert_eq!(outcome.batch.chats_update[0].jid, chat_jid);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires WA_LIVE_E2E=1, WA_SESSION_DB, paired credentials, and WA_STATUS_JIDS"]
async fn live_status_text_send_smoke() -> Result<(), Box<dyn Error>> {
    if !live_enabled() {
        return Ok(());
    }
    let status_jids = csv_env("WA_STATUS_JIDS");
    if status_jids.is_empty() {
        return Ok(());
    }
    let text =
        optional_env("WA_STATUS_TEXT").unwrap_or_else(|| "wa-client live status smoke".to_owned());

    let client = live_client().await?;
    let validated = client.connect_websocket().await?;
    let relay = client
        .send_status_text_with_signal_provider(
            validated.connection(),
            status_jids.iter().map(String::as_str),
            text,
            MessageRelayOptions::new(),
        )
        .await?;

    assert!(!relay.message_id.is_empty());
    assert!(relay.recipient_count > 0);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires WA_LIVE_E2E=1, WA_SESSION_DB, paired credentials, and WA_STATUS_JIDS"]
async fn live_status_poll_send_smoke() -> Result<(), Box<dyn Error>> {
    if !live_enabled() {
        return Ok(());
    }
    let status_jids = csv_env("WA_STATUS_JIDS");
    if status_jids.is_empty() {
        return Ok(());
    }
    let name =
        optional_env("WA_STATUS_POLL_NAME").unwrap_or_else(|| "wa-client status poll".to_owned());
    let options = {
        let configured = csv_env("WA_STATUS_POLL_OPTIONS");
        if configured.is_empty() {
            vec!["Yes".to_owned(), "No".to_owned()]
        } else {
            configured
        }
    };
    let selectable_options_count = optional_env("WA_STATUS_POLL_SELECTABLE_COUNT")
        .map(|value| value.parse())
        .transpose()?
        .unwrap_or(1);
    let message_secret = message_secret_env("WA_STATUS_POLL_SECRET_HEX", 0x51)?;

    let client = live_client().await?;
    let validated = client.connect_websocket().await?;
    let relay = client
        .send_status_poll_with_signal_provider(
            validated.connection(),
            status_jids.iter().map(String::as_str),
            PollContent::new(name, options, selectable_options_count, message_secret),
            MessageRelayOptions::new(),
        )
        .await?;

    assert!(!relay.message_id.is_empty());
    assert!(relay.recipient_count > 0);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires WA_LIVE_E2E=1, WA_SESSION_DB, paired credentials, and WA_STATUS_JIDS"]
async fn live_status_event_send_smoke() -> Result<(), Box<dyn Error>> {
    if !live_enabled() {
        return Ok(());
    }
    let status_jids = csv_env("WA_STATUS_JIDS");
    if status_jids.is_empty() {
        return Ok(());
    }
    let name =
        optional_env("WA_STATUS_EVENT_NAME").unwrap_or_else(|| "wa-client status event".to_owned());
    let start_time = optional_env("WA_STATUS_EVENT_START_UNIX")
        .map(|value| value.parse())
        .transpose()?
        .map_or_else(
            || current_timestamp_ms().map(|timestamp_ms| (timestamp_ms / 1000 + 3600) as i64),
            Ok,
        )?;
    let message_secret = message_secret_env("WA_STATUS_EVENT_SECRET_HEX", 0x52)?;
    let mut event = EventContent::new(name, start_time, message_secret);
    event.description = optional_env("WA_STATUS_EVENT_DESCRIPTION");
    event.end_time = optional_env("WA_STATUS_EVENT_END_UNIX")
        .map(|value| value.parse())
        .transpose()?;
    if let Some(join_link) = optional_env("WA_STATUS_EVENT_JOIN_LINK") {
        event = event.with_join_link(join_link);
    }

    let client = live_client().await?;
    let validated = client.connect_websocket().await?;
    let relay = client
        .send_status_event_with_signal_provider(
            validated.connection(),
            status_jids.iter().map(String::as_str),
            event,
            MessageRelayOptions::new(),
        )
        .await?;

    assert!(!relay.message_id.is_empty());
    assert!(relay.recipient_count > 0);
    Ok(())
}

#[cfg(feature = "http-media")]
#[tokio::test(flavor = "current_thread")]
#[ignore = "requires WA_LIVE_E2E=1, WA_SESSION_DB, paired credentials, WA_STATUS_JIDS, and WA_STATUS_MEDIA_PATH"]
async fn live_status_image_media_send_smoke() -> Result<(), Box<dyn Error>> {
    if !live_enabled() {
        return Ok(());
    }
    let status_jids = csv_env("WA_STATUS_JIDS");
    if status_jids.is_empty() {
        return Ok(());
    }
    let Some(media_path) = optional_env("WA_STATUS_MEDIA_PATH") else {
        return Ok(());
    };

    let plaintext = std::fs::read(media_path)?;
    let mimetype =
        optional_env("WA_STATUS_MEDIA_MIMETYPE").unwrap_or_else(|| "image/jpeg".to_owned());

    let client = live_client().await?;
    let validated = client.connect_websocket().await?;
    let media_connection = client
        .fetch_media_connection_info(validated.connection())
        .await?;
    let transfer = MediaTransfer::new(HttpMediaTransport::new(media_connection));
    let uploaded = client
        .upload_media_bytes(&transfer, &plaintext, MediaKind::Image)
        .await?;

    let mut image = ImageContent::new(uploaded, mimetype);
    image.caption = optional_env("WA_STATUS_MEDIA_CAPTION");
    let relay = client
        .send_status_image_with_signal_provider(
            validated.connection(),
            status_jids.iter().map(String::as_str),
            image,
            MessageRelayOptions::new(),
        )
        .await?;

    assert!(!relay.message_id.is_empty());
    assert!(relay.recipient_count > 0);
    Ok(())
}

#[cfg(feature = "http-media")]
#[tokio::test(flavor = "current_thread")]
#[ignore = "requires WA_LIVE_E2E=1, WA_SESSION_DB, paired credentials, WA_STATUS_JIDS, and WA_STATUS_AUDIO_PATH"]
async fn live_status_audio_media_send_smoke() -> Result<(), Box<dyn Error>> {
    if !live_enabled() {
        return Ok(());
    }
    let status_jids = csv_env("WA_STATUS_JIDS");
    if status_jids.is_empty() {
        return Ok(());
    }
    let Some(audio_path) = optional_env("WA_STATUS_AUDIO_PATH") else {
        return Ok(());
    };

    let plaintext = std::fs::read(audio_path)?;
    let mimetype = optional_env("WA_STATUS_AUDIO_MIMETYPE")
        .unwrap_or_else(|| "audio/ogg; codecs=opus".to_owned());

    let client = live_client().await?;
    let validated = client.connect_websocket().await?;
    let media_connection = client
        .fetch_media_connection_info(validated.connection())
        .await?;
    let transfer = MediaTransfer::new(HttpMediaTransport::new(media_connection));
    let uploaded = client
        .upload_media_bytes(&transfer, &plaintext, MediaKind::Audio)
        .await?;

    let mut audio = AudioContent::new(uploaded, mimetype);
    audio.ptt = bool_env("WA_STATUS_AUDIO_PTT", false);
    let relay = client
        .send_status_audio_with_signal_provider(
            validated.connection(),
            status_jids.iter().map(String::as_str),
            audio,
            MessageRelayOptions::new(),
        )
        .await?;

    assert!(!relay.message_id.is_empty());
    assert!(relay.recipient_count > 0);
    Ok(())
}

#[cfg(feature = "http-media")]
#[tokio::test(flavor = "current_thread")]
#[ignore = "requires WA_LIVE_E2E=1, WA_SESSION_DB, paired credentials, WA_STATUS_JIDS, and WA_STATUS_STICKER_PATH"]
async fn live_status_sticker_media_send_smoke() -> Result<(), Box<dyn Error>> {
    if !live_enabled() {
        return Ok(());
    }
    let status_jids = csv_env("WA_STATUS_JIDS");
    if status_jids.is_empty() {
        return Ok(());
    }
    let Some(sticker_path) = optional_env("WA_STATUS_STICKER_PATH") else {
        return Ok(());
    };

    let plaintext = std::fs::read(sticker_path)?;
    let mimetype =
        optional_env("WA_STATUS_STICKER_MIMETYPE").unwrap_or_else(|| "image/webp".to_owned());

    let client = live_client().await?;
    let validated = client.connect_websocket().await?;
    let media_connection = client
        .fetch_media_connection_info(validated.connection())
        .await?;
    let transfer = MediaTransfer::new(HttpMediaTransport::new(media_connection));
    let uploaded = client
        .upload_media_bytes(&transfer, &plaintext, MediaKind::Sticker)
        .await?;

    let mut sticker = StickerContent::new(uploaded, mimetype);
    sticker.is_animated = bool_env("WA_STATUS_STICKER_ANIMATED", false);
    let relay = client
        .send_status_sticker_with_signal_provider(
            validated.connection(),
            status_jids.iter().map(String::as_str),
            sticker,
            MessageRelayOptions::new(),
        )
        .await?;

    assert!(!relay.message_id.is_empty());
    assert!(relay.recipient_count > 0);
    Ok(())
}

#[cfg(all(feature = "http-media", feature = "image"))]
#[tokio::test(flavor = "current_thread")]
#[ignore = "requires WA_LIVE_E2E=1, WA_SESSION_DB, paired credentials, WA_STATUS_JIDS, WA_STATUS_VIDEO_PATH, and ffmpeg"]
async fn live_status_video_remote_thumbnail_send_smoke() -> Result<(), Box<dyn Error>> {
    if !live_enabled() {
        return Ok(());
    }
    let status_jids = csv_env("WA_STATUS_JIDS");
    if status_jids.is_empty() {
        return Ok(());
    }
    let Some(video_path) = optional_env("WA_STATUS_VIDEO_PATH") else {
        return Ok(());
    };
    let video_path = PathBuf::from(video_path);
    let plaintext = std::fs::read(&video_path)?;
    let mimetype =
        optional_env("WA_STATUS_VIDEO_MIMETYPE").unwrap_or_else(|| "video/mp4".to_owned());

    let client = live_client().await?;
    let validated = client.connect_websocket().await?;
    let media_connection = client
        .fetch_media_connection_info(validated.connection())
        .await?;
    let transfer = MediaTransfer::new(HttpMediaTransport::new(media_connection));
    let uploaded = client
        .upload_media_bytes(&transfer, &plaintext, MediaKind::Video)
        .await?;
    let thumbnail = client
        .upload_generated_video_remote_thumbnail_file(
            &transfer,
            &uploaded,
            &video_path,
            live_video_thumbnail_options(),
        )
        .await?;
    assert!(!thumbnail.jpeg_thumbnail.is_empty());
    assert!(!thumbnail.remote_thumbnail.direct_path.is_empty());

    let mut video =
        VideoContent::new(uploaded, mimetype).with_remote_thumbnail(thumbnail.remote_thumbnail);
    video.caption = optional_env("WA_STATUS_VIDEO_CAPTION");
    let relay = client
        .send_status_video_with_signal_provider(
            validated.connection(),
            status_jids.iter().map(String::as_str),
            video,
            MessageRelayOptions::new(),
        )
        .await?;

    assert!(!relay.message_id.is_empty());
    assert!(relay.recipient_count > 0);
    Ok(())
}

#[cfg(all(feature = "http-media", feature = "image"))]
#[tokio::test(flavor = "current_thread")]
#[ignore = "requires WA_LIVE_E2E=1, WA_SESSION_DB, paired credentials, WA_STATUS_JIDS, WA_STATUS_DOCUMENT_PATH, and pdftoppm"]
async fn live_status_document_remote_thumbnail_send_smoke() -> Result<(), Box<dyn Error>> {
    if !live_enabled() {
        return Ok(());
    }
    let status_jids = csv_env("WA_STATUS_JIDS");
    if status_jids.is_empty() {
        return Ok(());
    }
    let Some(document_path) = optional_env("WA_STATUS_DOCUMENT_PATH") else {
        return Ok(());
    };
    let document_path = PathBuf::from(document_path);
    let plaintext = std::fs::read(&document_path)?;
    let mimetype =
        optional_env("WA_STATUS_DOCUMENT_MIMETYPE").unwrap_or_else(|| "application/pdf".to_owned());

    let client = live_client().await?;
    let validated = client.connect_websocket().await?;
    let media_connection = client
        .fetch_media_connection_info(validated.connection())
        .await?;
    let transfer = MediaTransfer::new(HttpMediaTransport::new(media_connection));
    let uploaded = client
        .upload_media_bytes(&transfer, &plaintext, MediaKind::Document)
        .await?;
    let thumbnail = client
        .upload_generated_document_remote_thumbnail_file(
            &transfer,
            &uploaded,
            &document_path,
            live_document_thumbnail_options()?,
        )
        .await?;
    assert!(!thumbnail.jpeg_thumbnail.is_empty());
    assert!(!thumbnail.remote_thumbnail.direct_path.is_empty());

    let mut document =
        DocumentContent::new(uploaded, mimetype).with_remote_thumbnail(thumbnail.remote_thumbnail);
    document.caption = optional_env("WA_STATUS_DOCUMENT_CAPTION");
    document.title = optional_env("WA_STATUS_DOCUMENT_TITLE");
    document.file_name = optional_env("WA_STATUS_DOCUMENT_FILE_NAME").or_else(|| {
        document_path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
    });
    let relay = client
        .send_status_document_with_signal_provider(
            validated.connection(),
            status_jids.iter().map(String::as_str),
            document,
            MessageRelayOptions::new(),
        )
        .await?;

    assert!(!relay.message_id.is_empty());
    assert!(relay.recipient_count > 0);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires WA_LIVE_E2E=1, WA_SESSION_DB, paired credentials, and WA_GROUP_JID"]
async fn live_group_metadata_smoke() -> Result<(), Box<dyn Error>> {
    if !live_enabled() {
        return Ok(());
    }
    let Some(group_jid) = optional_env("WA_GROUP_JID") else {
        return Ok(());
    };

    let client = live_client().await?;
    let validated = client.connect_websocket().await?;
    let metadata = client
        .fetch_group_metadata(validated.connection(), &group_jid)
        .await?;

    assert_eq!(metadata.jid, group_jid);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires WA_LIVE_E2E=1, WA_SESSION_DB, paired credentials, and WA_COMMUNITY_JID, WA_COMMUNITY_INVITE_CODE, or WA_COMMUNITY_FETCH_PARTICIPATING=1"]
async fn live_community_read_smoke() -> Result<(), Box<dyn Error>> {
    if !live_enabled() {
        return Ok(());
    }
    let community_jid = optional_env("WA_COMMUNITY_JID");
    let invite_code = optional_env("WA_COMMUNITY_INVITE_CODE");
    if community_jid.is_none()
        && invite_code.is_none()
        && !bool_env("WA_COMMUNITY_FETCH_PARTICIPATING", false)
    {
        return Ok(());
    }

    let client = live_client().await?;
    let validated = client.connect_websocket().await?;

    if let Some(community_jid) = community_jid.as_deref() {
        let metadata = client
            .fetch_community_metadata(validated.connection(), community_jid)
            .await?;
        assert_eq!(metadata.jid, community_jid);

        if bool_env("WA_COMMUNITY_FETCH_LINKED_GROUPS", false) {
            let linked_groups = client
                .fetch_community_linked_groups(validated.connection(), community_jid)
                .await?;
            for group in linked_groups {
                assert!(!group.jid.is_empty());
            }
        }

        if bool_env("WA_COMMUNITY_RESOLVE_LINKED_GROUPS", false) {
            let linked_groups = client
                .fetch_community_linked_groups_resolved(validated.connection(), community_jid)
                .await?;
            assert!(!linked_groups.community_jid.is_empty());
            for group in linked_groups.linked_groups {
                assert!(!group.jid.is_empty());
            }
        }

        if bool_env("WA_COMMUNITY_FETCH_JOIN_REQUESTS", false) {
            let requests = client
                .fetch_community_join_requests(validated.connection(), community_jid)
                .await?;
            for request in requests {
                assert!(!request.jid.is_empty());
            }
        }
    }

    if bool_env("WA_COMMUNITY_FETCH_PARTICIPATING", false) {
        let communities = client
            .fetch_participating_communities(validated.connection())
            .await?;
        for community in communities {
            assert!(!community.jid.is_empty());
        }
    }

    if let Some(invite_code) = invite_code.as_deref() {
        let metadata = client
            .fetch_community_invite_info(validated.connection(), invite_code)
            .await?;
        assert!(!metadata.jid.is_empty());
    }

    Ok(())
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires WA_LIVE_E2E=1, WA_SESSION_DB, paired credentials, and WA_NEWSLETTER_JID or WA_NEWSLETTER_INVITE"]
async fn live_newsletter_metadata_smoke() -> Result<(), Box<dyn Error>> {
    if !live_enabled() {
        return Ok(());
    }
    let Some((lookup, explicit_jid)) = newsletter_lookup_from_env() else {
        return Ok(());
    };

    let client = live_client().await?;
    let validated = client.connect_websocket().await?;
    let metadata = client
        .fetch_newsletter_metadata(validated.connection(), lookup)
        .await?;

    if let Some(metadata) = metadata {
        assert!(!metadata.id.is_empty());
        let jid = explicit_jid.as_deref().unwrap_or(&metadata.id);
        if bool_env("WA_NEWSLETTER_FETCH_COUNTS", false) {
            let _subscribers = client
                .fetch_newsletter_subscriber_count(validated.connection(), jid)
                .await?;
            let _admins = client
                .fetch_newsletter_admin_count(validated.connection(), jid)
                .await?;
        }
        if bool_env("WA_NEWSLETTER_FETCH_MESSAGES", false) {
            let count = u32_env("WA_NEWSLETTER_MESSAGE_COUNT")?.unwrap_or(10);
            let since = u64_env("WA_NEWSLETTER_MESSAGE_SINCE")?;
            let after = u64_env("WA_NEWSLETTER_MESSAGE_AFTER")?;
            let messages = client
                .fetch_newsletter_messages(validated.connection(), jid, count, since, after)
                .await?;
            for message in messages {
                assert_eq!(message.key.remote_jid, jid);
                assert!(!message.key.id.is_empty());
                assert_eq!(
                    message.fields.get("kind").map(String::as_str),
                    Some("newsletter")
                );
                assert_eq!(
                    message.fields.get("source").map(String::as_str),
                    Some("newsletter_fetch")
                );
            }
        }
        if bool_env("WA_NEWSLETTER_LIVE_UPDATES", false)
            && let Some(subscription) = client
                .subscribe_newsletter_live_updates(validated.connection(), jid)
                .await?
        {
            assert!(!subscription.duration.is_empty());
        }
    }
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires WA_LIVE_E2E=1, WA_SESSION_DB, paired credentials, and WA_BUSINESS_JID"]
async fn live_business_profile_smoke() -> Result<(), Box<dyn Error>> {
    if !live_enabled() {
        return Ok(());
    }
    let Some(business_jid) = optional_env("WA_BUSINESS_JID") else {
        return Ok(());
    };

    let client = live_client().await?;
    let validated = client.connect_websocket().await?;
    let profile = client
        .fetch_business_profile(validated.connection(), &business_jid)
        .await?;

    if let Some(profile) = profile
        && let Some(jid) = profile.jid.as_deref()
    {
        assert!(!jid.is_empty());
    }
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires WA_LIVE_E2E=1, WA_SESSION_DB, paired credentials, WA_BUSINESS_PROFILE_UPDATE=1, and at least one WA_BUSINESS_PROFILE_* field; mutates business profile"]
async fn live_business_profile_update_smoke() -> Result<(), Box<dyn Error>> {
    if !live_enabled() || !bool_env("WA_BUSINESS_PROFILE_UPDATE", false) {
        return Ok(());
    }
    let update = business_profile_update_from_env();
    if update.is_empty() {
        return Ok(());
    }

    let client = live_client().await?;
    let validated = client.connect_websocket().await?;
    client
        .update_business_profile(validated.connection(), update)
        .await?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires WA_LIVE_E2E=1, WA_SESSION_DB, paired credentials, and WA_BUSINESS_CATALOG_JID"]
async fn live_business_catalog_smoke() -> Result<(), Box<dyn Error>> {
    if !live_enabled() {
        return Ok(());
    }
    let Some(business_jid) = optional_env("WA_BUSINESS_CATALOG_JID") else {
        return Ok(());
    };

    let mut query = BusinessCatalogQuery::new(&business_jid)?;
    if let Some(limit) = u32_env("WA_BUSINESS_CATALOG_LIMIT")? {
        query = query.with_limit(limit)?;
    }
    if let Some(cursor) = optional_env("WA_BUSINESS_CATALOG_CURSOR") {
        query = query.with_cursor(cursor)?;
    }

    let client = live_client().await?;
    let validated = client.connect_websocket().await?;
    let catalog = client
        .fetch_business_catalog(validated.connection(), query)
        .await?;

    if let Some(cursor) = catalog.next_page_cursor.as_deref() {
        assert!(!cursor.is_empty());
    }
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires WA_LIVE_E2E=1, WA_SESSION_DB, paired credentials, and WA_BUSINESS_COLLECTIONS_JID"]
async fn live_business_collections_smoke() -> Result<(), Box<dyn Error>> {
    if !live_enabled() {
        return Ok(());
    }
    let Some(business_jid) = optional_env("WA_BUSINESS_COLLECTIONS_JID") else {
        return Ok(());
    };

    let mut query = BusinessCollectionsQuery::new(&business_jid)?;
    if let Some(limit) = u32_env("WA_BUSINESS_COLLECTION_LIMIT")? {
        query = query.with_collection_limit(limit)?;
    }
    if let Some(limit) = u32_env("WA_BUSINESS_COLLECTION_ITEM_LIMIT")? {
        query = query.with_item_limit(limit)?;
    }

    let client = live_client().await?;
    let validated = client.connect_websocket().await?;
    let collections = client
        .fetch_business_collections(validated.connection(), query)
        .await?;

    for collection in collections {
        assert!(!collection.id.is_empty());
    }
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires WA_LIVE_E2E=1, WA_SESSION_DB, paired credentials, WA_BUSINESS_ORDER_ID, and WA_BUSINESS_ORDER_TOKEN"]
async fn live_business_order_details_smoke() -> Result<(), Box<dyn Error>> {
    if !live_enabled() {
        return Ok(());
    }
    let Some(order_id) = optional_env("WA_BUSINESS_ORDER_ID") else {
        return Ok(());
    };
    let Some(token) = optional_env("WA_BUSINESS_ORDER_TOKEN") else {
        return Ok(());
    };

    let client = live_client().await?;
    let validated = client.connect_websocket().await?;
    let details = client
        .fetch_business_order_details(validated.connection(), &order_id, &token)
        .await?;

    assert!(!details.price.currency.is_empty());
    for product in details.products {
        assert!(!product.id.is_empty());
    }
    Ok(())
}

#[cfg(feature = "http-media")]
#[tokio::test(flavor = "current_thread")]
#[ignore = "requires WA_LIVE_E2E=1, WA_SESSION_DB, paired credentials, and WA_BUSINESS_PRODUCT_IMAGE_PATH"]
async fn live_business_product_image_upload_smoke() -> Result<(), Box<dyn Error>> {
    if !live_enabled() {
        return Ok(());
    }
    let Some(image_path) = optional_env("WA_BUSINESS_PRODUCT_IMAGE_PATH") else {
        return Ok(());
    };

    let client = live_client().await?;
    let validated = client.connect_websocket().await?;
    let media_connection = client
        .fetch_media_connection_info(validated.connection())
        .await?;
    let transfer = MediaTransfer::new(HttpMediaTransport::new(media_connection));
    let fallback_host = optional_env("WA_BUSINESS_MEDIA_FALLBACK_HOST");
    let image = client
        .upload_business_product_image_file(&transfer, image_path, fallback_host.as_deref())
        .await?;

    assert!(image.url.starts_with("https://"));
    Ok(())
}

#[cfg(feature = "http-media")]
#[tokio::test(flavor = "current_thread")]
#[ignore = "requires WA_LIVE_E2E=1, WA_SESSION_DB, paired credentials, and WA_BUSINESS_COVER_PHOTO_PATH"]
async fn live_business_cover_photo_upload_smoke() -> Result<(), Box<dyn Error>> {
    if !live_enabled() {
        return Ok(());
    }
    let Some(image_path) = optional_env("WA_BUSINESS_COVER_PHOTO_PATH") else {
        return Ok(());
    };

    let client = live_client().await?;
    let validated = client.connect_websocket().await?;
    let media_connection = client
        .fetch_media_connection_info(validated.connection())
        .await?;
    let transfer = MediaTransfer::new(HttpMediaTransport::new(media_connection));
    let upload = client
        .upload_business_cover_photo_file(&transfer, image_path)
        .await?;

    assert!(!upload.id.is_empty());
    assert!(!upload.token.is_empty());
    assert!(upload.timestamp >= 0);
    Ok(())
}

#[cfg(feature = "http-media")]
#[tokio::test(flavor = "current_thread")]
#[ignore = "requires WA_LIVE_E2E=1, WA_SESSION_DB, paired credentials, WA_BUSINESS_COVER_PHOTO_UPDATE=1, and WA_BUSINESS_COVER_PHOTO_PATH; mutates business cover photo"]
async fn live_business_cover_photo_update_smoke() -> Result<(), Box<dyn Error>> {
    if !live_enabled() || !bool_env("WA_BUSINESS_COVER_PHOTO_UPDATE", false) {
        return Ok(());
    }
    let Some(image_path) = optional_env("WA_BUSINESS_COVER_PHOTO_PATH") else {
        return Ok(());
    };

    let client = live_client().await?;
    let validated = client.connect_websocket().await?;
    let media_connection = client
        .fetch_media_connection_info(validated.connection())
        .await?;
    let transfer = MediaTransfer::new(HttpMediaTransport::new(media_connection));
    let upload = client
        .upload_business_cover_photo_file(&transfer, image_path)
        .await?;
    let id = client
        .update_business_cover_photo(validated.connection(), upload)
        .await?;

    assert!(!id.is_empty());
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires WA_LIVE_E2E=1, WA_SESSION_DB, paired credentials, WA_BUSINESS_COVER_PHOTO_REMOVE=1, and WA_BUSINESS_COVER_PHOTO_ID; mutates business cover photo"]
async fn live_business_cover_photo_remove_smoke() -> Result<(), Box<dyn Error>> {
    if !live_enabled() || !bool_env("WA_BUSINESS_COVER_PHOTO_REMOVE", false) {
        return Ok(());
    }
    let Some(id) = optional_env("WA_BUSINESS_COVER_PHOTO_ID") else {
        return Ok(());
    };

    let client = live_client().await?;
    let validated = client.connect_websocket().await?;
    client
        .remove_business_cover_photo(validated.connection(), &id)
        .await?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires WA_LIVE_E2E=1, WA_SESSION_DB, paired credentials, and WA_GROUP_SEND_JID"]
async fn live_group_sender_key_text_send_smoke() -> Result<(), Box<dyn Error>> {
    if !live_enabled() {
        return Ok(());
    }
    let Some(group_jid) = optional_env("WA_GROUP_SEND_JID") else {
        return Ok(());
    };
    let text = optional_env("WA_GROUP_TEXT")
        .unwrap_or_else(|| "wa-client live group sender-key smoke".to_owned());

    let client = live_client().await?;
    let validated = client.connect_websocket().await?;
    let relay = client
        .send_group_sender_key_text_with_signal_provider(
            validated.connection(),
            &group_jid,
            text,
            MessageRelayOptions::new(),
            MessageRelayOptions::new(),
        )
        .await?;

    assert!(!relay.distribution.message_id.is_empty());
    assert!(!relay.message.message_id.is_empty());
    assert!(relay.distribution.recipient_count > 0);
    Ok(())
}

#[cfg(feature = "image")]
#[tokio::test(flavor = "current_thread")]
#[ignore = "requires WA_LIVE_E2E=1, WA_SESSION_DB, paired credentials, and WA_PROFILE_PICTURE_PATH; mutates profile picture"]
async fn live_profile_picture_update_smoke() -> Result<(), Box<dyn Error>> {
    if !live_enabled() {
        return Ok(());
    }
    let Some(image_path) = optional_env("WA_PROFILE_PICTURE_PATH") else {
        return Ok(());
    };
    let target_jid = optional_env("WA_PROFILE_PICTURE_TARGET_JID");
    let image = std::fs::read(image_path)?;

    let client = live_client().await?;
    let validated = client.connect_websocket().await?;
    let generated = client
        .update_profile_picture_from_image(
            validated.connection(),
            target_jid.as_deref(),
            &image,
            live_profile_picture_options()?,
        )
        .await?;

    assert!(!generated.image.is_empty());
    assert!(!generated.preview.is_empty());
    assert!(generated.image_size > 0);
    assert!(generated.preview_size > 0);
    Ok(())
}

#[cfg(feature = "http-media")]
#[tokio::test(flavor = "current_thread")]
#[ignore = "requires WA_LIVE_E2E=1, WA_SESSION_DB, paired credentials, WA_TARGET_JID, and WA_MEDIA_PATH"]
async fn live_image_media_send_smoke() -> Result<(), Box<dyn Error>> {
    if !live_enabled() {
        return Ok(());
    }
    let Some(target_jid) = optional_env("WA_TARGET_JID") else {
        return Ok(());
    };
    let Some(media_path) = optional_env("WA_MEDIA_PATH") else {
        return Ok(());
    };

    let plaintext = std::fs::read(media_path)?;
    let mimetype = optional_env("WA_MEDIA_MIMETYPE").unwrap_or_else(|| "image/jpeg".to_owned());

    let client = live_client().await?;
    let validated = client.connect_websocket().await?;
    let media_connection = client
        .fetch_media_connection_info(validated.connection())
        .await?;
    let transfer = MediaTransfer::new(HttpMediaTransport::new(media_connection));
    let uploaded = client
        .upload_media_bytes(&transfer, &plaintext, MediaKind::Image)
        .await?;

    let mut image = ImageContent::new(uploaded, mimetype);
    image.caption = optional_env("WA_MEDIA_CAPTION");

    let relay = client
        .send_image_with_signal_provider(
            validated.connection(),
            &target_jid,
            image,
            MessageRelayOptions::new(),
        )
        .await?;

    assert!(!relay.message_id.is_empty());
    Ok(())
}

#[cfg(feature = "http-media")]
#[tokio::test(flavor = "current_thread")]
#[ignore = "requires WA_LIVE_E2E=1, WA_SESSION_DB, paired credentials, WA_TARGET_JID, and WA_VIDEO_MEDIA_PATH"]
async fn live_video_media_send_smoke() -> Result<(), Box<dyn Error>> {
    if !live_enabled() {
        return Ok(());
    }
    let Some(target_jid) = optional_env("WA_TARGET_JID") else {
        return Ok(());
    };
    let Some(video_path) = optional_env("WA_VIDEO_MEDIA_PATH") else {
        return Ok(());
    };

    let plaintext = std::fs::read(video_path)?;
    let mimetype =
        optional_env("WA_VIDEO_MEDIA_MIMETYPE").unwrap_or_else(|| "video/mp4".to_owned());

    let client = live_client().await?;
    let validated = client.connect_websocket().await?;
    let media_connection = client
        .fetch_media_connection_info(validated.connection())
        .await?;
    let transfer = MediaTransfer::new(HttpMediaTransport::new(media_connection));
    let uploaded = client
        .upload_media_bytes(&transfer, &plaintext, MediaKind::Video)
        .await?;

    let mut video = VideoContent::new(uploaded, mimetype);
    video.caption = optional_env("WA_VIDEO_MEDIA_CAPTION");
    video.seconds = u32_env("WA_VIDEO_MEDIA_SECONDS")?;
    video.height = u32_env("WA_VIDEO_MEDIA_HEIGHT")?;
    video.width = u32_env("WA_VIDEO_MEDIA_WIDTH")?;
    let relay = client
        .send_video_with_signal_provider(
            validated.connection(),
            &target_jid,
            video,
            MessageRelayOptions::new(),
        )
        .await?;

    assert!(!relay.message_id.is_empty());
    Ok(())
}

#[cfg(feature = "http-media")]
#[tokio::test(flavor = "current_thread")]
#[ignore = "requires WA_LIVE_E2E=1, WA_SESSION_DB, paired credentials, WA_TARGET_JID, and WA_VIEW_ONCE_IMAGE_PATH"]
async fn live_view_once_image_media_send_smoke() -> Result<(), Box<dyn Error>> {
    if !live_enabled() {
        return Ok(());
    }
    let Some(target_jid) = optional_env("WA_TARGET_JID") else {
        return Ok(());
    };
    let Some(image_path) = optional_env("WA_VIEW_ONCE_IMAGE_PATH") else {
        return Ok(());
    };

    let plaintext = std::fs::read(image_path)?;
    let mimetype =
        optional_env("WA_VIEW_ONCE_IMAGE_MIMETYPE").unwrap_or_else(|| "image/jpeg".to_owned());

    let client = live_client().await?;
    let validated = client.connect_websocket().await?;
    let media_connection = client
        .fetch_media_connection_info(validated.connection())
        .await?;
    let transfer = MediaTransfer::new(HttpMediaTransport::new(media_connection));
    let uploaded = client
        .upload_media_bytes(&transfer, &plaintext, MediaKind::Image)
        .await?;

    let mut image = ImageContent::new(uploaded, mimetype);
    image.caption = optional_env("WA_VIEW_ONCE_IMAGE_CAPTION");
    let relay = client
        .send_view_once_image_with_signal_provider(
            validated.connection(),
            &target_jid,
            image,
            MessageRelayOptions::new(),
        )
        .await?;

    assert!(!relay.message_id.is_empty());
    Ok(())
}

#[cfg(feature = "http-media")]
#[tokio::test(flavor = "current_thread")]
#[ignore = "requires WA_LIVE_E2E=1, WA_SESSION_DB, paired credentials, WA_TARGET_JID, and WA_VIEW_ONCE_VIDEO_PATH"]
async fn live_view_once_video_media_send_smoke() -> Result<(), Box<dyn Error>> {
    if !live_enabled() {
        return Ok(());
    }
    let Some(target_jid) = optional_env("WA_TARGET_JID") else {
        return Ok(());
    };
    let Some(video_path) = optional_env("WA_VIEW_ONCE_VIDEO_PATH") else {
        return Ok(());
    };

    let plaintext = std::fs::read(video_path)?;
    let mimetype =
        optional_env("WA_VIEW_ONCE_VIDEO_MIMETYPE").unwrap_or_else(|| "video/mp4".to_owned());

    let client = live_client().await?;
    let validated = client.connect_websocket().await?;
    let media_connection = client
        .fetch_media_connection_info(validated.connection())
        .await?;
    let transfer = MediaTransfer::new(HttpMediaTransport::new(media_connection));
    let uploaded = client
        .upload_media_bytes(&transfer, &plaintext, MediaKind::Video)
        .await?;

    let mut video = VideoContent::new(uploaded, mimetype);
    video.caption = optional_env("WA_VIEW_ONCE_VIDEO_CAPTION");
    video.seconds = u32_env("WA_VIEW_ONCE_VIDEO_SECONDS")?;
    video.height = u32_env("WA_VIEW_ONCE_VIDEO_HEIGHT")?;
    video.width = u32_env("WA_VIEW_ONCE_VIDEO_WIDTH")?;
    let relay = client
        .send_view_once_video_with_signal_provider(
            validated.connection(),
            &target_jid,
            video,
            MessageRelayOptions::new(),
        )
        .await?;

    assert!(!relay.message_id.is_empty());
    Ok(())
}

#[cfg(feature = "http-media")]
#[tokio::test(flavor = "current_thread")]
#[ignore = "requires WA_LIVE_E2E=1, WA_SESSION_DB, paired credentials, WA_TARGET_JID, and WA_DOCUMENT_MEDIA_PATH"]
async fn live_document_media_send_smoke() -> Result<(), Box<dyn Error>> {
    if !live_enabled() {
        return Ok(());
    }
    let Some(target_jid) = optional_env("WA_TARGET_JID") else {
        return Ok(());
    };
    let Some(document_path) = optional_env("WA_DOCUMENT_MEDIA_PATH") else {
        return Ok(());
    };
    let document_path = PathBuf::from(document_path);
    let plaintext = std::fs::read(&document_path)?;
    let mimetype =
        optional_env("WA_DOCUMENT_MEDIA_MIMETYPE").unwrap_or_else(|| "application/pdf".to_owned());

    let client = live_client().await?;
    let validated = client.connect_websocket().await?;
    let media_connection = client
        .fetch_media_connection_info(validated.connection())
        .await?;
    let transfer = MediaTransfer::new(HttpMediaTransport::new(media_connection));
    let uploaded = client
        .upload_media_bytes(&transfer, &plaintext, MediaKind::Document)
        .await?;

    let mut document = DocumentContent::new(uploaded, mimetype);
    document.caption = optional_env("WA_DOCUMENT_MEDIA_CAPTION");
    document.title = optional_env("WA_DOCUMENT_MEDIA_TITLE");
    document.file_name = optional_env("WA_DOCUMENT_MEDIA_FILE_NAME").or_else(|| {
        document_path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
    });
    document.page_count = u32_env("WA_DOCUMENT_MEDIA_PAGE_COUNT")?;
    let relay = client
        .send_document_with_signal_provider(
            validated.connection(),
            &target_jid,
            document,
            MessageRelayOptions::new(),
        )
        .await?;

    assert!(!relay.message_id.is_empty());
    Ok(())
}

#[cfg(feature = "http-media")]
#[tokio::test(flavor = "current_thread")]
#[ignore = "requires WA_LIVE_E2E=1, WA_SESSION_DB, paired credentials, WA_TARGET_JID, and WA_GIF_PATH"]
async fn live_gif_media_send_smoke() -> Result<(), Box<dyn Error>> {
    if !live_enabled() {
        return Ok(());
    }
    let Some(target_jid) = optional_env("WA_TARGET_JID") else {
        return Ok(());
    };
    let Some(gif_path) = optional_env("WA_GIF_PATH") else {
        return Ok(());
    };

    let plaintext = std::fs::read(gif_path)?;
    let mimetype = optional_env("WA_GIF_MIMETYPE").unwrap_or_else(|| "video/mp4".to_owned());

    let client = live_client().await?;
    let validated = client.connect_websocket().await?;
    let media_connection = client
        .fetch_media_connection_info(validated.connection())
        .await?;
    let transfer = MediaTransfer::new(HttpMediaTransport::new(media_connection));
    let uploaded = client
        .upload_media_bytes(&transfer, &plaintext, MediaKind::Gif)
        .await?;

    let mut gif = VideoContent::new(uploaded, mimetype);
    gif.caption = optional_env("WA_GIF_CAPTION");
    gif.seconds = u32_env("WA_GIF_SECONDS")?;
    gif.height = u32_env("WA_GIF_HEIGHT")?;
    gif.width = u32_env("WA_GIF_WIDTH")?;
    let relay = client
        .send_gif_with_signal_provider(
            validated.connection(),
            &target_jid,
            gif,
            MessageRelayOptions::new(),
        )
        .await?;

    assert!(!relay.message_id.is_empty());
    Ok(())
}

#[cfg(feature = "http-media")]
#[tokio::test(flavor = "current_thread")]
#[ignore = "requires WA_LIVE_E2E=1, WA_SESSION_DB, paired credentials, WA_TARGET_JID, and WA_PTV_PATH"]
async fn live_ptv_media_send_smoke() -> Result<(), Box<dyn Error>> {
    if !live_enabled() {
        return Ok(());
    }
    let Some(target_jid) = optional_env("WA_TARGET_JID") else {
        return Ok(());
    };
    let Some(ptv_path) = optional_env("WA_PTV_PATH") else {
        return Ok(());
    };

    let plaintext = std::fs::read(ptv_path)?;
    let mimetype = optional_env("WA_PTV_MIMETYPE").unwrap_or_else(|| "video/mp4".to_owned());

    let client = live_client().await?;
    let validated = client.connect_websocket().await?;
    let media_connection = client
        .fetch_media_connection_info(validated.connection())
        .await?;
    let transfer = MediaTransfer::new(HttpMediaTransport::new(media_connection));
    let uploaded = client
        .upload_media_bytes(&transfer, &plaintext, MediaKind::VideoNote)
        .await?;

    let mut ptv = VideoContent::new(uploaded, mimetype);
    ptv.seconds = u32_env("WA_PTV_SECONDS")?;
    ptv.height = u32_env("WA_PTV_HEIGHT")?;
    ptv.width = u32_env("WA_PTV_WIDTH")?;
    let relay = client
        .send_ptv_with_signal_provider(
            validated.connection(),
            &target_jid,
            ptv,
            MessageRelayOptions::new(),
        )
        .await?;

    assert!(!relay.message_id.is_empty());
    Ok(())
}

#[cfg(feature = "http-media")]
#[tokio::test(flavor = "current_thread")]
#[ignore = "requires WA_LIVE_E2E=1, WA_SESSION_DB, paired credentials, WA_TARGET_JID, and WA_PTT_PATH"]
async fn live_ptt_media_send_smoke() -> Result<(), Box<dyn Error>> {
    if !live_enabled() {
        return Ok(());
    }
    let Some(target_jid) = optional_env("WA_TARGET_JID") else {
        return Ok(());
    };
    let Some(ptt_path) = optional_env("WA_PTT_PATH") else {
        return Ok(());
    };

    let plaintext = std::fs::read(ptt_path)?;
    let mimetype =
        optional_env("WA_PTT_MIMETYPE").unwrap_or_else(|| "audio/ogg; codecs=opus".to_owned());

    let client = live_client().await?;
    let validated = client.connect_websocket().await?;
    let media_connection = client
        .fetch_media_connection_info(validated.connection())
        .await?;
    let transfer = MediaTransfer::new(HttpMediaTransport::new(media_connection));
    let uploaded = client
        .upload_media_bytes(&transfer, &plaintext, MediaKind::PushToTalk)
        .await?;

    let mut ptt = AudioContent::new(uploaded, mimetype);
    ptt.seconds = u32_env("WA_PTT_SECONDS")?;
    let relay = client
        .send_ptt_with_signal_provider(
            validated.connection(),
            &target_jid,
            ptt,
            MessageRelayOptions::new(),
        )
        .await?;

    assert!(!relay.message_id.is_empty());
    Ok(())
}

#[cfg(feature = "http-media")]
#[tokio::test(flavor = "current_thread")]
#[ignore = "requires WA_LIVE_E2E=1, WA_SESSION_DB, paired credentials, WA_TARGET_JID, and WA_AUDIO_PATH"]
async fn live_audio_media_send_smoke() -> Result<(), Box<dyn Error>> {
    if !live_enabled() {
        return Ok(());
    }
    let Some(target_jid) = optional_env("WA_TARGET_JID") else {
        return Ok(());
    };
    let Some(audio_path) = optional_env("WA_AUDIO_PATH") else {
        return Ok(());
    };

    let plaintext = std::fs::read(audio_path)?;
    let mimetype =
        optional_env("WA_AUDIO_MIMETYPE").unwrap_or_else(|| "audio/ogg; codecs=opus".to_owned());
    let ptt = bool_env("WA_AUDIO_PTT", false);

    let client = live_client().await?;
    let validated = client.connect_websocket().await?;
    let media_connection = client
        .fetch_media_connection_info(validated.connection())
        .await?;
    let transfer = MediaTransfer::new(HttpMediaTransport::new(media_connection));
    let upload_kind = if ptt {
        MediaKind::PushToTalk
    } else {
        MediaKind::Audio
    };
    let uploaded = client
        .upload_media_bytes(&transfer, &plaintext, upload_kind)
        .await?;

    let mut audio = AudioContent::new(uploaded, mimetype);
    audio.ptt = ptt;
    let relay = client
        .send_audio_with_signal_provider(
            validated.connection(),
            &target_jid,
            audio,
            MessageRelayOptions::new(),
        )
        .await?;

    assert!(!relay.message_id.is_empty());
    Ok(())
}

#[cfg(feature = "http-media")]
#[tokio::test(flavor = "current_thread")]
#[ignore = "requires WA_LIVE_E2E=1, WA_SESSION_DB, paired credentials, WA_TARGET_JID, and WA_STICKER_PATH"]
async fn live_sticker_media_send_smoke() -> Result<(), Box<dyn Error>> {
    if !live_enabled() {
        return Ok(());
    }
    let Some(target_jid) = optional_env("WA_TARGET_JID") else {
        return Ok(());
    };
    let Some(sticker_path) = optional_env("WA_STICKER_PATH") else {
        return Ok(());
    };

    let plaintext = std::fs::read(sticker_path)?;
    let mimetype = optional_env("WA_STICKER_MIMETYPE").unwrap_or_else(|| "image/webp".to_owned());

    let client = live_client().await?;
    let validated = client.connect_websocket().await?;
    let media_connection = client
        .fetch_media_connection_info(validated.connection())
        .await?;
    let transfer = MediaTransfer::new(HttpMediaTransport::new(media_connection));
    let uploaded = client
        .upload_media_bytes(&transfer, &plaintext, MediaKind::Sticker)
        .await?;

    let mut sticker = StickerContent::new(uploaded, mimetype);
    sticker.is_animated = bool_env("WA_STICKER_ANIMATED", false);
    let relay = client
        .send_sticker_with_signal_provider(
            validated.connection(),
            &target_jid,
            sticker,
            MessageRelayOptions::new(),
        )
        .await?;

    assert!(!relay.message_id.is_empty());
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires WA_LIVE_E2E=1, WA_SESSION_DB, paired credentials, WA_MEDIA_RETRY_REMOTE_JID, WA_MEDIA_RETRY_MESSAGE_ID, and WA_MEDIA_RETRY_MEDIA_KEY_HEX"]
async fn live_media_retry_request_smoke() -> Result<(), Box<dyn Error>> {
    if !live_enabled() {
        return Ok(());
    }
    let Some(remote_jid) = optional_env("WA_MEDIA_RETRY_REMOTE_JID") else {
        return Ok(());
    };
    let Some(message_id) = optional_env("WA_MEDIA_RETRY_MESSAGE_ID") else {
        return Ok(());
    };
    let Some(media_key) = media_key_hex("WA_MEDIA_RETRY_MEDIA_KEY_HEX")? else {
        return Ok(());
    };

    let key = MessageKey {
        remote_jid: Some(remote_jid.clone()),
        from_me: Some(bool_env("WA_MEDIA_RETRY_FROM_ME", false)),
        id: Some(message_id.clone()),
        participant: optional_env("WA_MEDIA_RETRY_PARTICIPANT"),
    };

    let client = live_client().await?;
    let validated = client.connect_websocket().await?;
    let node = client
        .send_media_retry_request(validated.connection(), &key, &media_key)
        .await?;

    assert_eq!(node.tag, "receipt");
    assert_eq!(node.attrs["id"], message_id);
    assert_eq!(node.attrs["type"], "server-error");
    Ok(())
}

#[cfg(feature = "http-media")]
#[tokio::test(flavor = "current_thread")]
#[ignore = "requires WA_LIVE_E2E=1, WA_SESSION_DB, paired credentials, http-media, WA_MEDIA_RETRY_REMOTE_JID, WA_MEDIA_RETRY_MESSAGE_ID, WA_MEDIA_RETRY_MEDIA_KEY_HEX, WA_MEDIA_RETRY_FILE_SHA256_HEX, WA_MEDIA_RETRY_FILE_ENC_SHA256_HEX, and WA_MEDIA_RETRY_FILE_LENGTH"]
async fn live_media_retry_response_roundtrip_smoke() -> Result<(), Box<dyn Error>> {
    if !live_enabled() {
        return Ok(());
    }
    let Some(remote_jid) = optional_env("WA_MEDIA_RETRY_REMOTE_JID") else {
        return Ok(());
    };
    let Some(message_id) = optional_env("WA_MEDIA_RETRY_MESSAGE_ID") else {
        return Ok(());
    };
    let Some(media_key) = media_key_hex("WA_MEDIA_RETRY_MEDIA_KEY_HEX")? else {
        return Ok(());
    };
    if optional_env("WA_MEDIA_RETRY_FILE_SHA256_HEX").is_none()
        || optional_env("WA_MEDIA_RETRY_FILE_ENC_SHA256_HEX").is_none()
        || optional_env("WA_MEDIA_RETRY_FILE_LENGTH").is_none()
    {
        return Ok(());
    }

    let participant = optional_env("WA_MEDIA_RETRY_PARTICIPANT");
    let key = MessageKey {
        remote_jid: Some(remote_jid.clone()),
        from_me: Some(bool_env("WA_MEDIA_RETRY_FROM_ME", false)),
        id: Some(message_id.clone()),
        participant: participant.clone(),
    };
    let retry_key = MessageEventKey::new(remote_jid, message_id.clone(), participant);
    let kind = media_retry_kind_env()?;
    let pending_media = live_media_retry_uploaded_media(media_key.clone())?;
    let mut pending = PendingMediaRetry::new(pending_media, kind);
    if let Some(host) = optional_env("WA_MEDIA_RETRY_FALLBACK_HOST") {
        pending = pending.with_fallback_host(host);
    }
    let receive_timeout = duration_env("WA_MEDIA_RETRY_TIMEOUT_SECS", 180)?;

    let client = live_client().await?;
    client
        .register_pending_media_retry_persisted(retry_key, pending)
        .await?;
    let mut events = client.subscribe();
    let validated = client.connect_websocket().await?;
    let connection = validated.into_connection();
    let media_connection = client.fetch_media_connection_info(&connection).await?;
    let transfer = MediaTransfer::new(HttpMediaTransport::new(media_connection));
    let mut processor = client.spawn_incoming_processor_with_media_retry_with_signal_provider(
        connection.clone(),
        transfer,
        EventBufferConfig::default(),
    )?;

    let node = client
        .send_media_retry_request(&connection, &key, &media_key)
        .await?;
    let processed = wait_for_live_media_retry_processed_event(&mut events, receive_timeout).await;
    processor.abort();

    assert_eq!(node.tag, "receipt");
    assert_eq!(node.attrs["id"], message_id);
    assert_eq!(node.attrs["type"], "server-error");
    let processed = processed?;
    assert!(
        !processed.downloads.is_empty(),
        "media retry response did not download refreshed media: {processed:?}"
    );
    assert!(
        processed.errors.is_empty(),
        "media retry response produced processing errors: {processed:?}"
    );
    assert_eq!(processed.ignored_without_pending, 0);
    assert_eq!(processed.malformed_stored_records, 0);
    Ok(())
}

#[cfg(all(feature = "http-media", feature = "image"))]
#[tokio::test(flavor = "current_thread")]
#[ignore = "requires WA_LIVE_E2E=1, WA_SESSION_DB, paired credentials, WA_TARGET_JID, WA_VIDEO_PATH, and ffmpeg"]
async fn live_video_remote_thumbnail_send_smoke() -> Result<(), Box<dyn Error>> {
    if !live_enabled() {
        return Ok(());
    }
    let Some(target_jid) = optional_env("WA_TARGET_JID") else {
        return Ok(());
    };
    let Some(video_path) = optional_env("WA_VIDEO_PATH") else {
        return Ok(());
    };
    let video_path = PathBuf::from(video_path);
    let plaintext = std::fs::read(&video_path)?;
    let mimetype = optional_env("WA_VIDEO_MIMETYPE").unwrap_or_else(|| "video/mp4".to_owned());

    let client = live_client().await?;
    let validated = client.connect_websocket().await?;
    let media_connection = client
        .fetch_media_connection_info(validated.connection())
        .await?;
    let transfer = MediaTransfer::new(HttpMediaTransport::new(media_connection));
    let uploaded = client
        .upload_media_bytes(&transfer, &plaintext, MediaKind::Video)
        .await?;
    let thumbnail = client
        .upload_generated_video_remote_thumbnail_file(
            &transfer,
            &uploaded,
            &video_path,
            live_video_thumbnail_options(),
        )
        .await?;
    assert!(!thumbnail.jpeg_thumbnail.is_empty());
    assert!(!thumbnail.remote_thumbnail.direct_path.is_empty());

    let mut video =
        VideoContent::new(uploaded, mimetype).with_remote_thumbnail(thumbnail.remote_thumbnail);
    video.caption = optional_env("WA_VIDEO_CAPTION");
    let relay = client
        .send_video_with_signal_provider(
            validated.connection(),
            &target_jid,
            video,
            MessageRelayOptions::new(),
        )
        .await?;

    assert!(!relay.message_id.is_empty());
    Ok(())
}

#[cfg(all(feature = "http-media", feature = "image"))]
#[tokio::test(flavor = "current_thread")]
#[ignore = "requires WA_LIVE_E2E=1, WA_SESSION_DB, paired credentials, WA_TARGET_JID, WA_DOCUMENT_PATH, and pdftoppm"]
async fn live_document_remote_thumbnail_send_smoke() -> Result<(), Box<dyn Error>> {
    if !live_enabled() {
        return Ok(());
    }
    let Some(target_jid) = optional_env("WA_TARGET_JID") else {
        return Ok(());
    };
    let Some(document_path) = optional_env("WA_DOCUMENT_PATH") else {
        return Ok(());
    };
    let document_path = PathBuf::from(document_path);
    let plaintext = std::fs::read(&document_path)?;
    let mimetype =
        optional_env("WA_DOCUMENT_MIMETYPE").unwrap_or_else(|| "application/pdf".to_owned());

    let client = live_client().await?;
    let validated = client.connect_websocket().await?;
    let media_connection = client
        .fetch_media_connection_info(validated.connection())
        .await?;
    let transfer = MediaTransfer::new(HttpMediaTransport::new(media_connection));
    let uploaded = client
        .upload_media_bytes(&transfer, &plaintext, MediaKind::Document)
        .await?;
    let thumbnail = client
        .upload_generated_document_remote_thumbnail_file(
            &transfer,
            &uploaded,
            &document_path,
            live_document_thumbnail_options()?,
        )
        .await?;
    assert!(!thumbnail.jpeg_thumbnail.is_empty());
    assert!(!thumbnail.remote_thumbnail.direct_path.is_empty());

    let mut document =
        DocumentContent::new(uploaded, mimetype).with_remote_thumbnail(thumbnail.remote_thumbnail);
    document.caption = optional_env("WA_DOCUMENT_CAPTION");
    document.title = optional_env("WA_DOCUMENT_TITLE");
    document.file_name = optional_env("WA_DOCUMENT_FILE_NAME").or_else(|| {
        document_path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
    });
    let relay = client
        .send_document_with_signal_provider(
            validated.connection(),
            &target_jid,
            document,
            MessageRelayOptions::new(),
        )
        .await?;

    assert!(!relay.message_id.is_empty());
    Ok(())
}

#[cfg(all(feature = "http-media", feature = "link-preview", feature = "image"))]
#[tokio::test(flavor = "current_thread")]
#[ignore = "requires WA_LIVE_E2E=1, WA_SESSION_DB, paired credentials, WA_TARGET_JID, and WA_LINK_PREVIEW_URL"]
async fn live_link_preview_send_smoke() -> Result<(), Box<dyn Error>> {
    if !live_enabled() {
        return Ok(());
    }
    let Some(target_jid) = optional_env("WA_TARGET_JID") else {
        return Ok(());
    };
    let Some(url) = optional_env("WA_LINK_PREVIEW_URL") else {
        return Ok(());
    };
    let text = optional_env("WA_LINK_PREVIEW_TEXT").unwrap_or_else(|| url.clone());

    let client = live_client().await?;
    let validated = client.connect_websocket().await?;
    let media_connection = client
        .fetch_media_connection_info(validated.connection())
        .await?;
    let transfer = MediaTransfer::new(HttpMediaTransport::new(media_connection));
    let fetched = client
        .fetch_link_preview_with_thumbnail(
            &transfer,
            &url,
            LinkPreviewThumbnailFetchOptions::default(),
        )
        .await?;
    assert!(!fetched.thumbnail_upload.jpeg_thumbnail.is_empty());
    assert!(
        !fetched
            .thumbnail_upload
            .high_quality_thumbnail
            .direct_path
            .is_empty()
    );

    let message = TextMessage::new(text).with_link_preview(fetched.preview.content);
    let relay = client
        .send_message_with_signal_provider(
            validated.connection(),
            &target_jid,
            MessageContent::text_message(message),
            MessageRelayOptions::new(),
        )
        .await?;

    assert!(!relay.message_id.is_empty());
    Ok(())
}

#[cfg(all(feature = "http-media", feature = "link-preview", feature = "image"))]
#[tokio::test(flavor = "current_thread")]
#[ignore = "requires WA_LIVE_E2E=1, WA_SESSION_DB, paired credentials, WA_TARGET_JID, WA_LINK_PREVIEW_URL, and WA_LINK_PREVIEW_IMAGE_PATH"]
async fn live_generated_link_preview_send_smoke() -> Result<(), Box<dyn Error>> {
    if !live_enabled() {
        return Ok(());
    }
    let Some(target_jid) = optional_env("WA_TARGET_JID") else {
        return Ok(());
    };
    let Some(url) = optional_env("WA_LINK_PREVIEW_URL") else {
        return Ok(());
    };
    let Some(image_path) = optional_env("WA_LINK_PREVIEW_IMAGE_PATH") else {
        return Ok(());
    };

    let title = optional_env("WA_LINK_PREVIEW_TITLE").unwrap_or_else(|| "Link preview".to_owned());
    let text = optional_env("WA_LINK_PREVIEW_TEXT").unwrap_or_else(|| url.clone());
    let image = std::fs::read(image_path)?;

    let client = live_client().await?;
    let validated = client.connect_websocket().await?;
    let media_connection = client
        .fetch_media_connection_info(validated.connection())
        .await?;
    let transfer = MediaTransfer::new(HttpMediaTransport::new(media_connection));
    let thumbnail = client
        .upload_generated_link_preview_thumbnail(
            &transfer,
            &image,
            LinkPreviewImageOptions::default(),
        )
        .await?;
    assert!(!thumbnail.jpeg_thumbnail.is_empty());
    assert!(!thumbnail.high_quality_thumbnail.direct_path.is_empty());

    let mut preview = LinkPreviewContent::new(url.clone(), title)
        .with_jpeg_thumbnail(thumbnail.jpeg_thumbnail)
        .with_high_quality_thumbnail(thumbnail.high_quality_thumbnail);
    if let Some(description) = optional_env("WA_LINK_PREVIEW_DESCRIPTION") {
        preview = preview.with_description(description);
    }

    let message = TextMessage::new(text).with_link_preview(preview);
    let relay = client
        .send_message_with_signal_provider(
            validated.connection(),
            &target_jid,
            MessageContent::text_message(message),
            MessageRelayOptions::new(),
        )
        .await?;

    assert!(!relay.message_id.is_empty());
    Ok(())
}
