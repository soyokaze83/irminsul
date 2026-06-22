#[cfg(feature = "http-media")]
use bytes::Bytes;
#[cfg(feature = "http-media")]
use std::time::Duration;
use std::{env, error::Error, path::PathBuf};
use wa_client::prelude::*;

fn session_db_path() -> PathBuf {
    env::var_os("WA_SESSION_DB")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(".wa/session.sqlite"))
}

fn optional_env(name: &str) -> Option<String> {
    env::var(name)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
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

fn fixed_hex_env(name: &str, expected_len: usize) -> Result<Option<Vec<u8>>, Box<dyn Error>> {
    let Some(bytes) = hex_env(name)? else {
        return Ok(None);
    };
    if bytes.len() != expected_len {
        return Err(format!("{name} must contain {} hex characters", expected_len * 2).into());
    }
    Ok(Some(bytes))
}

fn media_key_hex(name: &str) -> Result<Option<Vec<u8>>, Box<dyn Error>> {
    fixed_hex_env(name, 32)
}

#[cfg(feature = "http-media")]
fn duration_env(name: &str, default_secs: u64) -> Result<Duration, Box<dyn Error>> {
    let secs = optional_env(name)
        .map(|value| value.parse())
        .transpose()?
        .unwrap_or(default_secs);
    Ok(Duration::from_secs(secs))
}

#[cfg(feature = "http-media")]
fn u64_env(name: &str) -> Result<Option<u64>, Box<dyn Error>> {
    optional_env(name)
        .map(|value| value.parse())
        .transpose()
        .map_err(Into::into)
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
        .ok_or("WA_MEDIA_RETRY_FILE_SHA256_HEX is required when WA_MEDIA_RETRY_WAIT_RESPONSE=1")?;
    let file_enc_sha256 = fixed_hex_env("WA_MEDIA_RETRY_FILE_ENC_SHA256_HEX", 32)?.ok_or(
        "WA_MEDIA_RETRY_FILE_ENC_SHA256_HEX is required when WA_MEDIA_RETRY_WAIT_RESPONSE=1",
    )?;
    let file_length = u64_env("WA_MEDIA_RETRY_FILE_LENGTH")?
        .ok_or("WA_MEDIA_RETRY_FILE_LENGTH is required when WA_MEDIA_RETRY_WAIT_RESPONSE=1")?;
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

#[cfg(feature = "http-media")]
async fn wait_for_media_retry_processed_event(
    events: &mut tokio::sync::broadcast::Receiver<Event>,
    receive_timeout: Duration,
) -> Result<MediaRetryBatchOutcome, Box<dyn Error>> {
    let wait = async {
        loop {
            match events.recv().await? {
                Event::MediaRetryProcessed(outcome) if !outcome.is_empty() => return Ok(outcome),
                Event::ConnectionUpdate(ConnectionState::Closed) => {
                    return Err::<MediaRetryBatchOutcome, Box<dyn Error>>(
                        "connection closed before a media retry response was processed".into(),
                    );
                }
                _ => {}
            }
        }
    };

    tokio::time::timeout(receive_timeout, wait)
        .await
        .map_err(|_| {
            format!(
                "timed out after {}s waiting for a media retry response",
                receive_timeout.as_secs()
            )
        })?
}

#[cfg(feature = "http-media")]
async fn send_and_wait_for_media_retry_response(
    client: &Client<SqliteAuthStore>,
    connection: Connection,
    key: &MessageKey,
    media_key: &[u8],
) -> Result<(), Box<dyn Error>> {
    let remote_jid = key
        .remote_jid
        .clone()
        .ok_or("WA_MEDIA_RETRY_REMOTE_JID is required")?;
    let message_id = key
        .id
        .clone()
        .ok_or("WA_MEDIA_RETRY_MESSAGE_ID is required")?;
    let retry_key = MessageEventKey::new(remote_jid, message_id.clone(), key.participant.clone());
    let kind = media_retry_kind_env()?;
    let media = live_media_retry_uploaded_media(media_key.to_vec())?;
    let mut pending = PendingMediaRetry::new(media, kind);
    if let Some(host) = optional_env("WA_MEDIA_RETRY_FALLBACK_HOST") {
        pending = pending.with_fallback_host(host);
    }
    client
        .register_pending_media_retry_persisted(retry_key, pending)
        .await?;

    let media_connection = client.fetch_media_connection_info(&connection).await?;
    let transfer = MediaTransfer::new(HttpMediaTransport::new(media_connection));
    let mut events = client.subscribe();
    let mut processor = client.spawn_incoming_processor_with_media_retry_with_signal_provider(
        connection.clone(),
        transfer,
        EventBufferConfig::default(),
    )?;
    let node = client
        .send_media_retry_request(&connection, key, media_key)
        .await?;
    println!(
        "sent media retry request {} to {}",
        node.attrs["id"], node.attrs["to"]
    );

    let timeout = duration_env("WA_MEDIA_RETRY_TIMEOUT_SECS", 180)?;
    let processed = wait_for_media_retry_processed_event(&mut events, timeout).await;
    processor.abort();
    let processed = processed?;
    if !processed.errors.is_empty() {
        return Err(format!("media retry response produced errors: {processed:?}").into());
    }
    if processed.downloads.is_empty() {
        return Err(format!("media retry response produced no downloads: {processed:?}").into());
    }
    println!(
        "processed media retry response with {} download(s)",
        processed.downloads.len()
    );
    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    let Some(remote_jid) = optional_env("WA_MEDIA_RETRY_REMOTE_JID") else {
        println!("set WA_MEDIA_RETRY_REMOTE_JID to the chat JID for the failed media message");
        return Ok(());
    };
    let Some(message_id) = optional_env("WA_MEDIA_RETRY_MESSAGE_ID") else {
        println!("set WA_MEDIA_RETRY_MESSAGE_ID to the failed media message id");
        return Ok(());
    };
    let Some(media_key) = media_key_hex("WA_MEDIA_RETRY_MEDIA_KEY_HEX")? else {
        println!("set WA_MEDIA_RETRY_MEDIA_KEY_HEX to the 32-byte media key as hex");
        return Ok(());
    };

    let key = MessageKey {
        remote_jid: Some(remote_jid),
        from_me: Some(bool_env("WA_MEDIA_RETRY_FROM_ME", false)),
        id: Some(message_id),
        participant: optional_env("WA_MEDIA_RETRY_PARTICIPANT"),
    };

    let store = SqliteAuthStore::open(session_db_path()).await?;
    let client = Client::builder(store).connect().await?;
    let validated = client.connect_websocket().await?;

    #[cfg(feature = "http-media")]
    if bool_env("WA_MEDIA_RETRY_WAIT_RESPONSE", false) {
        return send_and_wait_for_media_retry_response(
            &client,
            validated.into_connection(),
            &key,
            &media_key,
        )
        .await;
    }
    #[cfg(not(feature = "http-media"))]
    if bool_env("WA_MEDIA_RETRY_WAIT_RESPONSE", false) {
        println!("compile with --features http-media to wait for and process the retry response");
    }

    let node = client
        .send_media_retry_request(validated.connection(), &key, &media_key)
        .await?;
    println!(
        "sent media retry request {} to {}",
        node.attrs["id"], node.attrs["to"]
    );

    Ok(())
}
