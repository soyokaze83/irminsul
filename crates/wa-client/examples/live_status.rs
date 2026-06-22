#[cfg(feature = "http-media")]
use std::fs;
use std::{env, error::Error, path::PathBuf};

use bytes::Bytes;
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

fn csv_jids(name: &str) -> Vec<String> {
    optional_env(name)
        .map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|jid| !jid.is_empty())
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default()
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

fn message_secret_env(name: &str, default_fill: u8) -> Result<Bytes, Box<dyn Error>> {
    let Some(bytes) = hex_env(name)? else {
        return Ok(Bytes::from(vec![default_fill; 32]));
    };
    if bytes.len() != 32 {
        return Err(format!("{name} must contain 64 hex characters").into());
    }
    Ok(Bytes::from(bytes))
}

fn current_timestamp_ms() -> Result<u64, Box<dyn Error>> {
    let millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_millis()
        .try_into()?;
    Ok(millis)
}

fn status_poll() -> Result<PollContent, Box<dyn Error>> {
    let name =
        optional_env("WA_STATUS_POLL_NAME").unwrap_or_else(|| "wa-client status poll".to_owned());
    let options = {
        let configured = csv_jids("WA_STATUS_POLL_OPTIONS");
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
    Ok(PollContent::new(
        name,
        options,
        selectable_options_count,
        message_secret,
    ))
}

fn status_event() -> Result<EventContent, Box<dyn Error>> {
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
    Ok(event)
}

#[cfg(all(feature = "http-media", feature = "image"))]
fn video_thumbnail_options() -> VideoThumbnailOptions {
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
fn document_thumbnail_options() -> Result<PdfThumbnailOptions, Box<dyn Error>> {
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

#[cfg(feature = "http-media")]
async fn send_image_status(
    client: &Client<SqliteAuthStore>,
    connection: &Connection,
    status_jids: &[String],
    media_path: &str,
) -> Result<MessageRelay, Box<dyn Error>> {
    let plaintext = fs::read(media_path)?;
    let mimetype =
        optional_env("WA_STATUS_MEDIA_MIMETYPE").unwrap_or_else(|| "image/jpeg".to_owned());

    let media_connection = client.fetch_media_connection_info(connection).await?;
    let transfer = MediaTransfer::new(HttpMediaTransport::new(media_connection));
    let uploaded = client
        .upload_media_bytes(&transfer, &plaintext, MediaKind::Image)
        .await?;

    let mut image = ImageContent::new(uploaded, mimetype);
    image.caption = optional_env("WA_STATUS_MEDIA_CAPTION");
    Ok(client
        .send_status_image_with_signal_provider(
            connection,
            status_jids.iter().map(String::as_str),
            image,
            MessageRelayOptions::new(),
        )
        .await?)
}

#[cfg(all(feature = "http-media", feature = "image"))]
async fn send_video_status(
    client: &Client<SqliteAuthStore>,
    connection: &Connection,
    status_jids: &[String],
    video_path: &str,
) -> Result<MessageRelay, Box<dyn Error>> {
    let video_path = PathBuf::from(video_path);
    let plaintext = fs::read(&video_path)?;
    let mimetype =
        optional_env("WA_STATUS_VIDEO_MIMETYPE").unwrap_or_else(|| "video/mp4".to_owned());

    let media_connection = client.fetch_media_connection_info(connection).await?;
    let transfer = MediaTransfer::new(HttpMediaTransport::new(media_connection));
    let uploaded = client
        .upload_media_bytes(&transfer, &plaintext, MediaKind::Video)
        .await?;
    let thumbnail = client
        .upload_generated_video_remote_thumbnail_file(
            &transfer,
            &uploaded,
            &video_path,
            video_thumbnail_options(),
        )
        .await?;

    let mut video =
        VideoContent::new(uploaded, mimetype).with_remote_thumbnail(thumbnail.remote_thumbnail);
    video.caption = optional_env("WA_STATUS_VIDEO_CAPTION");
    Ok(client
        .send_status_video_with_signal_provider(
            connection,
            status_jids.iter().map(String::as_str),
            video,
            MessageRelayOptions::new(),
        )
        .await?)
}

#[cfg(all(feature = "http-media", feature = "image"))]
async fn send_document_status(
    client: &Client<SqliteAuthStore>,
    connection: &Connection,
    status_jids: &[String],
    document_path: &str,
) -> Result<MessageRelay, Box<dyn Error>> {
    let document_path = PathBuf::from(document_path);
    let plaintext = fs::read(&document_path)?;
    let mimetype =
        optional_env("WA_STATUS_DOCUMENT_MIMETYPE").unwrap_or_else(|| "application/pdf".to_owned());

    let media_connection = client.fetch_media_connection_info(connection).await?;
    let transfer = MediaTransfer::new(HttpMediaTransport::new(media_connection));
    let uploaded = client
        .upload_media_bytes(&transfer, &plaintext, MediaKind::Document)
        .await?;
    let thumbnail = client
        .upload_generated_document_remote_thumbnail_file(
            &transfer,
            &uploaded,
            &document_path,
            document_thumbnail_options()?,
        )
        .await?;

    let mut document =
        DocumentContent::new(uploaded, mimetype).with_remote_thumbnail(thumbnail.remote_thumbnail);
    document.caption = optional_env("WA_STATUS_DOCUMENT_CAPTION");
    document.title = optional_env("WA_STATUS_DOCUMENT_TITLE");
    document.file_name = optional_env("WA_STATUS_DOCUMENT_FILE_NAME").or_else(|| {
        document_path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
    });
    Ok(client
        .send_status_document_with_signal_provider(
            connection,
            status_jids.iter().map(String::as_str),
            document,
            MessageRelayOptions::new(),
        )
        .await?)
}

#[cfg(feature = "http-media")]
async fn send_audio_status(
    client: &Client<SqliteAuthStore>,
    connection: &Connection,
    status_jids: &[String],
    audio_path: &str,
) -> Result<MessageRelay, Box<dyn Error>> {
    let plaintext = fs::read(audio_path)?;
    let mimetype = optional_env("WA_STATUS_AUDIO_MIMETYPE")
        .unwrap_or_else(|| "audio/ogg; codecs=opus".to_owned());

    let media_connection = client.fetch_media_connection_info(connection).await?;
    let transfer = MediaTransfer::new(HttpMediaTransport::new(media_connection));
    let uploaded = client
        .upload_media_bytes(&transfer, &plaintext, MediaKind::Audio)
        .await?;

    let mut audio = AudioContent::new(uploaded, mimetype);
    audio.ptt = matches!(
        optional_env("WA_STATUS_AUDIO_PTT").as_deref(),
        Some("1" | "true" | "TRUE" | "yes" | "YES")
    );
    Ok(client
        .send_status_audio_with_signal_provider(
            connection,
            status_jids.iter().map(String::as_str),
            audio,
            MessageRelayOptions::new(),
        )
        .await?)
}

#[cfg(feature = "http-media")]
async fn send_sticker_status(
    client: &Client<SqliteAuthStore>,
    connection: &Connection,
    status_jids: &[String],
    sticker_path: &str,
) -> Result<MessageRelay, Box<dyn Error>> {
    let plaintext = fs::read(sticker_path)?;
    let mimetype =
        optional_env("WA_STATUS_STICKER_MIMETYPE").unwrap_or_else(|| "image/webp".to_owned());

    let media_connection = client.fetch_media_connection_info(connection).await?;
    let transfer = MediaTransfer::new(HttpMediaTransport::new(media_connection));
    let uploaded = client
        .upload_media_bytes(&transfer, &plaintext, MediaKind::Sticker)
        .await?;

    let mut sticker = StickerContent::new(uploaded, mimetype);
    sticker.is_animated = matches!(
        optional_env("WA_STATUS_STICKER_ANIMATED").as_deref(),
        Some("1" | "true" | "TRUE" | "yes" | "YES")
    );
    Ok(client
        .send_status_sticker_with_signal_provider(
            connection,
            status_jids.iter().map(String::as_str),
            sticker,
            MessageRelayOptions::new(),
        )
        .await?)
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    let status_jids = csv_jids("WA_STATUS_JIDS");
    if status_jids.is_empty() {
        println!("set WA_STATUS_JIDS to a comma-separated status audience");
        return Ok(());
    }

    let store = SqliteAuthStore::open(session_db_path()).await?;
    let client = Client::builder(store).connect().await?;
    let validated = client.connect_websocket().await?;

    let media_path = optional_env("WA_STATUS_MEDIA_PATH");
    let video_path = optional_env("WA_STATUS_VIDEO_PATH");
    let document_path = optional_env("WA_STATUS_DOCUMENT_PATH");
    let audio_path = optional_env("WA_STATUS_AUDIO_PATH");
    let sticker_path = optional_env("WA_STATUS_STICKER_PATH");
    let status_kind = optional_env("WA_STATUS_KIND").unwrap_or_else(|| {
        if media_path.is_some() {
            "image".to_owned()
        } else if video_path.is_some() {
            "video".to_owned()
        } else if document_path.is_some() {
            "document".to_owned()
        } else if audio_path.is_some() {
            "audio".to_owned()
        } else if sticker_path.is_some() {
            "sticker".to_owned()
        } else {
            "text".to_owned()
        }
    });
    let relay = match status_kind.as_str() {
        "text" => {
            let text =
                optional_env("WA_STATUS_TEXT").unwrap_or_else(|| "hello from wa-client".to_owned());
            client
                .send_status_text_with_signal_provider(
                    validated.connection(),
                    status_jids.iter().map(String::as_str),
                    text,
                    MessageRelayOptions::new(),
                )
                .await?
        }
        "image" | "media" => {
            let Some(media_path) = media_path.as_deref() else {
                println!("set WA_STATUS_MEDIA_PATH to an image file");
                return Ok(());
            };
            #[cfg(feature = "http-media")]
            {
                send_image_status(&client, validated.connection(), &status_jids, media_path).await?
            }
            #[cfg(not(feature = "http-media"))]
            {
                let _ = media_path;
                println!("rerun with --features http-media to send WA_STATUS_MEDIA_PATH");
                return Ok(());
            }
        }
        "video" => {
            let Some(video_path) = video_path.as_deref() else {
                println!("set WA_STATUS_VIDEO_PATH to a video file");
                return Ok(());
            };
            #[cfg(all(feature = "http-media", feature = "image"))]
            {
                send_video_status(&client, validated.connection(), &status_jids, video_path).await?
            }
            #[cfg(not(all(feature = "http-media", feature = "image")))]
            {
                let _ = video_path;
                println!("rerun with --features http-media,image to send WA_STATUS_VIDEO_PATH");
                return Ok(());
            }
        }
        "document" => {
            let Some(document_path) = document_path.as_deref() else {
                println!("set WA_STATUS_DOCUMENT_PATH to a PDF document");
                return Ok(());
            };
            #[cfg(all(feature = "http-media", feature = "image"))]
            {
                send_document_status(&client, validated.connection(), &status_jids, document_path)
                    .await?
            }
            #[cfg(not(all(feature = "http-media", feature = "image")))]
            {
                let _ = document_path;
                println!("rerun with --features http-media,image to send WA_STATUS_DOCUMENT_PATH");
                return Ok(());
            }
        }
        "audio" => {
            let Some(audio_path) = audio_path.as_deref() else {
                println!("set WA_STATUS_AUDIO_PATH to an audio file");
                return Ok(());
            };
            #[cfg(feature = "http-media")]
            {
                send_audio_status(&client, validated.connection(), &status_jids, audio_path).await?
            }
            #[cfg(not(feature = "http-media"))]
            {
                let _ = audio_path;
                println!("rerun with --features http-media to send WA_STATUS_AUDIO_PATH");
                return Ok(());
            }
        }
        "sticker" => {
            let Some(sticker_path) = sticker_path.as_deref() else {
                println!("set WA_STATUS_STICKER_PATH to a WebP sticker file");
                return Ok(());
            };
            #[cfg(feature = "http-media")]
            {
                send_sticker_status(&client, validated.connection(), &status_jids, sticker_path)
                    .await?
            }
            #[cfg(not(feature = "http-media"))]
            {
                let _ = sticker_path;
                println!("rerun with --features http-media to send WA_STATUS_STICKER_PATH");
                return Ok(());
            }
        }
        "poll" => {
            client
                .send_status_poll_with_signal_provider(
                    validated.connection(),
                    status_jids.iter().map(String::as_str),
                    status_poll()?,
                    MessageRelayOptions::new(),
                )
                .await?
        }
        "event" => {
            client
                .send_status_event_with_signal_provider(
                    validated.connection(),
                    status_jids.iter().map(String::as_str),
                    status_event()?,
                    MessageRelayOptions::new(),
                )
                .await?
        }
        other => {
            println!(
                "unsupported WA_STATUS_KIND={other}; use text, image, video, document, audio, sticker, poll, or event"
            );
            return Ok(());
        }
    };
    println!(
        "sent status message {} to {} recipient devices",
        relay.message_id, relay.recipient_count
    );

    Ok(())
}
