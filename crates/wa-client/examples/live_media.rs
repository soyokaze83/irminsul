use std::{env, error::Error, fs, path::PathBuf};
use wa_client::prelude::*;

#[derive(Clone, Copy)]
enum DirectMediaKind {
    Image,
    Video,
    Gif,
    Ptv,
    Audio,
    Ptt,
    Document,
    Sticker,
}

impl DirectMediaKind {
    fn from_env() -> Result<Self, Box<dyn Error>> {
        let value = optional_env("WA_MEDIA_KIND").unwrap_or_else(|| "image".to_owned());
        match value.to_ascii_lowercase().as_str() {
            "image" => Ok(Self::Image),
            "video" => Ok(Self::Video),
            "gif" => Ok(Self::Gif),
            "ptv" | "video_note" | "video-note" | "videonote" => Ok(Self::Ptv),
            "audio" => Ok(Self::Audio),
            "ptt" | "push_to_talk" | "push-to-talk" => Ok(Self::Ptt),
            "document" => Ok(Self::Document),
            "sticker" => Ok(Self::Sticker),
            other => Err(format!(
                "unsupported WA_MEDIA_KIND={other}; use image, video, gif, ptv, audio, ptt, document, or sticker"
            )
            .into()),
        }
    }

    fn default_mimetype(self) -> &'static str {
        match self {
            Self::Image => "image/jpeg",
            Self::Video | Self::Gif | Self::Ptv => "video/mp4",
            Self::Audio | Self::Ptt => "audio/ogg; codecs=opus",
            Self::Document => "application/pdf",
            Self::Sticker => "image/webp",
        }
    }

    fn upload_kind(self, ptt: bool) -> MediaKind {
        match self {
            Self::Image => MediaKind::Image,
            Self::Video => MediaKind::Video,
            Self::Gif => MediaKind::Gif,
            Self::Ptv => MediaKind::VideoNote,
            Self::Audio if ptt => MediaKind::PushToTalk,
            Self::Audio => MediaKind::Audio,
            Self::Ptt => MediaKind::PushToTalk,
            Self::Document => MediaKind::Document,
            Self::Sticker => MediaKind::Sticker,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Image => "image",
            Self::Video => "video",
            Self::Gif => "gif",
            Self::Ptv => "ptv",
            Self::Audio => "audio",
            Self::Ptt => "ptt",
            Self::Document => "document",
            Self::Sticker => "sticker",
        }
    }
}

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

fn u32_env(name: &str) -> Result<Option<u32>, Box<dyn Error>> {
    optional_env(name)
        .map(|value| value.parse())
        .transpose()
        .map_err(Into::into)
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    let kind = DirectMediaKind::from_env()?;
    let Some(target_jid) = optional_env("WA_TARGET_JID") else {
        println!("set WA_TARGET_JID to send media");
        return Ok(());
    };
    let Some(media_path) = optional_env("WA_MEDIA_PATH") else {
        println!("set WA_MEDIA_PATH to a media file");
        return Ok(());
    };
    let media_path = PathBuf::from(media_path);

    let plaintext = fs::read(&media_path)?;
    let mimetype =
        optional_env("WA_MEDIA_MIMETYPE").unwrap_or_else(|| kind.default_mimetype().to_owned());
    let audio_ptt = bool_env("WA_MEDIA_AUDIO_PTT", false);
    let view_once = bool_env("WA_MEDIA_VIEW_ONCE", false);
    if view_once && !matches!(kind, DirectMediaKind::Image | DirectMediaKind::Video) {
        return Err("WA_MEDIA_VIEW_ONCE is supported for image or video media".into());
    }

    let store = SqliteAuthStore::open(session_db_path()).await?;
    let client = Client::builder(store).connect().await?;
    let validated = client.connect_websocket().await?;

    let media_connection = client
        .fetch_media_connection_info(validated.connection())
        .await?;
    let transfer = MediaTransfer::new(HttpMediaTransport::new(media_connection));
    let uploaded = client
        .upload_media_bytes(&transfer, &plaintext, kind.upload_kind(audio_ptt))
        .await?;

    let relay = match kind {
        DirectMediaKind::Image => {
            let mut image = ImageContent::new(uploaded, mimetype);
            image.caption = optional_env("WA_MEDIA_CAPTION");
            if view_once {
                client
                    .send_view_once_image_with_signal_provider(
                        validated.connection(),
                        &target_jid,
                        image,
                        MessageRelayOptions::new(),
                    )
                    .await?
            } else {
                client
                    .send_image_with_signal_provider(
                        validated.connection(),
                        &target_jid,
                        image,
                        MessageRelayOptions::new(),
                    )
                    .await?
            }
        }
        DirectMediaKind::Video => {
            let mut video = VideoContent::new(uploaded, mimetype);
            video.caption = optional_env("WA_MEDIA_CAPTION");
            video.seconds = u32_env("WA_MEDIA_VIDEO_SECONDS")?;
            video.height = u32_env("WA_MEDIA_VIDEO_HEIGHT")?;
            video.width = u32_env("WA_MEDIA_VIDEO_WIDTH")?;
            if view_once {
                client
                    .send_view_once_video_with_signal_provider(
                        validated.connection(),
                        &target_jid,
                        video,
                        MessageRelayOptions::new(),
                    )
                    .await?
            } else {
                client
                    .send_video_with_signal_provider(
                        validated.connection(),
                        &target_jid,
                        video,
                        MessageRelayOptions::new(),
                    )
                    .await?
            }
        }
        DirectMediaKind::Gif => {
            let mut gif = VideoContent::new(uploaded, mimetype);
            gif.caption = optional_env("WA_MEDIA_CAPTION");
            gif.seconds = u32_env("WA_MEDIA_GIF_SECONDS")?;
            gif.height = u32_env("WA_MEDIA_GIF_HEIGHT")?;
            gif.width = u32_env("WA_MEDIA_GIF_WIDTH")?;
            client
                .send_gif_with_signal_provider(
                    validated.connection(),
                    &target_jid,
                    gif,
                    MessageRelayOptions::new(),
                )
                .await?
        }
        DirectMediaKind::Ptv => {
            let mut ptv = VideoContent::new(uploaded, mimetype);
            ptv.seconds = u32_env("WA_MEDIA_PTV_SECONDS")?;
            ptv.height = u32_env("WA_MEDIA_PTV_HEIGHT")?;
            ptv.width = u32_env("WA_MEDIA_PTV_WIDTH")?;
            client
                .send_ptv_with_signal_provider(
                    validated.connection(),
                    &target_jid,
                    ptv,
                    MessageRelayOptions::new(),
                )
                .await?
        }
        DirectMediaKind::Audio => {
            let mut audio = AudioContent::new(uploaded, mimetype);
            audio.ptt = audio_ptt;
            audio.seconds = u32_env("WA_MEDIA_AUDIO_SECONDS")?;
            client
                .send_audio_with_signal_provider(
                    validated.connection(),
                    &target_jid,
                    audio,
                    MessageRelayOptions::new(),
                )
                .await?
        }
        DirectMediaKind::Ptt => {
            let mut ptt = AudioContent::new(uploaded, mimetype);
            ptt.seconds = u32_env("WA_MEDIA_PTT_SECONDS")?;
            client
                .send_ptt_with_signal_provider(
                    validated.connection(),
                    &target_jid,
                    ptt,
                    MessageRelayOptions::new(),
                )
                .await?
        }
        DirectMediaKind::Document => {
            let mut document = DocumentContent::new(uploaded, mimetype);
            document.caption = optional_env("WA_MEDIA_CAPTION");
            document.title = optional_env("WA_MEDIA_DOCUMENT_TITLE");
            document.file_name = optional_env("WA_MEDIA_DOCUMENT_FILE_NAME").or_else(|| {
                media_path
                    .file_name()
                    .map(|name| name.to_string_lossy().into_owned())
            });
            document.page_count = u32_env("WA_MEDIA_DOCUMENT_PAGE_COUNT")?;
            client
                .send_document_with_signal_provider(
                    validated.connection(),
                    &target_jid,
                    document,
                    MessageRelayOptions::new(),
                )
                .await?
        }
        DirectMediaKind::Sticker => {
            let mut sticker = StickerContent::new(uploaded, mimetype);
            sticker.height = u32_env("WA_MEDIA_STICKER_HEIGHT")?;
            sticker.width = u32_env("WA_MEDIA_STICKER_WIDTH")?;
            sticker.is_animated = bool_env("WA_MEDIA_STICKER_ANIMATED", false);
            client
                .send_sticker_with_signal_provider(
                    validated.connection(),
                    &target_jid,
                    sticker,
                    MessageRelayOptions::new(),
                )
                .await?
        }
    };
    let view_once_label = if view_once { " view-once" } else { "" };
    println!(
        "sent{view_once_label} {} media message {}",
        kind.label(),
        relay.message_id
    );

    Ok(())
}
