use std::{env, error::Error, fs, path::PathBuf};
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

fn thumbnail_options() -> VideoThumbnailOptions {
    let mut options = VideoThumbnailOptions::default();
    if let Some(ffmpeg_path) = optional_env("WA_VIDEO_THUMBNAIL_FFMPEG") {
        options.ffmpeg_path = PathBuf::from(ffmpeg_path);
    }
    if let Some(seek_time) = optional_env("WA_VIDEO_THUMBNAIL_SEEK_TIME") {
        options.seek_time = seek_time;
    }
    options
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    let Some(target_jid) = optional_env("WA_TARGET_JID") else {
        println!("set WA_TARGET_JID to send a video with a generated remote thumbnail");
        return Ok(());
    };
    let Some(video_path) = optional_env("WA_VIDEO_PATH") else {
        println!("set WA_VIDEO_PATH to a local video file");
        return Ok(());
    };
    let video_path = PathBuf::from(video_path);
    let mimetype = optional_env("WA_VIDEO_MIMETYPE").unwrap_or_else(|| "video/mp4".to_owned());

    let plaintext = fs::read(&video_path)?;
    let store = SqliteAuthStore::open(session_db_path()).await?;
    let client = Client::builder(store).connect().await?;
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
            thumbnail_options(),
        )
        .await?;

    let mut video =
        VideoContent::new(uploaded, mimetype).with_remote_thumbnail(thumbnail.remote_thumbnail);
    video.caption = optional_env("WA_VIDEO_CAPTION");

    let relay = client
        .send_message_with_signal_provider(
            validated.connection(),
            &target_jid,
            MessageContent::video(video),
            MessageRelayOptions::new(),
        )
        .await?;
    println!("sent video message {}", relay.message_id);

    Ok(())
}
