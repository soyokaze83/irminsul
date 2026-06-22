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

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    let Some(target_jid) = optional_env("WA_TARGET_JID") else {
        println!("set WA_TARGET_JID to send a generated link preview");
        return Ok(());
    };
    let Some(url) = optional_env("WA_LINK_PREVIEW_URL") else {
        println!("set WA_LINK_PREVIEW_URL to the URL matched by the preview");
        return Ok(());
    };
    let Some(image_path) = optional_env("WA_LINK_PREVIEW_IMAGE_PATH") else {
        println!("set WA_LINK_PREVIEW_IMAGE_PATH to a local preview image");
        return Ok(());
    };

    let title = optional_env("WA_LINK_PREVIEW_TITLE").unwrap_or_else(|| "Link preview".to_owned());
    let text = optional_env("WA_LINK_PREVIEW_TEXT").unwrap_or_else(|| url.clone());
    let image = fs::read(image_path)?;

    let store = SqliteAuthStore::open(session_db_path()).await?;
    let client = Client::builder(store).connect().await?;
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
    println!("sent generated link preview message {}", relay.message_id);

    Ok(())
}
