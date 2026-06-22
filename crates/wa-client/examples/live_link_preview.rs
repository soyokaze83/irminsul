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

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    let Some(target_jid) = optional_env("WA_TARGET_JID") else {
        println!("set WA_TARGET_JID to send a link preview");
        return Ok(());
    };
    let Some(url) = optional_env("WA_LINK_PREVIEW_URL") else {
        println!("set WA_LINK_PREVIEW_URL to a page with preview image metadata");
        return Ok(());
    };
    let text = optional_env("WA_LINK_PREVIEW_TEXT").unwrap_or_else(|| url.clone());

    let store = SqliteAuthStore::open(session_db_path()).await?;
    let client = Client::builder(store).connect().await?;
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
    let message = TextMessage::new(text).with_link_preview(fetched.preview.content);
    let relay = client
        .send_message_with_signal_provider(
            validated.connection(),
            &target_jid,
            MessageContent::text_message(message),
            MessageRelayOptions::new(),
        )
        .await?;
    println!("sent link preview message {}", relay.message_id);

    Ok(())
}
