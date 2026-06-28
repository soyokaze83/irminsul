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

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    if bool_env("WA_BUSINESS_COVER_PHOTO_REMOVE", false) {
        let Some(id) = optional_env("WA_BUSINESS_COVER_PHOTO_ID") else {
            println!("set WA_BUSINESS_COVER_PHOTO_ID to remove the business cover photo");
            return Ok(());
        };

        let store = SqliteAuthStore::open(session_db_path()).await?;
        let client = Client::builder(store).connect().await?;
        let validated = client.connect_websocket().await?;
        client
            .remove_business_cover_photo(validated.connection(), &id)
            .await?;
        println!("removed business cover photo {id}");
        return Ok(());
    }

    if !bool_env("WA_BUSINESS_COVER_PHOTO_UPDATE", false) {
        println!(
            "set WA_BUSINESS_COVER_PHOTO_UPDATE=1 to update or WA_BUSINESS_COVER_PHOTO_REMOVE=1 to remove the business cover photo"
        );
        return Ok(());
    }

    #[cfg(not(feature = "http-media"))]
    {
        println!("enable the http-media feature to update the business cover photo");
        return Ok(());
    }

    #[cfg(feature = "http-media")]
    {
        let Some(image_path) = optional_env("WA_BUSINESS_COVER_PHOTO_PATH") else {
            println!("set WA_BUSINESS_COVER_PHOTO_PATH to update the business cover photo");
            return Ok(());
        };
        let image_path = PathBuf::from(image_path);

        let store = SqliteAuthStore::open(session_db_path()).await?;
        let client = Client::builder(store).connect().await?;
        let validated = client.connect_websocket().await?;

        let media_connection = client
            .fetch_media_connection_info(validated.connection())
            .await?;
        let transfer = MediaTransfer::new(HttpMediaTransport::new(media_connection));
        let upload = client
            .upload_business_cover_photo_file(&transfer, &image_path)
            .await?;
        let id = client
            .update_business_cover_photo(validated.connection(), upload)
            .await?;

        println!("updated business cover photo {id}");
        Ok(())
    }
}
