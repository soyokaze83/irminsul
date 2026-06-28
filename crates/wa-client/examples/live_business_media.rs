use std::{env, error::Error, path::PathBuf};
use wa_client::prelude::*;

#[derive(Clone, Copy)]
enum BusinessMediaKind {
    ProductImage,
    CoverPhoto,
}

impl BusinessMediaKind {
    fn from_env() -> Result<Self, Box<dyn Error>> {
        let value =
            optional_env("WA_BUSINESS_MEDIA_KIND").unwrap_or_else(|| "product_image".to_owned());
        match value.to_ascii_lowercase().as_str() {
            "product_image" | "product-image" | "product" => Ok(Self::ProductImage),
            "cover_photo" | "cover-photo" | "cover" => Ok(Self::CoverPhoto),
            other => Err(format!(
                "unsupported WA_BUSINESS_MEDIA_KIND={other}; use product_image or cover_photo"
            )
            .into()),
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

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    let kind = BusinessMediaKind::from_env()?;
    let Some(media_path) = optional_env("WA_BUSINESS_MEDIA_PATH") else {
        println!("set WA_BUSINESS_MEDIA_PATH to upload business media");
        return Ok(());
    };
    let media_path = PathBuf::from(media_path);

    let store = SqliteAuthStore::open(session_db_path()).await?;
    let client = Client::builder(store).connect().await?;
    let validated = client.connect_websocket().await?;

    let media_connection = client
        .fetch_media_connection_info(validated.connection())
        .await?;
    let transfer = MediaTransfer::new(HttpMediaTransport::new(media_connection));

    match kind {
        BusinessMediaKind::ProductImage => {
            let fallback_host = optional_env("WA_BUSINESS_MEDIA_FALLBACK_HOST");
            let image = client
                .upload_business_product_image_file(
                    &transfer,
                    &media_path,
                    fallback_host.as_deref(),
                )
                .await?;
            println!("uploaded business product image {}", image.url);
        }
        BusinessMediaKind::CoverPhoto => {
            let upload = client
                .upload_business_cover_photo_file(&transfer, &media_path)
                .await?;
            println!(
                "uploaded business cover photo id={} token_len={} timestamp={}",
                upload.id,
                upload.token.len(),
                upload.timestamp
            );
        }
    }

    Ok(())
}
