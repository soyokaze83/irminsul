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

fn profile_picture_options() -> Result<ProfilePictureOptions, Box<dyn Error>> {
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

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    let Some(image_path) = optional_env("WA_PROFILE_PICTURE_PATH") else {
        println!("set WA_PROFILE_PICTURE_PATH to update the profile picture");
        return Ok(());
    };
    let target_jid = optional_env("WA_PROFILE_PICTURE_TARGET_JID");
    let image = fs::read(image_path)?;

    let store = SqliteAuthStore::open(session_db_path()).await?;
    let client = Client::builder(store).connect().await?;
    let validated = client.connect_websocket().await?;
    let generated = client
        .update_profile_picture_from_image(
            validated.connection(),
            target_jid.as_deref(),
            &image,
            profile_picture_options()?,
        )
        .await?;

    println!(
        "updated profile picture from {}x{} source to {}x{} image with {}x{} preview",
        generated.source_width,
        generated.source_height,
        generated.image_size,
        generated.image_size,
        generated.preview_size,
        generated.preview_size
    );

    Ok(())
}
