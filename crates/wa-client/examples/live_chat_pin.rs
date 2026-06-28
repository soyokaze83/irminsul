use std::{
    env,
    error::Error,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};
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

fn current_timestamp_ms() -> Result<u64, Box<dyn Error>> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_millis()
        .try_into()?;
    Ok(millis)
}

fn action_timestamp_ms() -> Result<u64, Box<dyn Error>> {
    optional_env("WA_CHAT_PIN_TIMESTAMP_MS")
        .map(|value| value.parse())
        .transpose()?
        .map_or_else(current_timestamp_ms, Ok)
}

async fn app_state_key_data(
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

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    let Some(chat_jid) = optional_env("WA_CHAT_PIN_JID") else {
        println!("set WA_CHAT_PIN_JID to pin or unpin a chat");
        return Ok(());
    };
    let Some(key_id) = hex_env("WA_APP_STATE_KEY_ID_HEX")? else {
        println!("set WA_APP_STATE_KEY_ID_HEX to the app-state sync key id");
        return Ok(());
    };
    let pinned = bool_env("WA_CHAT_PINNED", true);
    let action_timestamp_ms = action_timestamp_ms()?;

    let store = SqliteAuthStore::open(session_db_path()).await?;
    let client = Client::builder(store).connect().await?;
    let key_data = app_state_key_data(&client, &key_id).await?;
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
            action_timestamp_ms,
            upload,
        )
        .await?;

    println!(
        "{} chat {}, app-state regular_low version {} -> {}",
        if pinned { "pinned" } else { "unpinned" },
        chat_jid,
        outcome.bundle.previous_version,
        outcome.bundle.next_state.version()
    );
    println!(
        "local event batch pending items: {}",
        outcome.batch.pending_items()
    );
    Ok(())
}
