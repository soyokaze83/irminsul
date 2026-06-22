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
    let Some(group_jid) = optional_env("WA_GROUP_SEND_JID") else {
        println!("set WA_GROUP_SEND_JID to send a group sender-key text message");
        return Ok(());
    };
    let text = optional_env("WA_GROUP_TEXT").unwrap_or_else(|| "hello from wa-client".to_owned());

    let store = SqliteAuthStore::open(session_db_path()).await?;
    let client = Client::builder(store).connect().await?;
    let validated = client.connect_websocket().await?;

    let relay = client
        .send_group_sender_key_text_with_signal_provider(
            validated.connection(),
            &group_jid,
            text,
            MessageRelayOptions::new(),
            MessageRelayOptions::new(),
        )
        .await?;
    println!(
        "sent group message {} after distribution {} to {} recipient devices",
        relay.message.message_id, relay.distribution.message_id, relay.distribution.recipient_count
    );

    Ok(())
}
