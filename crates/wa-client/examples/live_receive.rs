use std::{env, error::Error, path::PathBuf, time::Duration};
use tokio::time::timeout;
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

fn bool_env(name: &str) -> bool {
    optional_env(name)
        .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false)
}

fn duration_env(name: &str, default_secs: u64) -> Result<Duration, Box<dyn Error>> {
    let secs = optional_env(name)
        .map(|value| value.parse())
        .transpose()?
        .unwrap_or(default_secs);
    Ok(Duration::from_secs(secs))
}

fn matching_message_count(messages: &[MessageEvent], expected_remote_jid: Option<&str>) -> usize {
    messages
        .iter()
        .filter(|message| {
            expected_remote_jid.is_none_or(|remote_jid| message.key.remote_jid == remote_jid)
        })
        .count()
}

async fn wait_for_message_event(
    events: &mut tokio::sync::broadcast::Receiver<Event>,
    receive_timeout: Duration,
    expected_remote_jid: Option<&str>,
) -> Result<usize, Box<dyn Error>> {
    let wait = async {
        loop {
            match events.recv().await? {
                Event::MessagesUpsert(messages) => {
                    let count = matching_message_count(&messages, expected_remote_jid);
                    if count > 0 {
                        return Ok(count);
                    }
                }
                Event::Batch(batch) => {
                    let count = matching_message_count(&batch.messages_upsert, expected_remote_jid);
                    if count > 0 {
                        return Ok(count);
                    }
                }
                Event::ConnectionUpdate(ConnectionState::Closed) => {
                    return Err("connection closed before a message event arrived".into());
                }
                _ => {}
            }
        }
    };

    timeout(receive_timeout, wait).await.map_err(|_| {
        format!(
            "timed out after {}s waiting for a message event",
            receive_timeout.as_secs()
        )
    })?
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    if !bool_env("WA_RECEIVE") {
        println!("set WA_RECEIVE=1 to open the websocket and wait for inbound messages");
        return Ok(());
    }

    let receive_timeout = duration_env("WA_RECEIVE_TIMEOUT_SECS", 60)?;
    let expected_remote_jid = optional_env("WA_RECEIVE_REMOTE_JID");

    let store = SqliteAuthStore::open(session_db_path()).await?;
    let client = Client::builder(store).connect().await?;
    let mut events = client.subscribe();
    let validated = client.connect_websocket().await?;
    let mut processor = client.spawn_incoming_processor_with_signal_provider(
        validated.into_connection(),
        EventBufferConfig::default(),
    )?;

    println!(
        "waiting up to {}s for inbound message events",
        receive_timeout.as_secs()
    );
    let count =
        wait_for_message_event(&mut events, receive_timeout, expected_remote_jid.as_deref()).await;
    processor.abort();

    println!("received {} matching message event(s)", count?);
    Ok(())
}
