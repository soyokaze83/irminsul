use std::{env, error::Error, path::PathBuf, time::Duration};
use tokio::time::timeout;
use wa_client::prelude::*;

#[derive(Default)]
struct HistorySyncSummary {
    syncs: usize,
    chats: usize,
    contacts: usize,
    messages: usize,
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

fn duration_env(name: &str, default_secs: u64) -> Result<Duration, Box<dyn Error>> {
    let secs = optional_env(name)
        .map(|value| value.parse())
        .transpose()?
        .unwrap_or(default_secs);
    Ok(Duration::from_secs(secs))
}

fn summarize_history_sync(processed: &[ProcessedHistorySync]) -> HistorySyncSummary {
    let mut summary = HistorySyncSummary {
        syncs: processed.len(),
        ..HistorySyncSummary::default()
    };
    for item in processed {
        if let Some(history) = &item.batch.history {
            summary.chats += history.chats.len();
            summary.contacts += history.contacts.len();
            summary.messages += history.messages.len();
        }
    }
    summary
}

async fn wait_for_history_sync(
    client: &Client<SqliteAuthStore>,
    transfer: &MediaTransfer<HttpMediaTransport>,
    events: &mut tokio::sync::broadcast::Receiver<Event>,
    history_timeout: Duration,
    fallback_host: Option<&str>,
    process_config: HistorySyncProcessConfig,
) -> Result<HistorySyncSummary, Box<dyn Error>> {
    let wait = async {
        loop {
            let event = events.recv().await?;
            match &event {
                Event::MessagesUpsert(_) | Event::Batch(_) => {
                    let processed = client
                        .download_process_and_emit_history_sync_events(
                            transfer,
                            std::slice::from_ref(&event),
                            fallback_host,
                            HistorySyncDecodeConfig::default(),
                            process_config,
                        )
                        .await?;
                    if !processed.is_empty() {
                        return Ok(summarize_history_sync(&processed));
                    }
                }
                Event::ConnectionUpdate(ConnectionState::Closed) => {
                    return Err::<HistorySyncSummary, Box<dyn Error>>(
                        "connection closed before a history sync notification arrived".into(),
                    );
                }
                _ => {}
            }
        }
    };

    timeout(history_timeout, wait).await.map_err(|_| {
        format!(
            "timed out after {}s waiting for a history sync notification",
            history_timeout.as_secs()
        )
    })?
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    if !bool_env("WA_HISTORY_SYNC", false) {
        println!("set WA_HISTORY_SYNC=1 to open the websocket and process history sync events");
        return Ok(());
    }

    let history_timeout = duration_env("WA_HISTORY_SYNC_TIMEOUT_SECS", 180)?;
    let fallback_host = optional_env("WA_HISTORY_SYNC_FALLBACK_HOST");
    let process_config =
        HistorySyncProcessConfig::default().latest(bool_env("WA_HISTORY_SYNC_LATEST", true));

    let store = SqliteAuthStore::open(session_db_path()).await?;
    let client = Client::builder(store).connect().await?;
    let mut events = client.subscribe();
    let validated = client.connect_websocket().await?;
    let connection = validated.into_connection();
    let media_connection = client.fetch_media_connection_info(&connection).await?;
    let transfer = MediaTransfer::new(HttpMediaTransport::new(media_connection));
    let mut processor = client
        .spawn_incoming_processor_with_signal_provider(connection, EventBufferConfig::default())?;

    println!(
        "waiting up to {}s for history sync notifications",
        history_timeout.as_secs()
    );
    let summary = wait_for_history_sync(
        &client,
        &transfer,
        &mut events,
        history_timeout,
        fallback_host.as_deref(),
        process_config,
    )
    .await;
    processor.abort();

    let summary = summary?;
    println!(
        "processed {} history sync(s), {} chat(s), {} contact(s), {} message(s)",
        summary.syncs, summary.chats, summary.contacts, summary.messages
    );
    Ok(())
}
