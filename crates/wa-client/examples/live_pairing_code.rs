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

fn duration_env(name: &str, default_secs: u64) -> Result<Duration, Box<dyn Error>> {
    let secs = optional_env(name)
        .map(|value| value.parse())
        .transpose()?
        .unwrap_or(default_secs);
    Ok(Duration::from_secs(secs))
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    let Some(phone_number) = optional_env("WA_PHONE_NUMBER") else {
        println!("set WA_PHONE_NUMBER to request a live pairing code");
        return Ok(());
    };
    let custom_pairing_code = optional_env("WA_PAIRING_CODE");
    let pairing_timeout = duration_env("WA_PAIRING_TIMEOUT_SECS", 180)?;

    let store = SqliteAuthStore::open(session_db_path()).await?;
    let mut client = Client::builder(store).connect().await?;
    if client.credentials().registered {
        println!("session is already registered; use a fresh WA_SESSION_DB for pairing");
        return Ok(());
    }

    let mut events = client.subscribe();
    let validated = client.connect_websocket().await?;
    let pairing = client
        .send_pairing_code_request(
            validated.connection(),
            &phone_number,
            custom_pairing_code.as_deref(),
        )
        .await?;

    println!("pairing code: {}", pairing.pairing_code);
    println!("account JID: {}", pairing.account_jid);
    println!("pairing request node id: {}", pairing.node.attrs["id"]);
    println!(
        "waiting up to {}s for pairing completion",
        pairing_timeout.as_secs()
    );

    let paired_jid = timeout(pairing_timeout, async {
        loop {
            match events.recv().await? {
                Event::RawNode(node)
                    if node.tag == "notification"
                        && node.attrs.get("type").map(String::as_str)
                            == Some("link_code_companion_reg") =>
                {
                    if let Some(finish) = client
                        .respond_to_link_code_companion_reg_notification(
                            validated.connection(),
                            &node,
                        )
                        .await?
                    {
                        return Ok::<String, Box<dyn Error>>(
                            finish
                                .credentials
                                .account_jid
                                .unwrap_or(pairing.account_jid),
                        );
                    }
                }
                Event::ConnectionUpdate(ConnectionState::Closed) => {
                    return Err::<String, Box<dyn Error>>(
                        "connection closed before pairing completed".into(),
                    );
                }
                _ => {}
            }
        }
    })
    .await
    .map_err(|_| {
        format!(
            "timed out after {}s waiting for pairing completion",
            pairing_timeout.as_secs()
        )
    })??;

    println!("pairing completed for {paired_jid}");
    Ok(())
}
