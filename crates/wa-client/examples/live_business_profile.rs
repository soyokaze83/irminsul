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
    let Some(business_jid) = optional_env("WA_BUSINESS_JID") else {
        println!("set WA_BUSINESS_JID to fetch a business profile");
        return Ok(());
    };

    let store = SqliteAuthStore::open(session_db_path()).await?;
    let client = Client::builder(store).connect().await?;
    let validated = client.connect_websocket().await?;

    let profile = client
        .fetch_business_profile(validated.connection(), &business_jid)
        .await?;

    match profile {
        Some(profile) => {
            println!(
                "business profile {} description_len={} websites={}",
                profile.jid.as_deref().unwrap_or(&business_jid),
                profile.description.len(),
                profile.websites.len()
            );
        }
        None => {
            println!("no business profile returned for {business_jid}");
        }
    }

    Ok(())
}
