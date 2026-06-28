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

fn csv_env(name: &str) -> Vec<String> {
    optional_env(name)
        .map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn profile_update_from_env() -> BusinessProfileUpdate {
    let mut update = BusinessProfileUpdate::new();
    if let Some(address) = optional_env("WA_BUSINESS_PROFILE_ADDRESS") {
        update = update.with_address(address);
    }
    if let Some(email) = optional_env("WA_BUSINESS_PROFILE_EMAIL") {
        update = update.with_email(email);
    }
    if let Some(description) = optional_env("WA_BUSINESS_PROFILE_DESCRIPTION") {
        update = update.with_description(description);
    }
    let websites = csv_env("WA_BUSINESS_PROFILE_WEBSITES");
    if !websites.is_empty() {
        update = update.with_websites(websites);
    }
    update
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    if !bool_env("WA_BUSINESS_PROFILE_UPDATE", false) {
        println!("set WA_BUSINESS_PROFILE_UPDATE=1 to mutate the business profile");
        return Ok(());
    }
    let update = profile_update_from_env();
    if update.is_empty() {
        println!(
            "set at least one of WA_BUSINESS_PROFILE_ADDRESS, WA_BUSINESS_PROFILE_EMAIL, WA_BUSINESS_PROFILE_DESCRIPTION, or WA_BUSINESS_PROFILE_WEBSITES"
        );
        return Ok(());
    }

    let store = SqliteAuthStore::open(session_db_path()).await?;
    let client = Client::builder(store).connect().await?;
    let validated = client.connect_websocket().await?;

    client
        .update_business_profile(validated.connection(), update)
        .await?;
    println!("updated business profile");

    Ok(())
}
