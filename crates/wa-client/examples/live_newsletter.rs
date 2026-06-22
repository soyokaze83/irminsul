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

fn u32_env(name: &str) -> Result<Option<u32>, Box<dyn Error>> {
    optional_env(name)
        .map(|value| value.parse())
        .transpose()
        .map_err(Into::into)
}

fn u64_env(name: &str) -> Result<Option<u64>, Box<dyn Error>> {
    optional_env(name)
        .map(|value| value.parse())
        .transpose()
        .map_err(Into::into)
}

fn newsletter_lookup_from_env() -> Option<(NewsletterMetadataLookup, Option<String>)> {
    if let Some(jid) = optional_env("WA_NEWSLETTER_JID") {
        return Some((NewsletterMetadataLookup::jid(jid.clone()), Some(jid)));
    }
    optional_env("WA_NEWSLETTER_INVITE")
        .map(|invite| (NewsletterMetadataLookup::invite(invite), None))
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    let Some((lookup, explicit_jid)) = newsletter_lookup_from_env() else {
        println!("set WA_NEWSLETTER_JID or WA_NEWSLETTER_INVITE to fetch newsletter metadata");
        return Ok(());
    };

    let store = SqliteAuthStore::open(session_db_path()).await?;
    let client = Client::builder(store).connect().await?;
    let validated = client.connect_websocket().await?;

    let metadata = client
        .fetch_newsletter_metadata(validated.connection(), lookup)
        .await?;
    let Some(metadata) = metadata else {
        println!("newsletter metadata not found");
        return Ok(());
    };

    println!(
        "newsletter {} name={} subscribers={}",
        metadata.id,
        metadata.name.as_deref().unwrap_or("<none>"),
        metadata
            .subscribers
            .map(|subscribers| subscribers.to_string())
            .unwrap_or_else(|| "<unknown>".to_owned())
    );

    let newsletter_jid = explicit_jid.as_deref().unwrap_or(&metadata.id);

    if bool_env("WA_NEWSLETTER_FETCH_COUNTS", false) {
        let subscribers = client
            .fetch_newsletter_subscriber_count(validated.connection(), newsletter_jid)
            .await?;
        let admins = client
            .fetch_newsletter_admin_count(validated.connection(), newsletter_jid)
            .await?;
        println!("newsletter {newsletter_jid} subscriber_count={subscribers} admin_count={admins}");
    }

    if bool_env("WA_NEWSLETTER_FETCH_MESSAGES", false) {
        let count = u32_env("WA_NEWSLETTER_MESSAGE_COUNT")?.unwrap_or(10);
        let since = u64_env("WA_NEWSLETTER_MESSAGE_SINCE")?;
        let after = u64_env("WA_NEWSLETTER_MESSAGE_AFTER")?;
        let messages = client
            .fetch_newsletter_messages(validated.connection(), newsletter_jid, count, since, after)
            .await?;
        println!(
            "newsletter {newsletter_jid} fetched_messages={}",
            messages.len()
        );
    }

    if bool_env("WA_NEWSLETTER_LIVE_UPDATES", false) {
        let subscription = client
            .subscribe_newsletter_live_updates(validated.connection(), newsletter_jid)
            .await?;
        println!(
            "newsletter {newsletter_jid} live_update_duration={}",
            subscription
                .as_ref()
                .map(|subscription| subscription.duration.as_str())
                .unwrap_or("<none>")
        );
    }

    Ok(())
}
