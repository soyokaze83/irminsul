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

fn u32_env(name: &str) -> Result<Option<u32>, Box<dyn Error>> {
    optional_env(name)
        .map(|value| value.parse())
        .transpose()
        .map_err(Into::into)
}

fn collections_query_from_env(jid: &str) -> Result<BusinessCollectionsQuery, Box<dyn Error>> {
    let mut query = BusinessCollectionsQuery::new(jid)?;
    if let Some(limit) = u32_env("WA_BUSINESS_COLLECTION_LIMIT")? {
        query = query.with_collection_limit(limit)?;
    }
    if let Some(limit) = u32_env("WA_BUSINESS_COLLECTION_ITEM_LIMIT")? {
        query = query.with_item_limit(limit)?;
    }
    Ok(query)
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    let Some(business_jid) = optional_env("WA_BUSINESS_COLLECTIONS_JID") else {
        println!("set WA_BUSINESS_COLLECTIONS_JID to fetch business collections");
        return Ok(());
    };

    let store = SqliteAuthStore::open(session_db_path()).await?;
    let client = Client::builder(store).connect().await?;
    let validated = client.connect_websocket().await?;

    let collections = client
        .fetch_business_collections(
            validated.connection(),
            collections_query_from_env(&business_jid)?,
        )
        .await?;

    let product_count: usize = collections
        .iter()
        .map(|collection| collection.products.len())
        .sum();
    println!(
        "business collections {} collections={} products={}",
        business_jid,
        collections.len(),
        product_count
    );

    Ok(())
}
