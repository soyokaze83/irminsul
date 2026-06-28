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

fn catalog_query_from_env(jid: &str) -> Result<BusinessCatalogQuery, Box<dyn Error>> {
    let mut query = BusinessCatalogQuery::new(jid)?;
    if let Some(limit) = u32_env("WA_BUSINESS_CATALOG_LIMIT")? {
        query = query.with_limit(limit)?;
    }
    if let Some(cursor) = optional_env("WA_BUSINESS_CATALOG_CURSOR") {
        query = query.with_cursor(cursor)?;
    }
    Ok(query)
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    let Some(business_jid) = optional_env("WA_BUSINESS_CATALOG_JID") else {
        println!("set WA_BUSINESS_CATALOG_JID to fetch a business catalog");
        return Ok(());
    };

    let store = SqliteAuthStore::open(session_db_path()).await?;
    let client = Client::builder(store).connect().await?;
    let validated = client.connect_websocket().await?;

    let catalog = client
        .fetch_business_catalog(
            validated.connection(),
            catalog_query_from_env(&business_jid)?,
        )
        .await?;

    println!(
        "business catalog {} products={} next_cursor={}",
        business_jid,
        catalog.products.len(),
        catalog.next_page_cursor.as_deref().unwrap_or("<none>")
    );

    Ok(())
}
