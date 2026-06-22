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
    let Some(order_id) = optional_env("WA_BUSINESS_ORDER_ID") else {
        println!("set WA_BUSINESS_ORDER_ID to fetch business order details");
        return Ok(());
    };
    let Some(token) = optional_env("WA_BUSINESS_ORDER_TOKEN") else {
        println!("set WA_BUSINESS_ORDER_TOKEN to fetch business order details");
        return Ok(());
    };

    let store = SqliteAuthStore::open(session_db_path()).await?;
    let client = Client::builder(store).connect().await?;
    let validated = client.connect_websocket().await?;

    let details = client
        .fetch_business_order_details(validated.connection(), &order_id, &token)
        .await?;

    println!(
        "business order {} total={} {} products={}",
        order_id,
        details.price.total,
        details.price.currency,
        details.products.len()
    );

    Ok(())
}
