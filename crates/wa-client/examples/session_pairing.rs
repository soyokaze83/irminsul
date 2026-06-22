use std::{env, error::Error, path::PathBuf};
use wa_client::prelude::*;

fn session_db_path() -> PathBuf {
    env::var_os("WA_SESSION_DB")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(".wa/session.sqlite"))
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    let store = SqliteAuthStore::open(session_db_path()).await?;
    let mut client = Client::builder(store).connect().await?;
    let mut events = client.subscribe();

    let reference =
        env::var("WA_QR_REFERENCE").unwrap_or_else(|_| "reference-from-server".to_owned());
    let qr_payload = client.pairing_qr_data(&reference);
    println!("pairing QR payload: {qr_payload}");

    match env::var("WA_PHONE_NUMBER") {
        Ok(phone_number) => {
            let pairing = client
                .prepare_pairing_code_request(&phone_number, None)
                .await?;
            println!(
                "prepared pairing code {} for {}",
                pairing.pairing_code, pairing.account_jid
            );
            println!("pairing request node id: {}", pairing.node.attrs["id"]);
        }
        Err(_) => {
            println!("set WA_PHONE_NUMBER to prepare a pairing-code request");
        }
    }

    while let Ok(event) = events.try_recv() {
        println!("event: {event:?}");
    }

    Ok(())
}
