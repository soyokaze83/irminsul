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

fn csv_jids(name: &str) -> Vec<String> {
    optional_env(name)
        .map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|jid| !jid.is_empty())
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    let Some(group_jid) = optional_env("WA_GROUP_JID") else {
        println!("set WA_GROUP_JID to inspect or update a group");
        return Ok(());
    };

    let store = SqliteAuthStore::open(session_db_path()).await?;
    let client = Client::builder(store).connect().await?;
    let validated = client.connect_websocket().await?;

    let metadata = client
        .fetch_group_metadata(validated.connection(), &group_jid)
        .await?;
    println!(
        "group {} has {} participants",
        metadata.subject.as_deref().unwrap_or("<no subject>"),
        metadata.participants.len()
    );

    if let Some(subject) = optional_env("WA_GROUP_SUBJECT") {
        client
            .set_group_subject(validated.connection(), &group_jid, &subject)
            .await?;
        println!("updated group subject");
    }

    let add_jids = csv_jids("WA_GROUP_ADD_JIDS");
    if !add_jids.is_empty() {
        let result = client
            .update_group_participants(
                validated.connection(),
                &group_jid,
                GroupParticipantAction::Add,
                add_jids.iter().map(String::as_str),
            )
            .await?;
        println!("participant updates: {}", result.participants.len());
    }

    Ok(())
}
