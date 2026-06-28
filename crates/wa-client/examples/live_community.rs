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

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    let community_jid = optional_env("WA_COMMUNITY_JID");
    let invite_code = optional_env("WA_COMMUNITY_INVITE_CODE");
    if community_jid.is_none()
        && invite_code.is_none()
        && !bool_env("WA_COMMUNITY_FETCH_PARTICIPATING", false)
    {
        println!(
            "set WA_COMMUNITY_JID, WA_COMMUNITY_INVITE_CODE, or WA_COMMUNITY_FETCH_PARTICIPATING=1"
        );
        return Ok(());
    }

    let store = SqliteAuthStore::open(session_db_path()).await?;
    let client = Client::builder(store).connect().await?;
    let validated = client.connect_websocket().await?;

    if let Some(community_jid) = community_jid.as_deref() {
        let metadata = client
            .fetch_community_metadata(validated.connection(), community_jid)
            .await?;
        println!(
            "community {} subject={} participants={} is_community={} linked_parent={}",
            metadata.jid,
            metadata.subject.as_deref().unwrap_or("<none>"),
            metadata.participants.len(),
            metadata.is_community,
            metadata.linked_parent.as_deref().unwrap_or("<none>")
        );

        if bool_env("WA_COMMUNITY_FETCH_LINKED_GROUPS", false) {
            let groups = client
                .fetch_community_linked_groups(validated.connection(), community_jid)
                .await?;
            println!("community {community_jid} linked_groups={}", groups.len());
        }

        if bool_env("WA_COMMUNITY_RESOLVE_LINKED_GROUPS", false) {
            let groups = client
                .fetch_community_linked_groups_resolved(validated.connection(), community_jid)
                .await?;
            println!(
                "community {} resolved_from_is_community={} linked_groups={}",
                groups.community_jid,
                groups.is_community,
                groups.linked_groups.len()
            );
        }

        if bool_env("WA_COMMUNITY_FETCH_JOIN_REQUESTS", false) {
            let requests = client
                .fetch_community_join_requests(validated.connection(), community_jid)
                .await?;
            println!("community {community_jid} join_requests={}", requests.len());
        }
    }

    if bool_env("WA_COMMUNITY_FETCH_PARTICIPATING", false) {
        let communities = client
            .fetch_participating_communities(validated.connection())
            .await?;
        println!("participating_communities={}", communities.len());
    }

    if let Some(invite_code) = invite_code.as_deref() {
        let metadata = client
            .fetch_community_invite_info(validated.connection(), invite_code)
            .await?;
        println!(
            "community invite {} subject={} participants={}",
            metadata.jid,
            metadata.subject.as_deref().unwrap_or("<none>"),
            metadata.participants.len()
        );
    }

    Ok(())
}
