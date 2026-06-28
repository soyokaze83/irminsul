use std::{env, error::Error, path::PathBuf, time::Duration};

use bytes::Bytes;
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

fn bool_env(name: &str, default: bool) -> bool {
    optional_env(name)
        .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(default)
}

fn hex_env(name: &str) -> Result<Option<Vec<u8>>, Box<dyn Error>> {
    let Some(value) = optional_env(name) else {
        return Ok(None);
    };
    let value = value.replace([':', ' ', '-'], "");
    if value.len() % 2 != 0 {
        return Err(format!("{name} must contain an even number of hex characters").into());
    }
    let mut bytes = Vec::with_capacity(value.len() / 2);
    for chunk in value.as_bytes().chunks_exact(2) {
        let hex = std::str::from_utf8(chunk)?;
        bytes.push(u8::from_str_radix(hex, 16)?);
    }
    Ok(Some(bytes))
}

fn message_secret_env(name: &str, default_fill: u8) -> Result<Bytes, Box<dyn Error>> {
    let Some(bytes) = hex_env(name)? else {
        return Ok(Bytes::from(vec![default_fill; 32]));
    };
    if bytes.len() != 32 {
        return Err(format!("{name} must contain 64 hex characters").into());
    }
    Ok(Bytes::from(bytes))
}

fn current_timestamp_ms() -> Result<u64, Box<dyn Error>> {
    let millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_millis()
        .try_into()?;
    Ok(millis)
}

fn timestamp_ms_env(name: &str) -> Result<i64, Box<dyn Error>> {
    optional_env(name)
        .map(|value| value.parse())
        .transpose()?
        .map_or_else(
            || current_timestamp_ms().map(|timestamp_ms| timestamp_ms as i64),
            Ok,
        )
}

fn message_key_from_env(
    prefix: &str,
    default_remote_jid: &str,
    default_from_me: bool,
) -> Result<Option<MessageKey>, Box<dyn Error>> {
    let id_env = format!("WA_{prefix}_MESSAGE_ID");
    let Some(message_id) = optional_env(&id_env) else {
        return Ok(None);
    };
    let remote_jid_env = format!("WA_{prefix}_REMOTE_JID");
    let remote_jid = optional_env(&remote_jid_env).unwrap_or_else(|| default_remote_jid.to_owned());
    let from_me_env = format!("WA_{prefix}_FROM_ME");
    let participant_env = format!("WA_{prefix}_PARTICIPANT");
    Ok(Some(build_message_key(
        remote_jid,
        bool_env(&from_me_env, default_from_me),
        message_id,
        optional_env(&participant_env),
    )?))
}

fn contact_content() -> ContactContent {
    let display_name =
        optional_env("WA_CONTACT_DISPLAY_NAME").unwrap_or_else(|| "wa-client contact".to_owned());
    let vcard = optional_env("WA_CONTACT_VCARD")
        .unwrap_or_else(|| format!("BEGIN:VCARD\nVERSION:3.0\nFN:{display_name}\nEND:VCARD"));
    ContactContent::new(display_name, vcard)
}

fn location_content() -> Result<Option<LocationContent>, Box<dyn Error>> {
    let Some(latitude) = optional_env("WA_LOCATION_LATITUDE") else {
        return Ok(None);
    };
    let Some(longitude) = optional_env("WA_LOCATION_LONGITUDE") else {
        return Ok(None);
    };
    let mut location = LocationContent::new(latitude.parse()?, longitude.parse()?);
    if let Some(name) = optional_env("WA_LOCATION_NAME") {
        location = location.with_name(name);
    }
    if let Some(address) = optional_env("WA_LOCATION_ADDRESS") {
        location = location.with_address(address);
    }
    if let Some(url) = optional_env("WA_LOCATION_URL") {
        location = location.with_url(url);
    }
    Ok(Some(location))
}

fn poll_content() -> Result<PollContent, Box<dyn Error>> {
    let name = optional_env("WA_POLL_NAME").unwrap_or_else(|| "wa-client poll".to_owned());
    let options = {
        let configured = csv_env("WA_POLL_OPTIONS");
        if configured.is_empty() {
            vec!["Yes".to_owned(), "No".to_owned()]
        } else {
            configured
        }
    };
    let selectable_options_count = optional_env("WA_POLL_SELECTABLE_COUNT")
        .map(|value| value.parse())
        .transpose()?
        .unwrap_or(1);
    let message_secret = message_secret_env("WA_POLL_SECRET_HEX", 0x61)?;
    Ok(PollContent::new(
        name,
        options,
        selectable_options_count,
        message_secret,
    ))
}

fn event_content() -> Result<EventContent, Box<dyn Error>> {
    let name = optional_env("WA_EVENT_NAME").unwrap_or_else(|| "wa-client event".to_owned());
    let start_time = optional_env("WA_EVENT_START_UNIX")
        .map(|value| value.parse())
        .transpose()?
        .map_or_else(
            || current_timestamp_ms().map(|timestamp_ms| (timestamp_ms / 1000 + 3600) as i64),
            Ok,
        )?;
    let message_secret = message_secret_env("WA_EVENT_SECRET_HEX", 0x62)?;
    let mut event = EventContent::new(name, start_time, message_secret);
    event.description = optional_env("WA_EVENT_DESCRIPTION");
    event.end_time = optional_env("WA_EVENT_END_UNIX")
        .map(|value| value.parse())
        .transpose()?;
    if let Some(join_link) = optional_env("WA_EVENT_JOIN_LINK") {
        event = event.with_join_link(join_link);
    }
    Ok(event)
}

fn reaction_content(default_remote_jid: &str) -> Result<Option<ReactionContent>, Box<dyn Error>> {
    let Some(key) = message_key_from_env("REACTION", default_remote_jid, false)? else {
        return Ok(None);
    };
    let text = optional_env("WA_REACTION_TEXT").unwrap_or_else(|| "+".to_owned());
    Ok(Some(ReactionContent::new(key, text)))
}

fn edit_content(default_remote_jid: &str) -> Result<Option<EditContent>, Box<dyn Error>> {
    let Some(key) = message_key_from_env("EDIT", default_remote_jid, true)? else {
        return Ok(None);
    };
    let text = optional_env("WA_EDIT_TEXT").unwrap_or_else(|| "edited from wa-client".to_owned());
    Ok(Some(EditContent {
        key,
        message: build_text_message(text)?,
        timestamp_ms: Some(timestamp_ms_env("WA_EDIT_TIMESTAMP_MS")?),
    }))
}

fn delete_content(default_remote_jid: &str) -> Result<Option<DeleteContent>, Box<dyn Error>> {
    Ok(message_key_from_env("DELETE", default_remote_jid, true)?.map(|key| DeleteContent { key }))
}

fn pin_content(default_remote_jid: &str) -> Result<Option<PinContent>, Box<dyn Error>> {
    let Some(key) = message_key_from_env("PIN", default_remote_jid, true)? else {
        return Ok(None);
    };
    let action = match optional_env("WA_PIN_ACTION")
        .unwrap_or_else(|| "pin".to_owned())
        .as_str()
    {
        "pin" | "PIN" | "Pin" => PinAction::Pin,
        "unpin" | "UNPIN" | "Unpin" => PinAction::Unpin,
        other => return Err(format!("unsupported WA_PIN_ACTION={other}; use pin or unpin").into()),
    };
    Ok(Some(PinContent {
        key,
        action,
        sender_timestamp_ms: Some(timestamp_ms_env("WA_PIN_TIMESTAMP_MS")?),
    }))
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    let Some(target_jid) = optional_env("WA_TARGET_JID") else {
        println!("set WA_TARGET_JID to send a message");
        return Ok(());
    };

    let store = SqliteAuthStore::open(session_db_path()).await?;
    let client = Client::builder(store).connect().await?;
    let mut events = client.subscribe();
    let validated = client.connect_websocket().await?;

    let message_kind = optional_env("WA_MESSAGE_KIND").unwrap_or_else(|| "text".to_owned());
    let relay = match message_kind.as_str() {
        "text" => {
            let text = optional_env("WA_TEXT").unwrap_or_else(|| "hello from wa-client".to_owned());
            client
                .send_text_with_signal_provider(
                    validated.connection(),
                    &target_jid,
                    text,
                    MessageRelayOptions::new(),
                )
                .await?
        }
        "contact" => {
            client
                .send_message_with_signal_provider(
                    validated.connection(),
                    &target_jid,
                    MessageContent::contact(contact_content()),
                    MessageRelayOptions::new(),
                )
                .await?
        }
        "location" => {
            let Some(location) = location_content()? else {
                println!("set WA_LOCATION_LATITUDE and WA_LOCATION_LONGITUDE to send a location");
                return Ok(());
            };
            client
                .send_message_with_signal_provider(
                    validated.connection(),
                    &target_jid,
                    MessageContent::location(location),
                    MessageRelayOptions::new(),
                )
                .await?
        }
        "poll" => {
            client
                .send_poll_with_signal_provider(
                    validated.connection(),
                    &target_jid,
                    poll_content()?,
                    MessageRelayOptions::new(),
                )
                .await?
        }
        "event" => {
            client
                .send_event_with_signal_provider(
                    validated.connection(),
                    &target_jid,
                    event_content()?,
                    MessageRelayOptions::new(),
                )
                .await?
        }
        "reaction" => {
            let Some(reaction) = reaction_content(&target_jid)? else {
                println!("set WA_REACTION_MESSAGE_ID to react to a message");
                return Ok(());
            };
            client
                .send_reaction_with_signal_provider(
                    validated.connection(),
                    &target_jid,
                    reaction,
                    MessageRelayOptions::new(),
                )
                .await?
        }
        "edit" => {
            let Some(edit) = edit_content(&target_jid)? else {
                println!("set WA_EDIT_MESSAGE_ID to edit a message");
                return Ok(());
            };
            client
                .send_edit_with_signal_provider(
                    validated.connection(),
                    &target_jid,
                    edit,
                    MessageRelayOptions::new(),
                )
                .await?
        }
        "delete" => {
            let Some(delete) = delete_content(&target_jid)? else {
                println!("set WA_DELETE_MESSAGE_ID to delete a message");
                return Ok(());
            };
            client
                .send_delete_with_signal_provider(
                    validated.connection(),
                    &target_jid,
                    delete,
                    MessageRelayOptions::new(),
                )
                .await?
        }
        "pin" => {
            let Some(pin) = pin_content(&target_jid)? else {
                println!("set WA_PIN_MESSAGE_ID to pin or unpin a message");
                return Ok(());
            };
            client
                .send_pin_with_signal_provider(
                    validated.connection(),
                    &target_jid,
                    pin,
                    MessageRelayOptions::new(),
                )
                .await?
        }
        other => {
            println!(
                "unsupported WA_MESSAGE_KIND={other}; use text, contact, location, poll, event, reaction, edit, delete, or pin"
            );
            return Ok(());
        }
    };
    println!("sent {message_kind} message {}", relay.message_id);

    loop {
        match timeout(Duration::from_secs(5), events.recv()).await {
            Ok(Ok(event)) => println!("event: {event:?}"),
            Ok(Err(error)) => {
                println!("event receiver closed: {error}");
                break;
            }
            Err(_) => break,
        }
    }

    Ok(())
}
