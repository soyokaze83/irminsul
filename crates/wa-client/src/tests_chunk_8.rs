// Auto-partitioned test chunk 8 of 8 (feature `wat8`).
// Kept in-crate via include! so tests use private helpers (mock_connection, etc.).
// Memory-bounded: compile only with --features wat8 to stay within the VM RAM budget.
// Included into `mod chunk_8` in lib.rs; allow-attrs live on that module decl.
use async_trait::async_trait;
use bytes::Bytes;
#[cfg(all(feature = "memory-store", feature = "noise"))]
use bytes::{BufMut, BytesMut};
#[cfg(all(feature = "memory-store", feature = "noise"))]
use flate2::{Compression, write::ZlibEncoder};
#[cfg(all(feature = "memory-store", feature = "noise"))]
use prost::Message as _;
#[cfg(feature = "noise")]
use std::collections::BTreeMap;
#[cfg(all(feature = "memory-store", feature = "noise"))]
use std::io::Write as _;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;
use wa_binary::encode_binary_node;
#[cfg(all(feature = "memory-store", feature = "noise"))]
use wa_core::ValidationPayload;
use wa_core::{FrameSink, FrameStream, InboundFrame, decode_inbound_binary_node};
#[cfg(all(feature = "memory-store", feature = "noise"))]
use wa_crypto::{
    SecretBytes, aes_256_ctr_apply, derive_pairing_code_key, generate_key_pair, hmac_sha256,
    prefixed_signal_public_key, sign_x25519,
};
#[cfg(all(feature = "memory-store", feature = "noise"))]
use wa_proto::proto::{
    AdvDeviceIdentity, AdvEncryptionType, AdvSignedDeviceIdentity, AdvSignedDeviceIdentityHmac,
    SenderKeyRecordStructure, SenderKeyStateStructure, sender_key_state_structure,
};
#[cfg(feature = "memory-store")]
use wa_store::KeyNamespace;

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn incoming_processor_emits_group_participant_demote_message_stub() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.account_jid = Some("999:2@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection_with_events(client.events.clone());
    let mut processor = client
        .spawn_incoming_processor(
            connection.clone(),
            IncomingDecryptor,
            wa_core::EventBufferConfig {
                max_pending_items: 8,
            },
        )
        .unwrap();
    let mut events = client.subscribe();
    let notification = BinaryNode::new("notification")
        .with_attr("id", "auto-group-participant-demote-stub")
        .with_attr("from", "123@g.us")
        .with_attr("type", "w:gp2")
        .with_attr("participant", "111@s.whatsapp.net")
        .with_attr("t", "1700000330")
        .with_content(vec![BinaryNode::new("demote").with_content(vec![
            BinaryNode::new("participant")
                .with_attr("jid", "222@lid")
                .with_attr("lidJid", "222@lid")
                .with_attr("phoneNumber", "222@s.whatsapp.net")
                .with_attr("participantUsername", "two"),
        ])]);

    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&notification).unwrap(),
        ))
        .await
        .unwrap();

    let ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(ack.tag, "ack");
    assert_eq!(ack.attrs["id"], "auto-group-participant-demote-stub");
    assert_eq!(ack.attrs["class"], "notification");
    assert_eq!(ack.attrs["to"], "123@g.us");
    assert!(!ack.attrs.contains_key("from"));

    assert_eq!(recv_node_event(&mut events).await, notification);
    let group_batch = recv_batch_event(&mut events).await;
    assert_eq!(group_batch.groups_update.len(), 1);
    assert!(group_batch.messages_upsert.is_empty());
    let group = &group_batch.groups_update[0];
    assert_eq!(group.jid, "123@g.us");
    assert_eq!(
        group.fields["notification_id"],
        "auto-group-participant-demote-stub"
    );
    assert_eq!(group.fields["notification_type"], "w:gp2");
    assert_eq!(group.fields["actor"], "111@s.whatsapp.net");
    assert_eq!(group.fields["timestamp"], "1700000330");
    assert_eq!(group.fields["participants_demote"], "222@lid");
    assert_eq!(group.fields["participants_demote_lids"], "222@lid=222@lid");
    assert_eq!(
        group.fields["participants_demote_phone_numbers"],
        "222@lid=222@s.whatsapp.net"
    );
    assert_eq!(group.fields["participants_demote_usernames"], "222@lid=two");
    assert!(!group.fields.contains_key("participants_demote_roles"));

    let message_batch = recv_batch_event(&mut events).await;
    assert_eq!(message_batch.messages_upsert.len(), 1);
    let stub = &message_batch.messages_upsert[0];
    assert_eq!(stub.key.remote_jid, "123@g.us");
    assert_eq!(stub.key.id, "auto-group-participant-demote-stub");
    assert_eq!(stub.key.participant.as_deref(), Some("111@s.whatsapp.net"));
    assert_eq!(stub.timestamp, Some(1_700_000_330));
    assert_eq!(stub.fields["source"], "group_notification");
    assert_eq!(stub.fields["kind"], "notify");
    assert_eq!(stub.fields["from_me"], "false");
    assert_eq!(stub.fields["notification_type"], "w:gp2");
    assert_eq!(
        stub.fields["message_stub_type"],
        (wa_proto::proto::web_message_info::StubType::GroupParticipantDemote as i32).to_string()
    );
    assert_eq!(stub.fields["stub_type"], "group_participant_demote");
    assert!(!stub.fields.contains_key("payload_kind"));
    assert!(stub.payload.is_none());
    let parameters: Vec<String> =
        serde_json::from_str(&stub.fields["message_stub_parameters"]).unwrap();
    assert_eq!(parameters.len(), 1);
    let participant: serde_json::Value = serde_json::from_str(&parameters[0]).unwrap();
    assert_eq!(participant["id"], "222@lid");
    assert_eq!(participant["lid"], "222@lid");
    assert_eq!(participant["phoneNumber"], "222@s.whatsapp.net");
    assert_eq!(participant["username"], "two");
    assert!(participant.get("admin").is_none());

    let stored_group = store
        .get(KeyNamespace::GroupEvent, &group.jid)
        .await
        .unwrap()
        .unwrap();
    let stored_group = wa_core::decode_stored_group_event(&stored_group).unwrap();
    assert_eq!(stored_group, *group);
    let stored_message = store
        .get(
            KeyNamespace::MessageEvent,
            &wa_core::message_event_store_key(&stub.key),
        )
        .await
        .unwrap()
        .unwrap();
    let stored_message = wa_core::decode_stored_message_event(&stored_message).unwrap();
    assert_eq!(stored_message, *stub);
    tokio::task::yield_now().await;
    assert!(matches!(
        sink_rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
    processor.abort();
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn incoming_processor_emits_offline_group_participant_add_append_stub() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.account_jid = Some("999:2@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection_with_events(client.events.clone());
    let mut processor = client
        .spawn_incoming_processor(
            connection.clone(),
            IncomingDecryptor,
            wa_core::EventBufferConfig {
                max_pending_items: 8,
            },
        )
        .unwrap();
    let mut events = client.subscribe();
    let notification = BinaryNode::new("notification")
        .with_attr("id", "auto-offline-group-participant-add-stub")
        .with_attr("from", "123@g.us")
        .with_attr("type", "w:gp2")
        .with_attr("participant", "111@s.whatsapp.net")
        .with_attr("t", "1700000270")
        .with_attr("offline", "1")
        .with_content(vec![BinaryNode::new("add").with_content(vec![
            BinaryNode::new("participant")
                .with_attr("jid", "222@lid")
                .with_attr("phoneNumber", "222@s.whatsapp.net")
                .with_attr("participantUsername", "two")
                .with_attr("type", "admin"),
        ])]);
    let offline = BinaryNode::new("offline").with_content(vec![notification.clone()]);

    stream_tx
        .send(InboundFrame::new(encode_binary_node(&offline).unwrap()))
        .await
        .unwrap();

    let ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(ack.tag, "ack");
    assert_eq!(ack.attrs["id"], "auto-offline-group-participant-add-stub");
    assert_eq!(ack.attrs["class"], "notification");
    assert_eq!(ack.attrs["to"], "123@g.us");
    assert!(!ack.attrs.contains_key("from"));

    assert_eq!(recv_node_event(&mut events).await, notification);
    let group_batch = recv_batch_event(&mut events).await;
    assert_eq!(group_batch.groups_update.len(), 1);
    assert!(group_batch.messages_upsert.is_empty());
    let group = &group_batch.groups_update[0];
    assert_eq!(group.jid, "123@g.us");
    assert_eq!(
        group.fields["notification_id"],
        "auto-offline-group-participant-add-stub"
    );
    assert_eq!(group.fields["notification_type"], "w:gp2");
    assert_eq!(group.fields["actor"], "111@s.whatsapp.net");
    assert_eq!(group.fields["timestamp"], "1700000270");
    assert_eq!(group.fields["offline"], "true");
    assert_eq!(group.fields["participants_add"], "222@lid");
    assert_eq!(
        group.fields["participants_add_phone_numbers"],
        "222@lid=222@s.whatsapp.net"
    );
    assert_eq!(group.fields["participants_add_usernames"], "222@lid=two");
    assert_eq!(group.fields["participants_add_roles"], "222@lid=admin");

    let message_batch = recv_batch_event(&mut events).await;
    assert_eq!(message_batch.messages_upsert.len(), 1);
    let stub = &message_batch.messages_upsert[0];
    assert_eq!(stub.key.remote_jid, "123@g.us");
    assert_eq!(stub.key.id, "auto-offline-group-participant-add-stub");
    assert_eq!(stub.key.participant.as_deref(), Some("111@s.whatsapp.net"));
    assert_eq!(stub.timestamp, Some(1_700_000_270));
    assert_eq!(stub.fields["source"], "group_notification");
    assert_eq!(stub.fields["kind"], "append");
    assert_eq!(stub.fields["offline"], "true");
    assert_eq!(stub.fields["from_me"], "false");
    assert_eq!(stub.fields["notification_type"], "w:gp2");
    assert_eq!(
        stub.fields["message_stub_type"],
        (wa_proto::proto::web_message_info::StubType::GroupParticipantAdd as i32).to_string()
    );
    assert_eq!(stub.fields["stub_type"], "group_participant_add");
    assert!(!stub.fields.contains_key("payload_kind"));
    assert!(stub.payload.is_none());
    let parameters: Vec<String> =
        serde_json::from_str(&stub.fields["message_stub_parameters"]).unwrap();
    assert_eq!(parameters.len(), 1);
    let participant: serde_json::Value = serde_json::from_str(&parameters[0]).unwrap();
    assert_eq!(participant["id"], "222@lid");
    assert_eq!(participant["phoneNumber"], "222@s.whatsapp.net");
    assert_eq!(participant["username"], "two");
    assert_eq!(participant["admin"], "admin");

    let stored_group = store
        .get(KeyNamespace::GroupEvent, &group.jid)
        .await
        .unwrap()
        .unwrap();
    let stored_group = wa_core::decode_stored_group_event(&stored_group).unwrap();
    assert_eq!(stored_group, *group);
    let stored_message = store
        .get(
            KeyNamespace::MessageEvent,
            &wa_core::message_event_store_key(&stub.key),
        )
        .await
        .unwrap()
        .unwrap();
    let stored_message = wa_core::decode_stored_message_event(&stored_message).unwrap();
    assert_eq!(stored_message, *stub);
    tokio::task::yield_now().await;
    assert!(matches!(
        sink_rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
    processor.abort();
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn incoming_processor_emits_offline_group_notification_append_stub() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.account_jid = Some("999:2@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection_with_events(client.events.clone());
    let mut processor = client
        .spawn_incoming_processor(
            connection.clone(),
            IncomingDecryptor,
            wa_core::EventBufferConfig {
                max_pending_items: 8,
            },
        )
        .unwrap();
    let mut events = client.subscribe();
    let notification = BinaryNode::new("notification")
        .with_attr("id", "auto-offline-group-ephemeral-stub")
        .with_attr("from", "123@g.us")
        .with_attr("type", "w:gp2")
        .with_attr("participant", "111@s.whatsapp.net")
        .with_attr("t", "1700000170")
        .with_attr("offline", "1")
        .with_content(vec![
            BinaryNode::new("ephemeral").with_attr("expiration", "86400"),
        ]);
    let offline = BinaryNode::new("offline").with_content(vec![notification.clone()]);

    stream_tx
        .send(InboundFrame::new(encode_binary_node(&offline).unwrap()))
        .await
        .unwrap();

    let ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(ack.tag, "ack");
    assert_eq!(ack.attrs["id"], "auto-offline-group-ephemeral-stub");
    assert_eq!(ack.attrs["class"], "notification");
    assert_eq!(ack.attrs["to"], "123@g.us");
    assert!(!ack.attrs.contains_key("from"));

    assert_eq!(recv_node_event(&mut events).await, notification);
    let group_batch = recv_batch_event(&mut events).await;
    assert_eq!(group_batch.groups_update.len(), 1);
    assert!(group_batch.messages_upsert.is_empty());
    let group = &group_batch.groups_update[0];
    assert_eq!(group.jid, "123@g.us");
    assert_eq!(
        group.fields["notification_id"],
        "auto-offline-group-ephemeral-stub"
    );
    assert_eq!(group.fields["notification_type"], "w:gp2");
    assert_eq!(group.fields["actor"], "111@s.whatsapp.net");
    assert_eq!(group.fields["timestamp"], "1700000170");
    assert_eq!(group.fields["ephemeral_duration"], "86400");
    assert_eq!(group.fields["offline"], "true");

    let message_batch = recv_batch_event(&mut events).await;
    assert_eq!(message_batch.messages_upsert.len(), 1);
    let stub = &message_batch.messages_upsert[0];
    assert_eq!(stub.key.remote_jid, "123@g.us");
    assert_eq!(stub.key.id, "auto-offline-group-ephemeral-stub");
    assert_eq!(stub.key.participant.as_deref(), Some("111@s.whatsapp.net"));
    assert_eq!(stub.timestamp, Some(1_700_000_170));
    assert_eq!(stub.fields["source"], "group_notification");
    assert_eq!(stub.fields["kind"], "append");
    assert_eq!(stub.fields["offline"], "true");
    assert_eq!(stub.fields["from_me"], "false");
    assert_eq!(stub.fields["notification_type"], "w:gp2");
    assert_eq!(
        stub.fields["message_stub_type"],
        (wa_proto::proto::web_message_info::StubType::ChangeEphemeralSetting as i32).to_string()
    );
    assert_eq!(stub.fields["stub_type"], "change_ephemeral_setting");
    assert_eq!(stub.fields["message_stub_parameters"], r#"["86400"]"#);
    assert_eq!(stub.fields["payload_kind"], "protocol_message");
    let decoded = wa_proto::proto::Message::decode(stub.payload.clone().unwrap()).unwrap();
    let protocol = decoded.protocol_message.unwrap();
    assert_eq!(
        protocol.r#type,
        Some(wa_proto::proto::message::protocol_message::Type::EphemeralSetting as i32)
    );
    assert_eq!(protocol.ephemeral_expiration, Some(86_400));

    let stored_group = store
        .get(KeyNamespace::GroupEvent, &group.jid)
        .await
        .unwrap()
        .unwrap();
    let stored_group = wa_core::decode_stored_group_event(&stored_group).unwrap();
    assert_eq!(stored_group, *group);
    let stored_message = store
        .get(
            KeyNamespace::MessageEvent,
            &wa_core::message_event_store_key(&stub.key),
        )
        .await
        .unwrap()
        .unwrap();
    let stored_message = wa_core::decode_stored_message_event(&stored_message).unwrap();
    assert_eq!(stored_message, *stub);
    processor.abort();
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn incoming_processor_handles_offline_node_children() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.account_jid = Some("999:2@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection_with_events(client.events.clone());
    let mut processor = client
        .spawn_incoming_processor(
            connection.clone(),
            IncomingDecryptor,
            wa_core::EventBufferConfig {
                max_pending_items: 8,
            },
        )
        .unwrap();
    let mut events = client.subscribe();
    let text_one = wa_proto::proto::Message {
        conversation: Some("one".to_owned()),
        ..wa_proto::proto::Message::default()
    };
    let text_two = wa_proto::proto::Message {
        conversation: Some("two".to_owned()),
        ..wa_proto::proto::Message::default()
    };
    let offline = BinaryNode::new("offline").with_content(vec![
        BinaryNode::new("message")
            .with_attr("id", "offline-1")
            .with_attr("from", "123@s.whatsapp.net")
            .with_attr("type", "text")
            .with_content(vec![
                BinaryNode::new("plaintext").with_content(Bytes::from(text_one.encode_to_vec())),
            ]),
        BinaryNode::new("message")
            .with_attr("id", "offline-2")
            .with_attr("from", "456@s.whatsapp.net")
            .with_attr("type", "text")
            .with_content(vec![
                BinaryNode::new("plaintext").with_content(Bytes::from(text_two.encode_to_vec())),
            ]),
    ]);

    stream_tx
        .send(InboundFrame::new(encode_binary_node(&offline).unwrap()))
        .await
        .unwrap();

    let first_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(first_ack.tag, "ack");
    assert_eq!(first_ack.attrs["id"], "offline-1");
    assert_eq!(first_ack.attrs["class"], "message");
    let second_ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(second_ack.tag, "ack");
    assert_eq!(second_ack.attrs["id"], "offline-2");
    assert_eq!(second_ack.attrs["class"], "message");

    let batch = recv_batch_event(&mut events).await;
    assert_eq!(batch.messages_upsert.len(), 2);
    assert_eq!(batch.messages_upsert[0].key.id, "offline-1");
    assert_eq!(batch.messages_upsert[1].key.id, "offline-2");

    let stored_key = wa_core::message_event_store_key(&batch.messages_upsert[1].key);
    let stored = store
        .get(KeyNamespace::MessageEvent, &stored_key)
        .await
        .unwrap()
        .unwrap();
    let stored = wa_core::decode_stored_message_event(&stored).unwrap();
    assert_eq!(stored, batch.messages_upsert[1]);
    processor.abort();
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn incoming_processor_prefers_group_call_timeout_stub_over_offer_message() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.account_jid = Some("999:2@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection_with_events(client.events.clone());
    let mut processor = client
        .spawn_incoming_processor(
            connection.clone(),
            IncomingDecryptor,
            wa_core::EventBufferConfig {
                max_pending_items: 8,
            },
        )
        .unwrap();
    let mut events = client.subscribe();
    let offer = BinaryNode::new("call")
        .with_attr("id", "auto-offline-group-call-offer")
        .with_attr("from", "456@g.us")
        .with_attr("t", "1700000130")
        .with_attr("offline", "1")
        .with_content(vec![
            BinaryNode::new("offer")
                .with_attr("call-id", "auto-offline-group-call-1")
                .with_attr("from", "123@s.whatsapp.net")
                .with_attr("caller_pn", "123@s.whatsapp.net")
                .with_attr("type", "group")
                .with_attr("group-jid", "456@g.us")
                .with_content(vec![BinaryNode::new("video")]),
        ]);
    let timeout = BinaryNode::new("call")
        .with_attr("id", "auto-offline-group-call-timeout")
        .with_attr("from", "456@g.us")
        .with_attr("t", "1700000135")
        .with_attr("offline", "1")
        .with_content(vec![
            BinaryNode::new("timeout").with_attr("call-id", "auto-offline-group-call-1"),
        ]);
    let offline = BinaryNode::new("offline").with_content(vec![offer, timeout]);

    stream_tx
        .send(InboundFrame::new(encode_binary_node(&offline).unwrap()))
        .await
        .unwrap();

    for expected_id in [
        "auto-offline-group-call-offer",
        "auto-offline-group-call-timeout",
    ] {
        let ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
            .unwrap()
            .node;
        assert_eq!(ack.tag, "ack");
        assert_eq!(ack.attrs["id"], expected_id);
        assert_eq!(ack.attrs["class"], "call");
        assert_eq!(ack.attrs["to"], "456@g.us");
        assert!(!ack.attrs.contains_key("from"));
    }

    let calls_batch = recv_batch_event(&mut events).await;
    assert_eq!(calls_batch.calls_update.len(), 2);
    assert!(calls_batch.messages_upsert.is_empty());
    let offer_call = calls_batch
        .calls_update
        .iter()
        .find(|call| call.event_type == "offer")
        .unwrap();
    let timeout_call = calls_batch
        .calls_update
        .iter()
        .find(|call| call.event_type == "timeout")
        .unwrap();
    assert_eq!(
        offer_call.call_id.as_deref(),
        Some("auto-offline-group-call-1")
    );
    assert_eq!(offer_call.fields["is_video"], "true");
    assert_eq!(offer_call.fields["is_group"], "true");
    assert_eq!(
        timeout_call.call_id.as_deref(),
        Some("auto-offline-group-call-1")
    );
    assert_eq!(timeout_call.timestamp, Some(1_700_000_135));
    assert_eq!(timeout_call.fields["is_video"], "true");
    assert_eq!(timeout_call.fields["is_group"], "true");
    assert_eq!(timeout_call.fields["caller_pn"], "123@s.whatsapp.net");

    let message_batch = recv_batch_event(&mut events).await;
    assert_eq!(message_batch.messages_upsert.len(), 1);
    let missed = &message_batch.messages_upsert[0];
    assert_eq!(missed.key.remote_jid, "456@g.us");
    assert_eq!(missed.key.id, "auto-offline-group-call-1");
    assert_eq!(missed.timestamp, Some(1_700_000_135));
    assert_eq!(missed.fields["kind"], "append");
    assert_eq!(missed.fields["source"], "call_event");
    assert_eq!(missed.fields["call_status"], "timeout");
    assert_eq!(missed.fields["is_video"], "true");
    assert_eq!(missed.fields["is_group"], "true");
    assert_eq!(missed.fields["caller_pn"], "123@s.whatsapp.net");
    assert_eq!(
        missed.fields["message_stub_type"],
        (wa_proto::proto::web_message_info::StubType::CallMissedGroupVideo as i32).to_string()
    );
    assert_eq!(missed.fields["stub_type"], "call_missed_group_video");
    assert!(missed.payload.is_none());

    let stored_message = store
        .get(
            KeyNamespace::MessageEvent,
            &wa_core::message_event_store_key(&missed.key),
        )
        .await
        .unwrap()
        .unwrap();
    let stored_message = wa_core::decode_stored_message_event(&stored_message).unwrap();
    assert_eq!(stored_message, *missed);
    assert!(
        store
            .get(
                KeyNamespace::CallEvent,
                &call_offer_cache_key(offer_call).unwrap()
            )
            .await
            .unwrap()
            .is_none()
    );
    processor.abort();
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn incoming_processor_refreshes_dirty_communities() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.account_jid = Some("999:2@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store).connect().await.unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection_with_events(client.events.clone());
    let mut processor = client
        .spawn_incoming_processor(
            connection.clone(),
            IncomingDecryptor,
            wa_core::EventBufferConfig {
                max_pending_items: 8,
            },
        )
        .unwrap();
    let mut events = client.subscribe();
    let dirty = BinaryNode::new("ib").with_content(vec![
        BinaryNode::new("dirty")
            .with_attr("type", "status")
            .with_attr("timestamp", "111"),
        BinaryNode::new("dirty")
            .with_attr("type", "communities")
            .with_attr("timestamp", "999"),
    ]);

    stream_tx
        .send(InboundFrame::new(encode_binary_node(&dirty).unwrap()))
        .await
        .unwrap();

    let participating_query = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(participating_query.attrs["xmlns"], "w:g2");
    assert_eq!(participating_query.attrs["to"], "@g.us");
    assert_eq!(participating_query.attrs["type"], "get");
    assert_child(
        test_child(&participating_query, "participating"),
        "participants",
    );
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(
                &BinaryNode::new("iq")
                    .with_attr("id", participating_query.attrs["id"].clone())
                    .with_attr("type", "result")
                    .with_content(vec![BinaryNode::new("communities").with_content(vec![
                        BinaryNode::new("community")
                            .with_attr("id", "123")
                            .with_attr("subject", "Updates")
                            .with_content(vec![
                                BinaryNode::new("parent"),
                                BinaryNode::new("participant")
                                    .with_attr("jid", "111@s.whatsapp.net")
                                    .with_attr("type", "admin"),
                            ]),
                    ])]),
            )
            .unwrap(),
        ))
        .await
        .unwrap();

    let clean = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(clean.attrs["xmlns"], "urn:xmpp:whatsapp:dirty");
    let clean_child = test_child(&clean, "clean");
    assert_eq!(clean_child.attrs["type"], "groups");
    assert_eq!(clean_child.attrs["timestamp"], "999");
    let update = recv_groups_update_event(&mut events).await;
    assert_eq!(update.len(), 1);
    assert_eq!(update[0].jid, "123@g.us");
    assert_eq!(update[0].fields["source"], "community_dirty_refresh");
    assert_eq!(update[0].fields["subject"], "Updates");
    assert_eq!(update[0].fields["is_community"], "true");
    assert_eq!(update[0].fields["participants"], "111@s.whatsapp.net");
    assert_eq!(update[0].fields["participants_count"], "1");
    assert_eq!(
        update[0].fields["participants_admins"],
        "111@s.whatsapp.net"
    );
    processor.abort();
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn incoming_processor_refreshes_dirty_groups() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.account_jid = Some("999:2@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store).connect().await.unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection_with_events(client.events.clone());
    let mut processor = client
        .spawn_incoming_processor(
            connection.clone(),
            IncomingDecryptor,
            wa_core::EventBufferConfig {
                max_pending_items: 8,
            },
        )
        .unwrap();
    let mut events = client.subscribe();
    let dirty = BinaryNode::new("ib").with_content(vec![
        BinaryNode::new("dirty")
            .with_attr("type", "groups")
            .with_attr("timestamp", "998"),
    ]);

    stream_tx
        .send(InboundFrame::new(encode_binary_node(&dirty).unwrap()))
        .await
        .unwrap();

    let participating_query = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(participating_query.attrs["xmlns"], "w:g2");
    assert_eq!(participating_query.attrs["to"], "@g.us");
    assert_eq!(participating_query.attrs["type"], "get");
    assert_child(
        test_child(&participating_query, "participating"),
        "participants",
    );
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(
                &BinaryNode::new("iq")
                    .with_attr("id", participating_query.attrs["id"].clone())
                    .with_attr("type", "result")
                    .with_content(vec![BinaryNode::new("groups").with_content(vec![
                        BinaryNode::new("group")
                        .with_attr("id", "123")
                        .with_attr("subject", "Team")
                        .with_content(vec![
                            BinaryNode::new("linked_parent").with_attr("jid", "456@g.us"),
                            BinaryNode::new("participant")
                                .with_attr("jid", "111@s.whatsapp.net")
                                .with_attr("type", "superadmin"),
                            BinaryNode::new("participant")
                                .with_attr("jid", "222@s.whatsapp.net"),
                        ]),
                    ])]),
            )
            .unwrap(),
        ))
        .await
        .unwrap();

    let community_query = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(community_query.attrs["xmlns"], "w:g2");
    assert_eq!(community_query.attrs["to"], "@g.us");
    assert_eq!(community_query.attrs["type"], "get");
    let participating = test_child(&community_query, "participating");
    assert_child(participating, "participants");
    assert_child(participating, "description");
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(
                &BinaryNode::new("iq")
                    .with_attr("id", community_query.attrs["id"].clone())
                    .with_attr("type", "result")
                    .with_content(vec![BinaryNode::new("communities").with_content(vec![
                        BinaryNode::new("community")
                            .with_attr("id", "456")
                            .with_attr("subject", "Community")
                            .with_content(vec![
                                BinaryNode::new("parent"),
                                BinaryNode::new("participant")
                                    .with_attr("jid", "333@s.whatsapp.net")
                                    .with_attr("type", "admin"),
                            ]),
                    ])]),
            )
            .unwrap(),
        ))
        .await
        .unwrap();

    let clean = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(clean.attrs["xmlns"], "urn:xmpp:whatsapp:dirty");
    let clean_child = test_child(&clean, "clean");
    assert_eq!(clean_child.attrs["type"], "groups");
    assert_eq!(clean_child.attrs["timestamp"], "998");
    let update = recv_groups_update_event(&mut events).await;
    assert_eq!(update.len(), 1);
    assert_eq!(update[0].jid, "123@g.us");
    assert_eq!(update[0].fields["source"], "group_dirty_refresh");
    assert_eq!(update[0].fields["subject"], "Team");
    assert_eq!(update[0].fields["linked_parent"], "456@g.us");
    assert_eq!(
        update[0].fields["participants"],
        "111@s.whatsapp.net,222@s.whatsapp.net"
    );
    assert_eq!(update[0].fields["participants_count"], "2");
    assert_eq!(
        update[0].fields["participants_superadmins"],
        "111@s.whatsapp.net"
    );
    let update = recv_groups_update_event(&mut events).await;
    assert_eq!(update.len(), 1);
    assert_eq!(update[0].jid, "456@g.us");
    assert_eq!(update[0].fields["source"], "community_dirty_refresh");
    assert_eq!(update[0].fields["subject"], "Community");
    assert_eq!(update[0].fields["participants"], "333@s.whatsapp.net");
    assert_eq!(
        update[0].fields["participants_admins"],
        "333@s.whatsapp.net"
    );
    processor.abort();
    connection.close().await.unwrap();
}

#[cfg(feature = "memory-store")]
#[tokio::test]
async fn send_media_retry_request_with_payload_writes_server_error_receipt() {
    let store = wa_store::MemoryAuthStore::new();
    let client = Client::builder(store).connect().await.unwrap();
    let (connection, mut sink_rx, _stream_tx) = mock_connection();
    let key = MessageKey {
        remote_jid: Some("123@s.whatsapp.net".to_owned()),
        from_me: Some(false),
        id: Some("m1".to_owned()),
        participant: None,
    };

    let node = client
        .send_media_retry_request_with_payload(
            &connection,
            &key,
            "999:7@s.whatsapp.net",
            MediaRetryPayload::new(
                Bytes::from_static(b"ciphertext"),
                Bytes::from(vec![1u8; 12]),
            ),
        )
        .await
        .unwrap();
    assert_eq!(node.attrs["type"], "server-error");

    let sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(sent, node);
    assert_eq!(sent.attrs["to"], "999@s.whatsapp.net");
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn send_media_retry_request_encrypts_payload_from_stored_account() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.registered = true;
    credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store).connect().await.unwrap();
    let (connection, mut sink_rx, _stream_tx) = mock_connection();
    let key = MessageKey {
        remote_jid: Some("123@s.whatsapp.net".to_owned()),
        from_me: Some(false),
        id: Some("m1".to_owned()),
        participant: None,
    };

    let node = client
        .send_media_retry_request(&connection, &key, &[8u8; 32])
        .await
        .unwrap();

    assert_eq!(node.attrs["to"], "999@s.whatsapp.net");
    let sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    let update = wa_core::parse_media_retry_update(&sent).unwrap();
    assert_eq!(update.key, key);
    let media = update.media.unwrap();
    assert_eq!(media.iv.len(), 12);
    assert!(!media.ciphertext.is_empty());
    connection.close().await.unwrap();
}

#[cfg(feature = "memory-store")]
#[tokio::test]
async fn read_messages_can_send_read_self_receipts() {
    let store = wa_store::MemoryAuthStore::new();
    let client = Client::builder(store).connect().await.unwrap();
    let (connection, mut sink_rx, _stream_tx) = mock_connection();
    let keys = vec![MessageKey {
        remote_jid: Some("123@s.whatsapp.net".to_owned()),
        from_me: Some(false),
        id: Some("m1".to_owned()),
        participant: None,
    }];

    let receipts = client
        .read_messages(&connection, &keys, false, Some(11))
        .await
        .unwrap();

    assert_eq!(receipts.len(), 1);
    let sent = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(sent.attrs["id"], "m1");
    assert_eq!(sent.attrs["type"], "read-self");
    assert_eq!(sent.attrs["t"], "11");
    connection.close().await.unwrap();
}

#[cfg(feature = "memory-store")]
#[tokio::test]
async fn fetch_statuses_and_disappearing_modes_send_usync_queries() {
    let store = wa_store::MemoryAuthStore::new();
    let client = Client::builder(store).connect().await.unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let status_fut = client.fetch_statuses(&connection, ["123@s.whatsapp.net"]);
    tokio::pin!(status_fut);

    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "usync");
            assert_usync_query_protocol(&node, "status");
            BinaryNode::new("iq")
                .with_attr("id", node.attrs["id"].clone())
                .with_attr("type", "result")
                .with_content(vec![BinaryNode::new("usync").with_content(vec![
                    BinaryNode::new("list").with_content(vec![
                        BinaryNode::new("user")
                            .with_attr("jid", "123@s.whatsapp.net")
                            .with_content(vec![
                                BinaryNode::new("status")
                                    .with_attr("t", "42")
                                    .with_content("available"),
                            ]),
                    ]),
                ])])
        },
        &mut status_fut,
    )
    .await;

    assert_eq!(
        status_fut.await.unwrap(),
        vec![USyncStatusResult {
            jid: "123@s.whatsapp.net".to_owned(),
            status: wa_core::USyncStatus {
                status: Some("available".to_owned()),
                set_at: Some(42),
            },
        }]
    );

    let disappearing_fut = client.fetch_disappearing_modes(&connection, ["123@s.whatsapp.net"]);
    tokio::pin!(disappearing_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "usync");
            assert_usync_query_protocol(&node, "disappearing_mode");
            BinaryNode::new("iq")
                .with_attr("id", node.attrs["id"].clone())
                .with_attr("type", "result")
                .with_content(vec![BinaryNode::new("usync").with_content(vec![
                    BinaryNode::new("list").with_content(vec![
                        BinaryNode::new("user")
                            .with_attr("jid", "123@s.whatsapp.net")
                            .with_content(vec![
                                BinaryNode::new("disappearing_mode")
                                    .with_attr("duration", "604800")
                                    .with_attr("t", "43"),
                            ]),
                    ]),
                ])])
        },
        &mut disappearing_fut,
    )
    .await;

    assert_eq!(
        disappearing_fut.await.unwrap(),
        vec![USyncDisappearingModeResult {
            jid: "123@s.whatsapp.net".to_owned(),
            mode: wa_core::USyncDisappearingMode {
                duration: 604800,
                set_at: Some(43),
            },
        }]
    );
    connection.close().await.unwrap();
}

#[cfg(feature = "memory-store")]
#[tokio::test]
async fn fetch_bot_profiles_sends_profile_query_and_maps_results() {
    let store = wa_store::MemoryAuthStore::new();
    let client = Client::builder(store).connect().await.unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let profile_fut = client.fetch_bot_profiles(&connection, [("123@s.whatsapp.net", "persona-1")]);
    tokio::pin!(profile_fut);

    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "usync");
            assert_usync_query_protocol(&node, "bot");
            BinaryNode::new("iq")
                .with_attr("id", node.attrs["id"].clone())
                .with_attr("type", "result")
                .with_content(vec![BinaryNode::new("usync").with_content(vec![
                    BinaryNode::new("list").with_content(vec![
                        BinaryNode::new("user")
                            .with_attr("jid", "123@s.whatsapp.net")
                            .with_content(vec![BinaryNode::new("bot").with_content(vec![
                                BinaryNode::new("profile")
                                    .with_attr("persona_id", "persona-1")
                                    .with_content(vec![
                                        BinaryNode::new("name").with_content("Helper"),
                                        BinaryNode::new("commands").with_content(vec![
                                            BinaryNode::new("command").with_content(vec![
                                                BinaryNode::new("name").with_content("/help"),
                                                BinaryNode::new("description")
                                                    .with_content("Show help"),
                                            ]),
                                        ]),
                                    ]),
                            ])]),
                    ]),
                ])])
        },
        &mut profile_fut,
    )
    .await;

    assert_eq!(
        profile_fut.await.unwrap(),
        vec![USyncBotProfile {
            jid: "123@s.whatsapp.net".to_owned(),
            name: Some("Helper".to_owned()),
            attributes: None,
            description: None,
            category: None,
            is_default: false,
            prompts: Vec::new(),
            persona_id: Some("persona-1".to_owned()),
            commands: vec![wa_core::USyncBotProfileCommand {
                name: "/help".to_owned(),
                description: "Show help".to_owned(),
            }],
            commands_description: None,
        }]
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn profile_picture_url_attaches_lid_backed_tc_token_for_user_target() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.registered = true;
    credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    credentials.account_lid = Some("ownlid@lid".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    wa_core::LidPnMappingStore::new(store.clone())
        .store_mappings(vec![wa_core::LidPnMapping {
            pn: "123@s.whatsapp.net".to_owned(),
            lid: "abc@lid".to_owned(),
        }])
        .await
        .unwrap();
    wa_core::save_tc_token(
        &store,
        wa_core::TcTokenRecord::new("abc@lid", Bytes::from_static(b"profile-token"))
            .unwrap()
            .with_timestamp_seconds(current_unix_timestamp()),
    )
    .await
    .unwrap();
    let client = Client::builder(store).connect().await.unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection();

    let picture_fut =
        client.fetch_profile_picture_url(&connection, "123@c.us", ProfilePictureType::Preview);
    tokio::pin!(picture_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "w:profile:picture");
            assert_eq!(node.attrs["target"], "123@s.whatsapp.net");
            let picture = test_child(&node, "picture");
            assert_eq!(picture.attrs["type"], "preview");
            assert_eq!(picture.attrs["query"], "url");
            assert_eq!(
                test_node_bytes(test_child(&node, "tctoken")),
                Some(Bytes::from_static(b"profile-token"))
            );
            BinaryNode::new("iq")
                .with_attr("id", node.attrs["id"].clone())
                .with_attr("type", "result")
                .with_content(vec![
                    BinaryNode::new("picture").with_attr("url", "https://example.invalid/u"),
                ])
        },
        &mut picture_fut,
    )
    .await;

    assert_eq!(
        picture_fut.await.unwrap().as_deref(),
        Some("https://example.invalid/u")
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn profile_picture_url_skips_tc_token_for_group_and_self_targets() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.registered = true;
    credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    credentials.account_lid = Some("ownlid@lid".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    wa_core::save_tc_token(
        &store,
        wa_core::TcTokenRecord::new("123@g.us", Bytes::from_static(b"group-token"))
            .unwrap()
            .with_timestamp_seconds(current_unix_timestamp()),
    )
    .await
    .unwrap();
    wa_core::save_tc_token(
        &store,
        wa_core::TcTokenRecord::new("999@s.whatsapp.net", Bytes::from_static(b"self-token"))
            .unwrap()
            .with_timestamp_seconds(current_unix_timestamp()),
    )
    .await
    .unwrap();
    let client = Client::builder(store).connect().await.unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection();

    let group_picture_fut =
        client.fetch_profile_picture_url(&connection, "123@g.us", ProfilePictureType::Preview);
    tokio::pin!(group_picture_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "w:profile:picture");
            assert_eq!(node.attrs["target"], "123@g.us");
            assert!(test_children(&node, "tctoken").is_empty());
            empty_result_for(&node)
        },
        &mut group_picture_fut,
    )
    .await;
    assert_eq!(group_picture_fut.await.unwrap(), None);

    let self_picture_fut = client.fetch_profile_picture_url(
        &connection,
        "999:7@s.whatsapp.net",
        ProfilePictureType::Preview,
    );
    tokio::pin!(self_picture_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "w:profile:picture");
            assert_eq!(node.attrs["target"], "999@s.whatsapp.net");
            assert!(test_children(&node, "tctoken").is_empty());
            empty_result_for(&node)
        },
        &mut self_picture_fut,
    )
    .await;
    assert_eq!(self_picture_fut.await.unwrap(), None);
    connection.close().await.unwrap();
}

#[cfg(feature = "memory-store")]
#[tokio::test]
async fn privacy_profile_and_blocklist_methods_use_account_iqs() {
    let store = wa_store::MemoryAuthStore::new();
    let client = Client::builder(store).connect().await.unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection();

    let privacy_fut = client.fetch_privacy_settings(&connection);
    tokio::pin!(privacy_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "privacy");
            assert_eq!(node.attrs["type"], "get");
            assert!(test_child(&node, "privacy").attrs.is_empty());
            BinaryNode::new("iq")
                .with_attr("id", node.attrs["id"].clone())
                .with_attr("type", "result")
                .with_content(vec![BinaryNode::new("privacy").with_content(vec![
                    BinaryNode::new("category")
                        .with_attr("name", "last")
                        .with_attr("value", "contacts"),
                ])])
        },
        &mut privacy_fut,
    )
    .await;
    let settings = privacy_fut.await.unwrap();
    assert_eq!(settings.get(PrivacyCategory::LastSeen), Some("contacts"));

    let update_privacy_fut = client.update_privacy_setting(
        &connection,
        PrivacyCategory::Online,
        PrivacyValue::MatchLastSeen,
    );
    tokio::pin!(update_privacy_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "privacy");
            assert_eq!(node.attrs["type"], "set");
            let category = test_child(test_child(&node, "privacy"), "category");
            assert_eq!(category.attrs["name"], "online");
            assert_eq!(category.attrs["value"], "match_last_seen");
            empty_result_for(&node)
        },
        &mut update_privacy_fut,
    )
    .await;
    update_privacy_fut.await.unwrap();

    let failed_privacy_fut = client.update_privacy_setting(
        &connection,
        PrivacyCategory::Online,
        PrivacyValue::MatchLastSeen,
    );
    tokio::pin!(failed_privacy_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "privacy");
            error_result_for(&node, "403", "denied")
        },
        &mut failed_privacy_fut,
    )
    .await;
    assert!(failed_privacy_fut.await.is_err());

    let disappearing_fut = client.set_default_disappearing_mode(&connection, 604800);
    tokio::pin!(disappearing_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "disappearing_mode");
            assert_eq!(
                test_child(&node, "disappearing_mode").attrs["duration"],
                "604800"
            );
            empty_result_for(&node)
        },
        &mut disappearing_fut,
    )
    .await;
    disappearing_fut.await.unwrap();

    let failed_disappearing_fut = client.set_default_disappearing_mode(&connection, 604800);
    tokio::pin!(failed_disappearing_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "disappearing_mode");
            error_result_for(&node, "500", "server rejected update")
        },
        &mut failed_disappearing_fut,
    )
    .await;
    assert!(failed_disappearing_fut.await.is_err());

    let status_fut = client.update_profile_status(&connection, "Busy");
    tokio::pin!(status_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "status");
            assert_eq!(
                test_node_text(test_child(&node, "status")).as_deref(),
                Some("Busy")
            );
            empty_result_for(&node)
        },
        &mut status_fut,
    )
    .await;
    status_fut.await.unwrap();

    let failed_status_fut = client.update_profile_status(&connection, "Busy");
    tokio::pin!(failed_status_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "status");
            error_result_for(&node, "400", "bad status")
        },
        &mut failed_status_fut,
    )
    .await;
    assert!(failed_status_fut.await.is_err());

    let picture_fut =
        client.fetch_profile_picture_url(&connection, "123@c.us", ProfilePictureType::Preview);
    tokio::pin!(picture_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "w:profile:picture");
            assert_eq!(node.attrs["target"], "123@s.whatsapp.net");
            let picture = test_child(&node, "picture");
            assert_eq!(picture.attrs["type"], "preview");
            assert_eq!(picture.attrs["query"], "url");
            BinaryNode::new("iq")
                .with_attr("id", node.attrs["id"].clone())
                .with_attr("type", "result")
                .with_content(vec![
                    BinaryNode::new("picture").with_attr("url", "https://example.invalid/p"),
                ])
        },
        &mut picture_fut,
    )
    .await;
    assert_eq!(
        picture_fut.await.unwrap().as_deref(),
        Some("https://example.invalid/p")
    );

    let update_picture_fut =
        client.update_profile_picture(&connection, Some("123@s.whatsapp.net"), b"jpeg".to_vec());
    tokio::pin!(update_picture_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "w:profile:picture");
            assert_eq!(node.attrs["target"], "123@s.whatsapp.net");
            let picture = test_child(&node, "picture");
            assert_eq!(picture.attrs["type"], "image");
            assert_eq!(test_node_text(picture).as_deref(), Some("jpeg"));
            empty_result_for(&node)
        },
        &mut update_picture_fut,
    )
    .await;
    update_picture_fut.await.unwrap();

    let failed_picture_update =
        client.update_profile_picture(&connection, Some("123@s.whatsapp.net"), b"jpeg".to_vec());
    tokio::pin!(failed_picture_update);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "w:profile:picture");
            assert_eq!(node.attrs["target"], "123@s.whatsapp.net");
            error_result_for(&node, "403", "denied")
        },
        &mut failed_picture_update,
    )
    .await;
    assert!(failed_picture_update.await.is_err());

    let remove_picture_fut = client.remove_profile_picture(&connection, None);
    tokio::pin!(remove_picture_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "w:profile:picture");
            assert!(!node.attrs.contains_key("target"));
            assert!(node.content.is_none());
            empty_result_for(&node)
        },
        &mut remove_picture_fut,
    )
    .await;
    remove_picture_fut.await.unwrap();

    let blocklist_fut = client.fetch_blocklist(&connection);
    tokio::pin!(blocklist_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "blocklist");
            assert_eq!(node.attrs["type"], "get");
            BinaryNode::new("iq")
                .with_attr("id", node.attrs["id"].clone())
                .with_attr("type", "result")
                .with_content(vec![BinaryNode::new("list").with_content(vec![
                    BinaryNode::new("item").with_attr("jid", "abc@lid"),
                    BinaryNode::new("item").with_attr("jid", "def@lid"),
                ])])
        },
        &mut blocklist_fut,
    )
    .await;
    assert_eq!(blocklist_fut.await.unwrap(), vec!["abc@lid", "def@lid"]);
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn block_status_and_presence_methods_use_identity_state() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.registered = true;
    credentials.account_jid = Some("123:7@s.whatsapp.net".to_owned());
    credentials.account_lid = Some("own@lid".to_owned());
    credentials.account_name = Some("Agent@Desk".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    wa_core::LidPnMappingStore::new(store.clone())
        .store_mappings(vec![wa_core::LidPnMapping {
            pn: "555@s.whatsapp.net".to_owned(),
            lid: "lid555@lid".to_owned(),
        }])
        .await
        .unwrap();
    wa_core::save_tc_token(
        &store,
        wa_core::TcTokenRecord::new("lid555@lid", Bytes::from_static(b"presence-token"))
            .unwrap()
            .with_timestamp_seconds(current_unix_timestamp()),
    )
    .await
    .unwrap();
    wa_core::save_tc_token(
        &store,
        wa_core::TcTokenRecord::new("777@g.us", Bytes::from_static(b"group-presence-token"))
            .unwrap()
            .with_timestamp_seconds(current_unix_timestamp()),
    )
    .await
    .unwrap();
    wa_core::save_tc_token(
        &store,
        wa_core::TcTokenRecord::new("123@s.whatsapp.net", Bytes::from_static(b"self-pn-token"))
            .unwrap()
            .with_timestamp_seconds(current_unix_timestamp()),
    )
    .await
    .unwrap();
    wa_core::save_tc_token(
        &store,
        wa_core::TcTokenRecord::new("own@lid", Bytes::from_static(b"self-lid-token"))
            .unwrap()
            .with_timestamp_seconds(current_unix_timestamp()),
    )
    .await
    .unwrap();

    let client = Client::builder(store).connect().await.unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let block_fut =
        client.update_block_status(&connection, "555@s.whatsapp.net", BlocklistAction::Block);
    tokio::pin!(block_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "blocklist");
            let item = test_child(&node, "item");
            assert_eq!(item.attrs["action"], "block");
            assert_eq!(item.attrs["jid"], "lid555@lid");
            assert_eq!(item.attrs["pn_jid"], "555@s.whatsapp.net");
            empty_result_for(&node)
        },
        &mut block_fut,
    )
    .await;
    block_fut.await.unwrap();

    let failed_block_fut =
        client.update_block_status(&connection, "555@s.whatsapp.net", BlocklistAction::Block);
    tokio::pin!(failed_block_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "blocklist");
            let item = test_child(&node, "item");
            assert_eq!(item.attrs["action"], "block");
            error_result_for(&node, "403", "denied")
        },
        &mut failed_block_fut,
    )
    .await;
    assert!(failed_block_fut.await.is_err());

    let unblock_fut =
        client.update_block_status(&connection, "lid555@lid", BlocklistAction::Unblock);
    tokio::pin!(unblock_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            let item = test_child(&node, "item");
            assert_eq!(item.attrs["action"], "unblock");
            assert_eq!(item.attrs["jid"], "lid555@lid");
            assert!(!item.attrs.contains_key("pn_jid"));
            empty_result_for(&node)
        },
        &mut unblock_fut,
    )
    .await;
    unblock_fut.await.unwrap();

    let online = client
        .send_presence_update(&connection, PresenceState::Available, None)
        .await
        .unwrap();
    assert_eq!(online.tag, "presence");
    assert_eq!(online.attrs["name"], "AgentDesk");
    assert_eq!(online.attrs["type"], "available");
    let sent_online = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(sent_online, online);

    let recording = client
        .send_presence_update(&connection, PresenceState::Recording, Some("777@lid"))
        .await
        .unwrap();
    assert_eq!(recording.tag, "chatstate");
    assert_eq!(recording.attrs["from"], "own@lid");
    assert_eq!(recording.attrs["to"], "777@lid");
    assert_eq!(test_child(&recording, "composing").attrs["media"], "audio");
    let sent_recording = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(sent_recording, recording);

    let subscribe = client
        .subscribe_presence(&connection, "555@s.whatsapp.net")
        .await
        .unwrap();
    assert_eq!(subscribe.tag, "presence");
    assert_eq!(subscribe.attrs["type"], "subscribe");
    assert_eq!(subscribe.attrs["to"], "555@s.whatsapp.net");
    assert_eq!(
        test_node_bytes(test_child(&subscribe, "tctoken")),
        Some(Bytes::from_static(b"presence-token"))
    );
    let sent_subscribe = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(sent_subscribe, subscribe);

    let group_subscribe = client
        .subscribe_presence(&connection, "777@g.us")
        .await
        .unwrap();
    assert_eq!(group_subscribe.tag, "presence");
    assert_eq!(group_subscribe.attrs["type"], "subscribe");
    assert_eq!(group_subscribe.attrs["to"], "777@g.us");
    assert!(group_subscribe.content.is_none());
    let sent_group_subscribe = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(sent_group_subscribe, group_subscribe);

    let self_pn_subscribe = client
        .subscribe_presence(&connection, "123:7@s.whatsapp.net")
        .await
        .unwrap();
    assert_eq!(self_pn_subscribe.attrs["to"], "123:7@s.whatsapp.net");
    assert!(self_pn_subscribe.content.is_none());
    let sent_self_pn_subscribe = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(sent_self_pn_subscribe, self_pn_subscribe);

    let self_lid_subscribe = client
        .subscribe_presence(&connection, "own@lid")
        .await
        .unwrap();
    assert_eq!(self_lid_subscribe.attrs["to"], "own@lid");
    assert!(self_lid_subscribe.content.is_none());
    let sent_self_lid_subscribe = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(sent_self_lid_subscribe, self_lid_subscribe);
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn identity_change_tc_token_reissue_coalesces_with_existing_in_flight_issue() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.registered = true;
    credentials.account_jid = Some("999:7@s.whatsapp.net".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let sender_timestamp = current_unix_timestamp().saturating_sub(60);
    wa_core::save_tc_token(
        &store,
        wa_core::TcTokenRecord::new(
            "123@s.whatsapp.net",
            Bytes::from_static(b"old-coalesced-token"),
        )
        .unwrap()
        .with_timestamp_seconds(sender_timestamp)
        .with_sender_timestamp_seconds(sender_timestamp),
    )
    .await
    .unwrap();

    let client = Client::builder(store.clone()).connect().await.unwrap();
    client
        .signal_repository()
        .inject_e2e_session(wa_core::SessionInjection {
            jid: "123@s.whatsapp.net".to_owned(),
            session: test_signal_session(),
        })
        .await
        .unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let plan = TcTokenIssuePlan {
        storage_jid: "123@s.whatsapp.net".to_owned(),
        issue_jid: "123@s.whatsapp.net".to_owned(),
        timestamp_seconds: sender_timestamp,
    };
    assert!(
        client
            .spawn_tc_token_issue_after_send(&connection, plan)
            .unwrap()
    );
    let privacy_frame = tokio::time::timeout(Duration::from_secs(1), sink_rx.recv())
        .await
        .expect("existing tctoken issue should send a privacy IQ")
        .expect("connection sink should stay open");
    let privacy = decode_inbound_binary_node(&privacy_frame).unwrap().node;
    assert_eq!(privacy.attrs["xmlns"], "privacy");
    assert_eq!(
        test_child(test_child(&privacy, "tokens"), "token").attrs["jid"],
        "123@s.whatsapp.net"
    );

    let notification = BinaryNode::new("notification")
        .with_attr("id", "identity-coalesced")
        .with_attr("from", "123@s.whatsapp.net")
        .with_attr("type", "encrypt")
        .with_content(vec![
            BinaryNode::new("identity").with_content(Bytes::from_static(b"changed")),
        ]);
    let identity_fut = client.handle_identity_change_notification(&connection, &notification);
    tokio::pin!(identity_fut);

    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "encrypt");
            assert_eq!(
                encrypt_key_query_user_attrs(&node),
                vec![("123@s.whatsapp.net".to_owned(), Some("identity".to_owned()))]
            );
            session_response_for_query(&node)
        },
        &mut identity_fut,
    )
    .await;

    assert_eq!(
        identity_fut.await.unwrap(),
        IdentityChangeOutcome::SessionRefreshed {
            token_reissue_scheduled: false
        }
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(100), sink_rx.recv())
            .await
            .is_err(),
        "identity-change reissue should not emit a duplicate privacy IQ while in flight"
    );

    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(
                &BinaryNode::new("iq")
                    .with_attr("id", privacy.attrs["id"].clone())
                    .with_attr("type", "result")
                    .with_content(vec![BinaryNode::new("tokens").with_content(vec![
                        BinaryNode::new("token")
                            .with_attr("jid", "ignored@s.whatsapp.net")
                            .with_attr("t", (sender_timestamp + 1).to_string())
                            .with_attr("type", "trusted_contact")
                            .with_content(Bytes::from_static(b"in-flight-identity-token")),
                    ])]),
            )
            .unwrap(),
        ))
        .await
        .unwrap();

    let mut loaded = None;
    for _ in 0..20 {
        loaded = wa_core::load_tc_token(&store, "123@s.whatsapp.net")
            .await
            .unwrap();
        if loaded
            .as_ref()
            .is_some_and(|record| record.token == Bytes::from_static(b"in-flight-identity-token"))
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let loaded = loaded.unwrap();
    assert_eq!(
        loaded.token,
        Bytes::from_static(b"in-flight-identity-token")
    );
    assert_eq!(loaded.timestamp_seconds, Some(sender_timestamp + 1));
    assert_eq!(loaded.sender_timestamp_seconds, Some(sender_timestamp));
    connection.close().await.unwrap();
}

#[cfg(feature = "memory-store")]
#[tokio::test]
async fn app_state_methods_use_sync_and_dirty_iqs() {
    let store = wa_store::MemoryAuthStore::new();
    let client = Client::builder(store).connect().await.unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection();

    let clean = client
        .clean_dirty_bits(&connection, DirtyBitType::Groups, Some(123))
        .await
        .unwrap();
    assert_eq!(clean.attrs["xmlns"], "urn:xmpp:whatsapp:dirty");
    assert_eq!(clean.attrs["type"], "set");
    let clean_child = test_child(&clean, "clean");
    assert_eq!(clean_child.attrs["type"], "groups");
    assert_eq!(clean_child.attrs["timestamp"], "123");
    let sent_clean = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(sent_clean, clean);

    let sync_fut = client.sync_app_state(
        &connection,
        [
            AppStateCollectionRequest::new(AppStateCollection::RegularHigh, 0),
            AppStateCollectionRequest::new(AppStateCollection::RegularLow, 9)
                .with_return_snapshot(false),
        ],
    );
    tokio::pin!(sync_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "w:sync:app:state");
            assert_eq!(node.attrs["type"], "set");
            let collections = test_children(test_child(&node, "sync"), "collection");
            assert_eq!(collections[0].attrs["name"], "regular_high");
            assert_eq!(collections[0].attrs["version"], "0");
            assert_eq!(collections[0].attrs["return_snapshot"], "true");
            assert_eq!(collections[1].attrs["name"], "regular_low");
            assert_eq!(collections[1].attrs["version"], "9");
            assert_eq!(collections[1].attrs["return_snapshot"], "false");
            empty_result_for(&node)
        },
        &mut sync_fut,
    )
    .await;
    assert_eq!(sync_fut.await.unwrap().attrs["type"], "result");

    let failed_sync_fut = client.sync_app_state(
        &connection,
        [AppStateCollectionRequest::new(
            AppStateCollection::RegularHigh,
            0,
        )],
    );
    tokio::pin!(failed_sync_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "w:sync:app:state");
            error_result_for(&node, "409", "collection conflict")
        },
        &mut failed_sync_fut,
    )
    .await;
    assert!(failed_sync_fut.await.is_err());

    let patch_fut = client.upload_app_state_patch_bytes(
        &connection,
        AppStateCollection::RegularHigh,
        8,
        b"patch".to_vec(),
    );
    tokio::pin!(patch_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "w:sync:app:state");
            let collection = test_child(test_child(&node, "sync"), "collection");
            assert_eq!(collection.attrs["name"], "regular_high");
            assert_eq!(collection.attrs["version"], "8");
            assert_eq!(collection.attrs["return_snapshot"], "false");
            assert_eq!(
                test_node_text(test_child(collection, "patch")).as_deref(),
                Some("patch")
            );
            empty_result_for(&node)
        },
        &mut patch_fut,
    )
    .await;
    assert_eq!(patch_fut.await.unwrap().attrs["type"], "result");

    let failed_patch_fut = client.upload_app_state_patch_bytes(
        &connection,
        AppStateCollection::RegularHigh,
        8,
        b"patch".to_vec(),
    );
    tokio::pin!(failed_patch_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "w:sync:app:state");
            let collection = test_child(test_child(&node, "sync"), "collection");
            assert_eq!(collection.attrs["name"], "regular_high");
            error_result_for(&node, "500", "patch rejected")
        },
        &mut failed_patch_fut,
    )
    .await;
    assert!(failed_patch_fut.await.is_err());
    connection.close().await.unwrap();
}

#[cfg(feature = "memory-store")]
#[tokio::test]
async fn refresh_dirty_groups_fetches_groups_then_cleans_dirty_bit() {
    let store = wa_store::MemoryAuthStore::new();
    let client = Client::builder(store).connect().await.unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection();

    let refresh_fut = client.refresh_dirty_groups(&connection, Some(777));
    tokio::pin!(refresh_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "w:g2");
            assert_eq!(node.attrs["type"], "get");
            assert_eq!(node.attrs["to"], "@g.us");
            let participating = test_child(&node, "participating");
            assert_child(participating, "participants");
            BinaryNode::new("iq")
                .with_attr("id", node.attrs["id"].clone())
                .with_attr("type", "result")
                .with_content(vec![BinaryNode::new("groups").with_content(vec![
                    BinaryNode::new("group")
                        .with_attr("id", "123")
                        .with_attr("subject", "Team")
                        .with_content(vec![BinaryNode::new("participant")
                            .with_attr("jid", "111@s.whatsapp.net")]),
                ])])
        },
        &mut refresh_fut,
    )
    .await;

    let refresh = refresh_fut.await.unwrap();
    assert_eq!(refresh.groups.len(), 1);
    assert_eq!(refresh.groups[0].jid, "123@g.us");
    assert_eq!(refresh.groups[0].subject.as_deref(), Some("Team"));
    assert_eq!(refresh.clean.attrs["xmlns"], "urn:xmpp:whatsapp:dirty");
    let clean_child = test_child(&refresh.clean, "clean");
    assert_eq!(clean_child.attrs["type"], "groups");
    assert_eq!(clean_child.attrs["timestamp"], "777");
    let sent_clean = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(sent_clean, refresh.clean);
    connection.close().await.unwrap();
}

#[cfg(feature = "memory-store")]
#[tokio::test]
async fn refresh_dirty_groups_does_not_clean_after_participating_error() {
    let store = wa_store::MemoryAuthStore::new();
    let client = Client::builder(store).connect().await.unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection();

    let refresh_fut = client.refresh_dirty_groups(&connection, Some(777));
    tokio::pin!(refresh_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "w:g2");
            assert_eq!(node.attrs["type"], "get");
            assert_eq!(node.attrs["to"], "@g.us");
            assert_child(test_child(&node, "participating"), "participants");
            error_result_for(&node, "503", "groups unavailable")
        },
        &mut refresh_fut,
    )
    .await;

    let err = refresh_fut.await.unwrap_err();
    assert!(
        err.to_string()
            .contains("group query failed (503): groups unavailable")
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(50), sink_rx.recv())
            .await
            .is_err(),
        "dirty bit clean stanza must not be sent after failed group refresh"
    );
    connection.close().await.unwrap();
}

#[cfg(feature = "memory-store")]
#[tokio::test]
async fn process_group_dirty_node_refreshes_and_emits_update() {
    let store = wa_store::MemoryAuthStore::new();
    let client = Client::builder(store).connect().await.unwrap();
    let mut events = client.subscribe();
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let dirty = BinaryNode::new("ib").with_content(vec![
        BinaryNode::new("dirty")
            .with_attr("type", "groups")
            .with_attr("timestamp", "900"),
    ]);

    let process_fut = client.process_group_dirty_node(&connection, &dirty);
    tokio::pin!(process_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "w:g2");
            assert_eq!(node.attrs["to"], "@g.us");
            BinaryNode::new("iq")
                .with_attr("id", node.attrs["id"].clone())
                .with_attr("type", "result")
                .with_content(vec![BinaryNode::new("groups").with_content(vec![
                    BinaryNode::new("group")
                        .with_attr("id", "123")
                        .with_attr("subject", "Team")
                        .with_content(vec![
                            BinaryNode::new("participant")
                                .with_attr("jid", "111@s.whatsapp.net")
                                .with_attr("type", "superadmin"),
                            BinaryNode::new("participant")
                                .with_attr("jid", "222@s.whatsapp.net")
                                .with_attr("type", "admin"),
                        ]),
                ])])
        },
        &mut process_fut,
    )
    .await;
    let refresh = process_fut.await.unwrap().unwrap();
    assert_eq!(refresh.groups.len(), 1);
    assert_eq!(refresh.clean.attrs["xmlns"], "urn:xmpp:whatsapp:dirty");
    let sent_clean = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(sent_clean, refresh.clean);
    let update = recv_groups_update_event(&mut events).await;
    assert_eq!(update[0].jid, "123@g.us");
    assert_eq!(update[0].fields["source"], "group_dirty_refresh");
    assert_eq!(update[0].fields["subject"], "Team");
    assert_eq!(
        update[0].fields["participants"],
        "111@s.whatsapp.net,222@s.whatsapp.net"
    );
    assert_eq!(update[0].fields["participants_count"], "2");
    assert_eq!(
        update[0].fields["participants_admins"],
        "222@s.whatsapp.net"
    );
    assert_eq!(update[0].fields["participants_admins_count"], "1");
    assert_eq!(
        update[0].fields["participants_superadmins"],
        "111@s.whatsapp.net"
    );
    assert_eq!(update[0].fields["participants_superadmins_count"], "1");
    connection.close().await.unwrap();
}

#[cfg(feature = "memory-store")]
#[tokio::test]
async fn account_reachout_and_message_capping_use_wmex_queries() {
    let store = wa_store::MemoryAuthStore::new();
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let mut events = client.subscribe();
    let (connection, mut sink_rx, stream_tx) = mock_connection();

    let reachout_fut = client.fetch_account_reachout_timelock(&connection);
    tokio::pin!(reachout_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "w:mex");
            assert_eq!(node.attrs["to"], "s.whatsapp.net");
            let (query_id, variables) = test_wmex_query(&node);
            assert_eq!(query_id, "23983697327930364");
            assert_eq!(variables, serde_json::json!({}));
            wmex_response_for_query(
                &node,
                "xwa2_fetch_account_reachout_timelock",
                r#"{
                    "is_active": true,
                    "time_enforcement_ends": "1700000000",
                    "enforcement_type": "WEB_COMPANION_ONLY"
                }"#,
            )
        },
        &mut reachout_fut,
    )
    .await;
    let reachout = reachout_fut.await.unwrap();
    assert!(reachout.is_active);
    assert_eq!(reachout.time_enforcement_ends, Some(1_700_000_000));
    assert_eq!(
        reachout.enforcement_type,
        wa_core::ReachoutTimelockEnforcementType::WebCompanionOnly
    );
    assert_eq!(
        events.recv().await.unwrap(),
        Event::ReachoutTimelockUpdate(reachout)
    );
    let stored_reachout = store
        .get(
            KeyNamespace::AccountReachoutTimelock,
            wa_core::reachout_timelock_store_key(),
        )
        .await
        .unwrap()
        .unwrap();
    let stored_reachout = wa_core::decode_stored_reachout_timelock_state(&stored_reachout).unwrap();
    assert!(stored_reachout.is_active);
    assert_eq!(
        stored_reachout.enforcement_type,
        wa_core::ReachoutTimelockEnforcementType::WebCompanionOnly
    );

    let capping_fut = client.fetch_message_capping_info(&connection);
    tokio::pin!(capping_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            let (query_id, variables) = test_wmex_query(&node);
            assert_eq!(query_id, "24503548349331633");
            assert_eq!(variables["input"]["type"], "INDIVIDUAL_NEW_CHAT_MSG");
            wmex_response_for_query(
                &node,
                "xwa2_message_capping_info",
                r#"{
                    "total_quota": "50",
                    "used_quota": 12,
                    "capping_status": "FIRST_WARNING"
                }"#,
            )
        },
        &mut capping_fut,
    )
    .await;
    let capping = capping_fut.await.unwrap();
    assert_eq!(capping.total_quota, Some(50));
    assert_eq!(capping.used_quota, Some(12));
    assert_eq!(
        capping.capping_status,
        Some(wa_core::MessageCappingStatus::FirstWarning)
    );
    assert_eq!(
        events.recv().await.unwrap(),
        Event::MessageCappingUpdate(capping)
    );
    let stored_capping = store
        .get(
            KeyNamespace::MessageCappingInfo,
            wa_core::message_capping_info_store_key(),
        )
        .await
        .unwrap()
        .unwrap();
    let stored_capping = wa_core::decode_stored_message_capping_info(&stored_capping).unwrap();
    assert_eq!(stored_capping.total_quota, Some(50));
    assert_eq!(
        stored_capping.capping_status,
        Some(wa_core::MessageCappingStatus::FirstWarning)
    );

    let failed_capping_fut = client.fetch_message_capping_info(&connection);
    tokio::pin!(failed_capping_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            let (query_id, variables) = test_wmex_query(&node);
            assert_eq!(query_id, "24503548349331633");
            assert_eq!(variables["input"]["type"], "INDIVIDUAL_NEW_CHAT_MSG");
            error_result_for(&node, "429", "rate limited")
        },
        &mut failed_capping_fut,
    )
    .await;
    let err = failed_capping_fut.await.unwrap_err();
    assert!(
        err.to_string()
            .contains("WMex query failed (429): rate limited")
    );
    connection.close().await.unwrap();
}

#[cfg(feature = "memory-store")]
#[tokio::test]
async fn refresh_dirty_communities_fetches_communities_then_cleans_group_dirty_bit() {
    let store = wa_store::MemoryAuthStore::new();
    let client = Client::builder(store).connect().await.unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection();

    let refresh_fut = client.refresh_dirty_communities(&connection, Some(888));
    tokio::pin!(refresh_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "w:g2");
            assert_eq!(node.attrs["type"], "get");
            assert_eq!(node.attrs["to"], "@g.us");
            let participating = test_child(&node, "participating");
            assert_child(participating, "participants");
            assert_child(participating, "description");
            BinaryNode::new("iq")
                .with_attr("id", node.attrs["id"].clone())
                .with_attr("type", "result")
                .with_content(vec![BinaryNode::new("communities").with_content(vec![
                    BinaryNode::new("community")
                        .with_attr("id", "123")
                        .with_attr("subject", "Updates")
                        .with_content(vec![
                            BinaryNode::new("parent"),
                            BinaryNode::new("participant")
                                .with_attr("jid", "111@s.whatsapp.net"),
                        ]),
                ])])
        },
        &mut refresh_fut,
    )
    .await;

    let refresh = refresh_fut.await.unwrap();
    assert_eq!(refresh.communities.len(), 1);
    assert_eq!(refresh.communities[0].jid, "123@g.us");
    assert_eq!(refresh.communities[0].subject.as_deref(), Some("Updates"));
    assert!(refresh.communities[0].is_community);
    assert_eq!(refresh.clean.attrs["xmlns"], "urn:xmpp:whatsapp:dirty");
    let clean_child = test_child(&refresh.clean, "clean");
    assert_eq!(clean_child.attrs["type"], "groups");
    assert_eq!(clean_child.attrs["timestamp"], "888");
    let sent_clean = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(sent_clean, refresh.clean);
    connection.close().await.unwrap();
}

#[cfg(feature = "memory-store")]
#[tokio::test]
async fn process_community_dirty_node_refreshes_and_emits_update() {
    let store = wa_store::MemoryAuthStore::new();
    let client = Client::builder(store).connect().await.unwrap();
    let mut events = client.subscribe();
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let dirty = BinaryNode::new("ib").with_content(vec![
        BinaryNode::new("dirty")
            .with_attr("type", "communities")
            .with_attr("timestamp", "901"),
    ]);

    let process_fut = client.process_community_dirty_node(&connection, &dirty);
    tokio::pin!(process_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "w:g2");
            assert_eq!(node.attrs["to"], "@g.us");
            BinaryNode::new("iq")
                .with_attr("id", node.attrs["id"].clone())
                .with_attr("type", "result")
                .with_content(vec![BinaryNode::new("communities").with_content(vec![
                    BinaryNode::new("community")
                        .with_attr("id", "123")
                        .with_attr("subject", "Updates")
                        .with_content(vec![
                            BinaryNode::new("parent"),
                            BinaryNode::new("participant")
                                .with_attr("jid", "111@s.whatsapp.net")
                                .with_attr("type", "admin"),
                        ]),
                ])])
        },
        &mut process_fut,
    )
    .await;
    let refresh = process_fut.await.unwrap().unwrap();
    assert_eq!(refresh.communities.len(), 1);
    assert_eq!(refresh.clean.attrs["xmlns"], "urn:xmpp:whatsapp:dirty");
    let sent_clean = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(sent_clean, refresh.clean);
    let update = recv_groups_update_event(&mut events).await;
    assert_eq!(update[0].jid, "123@g.us");
    assert_eq!(update[0].fields["source"], "community_dirty_refresh");
    assert_eq!(update[0].fields["participants"], "111@s.whatsapp.net");
    assert_eq!(update[0].fields["participants_count"], "1");
    assert_eq!(
        update[0].fields["participants_admins"],
        "111@s.whatsapp.net"
    );
    assert_eq!(update[0].fields["participants_admins_count"], "1");
    connection.close().await.unwrap();
}

#[cfg(feature = "memory-store")]
#[tokio::test]
async fn business_profile_and_catalog_methods_use_business_iqs() {
    let store = wa_store::MemoryAuthStore::new();
    let client = Client::builder(store).connect().await.unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection();

    let profile_fut = client.fetch_business_profile(&connection, "123@c.us");
    tokio::pin!(profile_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "w:biz");
            assert_eq!(node.attrs["to"], "s.whatsapp.net");
            assert_eq!(node.attrs["type"], "get");
            let business_profile = test_child(&node, "business_profile");
            assert_eq!(business_profile.attrs["v"], "244");
            assert_eq!(
                test_child(business_profile, "profile").attrs["jid"],
                "123@s.whatsapp.net"
            );
            BinaryNode::new("iq")
                .with_attr("id", node.attrs["id"].clone())
                .with_attr("type", "result")
                .with_content(vec![BinaryNode::new("business_profile").with_content(
                    vec![
                        BinaryNode::new("profile")
                            .with_attr("jid", "123@s.whatsapp.net")
                            .with_content(vec![
                                BinaryNode::new("address").with_content("1 Main"),
                                BinaryNode::new("description").with_content("Daily goods"),
                                BinaryNode::new("website").with_content("https://example.com"),
                                BinaryNode::new("email").with_content("shop@example.com"),
                                BinaryNode::new("categories").with_content(vec![
                                    BinaryNode::new("category").with_content("Grocery"),
                                ]),
                                BinaryNode::new("business_hours")
                                    .with_attr("timezone", "UTC")
                                    .with_content(vec![
                                        BinaryNode::new("business_hours_config")
                                            .with_attr("day_of_week", "mon")
                                            .with_attr("mode", "specific_hours")
                                            .with_attr("open_time", "540")
                                            .with_attr("close_time", "1020"),
                                    ]),
                            ]),
                    ],
                )])
        },
        &mut profile_fut,
    )
    .await;
    let profile = profile_fut.await.unwrap().unwrap();
    assert_eq!(profile.jid.as_deref(), Some("123@s.whatsapp.net"));
    assert_eq!(profile.description, "Daily goods");
    assert_eq!(profile.websites, vec!["https://example.com"]);
    assert_eq!(profile.category.as_deref(), Some("Grocery"));
    assert_eq!(
        profile.business_hours.unwrap().config[0].close_time,
        Some(1020)
    );

    let update = BusinessProfileUpdate::new()
        .with_address("2 Main")
        .with_email("team@example.com")
        .with_description("Open daily")
        .with_websites(["https://example.com"])
        .with_hours(wa_core::BusinessHours {
            timezone: Some("UTC".to_owned()),
            config: vec![
                wa_core::BusinessHoursConfig::new("mon", "specific_hours")
                    .unwrap()
                    .with_open_close(540, 1020),
            ],
        });
    let update_fut = client.update_business_profile(&connection, update);
    tokio::pin!(update_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "w:biz");
            assert_eq!(node.attrs["to"], "s.whatsapp.net");
            assert_eq!(node.attrs["type"], "set");
            let profile = test_child(&node, "business_profile");
            assert_eq!(profile.attrs["v"], "3");
            assert_eq!(profile.attrs["mutation_type"], "delta");
            assert_eq!(
                test_node_text(test_child(profile, "address")).as_deref(),
                Some("2 Main")
            );
            assert_eq!(
                test_node_text(test_child(profile, "website")).as_deref(),
                Some("https://example.com")
            );
            let hours = test_child(profile, "business_hours");
            assert_eq!(hours.attrs["timezone"], "UTC");
            let config = test_child(hours, "business_hours_config");
            assert_eq!(config.attrs["day_of_week"], "mon");
            assert_eq!(config.attrs["open_time"], "540");
            empty_result_for(&node)
        },
        &mut update_fut,
    )
    .await;
    update_fut.await.unwrap();

    let cover_upload =
        wa_core::BusinessCoverPhotoUpload::new("cover-1", "token-1", 1_700_000_000).unwrap();
    let cover_update_fut = client.update_business_cover_photo(&connection, cover_upload);
    tokio::pin!(cover_update_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "w:biz");
            assert_eq!(node.attrs["to"], "s.whatsapp.net");
            assert_eq!(node.attrs["type"], "set");
            let profile = test_child(&node, "business_profile");
            assert_eq!(profile.attrs["v"], "3");
            assert_eq!(profile.attrs["mutation_type"], "delta");
            let cover = test_child(profile, "cover_photo");
            assert_eq!(cover.attrs["op"], "update");
            assert_eq!(cover.attrs["id"], "cover-1");
            assert_eq!(cover.attrs["token"], "token-1");
            assert_eq!(cover.attrs["ts"], "1700000000");
            empty_result_for(&node)
        },
        &mut cover_update_fut,
    )
    .await;
    assert_eq!(cover_update_fut.await.unwrap(), "cover-1");

    let failed_cover_update = client.update_business_cover_photo(
        &connection,
        wa_core::BusinessCoverPhotoUpload::new("cover-2", "token-2", 1_700_000_001).unwrap(),
    );
    tokio::pin!(failed_cover_update);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            let profile = test_child(&node, "business_profile");
            let cover = test_child(profile, "cover_photo");
            assert_eq!(cover.attrs["op"], "update");
            assert_eq!(cover.attrs["id"], "cover-2");
            BinaryNode::new("iq")
                .with_attr("id", node.attrs["id"].clone())
                .with_attr("type", "error")
                .with_attr("code", "403")
                .with_attr("text", "denied")
        },
        &mut failed_cover_update,
    )
    .await;
    assert!(failed_cover_update.await.is_err());

    let cover_remove_fut = client.remove_business_cover_photo(&connection, "cover-1");
    tokio::pin!(cover_remove_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "w:biz");
            let profile = test_child(&node, "business_profile");
            let cover = test_child(profile, "cover_photo");
            assert_eq!(cover.attrs["op"], "delete");
            assert_eq!(cover.attrs["id"], "cover-1");
            empty_result_for(&node)
        },
        &mut cover_remove_fut,
    )
    .await;
    cover_remove_fut.await.unwrap();

    let catalog_query = BusinessCatalogQuery::new("123@c.us")
        .unwrap()
        .with_limit(25)
        .unwrap()
        .with_cursor("cursor")
        .unwrap();
    let catalog_fut = client.fetch_business_catalog(&connection, catalog_query);
    tokio::pin!(catalog_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "w:biz:catalog");
            assert_eq!(node.attrs["to"], "s.whatsapp.net");
            assert_eq!(node.attrs["type"], "get");
            let catalog = test_child(&node, "product_catalog");
            assert_eq!(catalog.attrs["jid"], "123@s.whatsapp.net");
            assert_eq!(catalog.attrs["allow_shop_source"], "true");
            assert_eq!(
                test_node_text(test_child(catalog, "limit")).as_deref(),
                Some("25")
            );
            assert_eq!(
                test_node_text(test_child(catalog, "after")).as_deref(),
                Some("cursor")
            );
            BinaryNode::new("iq")
                .with_attr("id", node.attrs["id"].clone())
                .with_attr("type", "result")
                .with_content(vec![BinaryNode::new("product_catalog").with_content(vec![
                        BinaryNode::new("product")
                            .with_attr("is_hidden", "true")
                            .with_content(vec![
                                BinaryNode::new("id").with_content("sku-1"),
                                BinaryNode::new("name").with_content("Widget"),
                                BinaryNode::new("retailer_id").with_content("retailer"),
                                BinaryNode::new("description").with_content("Useful"),
                                BinaryNode::new("price").with_content("12345000"),
                                BinaryNode::new("currency").with_content("USD"),
                                BinaryNode::new("media").with_content(vec![
                                    BinaryNode::new("image").with_content(vec![
                                        BinaryNode::new("request_image_url")
                                            .with_content("https://img/small"),
                                        BinaryNode::new("original_image_url")
                                            .with_content("https://img/full"),
                                    ]),
                                ]),
                                BinaryNode::new("status_info").with_content(vec![
                                    BinaryNode::new("status").with_content("APPROVED"),
                                ]),
                            ]),
                        BinaryNode::new("paging").with_content(vec![
                            BinaryNode::new("after").with_content("next"),
                        ]),
                    ])])
        },
        &mut catalog_fut,
    )
    .await;
    let catalog = catalog_fut.await.unwrap();
    assert_eq!(catalog.next_page_cursor.as_deref(), Some("next"));
    assert_eq!(catalog.products.len(), 1);
    assert_eq!(catalog.products[0].id, "sku-1");
    assert_eq!(catalog.products[0].price, 12_345_000);
    assert!(catalog.products[0].is_hidden);
    assert_eq!(
        catalog.products[0].image_urls.requested.as_deref(),
        Some("https://img/small")
    );

    let create = BusinessProductCreate::new("Widget", "Useful", 12_345_000, "USD")
        .unwrap()
        .with_retailer_id("retailer")
        .with_url("https://example.com/widget")
        .with_images([wa_core::BusinessProductImage::new("https://img/uploaded").unwrap()])
        .with_origin(wa_core::BusinessProductOrigin::country_code("US").unwrap())
        .hidden(true);
    let create_fut = client.create_business_product(&connection, create);
    tokio::pin!(create_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "w:biz:catalog");
            assert_eq!(node.attrs["to"], "s.whatsapp.net");
            assert_eq!(node.attrs["type"], "set");
            let add = test_child(&node, "product_catalog_add");
            assert_eq!(add.attrs["v"], "1");
            let product = test_child(add, "product");
            assert_eq!(product.attrs["is_hidden"], "true");
            assert_eq!(
                test_node_text(test_child(product, "name")).as_deref(),
                Some("Widget")
            );
            assert_eq!(
                test_node_text(test_child(product, "price")).as_deref(),
                Some("12345000")
            );
            let image = test_child(test_child(product, "media"), "image");
            assert_eq!(
                test_node_text(test_child(image, "url")).as_deref(),
                Some("https://img/uploaded")
            );
            let compliance = test_child(product, "compliance_info");
            assert_eq!(
                test_node_text(test_child(compliance, "country_code_origin")).as_deref(),
                Some("US")
            );
            business_product_mutation_response(&node, "product_catalog_add")
        },
        &mut create_fut,
    )
    .await;
    let created = create_fut.await.unwrap();
    assert_eq!(created.id, "sku-1");
    assert_eq!(created.name, "Widget");

    let update = BusinessProductUpdate::new()
        .with_name("Widget v2")
        .with_price(22)
        .hidden(false);
    let update_fut = client.update_business_product(&connection, "sku-1", update);
    tokio::pin!(update_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            let edit = test_child(&node, "product_catalog_edit");
            assert_eq!(edit.attrs["v"], "1");
            let product = test_child(edit, "product");
            assert_eq!(
                test_node_text(test_child(product, "id")).as_deref(),
                Some("sku-1")
            );
            assert_eq!(
                test_node_text(test_child(product, "name")).as_deref(),
                Some("Widget v2")
            );
            assert_eq!(product.attrs["is_hidden"], "false");
            business_product_mutation_response(&node, "product_catalog_edit")
        },
        &mut update_fut,
    )
    .await;
    let updated = update_fut.await.unwrap();
    assert_eq!(updated.id, "sku-1");

    let delete_fut = client.delete_business_products(&connection, ["sku-1", "sku-2"]);
    tokio::pin!(delete_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            let delete = test_child(&node, "product_catalog_delete");
            assert_eq!(delete.attrs["v"], "1");
            let products = test_children(delete, "product");
            assert_eq!(products.len(), 2);
            assert_eq!(
                test_node_text(test_child(products[0], "id")).as_deref(),
                Some("sku-1")
            );
            BinaryNode::new("iq")
                .with_attr("id", node.attrs["id"].clone())
                .with_attr("type", "result")
                .with_content(vec![
                    BinaryNode::new("product_catalog_delete").with_attr("deleted_count", "2"),
                ])
        },
        &mut delete_fut,
    )
    .await;
    assert_eq!(delete_fut.await.unwrap(), 2);

    let collections_query = BusinessCollectionsQuery::new("123@c.us")
        .unwrap()
        .with_collection_limit(12)
        .unwrap()
        .with_item_limit(5)
        .unwrap();
    let collections_fut = client.fetch_business_collections(&connection, collections_query);
    tokio::pin!(collections_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "w:biz:catalog");
            assert_eq!(node.attrs["smax_id"], "35");
            let collections = test_child(&node, "collections");
            assert_eq!(collections.attrs["biz_jid"], "123@s.whatsapp.net");
            assert_eq!(
                test_node_text(test_child(collections, "collection_limit")).as_deref(),
                Some("12")
            );
            assert_eq!(
                test_node_text(test_child(collections, "item_limit")).as_deref(),
                Some("5")
            );
            BinaryNode::new("iq")
                .with_attr("id", node.attrs["id"].clone())
                .with_attr("type", "result")
                .with_content(vec![BinaryNode::new("collections").with_content(vec![
                    BinaryNode::new("collection").with_content(vec![
                        BinaryNode::new("id").with_content("collection-1"),
                        BinaryNode::new("name").with_content("Featured"),
                        business_product_node(),
                        BinaryNode::new("status_info").with_content(vec![
                            BinaryNode::new("status").with_content("APPROVED"),
                            BinaryNode::new("can_appeal").with_content("true"),
                        ]),
                    ]),
                ])])
        },
        &mut collections_fut,
    )
    .await;
    let collections = collections_fut.await.unwrap();
    assert_eq!(collections.len(), 1);
    assert_eq!(collections[0].id, "collection-1");
    assert_eq!(collections[0].products[0].id, "sku-1");
    assert!(collections[0].status.can_appeal);

    let order_fut = client.fetch_business_order_details(&connection, "order-1", "token");
    tokio::pin!(order_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "fb:thrift_iq");
            assert_eq!(node.attrs["smax_id"], "5");
            let order = test_child(&node, "order");
            assert_eq!(order.attrs["op"], "get");
            assert_eq!(order.attrs["id"], "order-1");
            assert_eq!(
                test_node_text(test_child(order, "token")).as_deref(),
                Some("token")
            );
            let dimensions = test_child(order, "image_dimensions");
            assert_eq!(
                test_node_text(test_child(dimensions, "width")).as_deref(),
                Some("100")
            );
            BinaryNode::new("iq")
                .with_attr("id", node.attrs["id"].clone())
                .with_attr("type", "result")
                .with_content(vec![BinaryNode::new("order").with_content(vec![
                    BinaryNode::new("product").with_content(vec![
                        BinaryNode::new("id").with_content("sku-1"),
                        BinaryNode::new("name").with_content("Widget"),
                        BinaryNode::new("image").with_content(vec![
                            BinaryNode::new("url").with_content("https://img"),
                        ]),
                        BinaryNode::new("price").with_content("12345000"),
                        BinaryNode::new("currency").with_content("USD"),
                        BinaryNode::new("quantity").with_content("2"),
                    ]),
                    BinaryNode::new("price").with_content(vec![
                        BinaryNode::new("total").with_content("24690000"),
                        BinaryNode::new("currency").with_content("USD"),
                    ]),
                ])])
        },
        &mut order_fut,
    )
    .await;
    let order = order_fut.await.unwrap();
    assert_eq!(order.price.total, 24_690_000);
    assert_eq!(order.products[0].quantity, 2);
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn business_product_mutations_upload_images_before_sending_iqs() {
    let store = wa_store::MemoryAuthStore::new();
    let client = Client::builder(store).connect().await.unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let transport = ClientMediaUploadTransport::default();
    let transfer = wa_core::MediaTransfer::new(transport.clone());

    let create = BusinessProductCreate::new("Widget", "Useful", 12_345_000, "USD").unwrap();
    let create_fut = client.create_business_product_with_image_bytes(
        &connection,
        &transfer,
        create,
        vec![b"image a".as_slice(), b"image b".as_slice()],
        Some("media.test"),
    );
    tokio::pin!(create_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            let add = test_child(&node, "product_catalog_add");
            let product = test_child(add, "product");
            let images = test_children(test_child(product, "media"), "image");
            assert_eq!(images.len(), 2);
            assert_eq!(
                test_node_text(test_child(images[0], "url")).as_deref(),
                Some("https://media.test/client/upload/0")
            );
            assert_eq!(
                test_node_text(test_child(images[1], "url")).as_deref(),
                Some("https://media.test/client/upload/1")
            );
            business_product_mutation_response(&node, "product_catalog_add")
        },
        &mut create_fut,
    )
    .await;
    assert_eq!(create_fut.await.unwrap().id, "sku-1");

    {
        let uploads = transport.uploads.lock().unwrap();
        assert_eq!(uploads.len(), 2);
        assert_eq!(uploads[0].kind, wa_core::MediaKind::ProductCatalogImage);
        assert_eq!(uploads[1].kind, wa_core::MediaKind::ProductCatalogImage);
    }

    let input = test_client_media_path("product-update-image");
    tokio::fs::write(&input, b"updated image").await.unwrap();
    let update = BusinessProductUpdate::new().with_name("Widget v2");
    let update_fut = client.update_business_product_with_image_files(
        &connection,
        &transfer,
        "sku-1",
        update,
        [&input],
        Some("media.test"),
    );
    tokio::pin!(update_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            let edit = test_child(&node, "product_catalog_edit");
            let product = test_child(edit, "product");
            assert_eq!(
                test_node_text(test_child(product, "id")).as_deref(),
                Some("sku-1")
            );
            assert_eq!(
                test_node_text(test_child(product, "name")).as_deref(),
                Some("Widget v2")
            );
            let image = test_child(test_child(product, "media"), "image");
            assert_eq!(
                test_node_text(test_child(image, "url")).as_deref(),
                Some("https://media.test/client/upload/2")
            );
            business_product_mutation_response(&node, "product_catalog_edit")
        },
        &mut update_fut,
    )
    .await;
    assert_eq!(update_fut.await.unwrap().id, "sku-1");
    {
        let uploads = transport.uploads.lock().unwrap();
        assert_eq!(uploads.len(), 3);
        assert_eq!(uploads[2].kind, wa_core::MediaKind::ProductCatalogImage);
    }

    let _ = tokio::fs::remove_file(&input).await;
    connection.close().await.unwrap();
}

#[cfg(feature = "memory-store")]
#[tokio::test]
async fn newsletter_wmex_methods_send_queries_and_parse_results() {
    let store = wa_store::MemoryAuthStore::new();
    let client = Client::builder(store).connect().await.unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection();

    let metadata_fut = client
        .fetch_newsletter_metadata(&connection, NewsletterMetadataLookup::jid("abc@newsletter"));
    tokio::pin!(metadata_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "w:mex");
            assert_eq!(node.attrs["to"], "s.whatsapp.net");
            let (query_id, variables) = test_wmex_query(&node);
            assert_eq!(query_id, "6563316087068696");
            assert_eq!(variables["input"]["key"], "abc@newsletter");
            assert_eq!(variables["input"]["type"], "JID");
            wmex_response_for_query(
                &node,
                "xwa2_newsletter",
                r#"{
                    "result": {
                        "id": "abc@newsletter",
                        "thread_metadata": {
                            "name": { "text": "Updates" },
                            "description": { "text": "Daily" },
                            "subscribers_count": "9"
                        },
                        "viewer_metadata": { "mute": "OFF", "role": "SUBSCRIBER" }
                    }
                }"#,
            )
        },
        &mut metadata_fut,
    )
    .await;
    let metadata = metadata_fut.await.unwrap().unwrap();
    assert_eq!(metadata.id, "abc@newsletter");
    assert_eq!(metadata.name.as_deref(), Some("Updates"));
    assert_eq!(metadata.subscribers, Some(9));

    let follow_fut = client.follow_newsletter(&connection, "abc@newsletter");
    tokio::pin!(follow_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            let (query_id, variables) = test_wmex_query(&node);
            assert_eq!(query_id, "24404358912487870");
            assert_eq!(variables["newsletter_id"], "abc@newsletter");
            wmex_response_for_query(&node, "xwa2_newsletter_join_v2", "{}")
        },
        &mut follow_fut,
    )
    .await;
    follow_fut.await.unwrap();

    let subscribers_fut = client.fetch_newsletter_subscriber_count(&connection, "abc@newsletter");
    tokio::pin!(subscribers_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            let (query_id, _) = test_wmex_query(&node);
            assert_eq!(query_id, "9783111038412085");
            wmex_response_for_query(
                &node,
                "xwa2_newsletter_subscribers",
                r#"{ "subscribers": "12" }"#,
            )
        },
        &mut subscribers_fut,
    )
    .await;
    assert_eq!(subscribers_fut.await.unwrap(), 12);

    let admin_fut = client.fetch_newsletter_admin_count(&connection, "abc@newsletter");
    tokio::pin!(admin_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            let (query_id, _) = test_wmex_query(&node);
            assert_eq!(query_id, "7130823597031706");
            wmex_response_for_query(&node, "xwa2_newsletter_admin", r#"{ "admin_count": 2 }"#)
        },
        &mut admin_fut,
    )
    .await;
    assert_eq!(admin_fut.await.unwrap(), 2);
    connection.close().await.unwrap();
}

#[cfg(feature = "memory-store")]
#[tokio::test]
async fn newsletter_direct_methods_use_newsletter_iqs_and_message_reactions() {
    let store = wa_store::MemoryAuthStore::new();
    let client = Client::builder(store).connect().await.unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection();

    let messages_fut =
        client.fetch_newsletter_messages(&connection, "abc@newsletter", 5, Some(10), Some(20));
    tokio::pin!(messages_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "newsletter");
            assert_eq!(node.attrs["to"], "abc@newsletter");
            assert_eq!(node.attrs["type"], "get");
            let updates = test_child(&node, "message_updates");
            assert_eq!(updates.attrs["count"], "5");
            assert_eq!(updates.attrs["since"], "10");
            assert_eq!(updates.attrs["after"], "20");
            let message = wa_proto::proto::Message {
                conversation: Some("newsletter text".to_owned()),
                ..wa_proto::proto::Message::default()
            };
            BinaryNode::new("iq")
                .with_attr("id", node.attrs["id"].clone())
                .with_attr("type", "result")
                .with_content(vec![BinaryNode::new("message_updates").with_content(vec![
                    BinaryNode::new("message")
                        .with_attr("message_id", "server-1")
                        .with_attr("t", "1700000000")
                        .with_content(vec![
                            BinaryNode::new("plaintext").with_content(message.encode_to_vec()),
                        ]),
                ])])
        },
        &mut messages_fut,
    )
    .await;
    let messages = messages_fut.await.unwrap();
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].key.remote_jid, "abc@newsletter");
    assert_eq!(messages[0].key.id, "server-1");
    assert_eq!(messages[0].timestamp, Some(1_700_000_000));
    assert_eq!(messages[0].fields["kind"], "newsletter");
    assert_eq!(messages[0].fields["payload_kind"], "plaintext");
    assert_eq!(messages[0].fields["source"], "newsletter_fetch");
    let decoded = wa_proto::proto::Message::decode(messages[0].payload.clone().unwrap()).unwrap();
    assert_eq!(decoded.conversation.as_deref(), Some("newsletter text"));

    let live_fut = client.subscribe_newsletter_live_updates(&connection, "abc@newsletter");
    tokio::pin!(live_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "newsletter");
            assert_eq!(node.attrs["type"], "set");
            assert!(test_child(&node, "live_updates").attrs.is_empty());
            BinaryNode::new("iq")
                .with_attr("id", node.attrs["id"].clone())
                .with_attr("type", "result")
                .with_content(vec![
                    BinaryNode::new("live_updates").with_attr("duration", "3600"),
                ])
        },
        &mut live_fut,
    )
    .await;
    assert_eq!(live_fut.await.unwrap().unwrap().duration, "3600");

    let reaction_fut =
        client.react_to_newsletter_message(&connection, "abc@newsletter", "server-1", Some("+"));
    tokio::pin!(reaction_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.tag, "message");
            assert_eq!(node.attrs["to"], "abc@newsletter");
            assert_eq!(node.attrs["type"], "reaction");
            assert_eq!(node.attrs["server_id"], "server-1");
            assert_eq!(test_child(&node, "reaction").attrs["code"], "+");
            BinaryNode::new("message")
                .with_attr("id", node.attrs["id"].clone())
                .with_attr("type", "result")
        },
        &mut reaction_fut,
    )
    .await;
    reaction_fut.await.unwrap();
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn app_state_patch_bundle_upload_uses_encoded_patch_and_previous_version() {
    let store = wa_store::MemoryAuthStore::new();
    let client = Client::builder(store).connect().await.unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let chat_patch = wa_core::build_pin_chat_patch("123@s.whatsapp.net", true, 13).unwrap();
    let key_id = [4u8; 32];
    let key_data = [8u8; 32];
    let mutation =
        wa_core::encrypt_chat_mutation_patch_with_iv(&chat_patch, &key_id, &key_data, &[3u8; 16])
            .unwrap();
    let previous =
        wa_core::AppStatePatchState::new(3, Bytes::from(vec![0u8; wa_core::APP_STATE_HASH_LEN]))
            .unwrap();
    let bundle = wa_core::build_app_state_patch_bundle(
        AppStateCollection::RegularLow,
        &previous,
        &key_id,
        &key_data,
        [mutation],
    )
    .unwrap();
    let upload_fut = client.upload_app_state_patch_bundle(&connection, &bundle);
    tokio::pin!(upload_fut);

    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "w:sync:app:state");
            let collection = test_child(test_child(&node, "sync"), "collection");
            assert_eq!(collection.attrs["name"], "regular_low");
            assert_eq!(collection.attrs["version"], "3");
            assert_eq!(collection.attrs["return_snapshot"], "false");
            assert_eq!(
                test_node_bytes(test_child(collection, "patch")).as_deref(),
                Some(bundle.encoded_patch.as_ref())
            );
            empty_result_for(&node)
        },
        &mut upload_fut,
    )
    .await;
    assert_eq!(upload_fut.await.unwrap().attrs["type"], "result");

    let failed_upload_fut = client.upload_app_state_patch_bundle(&connection, &bundle);
    tokio::pin!(failed_upload_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "w:sync:app:state");
            let collection = test_child(test_child(&node, "sync"), "collection");
            assert_eq!(collection.attrs["name"], "regular_low");
            error_result_for(&node, "500", "patch rejected")
        },
        &mut failed_upload_fut,
    )
    .await;
    assert!(failed_upload_fut.await.is_err());
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn apply_decoded_app_state_patch_persists_state_and_emits_batch() {
    let store = wa_store::MemoryAuthStore::new();
    let client = Client::builder(store).connect().await.unwrap();
    let mut events = client.subscribe();
    let previous = client
        .load_app_state_patch_state(AppStateCollection::Regular)
        .await
        .unwrap();
    assert_eq!(previous.version(), 0);

    let key_id = [4u8; 32];
    let key_data = [8u8; 32];
    let patch =
        wa_core::build_quick_reply_patch(QuickReplyMutation::new("qr-1", "/hi", "hello"), 19)
            .unwrap();
    let mutation =
        wa_core::encrypt_chat_mutation_patch_with_iv(&patch, &key_id, &key_data, &[3u8; 16])
            .unwrap();
    let bundle = wa_core::build_app_state_patch_bundle(
        AppStateCollection::Regular,
        &previous,
        &key_id,
        &key_data,
        [mutation],
    )
    .unwrap();
    let decoded = wa_core::decode_app_state_patch(
        AppStateCollection::Regular,
        &previous,
        &bundle.patch,
        &key_data,
    )
    .unwrap();

    let batch = client
        .apply_decoded_app_state_patch(&decoded, false)
        .await
        .unwrap();
    assert_eq!(batch.quick_replies_update.len(), 1);
    assert_eq!(batch.quick_replies_update[0].id, "qr-1");

    let emitted = recv_batch_event(&mut events).await;
    assert_eq!(emitted.quick_replies_update.len(), 1);
    assert_eq!(emitted.quick_replies_update[0].id, "qr-1");

    let stored = client
        .load_app_state_patch_state(AppStateCollection::Regular)
        .await
        .unwrap();
    assert_eq!(stored.version(), bundle.next_state.version());
    assert_eq!(stored.hash(), bundle.next_state.hash());
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn sync_and_apply_app_state_persists_inline_patches_and_emits_batch() {
    let store = wa_store::MemoryAuthStore::new();
    let client = Client::builder(store).connect().await.unwrap();
    let mut events = client.subscribe();
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let previous = client
        .load_app_state_patch_state(AppStateCollection::Regular)
        .await
        .unwrap();
    let key_id = [4u8; 32];
    let key_data = [8u8; 32];
    let patch =
        wa_core::build_quick_reply_patch(QuickReplyMutation::new("qr-1", "/hi", "hello"), 19)
            .unwrap();
    let mutation =
        wa_core::encrypt_chat_mutation_patch_with_iv(&patch, &key_id, &key_data, &[3u8; 16])
            .unwrap();
    let bundle = wa_core::build_app_state_patch_bundle(
        AppStateCollection::Regular,
        &previous,
        &key_id,
        &key_data,
        [mutation],
    )
    .unwrap();
    let encoded_patch = bundle.patch.encode_to_vec();
    let expected_version = bundle.next_state.version();
    let expected_hash = bundle.next_state.hash().clone();

    let sync_fut = client.sync_and_apply_app_state(
        &connection,
        [AppStateCollectionRequest::new(
            AppStateCollection::Regular,
            0,
        )],
        &key_data,
        false,
    );
    tokio::pin!(sync_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "w:sync:app:state");
            let collection = test_child(test_child(&node, "sync"), "collection");
            assert_eq!(collection.attrs["name"], "regular");
            assert_eq!(collection.attrs["version"], "0");
            BinaryNode::new("iq")
                .with_attr("id", node.attrs["id"].clone())
                .with_attr("type", "result")
                .with_content(vec![BinaryNode::new("sync").with_content(vec![
                    BinaryNode::new("collection")
                        .with_attr("name", "regular")
                        .with_attr("version", expected_version.to_string())
                        .with_content(vec![BinaryNode::new("patches").with_content(vec![
                            BinaryNode::new("patch").with_content(encoded_patch),
                        ])]),
                ])])
        },
        &mut sync_fut,
    )
    .await;

    let outcome = sync_fut.await.unwrap();
    assert_eq!(outcome.batches.len(), 1);
    assert_eq!(outcome.batches[0].quick_replies_update[0].id, "qr-1");
    assert_eq!(outcome.collections.len(), 1);
    assert_eq!(
        outcome.collections[0].collection,
        AppStateCollection::Regular
    );
    assert_eq!(outcome.collections[0].applied_patches, 1);
    assert_eq!(outcome.collections[0].emitted_batches, 1);
    assert!(!outcome.collections[0].snapshot_pending);
    assert!(outcome.pending_snapshots.is_empty());

    let emitted = recv_batch_event(&mut events).await;
    assert_eq!(emitted.quick_replies_update.len(), 1);
    assert_eq!(emitted.quick_replies_update[0].id, "qr-1");

    let stored = client
        .load_app_state_patch_state(AppStateCollection::Regular)
        .await
        .unwrap();
    assert_eq!(stored.version(), expected_version);
    assert_eq!(stored.hash(), &expected_hash);
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn sync_and_apply_app_state_until_current_follows_inline_patch_pages() {
    let store = wa_store::MemoryAuthStore::new();
    let client = Client::builder(store).connect().await.unwrap();
    let mut events = client.subscribe();
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let previous = client
        .load_app_state_patch_state(AppStateCollection::Regular)
        .await
        .unwrap();
    let key_id = [4u8; 32];
    let key_data = [8u8; 32];

    let quick_patch =
        wa_core::build_quick_reply_patch(QuickReplyMutation::new("qr-1", "/hi", "hello"), 19)
            .unwrap();
    let quick_mutation =
        wa_core::encrypt_chat_mutation_patch_with_iv(&quick_patch, &key_id, &key_data, &[3u8; 16])
            .unwrap();
    let quick_bundle = wa_core::build_app_state_patch_bundle(
        AppStateCollection::Regular,
        &previous,
        &key_id,
        &key_data,
        [quick_mutation],
    )
    .unwrap();

    let label_patch =
        wa_core::build_label_edit_patch(LabelEditMutation::new("7", "Important"), 20).unwrap();
    let label_mutation =
        wa_core::encrypt_chat_mutation_patch_with_iv(&label_patch, &key_id, &key_data, &[4u8; 16])
            .unwrap();
    let label_bundle = wa_core::build_app_state_patch_bundle(
        AppStateCollection::Regular,
        &quick_bundle.next_state,
        &key_id,
        &key_data,
        [label_mutation],
    )
    .unwrap();
    let quick_patch_bytes = quick_bundle.patch.encode_to_vec();
    let label_patch_bytes = label_bundle.patch.encode_to_vec();
    let quick_version = quick_bundle.next_state.version();
    let label_version = label_bundle.next_state.version();
    let label_hash = label_bundle.next_state.hash().clone();

    let sync_fut = client.sync_and_apply_app_state_until_current(
        &connection,
        [AppStateCollection::Regular],
        &key_data,
        false,
        4,
    );
    tokio::pin!(sync_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            let collection = test_child(test_child(&node, "sync"), "collection");
            assert_eq!(collection.attrs["name"], "regular");
            assert_eq!(collection.attrs["version"], "0");
            BinaryNode::new("iq")
                .with_attr("id", node.attrs["id"].clone())
                .with_attr("type", "result")
                .with_content(vec![BinaryNode::new("sync").with_content(vec![
                    BinaryNode::new("collection")
                        .with_attr("name", "regular")
                        .with_attr("version", quick_version.to_string())
                        .with_attr("has_more_patches", "true")
                        .with_content(vec![BinaryNode::new("patches").with_content(vec![
                            BinaryNode::new("patch").with_content(quick_patch_bytes),
                        ])]),
                ])])
        },
        &mut sync_fut,
    )
    .await;
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            let collection = test_child(test_child(&node, "sync"), "collection");
            assert_eq!(collection.attrs["name"], "regular");
            assert_eq!(collection.attrs["version"], quick_version.to_string());
            BinaryNode::new("iq")
                .with_attr("id", node.attrs["id"].clone())
                .with_attr("type", "result")
                .with_content(vec![BinaryNode::new("sync").with_content(vec![
                    BinaryNode::new("collection")
                        .with_attr("name", "regular")
                        .with_attr("version", label_version.to_string())
                        .with_content(vec![BinaryNode::new("patches").with_content(vec![
                            BinaryNode::new("patch").with_content(label_patch_bytes),
                        ])]),
                ])])
        },
        &mut sync_fut,
    )
    .await;

    let outcome = sync_fut.await.unwrap();
    assert_eq!(outcome.batches.len(), 2);
    assert_eq!(outcome.batches[0].quick_replies_update[0].id, "qr-1");
    assert_eq!(outcome.batches[1].labels_edit[0].id, "7");
    assert_eq!(outcome.collections.len(), 2);
    assert_eq!(outcome.collections[0].final_version, quick_version);
    assert!(outcome.collections[0].has_more_patches);
    assert_eq!(outcome.collections[1].final_version, label_version);
    assert!(!outcome.collections[1].has_more_patches);

    let first = recv_batch_event(&mut events).await;
    assert_eq!(first.quick_replies_update[0].id, "qr-1");
    let second = recv_batch_event(&mut events).await;
    assert_eq!(second.labels_edit[0].id, "7");

    let stored = client
        .load_app_state_patch_state(AppStateCollection::Regular)
        .await
        .unwrap();
    assert_eq!(stored.version(), label_version);
    assert_eq!(stored.hash(), &label_hash);
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn sync_with_store_keys_blocks_missing_key_then_retries_after_key_arrives() {
    let store = wa_store::MemoryAuthStore::new();
    let client = Client::builder(store).connect().await.unwrap();
    let mut events = client.subscribe();
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let previous = client
        .load_app_state_patch_state(AppStateCollection::Regular)
        .await
        .unwrap();
    let key_id = [4u8; 32];
    let key_data = [8u8; 32];
    let patch =
        wa_core::build_quick_reply_patch(QuickReplyMutation::new("qr-1", "/hi", "hello"), 19)
            .unwrap();
    let mutation =
        wa_core::encrypt_chat_mutation_patch_with_iv(&patch, &key_id, &key_data, &[3u8; 16])
            .unwrap();
    let bundle = wa_core::build_app_state_patch_bundle(
        AppStateCollection::Regular,
        &previous,
        &key_id,
        &key_data,
        [mutation],
    )
    .unwrap();
    let encoded_patch = bundle.patch.encode_to_vec();
    let expected_version = bundle.next_state.version();
    let expected_hash = bundle.next_state.hash().clone();

    let blocked_fut = client.sync_and_apply_app_state_until_current_with_store_keys(
        &connection,
        [AppStateCollection::Regular],
        false,
        3,
    );
    tokio::pin!(blocked_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            let collection = test_child(test_child(&node, "sync"), "collection");
            assert_eq!(collection.attrs["name"], "regular");
            assert_eq!(collection.attrs["version"], "0");
            BinaryNode::new("iq")
                .with_attr("id", node.attrs["id"].clone())
                .with_attr("type", "result")
                .with_content(vec![BinaryNode::new("sync").with_content(vec![
                    BinaryNode::new("collection")
                        .with_attr("name", "regular")
                        .with_attr("version", expected_version.to_string())
                        .with_attr("has_more_patches", "true")
                        .with_content(vec![BinaryNode::new("patches").with_content(vec![
                            BinaryNode::new("patch").with_content(encoded_patch.clone()),
                        ])]),
                ])])
        },
        &mut blocked_fut,
    )
    .await;
    let blocked = blocked_fut.await.unwrap();
    assert!(blocked.batches.is_empty());
    assert_eq!(blocked.blocked.len(), 1);
    assert_eq!(blocked.blocked[0].collection, AppStateCollection::Regular);
    assert_eq!(blocked.blocked[0].key_id, Bytes::copy_from_slice(&key_id));
    assert_eq!(blocked.blocked[0].previous_version, 0);
    assert_eq!(
        client
            .load_app_state_patch_state(AppStateCollection::Regular)
            .await
            .unwrap()
            .version(),
        0
    );

    let key_share_message = wa_proto::proto::Message {
        protocol_message: Some(Box::new(wa_proto::proto::message::ProtocolMessage {
            r#type: Some(
                wa_proto::proto::message::protocol_message::Type::AppStateSyncKeyShare as i32,
            ),
            app_state_sync_key_share: Some(wa_proto::proto::message::AppStateSyncKeyShare {
                keys: vec![wa_proto::proto::message::AppStateSyncKey {
                    key_id: Some(wa_proto::proto::message::AppStateSyncKeyId {
                        key_id: Some(Bytes::copy_from_slice(&key_id)),
                    }),
                    key_data: Some(wa_proto::proto::message::AppStateSyncKeyData {
                        key_data: Some(Bytes::copy_from_slice(&key_data)),
                        fingerprint: None,
                        timestamp: None,
                    }),
                }],
            }),
            ..Default::default()
        })),
        ..Default::default()
    };
    let key_share_event = Event::MessagesUpsert(vec![
        MessageEvent::new(wa_core::MessageEventKey::new(
            "own@s.whatsapp.net",
            "key-share",
            None,
        ))
        .with_payload(Bytes::from(key_share_message.encode_to_vec()))
        .with_field("from_me", "true"),
    ]);
    let key_share_events = [key_share_event];
    let retry_fut =
        client.handle_app_state_sync_key_share_events(&connection, &key_share_events, false, 3);
    tokio::pin!(retry_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            let collection = test_child(test_child(&node, "sync"), "collection");
            assert_eq!(collection.attrs["name"], "regular");
            assert_eq!(collection.attrs["version"], "0");
            BinaryNode::new("iq")
                .with_attr("id", node.attrs["id"].clone())
                .with_attr("type", "result")
                .with_content(vec![BinaryNode::new("sync").with_content(vec![
                    BinaryNode::new("collection")
                        .with_attr("name", "regular")
                        .with_attr("version", expected_version.to_string())
                        .with_content(vec![BinaryNode::new("patches").with_content(vec![
                            BinaryNode::new("patch").with_content(encoded_patch),
                        ])]),
                ])])
        },
        &mut retry_fut,
    )
    .await;
    let applied = retry_fut.await.unwrap();
    assert_eq!(
        client
            .load_app_state_sync_key_data(&key_id)
            .await
            .unwrap()
            .unwrap(),
        key_data.to_vec()
    );
    assert!(applied.blocked.is_empty());
    assert_eq!(applied.batches.len(), 1);
    assert_eq!(applied.batches[0].quick_replies_update[0].id, "qr-1");
    let emitted = recv_batch_event(&mut events).await;
    assert_eq!(emitted.quick_replies_update[0].id, "qr-1");

    let stored = client
        .load_app_state_patch_state(AppStateCollection::Regular)
        .await
        .unwrap();
    assert_eq!(stored.version(), expected_version);
    assert_eq!(stored.hash(), &expected_hash);
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn sync_blocked_app_state_collections_retries_after_key_is_already_stored() {
    let store = wa_store::MemoryAuthStore::new();
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let previous = client
        .load_app_state_patch_state(AppStateCollection::Regular)
        .await
        .unwrap();
    let key_id = [4u8; 32];
    let key_data = [8u8; 32];
    let patch =
        wa_core::build_quick_reply_patch(QuickReplyMutation::new("qr-1", "/hi", "hello"), 19)
            .unwrap();
    let mutation =
        wa_core::encrypt_chat_mutation_patch_with_iv(&patch, &key_id, &key_data, &[3u8; 16])
            .unwrap();
    let bundle = wa_core::build_app_state_patch_bundle(
        AppStateCollection::Regular,
        &previous,
        &key_id,
        &key_data,
        [mutation],
    )
    .unwrap();
    let encoded_patch = bundle.patch.encode_to_vec();
    let expected_version = bundle.next_state.version();
    let expected_hash = bundle.next_state.hash().clone();

    let blocked_fut = client.sync_and_apply_app_state_until_current_with_store_keys(
        &connection,
        [AppStateCollection::Regular],
        false,
        3,
    );
    tokio::pin!(blocked_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            let collection = test_child(test_child(&node, "sync"), "collection");
            assert_eq!(collection.attrs["name"], "regular");
            assert_eq!(collection.attrs["version"], "0");
            BinaryNode::new("iq")
                .with_attr("id", node.attrs["id"].clone())
                .with_attr("type", "result")
                .with_content(vec![BinaryNode::new("sync").with_content(vec![
                    BinaryNode::new("collection")
                        .with_attr("name", "regular")
                        .with_attr("version", expected_version.to_string())
                        .with_attr("has_more_patches", "true")
                        .with_content(vec![BinaryNode::new("patches").with_content(vec![
                            BinaryNode::new("patch").with_content(encoded_patch.clone()),
                        ])]),
                ])])
        },
        &mut blocked_fut,
    )
    .await;
    let blocked = blocked_fut.await.unwrap();
    assert_eq!(blocked.blocked.len(), 1);
    assert_eq!(blocked.blocked[0].collection, AppStateCollection::Regular);
    assert_eq!(blocked.blocked[0].key_id, Bytes::copy_from_slice(&key_id));
    assert!(
        wa_core::load_app_state_blocked_collection(&store, AppStateCollection::Regular)
            .await
            .unwrap()
            .is_some()
    );

    client
        .save_app_state_sync_key_data(&key_id, &key_data)
        .await
        .unwrap();
    let restored_client = Client::builder(store.clone()).connect().await.unwrap();
    let mut events = restored_client.subscribe();
    let retry_fut =
        restored_client.sync_app_state_blocked_collections_with_store_keys(&connection, false, 3);
    tokio::pin!(retry_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            let collection = test_child(test_child(&node, "sync"), "collection");
            assert_eq!(collection.attrs["name"], "regular");
            assert_eq!(collection.attrs["version"], "0");
            BinaryNode::new("iq")
                .with_attr("id", node.attrs["id"].clone())
                .with_attr("type", "result")
                .with_content(vec![BinaryNode::new("sync").with_content(vec![
                    BinaryNode::new("collection")
                        .with_attr("name", "regular")
                        .with_attr("version", expected_version.to_string())
                        .with_content(vec![BinaryNode::new("patches").with_content(vec![
                            BinaryNode::new("patch").with_content(encoded_patch),
                        ])]),
                ])])
        },
        &mut retry_fut,
    )
    .await;
    let applied = retry_fut.await.unwrap();
    assert!(applied.blocked.is_empty());
    assert_eq!(applied.batches.len(), 1);
    assert_eq!(applied.batches[0].quick_replies_update[0].id, "qr-1");
    let emitted = recv_batch_event(&mut events).await;
    assert_eq!(emitted.quick_replies_update[0].id, "qr-1");
    assert!(
        wa_core::load_app_state_blocked_collection(&store, AppStateCollection::Regular)
            .await
            .unwrap()
            .is_none()
    );

    let stored = restored_client
        .load_app_state_patch_state(AppStateCollection::Regular)
        .await
        .unwrap();
    assert_eq!(stored.version(), expected_version);
    assert_eq!(stored.hash(), &expected_hash);
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn key_share_snapshot_recovery_downloads_snapshot_after_unblocking_collection() {
    let store = wa_store::MemoryAuthStore::new();
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let mut events = client.subscribe();
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let key_id = [4u8; 32];
    let key_data = [8u8; 32];
    wa_core::save_app_state_blocked_collection(
        &store,
        &wa_core::AppStateBlockedCollection {
            collection: AppStateCollection::Regular,
            key_id: Bytes::copy_from_slice(&key_id),
            previous_version: 0,
        },
    )
    .await
    .unwrap();

    let patch =
        wa_core::build_quick_reply_patch(QuickReplyMutation::new("qr-1", "/hi", "hello"), 19)
            .unwrap();
    let mutation =
        wa_core::encrypt_chat_mutation_patch_with_iv(&patch, &key_id, &key_data, &[3u8; 16])
            .unwrap();
    let expected_state = AppStatePatchState::empty()
        .apply_hash_mutations_at_version(
            11,
            [wa_core::AppStateHashMutation::from_encrypted(&mutation).unwrap()],
        )
        .unwrap();
    let keys = wa_crypto::derive_app_state_keys(&key_data).unwrap();
    let snapshot_mac = wa_crypto::app_state_snapshot_mac(
        expected_state.hash(),
        11,
        AppStateCollection::Regular.name(),
        &keys,
    )
    .unwrap();
    let snapshot = wa_proto::proto::SyncdSnapshot {
        version: Some(wa_proto::proto::SyncdVersion { version: Some(11) }),
        records: vec![mutation.mutation.record.clone().unwrap()],
        mac: Some(Bytes::copy_from_slice(&snapshot_mac)),
        key_id: Some(wa_proto::proto::KeyId {
            id: Some(Bytes::copy_from_slice(&key_id)),
        }),
    };
    let snapshot_bytes = Bytes::from(snapshot.encode_to_vec());
    let encrypted = wa_crypto::encrypt_media_bytes_with_key(
        &snapshot_bytes,
        wa_crypto::MediaKind::AppState,
        &[6u8; 32],
    )
    .unwrap();
    let snapshot_ref = wa_core::ExternalBlobReference {
        media_key: Some(Bytes::copy_from_slice(encrypted.media_key.expose())),
        direct_path: Some("/app-state/snapshot".to_owned()),
        handle: None,
        file_size_bytes: Some(encrypted.file_length),
        file_sha256: Some(encrypted.file_sha256.clone()),
        file_enc_sha256: Some(encrypted.file_enc_sha256.clone()),
    };
    let snapshot_ref_bytes = Bytes::from(snapshot_ref.encode_to_vec());
    let transport = HistoryDownloadTransport::default();
    transport.add_download(
        "https://snapshot.test/app-state/snapshot",
        encrypted.ciphertext_with_mac.clone(),
    );
    let transfer = wa_core::MediaTransfer::new(transport);
    let key_share_message = wa_proto::proto::Message {
        protocol_message: Some(Box::new(wa_proto::proto::message::ProtocolMessage {
            r#type: Some(
                wa_proto::proto::message::protocol_message::Type::AppStateSyncKeyShare as i32,
            ),
            app_state_sync_key_share: Some(wa_proto::proto::message::AppStateSyncKeyShare {
                keys: vec![wa_proto::proto::message::AppStateSyncKey {
                    key_id: Some(wa_proto::proto::message::AppStateSyncKeyId {
                        key_id: Some(Bytes::copy_from_slice(&key_id)),
                    }),
                    key_data: Some(wa_proto::proto::message::AppStateSyncKeyData {
                        key_data: Some(Bytes::copy_from_slice(&key_data)),
                        fingerprint: None,
                        timestamp: None,
                    }),
                }],
            }),
            ..Default::default()
        })),
        ..Default::default()
    };
    let key_share_event = Event::MessagesUpsert(vec![
        MessageEvent::new(wa_core::MessageEventKey::new(
            "own@s.whatsapp.net",
            "key-share",
            None,
        ))
        .with_payload(Bytes::from(key_share_message.encode_to_vec()))
        .with_field("from_me", "true"),
    ]);
    let key_share_events = [key_share_event];

    let recovery_fut = client.handle_app_state_sync_key_share_events_with_snapshot_recovery(
        &connection,
        &transfer,
        &key_share_events,
        true,
        2,
        Some("snapshot.test"),
    );
    tokio::pin!(recovery_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            let collection = test_child(test_child(&node, "sync"), "collection");
            assert_eq!(collection.attrs["name"], "regular");
            assert_eq!(collection.attrs["version"], "0");
            BinaryNode::new("iq")
                .with_attr("id", node.attrs["id"].clone())
                .with_attr("type", "result")
                .with_content(vec![BinaryNode::new("sync").with_content(vec![
                    BinaryNode::new("collection")
                        .with_attr("name", "regular")
                        .with_attr("version", "0")
                        .with_content(vec![
                            BinaryNode::new("snapshot").with_content(snapshot_ref_bytes),
                        ]),
                ])])
        },
        &mut recovery_fut,
    )
    .await;

    let outcome = recovery_fut.await.unwrap();
    assert!(outcome.blocked.is_empty());
    assert!(outcome.pending_snapshots.is_empty());
    assert_eq!(outcome.batches.len(), 1);
    assert_eq!(outcome.batches[0].quick_replies_update[0].id, "qr-1");
    assert_eq!(outcome.collections.len(), 2);
    assert!(outcome.collections[0].snapshot_pending);
    assert_eq!(outcome.collections[1].final_version, 11);

    let emitted = recv_batch_event(&mut events).await;
    assert_eq!(emitted.quick_replies_update[0].id, "qr-1");
    assert_eq!(
        client
            .load_app_state_sync_key_data(&key_id)
            .await
            .unwrap()
            .unwrap(),
        key_data.to_vec()
    );
    assert!(
        wa_core::load_app_state_blocked_collection(&store, AppStateCollection::Regular)
            .await
            .unwrap()
            .is_none()
    );
    let stored = client
        .load_app_state_patch_state(AppStateCollection::Regular)
        .await
        .unwrap();
    assert_eq!(stored.version(), expected_state.version());
    assert_eq!(stored.hash(), expected_state.hash());
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn sync_recover_and_apply_app_state_until_current_downloads_snapshot() {
    let store = wa_store::MemoryAuthStore::new();
    let client = Client::builder(store).connect().await.unwrap();
    let mut events = client.subscribe();
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let key_id = [4u8; 32];
    let key_data = [8u8; 32];

    let patch =
        wa_core::build_quick_reply_patch(QuickReplyMutation::new("qr-1", "/hi", "hello"), 19)
            .unwrap();
    let mutation =
        wa_core::encrypt_chat_mutation_patch_with_iv(&patch, &key_id, &key_data, &[3u8; 16])
            .unwrap();
    let expected_state = AppStatePatchState::empty()
        .apply_hash_mutations_at_version(
            11,
            [wa_core::AppStateHashMutation::from_encrypted(&mutation).unwrap()],
        )
        .unwrap();
    let keys = wa_crypto::derive_app_state_keys(&key_data).unwrap();
    let snapshot_mac = wa_crypto::app_state_snapshot_mac(
        expected_state.hash(),
        11,
        AppStateCollection::Regular.name(),
        &keys,
    )
    .unwrap();
    let snapshot = wa_proto::proto::SyncdSnapshot {
        version: Some(wa_proto::proto::SyncdVersion { version: Some(11) }),
        records: vec![mutation.mutation.record.clone().unwrap()],
        mac: Some(Bytes::copy_from_slice(&snapshot_mac)),
        key_id: Some(wa_proto::proto::KeyId {
            id: Some(Bytes::copy_from_slice(&key_id)),
        }),
    };
    let snapshot_bytes = Bytes::from(snapshot.encode_to_vec());
    let encrypted = wa_crypto::encrypt_media_bytes_with_key(
        &snapshot_bytes,
        wa_crypto::MediaKind::AppState,
        &[6u8; 32],
    )
    .unwrap();
    let snapshot_ref = wa_core::ExternalBlobReference {
        media_key: Some(Bytes::copy_from_slice(encrypted.media_key.expose())),
        direct_path: Some("/app-state/snapshot".to_owned()),
        handle: None,
        file_size_bytes: Some(encrypted.file_length),
        file_sha256: Some(encrypted.file_sha256.clone()),
        file_enc_sha256: Some(encrypted.file_enc_sha256.clone()),
    };
    let snapshot_ref_bytes = Bytes::from(snapshot_ref.encode_to_vec());
    let transport = HistoryDownloadTransport::default();
    transport.add_download(
        "https://snapshot.test/app-state/snapshot",
        encrypted.ciphertext_with_mac.clone(),
    );
    let transfer = wa_core::MediaTransfer::new(transport);

    let sync_fut = client.sync_recover_and_apply_app_state_until_current(
        &connection,
        &transfer,
        [AppStateCollection::Regular],
        AppStateSyncRecoveryOptions::new(&key_data, 2)
            .with_initial_sync(true)
            .with_fallback_host("snapshot.test"),
    );
    tokio::pin!(sync_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            let collection = test_child(test_child(&node, "sync"), "collection");
            assert_eq!(collection.attrs["name"], "regular");
            assert_eq!(collection.attrs["version"], "0");
            BinaryNode::new("iq")
                .with_attr("id", node.attrs["id"].clone())
                .with_attr("type", "result")
                .with_content(vec![BinaryNode::new("sync").with_content(vec![
                    BinaryNode::new("collection")
                        .with_attr("name", "regular")
                        .with_attr("version", "0")
                        .with_content(vec![
                            BinaryNode::new("snapshot").with_content(snapshot_ref_bytes),
                        ]),
                ])])
        },
        &mut sync_fut,
    )
    .await;

    let outcome = sync_fut.await.unwrap();
    assert!(outcome.pending_snapshots.is_empty());
    assert_eq!(outcome.batches.len(), 1);
    assert_eq!(outcome.batches[0].quick_replies_update[0].id, "qr-1");
    assert_eq!(outcome.collections.len(), 2);
    assert!(outcome.collections[0].snapshot_pending);
    assert_eq!(outcome.collections[1].final_version, 11);
    assert!(!outcome.collections[1].snapshot_pending);

    let emitted = recv_batch_event(&mut events).await;
    assert_eq!(emitted.quick_replies_update.len(), 1);
    assert_eq!(emitted.quick_replies_update[0].id, "qr-1");

    let stored = client
        .load_app_state_patch_state(AppStateCollection::Regular)
        .await
        .unwrap();
    assert_eq!(stored.version(), expected_state.version());
    assert_eq!(stored.hash(), expected_state.hash());
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn sync_recover_and_apply_app_state_until_current_with_store_keys_downloads_snapshot() {
    let store = wa_store::MemoryAuthStore::new();
    let client = Client::builder(store).connect().await.unwrap();
    let mut events = client.subscribe();
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let key_id = [4u8; 32];
    let key_data = [8u8; 32];
    client
        .save_app_state_sync_key_data(&key_id, &key_data)
        .await
        .unwrap();

    let patch =
        wa_core::build_quick_reply_patch(QuickReplyMutation::new("qr-1", "/hi", "hello"), 19)
            .unwrap();
    let mutation =
        wa_core::encrypt_chat_mutation_patch_with_iv(&patch, &key_id, &key_data, &[3u8; 16])
            .unwrap();
    let expected_state = AppStatePatchState::empty()
        .apply_hash_mutations_at_version(
            11,
            [wa_core::AppStateHashMutation::from_encrypted(&mutation).unwrap()],
        )
        .unwrap();
    let keys = wa_crypto::derive_app_state_keys(&key_data).unwrap();
    let snapshot_mac = wa_crypto::app_state_snapshot_mac(
        expected_state.hash(),
        11,
        AppStateCollection::Regular.name(),
        &keys,
    )
    .unwrap();
    let snapshot = wa_proto::proto::SyncdSnapshot {
        version: Some(wa_proto::proto::SyncdVersion { version: Some(11) }),
        records: vec![mutation.mutation.record.clone().unwrap()],
        mac: Some(Bytes::copy_from_slice(&snapshot_mac)),
        key_id: Some(wa_proto::proto::KeyId {
            id: Some(Bytes::copy_from_slice(&key_id)),
        }),
    };
    let snapshot_bytes = Bytes::from(snapshot.encode_to_vec());
    let encrypted = wa_crypto::encrypt_media_bytes_with_key(
        &snapshot_bytes,
        wa_crypto::MediaKind::AppState,
        &[6u8; 32],
    )
    .unwrap();
    let snapshot_ref = wa_core::ExternalBlobReference {
        media_key: Some(Bytes::copy_from_slice(encrypted.media_key.expose())),
        direct_path: Some("/app-state/snapshot".to_owned()),
        handle: None,
        file_size_bytes: Some(encrypted.file_length),
        file_sha256: Some(encrypted.file_sha256.clone()),
        file_enc_sha256: Some(encrypted.file_enc_sha256.clone()),
    };
    let snapshot_ref_bytes = Bytes::from(snapshot_ref.encode_to_vec());
    let transport = HistoryDownloadTransport::default();
    transport.add_download(
        "https://snapshot.test/app-state/snapshot",
        encrypted.ciphertext_with_mac.clone(),
    );
    let transfer = wa_core::MediaTransfer::new(transport);

    let sync_fut = client.sync_recover_and_apply_app_state_until_current_with_store_keys(
        &connection,
        &transfer,
        [AppStateCollection::Regular],
        true,
        2,
        Some("snapshot.test"),
    );
    tokio::pin!(sync_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            let collection = test_child(test_child(&node, "sync"), "collection");
            assert_eq!(collection.attrs["name"], "regular");
            assert_eq!(collection.attrs["version"], "0");
            BinaryNode::new("iq")
                .with_attr("id", node.attrs["id"].clone())
                .with_attr("type", "result")
                .with_content(vec![BinaryNode::new("sync").with_content(vec![
                    BinaryNode::new("collection")
                        .with_attr("name", "regular")
                        .with_attr("version", "0")
                        .with_content(vec![
                            BinaryNode::new("snapshot").with_content(snapshot_ref_bytes),
                        ]),
                ])])
        },
        &mut sync_fut,
    )
    .await;

    let outcome = sync_fut.await.unwrap();
    assert!(outcome.blocked.is_empty());
    assert!(outcome.pending_snapshots.is_empty());
    assert_eq!(outcome.batches.len(), 1);
    assert_eq!(outcome.batches[0].quick_replies_update[0].id, "qr-1");
    assert_eq!(outcome.collections.len(), 2);
    assert!(outcome.collections[0].snapshot_pending);
    assert_eq!(outcome.collections[1].final_version, 11);
    assert!(!outcome.collections[1].snapshot_pending);

    let emitted = recv_batch_event(&mut events).await;
    assert_eq!(emitted.quick_replies_update.len(), 1);
    assert_eq!(emitted.quick_replies_update[0].id, "qr-1");

    let stored = client
        .load_app_state_patch_state(AppStateCollection::Regular)
        .await
        .unwrap();
    assert_eq!(stored.version(), expected_state.version());
    assert_eq!(stored.hash(), expected_state.hash());
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn high_level_chat_mutation_methods_build_and_upload_patch_bundles() {
    let store = wa_store::MemoryAuthStore::new();
    let client = Client::builder(store).connect().await.unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let key_id = [4u8; 32];
    let key_data = [8u8; 32];
    let previous =
        wa_core::AppStatePatchState::new(3, Bytes::from(vec![0u8; wa_core::APP_STATE_HASH_LEN]))
            .unwrap();
    let upload = AppStateMutationUpload::new(&previous, &key_id, &key_data);

    let pin_fut = client.set_chat_pinned(&connection, "123@s.whatsapp.net", true, 13, upload);
    tokio::pin!(pin_fut);
    let sent_frame = tokio::select! {
        _ = &mut pin_fut => panic!("pin chat mutation completed before mock response"),
        sent = sink_rx.recv() => sent.unwrap(),
    };
    let node = decode_inbound_binary_node(&sent_frame).unwrap().node;
    assert_eq!(node.attrs["xmlns"], "w:sync:app:state");
    let collection = test_child(test_child(&node, "sync"), "collection");
    assert_eq!(collection.attrs["name"], "regular_low");
    assert_eq!(collection.attrs["version"], "3");
    let patch_bytes = test_node_bytes(test_child(collection, "patch")).unwrap();
    let patch = wa_proto::proto::SyncdPatch::decode(patch_bytes.as_ref()).unwrap();
    assert_eq!(
        patch.version.as_ref().and_then(|version| version.version),
        Some(4)
    );
    assert_eq!(patch.mutations.len(), 1);
    assert_eq!(
        patch.key_id.as_ref().and_then(|key| key.id.as_deref()),
        Some(key_id.as_slice())
    );
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&empty_result_for(&node)).unwrap(),
        ))
        .await
        .unwrap();

    let bundle = pin_fut.await.unwrap();
    assert_eq!(bundle.collection, AppStateCollection::RegularLow);
    assert_eq!(bundle.previous_version, 3);
    assert_eq!(bundle.next_state.version(), 4);
    assert_eq!(bundle.patch.mutations.len(), 1);

    let delete_fut = client.delete_chat(&connection, "123@s.whatsapp.net", None, 15, upload);
    tokio::pin!(delete_fut);
    let (node, patch) = recv_app_state_upload(
        &mut sink_rx,
        &mut delete_fut,
        "delete chat",
        AppStateCollection::RegularHigh,
        3,
    )
    .await;
    assert_eq!(
        patch.version.as_ref().and_then(|version| version.version),
        Some(4)
    );
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&empty_result_for(&node)).unwrap(),
        ))
        .await
        .unwrap();
    let bundle = delete_fut.await.unwrap();
    assert_eq!(bundle.collection, AppStateCollection::RegularHigh);
    assert_eq!(bundle.previous_version, 3);
    assert_eq!(bundle.next_state.version(), 4);

    let key = MessageKey {
        remote_jid: Some("123@s.whatsapp.net".to_owned()),
        from_me: Some(false),
        id: Some("msg-1".to_owned()),
        participant: None,
    };
    let star_fut = client.set_message_starred(&connection, key, true, 16, upload);
    tokio::pin!(star_fut);
    let (node, patch) = recv_app_state_upload(
        &mut sink_rx,
        &mut star_fut,
        "star message",
        AppStateCollection::RegularLow,
        3,
    )
    .await;
    assert_eq!(patch.mutations.len(), 1);
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&empty_result_for(&node)).unwrap(),
        ))
        .await
        .unwrap();
    let bundle = star_fut.await.unwrap();
    assert_eq!(bundle.collection, AppStateCollection::RegularLow);
    assert_eq!(bundle.next_state.version(), 4);

    let profile_name_fut = client.update_profile_name(&connection, "Agent", 17, upload);
    tokio::pin!(profile_name_fut);
    let (node, patch) = recv_app_state_upload(
        &mut sink_rx,
        &mut profile_name_fut,
        "profile name",
        AppStateCollection::CriticalBlock,
        3,
    )
    .await;
    assert_eq!(patch.mutations.len(), 1);
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&empty_result_for(&node)).unwrap(),
        ))
        .await
        .unwrap();
    let bundle = profile_name_fut.await.unwrap();
    assert_eq!(bundle.collection, AppStateCollection::CriticalBlock);
    assert_eq!(bundle.next_state.version(), 4);

    let contact = ContactSyncAction::new()
        .with_full_name("Agent Smith")
        .with_pn_jid("123@s.whatsapp.net");
    let contact_fut = client.update_contact(&connection, "123@s.whatsapp.net", contact, 18, upload);
    tokio::pin!(contact_fut);
    let (node, patch) = recv_app_state_upload(
        &mut sink_rx,
        &mut contact_fut,
        "contact",
        AppStateCollection::CriticalUnblockLow,
        3,
    )
    .await;
    assert_eq!(patch.mutations.len(), 1);
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&empty_result_for(&node)).unwrap(),
        ))
        .await
        .unwrap();
    let bundle = contact_fut.await.unwrap();
    assert_eq!(bundle.collection, AppStateCollection::CriticalUnblockLow);
    assert_eq!(bundle.next_state.version(), 4);

    let remove_contact_fut = client.remove_contact(&connection, "123@s.whatsapp.net", 19, upload);
    tokio::pin!(remove_contact_fut);
    let (node, patch) = recv_app_state_upload(
        &mut sink_rx,
        &mut remove_contact_fut,
        "remove contact",
        AppStateCollection::CriticalUnblockLow,
        3,
    )
    .await;
    assert_eq!(
        patch.mutations[0].operation,
        Some(wa_core::AppStatePatchOperation::Remove.proto_value())
    );
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&empty_result_for(&node)).unwrap(),
        ))
        .await
        .unwrap();
    let bundle = remove_contact_fut.await.unwrap();
    assert_eq!(bundle.collection, AppStateCollection::CriticalUnblockLow);

    let quick_reply = QuickReplyMutation::new("1700000000", "/hi", "hello");
    let quick_reply_fut = client.upsert_quick_reply(&connection, quick_reply, 20, upload);
    tokio::pin!(quick_reply_fut);
    let (node, patch) = recv_app_state_upload(
        &mut sink_rx,
        &mut quick_reply_fut,
        "quick reply",
        AppStateCollection::Regular,
        3,
    )
    .await;
    assert_eq!(patch.mutations.len(), 1);
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&empty_result_for(&node)).unwrap(),
        ))
        .await
        .unwrap();
    assert_eq!(
        quick_reply_fut.await.unwrap().collection,
        AppStateCollection::Regular
    );

    let delete_quick_reply_fut = client.delete_quick_reply(&connection, "1700000000", 21, upload);
    tokio::pin!(delete_quick_reply_fut);
    let (node, patch) = recv_app_state_upload(
        &mut sink_rx,
        &mut delete_quick_reply_fut,
        "delete quick reply",
        AppStateCollection::Regular,
        3,
    )
    .await;
    assert_eq!(patch.mutations.len(), 1);
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&empty_result_for(&node)).unwrap(),
        ))
        .await
        .unwrap();
    assert_eq!(
        delete_quick_reply_fut.await.unwrap().collection,
        AppStateCollection::Regular
    );

    let label = LabelEditMutation::new("7", "Important");
    let label_fut = client.upsert_label(&connection, label, 22, upload);
    tokio::pin!(label_fut);
    let (node, patch) = recv_app_state_upload(
        &mut sink_rx,
        &mut label_fut,
        "label",
        AppStateCollection::Regular,
        3,
    )
    .await;
    assert_eq!(patch.mutations.len(), 1);
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&empty_result_for(&node)).unwrap(),
        ))
        .await
        .unwrap();
    assert_eq!(
        label_fut.await.unwrap().collection,
        AppStateCollection::Regular
    );

    let delete_label_fut = client.delete_label(&connection, "7", 23, upload);
    tokio::pin!(delete_label_fut);
    let (node, patch) = recv_app_state_upload(
        &mut sink_rx,
        &mut delete_label_fut,
        "delete label",
        AppStateCollection::Regular,
        3,
    )
    .await;
    assert_eq!(patch.mutations.len(), 1);
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&empty_result_for(&node)).unwrap(),
        ))
        .await
        .unwrap();
    assert_eq!(
        delete_label_fut.await.unwrap().collection,
        AppStateCollection::Regular
    );

    let chat_label_fut =
        client.set_chat_label(&connection, "123@s.whatsapp.net", "7", true, 24, upload);
    tokio::pin!(chat_label_fut);
    let (node, patch) = recv_app_state_upload(
        &mut sink_rx,
        &mut chat_label_fut,
        "chat label",
        AppStateCollection::Regular,
        3,
    )
    .await;
    assert_eq!(patch.mutations.len(), 1);
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&empty_result_for(&node)).unwrap(),
        ))
        .await
        .unwrap();
    assert_eq!(
        chat_label_fut.await.unwrap().collection,
        AppStateCollection::Regular
    );

    let message_label_fut = client.set_message_label(
        &connection,
        MessageLabelTarget::new("123@s.whatsapp.net", "7", "msg-1"),
        false,
        25,
        upload,
    );
    tokio::pin!(message_label_fut);
    let (node, patch) = recv_app_state_upload(
        &mut sink_rx,
        &mut message_label_fut,
        "message label",
        AppStateCollection::Regular,
        3,
    )
    .await;
    assert_eq!(patch.mutations.len(), 1);
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&empty_result_for(&node)).unwrap(),
        ))
        .await
        .unwrap();
    assert_eq!(
        message_label_fut.await.unwrap().collection,
        AppStateCollection::Regular
    );

    let failed_pin_fut =
        client.set_chat_pinned(&connection, "123@s.whatsapp.net", false, 14, upload);
    tokio::pin!(failed_pin_fut);
    let sent_frame = tokio::select! {
        _ = &mut failed_pin_fut => panic!("failed pin chat mutation completed before mock response"),
        sent = sink_rx.recv() => sent.unwrap(),
    };
    let node = decode_inbound_binary_node(&sent_frame).unwrap().node;
    assert_eq!(node.attrs["xmlns"], "w:sync:app:state");
    let collection = test_child(test_child(&node, "sync"), "collection");
    assert_eq!(collection.attrs["name"], "regular_low");
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&error_result_for(&node, "500", "patch rejected")).unwrap(),
        ))
        .await
        .unwrap();
    assert!(failed_pin_fut.await.is_err());
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn chat_mutation_upload_and_apply_persists_state_and_events() {
    let store = wa_store::MemoryAuthStore::new();
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let mut events = client.subscribe();
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let key_id = [4u8; 32];
    let key_data = [8u8; 32];
    let previous =
        wa_core::AppStatePatchState::new(3, Bytes::from(vec![0u8; wa_core::APP_STATE_HASH_LEN]))
            .unwrap();
    let upload = AppStateMutationUpload::new(&previous, &key_id, &key_data);

    let apply_fut =
        client.set_chat_pinned_and_apply(&connection, "123@s.whatsapp.net", true, 13, upload);
    tokio::pin!(apply_fut);
    let (node, patch) = recv_app_state_upload(
        &mut sink_rx,
        &mut apply_fut,
        "pin chat apply",
        AppStateCollection::RegularLow,
        3,
    )
    .await;
    assert_eq!(patch.mutations.len(), 1);
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(&empty_result_for(&node)).unwrap(),
        ))
        .await
        .unwrap();

    let outcome = apply_fut.await.unwrap();
    assert_eq!(outcome.bundle.collection, AppStateCollection::RegularLow);
    assert_eq!(outcome.bundle.previous_version, 3);
    assert_eq!(outcome.bundle.next_state.version(), 4);
    assert_eq!(outcome.batch.pending_items(), 1);
    assert_eq!(outcome.batch.chats_update.len(), 1);
    assert_eq!(outcome.batch.chats_update[0].jid, "123@s.whatsapp.net");
    assert_eq!(outcome.batch.chats_update[0].fields["pinned"], "13");

    let emitted = recv_batch_event(&mut events).await;
    assert_eq!(emitted.chats_update.len(), 1);
    assert_eq!(emitted.chats_update[0].jid, "123@s.whatsapp.net");
    assert_eq!(emitted.chats_update[0].fields["pinned"], "13");

    let stored_state = client
        .load_app_state_patch_state(AppStateCollection::RegularLow)
        .await
        .unwrap();
    assert_eq!(stored_state.version(), outcome.bundle.next_state.version());
    assert_eq!(stored_state.hash(), outcome.bundle.next_state.hash());

    let stored_chat = store
        .get(KeyNamespace::ChatEvent, "123@s.whatsapp.net")
        .await
        .unwrap()
        .unwrap();
    let stored_chat = wa_core::decode_stored_chat_event(&stored_chat).unwrap();
    assert_eq!(stored_chat.jid, "123@s.whatsapp.net");
    assert_eq!(stored_chat.fields["pinned"], "13");
    connection.close().await.unwrap();
}

#[cfg(feature = "memory-store")]
#[tokio::test]
async fn group_metadata_create_and_participants_use_group_iqs() {
    let store = wa_store::MemoryAuthStore::new();
    let client = Client::builder(store).connect().await.unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection();

    let metadata_fut = client.fetch_group_metadata(&connection, "123@g.us");
    tokio::pin!(metadata_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "w:g2");
            assert_eq!(node.attrs["to"], "123@g.us");
            assert_eq!(node.attrs["type"], "get");
            assert_eq!(test_child(&node, "query").attrs["request"], "interactive");
            group_metadata_response(&node, "123", "Team")
        },
        &mut metadata_fut,
    )
    .await;
    let metadata = metadata_fut.await.unwrap();
    assert_eq!(metadata.jid, "123@g.us");
    assert_eq!(metadata.subject.as_deref(), Some("Team"));

    let create_fut = client.create_group(
        &connection,
        "New team",
        ["111@s.whatsapp.net", "222@s.whatsapp.net"],
    );
    tokio::pin!(create_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "w:g2");
            assert_eq!(node.attrs["to"], "@g.us");
            assert_eq!(node.attrs["type"], "set");
            let create = test_child(&node, "create");
            assert_eq!(create.attrs["subject"], "New team");
            assert!(!create.attrs["key"].is_empty());
            assert_eq!(test_children(create, "participant").len(), 2);
            group_metadata_response(&node, "456", "New team")
        },
        &mut create_fut,
    )
    .await;
    assert_eq!(create_fut.await.unwrap().jid, "456@g.us");

    let participants_fut = client.update_group_participants(
        &connection,
        "123@g.us",
        GroupParticipantAction::Add,
        ["333@s.whatsapp.net", "444@s.whatsapp.net"],
    );
    tokio::pin!(participants_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["to"], "123@g.us");
            let add = test_child(&node, "add");
            assert_eq!(test_children(add, "participant").len(), 2);
            BinaryNode::new("iq")
                .with_attr("id", node.attrs["id"].clone())
                .with_attr("type", "result")
                .with_attr("from", "123@g.us")
                .with_content(vec![BinaryNode::new("add").with_content(vec![
                    BinaryNode::new("participant").with_attr("jid", "333@s.whatsapp.net"),
                    BinaryNode::new("participant")
                        .with_attr("jid", "444@s.whatsapp.net")
                        .with_attr("error", "403"),
                ])])
        },
        &mut participants_fut,
    )
    .await;
    let result = participants_fut.await.unwrap();
    assert_eq!(result.group_jid.as_deref(), Some("123@g.us"));
    assert_eq!(result.action, GroupParticipantAction::Add);
    assert_eq!(result.participants[0].status, 200);
    assert_eq!(result.participants[1].error_code, Some(403));
    assert_eq!(
        result.participants[1]
            .content
            .as_ref()
            .and_then(|node| node.attrs.get("error"))
            .map(String::as_str),
        Some("403")
    );

    let leave_fut = client.leave_group(&connection, "123@g.us");
    tokio::pin!(leave_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "w:g2");
            assert_eq!(node.attrs["to"], "@g.us");
            assert_eq!(node.attrs["type"], "set");
            let leave = test_child(&node, "leave");
            assert_eq!(test_child(leave, "group").attrs["id"], "123@g.us");
            empty_result_for(&node)
        },
        &mut leave_fut,
    )
    .await;
    leave_fut.await.unwrap();

    let subject_fut = client.set_group_subject(&connection, "123@g.us", "Renamed");
    tokio::pin!(subject_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "w:g2");
            assert_eq!(node.attrs["to"], "123@g.us");
            assert_eq!(node.attrs["type"], "set");
            assert_eq!(
                test_node_text(test_child(&node, "subject")).as_deref(),
                Some("Renamed")
            );
            empty_result_for(&node)
        },
        &mut subject_fut,
    )
    .await;
    subject_fut.await.unwrap();
    connection.close().await.unwrap();
}

#[cfg(feature = "memory-store")]
#[tokio::test]
async fn group_description_invites_settings_and_join_requests_use_group_iqs() {
    let store = wa_store::MemoryAuthStore::new();
    let client = Client::builder(store).connect().await.unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection();

    let description_fut =
        client.set_group_description(&connection, "123@g.us", Some("New description"));
    tokio::pin!(description_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["type"], "get");
            group_metadata_response_with_description(&node, "123", "Team", Some("old-desc"))
        },
        &mut description_fut,
    )
    .await;
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["type"], "set");
            let description = test_child(&node, "description");
            assert_eq!(description.attrs["prev"], "old-desc");
            assert!(!description.attrs["id"].is_empty());
            assert_eq!(
                test_child(description, "body")
                    .content
                    .as_ref()
                    .and_then(|content| {
                        match content {
                            wa_binary::BinaryNodeContent::Bytes(bytes) => {
                                std::str::from_utf8(bytes).ok().map(str::to_owned)
                            }
                            wa_binary::BinaryNodeContent::Text(text) => Some(text.clone()),
                            wa_binary::BinaryNodeContent::Nodes(_) => None,
                        }
                    }),
                Some("New description".to_owned())
            );
            BinaryNode::new("iq")
                .with_attr("id", node.attrs["id"].clone())
                .with_attr("type", "result")
        },
        &mut description_fut,
    )
    .await;
    description_fut.await.unwrap();

    let invite_fut = client.fetch_group_invite_code(&connection, "123@g.us");
    tokio::pin!(invite_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["type"], "get");
            assert!(test_child(&node, "invite").attrs.is_empty());
            BinaryNode::new("iq")
                .with_attr("id", node.attrs["id"].clone())
                .with_attr("type", "result")
                .with_content(vec![
                    BinaryNode::new("invite").with_attr("code", "invite-code"),
                ])
        },
        &mut invite_fut,
    )
    .await;
    assert_eq!(invite_fut.await.unwrap().as_deref(), Some("invite-code"));

    let accept_fut = client.accept_group_invite(&connection, "invite-code");
    tokio::pin!(accept_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["to"], "@g.us");
            assert_eq!(test_child(&node, "invite").attrs["code"], "invite-code");
            BinaryNode::new("iq")
                .with_attr("id", node.attrs["id"].clone())
                .with_attr("type", "result")
                .with_content(vec![BinaryNode::new("group").with_attr("jid", "789@g.us")])
        },
        &mut accept_fut,
    )
    .await;
    assert_eq!(accept_fut.await.unwrap().as_deref(), Some("789@g.us"));

    let invite_v4 =
        GroupInviteV4::new("123@g.us", "v4-code", 1_700_000_000, "222@s.whatsapp.net").unwrap();
    let accept_v4_fut = client.accept_group_invite_v4(&connection, &invite_v4);
    tokio::pin!(accept_v4_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["to"], "123@g.us");
            assert_eq!(node.attrs["type"], "set");
            let accept = test_child(&node, "accept");
            assert_eq!(accept.attrs["code"], "v4-code");
            assert_eq!(accept.attrs["expiration"], "1700000000");
            assert_eq!(accept.attrs["admin"], "222@s.whatsapp.net");
            empty_result_for(&node).with_attr("from", "123@g.us")
        },
        &mut accept_v4_fut,
    )
    .await;
    assert_eq!(accept_v4_fut.await.unwrap().as_deref(), Some("123@g.us"));

    let revoke_v4_fut =
        client.revoke_group_invite_v4(&connection, "123@g.us", "333@s.whatsapp.net");
    tokio::pin!(revoke_v4_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["to"], "123@g.us");
            assert_eq!(node.attrs["type"], "set");
            let revoke = test_child(&node, "revoke");
            assert_eq!(
                test_child(revoke, "participant").attrs["jid"],
                "333@s.whatsapp.net"
            );
            empty_result_for(&node)
        },
        &mut revoke_v4_fut,
    )
    .await;
    assert!(revoke_v4_fut.await.unwrap());

    let setting_fut =
        client.update_group_setting(&connection, "123@g.us", GroupSettingUpdate::Locked);
    tokio::pin!(setting_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["type"], "set");
            assert!(test_child(&node, "locked").attrs.is_empty());
            BinaryNode::new("iq")
                .with_attr("id", node.attrs["id"].clone())
                .with_attr("type", "result")
        },
        &mut setting_fut,
    )
    .await;
    setting_fut.await.unwrap();

    let failed_setting_fut =
        client.update_group_setting(&connection, "123@g.us", GroupSettingUpdate::Locked);
    tokio::pin!(failed_setting_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["type"], "set");
            assert!(test_child(&node, "locked").attrs.is_empty());
            error_result_for(&node, "403", "denied")
        },
        &mut failed_setting_fut,
    )
    .await;
    assert!(failed_setting_fut.await.is_err());

    let ephemeral_fut = client.set_group_ephemeral(&connection, "123@g.us", 86400);
    tokio::pin!(ephemeral_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["type"], "set");
            assert_eq!(test_child(&node, "ephemeral").attrs["expiration"], "86400");
            empty_result_for(&node)
        },
        &mut ephemeral_fut,
    )
    .await;
    ephemeral_fut.await.unwrap();

    let member_add_fut =
        client.set_group_member_add_mode(&connection, "123@g.us", GroupMemberAddMode::AllMembers);
    tokio::pin!(member_add_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["type"], "set");
            assert_eq!(
                test_node_text(test_child(&node, "member_add_mode")).as_deref(),
                Some("all_member_add")
            );
            empty_result_for(&node)
        },
        &mut member_add_fut,
    )
    .await;
    member_add_fut.await.unwrap();

    let join_approval_fut =
        client.set_group_join_approval_mode(&connection, "123@g.us", GroupJoinApprovalMode::On);
    tokio::pin!(join_approval_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["type"], "set");
            let mode = test_child(&node, "membership_approval_mode");
            assert_eq!(test_child(mode, "group_join").attrs["state"], "on");
            empty_result_for(&node)
        },
        &mut join_approval_fut,
    )
    .await;
    join_approval_fut.await.unwrap();

    let join_list_fut = client.fetch_group_join_requests(&connection, "123@g.us");
    tokio::pin!(join_list_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["type"], "get");
            assert!(
                test_child(&node, "membership_approval_requests")
                    .attrs
                    .is_empty()
            );
            BinaryNode::new("iq")
                .with_attr("id", node.attrs["id"].clone())
                .with_attr("type", "result")
                .with_content(vec![
                    BinaryNode::new("membership_approval_requests").with_content(vec![
                        BinaryNode::new("membership_approval_request")
                            .with_attr("jid", "555@s.whatsapp.net")
                            .with_attr("phoneNumber", "555@s.whatsapp.net")
                            .with_attr("lidJid", "555@lid")
                            .with_attr("participantUsername", "five")
                            .with_attr("t", "44")
                            .with_attr("requestMethod", "invite_link"),
                    ]),
                ])
        },
        &mut join_list_fut,
    )
    .await;
    let requests = join_list_fut.await.unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].jid, "555@s.whatsapp.net");
    assert_eq!(
        requests[0].phone_number.as_deref(),
        Some("555@s.whatsapp.net")
    );
    assert_eq!(requests[0].lid.as_deref(), Some("555@lid"));
    assert_eq!(requests[0].username.as_deref(), Some("five"));
    assert_eq!(requests[0].requested_at, Some(44));
    assert_eq!(requests[0].request_method.as_deref(), Some("invite_link"));

    let join_update_fut = client.update_group_join_requests(
        &connection,
        "123@g.us",
        GroupJoinRequestAction::Approve,
        ["555@s.whatsapp.net"],
    );
    tokio::pin!(join_update_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["type"], "set");
            let wrapper = test_child(&node, "membership_requests_action");
            let approve = test_child(wrapper, "approve");
            assert_eq!(test_children(approve, "participant").len(), 1);
            BinaryNode::new("iq")
                .with_attr("id", node.attrs["id"].clone())
                .with_attr("type", "result")
                .with_content(vec![
                    BinaryNode::new("membership_requests_action").with_content(vec![
                        BinaryNode::new("approve").with_content(vec![
                            BinaryNode::new("participant").with_attr("jid", "555@s.whatsapp.net"),
                        ]),
                    ]),
                ])
        },
        &mut join_update_fut,
    )
    .await;
    let update = join_update_fut.await.unwrap();
    assert_eq!(update.action, GroupJoinRequestAction::Approve);
    assert_eq!(update.participants[0].status, 200);
    connection.close().await.unwrap();
}

#[cfg(feature = "memory-store")]
#[tokio::test]
async fn accept_group_invite_v4_with_message_events_emits_update_and_stub() {
    let store = wa_store::MemoryAuthStore::new();
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let mut events = client.subscribe();
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let invite =
        GroupInviteV4::new("123@g.us", "v4-code", 1_700_000_000, "222@s.whatsapp.net").unwrap();
    let invite_key = wa_core::MessageEventKey::new("222@s.whatsapp.net", "invite-msg", None);

    let accept_fut = client.accept_group_invite_v4_with_message_events(
        &connection,
        &invite,
        Some(invite_key.clone()),
    );
    tokio::pin!(accept_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["to"], "123@g.us");
            assert_eq!(node.attrs["type"], "set");
            let accept = test_child(&node, "accept");
            assert_eq!(accept.attrs["code"], "v4-code");
            assert_eq!(accept.attrs["expiration"], "1700000000");
            assert_eq!(accept.attrs["admin"], "222@s.whatsapp.net");
            empty_result_for(&node).with_attr("from", "123@g.us")
        },
        &mut accept_fut,
    )
    .await;
    assert_eq!(accept_fut.await.unwrap().as_deref(), Some("123@g.us"));

    let batch = recv_batch_event(&mut events).await;
    assert_eq!(batch.messages_update.len(), 1);
    assert_eq!(batch.messages_update[0].key, invite_key);
    assert_eq!(
        batch.messages_update[0].fields["source"],
        "group_invite_v4_accept"
    );
    assert_eq!(batch.messages_update[0].fields["invite_status"], "accepted");
    assert_eq!(batch.messages_update[0].fields["invite_code"], "");
    assert_eq!(batch.messages_update[0].fields["invite_expiration"], "0");
    assert_eq!(batch.messages_upsert.len(), 1);
    let stub = &batch.messages_upsert[0];
    assert_eq!(stub.key.remote_jid, "123@g.us");
    assert_eq!(stub.key.participant.as_deref(), Some("222@s.whatsapp.net"));
    assert_eq!(stub.fields["source"], "group_invite_v4_accept");
    assert_eq!(stub.fields["kind"], "notify");
    assert_eq!(stub.fields["stub_type"], "group_participant_add");
    assert_eq!(stub.fields["participant"], "222@s.whatsapp.net");

    let stored_update_key = wa_core::message_event_store_key(&invite_key);
    let stored_update = store
        .get(KeyNamespace::MessageUpdate, &stored_update_key)
        .await
        .unwrap()
        .unwrap();
    let stored_update = wa_core::decode_stored_message_update(&stored_update).unwrap();
    assert_eq!(stored_update, batch.messages_update[0]);

    let stored_stub_key = wa_core::message_event_store_key(&stub.key);
    let stored_stub = store
        .get(KeyNamespace::MessageEvent, &stored_stub_key)
        .await
        .unwrap()
        .unwrap();
    let stored_stub = wa_core::decode_stored_message_event(&stored_stub).unwrap();
    assert_eq!(stored_stub, *stub);
    connection.close().await.unwrap();
}

#[cfg(feature = "memory-store")]
#[tokio::test]
async fn persisted_message_event_batch_merges_updates_and_deletes() {
    let store = wa_store::MemoryAuthStore::new();
    let key = wa_core::MessageEventKey::new("123@s.whatsapp.net", "msg-1", None);
    let store_key = wa_core::message_event_store_key(&key);
    let upsert = MessageEvent::new(key.clone())
        .with_timestamp(10)
        .with_field("status", "pending");

    persist_message_event_batch(
        &store,
        &wa_core::EventBatch {
            messages_upsert: vec![upsert],
            ..wa_core::EventBatch::default()
        },
    )
    .await
    .unwrap();

    persist_message_event_batch(
        &store,
        &wa_core::EventBatch {
            messages_update: vec![
                wa_core::MessageUpdate::new(key.clone())
                    .with_timestamp(11)
                    .with_field("status", "server_ack"),
            ],
            ..wa_core::EventBatch::default()
        },
    )
    .await
    .unwrap();

    let stored = store
        .get(KeyNamespace::MessageEvent, &store_key)
        .await
        .unwrap()
        .unwrap();
    let stored = wa_core::decode_stored_message_event(&stored).unwrap();
    assert_eq!(stored.timestamp, Some(11));
    assert_eq!(stored.fields["status"], "server_ack");
    assert_eq!(
        store
            .get(KeyNamespace::MessageUpdate, &store_key)
            .await
            .unwrap(),
        None
    );

    let late_key = wa_core::MessageEventKey::new("123@s.whatsapp.net", "msg-2", None);
    let late_store_key = wa_core::message_event_store_key(&late_key);
    persist_message_event_batch(
        &store,
        &wa_core::EventBatch {
            messages_update: vec![
                wa_core::MessageUpdate::new(late_key.clone())
                    .with_timestamp(21)
                    .with_field("status", "server_ack"),
            ],
            ..wa_core::EventBatch::default()
        },
    )
    .await
    .unwrap();
    assert!(
        store
            .get(KeyNamespace::MessageUpdate, &late_store_key)
            .await
            .unwrap()
            .is_some()
    );
    persist_message_event_batch(
        &store,
        &wa_core::EventBatch {
            messages_upsert: vec![
                MessageEvent::new(late_key.clone())
                    .with_timestamp(20)
                    .with_field("body", "hello"),
            ],
            ..wa_core::EventBatch::default()
        },
    )
    .await
    .unwrap();
    let stored = store
        .get(KeyNamespace::MessageEvent, &late_store_key)
        .await
        .unwrap()
        .unwrap();
    let stored = wa_core::decode_stored_message_event(&stored).unwrap();
    assert_eq!(stored.timestamp, Some(21));
    assert_eq!(stored.fields["body"], "hello");
    assert_eq!(stored.fields["status"], "server_ack");
    assert_eq!(
        store
            .get(KeyNamespace::MessageUpdate, &late_store_key)
            .await
            .unwrap(),
        None
    );

    persist_message_event_batch(
        &store,
        &wa_core::EventBatch {
            messages_delete: vec![key],
            ..wa_core::EventBatch::default()
        },
    )
    .await
    .unwrap();

    assert_eq!(
        store
            .get(KeyNamespace::MessageEvent, &store_key)
            .await
            .unwrap(),
        None
    );
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn receive_persistence_stores_history_chat_contact_and_group_state() {
    let store = wa_store::MemoryAuthStore::new();
    let history = wa_core::HistorySetEvent {
        chats: vec![
            wa_core::ChatEvent::new("123@s.whatsapp.net").with_field("display_name", "Alice"),
        ],
        contacts: vec![
            wa_core::ContactEvent::new("123@s.whatsapp.net").with_field("name", "Alice"),
        ],
        messages: Vec::new(),
        is_latest: true,
    };
    let group = wa_core::GroupUpdateEvent::new("456@g.us").with_field("subject", "Team");
    let batch = wa_core::EventBatch {
        history: Some(history),
        groups_update: vec![group],
        ..wa_core::EventBatch::default()
    };

    persist_receive_events(&store, &[Event::Batch(Box::new(batch))])
        .await
        .unwrap();

    let chat = store
        .get(KeyNamespace::ChatEvent, "123@s.whatsapp.net")
        .await
        .unwrap()
        .unwrap();
    let chat = wa_core::decode_stored_chat_event(&chat).unwrap();
    assert_eq!(chat.fields["display_name"], "Alice");

    let contact = store
        .get(KeyNamespace::ContactEvent, "123@s.whatsapp.net")
        .await
        .unwrap()
        .unwrap();
    let contact = wa_core::decode_stored_contact_event(&contact).unwrap();
    assert_eq!(contact.fields["name"], "Alice");

    let group = store
        .get(KeyNamespace::GroupEvent, "456@g.us")
        .await
        .unwrap()
        .unwrap();
    let group = wa_core::decode_stored_group_event(&group).unwrap();
    assert_eq!(group.fields["subject"], "Team");

    persist_receive_events(
        &store,
        &[
            Event::ChatsUpdate(vec![
                wa_core::ChatEvent::new("123@s.whatsapp.net").with_field("unread_count", "3"),
            ]),
            Event::ContactsUpdate(vec![
                wa_core::ContactEvent::new("123@s.whatsapp.net").with_field("notify", "A"),
            ]),
            Event::GroupsUpdate(vec![
                wa_core::GroupUpdateEvent::new("456@g.us").with_field("announce", "false"),
            ]),
        ],
    )
    .await
    .unwrap();

    let chat = store
        .get(KeyNamespace::ChatEvent, "123@s.whatsapp.net")
        .await
        .unwrap()
        .unwrap();
    let chat = wa_core::decode_stored_chat_event(&chat).unwrap();
    assert_eq!(chat.fields["display_name"], "Alice");
    assert_eq!(chat.fields["unread_count"], "3");

    let contact = store
        .get(KeyNamespace::ContactEvent, "123@s.whatsapp.net")
        .await
        .unwrap()
        .unwrap();
    let contact = wa_core::decode_stored_contact_event(&contact).unwrap();
    assert_eq!(contact.fields["name"], "Alice");
    assert_eq!(contact.fields["notify"], "A");

    let group = store
        .get(KeyNamespace::GroupEvent, "456@g.us")
        .await
        .unwrap()
        .unwrap();
    let group = wa_core::decode_stored_group_event(&group).unwrap();
    assert_eq!(group.fields["subject"], "Team");
    assert_eq!(group.fields["announce"], "false");

    persist_receive_events(
        &store,
        &[
            Event::ChatsDelete(vec!["123@s.whatsapp.net".to_owned()]),
            Event::ContactsDelete(vec!["123@s.whatsapp.net".to_owned()]),
        ],
    )
    .await
    .unwrap();

    assert_eq!(
        store
            .get(KeyNamespace::ChatEvent, "123@s.whatsapp.net")
            .await
            .unwrap(),
        None
    );
    assert_eq!(
        store
            .get(KeyNamespace::ContactEvent, "123@s.whatsapp.net")
            .await
            .unwrap(),
        None
    );
    assert!(
        store
            .get(KeyNamespace::GroupEvent, "456@g.us")
            .await
            .unwrap()
            .is_some()
    );
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn receive_persistence_stores_business_notification_state() {
    let store = wa_store::MemoryAuthStore::new();
    let notification = wa_core::BusinessNotificationEvent::new(
        "server@s.whatsapp.net",
        "biz-1",
        "product_catalog",
    )
    .with_field("attr_version", "1");
    let store_key = wa_core::business_notification_event_store_key(&notification);
    let batch = wa_core::EventBatch {
        business_notifications: vec![notification],
        ..wa_core::EventBatch::default()
    };

    persist_receive_events(&store, &[Event::Batch(Box::new(batch))])
        .await
        .unwrap();

    let stored = store
        .get(KeyNamespace::BusinessNotificationEvent, &store_key)
        .await
        .unwrap()
        .unwrap();
    let stored = wa_core::decode_stored_business_notification_event(&stored).unwrap();
    assert_eq!(stored.from, "server@s.whatsapp.net");
    assert_eq!(stored.notification_id, "biz-1");
    assert_eq!(stored.event_type, "product_catalog");
    assert_eq!(stored.fields["attr_version"], "1");

    persist_receive_events(
        &store,
        &[Event::BusinessNotificationUpdate(vec![
            wa_core::BusinessNotificationEvent::new(
                "server@s.whatsapp.net",
                "biz-1",
                "product_catalog",
            )
            .with_field("child_product_id", "sku-1"),
        ])],
    )
    .await
    .unwrap();

    let stored = store
        .get(KeyNamespace::BusinessNotificationEvent, &store_key)
        .await
        .unwrap()
        .unwrap();
    let stored = wa_core::decode_stored_business_notification_event(&stored).unwrap();
    assert_eq!(stored.fields["attr_version"], "1");
    assert_eq!(stored.fields["child_product_id"], "sku-1");
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn receive_persistence_stores_history_poll_and_event_updates() {
    let store = wa_store::MemoryAuthStore::new();
    let poll_key = wa_proto::proto::MessageKey {
        remote_jid: Some("123@g.us".to_owned()),
        from_me: Some(false),
        id: Some("poll-creation-1".to_owned()),
        participant: Some("456@s.whatsapp.net".to_owned()),
    };
    let event_key = wa_proto::proto::MessageKey {
        remote_jid: Some("123@g.us".to_owned()),
        from_me: Some(false),
        id: Some("event-creation-1".to_owned()),
        participant: Some("456@s.whatsapp.net".to_owned()),
    };
    let history = wa_core::HistorySync {
        sync_type: wa_core::HistorySyncType::InitialBootstrap as i32,
        conversations: vec![wa_proto::proto::Conversation {
            id: "123@g.us".to_owned(),
            messages: vec![wa_proto::proto::HistorySyncMsg {
                msg_order_id: Some(9),
                message: Some(wa_proto::proto::WebMessageInfo {
                    key: Some(wa_proto::proto::MessageKey {
                        remote_jid: Some("123@g.us".to_owned()),
                        from_me: Some(false),
                        id: Some("history-wrapper-1".to_owned()),
                        participant: Some("789@s.whatsapp.net".to_owned()),
                    }),
                    message_timestamp: Some(1_700_000_010),
                    poll_updates: vec![wa_proto::proto::PollUpdate {
                        poll_update_message_key: Some(poll_key),
                        vote: Some(wa_proto::proto::message::PollVoteMessage {
                            selected_options: vec![Bytes::from_static(b"option-a")],
                        }),
                        sender_timestamp_ms: Some(1_700_000_011_123),
                        server_timestamp_ms: Some(1_700_000_011_456),
                        unread: Some(true),
                    }],
                    event_responses: vec![wa_proto::proto::EventResponse {
                        event_response_message_key: Some(event_key),
                        timestamp_ms: Some(1_700_000_012_123),
                        event_response_message: Some(
                            wa_proto::proto::message::EventResponseMessage {
                                response: Some(
                                    wa_proto::proto::message::event_response_message::EventResponseType::Going
                                        as i32,
                                ),
                                timestamp_ms: Some(1_700_000_012_456),
                                extra_guest_count: Some(2),
                            },
                        ),
                        unread: Some(false),
                    }],
                    ..Default::default()
                }),
            }],
            ..Default::default()
        }],
        ..Default::default()
    };
    let processed =
        wa_core::process_history_sync(&history, wa_core::HistorySyncProcessConfig::default())
            .unwrap();
    assert_eq!(processed.batch.messages_update.len(), 2);
    let batch = processed.batch;

    persist_receive_events(&store, &[Event::Batch(Box::new(batch.clone()))])
        .await
        .unwrap();

    let history_key =
        wa_core::message_event_store_key(&batch.history.as_ref().unwrap().messages[0].key);
    let stored_history = store
        .get(KeyNamespace::MessageEvent, &history_key)
        .await
        .unwrap()
        .unwrap();
    let stored_history = wa_core::decode_stored_message_event(&stored_history).unwrap();
    assert_eq!(stored_history.key.id, "history-wrapper-1");

    for update in batch.messages_update {
        let stored_key = wa_core::message_event_store_key(&update.key);
        let stored_update = store
            .get(KeyNamespace::MessageUpdate, &stored_key)
            .await
            .unwrap()
            .unwrap();
        let stored_update = wa_core::decode_stored_message_update(&stored_update).unwrap();
        assert_eq!(stored_update, update);
    }
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn receive_persistence_stores_history_message_add_on_updates() {
    let store = wa_store::MemoryAuthStore::new();
    let poll_key = wa_proto::proto::MessageKey {
        remote_jid: Some("123@g.us".to_owned()),
        from_me: Some(false),
        id: Some("poll-creation-1".to_owned()),
        participant: Some("456@s.whatsapp.net".to_owned()),
    };
    let history = wa_core::HistorySync {
        sync_type: wa_core::HistorySyncType::InitialBootstrap as i32,
        conversations: vec![wa_proto::proto::Conversation {
            id: "123@g.us".to_owned(),
            messages: vec![wa_proto::proto::HistorySyncMsg {
                msg_order_id: Some(10),
                message: Some(wa_proto::proto::WebMessageInfo {
                    key: Some(wa_proto::proto::MessageKey {
                        remote_jid: Some("123@g.us".to_owned()),
                        from_me: Some(false),
                        id: Some("history-wrapper-2".to_owned()),
                        participant: Some("789@s.whatsapp.net".to_owned()),
                    }),
                    message_timestamp: Some(1_700_000_013),
                    message_add_ons: vec![wa_proto::proto::MessageAddOn {
                        message_add_on_type: Some(
                            wa_proto::proto::message_add_on::MessageAddOnType::PollUpdate as i32,
                        ),
                        sender_timestamp_ms: Some(1_700_000_014_123),
                        message_add_on_key: Some(poll_key),
                        legacy_message: Some(wa_proto::proto::LegacyMessage {
                            poll_vote: Some(wa_proto::proto::message::PollVoteMessage {
                                selected_options: vec![Bytes::from_static(b"option-a")],
                            }),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }],
                    ..Default::default()
                }),
            }],
            ..Default::default()
        }],
        ..Default::default()
    };
    let processed =
        wa_core::process_history_sync(&history, wa_core::HistorySyncProcessConfig::default())
            .unwrap();
    assert_eq!(processed.batch.messages_update.len(), 1);
    let batch = processed.batch;

    persist_receive_events(&store, &[Event::Batch(Box::new(batch.clone()))])
        .await
        .unwrap();

    let update = batch.messages_update[0].clone();
    let stored_key = wa_core::message_event_store_key(&update.key);
    let stored_update = store
        .get(KeyNamespace::MessageUpdate, &stored_key)
        .await
        .unwrap()
        .unwrap();
    let stored_update = wa_core::decode_stored_message_update(&stored_update).unwrap();
    assert_eq!(stored_update, update);
    assert_eq!(stored_update.fields["source"], "history_message_add_on");
    assert_eq!(stored_update.fields["add_on_type"], "poll_update");
    assert_eq!(stored_update.fields["selected_options_count"], "1");
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn receive_persistence_stores_history_reactions() {
    let store = wa_store::MemoryAuthStore::new();
    let target_key = wa_proto::proto::MessageKey {
        remote_jid: Some("123@g.us".to_owned()),
        from_me: Some(false),
        id: Some("target-1".to_owned()),
        participant: Some("456@s.whatsapp.net".to_owned()),
    };
    let history = wa_core::HistorySync {
        sync_type: wa_core::HistorySyncType::InitialBootstrap as i32,
        conversations: vec![wa_proto::proto::Conversation {
            id: "123@g.us".to_owned(),
            messages: vec![wa_proto::proto::HistorySyncMsg {
                msg_order_id: Some(11),
                message: Some(wa_proto::proto::WebMessageInfo {
                    key: Some(target_key),
                    message_timestamp: Some(1_700_000_016),
                    reactions: vec![wa_proto::proto::Reaction {
                        key: Some(wa_proto::proto::MessageKey {
                            remote_jid: Some("123@g.us".to_owned()),
                            from_me: Some(false),
                            id: Some("reaction-1".to_owned()),
                            participant: Some("789@s.whatsapp.net".to_owned()),
                        }),
                        text: Some("+".to_owned()),
                        sender_timestamp_ms: Some(1_700_000_016_123),
                        unread: Some(true),
                        ..Default::default()
                    }],
                    ..Default::default()
                }),
            }],
            ..Default::default()
        }],
        ..Default::default()
    };
    let processed =
        wa_core::process_history_sync(&history, wa_core::HistorySyncProcessConfig::default())
            .unwrap();
    assert_eq!(processed.batch.reactions_update.len(), 1);
    let batch = processed.batch;

    persist_receive_events(&store, &[Event::Batch(Box::new(batch.clone()))])
        .await
        .unwrap();

    let history_key =
        wa_core::message_event_store_key(&batch.history.as_ref().unwrap().messages[0].key);
    let stored_history = store
        .get(KeyNamespace::MessageEvent, &history_key)
        .await
        .unwrap()
        .unwrap();
    let stored_history = wa_core::decode_stored_message_event(&stored_history).unwrap();
    assert_eq!(stored_history.key.id, "target-1");

    let reaction = batch.reactions_update[0].clone();
    let reaction_key = wa_core::reaction_event_store_key(&reaction);
    let stored_reaction = store
        .get(KeyNamespace::ReactionEvent, &reaction_key)
        .await
        .unwrap()
        .unwrap();
    let stored_reaction = wa_core::decode_stored_reaction_event(&stored_reaction).unwrap();
    assert_eq!(stored_reaction, reaction);
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn receive_persistence_stores_receipts_and_reactions() {
    let store = wa_store::MemoryAuthStore::new();
    let key = wa_core::MessageEventKey::new(
        "123@s.whatsapp.net",
        "msg-1",
        Some("456@s.whatsapp.net".to_owned()),
    );
    let receipt = wa_core::ReceiptEvent::new(key.clone(), "read")
        .with_participant("789@s.whatsapp.net")
        .with_timestamp(1_700_000_004);
    let reaction = wa_core::ReactionEvent::new(key, "789@s.whatsapp.net")
        .with_text("+")
        .with_timestamp(1_700_000_005);
    let batch = wa_core::EventBatch {
        receipts_update: vec![receipt.clone()],
        reactions_update: vec![reaction.clone()],
        ..wa_core::EventBatch::default()
    };

    persist_receive_events(&store, &[Event::Batch(Box::new(batch))])
        .await
        .unwrap();

    let receipt_key = wa_core::receipt_event_store_key(&receipt);
    let stored_receipt = store
        .get(KeyNamespace::ReceiptEvent, &receipt_key)
        .await
        .unwrap()
        .unwrap();
    let stored_receipt = wa_core::decode_stored_receipt_event(&stored_receipt).unwrap();
    assert_eq!(stored_receipt, receipt);

    let reaction_key = wa_core::reaction_event_store_key(&reaction);
    let stored_reaction = store
        .get(KeyNamespace::ReactionEvent, &reaction_key)
        .await
        .unwrap()
        .unwrap();
    let stored_reaction = wa_core::decode_stored_reaction_event(&stored_reaction).unwrap();
    assert_eq!(stored_reaction, reaction);

    let replacement =
        wa_core::ReactionEvent::new(stored_reaction.key.clone(), "789@s.whatsapp.net")
            .with_text("-")
            .with_timestamp(1_700_000_006);
    persist_receive_events(&store, &[Event::ReactionsUpdate(vec![replacement.clone()])])
        .await
        .unwrap();
    let stored_reaction = store
        .get(KeyNamespace::ReactionEvent, &reaction_key)
        .await
        .unwrap()
        .unwrap();
    let stored_reaction = wa_core::decode_stored_reaction_event(&stored_reaction).unwrap();
    assert_eq!(stored_reaction, replacement);
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn receive_persistence_stores_presence_events() {
    let store = wa_store::MemoryAuthStore::new();
    let presence = wa_core::PresenceEvent::new("123@g.us", "composing")
        .with_participant("456@s.whatsapp.net")
        .with_timestamp(1_700_000_008)
        .with_field("child_composing_media", "audio");
    let batch = wa_core::EventBatch {
        presence_update: vec![presence.clone()],
        ..wa_core::EventBatch::default()
    };

    persist_receive_events(&store, &[Event::Batch(Box::new(batch))])
        .await
        .unwrap();

    let store_key = wa_core::presence_event_store_key(&presence);
    let stored = store
        .get(KeyNamespace::PresenceEvent, &store_key)
        .await
        .unwrap()
        .unwrap();
    let stored = wa_core::decode_stored_presence_event(&stored).unwrap();
    assert_eq!(stored, presence);

    let replacement = wa_core::PresenceEvent::new("123@g.us", "paused")
        .with_participant("456@s.whatsapp.net")
        .with_timestamp(1_700_000_009);
    persist_receive_events(&store, &[Event::PresenceUpdate(vec![replacement.clone()])])
        .await
        .unwrap();
    let stored = store
        .get(KeyNamespace::PresenceEvent, &store_key)
        .await
        .unwrap()
        .unwrap();
    let stored = wa_core::decode_stored_presence_event(&stored).unwrap();
    assert_eq!(stored, replacement);
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn receive_persistence_stores_newsletter_events() {
    let store = wa_store::MemoryAuthStore::new();
    let reaction = wa_core::NewsletterReactionEvent::new("abc@newsletter", "server-1")
        .with_code("+")
        .with_count(4);
    let view = wa_core::NewsletterViewEvent::new("abc@newsletter", "server-1", 42);
    let participant = wa_core::NewsletterParticipantUpdateEvent::new(
        "abc@newsletter",
        "111@s.whatsapp.net",
        "222@s.whatsapp.net",
        "promote",
        "ADMIN",
    );
    let settings =
        wa_core::NewsletterSettingsUpdateEvent::new("abc@newsletter").with_field("name", "Updates");

    persist_receive_events(
        &store,
        &[
            Event::NewsletterReactionUpdate(vec![reaction.clone()]),
            Event::NewsletterViewUpdate(vec![view.clone()]),
            Event::NewsletterParticipantsUpdate(vec![participant.clone()]),
            Event::NewsletterSettingsUpdate(vec![settings.clone()]),
        ],
    )
    .await
    .unwrap();

    let reaction_key = wa_core::newsletter_reaction_event_store_key(&reaction);
    let stored_reaction = store
        .get(KeyNamespace::NewsletterReactionEvent, &reaction_key)
        .await
        .unwrap()
        .unwrap();
    let stored_reaction =
        wa_core::decode_stored_newsletter_reaction_event(&stored_reaction).unwrap();
    assert_eq!(stored_reaction, reaction);

    let view_key = wa_core::newsletter_view_event_store_key(&view);
    let stored_view = store
        .get(KeyNamespace::NewsletterViewEvent, &view_key)
        .await
        .unwrap()
        .unwrap();
    let stored_view = wa_core::decode_stored_newsletter_view_event(&stored_view).unwrap();
    assert_eq!(stored_view, view);

    let participant_key = wa_core::newsletter_participant_update_event_store_key(&participant);
    let stored_participant = store
        .get(KeyNamespace::NewsletterParticipantEvent, &participant_key)
        .await
        .unwrap()
        .unwrap();
    let stored_participant =
        wa_core::decode_stored_newsletter_participant_update_event(&stored_participant).unwrap();
    assert_eq!(stored_participant, participant);

    let settings_key = wa_core::newsletter_settings_update_event_store_key(&settings);
    let stored_settings = store
        .get(KeyNamespace::NewsletterSettingsEvent, &settings_key)
        .await
        .unwrap()
        .unwrap();
    let stored_settings =
        wa_core::decode_stored_newsletter_settings_update_event(&stored_settings).unwrap();
    assert_eq!(stored_settings.fields["name"], "Updates");

    persist_receive_events(
        &store,
        &[Event::NewsletterSettingsUpdate(vec![
            wa_core::NewsletterSettingsUpdateEvent::new("abc@newsletter")
                .with_field("description", "Daily notes"),
        ])],
    )
    .await
    .unwrap();

    let stored_settings = store
        .get(KeyNamespace::NewsletterSettingsEvent, &settings_key)
        .await
        .unwrap()
        .unwrap();
    let stored_settings =
        wa_core::decode_stored_newsletter_settings_update_event(&stored_settings).unwrap();
    assert_eq!(stored_settings.fields["name"], "Updates");
    assert_eq!(stored_settings.fields["description"], "Daily notes");
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn receive_persistence_stores_account_state_events() {
    let store = wa_store::MemoryAuthStore::new();
    let reachout = wa_core::ReachoutTimelockState {
        is_active: true,
        time_enforcement_ends: Some(1_700_000_000),
        enforcement_type: wa_core::ReachoutTimelockEnforcementType::BizQuality,
    };
    let capping = wa_core::MessageCappingInfo {
        total_quota: Some(25),
        used_quota: Some(23),
        capping_status: Some(wa_core::MessageCappingStatus::SecondWarning),
        ..wa_core::MessageCappingInfo::default()
    };
    let default_disappearing_mode =
        wa_core::DefaultDisappearingMode::new(86_400).with_timestamp(1_700_000_001);

    persist_receive_events(
        &store,
        &[
            Event::ReachoutTimelockUpdate(reachout.clone()),
            Event::MessageCappingUpdate(capping.clone()),
            Event::DefaultDisappearingModeUpdate(default_disappearing_mode.clone()),
        ],
    )
    .await
    .unwrap();

    let stored_reachout = store
        .get(
            KeyNamespace::AccountReachoutTimelock,
            wa_core::reachout_timelock_store_key(),
        )
        .await
        .unwrap()
        .unwrap();
    let stored_reachout = wa_core::decode_stored_reachout_timelock_state(&stored_reachout).unwrap();
    assert_eq!(stored_reachout, reachout);

    let stored_capping = store
        .get(
            KeyNamespace::MessageCappingInfo,
            wa_core::message_capping_info_store_key(),
        )
        .await
        .unwrap()
        .unwrap();
    let stored_capping = wa_core::decode_stored_message_capping_info(&stored_capping).unwrap();
    assert_eq!(stored_capping, capping);

    let stored_mode = store
        .get(
            KeyNamespace::DefaultDisappearingMode,
            wa_core::default_disappearing_mode_store_key(),
        )
        .await
        .unwrap()
        .unwrap();
    let stored_mode = wa_core::decode_stored_default_disappearing_mode(&stored_mode).unwrap();
    assert_eq!(stored_mode, default_disappearing_mode);
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn receive_persistence_stores_media_retry_events() {
    let store = wa_store::MemoryAuthStore::new();
    let key = wa_core::MessageEventKey::new(
        "123@s.whatsapp.net",
        "msg-1",
        Some("456@s.whatsapp.net".to_owned()),
    );
    let retry = wa_core::MediaRetryEvent::new(key.clone(), false)
        .with_encrypted_payload(Bytes::from_static(b"cipher"), Bytes::from_static(b"iv"));
    let batch = wa_core::EventBatch {
        media_retry: vec![retry.clone()],
        ..wa_core::EventBatch::default()
    };

    persist_receive_events(&store, &[Event::Batch(Box::new(batch))])
        .await
        .unwrap();

    let store_key = wa_core::media_retry_event_store_key(&retry);
    let stored = store
        .get(KeyNamespace::MediaRetryEvent, &store_key)
        .await
        .unwrap()
        .unwrap();
    let stored = wa_core::decode_stored_media_retry_event(&stored).unwrap();
    assert_eq!(stored, retry);

    let replacement =
        wa_core::MediaRetryEvent::new(key, false).with_error(2, Some("missing".to_owned()), 404);
    persist_receive_events(&store, &[Event::MediaRetry(vec![replacement.clone()])])
        .await
        .unwrap();

    let stored = store
        .get(KeyNamespace::MediaRetryEvent, &store_key)
        .await
        .unwrap()
        .unwrap();
    let stored = wa_core::decode_stored_media_retry_event(&stored).unwrap();
    assert_eq!(stored, replacement);
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn receive_persistence_generates_group_notification_message_stub() {
    let store = wa_store::MemoryAuthStore::new();
    let group = wa_core::GroupUpdateEvent::new("123@g.us")
        .with_field("notification_id", "g-stub-1")
        .with_field("notification_type", "w:gp2")
        .with_field("actor", "111@s.whatsapp.net")
        .with_field("timestamp", "1700000000")
        .with_field("participants_add", "222@lid")
        .with_field("participants_add_count", "1")
        .with_field(
            "participants_add_phone_numbers",
            "222@lid=222@s.whatsapp.net",
        )
        .with_field("participants_add_usernames", "222@lid=two")
        .with_field("participants_add_roles", "222@lid=admin");

    persist_receive_events(&store, &[Event::GroupsUpdate(vec![group.clone()])])
        .await
        .unwrap();

    let stored_group = store
        .get(KeyNamespace::GroupEvent, &group.jid)
        .await
        .unwrap()
        .unwrap();
    let stored_group = wa_core::decode_stored_group_event(&stored_group).unwrap();
    assert_eq!(stored_group, group);

    let message_key = wa_core::MessageEventKey::new(
        "123@g.us",
        "g-stub-1",
        Some("111@s.whatsapp.net".to_owned()),
    );
    let stored_message = store
        .get(
            KeyNamespace::MessageEvent,
            &wa_core::message_event_store_key(&message_key),
        )
        .await
        .unwrap()
        .unwrap();
    let stored_message = wa_core::decode_stored_message_event(&stored_message).unwrap();
    assert_eq!(stored_message.key, message_key);
    assert_eq!(stored_message.timestamp, Some(1_700_000_000));
    assert_eq!(stored_message.fields["source"], "group_notification");
    assert_eq!(stored_message.fields["kind"], "notify");
    assert_eq!(
        stored_message.fields["message_stub_type"],
        (wa_proto::proto::web_message_info::StubType::GroupParticipantAdd as i32).to_string()
    );
    assert_eq!(stored_message.fields["stub_type"], "group_participant_add");
    let parameters: Vec<String> =
        serde_json::from_str(&stored_message.fields["message_stub_parameters"]).unwrap();
    let participant: serde_json::Value = serde_json::from_str(&parameters[0]).unwrap();
    assert_eq!(participant["id"], "222@lid");
    assert_eq!(participant["phoneNumber"], "222@s.whatsapp.net");
    assert_eq!(participant["username"], "two");
    assert_eq!(participant["admin"], "admin");

    let ephemeral_group = wa_core::GroupUpdateEvent::new("123@g.us")
        .with_field("notification_id", "g-stub-ephemeral")
        .with_field("notification_type", "w:gp2")
        .with_field("actor", "111@s.whatsapp.net")
        .with_field("timestamp", "1700000001")
        .with_field("ephemeral_duration", "86400");
    persist_receive_events(&store, &[Event::GroupsUpdate(vec![ephemeral_group])])
        .await
        .unwrap();

    let ephemeral_key = wa_core::MessageEventKey::new(
        "123@g.us",
        "g-stub-ephemeral",
        Some("111@s.whatsapp.net".to_owned()),
    );
    let stored_ephemeral = store
        .get(
            KeyNamespace::MessageEvent,
            &wa_core::message_event_store_key(&ephemeral_key),
        )
        .await
        .unwrap()
        .unwrap();
    let stored_ephemeral = wa_core::decode_stored_message_event(&stored_ephemeral).unwrap();
    assert_eq!(stored_ephemeral.key, ephemeral_key);
    assert_eq!(
        stored_ephemeral.fields["message_stub_type"],
        (wa_proto::proto::web_message_info::StubType::ChangeEphemeralSetting as i32).to_string()
    );
    assert_eq!(
        stored_ephemeral.fields["stub_type"],
        "change_ephemeral_setting"
    );
    assert_eq!(stored_ephemeral.fields["payload_kind"], "protocol_message");
    let decoded =
        wa_proto::proto::Message::decode(stored_ephemeral.payload.clone().unwrap()).unwrap();
    let protocol = decoded.protocol_message.unwrap();
    assert_eq!(
        protocol.r#type,
        Some(wa_proto::proto::message::protocol_message::Type::EphemeralSetting as i32)
    );
    assert_eq!(protocol.ephemeral_expiration, Some(86_400));

    let pending_join_group = wa_core::GroupUpdateEvent::new("123@g.us")
        .with_field("notification_id", "g-stub-membership-request")
        .with_field("notification_type", "w:gp2")
        .with_field("actor", "111@s.whatsapp.net")
        .with_field("timestamp", "1700000002")
        .with_field("join_requests", "222@s.whatsapp.net")
        .with_field("join_requests_count", "1")
        .with_field("join_requests_lids", "222@s.whatsapp.net=222@lid")
        .with_field(
            "join_requests_phone_numbers",
            "222@s.whatsapp.net=222@s.whatsapp.net",
        )
        .with_field("join_requests_usernames", "222@s.whatsapp.net=two")
        .with_field("join_requests_methods", "222@s.whatsapp.net=invite_link");
    persist_receive_events(&store, &[Event::GroupsUpdate(vec![pending_join_group])])
        .await
        .unwrap();

    let pending_join_key = wa_core::MessageEventKey::new(
        "123@g.us",
        "g-stub-membership-request",
        Some("111@s.whatsapp.net".to_owned()),
    );
    let stored_pending_join = store
        .get(
            KeyNamespace::MessageEvent,
            &wa_core::message_event_store_key(&pending_join_key),
        )
        .await
        .unwrap()
        .unwrap();
    let stored_pending_join = wa_core::decode_stored_message_event(&stored_pending_join).unwrap();
    assert_eq!(stored_pending_join.key, pending_join_key);
    assert_eq!(
        stored_pending_join.fields["message_stub_type"],
        (wa_proto::proto::web_message_info::StubType::GroupMembershipJoinApprovalRequest as i32)
            .to_string()
    );
    assert_eq!(
        stored_pending_join.fields["stub_type"],
        "group_membership_join_approval_request"
    );
    let parameters: Vec<String> =
        serde_json::from_str(&stored_pending_join.fields["message_stub_parameters"]).unwrap();
    assert_eq!(parameters.len(), 3);
    let participant: serde_json::Value = serde_json::from_str(&parameters[0]).unwrap();
    assert_eq!(participant["lid"], "222@lid");
    assert_eq!(participant["pn"], "222@s.whatsapp.net");
    assert_eq!(participant["username"], "two");
    assert_eq!(parameters[1], "requested");
    assert_eq!(parameters[2], "invite_link");

    let membership_group = wa_core::GroupUpdateEvent::new("123@g.us")
        .with_field("notification_id", "g-stub-membership")
        .with_field("notification_type", "w:gp2")
        .with_field("actor", "111@lid")
        .with_field("timestamp", "1700000003")
        .with_field("join_requests_created", "333@lid")
        .with_field("join_requests_created_count", "1")
        .with_field(
            "join_requests_created_phone_numbers",
            "333@lid=333@s.whatsapp.net",
        )
        .with_field("join_requests_created_usernames", "333@lid=three")
        .with_field("join_requests_created_methods", "333@lid=non_admin_add")
        .with_field("join_requests_created_outcomes", "333@lid=created");
    persist_receive_events(&store, &[Event::GroupsUpdate(vec![membership_group])])
        .await
        .unwrap();

    let membership_key =
        wa_core::MessageEventKey::new("123@g.us", "g-stub-membership", Some("111@lid".to_owned()));
    let stored_membership = store
        .get(
            KeyNamespace::MessageEvent,
            &wa_core::message_event_store_key(&membership_key),
        )
        .await
        .unwrap()
        .unwrap();
    let stored_membership = wa_core::decode_stored_message_event(&stored_membership).unwrap();
    assert_eq!(stored_membership.key, membership_key);
    assert_eq!(
        stored_membership.fields["message_stub_type"],
        (wa_proto::proto::web_message_info::StubType::GroupMembershipJoinApprovalRequestNonAdminAdd
            as i32)
            .to_string()
    );
    assert_eq!(
        stored_membership.fields["stub_type"],
        "group_membership_join_approval_request_non_admin_add"
    );
    let parameters: Vec<String> =
        serde_json::from_str(&stored_membership.fields["message_stub_parameters"]).unwrap();
    assert_eq!(parameters.len(), 3);
    let participant: serde_json::Value = serde_json::from_str(&parameters[0]).unwrap();
    assert_eq!(participant["lid"], "333@lid");
    assert_eq!(participant["pn"], "333@s.whatsapp.net");
    assert_eq!(participant["username"], "three");
    assert_eq!(parameters[1], "created");
    assert_eq!(parameters[2], "non_admin_add");

    let invite_group = wa_core::GroupUpdateEvent::new("123@g.us")
        .with_field("notification_id", "g-stub-invite")
        .with_field("notification_type", "w:gp2")
        .with_field("actor", "111@s.whatsapp.net")
        .with_field("timestamp", "1700000004")
        .with_field("invite_updated", "true")
        .with_field("invite_code", "invite-code")
        .with_field("participants_invite", "444@s.whatsapp.net")
        .with_field("participants_invite_count", "1");
    let accept_group = wa_core::GroupUpdateEvent::new("123@g.us")
        .with_field("notification_id", "g-stub-accept")
        .with_field("notification_type", "w:gp2")
        .with_field("actor", "444@s.whatsapp.net")
        .with_field("timestamp", "1700000005")
        .with_field("invite_accepted", "true")
        .with_field("participants_accept", "444@s.whatsapp.net")
        .with_field("participants_accept_count", "1");
    let revoke_group = wa_core::GroupUpdateEvent::new("123@g.us")
        .with_field("notification_id", "g-stub-revoke")
        .with_field("notification_type", "w:gp2")
        .with_field("actor", "111@s.whatsapp.net")
        .with_field("timestamp", "1700000006")
        .with_field("invite_revoked", "true")
        .with_field("invite_code", "old-code");
    persist_receive_events(
        &store,
        &[Event::GroupsUpdate(vec![
            invite_group,
            accept_group,
            revoke_group,
        ])],
    )
    .await
    .unwrap();

    let invite_key = wa_core::MessageEventKey::new(
        "123@g.us",
        "g-stub-invite",
        Some("111@s.whatsapp.net".to_owned()),
    );
    let stored_invite = store
        .get(
            KeyNamespace::MessageEvent,
            &wa_core::message_event_store_key(&invite_key),
        )
        .await
        .unwrap()
        .unwrap();
    let stored_invite = wa_core::decode_stored_message_event(&stored_invite).unwrap();
    assert_eq!(stored_invite.key, invite_key);
    assert_eq!(
        stored_invite.fields["message_stub_type"],
        (wa_proto::proto::web_message_info::StubType::GroupParticipantInvite as i32).to_string()
    );
    assert_eq!(
        stored_invite.fields["stub_type"],
        "group_participant_invite"
    );

    let accept_key = wa_core::MessageEventKey::new(
        "123@g.us",
        "g-stub-accept",
        Some("444@s.whatsapp.net".to_owned()),
    );
    let stored_accept = store
        .get(
            KeyNamespace::MessageEvent,
            &wa_core::message_event_store_key(&accept_key),
        )
        .await
        .unwrap()
        .unwrap();
    let stored_accept = wa_core::decode_stored_message_event(&stored_accept).unwrap();
    assert_eq!(stored_accept.key, accept_key);
    assert_eq!(
        stored_accept.fields["message_stub_type"],
        (wa_proto::proto::web_message_info::StubType::GroupParticipantAccept as i32).to_string()
    );
    assert_eq!(
        stored_accept.fields["stub_type"],
        "group_participant_accept"
    );

    let revoke_key = wa_core::MessageEventKey::new(
        "123@g.us",
        "g-stub-revoke",
        Some("111@s.whatsapp.net".to_owned()),
    );
    let stored_revoke = store
        .get(
            KeyNamespace::MessageEvent,
            &wa_core::message_event_store_key(&revoke_key),
        )
        .await
        .unwrap()
        .unwrap();
    let stored_revoke = wa_core::decode_stored_message_event(&stored_revoke).unwrap();
    assert_eq!(stored_revoke.key, revoke_key);
    assert_eq!(
        stored_revoke.fields["message_stub_type"],
        (wa_proto::proto::web_message_info::StubType::GroupChangeInviteLink as i32).to_string()
    );
    assert_eq!(
        stored_revoke.fields["stub_type"],
        "group_change_invite_link"
    );
    assert_eq!(
        stored_revoke.fields["message_stub_parameters"],
        r#"["old-code"]"#
    );
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn receive_persistence_stores_call_events() {
    let store = wa_store::MemoryAuthStore::new();
    let call = wa_core::CallEvent::new("call-stanza-1", "123@s.whatsapp.net", "offer")
        .with_call_id("call-1")
        .with_participant("456@s.whatsapp.net")
        .with_timestamp(1_700_000_007)
        .with_field("child_audio", "true");
    let batch = wa_core::EventBatch {
        calls_update: vec![call.clone()],
        ..wa_core::EventBatch::default()
    };

    persist_receive_events(&store, &[Event::Batch(Box::new(batch))])
        .await
        .unwrap();

    let store_key = wa_core::call_event_store_key(&call);
    let stored = store
        .get(KeyNamespace::CallEvent, &store_key)
        .await
        .unwrap()
        .unwrap();
    let stored = wa_core::decode_stored_call_event(&stored).unwrap();
    assert_eq!(stored, call);

    let replacement = wa_core::CallEvent::new("call-stanza-1", "123@s.whatsapp.net", "offer")
        .with_call_id("call-1")
        .with_participant("789@s.whatsapp.net")
        .with_timestamp(1_700_000_008)
        .with_field("child_video", "true");
    persist_receive_events(&store, &[Event::CallsUpdate(vec![replacement.clone()])])
        .await
        .unwrap();

    let stored = store
        .get(KeyNamespace::CallEvent, &store_key)
        .await
        .unwrap()
        .unwrap();
    let stored = wa_core::decode_stored_call_event(&stored).unwrap();
    assert_eq!(stored, replacement);
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn receive_persistence_inherits_call_offer_metadata_for_later_terminal_event() {
    let store = wa_store::MemoryAuthStore::new();
    let offer = wa_core::CallEvent::new("call-offer-stanza", "123@s.whatsapp.net", "offer")
        .with_call_id("call-1")
        .with_field("is_video", "true")
        .with_field("is_group", "true")
        .with_field("caller_pn", "456@s.whatsapp.net");
    let cache_key = call_offer_cache_key(&offer).unwrap();

    persist_receive_events(&store, &[Event::CallsUpdate(vec![offer])])
        .await
        .unwrap();

    assert!(
        store
            .get(KeyNamespace::CallEvent, &cache_key)
            .await
            .unwrap()
            .is_some()
    );

    let terminal =
        wa_core::CallEvent::new("call-terminal-stanza", "123@s.whatsapp.net", "terminate")
            .with_call_id("call-1")
            .with_field("latency_ms", "12");
    persist_receive_events(&store, &[Event::CallsUpdate(vec![terminal.clone()])])
        .await
        .unwrap();

    let stored = store
        .get(
            KeyNamespace::CallEvent,
            &wa_core::call_event_store_key(&terminal),
        )
        .await
        .unwrap()
        .unwrap();
    let stored = wa_core::decode_stored_call_event(&stored).unwrap();
    assert_eq!(
        stored.fields.get("is_video").map(String::as_str),
        Some("true")
    );
    assert_eq!(
        stored.fields.get("is_group").map(String::as_str),
        Some("true")
    );
    assert_eq!(
        stored.fields.get("caller_pn").map(String::as_str),
        Some("456@s.whatsapp.net")
    );
    assert_eq!(
        stored.fields.get("latency_ms").map(String::as_str),
        Some("12")
    );
    assert!(
        store
            .get(KeyNamespace::CallEvent, &cache_key)
            .await
            .unwrap()
            .is_none()
    );
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn receive_persistence_generates_missed_call_message_from_enriched_call_timeout() {
    let store = wa_store::MemoryAuthStore::new();
    let offer = wa_core::CallEvent::new("call-offer-stanza", "123@g.us", "offer")
        .with_call_id("call-3")
        .with_timestamp(1_700_000_010)
        .with_field("is_video", "true")
        .with_field("is_group", "true")
        .with_field("caller_pn", "456@s.whatsapp.net");

    persist_receive_events(&store, &[Event::CallsUpdate(vec![offer.clone()])])
        .await
        .unwrap();

    let offer_message_key = wa_core::MessageEventKey::new("123@g.us", "call-3", None);
    let stored = store
        .get(
            KeyNamespace::MessageEvent,
            &wa_core::message_event_store_key(&offer_message_key),
        )
        .await
        .unwrap()
        .unwrap();
    let stored = wa_core::decode_stored_message_event(&stored).unwrap();
    assert_eq!(stored.fields["call_status"], "offer");
    let decoded = wa_proto::proto::Message::decode(stored.payload.unwrap()).unwrap();
    assert_eq!(
        decoded.call.unwrap().call_key.as_deref(),
        Some(b"call-3".as_slice())
    );

    let timeout = wa_core::CallEvent::new("call-timeout-stanza", "123@g.us", "timeout")
        .with_call_id("call-3")
        .with_timestamp(1_700_000_020);
    persist_receive_events(&store, &[Event::CallsUpdate(vec![timeout.clone()])])
        .await
        .unwrap();

    let stored = store
        .get(
            KeyNamespace::MessageEvent,
            &wa_core::message_event_store_key(&offer_message_key),
        )
        .await
        .unwrap()
        .unwrap();
    let stored = wa_core::decode_stored_message_event(&stored).unwrap();
    assert_eq!(stored.key, offer_message_key);
    assert_eq!(stored.timestamp, Some(1_700_000_020));
    assert_eq!(stored.fields["call_status"], "timeout");
    assert_eq!(stored.fields["is_video"], "true");
    assert_eq!(stored.fields["is_group"], "true");
    assert_eq!(
        stored.fields["message_stub_type"],
        (wa_proto::proto::web_message_info::StubType::CallMissedGroupVideo as i32).to_string()
    );
    assert_eq!(stored.fields["stub_type"], "call_missed_group_video");
    assert!(stored.payload.is_none());

    let stored_timeout = store
        .get(
            KeyNamespace::CallEvent,
            &wa_core::call_event_store_key(&timeout),
        )
        .await
        .unwrap()
        .unwrap();
    let stored_timeout = wa_core::decode_stored_call_event(&stored_timeout).unwrap();
    assert_eq!(
        stored_timeout.fields.get("caller_pn").map(String::as_str),
        Some("456@s.whatsapp.net")
    );
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn receive_persistence_inherits_call_offer_metadata_within_same_batch() {
    let store = wa_store::MemoryAuthStore::new();
    let offer = wa_core::CallEvent::new("call-offer-stanza", "123@s.whatsapp.net", "offer")
        .with_call_id("call-2")
        .with_field("is_video", "false")
        .with_field("is_group", "true")
        .with_field("caller_pn", "456@s.whatsapp.net");
    let terminal = wa_core::CallEvent::new("call-terminal-stanza", "123@s.whatsapp.net", "accept")
        .with_call_id("call-2");
    let cache_key = call_offer_cache_key(&offer).unwrap();
    let batch = wa_core::EventBatch {
        calls_update: vec![offer, terminal.clone()],
        ..wa_core::EventBatch::default()
    };

    persist_receive_events(&store, &[Event::Batch(Box::new(batch))])
        .await
        .unwrap();

    let stored = store
        .get(
            KeyNamespace::CallEvent,
            &wa_core::call_event_store_key(&terminal),
        )
        .await
        .unwrap()
        .unwrap();
    let stored = wa_core::decode_stored_call_event(&stored).unwrap();
    assert_eq!(
        stored.fields.get("is_video").map(String::as_str),
        Some("false")
    );
    assert_eq!(
        stored.fields.get("is_group").map(String::as_str),
        Some("true")
    );
    assert_eq!(
        stored.fields.get("caller_pn").map(String::as_str),
        Some("456@s.whatsapp.net")
    );
    assert!(
        store
            .get(KeyNamespace::CallEvent, &cache_key)
            .await
            .unwrap()
            .is_none()
    );
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn receive_persistence_stores_labels_associations_and_quick_replies() {
    let store = wa_store::MemoryAuthStore::new();
    let label = wa_core::LabelEvent::new("7")
        .with_field("name", "Important")
        .with_field("color", "4");
    let association = wa_core::LabelAssociationEvent::chat("7", "123@s.whatsapp.net", true);
    let quick_reply = wa_core::QuickReplyEvent::new("qr-1")
        .with_field("shortcut", "/hi")
        .with_field("message", "hello");
    let batch = wa_core::EventBatch {
        labels_edit: vec![label.clone()],
        labels_association: vec![association.clone()],
        quick_replies_update: vec![quick_reply.clone()],
        ..wa_core::EventBatch::default()
    };

    persist_receive_events(&store, &[Event::Batch(Box::new(batch))])
        .await
        .unwrap();

    let stored_label = store
        .get(KeyNamespace::LabelEvent, "7")
        .await
        .unwrap()
        .unwrap();
    let stored_label = wa_core::decode_stored_label_event(&stored_label).unwrap();
    assert_eq!(stored_label, label);

    let association_key = wa_core::label_association_store_key(&association);
    let stored_association = store
        .get(KeyNamespace::LabelAssociation, &association_key)
        .await
        .unwrap()
        .unwrap();
    let stored_association =
        wa_core::decode_stored_label_association_event(&stored_association).unwrap();
    assert_eq!(stored_association, association);

    let stored_quick_reply = store
        .get(KeyNamespace::QuickReplyEvent, "qr-1")
        .await
        .unwrap()
        .unwrap();
    let stored_quick_reply = wa_core::decode_stored_quick_reply_event(&stored_quick_reply).unwrap();
    assert_eq!(stored_quick_reply, quick_reply);

    persist_receive_events(
        &store,
        &[
            Event::LabelsEdit(vec![
                wa_core::LabelEvent::new("7").with_field("name", "Renamed"),
            ]),
            Event::LabelsAssociation(vec![wa_core::LabelAssociationEvent::chat(
                "7",
                "123@s.whatsapp.net",
                false,
            )]),
            Event::QuickRepliesUpdate(vec![
                wa_core::QuickReplyEvent::new("qr-1").with_field("count", "2"),
            ]),
        ],
    )
    .await
    .unwrap();

    let stored_label = store
        .get(KeyNamespace::LabelEvent, "7")
        .await
        .unwrap()
        .unwrap();
    let stored_label = wa_core::decode_stored_label_event(&stored_label).unwrap();
    assert_eq!(stored_label.fields["name"], "Renamed");
    assert_eq!(stored_label.fields["color"], "4");

    let stored_association = store
        .get(KeyNamespace::LabelAssociation, &association_key)
        .await
        .unwrap()
        .unwrap();
    let stored_association =
        wa_core::decode_stored_label_association_event(&stored_association).unwrap();
    assert!(!stored_association.labeled);

    let stored_quick_reply = store
        .get(KeyNamespace::QuickReplyEvent, "qr-1")
        .await
        .unwrap()
        .unwrap();
    let stored_quick_reply = wa_core::decode_stored_quick_reply_event(&stored_quick_reply).unwrap();
    assert_eq!(stored_quick_reply.fields["shortcut"], "/hi");
    assert_eq!(stored_quick_reply.fields["message"], "hello");
    assert_eq!(stored_quick_reply.fields["count"], "2");
}

#[cfg(feature = "memory-store")]
#[tokio::test]
async fn community_methods_use_community_iqs_and_parse_results() {
    let store = wa_store::MemoryAuthStore::new();
    let client = Client::builder(store).connect().await.unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection();

    let metadata_fut = client.fetch_community_metadata(&connection, "123@g.us");
    tokio::pin!(metadata_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "w:g2");
            assert_eq!(node.attrs["to"], "123@g.us");
            assert_eq!(node.attrs["type"], "get");
            assert_eq!(test_child(&node, "query").attrs["request"], "interactive");
            community_metadata_response(&node, "123", "Updates")
        },
        &mut metadata_fut,
    )
    .await;
    let metadata = metadata_fut.await.unwrap();
    assert_eq!(metadata.jid, "123@g.us");
    assert_eq!(metadata.subject.as_deref(), Some("Updates"));
    assert_eq!(metadata.addressing_mode, wa_core::GroupAddressingMode::Lid);
    assert!(metadata.is_community);

    let participating_fut = client.fetch_participating_communities(&connection);
    tokio::pin!(participating_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["to"], "@g.us");
            assert!(test_child(&node, "participating").attrs.is_empty());
            BinaryNode::new("iq")
                .with_attr("id", node.attrs["id"].clone())
                .with_attr("type", "result")
                .with_content(vec![BinaryNode::new("communities").with_content(vec![
                    BinaryNode::new("community")
                        .with_attr("id", "123")
                        .with_attr("subject", "Updates")
                        .with_content(vec![BinaryNode::new("parent")]),
                ])])
        },
        &mut participating_fut,
    )
    .await;
    let communities = participating_fut.await.unwrap();
    assert_eq!(communities.len(), 1);
    assert_eq!(communities[0].jid, "123@g.us");

    let create_fut = client.create_community(&connection, "Rust users", "Daily updates");
    tokio::pin!(create_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["to"], "@g.us");
            assert_eq!(node.attrs["type"], "set");
            let create = test_child(&node, "create");
            assert_eq!(create.attrs["subject"], "Rust users");
            let description = test_child(create, "description");
            assert!(!description.attrs["id"].is_empty());
            assert_eq!(
                test_node_text(test_child(description, "body")).as_deref(),
                Some("Daily updates")
            );
            assert_eq!(
                test_child(create, "parent").attrs["default_membership_approval_mode"],
                "request_required"
            );
            assert_child(create, "allow_non_admin_sub_group_creation");
            assert_child(create, "create_general_chat");
            BinaryNode::new("iq")
                .with_attr("id", node.attrs["id"].clone())
                .with_attr("type", "result")
                .with_content(vec![BinaryNode::new("group").with_attr("id", "456")])
        },
        &mut create_fut,
    )
    .await;
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["to"], "456@g.us");
            assert_eq!(node.attrs["type"], "get");
            assert_eq!(test_child(&node, "query").attrs["request"], "interactive");
            group_metadata_response(&node, "456", "Rust users")
        },
        &mut create_fut,
    )
    .await;
    let created = create_fut.await.unwrap();
    assert_eq!(created.jid, "456@g.us");
    assert_eq!(created.subject.as_deref(), Some("Rust users"));

    let subgroup_fut = client.create_community_group(
        &connection,
        "Announcements",
        ["111@s.whatsapp.net"],
        "123@g.us",
    );
    tokio::pin!(subgroup_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["to"], "@g.us");
            let create = test_child(&node, "create");
            assert_eq!(create.attrs["subject"], "Announcements");
            assert!(!create.attrs["key"].is_empty());
            assert_eq!(test_children(create, "participant").len(), 1);
            assert_eq!(test_child(create, "linked_parent").attrs["jid"], "123@g.us");
            BinaryNode::new("iq")
                .with_attr("id", node.attrs["id"].clone())
                .with_attr("type", "result")
                .with_content(vec![BinaryNode::new("group").with_attr("jid", "789@g.us")])
        },
        &mut subgroup_fut,
    )
    .await;
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["to"], "789@g.us");
            assert_eq!(node.attrs["type"], "get");
            assert_eq!(test_child(&node, "query").attrs["request"], "interactive");
            BinaryNode::new("iq")
                .with_attr("id", node.attrs["id"].clone())
                .with_attr("type", "result")
                .with_content(vec![
                    BinaryNode::new("group")
                        .with_attr("id", "789")
                        .with_attr("subject", "Announcements")
                        .with_content(vec![
                            BinaryNode::new("linked_parent").with_attr("jid", "123@g.us"),
                            BinaryNode::new("participant")
                                .with_attr("jid", "111@s.whatsapp.net")
                                .with_attr("type", "admin"),
                        ]),
                ])
        },
        &mut subgroup_fut,
    )
    .await;
    let subgroup = subgroup_fut.await.unwrap();
    assert_eq!(subgroup.jid, "789@g.us");
    assert_eq!(subgroup.linked_parent.as_deref(), Some("123@g.us"));

    let leave_fut = client.leave_community(&connection, "123@g.us");
    tokio::pin!(leave_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["to"], "@g.us");
            assert_eq!(node.attrs["type"], "set");
            let leave = test_child(&node, "leave");
            assert_eq!(test_child(leave, "community").attrs["id"], "123@g.us");
            empty_result_for(&node)
        },
        &mut leave_fut,
    )
    .await;
    leave_fut.await.unwrap();

    let subject_fut = client.set_community_subject(&connection, "123@g.us", "Renamed");
    tokio::pin!(subject_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["to"], "123@g.us");
            assert_eq!(node.attrs["type"], "set");
            assert_eq!(
                test_node_text(test_child(&node, "subject")).as_deref(),
                Some("Renamed")
            );
            empty_result_for(&node)
        },
        &mut subject_fut,
    )
    .await;
    subject_fut.await.unwrap();

    let description_fut =
        client.set_community_description(&connection, "123@g.us", Some("New description"));
    tokio::pin!(description_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["type"], "get");
            community_metadata_response(&node, "123", "Updates")
        },
        &mut description_fut,
    )
    .await;
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["type"], "set");
            let description = test_child(&node, "description");
            assert_eq!(description.attrs["prev"], "desc-1");
            assert!(!description.attrs["id"].is_empty());
            assert_eq!(
                test_node_text(test_child(description, "body")).as_deref(),
                Some("New description")
            );
            empty_result_for(&node)
        },
        &mut description_fut,
    )
    .await;
    description_fut.await.unwrap();

    let link_fut = client.link_community_group(&connection, "789@g.us", "123@g.us");
    tokio::pin!(link_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["to"], "123@g.us");
            let link = test_child(test_child(&node, "links"), "link");
            assert_eq!(link.attrs["link_type"], "sub_group");
            assert_eq!(test_child(link, "group").attrs["jid"], "789@g.us");
            empty_result_for(&node)
        },
        &mut link_fut,
    )
    .await;
    link_fut.await.unwrap();

    let failed_link_fut = client.link_community_group(&connection, "789@g.us", "123@g.us");
    tokio::pin!(failed_link_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["to"], "123@g.us");
            let link = test_child(test_child(&node, "links"), "link");
            assert_eq!(link.attrs["link_type"], "sub_group");
            error_result_for(&node, "403", "denied")
        },
        &mut failed_link_fut,
    )
    .await;
    assert!(failed_link_fut.await.is_err());

    let linked_fut = client.fetch_community_linked_groups(&connection, "123@g.us");
    tokio::pin!(linked_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["type"], "get");
            assert!(test_child(&node, "sub_groups").attrs.is_empty());
            BinaryNode::new("iq")
                .with_attr("id", node.attrs["id"].clone())
                .with_attr("type", "result")
                .with_content(vec![BinaryNode::new("sub_groups").with_content(vec![
                    BinaryNode::new("group")
                        .with_attr("id", "789")
                        .with_attr("subject", "Announcements")
                        .with_attr("creator", "111@c.us")
                        .with_attr("creation", "10")
                        .with_attr("size", "4"),
                ])])
        },
        &mut linked_fut,
    )
    .await;
    let linked = linked_fut.await.unwrap();
    assert_eq!(linked[0].jid, "789@g.us");
    assert_eq!(linked[0].owner.as_deref(), Some("111@s.whatsapp.net"));
    assert_eq!(linked[0].size, Some(4));

    let resolved_linked_fut =
        client.fetch_community_linked_groups_resolved(&connection, "789@g.us");
    tokio::pin!(resolved_linked_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["to"], "789@g.us");
            assert_eq!(node.attrs["type"], "get");
            assert_eq!(test_child(&node, "query").attrs["request"], "interactive");
            BinaryNode::new("iq")
                .with_attr("id", node.attrs["id"].clone())
                .with_attr("type", "result")
                .with_content(vec![
                    BinaryNode::new("group")
                        .with_attr("id", "789")
                        .with_attr("subject", "Announcements")
                        .with_content(vec![
                            BinaryNode::new("linked_parent").with_attr("jid", "123@g.us"),
                        ]),
                ])
        },
        &mut resolved_linked_fut,
    )
    .await;
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["to"], "123@g.us");
            assert_eq!(node.attrs["type"], "get");
            assert!(test_child(&node, "sub_groups").attrs.is_empty());
            BinaryNode::new("iq")
                .with_attr("id", node.attrs["id"].clone())
                .with_attr("type", "result")
                .with_content(vec![BinaryNode::new("sub_groups").with_content(vec![
                    BinaryNode::new("group")
                        .with_attr("id", "999")
                        .with_attr("subject", "General")
                        .with_attr("creator", "222@c.us")
                        .with_attr("creation", "11")
                        .with_attr("size", "12"),
                ])])
        },
        &mut resolved_linked_fut,
    )
    .await;
    let resolved_linked = resolved_linked_fut.await.unwrap();
    assert_eq!(resolved_linked.community_jid, "123@g.us");
    assert!(!resolved_linked.is_community);
    assert_eq!(resolved_linked.linked_groups[0].jid, "999@g.us");
    assert_eq!(
        resolved_linked.linked_groups[0].owner.as_deref(),
        Some("222@s.whatsapp.net")
    );
    assert_eq!(resolved_linked.linked_groups[0].size, Some(12));

    let participants_fut = client.update_community_participants(
        &connection,
        "123@g.us",
        GroupParticipantAction::Remove,
        ["111@s.whatsapp.net"],
    );
    tokio::pin!(participants_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            let remove = test_child(&node, "remove");
            assert_eq!(remove.attrs["linked_groups"], "true");
            assert_eq!(
                test_child(remove, "participant").attrs["jid"],
                "111@s.whatsapp.net"
            );
            BinaryNode::new("iq")
                .with_attr("id", node.attrs["id"].clone())
                .with_attr("type", "result")
                .with_content(vec![BinaryNode::new("remove").with_content(vec![
                    BinaryNode::new("participant").with_attr("jid", "111@s.whatsapp.net"),
                ])])
        },
        &mut participants_fut,
    )
    .await;
    let participants = participants_fut.await.unwrap();
    assert_eq!(participants.action, GroupParticipantAction::Remove);
    assert_eq!(participants.participants[0].status, 200);
    assert_eq!(
        participants.participants[0]
            .content
            .as_ref()
            .and_then(|node| node.attrs.get("jid"))
            .map(String::as_str),
        Some("111@s.whatsapp.net")
    );

    let join_list_fut = client.fetch_community_join_requests(&connection, "123@g.us");
    tokio::pin!(join_list_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["type"], "get");
            assert!(
                test_child(&node, "membership_approval_requests")
                    .attrs
                    .is_empty()
            );
            BinaryNode::new("iq")
                .with_attr("id", node.attrs["id"].clone())
                .with_attr("type", "result")
                .with_content(vec![
                    BinaryNode::new("membership_approval_requests").with_content(vec![
                        BinaryNode::new("membership_approval_request")
                            .with_attr("jid", "222@s.whatsapp.net")
                            .with_attr("phoneNumber", "222@s.whatsapp.net")
                            .with_attr("lidJid", "222@lid")
                            .with_attr("participantUsername", "two")
                            .with_attr("t", "45")
                            .with_attr("requestMethod", "linked_group_invite"),
                    ]),
                ])
        },
        &mut join_list_fut,
    )
    .await;
    let join_requests = join_list_fut.await.unwrap();
    assert_eq!(join_requests.len(), 1);
    assert_eq!(join_requests[0].jid, "222@s.whatsapp.net");
    assert_eq!(
        join_requests[0].phone_number.as_deref(),
        Some("222@s.whatsapp.net")
    );
    assert_eq!(join_requests[0].lid.as_deref(), Some("222@lid"));
    assert_eq!(join_requests[0].username.as_deref(), Some("two"));
    assert_eq!(join_requests[0].requested_at, Some(45));
    assert_eq!(
        join_requests[0].request_method.as_deref(),
        Some("linked_group_invite")
    );

    let invite_fut = client.fetch_community_invite_code(&connection, "123@g.us");
    tokio::pin!(invite_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["type"], "get");
            assert!(test_child(&node, "invite").attrs.is_empty());
            BinaryNode::new("iq")
                .with_attr("id", node.attrs["id"].clone())
                .with_attr("type", "result")
                .with_content(vec![
                    BinaryNode::new("invite").with_attr("code", "community-code"),
                ])
        },
        &mut invite_fut,
    )
    .await;
    assert_eq!(invite_fut.await.unwrap().as_deref(), Some("community-code"));

    let accept_invite_fut = client.accept_community_invite(&connection, "community-code");
    tokio::pin!(accept_invite_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["to"], "@g.us");
            assert_eq!(node.attrs["type"], "set");
            assert_eq!(test_child(&node, "invite").attrs["code"], "community-code");
            BinaryNode::new("iq")
                .with_attr("id", node.attrs["id"].clone())
                .with_attr("type", "result")
                .with_content(vec![
                    BinaryNode::new("community").with_attr("jid", "456@g.us"),
                ])
        },
        &mut accept_invite_fut,
    )
    .await;
    assert_eq!(
        accept_invite_fut.await.unwrap().as_deref(),
        Some("456@g.us")
    );

    let ephemeral_fut = client.set_community_ephemeral(&connection, "123@g.us", 86400);
    tokio::pin!(ephemeral_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["type"], "set");
            assert_eq!(test_child(&node, "ephemeral").attrs["expiration"], "86400");
            empty_result_for(&node)
        },
        &mut ephemeral_fut,
    )
    .await;
    ephemeral_fut.await.unwrap();

    let setting_fut =
        client.update_community_setting(&connection, "123@g.us", GroupSettingUpdate::Locked);
    tokio::pin!(setting_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["type"], "set");
            assert!(test_child(&node, "locked").attrs.is_empty());
            empty_result_for(&node)
        },
        &mut setting_fut,
    )
    .await;
    setting_fut.await.unwrap();

    let member_add_fut = client.set_community_member_add_mode(
        &connection,
        "123@g.us",
        GroupMemberAddMode::AllMembers,
    );
    tokio::pin!(member_add_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["type"], "set");
            assert_eq!(
                test_node_text(test_child(&node, "member_add_mode")).as_deref(),
                Some("all_member_add")
            );
            empty_result_for(&node)
        },
        &mut member_add_fut,
    )
    .await;
    member_add_fut.await.unwrap();

    let approval_fut =
        client.set_community_join_approval_mode(&connection, "123@g.us", GroupJoinApprovalMode::On);
    tokio::pin!(approval_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            let mode = test_child(&node, "membership_approval_mode");
            assert_eq!(test_child(mode, "community_join").attrs["state"], "on");
            empty_result_for(&node)
        },
        &mut approval_fut,
    )
    .await;
    approval_fut.await.unwrap();

    let unlink_fut = client.unlink_community_group(&connection, "789@g.us", "123@g.us");
    tokio::pin!(unlink_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            let unlink = test_child(&node, "unlink");
            assert_eq!(unlink.attrs["unlink_type"], "sub_group");
            assert_eq!(test_child(unlink, "group").attrs["jid"], "789@g.us");
            empty_result_for(&node)
        },
        &mut unlink_fut,
    )
    .await;
    unlink_fut.await.unwrap();

    connection.close().await.unwrap();
}

#[cfg(feature = "memory-store")]
#[tokio::test]
async fn community_create_methods_accept_result_jid_aliases() {
    let store = wa_store::MemoryAuthStore::new();
    let client = Client::builder(store).connect().await.unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection();

    let create_from_fut = client.create_community(&connection, "Rust users", "Daily updates");
    tokio::pin!(create_from_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["to"], "@g.us");
            assert_eq!(node.attrs["type"], "set");
            assert_eq!(test_child(&node, "create").attrs["subject"], "Rust users");
            BinaryNode::new("iq")
                .with_attr("id", node.attrs["id"].clone())
                .with_attr("type", "result")
                .with_attr("from", "654@g.us")
        },
        &mut create_from_fut,
    )
    .await;
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["to"], "654@g.us");
            assert_eq!(node.attrs["type"], "get");
            group_metadata_response(&node, "654", "Rust users")
        },
        &mut create_from_fut,
    )
    .await;
    let created = create_from_fut.await.unwrap();
    assert_eq!(created.jid, "654@g.us");
    assert_eq!(created.subject.as_deref(), Some("Rust users"));

    let subgroup_fut = client.create_community_group(
        &connection,
        "Announcements",
        ["111@s.whatsapp.net"],
        "654@g.us",
    );
    tokio::pin!(subgroup_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["to"], "@g.us");
            let create = test_child(&node, "create");
            assert_eq!(create.attrs["subject"], "Announcements");
            assert_eq!(test_child(create, "linked_parent").attrs["jid"], "654@g.us");
            BinaryNode::new("iq")
                .with_attr("id", node.attrs["id"].clone())
                .with_attr("type", "result")
                .with_content(vec![BinaryNode::new("community").with_attr("id", "655")])
        },
        &mut subgroup_fut,
    )
    .await;
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["to"], "655@g.us");
            assert_eq!(node.attrs["type"], "get");
            BinaryNode::new("iq")
                .with_attr("id", node.attrs["id"].clone())
                .with_attr("type", "result")
                .with_content(vec![
                    BinaryNode::new("group")
                        .with_attr("id", "655")
                        .with_attr("subject", "Announcements")
                        .with_content(vec![
                            BinaryNode::new("linked_parent").with_attr("jid", "654@g.us"),
                        ]),
                ])
        },
        &mut subgroup_fut,
    )
    .await;
    let subgroup = subgroup_fut.await.unwrap();
    assert_eq!(subgroup.jid, "655@g.us");
    assert_eq!(subgroup.linked_parent.as_deref(), Some("654@g.us"));

    let fallback_fut = client.create_community(&connection, "Fallback", "Direct metadata");
    tokio::pin!(fallback_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["to"], "@g.us");
            BinaryNode::new("iq")
                .with_attr("id", node.attrs["id"].clone())
                .with_attr("type", "result")
                .with_content(vec![
                    BinaryNode::new("community")
                        .with_attr("id", "656")
                        .with_attr("subject", "Fallback")
                        .with_content(vec![BinaryNode::new("parent")]),
                ])
        },
        &mut fallback_fut,
    )
    .await;
    let fallback = fallback_fut.await.unwrap();
    assert_eq!(fallback.jid, "656@g.us");
    assert_eq!(fallback.subject.as_deref(), Some("Fallback"));
    tokio::task::yield_now().await;
    assert!(matches!(
        sink_rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
    connection.close().await.unwrap();
}

#[cfg(feature = "memory-store")]
#[tokio::test]
async fn community_read_methods_accept_group_style_result_wrappers() {
    let store = wa_store::MemoryAuthStore::new();
    let client = Client::builder(store).connect().await.unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection();

    let participating_fut = client.fetch_participating_communities(&connection);
    tokio::pin!(participating_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["to"], "@g.us");
            assert_eq!(node.attrs["type"], "get");
            assert_child(test_child(&node, "participating"), "participants");
            BinaryNode::new("iq")
                .with_attr("id", node.attrs["id"].clone())
                .with_attr("type", "result")
                .with_content(vec![BinaryNode::new("groups").with_content(vec![
                    BinaryNode::new("group")
                        .with_attr("id", "123")
                        .with_attr("subject", "Group-shaped community")
                        .with_content(vec![
                            BinaryNode::new("parent"),
                            BinaryNode::new("default_sub_group"),
                            BinaryNode::new("participant")
                                .with_attr("jid", "111@s.whatsapp.net")
                                .with_attr("type", "admin"),
                        ]),
                ])])
        },
        &mut participating_fut,
    )
    .await;
    let communities = participating_fut.await.unwrap();
    assert_eq!(communities.len(), 1);
    assert_eq!(communities[0].jid, "123@g.us");
    assert_eq!(
        communities[0].subject.as_deref(),
        Some("Group-shaped community")
    );
    assert!(communities[0].is_community);
    assert!(communities[0].is_community_announce);
    assert_eq!(communities[0].participants.len(), 1);

    let linked_fut = client.fetch_community_linked_groups(&connection, "123@g.us");
    tokio::pin!(linked_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["to"], "123@g.us");
            assert_eq!(node.attrs["type"], "get");
            assert!(test_child(&node, "sub_groups").attrs.is_empty());
            BinaryNode::new("iq")
                .with_attr("id", node.attrs["id"].clone())
                .with_attr("type", "result")
                .with_content(vec![BinaryNode::new("linked_groups").with_content(vec![
                    BinaryNode::new("linked_group")
                        .with_attr("jid", "456@g.us")
                        .with_attr("subject", "Alias Chat")
                        .with_attr("creator", "222@c.us")
                        .with_attr("creation", "10")
                        .with_attr("size", "7"),
                ])])
        },
        &mut linked_fut,
    )
    .await;
    let linked = linked_fut.await.unwrap();
    assert_eq!(linked.len(), 1);
    assert_eq!(linked[0].jid, "456@g.us");
    assert_eq!(linked[0].subject.as_deref(), Some("Alias Chat"));
    assert_eq!(linked[0].owner.as_deref(), Some("222@s.whatsapp.net"));
    assert_eq!(linked[0].creation, Some(10));
    assert_eq!(linked[0].size, Some(7));

    let groups_fut = client.fetch_community_linked_groups(&connection, "123@g.us");
    tokio::pin!(groups_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["to"], "123@g.us");
            BinaryNode::new("iq")
                .with_attr("id", node.attrs["id"].clone())
                .with_attr("type", "result")
                .with_content(vec![BinaryNode::new("groups").with_content(vec![
                    BinaryNode::new("community")
                        .with_attr("id", "789")
                        .with_attr("subject", "Community Alias")
                        .with_attr("creator", "333@c.us"),
                ])])
        },
        &mut groups_fut,
    )
    .await;
    let groups = groups_fut.await.unwrap();
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].jid, "789@g.us");
    assert_eq!(groups[0].subject.as_deref(), Some("Community Alias"));
    assert_eq!(groups[0].owner.as_deref(), Some("333@s.whatsapp.net"));
    tokio::task::yield_now().await;
    assert!(matches!(
        sink_rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
    connection.close().await.unwrap();
}

#[cfg(feature = "memory-store")]
#[tokio::test]
async fn community_invite_info_accepts_group_metadata_result() {
    let store = wa_store::MemoryAuthStore::new();
    let client = Client::builder(store).connect().await.unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection();

    let group_info_fut = client.fetch_community_invite_info(&connection, "community-code");
    tokio::pin!(group_info_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["to"], "@g.us");
            assert_eq!(node.attrs["type"], "get");
            assert_eq!(test_child(&node, "invite").attrs["code"], "community-code");
            BinaryNode::new("iq")
                .with_attr("id", node.attrs["id"].clone())
                .with_attr("type", "result")
                .with_content(vec![
                    BinaryNode::new("group")
                        .with_attr("id", "456")
                        .with_attr("subject", "Invite Community")
                        .with_attr("addressing_mode", "lid")
                        .with_content(vec![
                            BinaryNode::new("parent"),
                            BinaryNode::new("participant")
                                .with_attr("jid", "111@s.whatsapp.net")
                                .with_attr("type", "admin"),
                        ]),
                ])
        },
        &mut group_info_fut,
    )
    .await;
    let group_info = group_info_fut.await.unwrap();
    assert_eq!(group_info.jid, "456@g.us");
    assert_eq!(group_info.subject.as_deref(), Some("Invite Community"));
    assert_eq!(
        group_info.addressing_mode,
        wa_core::GroupAddressingMode::Lid
    );
    assert!(group_info.is_community);
    assert_eq!(group_info.participants.len(), 1);

    let community_info_fut = client.fetch_community_invite_info(&connection, "community-code");
    tokio::pin!(community_info_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["to"], "@g.us");
            assert_eq!(node.attrs["type"], "get");
            assert_eq!(test_child(&node, "invite").attrs["code"], "community-code");
            community_metadata_response(&node, "457", "Community Metadata")
        },
        &mut community_info_fut,
    )
    .await;
    let community_info = community_info_fut.await.unwrap();
    assert_eq!(community_info.jid, "457@g.us");
    assert_eq!(
        community_info.subject.as_deref(),
        Some("Community Metadata")
    );
    assert!(community_info.is_community);
    tokio::task::yield_now().await;
    assert!(matches!(
        sink_rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
    connection.close().await.unwrap();
}

#[cfg(feature = "memory-store")]
#[tokio::test]
async fn accept_community_invite_v4_with_message_events_emits_update_and_stub() {
    let store = wa_store::MemoryAuthStore::new();
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let mut events = client.subscribe();
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let invite =
        GroupInviteV4::new("123@g.us", "v4-code", 1_700_000_000, "222@s.whatsapp.net").unwrap();
    let invite_key =
        wa_core::MessageEventKey::new("222@s.whatsapp.net", "community-invite-msg", None);

    let accept_fut = client.accept_community_invite_v4_with_message_events(
        &connection,
        &invite,
        Some(invite_key.clone()),
    );
    tokio::pin!(accept_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["to"], "123@g.us");
            assert_eq!(node.attrs["type"], "set");
            let accept = test_child(&node, "accept");
            assert_eq!(accept.attrs["code"], "v4-code");
            assert_eq!(accept.attrs["expiration"], "1700000000");
            assert_eq!(accept.attrs["admin"], "222@s.whatsapp.net");
            empty_result_for(&node).with_attr("from", "123@g.us")
        },
        &mut accept_fut,
    )
    .await;
    assert_eq!(accept_fut.await.unwrap().as_deref(), Some("123@g.us"));

    let batch = recv_batch_event(&mut events).await;
    assert_eq!(batch.messages_update.len(), 1);
    assert_eq!(batch.messages_update[0].key, invite_key);
    assert_eq!(
        batch.messages_update[0].fields["source"],
        "community_invite_v4_accept"
    );
    assert_eq!(batch.messages_update[0].fields["invite_status"], "accepted");
    assert_eq!(batch.messages_update[0].fields["invite_expiration"], "0");
    assert_eq!(batch.messages_upsert.len(), 1);
    let stub = &batch.messages_upsert[0];
    assert_eq!(stub.key.remote_jid, "123@g.us");
    assert_eq!(stub.key.participant.as_deref(), Some("222@s.whatsapp.net"));
    assert_eq!(stub.fields["source"], "community_invite_v4_accept");
    assert_eq!(stub.fields["stub_type"], "group_participant_add");

    let stored_update_key = wa_core::message_event_store_key(&invite_key);
    let stored_update = store
        .get(KeyNamespace::MessageUpdate, &stored_update_key)
        .await
        .unwrap()
        .unwrap();
    let stored_update = wa_core::decode_stored_message_update(&stored_update).unwrap();
    assert_eq!(stored_update, batch.messages_update[0]);

    let stored_stub_key = wa_core::message_event_store_key(&stub.key);
    let stored_stub = store
        .get(KeyNamespace::MessageEvent, &stored_stub_key)
        .await
        .unwrap()
        .unwrap();
    let stored_stub = wa_core::decode_stored_message_event(&stored_stub).unwrap();
    assert_eq!(stored_stub, *stub);
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn fetch_lid_mappings_sends_query_and_persists_mappings() {
    let store = wa_store::MemoryAuthStore::new();
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let mapping_fut = client.fetch_lid_mappings(&connection, ["123@s.whatsapp.net"]);
    tokio::pin!(mapping_fut);

    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "usync");
            BinaryNode::new("iq")
                .with_attr("id", node.attrs["id"].clone())
                .with_attr("type", "result")
                .with_content(vec![BinaryNode::new("usync").with_content(vec![
                    BinaryNode::new("list").with_content(vec![
                            BinaryNode::new("user")
                                .with_attr("jid", "123@s.whatsapp.net")
                                .with_content(vec![
                                    BinaryNode::new("lid").with_attr("val", "abc@lid"),
                                ]),
                        ]),
                ])])
        },
        &mut mapping_fut,
    )
    .await;

    assert_eq!(
        mapping_fut.await.unwrap(),
        vec![wa_core::USyncLidMapping {
            pn: "123@s.whatsapp.net".to_owned(),
            lid: "abc@lid".to_owned(),
        }]
    );
    let mapping_store = wa_core::LidPnMappingStore::new(store);
    assert_eq!(
        mapping_store
            .lid_for_pn("123@s.whatsapp.net")
            .await
            .unwrap(),
        Some("abc".to_owned())
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn fetch_device_jids_sends_query_and_excludes_own_device() {
    let store = wa_store::MemoryAuthStore::new();
    let mut credentials = wa_core::create_initial_credentials().unwrap();
    credentials.registered = true;
    credentials.account_jid = Some("123:7@s.whatsapp.net".to_owned());
    credentials.account_lid = Some("abc@lid".to_owned());
    wa_core::save_credentials(&store, credentials)
        .await
        .unwrap();
    let client = Client::builder(store).connect().await.unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let devices_fut = client.fetch_device_jids(&connection, ["123@s.whatsapp.net"], false);
    tokio::pin!(devices_fut);

    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "usync");
            BinaryNode::new("iq")
                .with_attr("id", node.attrs["id"].clone())
                .with_attr("type", "result")
                .with_content(vec![BinaryNode::new("usync").with_content(vec![
                    BinaryNode::new("list").with_content(vec![
                        BinaryNode::new("user")
                            .with_attr("jid", "123@s.whatsapp.net")
                            .with_content(vec![BinaryNode::new("devices").with_content(vec![
                                BinaryNode::new("device-list").with_content(vec![
                                    BinaryNode::new("device").with_attr("id", "0"),
                                    BinaryNode::new("device")
                                        .with_attr("id", "7")
                                        .with_attr("key-index", "1"),
                                    BinaryNode::new("device")
                                        .with_attr("id", "8")
                                        .with_attr("key-index", "2"),
                                ]),
                            ])]),
                    ]),
                ])])
        },
        &mut devices_fut,
    )
    .await;

    assert_eq!(
        devices_fut.await.unwrap(),
        vec![
            USyncDeviceJid {
                jid: "123@s.whatsapp.net".to_owned(),
                key_index: None,
                is_hosted: false,
            },
            USyncDeviceJid {
                jid: "123:8@s.whatsapp.net".to_owned(),
                key_index: Some(2),
                is_hosted: false,
            },
        ]
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn prepare_pairing_code_request_persists_state() {
    let store = wa_store::MemoryAuthStore::new();
    let mut client = Client::builder(store.clone()).connect().await.unwrap();
    let mut events = client.subscribe();

    let request = client
        .prepare_pairing_code_request("+1 234-567", Some("ABCDEFGH"))
        .await
        .unwrap();

    assert_eq!(request.pairing_code, "ABCDEFGH");
    assert_eq!(request.account_jid, "1234567@s.whatsapp.net");
    assert!(matches!(
        events.recv().await.unwrap(),
        Event::CredentialsUpdated
    ));

    let stored = wa_core::load_credentials(&store).await.unwrap().unwrap();
    assert_eq!(stored.pairing_code.as_deref(), Some("ABCDEFGH"));
    assert_eq!(
        stored.account_jid.as_deref(),
        Some("1234567@s.whatsapp.net")
    );
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn send_pairing_code_request_writes_encoded_node() {
    let store = wa_store::MemoryAuthStore::new();
    let mut client = Client::builder(store).connect().await.unwrap();
    let (connection, mut sink_rx, _stream_tx) = mock_connection();

    let request = client
        .send_pairing_code_request(&connection, "+1 234-567", Some("ABCDEFGH"))
        .await
        .unwrap();

    let sent_frame = sink_rx.recv().await.unwrap();
    assert_eq!(sent_frame, encode_binary_node(&request.node).unwrap());

    let sent = decode_inbound_binary_node(&sent_frame).unwrap().node;
    assert_eq!(sent.tag, "iq");
    assert_eq!(sent.attrs["id"], request.node.attrs["id"]);
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn respond_to_link_code_companion_reg_notification_finishes_pairing() {
    let store = wa_store::MemoryAuthStore::new();
    let mut client = Client::builder(store.clone()).connect().await.unwrap();
    client
        .prepare_pairing_code_request("+1 234-567", Some("ABCDEFGH"))
        .await
        .unwrap();
    let mut events = client.subscribe();
    let primary_identity = generate_key_pair();
    let primary_ephemeral = generate_key_pair();
    let wrap_salt = [7u8; 32];
    let wrap_iv = [8u8; 16];
    let key = derive_pairing_code_key("ABCDEFGH", &wrap_salt);
    let wrapped_primary_ephemeral =
        aes_256_ctr_apply(&primary_ephemeral.public, &key, &wrap_iv).unwrap();
    let mut wrapped = Vec::new();
    wrapped.extend_from_slice(&wrap_salt);
    wrapped.extend_from_slice(&wrap_iv);
    wrapped.extend_from_slice(&wrapped_primary_ephemeral);
    let notification = BinaryNode::new("notification")
        .with_attr("id", "link-code-1")
        .with_attr("from", "server@s.whatsapp.net")
        .with_attr("type", "link_code_companion_reg")
        .with_content(vec![
            BinaryNode::new("link_code_companion_reg").with_content(vec![
                BinaryNode::new("link_code_pairing_ref")
                    .with_content(Bytes::from_static(b"pair-ref")),
                BinaryNode::new("primary_identity_pub")
                    .with_content(Bytes::copy_from_slice(&primary_identity.public)),
                BinaryNode::new("link_code_pairing_wrapped_primary_ephemeral_pub")
                    .with_content(Bytes::from(wrapped)),
            ]),
        ]);
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let companion_identity_public = client.credentials.signed_identity_key.public;

    let finish_fut =
        client.respond_to_link_code_companion_reg_notification(&connection, &notification);
    tokio::pin!(finish_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "md");
            assert_eq!(node.attrs["type"], "set");
            let registration = test_child(&node, "link_code_companion_reg");
            assert_eq!(registration.attrs["jid"], "1234567@s.whatsapp.net");
            assert_eq!(registration.attrs["stage"], "companion_finish");
            assert_child(registration, "link_code_pairing_wrapped_key_bundle");
            assert_eq!(
                test_node_bytes(test_child(registration, "companion_identity_public")).as_deref(),
                Some(companion_identity_public.as_slice())
            );
            assert_eq!(
                test_node_bytes(test_child(registration, "link_code_pairing_ref")).as_deref(),
                Some(b"pair-ref".as_slice())
            );
            BinaryNode::new("iq")
                .with_attr("id", node.attrs["id"].clone())
                .with_attr("type", "result")
        },
        &mut finish_fut,
    )
    .await;

    let finish = finish_fut.await.unwrap().unwrap();
    assert!(finish.credentials.registered);
    assert!(finish.credentials.pairing_code.is_none());
    assert!(matches!(
        events.recv().await.unwrap(),
        Event::CredentialsUpdated
    ));
    let stored = wa_core::load_credentials(&store).await.unwrap().unwrap();
    assert!(stored.registered);
    assert!(stored.pairing_code.is_none());
    assert_eq!(
        stored.adv_secret_key.expose(),
        finish.credentials.adv_secret_key.expose()
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn respond_to_pair_device_challenge_sends_ack_and_emits_qr() {
    let store = wa_store::MemoryAuthStore::new();
    let client = Client::builder(store).connect().await.unwrap();
    let mut events = client.subscribe();
    let (connection, mut sink_rx, _stream_tx) = mock_connection();
    let stanza = BinaryNode::new("iq")
        .with_attr("id", "pair-1")
        .with_content(vec![BinaryNode::new("pair-device").with_content(vec![
            BinaryNode::new("ref").with_content("ref-a"),
            BinaryNode::new("ref").with_content("ref-b"),
        ])]);

    let qr_codes = client
        .respond_to_pair_device_challenge(&connection, &stanza)
        .await
        .unwrap();

    let ack = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(
        ack,
        BinaryNode::new("iq")
            .with_attr("to", "s.whatsapp.net")
            .with_attr("type", "result")
            .with_attr("id", "pair-1")
    );
    assert_eq!(qr_codes.len(), 2);
    assert!(matches!(
        events.recv().await.unwrap(),
        Event::Qr(qr) if qr.contains("#ref-a,")
    ));
    assert!(matches!(
        events.recv().await.unwrap(),
        Event::Qr(qr) if qr.contains("#ref-b,")
    ));
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn respond_to_pair_success_sends_reply_and_persists_credentials() {
    let store = wa_store::MemoryAuthStore::new();
    let mut client = Client::builder(store.clone()).connect().await.unwrap();
    let credentials = client.credentials().clone();
    let account_key = generate_key_pair();
    let stanza = pair_success_stanza(&credentials, &account_key);
    let mut events = client.subscribe();
    let (connection, mut sink_rx, _stream_tx) = mock_connection();

    client
        .respond_to_pair_success(&connection, &stanza)
        .await
        .unwrap();

    let reply = decode_inbound_binary_node(&sink_rx.recv().await.unwrap())
        .unwrap()
        .node;
    assert_eq!(reply.attrs["id"], "success-1");
    assert!(matches!(
        events.recv().await.unwrap(),
        Event::CredentialsUpdated
    ));

    let stored = wa_core::load_credentials(&store).await.unwrap().unwrap();
    assert!(stored.registered);
    assert_eq!(
        stored.account_jid.as_deref(),
        Some("12345:7@s.whatsapp.net")
    );
    assert_eq!(stored.account_lid.as_deref(), Some("abc@lid"));
    assert_eq!(
        stored.account_signature_key,
        Some(Bytes::copy_from_slice(&account_key.public))
    );
    assert!(
        stored
            .signed_device_identity
            .as_ref()
            .is_some_and(|identity| !identity.is_empty())
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn query_available_pre_key_count_sends_count_iq() {
    let store = wa_store::MemoryAuthStore::new();
    let client = Client::builder(store).connect().await.unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let count_fut = client.query_available_pre_key_count(&connection);
    tokio::pin!(count_fut);

    let sent_frame = tokio::select! {
        result = &mut count_fut => panic!("count query completed before the mock server response: {result:?}"),
        sent = sink_rx.recv() => sent.unwrap(),
    };
    let sent = decode_inbound_binary_node(&sent_frame).unwrap().node;
    assert_eq!(sent.attrs["xmlns"], "encrypt");
    assert_eq!(sent.attrs["type"], "get");
    assert_eq!(sent.attrs["to"], wa_core::SERVER_JID);
    let tag = sent.attrs["id"].clone();
    stream_tx
        .send(InboundFrame::new(
            encode_binary_node(
                &BinaryNode::new("iq")
                    .with_attr("id", tag)
                    .with_attr("type", "result")
                    .with_content(vec![BinaryNode::new("count").with_attr("value", "7")]),
            )
            .unwrap(),
        ))
        .await
        .unwrap();

    assert_eq!(count_fut.await.unwrap(), 7);
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn validates_key_bundle_digest_as_typed_result() {
    let store = wa_store::MemoryAuthStore::new();
    let client = Client::builder(store).connect().await.unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection();

    let valid_fut = client.validate_key_bundle_digest(&connection);
    tokio::pin!(valid_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["xmlns"], "encrypt");
            assert_eq!(node.attrs["type"], "get");
            assert_eq!(node.attrs["to"], wa_core::SERVER_JID);
            assert_child(&node, "digest");
            BinaryNode::new("iq")
                .with_attr("id", node.attrs["id"].clone())
                .with_attr("type", "result")
                .with_content(vec![BinaryNode::new("digest")])
        },
        &mut valid_fut,
    )
    .await;
    assert!(valid_fut.await.unwrap());

    let missing_fut = client.validate_key_bundle_digest(&connection);
    tokio::pin!(missing_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_child(&node, "digest");
            BinaryNode::new("iq")
                .with_attr("id", node.attrs["id"].clone())
                .with_attr("type", "result")
        },
        &mut missing_fut,
    )
    .await;
    assert!(!missing_fut.await.unwrap());
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn upload_pre_keys_sends_query_and_persists_keys() {
    let store = wa_store::MemoryAuthStore::new();
    let mut client = Client::builder(store.clone()).connect().await.unwrap();
    let mut events = client.subscribe();
    let (connection, mut sink_rx, stream_tx) = mock_connection();

    let upload = {
        let upload_fut = client.upload_pre_keys(&connection, 3);
        tokio::pin!(upload_fut);

        let sent_frame = tokio::select! {
            result = &mut upload_fut => panic!("pre-key upload completed before the mock server response: {result:?}"),
            sent = sink_rx.recv() => sent.unwrap(),
        };
        let sent = decode_inbound_binary_node(&sent_frame).unwrap().node;
        assert_eq!(sent.attrs["xmlns"], "encrypt");
        assert_eq!(sent.attrs["type"], "set");
        assert_eq!(sent.attrs["to"], wa_core::SERVER_JID);
        let tag = sent.attrs["id"].clone();
        stream_tx
            .send(InboundFrame::new(
                encode_binary_node(
                    &BinaryNode::new("iq")
                        .with_attr("id", tag)
                        .with_attr("type", "result"),
                )
                .unwrap(),
            ))
            .await
            .unwrap();

        upload_fut.await.unwrap()
    };

    assert_eq!(upload.pre_key_ids, vec![1, 2, 3]);
    assert!(matches!(
        events.recv().await.unwrap(),
        Event::CredentialsUpdated
    ));
    let stored = wa_core::load_credentials(&store).await.unwrap().unwrap();
    assert_eq!(stored.next_pre_key_id, 4);
    assert_eq!(stored.first_unuploaded_pre_key_id, 4);
    for key_id in 1..=3 {
        assert!(
            store
                .get(KeyNamespace::PreKey, &key_id.to_string())
                .await
                .unwrap()
                .is_some()
        );
    }

    {
        let failed_upload_fut = client.upload_pre_keys(&connection, 1);
        tokio::pin!(failed_upload_fut);
        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_eq!(node.attrs["xmlns"], "encrypt");
                assert_eq!(node.attrs["type"], "set");
                assert_child(&node, "list");
                error_result_for(&node, "500", "upload failed")
            },
            &mut failed_upload_fut,
        )
        .await;
        let err = failed_upload_fut.await.unwrap_err();
        assert!(
            err.to_string()
                .contains("pre-key upload failed (500): upload failed")
        );
    }
    let failed_stored = wa_core::load_credentials(&store).await.unwrap().unwrap();
    assert_eq!(failed_stored.next_pre_key_id, 5);
    assert_eq!(failed_stored.first_unuploaded_pre_key_id, 4);
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn rotate_signed_pre_key_sends_query_then_persists_rotation() {
    let store = wa_store::MemoryAuthStore::new();
    let mut client = Client::builder(store.clone()).connect().await.unwrap();
    let original_key_id = client.credentials().signed_pre_key.key_id;
    let mut events = client.subscribe();
    let (connection, mut sink_rx, stream_tx) = mock_connection();

    let rotated = {
        let rotate_fut = client.rotate_signed_pre_key(&connection);
        tokio::pin!(rotate_fut);

        let sent_frame = tokio::select! {
            result = &mut rotate_fut => panic!("signed pre-key rotation completed before the mock server response: {result:?}"),
            sent = sink_rx.recv() => sent.unwrap(),
        };
        let sent = decode_inbound_binary_node(&sent_frame).unwrap().node;
        assert_eq!(sent.attrs["xmlns"], "encrypt");
        assert_eq!(sent.attrs["type"], "set");
        assert_eq!(sent.attrs["to"], wa_core::SERVER_JID);
        let tag = sent.attrs["id"].clone();
        stream_tx
            .send(InboundFrame::new(
                encode_binary_node(
                    &BinaryNode::new("iq")
                        .with_attr("id", tag)
                        .with_attr("type", "result"),
                )
                .unwrap(),
            ))
            .await
            .unwrap();

        rotate_fut.await.unwrap()
    };

    assert_eq!(rotated.key_id, original_key_id + 1);
    assert!(matches!(
        events.recv().await.unwrap(),
        Event::CredentialsUpdated
    ));
    let stored = wa_core::load_credentials(&store).await.unwrap().unwrap();
    assert_eq!(stored.signed_pre_key, rotated);

    {
        let failed_rotate_fut = client.rotate_signed_pre_key(&connection);
        tokio::pin!(failed_rotate_fut);
        respond_to_next_query(
            &mut sink_rx,
            &stream_tx,
            |node| {
                assert_eq!(node.attrs["xmlns"], "encrypt");
                assert_eq!(node.attrs["type"], "set");
                assert_child(&node, "rotate");
                error_result_for(&node, "409", "rotation rejected")
            },
            &mut failed_rotate_fut,
        )
        .await;
        let err = failed_rotate_fut.await.unwrap_err();
        assert!(
            err.to_string()
                .contains("signed pre-key rotation failed (409): rotation rejected")
        );
    }
    let stored_after_error = wa_core::load_credentials(&store).await.unwrap().unwrap();
    assert_eq!(stored_after_error.signed_pre_key, rotated);
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn post_auth_maintenance_uploads_minimum_when_digest_valid_but_server_count_low() {
    let store = wa_store::MemoryAuthStore::new();
    let mut client = Client::builder(store.clone()).connect().await.unwrap();
    let mut events = client.subscribe();
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let maintenance_fut = client.run_post_auth_key_maintenance(&connection);
    tokio::pin!(maintenance_fut);

    let digest_tag = respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_child(&node, "digest");
            BinaryNode::new("iq")
                .with_attr("id", node.attrs["id"].clone())
                .with_attr("type", "result")
                .with_content(vec![BinaryNode::new("digest")])
        },
        &mut maintenance_fut,
    )
    .await;
    assert!(digest_tag.starts_with("q-"));

    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_child(&node, "count");
            BinaryNode::new("iq")
                .with_attr("id", node.attrs["id"].clone())
                .with_attr("type", "result")
                .with_content(vec![BinaryNode::new("count").with_attr("value", "1")])
        },
        &mut maintenance_fut,
    )
    .await;

    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_child(&node, "list");
            BinaryNode::new("iq")
                .with_attr("id", node.attrs["id"].clone())
                .with_attr("type", "result")
        },
        &mut maintenance_fut,
    )
    .await;

    let maintenance = maintenance_fut.await.unwrap();
    assert!(maintenance.digest_validated);
    assert_eq!(
        maintenance.pre_key_upload.unwrap().pre_key_ids,
        vec![1, 2, 3, 4, 5]
    );
    assert!(maintenance.signed_pre_key_rotation.is_none());
    assert!(matches!(
        events.recv().await.unwrap(),
        Event::CredentialsUpdated
    ));
    let stored = wa_core::load_credentials(&store).await.unwrap().unwrap();
    assert_eq!(stored.next_pre_key_id, 6);
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn post_auth_maintenance_uploads_initial_keys_after_missing_digest_and_rotates_when_enabled()
{
    let store = wa_store::MemoryAuthStore::new();
    let config = ClientConfig {
        rotate_signed_pre_key_on_connect: true,
        ..ClientConfig::default()
    };
    let mut client = Client::builder(store.clone())
        .config(config)
        .connect()
        .await
        .unwrap();
    let original_signed_pre_key_id = client.credentials().signed_pre_key.key_id;
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let maintenance_fut = client.run_post_auth_key_maintenance(&connection);
    tokio::pin!(maintenance_fut);

    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_child(&node, "digest");
            BinaryNode::new("iq")
                .with_attr("id", node.attrs["id"].clone())
                .with_attr("type", "result")
        },
        &mut maintenance_fut,
    )
    .await;

    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_child(&node, "list");
            BinaryNode::new("iq")
                .with_attr("id", node.attrs["id"].clone())
                .with_attr("type", "result")
        },
        &mut maintenance_fut,
    )
    .await;

    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_child(&node, "rotate");
            BinaryNode::new("iq")
                .with_attr("id", node.attrs["id"].clone())
                .with_attr("type", "result")
        },
        &mut maintenance_fut,
    )
    .await;

    let maintenance = maintenance_fut.await.unwrap();
    assert!(!maintenance.digest_validated);
    assert_eq!(
        maintenance.pre_key_upload.unwrap().pre_key_ids.len(),
        wa_core::INITIAL_PRE_KEY_COUNT
    );
    assert_eq!(
        maintenance.signed_pre_key_rotation.unwrap().key_id,
        original_signed_pre_key_id + 1
    );

    let stored = wa_core::load_credentials(&store).await.unwrap().unwrap();
    assert_eq!(
        stored.next_pre_key_id,
        wa_core::INITIAL_PRE_KEY_COUNT as u32 + 1
    );
    assert_eq!(stored.signed_pre_key.key_id, original_signed_pre_key_id + 1);
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn history_sync_facade_downloads_and_processes_payload() {
    let store = wa_store::MemoryAuthStore::new();
    let client = Client::builder(store).connect().await.unwrap();
    let history = wa_core::HistorySync {
        sync_type: wa_core::HistorySyncType::InitialBootstrap as i32,
        conversations: vec![wa_proto::proto::Conversation {
            id: "123@s.whatsapp.net".to_owned(),
            display_name: Some("Alice".to_owned()),
            messages: vec![wa_proto::proto::HistorySyncMsg {
                msg_order_id: Some(1),
                message: Some(wa_proto::proto::WebMessageInfo {
                    key: Some(wa_proto::proto::MessageKey {
                        remote_jid: Some("123@s.whatsapp.net".to_owned()),
                        from_me: Some(false),
                        id: Some("msg-1".to_owned()),
                        participant: None,
                    }),
                    message_timestamp: Some(1_700_000_000),
                    ..Default::default()
                }),
            }],
            ..Default::default()
        }],
        ..Default::default()
    };
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&history.encode_to_vec()).unwrap();
    let compressed = Bytes::from(encoder.finish().unwrap());
    let encrypted = wa_crypto::encrypt_media_bytes_with_key(
        &compressed,
        wa_crypto::MediaKind::HistorySync,
        &[5u8; 32],
    )
    .unwrap();
    let notification = wa_core::HistorySyncNotification {
        file_sha256: Some(encrypted.file_sha256.clone()),
        file_length: Some(encrypted.file_length),
        media_key: Some(Bytes::copy_from_slice(encrypted.media_key.expose())),
        file_enc_sha256: Some(encrypted.file_enc_sha256.clone()),
        direct_path: Some("/history/sync".to_owned()),
        ..Default::default()
    };
    let transport = HistoryDownloadTransport::default();
    transport.add_download(
        "https://history.test/history/sync",
        encrypted.ciphertext_with_mac.clone(),
    );
    let transfer = wa_core::MediaTransfer::new(transport);

    let processed = client
        .download_and_process_history_sync(
            &transfer,
            &notification,
            Some("history.test"),
            wa_core::HistorySyncDecodeConfig::default(),
            wa_core::HistorySyncProcessConfig::default().latest(true),
        )
        .await
        .unwrap();

    let history = processed.batch.history.unwrap();
    assert!(history.is_latest);
    assert_eq!(history.chats.len(), 1);
    assert_eq!(history.messages.len(), 1);
    assert_eq!(history.messages[0].key.id, "msg-1");
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn history_sync_event_pump_downloads_persists_and_emits_batch() {
    let store = wa_store::MemoryAuthStore::new();
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let mut events = client.subscribe();
    let history = wa_core::HistorySync {
        sync_type: wa_core::HistorySyncType::InitialBootstrap as i32,
        conversations: vec![wa_proto::proto::Conversation {
            id: "123@s.whatsapp.net".to_owned(),
            display_name: Some("Alice".to_owned()),
            messages: vec![wa_proto::proto::HistorySyncMsg {
                msg_order_id: Some(1),
                message: Some(wa_proto::proto::WebMessageInfo {
                    key: Some(wa_proto::proto::MessageKey {
                        remote_jid: Some("123@s.whatsapp.net".to_owned()),
                        from_me: Some(false),
                        id: Some("msg-1".to_owned()),
                        participant: None,
                    }),
                    message_timestamp: Some(1_700_000_000),
                    ..Default::default()
                }),
            }],
            ..Default::default()
        }],
        phone_number_to_lid_mappings: vec![wa_proto::proto::PhoneNumberToLidMapping {
            pn_jid: Some("15551234567@s.whatsapp.net".to_owned()),
            lid_jid: Some("999999@lid".to_owned()),
        }],
        ..Default::default()
    };
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&history.encode_to_vec()).unwrap();
    let compressed = Bytes::from(encoder.finish().unwrap());
    let encrypted = wa_crypto::encrypt_media_bytes_with_key(
        &compressed,
        wa_crypto::MediaKind::HistorySync,
        &[5u8; 32],
    )
    .unwrap();
    let notification = wa_core::HistorySyncNotification {
        file_sha256: Some(encrypted.file_sha256.clone()),
        file_length: Some(encrypted.file_length),
        media_key: Some(Bytes::copy_from_slice(encrypted.media_key.expose())),
        file_enc_sha256: Some(encrypted.file_enc_sha256.clone()),
        direct_path: Some("/history/sync".to_owned()),
        ..Default::default()
    };
    let transport = HistoryDownloadTransport::default();
    transport.add_download(
        "https://history.test/history/sync",
        encrypted.ciphertext_with_mac.clone(),
    );
    let transfer = wa_core::MediaTransfer::new(transport);

    let processed = client
        .download_process_and_emit_history_sync(
            &transfer,
            &notification,
            Some("history.test"),
            wa_core::HistorySyncDecodeConfig::default(),
            wa_core::HistorySyncProcessConfig::default().latest(true),
        )
        .await
        .unwrap();

    assert_eq!(processed.lid_pn_mappings.len(), 1);
    let mappings = recv_lid_mapping_event(&mut events).await;
    assert_eq!(
        mappings,
        vec![wa_core::LidMappingEvent::new(
            "999999@lid",
            "15551234567@s.whatsapp.net",
        )]
    );
    let batch = recv_batch_event(&mut events).await;
    let history = batch.history.as_ref().unwrap();
    assert!(history.is_latest);
    assert_eq!(history.chats.len(), 1);
    assert_eq!(history.messages.len(), 1);
    assert_eq!(history.messages[0].key.id, "msg-1");

    let stored_message_key = wa_core::message_event_store_key(&history.messages[0].key);
    let stored_message = store
        .get(KeyNamespace::MessageEvent, &stored_message_key)
        .await
        .unwrap()
        .unwrap();
    let stored_message = wa_core::decode_stored_message_event(&stored_message).unwrap();
    assert_eq!(stored_message.key.id, "msg-1");

    let stored_chat = store
        .get(KeyNamespace::ChatEvent, "123@s.whatsapp.net")
        .await
        .unwrap()
        .unwrap();
    let stored_chat = wa_core::decode_stored_chat_event(&stored_chat).unwrap();
    assert_eq!(stored_chat.fields["display_name"], "Alice");

    let mapping_store = wa_core::LidPnMappingStore::new(store);
    assert_eq!(
        mapping_store
            .lid_for_pn("15551234567@s.whatsapp.net")
            .await
            .unwrap(),
        Some("999999".to_owned())
    );
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn history_sync_non_blocking_data_persists_and_emits_contact_status_and_mapping() {
    let store = wa_store::MemoryAuthStore::new();
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let mut events = client.subscribe();
    let history = wa_core::HistorySync {
        sync_type: wa_core::HistorySyncType::NonBlockingData as i32,
        pushnames: vec![wa_proto::proto::Pushname {
            id: Some("123@s.whatsapp.net".to_owned()),
            pushname: Some("Alice".to_owned()),
        }],
        status_v3_messages: vec![wa_proto::proto::WebMessageInfo {
            key: Some(wa_proto::proto::MessageKey {
                remote_jid: Some("status@broadcast".to_owned()),
                from_me: Some(false),
                id: Some("status-1".to_owned()),
                participant: Some("123@s.whatsapp.net".to_owned()),
            }),
            message: Some(wa_proto::proto::Message {
                conversation: Some("status update".to_owned()),
                ..Default::default()
            }),
            message_timestamp: Some(1_700_000_020),
            push_name: Some("Alice".to_owned()),
            ..Default::default()
        }],
        phone_number_to_lid_mappings: vec![wa_proto::proto::PhoneNumberToLidMapping {
            pn_jid: Some("123@s.whatsapp.net".to_owned()),
            lid_jid: Some("999999@lid".to_owned()),
        }],
        global_settings: Some(wa_proto::proto::GlobalSettings {
            media_visibility: Some(wa_proto::proto::MediaVisibility::On as i32),
            light_theme_wallpaper: Some(wa_proto::proto::WallpaperSettings {
                filename: Some("light.jpg".to_owned()),
                opacity: Some(80),
            }),
            dark_theme_wallpaper: Some(wa_proto::proto::WallpaperSettings {
                filename: Some("dark.jpg".to_owned()),
                opacity: Some(70),
            }),
            auto_download_wi_fi: Some(wa_proto::proto::AutoDownloadSettings {
                download_images: Some(true),
                download_audio: Some(false),
                download_video: Some(true),
                download_documents: Some(false),
            }),
            auto_download_cellular: Some(wa_proto::proto::AutoDownloadSettings {
                download_images: Some(false),
                download_audio: Some(true),
                download_video: Some(false),
                download_documents: Some(true),
            }),
            auto_download_roaming: Some(wa_proto::proto::AutoDownloadSettings {
                download_images: Some(false),
                download_audio: Some(false),
                download_video: Some(false),
                download_documents: Some(false),
            }),
            show_individual_notifications_preview: Some(true),
            show_group_notifications_preview: Some(false),
            disappearing_mode_duration: Some(86_400),
            disappearing_mode_timestamp: Some(1_700_000_060),
            avatar_user_settings: Some(wa_proto::proto::AvatarUserSettings {
                fbid: Some("fbid-1".to_owned()),
                password: Some("secret".to_owned()),
            }),
            font_size: Some(2),
            security_notifications: Some(true),
            auto_unarchive_chats: Some(false),
            video_quality_mode: Some(1),
            photo_quality_mode: Some(2),
            individual_notification_settings: Some(wa_proto::proto::NotificationSettings {
                message_vibrate: Some("short".to_owned()),
                message_popup: Some("always".to_owned()),
                message_light: Some("white".to_owned()),
                low_priority_notifications: Some(true),
                reactions_muted: Some(false),
                call_vibrate: Some("long".to_owned()),
            }),
            group_notification_settings: Some(wa_proto::proto::NotificationSettings {
                message_vibrate: Some("default".to_owned()),
                message_popup: Some("never".to_owned()),
                message_light: Some("green".to_owned()),
                low_priority_notifications: Some(false),
                reactions_muted: Some(true),
                call_vibrate: Some("short".to_owned()),
            }),
            chat_db_lid_migration_timestamp: Some(1_700_000_080),
            ..Default::default()
        }),
        accounts: vec![
            wa_proto::proto::Account {
                lid: Some("456".to_owned()),
                username: Some("alice_handle".to_owned()),
                country_code: Some("1".to_owned()),
                is_username_deleted: Some(false),
            },
            wa_proto::proto::Account {
                lid: Some("789@lid".to_owned()),
                username: Some("old_handle".to_owned()),
                country_code: Some("55".to_owned()),
                is_username_deleted: Some(true),
            },
        ],
        recent_stickers: vec![wa_proto::proto::StickerMetadata {
            url: Some("https://mmg.whatsapp.net/sticker".to_owned()),
            file_sha256: Some(Bytes::from_static(&[1, 2, 3])),
            file_enc_sha256: Some(Bytes::from_static(&[4, 5, 6])),
            media_key: Some(Bytes::from_static(&[7; 32])),
            mimetype: Some("image/webp".to_owned()),
            height: Some(512),
            width: Some(512),
            direct_path: Some("/v/t62.15575/sticker".to_owned()),
            file_length: Some(1234),
            weight: Some(0.75),
            last_sticker_sent_ts: Some(1_700_000_070),
            is_lottie: Some(false),
            image_hash: Some("hash-1".to_owned()),
            is_avatar_sticker: Some(true),
        }],
        call_log_records: vec![wa_proto::proto::CallLogRecord {
            call_result: Some(wa_proto::proto::call_log_record::CallResult::Missed as i32),
            silence_reason: Some(wa_proto::proto::call_log_record::SilenceReason::Privacy as i32),
            duration: Some(42),
            start_time: Some(1_700_000_030),
            is_incoming: Some(true),
            is_video: Some(true),
            call_id: Some("call-1".to_owned()),
            call_creator_jid: Some("123@s.whatsapp.net".to_owned()),
            group_jid: Some("456@g.us".to_owned()),
            participants: vec![
                wa_proto::proto::call_log_record::ParticipantInfo {
                    user_jid: Some("123@s.whatsapp.net".to_owned()),
                    call_result: Some(wa_proto::proto::call_log_record::CallResult::Missed as i32),
                },
                wa_proto::proto::call_log_record::ParticipantInfo {
                    user_jid: Some("789@s.whatsapp.net".to_owned()),
                    call_result: Some(
                        wa_proto::proto::call_log_record::CallResult::Connected as i32,
                    ),
                },
            ],
            call_type: Some(wa_proto::proto::call_log_record::CallType::Regular as i32),
            ..Default::default()
        }],
        past_participants: vec![wa_proto::proto::PastParticipants {
            group_jid: Some("456@g.us".to_owned()),
            past_participants: vec![
                wa_proto::proto::PastParticipant {
                    user_jid: Some("123@s.whatsapp.net".to_owned()),
                    leave_reason: Some(wa_proto::proto::past_participant::LeaveReason::Left as i32),
                    leave_ts: Some(1_700_000_040),
                },
                wa_proto::proto::PastParticipant {
                    user_jid: Some("789@s.whatsapp.net".to_owned()),
                    leave_reason: Some(
                        wa_proto::proto::past_participant::LeaveReason::Removed as i32,
                    ),
                    leave_ts: Some(1_700_000_050),
                },
            ],
        }],
        thread_id_user_secret: Some(Bytes::from_static(&[8, 9, 10, 11])),
        thread_ds_timeframe_offset: Some(15),
        ai_wait_list_state: Some(
            wa_proto::proto::history_sync::BotAiWaitListState::AiAvailable as i32,
        ),
        companion_meta_nonce: Some("nonce-1".to_owned()),
        shareable_chat_identifier_encryption_key: Some(Bytes::from_static(&[12, 13, 14])),
        ..Default::default()
    };
    let processed =
        wa_core::process_history_sync(&history, wa_core::HistorySyncProcessConfig::default())
            .unwrap();

    let processed = client.process_history_sync_result(processed).await.unwrap();

    assert_eq!(
        processed.sync_type,
        wa_core::HistorySyncType::NonBlockingData
    );
    assert_eq!(processed.lid_pn_mappings.len(), 1);
    assert_eq!(
        processed.default_disappearing_mode,
        Some(wa_core::DefaultDisappearingMode::new(86_400).with_timestamp(1_700_000_060))
    );
    let mappings = recv_lid_mapping_event(&mut events).await;
    assert_eq!(
        mappings,
        vec![wa_core::LidMappingEvent::new(
            "999999@lid",
            "123@s.whatsapp.net",
        )]
    );

    let batch = recv_batch_event(&mut events).await;
    let history = batch.history.as_ref().unwrap();
    assert_eq!(history.contacts.len(), 3);
    assert_eq!(history.contacts[0].jid, "123@s.whatsapp.net");
    assert_eq!(history.contacts[0].fields["notify"], "Alice");
    assert_eq!(history.contacts[1].jid, "456@lid");
    assert_eq!(history.contacts[1].fields["source"], "history_account");
    assert_eq!(history.contacts[1].fields["username"], "alice_handle");
    assert_eq!(history.contacts[1].fields["country_code"], "1");
    assert_eq!(history.contacts[1].fields["is_username_deleted"], "false");
    assert_eq!(history.contacts[2].jid, "789@lid");
    assert_eq!(history.contacts[2].fields["source"], "history_account");
    assert_eq!(history.contacts[2].fields["username"], "");
    assert_eq!(history.contacts[2].fields["username_deleted"], "true");
    assert_eq!(history.contacts[2].fields["is_username_deleted"], "true");
    assert_eq!(history.contacts[2].fields["country_code"], "55");
    assert_eq!(history.messages.len(), 1);
    assert_eq!(history.messages[0].key.remote_jid, "status@broadcast");
    assert_eq!(
        history.messages[0].key.participant.as_deref(),
        Some("123@s.whatsapp.net")
    );
    assert_eq!(history.messages[0].key.id, "status-1");
    assert_eq!(
        history.messages[0].fields["history_sync_type"],
        "NON_BLOCKING_DATA"
    );
    assert_eq!(batch.recent_stickers.len(), 1);
    let sticker = &batch.recent_stickers[0];
    assert_eq!(sticker.id, "file_sha256:010203");
    assert_eq!(sticker.file_sha256.as_deref(), Some(&[1, 2, 3][..]));
    assert_eq!(sticker.file_enc_sha256.as_deref(), Some(&[4, 5, 6][..]));
    assert_eq!(sticker.media_key.as_deref(), Some(&[7; 32][..]));
    assert_eq!(sticker.fields["source"], "history_recent_sticker");
    assert_eq!(sticker.fields["mimetype"], "image/webp");
    assert_eq!(sticker.fields["direct_path"], "/v/t62.15575/sticker");
    assert_eq!(sticker.fields["last_sticker_sent_ts"], "1700000070");
    assert_eq!(batch.account_settings.len(), 1);
    let settings = &batch.account_settings[0];
    assert_eq!(settings.id, "history_sync");
    assert_eq!(settings.fields["source"], "history_sync");
    assert_eq!(settings.fields["media_visibility"], "ON");
    assert_eq!(
        settings.fields["light_theme_wallpaper_filename"],
        "light.jpg"
    );
    assert_eq!(settings.fields["light_theme_wallpaper_opacity"], "80");
    assert_eq!(settings.fields["dark_theme_wallpaper_filename"], "dark.jpg");
    assert_eq!(settings.fields["dark_theme_wallpaper_opacity"], "70");
    assert_eq!(settings.fields["auto_download_wifi_images"], "true");
    assert_eq!(settings.fields["auto_download_wifi_audio"], "false");
    assert_eq!(settings.fields["auto_download_cellular_documents"], "true");
    assert_eq!(settings.fields["auto_download_roaming_video"], "false");
    assert_eq!(
        settings.fields["show_individual_notifications_preview"],
        "true"
    );
    assert_eq!(settings.fields["show_group_notifications_preview"], "false");
    assert_eq!(settings.fields["disappearing_mode_duration"], "86400");
    assert_eq!(settings.fields["disappearing_mode_timestamp"], "1700000060");
    assert_eq!(settings.fields["avatar_fbid"], "fbid-1");
    assert_eq!(settings.fields["avatar_password_present"], "true");
    assert!(!settings.fields.contains_key("avatar_password"));
    assert_eq!(settings.fields["font_size"], "2");
    assert_eq!(settings.fields["security_notifications"], "true");
    assert_eq!(settings.fields["auto_unarchive_chats"], "false");
    assert_eq!(settings.fields["video_quality_mode"], "1");
    assert_eq!(settings.fields["photo_quality_mode"], "2");
    assert_eq!(
        settings.fields["individual_notification_message_vibrate"],
        "short"
    );
    assert_eq!(
        settings.fields["individual_notification_message_popup"],
        "always"
    );
    assert_eq!(
        settings.fields["individual_notification_message_light"],
        "white"
    );
    assert_eq!(
        settings.fields["individual_notification_low_priority_notifications"],
        "true"
    );
    assert_eq!(
        settings.fields["individual_notification_reactions_muted"],
        "false"
    );
    assert_eq!(
        settings.fields["individual_notification_call_vibrate"],
        "long"
    );
    assert_eq!(
        settings.fields["group_notification_message_vibrate"],
        "default"
    );
    assert_eq!(settings.fields["group_notification_message_popup"], "never");
    assert_eq!(settings.fields["group_notification_message_light"], "green");
    assert_eq!(
        settings.fields["group_notification_low_priority_notifications"],
        "false"
    );
    assert_eq!(
        settings.fields["group_notification_reactions_muted"],
        "true"
    );
    assert_eq!(settings.fields["group_notification_call_vibrate"], "short");
    assert_eq!(
        settings.fields["chat_db_lid_migration_timestamp"],
        "1700000080"
    );
    assert_eq!(settings.fields["thread_id_user_secret_present"], "true");
    assert_eq!(settings.fields["thread_id_user_secret_len"], "4");
    assert_eq!(settings.fields["thread_ds_timeframe_offset"], "15");
    assert_eq!(settings.fields["ai_wait_list_state"], "AI_AVAILABLE");
    assert_eq!(settings.fields["companion_meta_nonce"], "nonce-1");
    assert_eq!(
        settings.fields["shareable_chat_identifier_encryption_key_present"],
        "true"
    );
    assert_eq!(
        settings.fields["shareable_chat_identifier_encryption_key_len"],
        "3"
    );
    assert_eq!(batch.calls_update.len(), 1);
    let call = &batch.calls_update[0];
    assert_eq!(call.id, "call-1");
    assert_eq!(call.from, "456@g.us");
    assert_eq!(call.event_type, "history_log");
    assert_eq!(call.fields["source"], "history_call_log");
    assert_eq!(call.fields["call_result"], "MISSED");
    assert_eq!(call.fields["participants_count"], "2");
    assert_eq!(batch.groups_update.len(), 1);
    let group = &batch.groups_update[0];
    assert_eq!(group.jid, "456@g.us");
    assert_eq!(group.fields["source"], "history_past_participants");
    assert_eq!(group.fields["participants_leave"], "123@s.whatsapp.net");
    assert_eq!(group.fields["participants_remove"], "789@s.whatsapp.net");
    let disappearing_mode = recv_default_disappearing_mode_event(&mut events).await;
    assert_eq!(
        disappearing_mode,
        wa_core::DefaultDisappearingMode::new(86_400).with_timestamp(1_700_000_060)
    );

    let stored_contact = store
        .get(KeyNamespace::ContactEvent, "123@s.whatsapp.net")
        .await
        .unwrap()
        .unwrap();
    let stored_contact = wa_core::decode_stored_contact_event(&stored_contact).unwrap();
    assert_eq!(stored_contact.fields["notify"], "Alice");

    let stored_account = store
        .get(KeyNamespace::ContactEvent, "456@lid")
        .await
        .unwrap()
        .unwrap();
    let stored_account = wa_core::decode_stored_contact_event(&stored_account).unwrap();
    assert_eq!(stored_account.fields["source"], "history_account");
    assert_eq!(stored_account.fields["username"], "alice_handle");
    assert_eq!(stored_account.fields["country_code"], "1");
    assert_eq!(stored_account.fields["is_username_deleted"], "false");

    let stored_deleted_account = store
        .get(KeyNamespace::ContactEvent, "789@lid")
        .await
        .unwrap()
        .unwrap();
    let stored_deleted_account =
        wa_core::decode_stored_contact_event(&stored_deleted_account).unwrap();
    assert_eq!(stored_deleted_account.fields["source"], "history_account");
    assert_eq!(stored_deleted_account.fields["username"], "");
    assert_eq!(stored_deleted_account.fields["username_deleted"], "true");
    assert_eq!(stored_deleted_account.fields["is_username_deleted"], "true");
    assert_eq!(stored_deleted_account.fields["country_code"], "55");

    let sticker_key = wa_core::recent_sticker_event_store_key(sticker);
    let stored_sticker = store
        .get(KeyNamespace::RecentStickerEvent, &sticker_key)
        .await
        .unwrap()
        .unwrap();
    let stored_sticker = wa_core::decode_stored_recent_sticker_event(&stored_sticker).unwrap();
    assert_eq!(stored_sticker.id, "file_sha256:010203");
    assert_eq!(stored_sticker.file_sha256.as_deref(), Some(&[1, 2, 3][..]));
    assert_eq!(
        stored_sticker.file_enc_sha256.as_deref(),
        Some(&[4, 5, 6][..])
    );
    assert_eq!(stored_sticker.media_key.as_deref(), Some(&[7; 32][..]));
    assert_eq!(stored_sticker.fields["source"], "history_recent_sticker");
    assert_eq!(stored_sticker.fields["mimetype"], "image/webp");

    let settings_key = wa_core::account_settings_event_store_key(settings);
    let stored_settings = store
        .get(KeyNamespace::AccountSettingsEvent, &settings_key)
        .await
        .unwrap()
        .unwrap();
    let stored_settings = wa_core::decode_stored_account_settings_event(&stored_settings).unwrap();
    assert_eq!(stored_settings.id, "history_sync");
    assert_eq!(stored_settings.fields["source"], "history_sync");
    assert_eq!(stored_settings.fields["media_visibility"], "ON");
    assert_eq!(
        stored_settings.fields["individual_notification_call_vibrate"],
        "long"
    );
    assert_eq!(
        stored_settings.fields["group_notification_reactions_muted"],
        "true"
    );
    assert_eq!(
        stored_settings.fields["thread_id_user_secret_present"],
        "true"
    );
    assert_eq!(stored_settings.fields["thread_id_user_secret_len"], "4");
    assert_eq!(
        stored_settings.fields["shareable_chat_identifier_encryption_key_len"],
        "3"
    );
    assert!(!stored_settings.fields.contains_key("avatar_password"));

    let stored_message_key = wa_core::message_event_store_key(&history.messages[0].key);
    let stored_message = store
        .get(KeyNamespace::MessageEvent, &stored_message_key)
        .await
        .unwrap()
        .unwrap();
    let stored_message = wa_core::decode_stored_message_event(&stored_message).unwrap();
    assert_eq!(stored_message.key.id, "status-1");
    assert_eq!(
        stored_message.fields["history_sync_type"],
        "NON_BLOCKING_DATA"
    );

    let stored_call_key = wa_core::call_event_store_key(call);
    let stored_call = store
        .get(KeyNamespace::CallEvent, &stored_call_key)
        .await
        .unwrap()
        .unwrap();
    let stored_call = wa_core::decode_stored_call_event(&stored_call).unwrap();
    assert_eq!(stored_call.id, "call-1");
    assert_eq!(stored_call.event_type, "history_log");
    assert_eq!(stored_call.fields["call_result"], "MISSED");

    let stored_group = store
        .get(KeyNamespace::GroupEvent, "456@g.us")
        .await
        .unwrap()
        .unwrap();
    let stored_group = wa_core::decode_stored_group_event(&stored_group).unwrap();
    assert_eq!(stored_group.fields["source"], "history_past_participants");
    assert_eq!(
        stored_group.fields["past_participant_reasons"],
        "123@s.whatsapp.net=LEFT,789@s.whatsapp.net=REMOVED"
    );

    let stored_mode = store
        .get(
            KeyNamespace::DefaultDisappearingMode,
            wa_core::default_disappearing_mode_store_key(),
        )
        .await
        .unwrap()
        .unwrap();
    let stored_mode = wa_core::decode_stored_default_disappearing_mode(&stored_mode).unwrap();
    assert_eq!(
        stored_mode,
        wa_core::DefaultDisappearingMode::new(86_400).with_timestamp(1_700_000_060)
    );

    let mapping_store = wa_core::LidPnMappingStore::new(store);
    assert_eq!(
        mapping_store
            .lid_for_pn("123@s.whatsapp.net")
            .await
            .unwrap(),
        Some("999999".to_owned())
    );
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn history_sync_event_scanner_processes_message_notification() {
    let store = wa_store::MemoryAuthStore::new();
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let mut emitted = client.subscribe();
    let history = wa_core::HistorySync {
        sync_type: wa_core::HistorySyncType::InitialBootstrap as i32,
        conversations: vec![wa_proto::proto::Conversation {
            id: "123@s.whatsapp.net".to_owned(),
            display_name: Some("Alice".to_owned()),
            messages: vec![wa_proto::proto::HistorySyncMsg {
                msg_order_id: Some(1),
                message: Some(wa_proto::proto::WebMessageInfo {
                    key: Some(wa_proto::proto::MessageKey {
                        remote_jid: Some("123@s.whatsapp.net".to_owned()),
                        from_me: Some(false),
                        id: Some("msg-from-notification".to_owned()),
                        participant: None,
                    }),
                    message_timestamp: Some(1_700_000_000),
                    ..Default::default()
                }),
            }],
            ..Default::default()
        }],
        ..Default::default()
    };
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&history.encode_to_vec()).unwrap();
    let compressed = Bytes::from(encoder.finish().unwrap());
    let encrypted = wa_crypto::encrypt_media_bytes_with_key(
        &compressed,
        wa_crypto::MediaKind::HistorySync,
        &[5u8; 32],
    )
    .unwrap();
    let notification = wa_core::HistorySyncNotification {
        file_sha256: Some(encrypted.file_sha256.clone()),
        file_length: Some(encrypted.file_length),
        media_key: Some(Bytes::copy_from_slice(encrypted.media_key.expose())),
        file_enc_sha256: Some(encrypted.file_enc_sha256.clone()),
        direct_path: Some("/history/sync-notification".to_owned()),
        sync_type: Some(wa_proto::proto::message::HistorySyncType::InitialBootstrap as i32),
        ..Default::default()
    };
    let transport = HistoryDownloadTransport::default();
    transport.add_download(
        "https://history.test/history/sync-notification",
        encrypted.ciphertext_with_mac.clone(),
    );
    let transfer = wa_core::MediaTransfer::new(transport);
    let notification_message = wa_proto::proto::Message {
        protocol_message: Some(Box::new(wa_proto::proto::message::ProtocolMessage {
            r#type: Some(
                wa_proto::proto::message::protocol_message::Type::HistorySyncNotification as i32,
            ),
            history_sync_notification: Some(notification),
            ..Default::default()
        })),
        ..Default::default()
    };
    let incoming = Event::MessagesUpsert(vec![
        wa_core::MessageEvent::new(wa_core::MessageEventKey::new(
            "status@broadcast",
            "history-notify-1",
            None,
        ))
        .with_payload(Bytes::from(notification_message.encode_to_vec()))
        .with_field("kind", "notify")
        .with_field("from_me", "false"),
    ]);

    let processed = client
        .download_process_and_emit_history_sync_events(
            &transfer,
            &[incoming],
            Some("history.test"),
            wa_core::HistorySyncDecodeConfig::default(),
            wa_core::HistorySyncProcessConfig::default().latest(true),
        )
        .await
        .unwrap();

    assert_eq!(processed.len(), 1);
    let batch = recv_batch_event(&mut emitted).await;
    let history = batch.history.as_ref().unwrap();
    assert!(history.is_latest);
    assert_eq!(history.messages.len(), 1);
    assert_eq!(history.messages[0].key.id, "msg-from-notification");

    let stored_key = wa_core::message_event_store_key(&history.messages[0].key);
    let stored_message = store
        .get(KeyNamespace::MessageEvent, &stored_key)
        .await
        .unwrap()
        .unwrap();
    let stored_message = wa_core::decode_stored_message_event(&stored_message).unwrap();
    assert_eq!(stored_message.key.id, "msg-from-notification");
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn inline_history_sync_event_scanner_processes_without_media_transfer() {
    let store = wa_store::MemoryAuthStore::new();
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let mut emitted = client.subscribe();
    let history = wa_core::HistorySync {
        sync_type: wa_core::HistorySyncType::InitialBootstrap as i32,
        conversations: vec![wa_proto::proto::Conversation {
            id: "123@s.whatsapp.net".to_owned(),
            display_name: Some("Alice".to_owned()),
            messages: vec![wa_proto::proto::HistorySyncMsg {
                msg_order_id: Some(1),
                message: Some(wa_proto::proto::WebMessageInfo {
                    key: Some(wa_proto::proto::MessageKey {
                        remote_jid: Some("123@s.whatsapp.net".to_owned()),
                        from_me: Some(false),
                        id: Some("inline-history-msg".to_owned()),
                        participant: None,
                    }),
                    message_timestamp: Some(1_700_000_000),
                    ..Default::default()
                }),
            }],
            ..Default::default()
        }],
        ..Default::default()
    };
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&history.encode_to_vec()).unwrap();
    let compressed = Bytes::from(encoder.finish().unwrap());
    let notification = wa_core::HistorySyncNotification {
        initial_hist_bootstrap_inline_payload: Some(compressed),
        sync_type: Some(wa_proto::proto::message::HistorySyncType::InitialBootstrap as i32),
        ..Default::default()
    };
    let notification_message = wa_proto::proto::Message {
        protocol_message: Some(Box::new(wa_proto::proto::message::ProtocolMessage {
            r#type: Some(
                wa_proto::proto::message::protocol_message::Type::HistorySyncNotification as i32,
            ),
            history_sync_notification: Some(notification),
            ..Default::default()
        })),
        ..Default::default()
    };
    let incoming = Event::MessagesUpsert(vec![
        wa_core::MessageEvent::new(wa_core::MessageEventKey::new(
            "status@broadcast",
            "inline-history-notify-1",
            None,
        ))
        .with_payload(Bytes::from(notification_message.encode_to_vec()))
        .with_field("kind", "notify")
        .with_field("from_me", "false"),
    ]);

    let processed = client
        .process_inline_and_emit_history_sync_events(
            &[incoming],
            wa_core::HistorySyncDecodeConfig::default(),
            wa_core::HistorySyncProcessConfig::default().latest(true),
        )
        .await
        .unwrap();

    assert_eq!(processed.len(), 1);
    assert_eq!(
        processed[0].sync_type,
        wa_core::HistorySyncType::InitialBootstrap
    );
    let batch = recv_batch_event(&mut emitted).await;
    let history = batch.history.as_ref().unwrap();
    assert!(history.is_latest);
    assert_eq!(history.messages.len(), 1);
    assert_eq!(history.messages[0].key.id, "inline-history-msg");

    let stored_key = wa_core::message_event_store_key(&history.messages[0].key);
    let stored_message = store
        .get(KeyNamespace::MessageEvent, &stored_key)
        .await
        .unwrap()
        .unwrap();
    let stored_message = wa_core::decode_stored_message_event(&stored_message).unwrap();
    assert_eq!(stored_message.key.id, "inline-history-msg");
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn history_sync_event_scanner_deduplicates_notifications_across_event_shapes() {
    let store = wa_store::MemoryAuthStore::new();
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let mut emitted = client.subscribe();
    let history = wa_core::HistorySync {
        sync_type: wa_core::HistorySyncType::InitialBootstrap as i32,
        conversations: vec![wa_proto::proto::Conversation {
            id: "123@s.whatsapp.net".to_owned(),
            display_name: Some("Alice".to_owned()),
            messages: vec![wa_proto::proto::HistorySyncMsg {
                msg_order_id: Some(1),
                message: Some(wa_proto::proto::WebMessageInfo {
                    key: Some(wa_proto::proto::MessageKey {
                        remote_jid: Some("123@s.whatsapp.net".to_owned()),
                        from_me: Some(false),
                        id: Some("dedup-inline-history-msg".to_owned()),
                        participant: None,
                    }),
                    message_timestamp: Some(1_700_000_000),
                    ..Default::default()
                }),
            }],
            ..Default::default()
        }],
        ..Default::default()
    };
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&history.encode_to_vec()).unwrap();
    let compressed = Bytes::from(encoder.finish().unwrap());
    let notification = wa_core::HistorySyncNotification {
        initial_hist_bootstrap_inline_payload: Some(compressed),
        sync_type: Some(wa_proto::proto::message::HistorySyncType::InitialBootstrap as i32),
        ..Default::default()
    };
    let notification_message = wa_proto::proto::Message {
        protocol_message: Some(Box::new(wa_proto::proto::message::ProtocolMessage {
            r#type: Some(
                wa_proto::proto::message::protocol_message::Type::HistorySyncNotification as i32,
            ),
            history_sync_notification: Some(notification),
            ..Default::default()
        })),
        ..Default::default()
    };
    let message_event = wa_core::MessageEvent::new(wa_core::MessageEventKey::new(
        "status@broadcast",
        "dedup-inline-history-notify-1",
        None,
    ))
    .with_payload(Bytes::from(notification_message.encode_to_vec()))
    .with_field("kind", "notify")
    .with_field("from_me", "false");
    let incoming = [
        Event::MessagesUpsert(vec![message_event.clone()]),
        Event::Batch(Box::new(wa_core::EventBatch {
            messages_upsert: vec![message_event],
            ..Default::default()
        })),
    ];

    let processed = client
        .process_inline_and_emit_history_sync_events(
            &incoming,
            wa_core::HistorySyncDecodeConfig::default(),
            wa_core::HistorySyncProcessConfig::default().latest(true),
        )
        .await
        .unwrap();

    assert_eq!(processed.len(), 1);
    let batch = recv_batch_event(&mut emitted).await;
    let history = batch.history.as_ref().unwrap();
    assert_eq!(history.messages.len(), 1);
    assert_eq!(history.messages[0].key.id, "dedup-inline-history-msg");
    assert!(matches!(
        emitted.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));

    let stored_key = wa_core::message_event_store_key(&history.messages[0].key);
    let stored_message = store
        .get(KeyNamespace::MessageEvent, &stored_key)
        .await
        .unwrap()
        .unwrap();
    let stored_message = wa_core::decode_stored_message_event(&stored_message).unwrap();
    assert_eq!(stored_message.key.id, "dedup-inline-history-msg");
}

#[cfg(feature = "memory-store")]
#[tokio::test]
async fn fetch_media_connection_info_sends_query_and_parses_hosts() {
    let store = wa_store::MemoryAuthStore::new();
    let client = Client::builder(store).connect().await.unwrap();
    let (connection, mut sink_rx, stream_tx) = mock_connection();
    let media_fut = client.fetch_media_connection_info(&connection);
    tokio::pin!(media_fut);

    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["type"], "set");
            assert_eq!(node.attrs["xmlns"], "w:m");
            assert_child(&node, "media_conn");
            BinaryNode::new("iq")
                .with_attr("id", node.attrs["id"].clone())
                .with_attr("type", "result")
                .with_content(vec![
                    BinaryNode::new("media_conn")
                        .with_attr("auth", "auth-token")
                        .with_attr("ttl", "90")
                        .with_content(vec![
                            BinaryNode::new("host")
                                .with_attr("hostname", "media.example")
                                .with_attr("maxContentLengthBytes", "4096"),
                        ]),
                ])
        },
        &mut media_fut,
    )
    .await;

    let info = media_fut.await.unwrap();
    assert_eq!(info.auth, "auth-token");
    assert_eq!(info.ttl_seconds, 90);
    assert_eq!(info.hosts[0].hostname, "media.example");
    assert_eq!(info.hosts[0].max_content_length_bytes, Some(4096));

    let failed_media_fut = client.fetch_media_connection_info(&connection);
    tokio::pin!(failed_media_fut);
    respond_to_next_query(
        &mut sink_rx,
        &stream_tx,
        |node| {
            assert_eq!(node.attrs["type"], "set");
            assert_eq!(node.attrs["xmlns"], "w:m");
            assert_child(&node, "media_conn");
            error_result_for(&node, "401", "media denied")
        },
        &mut failed_media_fut,
    )
    .await;

    let err = failed_media_fut.await.unwrap_err();
    assert!(
        err.to_string()
            .contains("media connection query failed (401): media denied")
    );
    connection.close().await.unwrap();
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn upload_media_bytes_cached_reuses_cached_descriptor() {
    let store = wa_store::MemoryAuthStore::new();
    let client = Client::builder(store).connect().await.unwrap();
    let transport = ClientMediaUploadTransport::default();
    let transfer = wa_core::MediaTransfer::new(transport.clone());
    let cache = wa_core::MemoryMediaUploadCache::default();

    let first = client
        .upload_media_bytes_cached(
            &transfer,
            b"client cached media",
            wa_core::MediaKind::Image,
            &cache,
        )
        .await
        .unwrap();
    let second = client
        .upload_media_bytes_cached(
            &transfer,
            b"client cached media",
            wa_core::MediaKind::Image,
            &cache,
        )
        .await
        .unwrap();

    assert_eq!(first, second);
    assert_eq!(transport.uploads.lock().unwrap().len(), 1);
    assert_eq!(cache.len().unwrap(), 1);
}

#[cfg(all(feature = "memory-store", feature = "link-preview"))]
#[tokio::test]
async fn link_preview_thumbnail_facade_uploads_thumbnail_link_media() {
    let store = wa_store::MemoryAuthStore::new();
    let client = Client::builder(store).connect().await.unwrap();
    let transport = ClientMediaUploadTransport::default();
    let transfer = wa_core::MediaTransfer::new(transport.clone());
    let cache = wa_core::MemoryMediaUploadCache::default();

    let thumbnail = client
        .upload_link_preview_thumbnail_bytes_cached(
            &transfer,
            b"client link preview jpeg",
            Some((300, 200)),
            &cache,
        )
        .await
        .unwrap();
    let thumbnail_again = client
        .upload_link_preview_thumbnail_bytes_cached(
            &transfer,
            b"client link preview jpeg",
            Some((300, 200)),
            &cache,
        )
        .await
        .unwrap();

    assert_eq!(thumbnail, thumbnail_again);
    assert_eq!(thumbnail.direct_path, "/client/upload/0");
    assert_eq!(thumbnail.width, Some(300));
    assert_eq!(thumbnail.height, Some(200));
    assert_eq!(transport.uploads.lock().unwrap().len(), 1);
    assert_eq!(
        transport.uploads.lock().unwrap()[0].kind,
        wa_core::MediaKind::ThumbnailLink
    );
    assert_eq!(cache.len().unwrap(), 1);

    let message = wa_core::build_text_message(
        wa_core::TextMessage::new("See https://example.invalid").with_link_preview(
            wa_core::LinkPreviewContent::new("https://example.invalid", "Example")
                .with_jpeg_thumbnail(bytes::Bytes::from_static(b"tiny"))
                .with_high_quality_thumbnail(thumbnail),
        ),
    )
    .unwrap();
    assert_eq!(
        message
            .extended_text_message
            .unwrap()
            .thumbnail_direct_path
            .as_deref(),
        Some("/client/upload/0")
    );
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn business_media_upload_facade_uses_business_media_kinds() {
    let store = wa_store::MemoryAuthStore::new();
    let client = Client::builder(store).connect().await.unwrap();
    let transport = ClientMediaUploadTransport::default();
    let transfer = wa_core::MediaTransfer::new(transport.clone());
    let cache = wa_core::MemoryMediaUploadCache::default();
    let input = test_client_media_path("business-image");
    tokio::fs::write(&input, b"product file image")
        .await
        .unwrap();

    let product = client
        .upload_business_product_image_bytes_cached(
            &transfer,
            b"product image",
            Some("media.test"),
            &cache,
        )
        .await
        .unwrap();
    let product_again = client
        .upload_business_product_image_bytes_cached(
            &transfer,
            b"product image",
            Some("media.test"),
            &cache,
        )
        .await
        .unwrap();
    assert_eq!(product, product_again);
    assert_eq!(product.url, "https://media.test/client/upload/0");

    let product_file = client
        .upload_business_product_image_file_cached(&transfer, &input, Some("media.test"), &cache)
        .await
        .unwrap();
    let product_file_again = client
        .upload_business_product_image_file_cached(&transfer, &input, Some("media.test"), &cache)
        .await
        .unwrap();
    assert_eq!(product_file, product_file_again);
    assert_eq!(product_file.url, "https://media.test/client/upload/1");

    let batch_bytes = client
        .upload_business_product_images_bytes(
            &transfer,
            vec![b"batch image a".as_slice(), b"batch image b".as_slice()],
            Some("media.test"),
        )
        .await
        .unwrap();
    assert_eq!(batch_bytes.len(), 2);
    assert_eq!(batch_bytes[0].url, "https://media.test/client/upload/2");
    assert_eq!(batch_bytes[1].url, "https://media.test/client/upload/3");

    let batch_files = client
        .upload_business_product_image_files(&transfer, [&input, &input], Some("media.test"))
        .await
        .unwrap();
    assert_eq!(batch_files.len(), 2);
    assert_eq!(batch_files[0].url, "https://media.test/client/upload/4");
    assert_eq!(batch_files[1].url, "https://media.test/client/upload/5");

    let cover = client
        .upload_business_cover_photo_bytes(&transfer, b"cover image")
        .await
        .unwrap();
    assert_eq!(cover.id, "cover-6");
    assert_eq!(cover.token, "token-6");
    assert_eq!(cover.timestamp, 1_700_000_006);

    let cover_file = client
        .upload_business_cover_photo_file(&transfer, &input)
        .await
        .unwrap();
    assert_eq!(cover_file.id, "cover-7");
    assert_eq!(cover_file.token, "token-7");
    assert_eq!(cover_file.timestamp, 1_700_000_007);

    {
        let uploads = transport.uploads.lock().unwrap();
        assert_eq!(uploads.len(), 8);
        for upload in uploads.iter().take(6) {
            assert_eq!(upload.kind, wa_core::MediaKind::ProductCatalogImage);
        }
        assert_eq!(uploads[6].kind, wa_core::MediaKind::BusinessCoverPhoto);
        assert_eq!(uploads[7].kind, wa_core::MediaKind::BusinessCoverPhoto);
    }

    let _ = tokio::fs::remove_file(&input).await;
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn media_file_facade_uploads_caches_and_downloads_files() {
    let store = wa_store::MemoryAuthStore::new();
    let client = Client::builder(store).connect().await.unwrap();
    let transport = ClientMediaUploadTransport::default();
    let transfer = wa_core::MediaTransfer::new(transport.clone());
    let cache = wa_core::MemoryMediaUploadCache::default();
    let input = test_client_media_path("input");
    let output = test_client_media_path("output");
    tokio::fs::write(&input, b"client file media")
        .await
        .unwrap();

    let first = client
        .upload_media_file_cached(&transfer, &input, wa_core::MediaKind::Image, &cache)
        .await
        .unwrap();
    let second = client
        .upload_media_file_cached(&transfer, &input, wa_core::MediaKind::Image, &cache)
        .await
        .unwrap();
    assert_eq!(first, second);
    assert_eq!(transport.uploads.lock().unwrap().len(), 1);

    let written = client
        .download_media_to_file(
            &transfer,
            &first,
            wa_core::MediaKind::Image,
            Some("media.test"),
            &output,
        )
        .await
        .unwrap();
    assert_eq!(written, 17);
    assert_eq!(
        tokio::fs::read(&output).await.unwrap(),
        b"client file media"
    );

    let _ = tokio::fs::remove_file(&input).await;
    let _ = tokio::fs::remove_file(&output).await;
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn remote_thumbnail_facade_uploads_and_attaches_video_document_thumbnails() {
    let store = wa_store::MemoryAuthStore::new();
    let client = Client::builder(store).connect().await.unwrap();
    let transport = ClientMediaUploadTransport::default();
    let transfer = wa_core::MediaTransfer::new(transport.clone());
    let video_encrypted = wa_crypto::encrypt_media_bytes_with_key(
        b"video media",
        wa_core::MediaKind::Video,
        &[11u8; 32],
    )
    .unwrap();
    let video_media = wa_core::uploaded_media_from_encrypted(
        &video_encrypted,
        wa_core::UploadedMediaLocation::new().with_direct_path("/client/video"),
    )
    .unwrap();
    let document_encrypted = wa_crypto::encrypt_media_bytes_with_key(
        b"document media",
        wa_core::MediaKind::Document,
        &[12u8; 32],
    )
    .unwrap();
    let document_media = wa_core::uploaded_media_from_encrypted(
        &document_encrypted,
        wa_core::UploadedMediaLocation::new().with_direct_path("/client/document"),
    )
    .unwrap();

    let video_thumbnail = client
        .upload_video_remote_thumbnail(&transfer, &video_media, b"video thumbnail")
        .await
        .unwrap();
    let document_thumbnail = client
        .upload_document_remote_thumbnail(
            &transfer,
            &document_media,
            b"document thumbnail",
            Some((96, 48)),
        )
        .await
        .unwrap();

    let video_message = wa_core::build_video_message(
        wa_core::VideoContent::new(video_media.clone(), "video/mp4")
            .with_remote_thumbnail(video_thumbnail.clone()),
    )
    .unwrap()
    .video_message
    .unwrap();
    assert_eq!(
        video_message.thumbnail_direct_path.as_deref(),
        Some("/client/upload/0")
    );
    assert_eq!(
        video_message.thumbnail_sha256,
        Some(video_thumbnail.sha256.clone())
    );
    assert_eq!(
        video_message.thumbnail_enc_sha256,
        Some(video_thumbnail.enc_sha256.clone())
    );

    let document_message = wa_core::build_document_message(
        wa_core::DocumentContent::new(document_media.clone(), "application/pdf")
            .with_remote_thumbnail(document_thumbnail.clone()),
    )
    .unwrap()
    .document_message
    .unwrap();
    assert_eq!(
        document_message.thumbnail_direct_path.as_deref(),
        Some("/client/upload/1")
    );
    assert_eq!(document_message.thumbnail_width, Some(96));
    assert_eq!(document_message.thumbnail_height, Some(48));

    let uploads = transport.uploads.lock().unwrap();
    assert_eq!(uploads.len(), 2);
    assert_eq!(uploads[0].kind, wa_core::MediaKind::ThumbnailVideo);
    assert_eq!(
        wa_crypto::decrypt_media_bytes(
            &uploads[0].ciphertext_with_mac,
            wa_core::MediaKind::ThumbnailVideo,
            &video_media.media_key,
        )
        .unwrap(),
        b"video thumbnail"
    );
    assert_eq!(uploads[1].kind, wa_core::MediaKind::ThumbnailDocument);
    assert_eq!(
        wa_crypto::decrypt_media_bytes(
            &uploads[1].ciphertext_with_mac,
            wa_core::MediaKind::ThumbnailDocument,
            &document_media.media_key,
        )
        .unwrap(),
        b"document thumbnail"
    );
}

#[cfg(all(feature = "memory-store", feature = "noise", feature = "image", unix))]
#[tokio::test]
async fn generated_remote_thumbnail_facade_extracts_uploads_and_attaches_thumbnails() {
    use std::os::unix::fs::PermissionsExt as _;

    let store = wa_store::MemoryAuthStore::new();
    let client = Client::builder(store).connect().await.unwrap();
    let dir = test_client_media_path("generated-remote-thumbnails");
    std::fs::create_dir_all(&dir).unwrap();
    let frame_path = dir.join("frame.jpg");
    let video_path = dir.join("video.mp4");
    let pdf_path = dir.join("document.pdf");
    let ffmpeg_path = dir.join("fake-ffmpeg");
    let renderer_path = dir.join("fake-pdftoppm");
    std::fs::write(&frame_path, sample_client_png()).unwrap();
    std::fs::write(&video_path, b"fake video").unwrap();
    std::fs::write(&pdf_path, b"%PDF-1.7\n").unwrap();
    std::fs::write(
        &ffmpeg_path,
        format!(
            "#!/bin/sh\nset -eu\nout=\"\"\nfor arg do out=\"$arg\"; done\ncp {} \"$out\"\n",
            shell_quote(&frame_path),
        ),
    )
    .unwrap();
    std::fs::write(
        &renderer_path,
        format!(
            "#!/bin/sh\nset -eu\nout=\"\"\nfor arg do out=\"$arg\"; done\ncp {} \"$out.jpg\"\n",
            shell_quote(&frame_path),
        ),
    )
    .unwrap();
    for command_path in [&ffmpeg_path, &renderer_path] {
        let mut permissions = std::fs::metadata(command_path).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(command_path, permissions).unwrap();
    }

    let video_media = wa_core::uploaded_media_from_encrypted(
        &wa_crypto::encrypt_media_bytes_with_key(
            b"video media",
            wa_core::MediaKind::Video,
            &[13u8; 32],
        )
        .unwrap(),
        wa_core::UploadedMediaLocation::new().with_direct_path("/client/generated-video"),
    )
    .unwrap();
    let document_media = wa_core::uploaded_media_from_encrypted(
        &wa_crypto::encrypt_media_bytes_with_key(
            b"document media",
            wa_core::MediaKind::Document,
            &[14u8; 32],
        )
        .unwrap(),
        wa_core::UploadedMediaLocation::new().with_direct_path("/client/generated-document"),
    )
    .unwrap();
    let transport = ClientMediaUploadTransport::default();
    let transfer = wa_core::MediaTransfer::new(transport.clone());

    let video_upload = client
        .upload_generated_video_remote_thumbnail_file(
            &transfer,
            &video_media,
            &video_path,
            wa_core::VideoThumbnailOptions {
                ffmpeg_path,
                temp_dir: Some(dir.clone()),
                ..wa_core::VideoThumbnailOptions::default()
            },
        )
        .await
        .unwrap();
    let document_upload = client
        .upload_generated_document_remote_thumbnail_file(
            &transfer,
            &document_media,
            &pdf_path,
            wa_core::PdfThumbnailOptions {
                pdftoppm_path: renderer_path,
                temp_dir: Some(dir.clone()),
                ..wa_core::PdfThumbnailOptions::default()
            },
        )
        .await
        .unwrap();

    assert_eq!(video_upload.thumbnail_width, 1);
    assert_eq!(video_upload.thumbnail_height, 1);
    let video_message = wa_core::build_video_message(
        wa_core::VideoContent::new(video_media.clone(), "video/mp4")
            .with_remote_thumbnail(video_upload.remote_thumbnail.clone()),
    )
    .unwrap()
    .video_message
    .unwrap();
    assert_eq!(
        video_message.thumbnail_direct_path.as_deref(),
        Some("/client/upload/0")
    );

    let document_message = wa_core::build_document_message(
        wa_core::DocumentContent::new(document_media.clone(), "application/pdf")
            .with_remote_thumbnail(document_upload.remote_thumbnail.clone()),
    )
    .unwrap()
    .document_message
    .unwrap();
    assert_eq!(
        document_message.thumbnail_direct_path.as_deref(),
        Some("/client/upload/1")
    );
    assert_eq!(document_message.thumbnail_width, Some(1));
    assert_eq!(document_message.thumbnail_height, Some(1));

    let uploads = transport.uploads.lock().unwrap();
    assert_eq!(uploads.len(), 2);
    assert_eq!(uploads[0].kind, wa_core::MediaKind::ThumbnailVideo);
    assert_eq!(
        wa_crypto::decrypt_media_bytes(
            &uploads[0].ciphertext_with_mac,
            wa_core::MediaKind::ThumbnailVideo,
            &video_media.media_key,
        )
        .unwrap(),
        video_upload.jpeg_thumbnail
    );
    assert_eq!(uploads[1].kind, wa_core::MediaKind::ThumbnailDocument);
    assert_eq!(
        wa_crypto::decrypt_media_bytes(
            &uploads[1].ciphertext_with_mac,
            wa_core::MediaKind::ThumbnailDocument,
            &document_media.media_key,
        )
        .unwrap(),
        document_upload.jpeg_thumbnail
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn media_retry_facade_refreshes_descriptor_and_downloads() {
    let store = wa_store::MemoryAuthStore::new();
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let media_key = [8u8; 32];
    let encrypted = wa_crypto::encrypt_media_bytes_with_key(
        b"client retried media",
        wa_core::MediaKind::Image,
        &media_key,
    )
    .unwrap();
    let media = wa_core::uploaded_media_from_encrypted(
        &encrypted,
        wa_core::UploadedMediaLocation::new().with_direct_path("/client/old"),
    )
    .unwrap();
    let notification = wa_proto::proto::MediaRetryNotification {
        stanza_id: Some("msg-1".to_owned()),
        direct_path: Some("/client/new".to_owned()),
        result: Some(wa_proto::proto::media_retry_notification::ResultType::Success as i32),
        message_secret: None,
    };
    let payload = wa_crypto::encrypt_media_retry_notification_with_iv(
        &notification,
        &media_key,
        "msg-1",
        &[4u8; 12],
    )
    .unwrap();
    let key = wa_core::MessageEventKey::new("123@s.whatsapp.net", "msg-1", None);
    let retry = wa_core::MediaRetryEvent::new(key.clone(), false)
        .with_encrypted_payload(payload.ciphertext, payload.iv);

    let application = client.apply_media_retry_event(&retry, &media).unwrap();
    assert_eq!(
        application.media.direct_path.as_deref(),
        Some("/client/new")
    );

    let transport = ClientMediaUploadTransport::default();
    transport.downloads.lock().unwrap().insert(
        "https://media.test/client/new".to_owned(),
        encrypted.ciphertext_with_mac.clone(),
    );
    let transfer = wa_core::MediaTransfer::new(transport);
    let download = client
        .download_media_bytes_after_retry(
            &transfer,
            &media,
            wa_core::MediaKind::Image,
            &retry,
            Some("media.test"),
        )
        .await
        .unwrap();

    assert_eq!(download.plaintext, b"client retried media");
    assert_eq!(
        download.application.media.direct_path.as_deref(),
        Some("/client/new")
    );

    client
        .register_pending_media_retry(
            key.clone(),
            wa_core::PendingMediaRetry::new(media.clone(), wa_core::MediaKind::Image)
                .with_fallback_host("media.test"),
        )
        .unwrap();
    let coordinated = client
        .download_pending_media_after_retry(&transfer, &retry)
        .await
        .unwrap();
    assert_eq!(coordinated.plaintext, b"client retried media");
    assert!(
        client
            .media_retry_coordinator()
            .pending(&key)
            .unwrap()
            .is_none()
    );

    client
        .register_pending_media_retry(
            key.clone(),
            wa_core::PendingMediaRetry::new(media.clone(), wa_core::MediaKind::Image)
                .with_fallback_host("media.test"),
        )
        .unwrap();
    let batch = wa_core::EventBatch {
        media_retry: vec![retry.clone()],
        ..wa_core::EventBatch::default()
    };
    let outcome = client
        .handle_media_retry_batch(&transfer, &batch)
        .await
        .unwrap();
    assert_eq!(outcome.downloads.len(), 1);
    assert_eq!(outcome.downloads[0].plaintext, b"client retried media");
    assert!(outcome.errors.is_empty());
    assert_eq!(outcome.ignored_without_pending, 0);
    assert!(
        client
            .media_retry_coordinator()
            .pending(&key)
            .unwrap()
            .is_none()
    );

    client
        .register_pending_media_retry_persisted(
            key.clone(),
            wa_core::PendingMediaRetry::new(media, wa_core::MediaKind::Image)
                .with_fallback_host("media.test"),
        )
        .await
        .unwrap();
    let store_key = wa_core::pending_media_retry_store_key(&key);
    assert!(
        store
            .get(KeyNamespace::PendingMediaRetry, &store_key)
            .await
            .unwrap()
            .is_some()
    );

    let restored_client = Client::builder(store.clone()).connect().await.unwrap();
    assert_eq!(
        restored_client
            .restore_pending_media_retries_from_store()
            .await
            .unwrap(),
        1
    );
    assert!(
        restored_client
            .media_retry_coordinator()
            .pending(&key)
            .unwrap()
            .is_some()
    );
    let restored_download = restored_client
        .download_persisted_pending_media_after_retry(&transfer, &retry)
        .await
        .unwrap();
    assert_eq!(restored_download.plaintext, b"client retried media");
    assert!(
        restored_client
            .media_retry_coordinator()
            .pending(&key)
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .get(KeyNamespace::PendingMediaRetry, &store_key)
            .await
            .unwrap()
            .is_none()
    );
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn persisted_media_retry_batch_loads_store_and_cleans_successful_entries() {
    let store = wa_store::MemoryAuthStore::new();
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let success_key = wa_core::MessageEventKey::new("123@s.whatsapp.net", "msg-ok", None);
    let failed_key = wa_core::MessageEventKey::new("123@s.whatsapp.net", "msg-fail", None);
    let missing_key = wa_core::MessageEventKey::new("123@s.whatsapp.net", "msg-missing", None);
    let success_media_key = [8u8; 32];
    let failed_media_key = [9u8; 32];
    let encrypted = wa_crypto::encrypt_media_bytes_with_key(
        b"persisted retry media",
        wa_core::MediaKind::Image,
        &success_media_key,
    )
    .unwrap();
    let success_media = wa_core::uploaded_media_from_encrypted(
        &encrypted,
        wa_core::UploadedMediaLocation::new().with_direct_path("/persisted/old"),
    )
    .unwrap();
    let failed_encrypted = wa_crypto::encrypt_media_bytes_with_key(
        b"failed persisted retry media",
        wa_core::MediaKind::Image,
        &failed_media_key,
    )
    .unwrap();
    let failed_media = wa_core::uploaded_media_from_encrypted(
        &failed_encrypted,
        wa_core::UploadedMediaLocation::new().with_direct_path("/persisted/failed-old"),
    )
    .unwrap();
    client
        .register_pending_media_retry_persisted(
            success_key.clone(),
            wa_core::PendingMediaRetry::new(success_media, wa_core::MediaKind::Image)
                .with_fallback_host("media.test"),
        )
        .await
        .unwrap();
    client
        .register_pending_media_retry_persisted(
            failed_key.clone(),
            wa_core::PendingMediaRetry::new(failed_media, wa_core::MediaKind::Image)
                .with_fallback_host("media.test"),
        )
        .await
        .unwrap();
    let success_store_key = wa_core::pending_media_retry_store_key(&success_key);
    let failed_store_key = wa_core::pending_media_retry_store_key(&failed_key);

    let restored_client = Client::builder(store.clone()).connect().await.unwrap();
    assert!(
        restored_client
            .media_retry_coordinator()
            .pending(&success_key)
            .unwrap()
            .is_none()
    );
    let notification = wa_proto::proto::MediaRetryNotification {
        stanza_id: Some(success_key.id.clone()),
        direct_path: Some("/persisted/new".to_owned()),
        result: Some(wa_proto::proto::media_retry_notification::ResultType::Success as i32),
        message_secret: None,
    };
    let payload = wa_crypto::encrypt_media_retry_notification_with_iv(
        &notification,
        &success_media_key,
        &success_key.id,
        &[5u8; 12],
    )
    .unwrap();
    let success_retry = wa_core::MediaRetryEvent::new(success_key.clone(), false)
        .with_encrypted_payload(payload.ciphertext, payload.iv);
    let failed_retry = wa_core::MediaRetryEvent::new(failed_key.clone(), false).with_error(
        2,
        Some("retry failed".to_owned()),
        404,
    );
    let missing_retry = wa_core::MediaRetryEvent::new(missing_key, false);
    let batch = wa_core::EventBatch {
        media_retry: vec![success_retry, failed_retry, missing_retry],
        ..wa_core::EventBatch::default()
    };
    let transport = ClientMediaUploadTransport::default();
    transport.downloads.lock().unwrap().insert(
        "https://media.test/persisted/new".to_owned(),
        encrypted.ciphertext_with_mac.clone(),
    );
    let transfer = wa_core::MediaTransfer::new(transport);

    let outcome = restored_client
        .handle_persisted_media_retry_batch(&transfer, &batch)
        .await
        .unwrap();

    assert_eq!(outcome.downloads.len(), 1);
    assert_eq!(outcome.downloads[0].plaintext, b"persisted retry media");
    assert_eq!(outcome.errors.len(), 1);
    assert_eq!(outcome.errors[0].key, failed_key);
    assert_eq!(outcome.ignored_without_pending, 1);
    assert!(
        store
            .get(KeyNamespace::PendingMediaRetry, &success_store_key)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .get(KeyNamespace::PendingMediaRetry, &failed_store_key)
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        restored_client
            .media_retry_coordinator()
            .pending(&success_key)
            .unwrap()
            .is_none()
    );
    assert!(
        restored_client
            .media_retry_coordinator()
            .pending(&failed_key)
            .unwrap()
            .is_some()
    );
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn media_retry_event_variant_downloads_pending_media() {
    let store = wa_store::MemoryAuthStore::new();
    let client = Client::builder(store).connect().await.unwrap();
    let key = wa_core::MessageEventKey::new("123@s.whatsapp.net", "event-variant", None);
    let media_key = [12u8; 32];
    let encrypted = wa_crypto::encrypt_media_bytes_with_key(
        b"event variant media",
        wa_core::MediaKind::Image,
        &media_key,
    )
    .unwrap();
    let media = wa_core::uploaded_media_from_encrypted(
        &encrypted,
        wa_core::UploadedMediaLocation::new().with_direct_path("/event/old"),
    )
    .unwrap();
    client
        .register_pending_media_retry(
            key.clone(),
            wa_core::PendingMediaRetry::new(media, wa_core::MediaKind::Image)
                .with_fallback_host("media.test"),
        )
        .unwrap();
    let notification = wa_proto::proto::MediaRetryNotification {
        stanza_id: Some(key.id.clone()),
        direct_path: Some("/event/new".to_owned()),
        result: Some(wa_proto::proto::media_retry_notification::ResultType::Success as i32),
        message_secret: None,
    };
    let payload = wa_crypto::encrypt_media_retry_notification_with_iv(
        &notification,
        &media_key,
        &key.id,
        &[10u8; 12],
    )
    .unwrap();
    let retry = wa_core::MediaRetryEvent::new(key.clone(), false)
        .with_encrypted_payload(payload.ciphertext, payload.iv);
    let transport = ClientMediaUploadTransport::default();
    transport.downloads.lock().unwrap().insert(
        "https://media.test/event/new".to_owned(),
        encrypted.ciphertext_with_mac.clone(),
    );
    let transfer = wa_core::MediaTransfer::new(transport);

    let outcome = client
        .handle_media_retry_events(&transfer, &[Event::MediaRetry(vec![retry])])
        .await
        .unwrap();

    assert_eq!(outcome.downloads.len(), 1);
    assert_eq!(outcome.downloads[0].plaintext, b"event variant media");
    assert!(outcome.errors.is_empty());
    assert_eq!(outcome.ignored_without_pending, 0);
    assert!(
        client
            .media_retry_coordinator()
            .pending(&key)
            .unwrap()
            .is_none()
    );
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn persisted_media_retry_event_variant_loads_store_and_cleans_success() {
    let store = wa_store::MemoryAuthStore::new();
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let key = wa_core::MessageEventKey::new("123@s.whatsapp.net", "persisted-event-variant", None);
    let media_key = [13u8; 32];
    let encrypted = wa_crypto::encrypt_media_bytes_with_key(
        b"persisted event variant media",
        wa_core::MediaKind::Image,
        &media_key,
    )
    .unwrap();
    let media = wa_core::uploaded_media_from_encrypted(
        &encrypted,
        wa_core::UploadedMediaLocation::new().with_direct_path("/persisted-event/old"),
    )
    .unwrap();
    client
        .register_pending_media_retry_persisted(
            key.clone(),
            wa_core::PendingMediaRetry::new(media, wa_core::MediaKind::Image)
                .with_fallback_host("media.test"),
        )
        .await
        .unwrap();
    let notification = wa_proto::proto::MediaRetryNotification {
        stanza_id: Some(key.id.clone()),
        direct_path: Some("/persisted-event/new".to_owned()),
        result: Some(wa_proto::proto::media_retry_notification::ResultType::Success as i32),
        message_secret: None,
    };
    let payload = wa_crypto::encrypt_media_retry_notification_with_iv(
        &notification,
        &media_key,
        &key.id,
        &[11u8; 12],
    )
    .unwrap();
    let retry = wa_core::MediaRetryEvent::new(key.clone(), false)
        .with_encrypted_payload(payload.ciphertext, payload.iv);
    persist_receive_events(&store, &[Event::MediaRetry(vec![retry.clone()])])
        .await
        .unwrap();
    let pending_store_key = wa_core::pending_media_retry_store_key(&key);
    let retry_store_key = wa_core::media_retry_event_store_key(&retry);
    let restored_client = Client::builder(store.clone()).connect().await.unwrap();
    let transport = ClientMediaUploadTransport::default();
    transport.downloads.lock().unwrap().insert(
        "https://media.test/persisted-event/new".to_owned(),
        encrypted.ciphertext_with_mac.clone(),
    );
    let transfer = wa_core::MediaTransfer::new(transport);

    let outcome = restored_client
        .handle_persisted_media_retry_events(&transfer, &[Event::MediaRetry(vec![retry])])
        .await
        .unwrap();

    assert_eq!(outcome.downloads.len(), 1);
    assert_eq!(
        outcome.downloads[0].plaintext,
        b"persisted event variant media"
    );
    assert!(outcome.errors.is_empty());
    assert_eq!(outcome.ignored_without_pending, 0);
    assert!(
        store
            .get(KeyNamespace::PendingMediaRetry, &pending_store_key)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .get(KeyNamespace::MediaRetryEvent, &retry_store_key)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        restored_client
            .media_retry_coordinator()
            .pending(&key)
            .unwrap()
            .is_none()
    );
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn stored_media_retry_events_replay_persisted_pending_media() {
    let store = wa_store::MemoryAuthStore::new();
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let success_key = wa_core::MessageEventKey::new("123@s.whatsapp.net", "stored-ok", None);
    let failed_key = wa_core::MessageEventKey::new("123@s.whatsapp.net", "stored-fail", None);
    let missing_key = wa_core::MessageEventKey::new("123@s.whatsapp.net", "stored-missing", None);
    let success_media_key = [10u8; 32];
    let failed_media_key = [11u8; 32];
    let encrypted = wa_crypto::encrypt_media_bytes_with_key(
        b"stored retried media",
        wa_core::MediaKind::Image,
        &success_media_key,
    )
    .unwrap();
    let success_media = wa_core::uploaded_media_from_encrypted(
        &encrypted,
        wa_core::UploadedMediaLocation::new().with_direct_path("/stored/old"),
    )
    .unwrap();
    let failed_encrypted = wa_crypto::encrypt_media_bytes_with_key(
        b"stored failed media",
        wa_core::MediaKind::Image,
        &failed_media_key,
    )
    .unwrap();
    let failed_media = wa_core::uploaded_media_from_encrypted(
        &failed_encrypted,
        wa_core::UploadedMediaLocation::new().with_direct_path("/stored/failed-old"),
    )
    .unwrap();

    client
        .register_pending_media_retry_persisted(
            success_key.clone(),
            wa_core::PendingMediaRetry::new(success_media, wa_core::MediaKind::Image)
                .with_fallback_host("media.test"),
        )
        .await
        .unwrap();
    client
        .register_pending_media_retry_persisted(
            failed_key.clone(),
            wa_core::PendingMediaRetry::new(failed_media, wa_core::MediaKind::Image)
                .with_fallback_host("media.test"),
        )
        .await
        .unwrap();

    let notification = wa_proto::proto::MediaRetryNotification {
        stanza_id: Some(success_key.id.clone()),
        direct_path: Some("/stored/new".to_owned()),
        result: Some(wa_proto::proto::media_retry_notification::ResultType::Success as i32),
        message_secret: None,
    };
    let payload = wa_crypto::encrypt_media_retry_notification_with_iv(
        &notification,
        &success_media_key,
        &success_key.id,
        &[6u8; 12],
    )
    .unwrap();
    let success_retry = wa_core::MediaRetryEvent::new(success_key.clone(), false)
        .with_encrypted_payload(payload.ciphertext, payload.iv);
    let failed_retry = wa_core::MediaRetryEvent::new(failed_key.clone(), false).with_error(
        2,
        Some("retry failed".to_owned()),
        404,
    );
    let missing_retry = wa_core::MediaRetryEvent::new(missing_key.clone(), false);
    persist_receive_events(
        &store,
        &[Event::MediaRetry(vec![
            success_retry.clone(),
            failed_retry.clone(),
            missing_retry.clone(),
        ])],
    )
    .await
    .unwrap();

    let success_pending_store_key = wa_core::pending_media_retry_store_key(&success_key);
    let failed_pending_store_key = wa_core::pending_media_retry_store_key(&failed_key);
    let success_retry_store_key = wa_core::media_retry_event_store_key(&success_retry);
    let failed_retry_store_key = wa_core::media_retry_event_store_key(&failed_retry);
    let missing_retry_store_key = wa_core::media_retry_event_store_key(&missing_retry);
    let restored_client = Client::builder(store.clone()).connect().await.unwrap();
    assert!(
        restored_client
            .media_retry_coordinator()
            .pending(&success_key)
            .unwrap()
            .is_none()
    );
    let transport = ClientMediaUploadTransport::default();
    transport.downloads.lock().unwrap().insert(
        "https://media.test/stored/new".to_owned(),
        encrypted.ciphertext_with_mac.clone(),
    );
    let transfer = wa_core::MediaTransfer::new(transport);

    let outcome = restored_client
        .handle_stored_media_retry_events(&transfer)
        .await
        .unwrap();

    assert_eq!(outcome.downloads.len(), 1);
    assert_eq!(outcome.downloads[0].plaintext, b"stored retried media");
    assert_eq!(outcome.errors.len(), 1);
    assert_eq!(outcome.errors[0].key, failed_key);
    assert_eq!(outcome.ignored_without_pending, 1);
    assert!(
        store
            .get(KeyNamespace::PendingMediaRetry, &success_pending_store_key)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .get(KeyNamespace::PendingMediaRetry, &failed_pending_store_key)
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        store
            .get(KeyNamespace::MediaRetryEvent, &success_retry_store_key)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .get(KeyNamespace::MediaRetryEvent, &failed_retry_store_key)
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        store
            .get(KeyNamespace::MediaRetryEvent, &missing_retry_store_key)
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        restored_client
            .media_retry_coordinator()
            .pending(&success_key)
            .unwrap()
            .is_none()
    );
    assert!(
        restored_client
            .media_retry_coordinator()
            .pending(&failed_key)
            .unwrap()
            .is_some()
    );
}

#[cfg(all(feature = "memory-store", feature = "noise"))]
#[tokio::test]
async fn stored_media_retry_events_replay_video_and_document_pending_media() {
    let store = wa_store::MemoryAuthStore::new();
    let client = Client::builder(store.clone()).connect().await.unwrap();
    let video_key = wa_core::MessageEventKey::new("123@s.whatsapp.net", "stored-video", None);
    let document_key = wa_core::MessageEventKey::new("123@s.whatsapp.net", "stored-document", None);
    let video_media_key = [15u8; 32];
    let document_media_key = [16u8; 32];
    let encrypted_video = wa_crypto::encrypt_media_bytes_with_key(
        b"stored retried video media",
        wa_core::MediaKind::Video,
        &video_media_key,
    )
    .unwrap();
    let encrypted_document = wa_crypto::encrypt_media_bytes_with_key(
        b"stored retried document media",
        wa_core::MediaKind::Document,
        &document_media_key,
    )
    .unwrap();
    let video_media = wa_core::uploaded_media_from_encrypted(
        &encrypted_video,
        wa_core::UploadedMediaLocation::new().with_direct_path("/stored-video/old"),
    )
    .unwrap();
    let document_media = wa_core::uploaded_media_from_encrypted(
        &encrypted_document,
        wa_core::UploadedMediaLocation::new().with_direct_path("/stored-document/old"),
    )
    .unwrap();

    client
        .register_pending_media_retry_persisted(
            video_key.clone(),
            wa_core::PendingMediaRetry::new(video_media, wa_core::MediaKind::Video)
                .with_fallback_host("media.test"),
        )
        .await
        .unwrap();
    client
        .register_pending_media_retry_persisted(
            document_key.clone(),
            wa_core::PendingMediaRetry::new(document_media, wa_core::MediaKind::Document)
                .with_fallback_host("media.test"),
        )
        .await
        .unwrap();

    let video_notification = wa_proto::proto::MediaRetryNotification {
        stanza_id: Some(video_key.id.clone()),
        direct_path: Some("/stored-video/new".to_owned()),
        result: Some(wa_proto::proto::media_retry_notification::ResultType::Success as i32),
        message_secret: None,
    };
    let video_payload = wa_crypto::encrypt_media_retry_notification_with_iv(
        &video_notification,
        &video_media_key,
        &video_key.id,
        &[12u8; 12],
    )
    .unwrap();
    let video_retry = wa_core::MediaRetryEvent::new(video_key.clone(), false)
        .with_encrypted_payload(video_payload.ciphertext, video_payload.iv);
    let document_notification = wa_proto::proto::MediaRetryNotification {
        stanza_id: Some(document_key.id.clone()),
        direct_path: Some("/stored-document/new".to_owned()),
        result: Some(wa_proto::proto::media_retry_notification::ResultType::Success as i32),
        message_secret: None,
    };
    let document_payload = wa_crypto::encrypt_media_retry_notification_with_iv(
        &document_notification,
        &document_media_key,
        &document_key.id,
        &[13u8; 12],
    )
    .unwrap();
    let document_retry = wa_core::MediaRetryEvent::new(document_key.clone(), false)
        .with_encrypted_payload(document_payload.ciphertext, document_payload.iv);
    persist_receive_events(
        &store,
        &[Event::MediaRetry(vec![
            video_retry.clone(),
            document_retry.clone(),
        ])],
    )
    .await
    .unwrap();

    let video_pending_store_key = wa_core::pending_media_retry_store_key(&video_key);
    let document_pending_store_key = wa_core::pending_media_retry_store_key(&document_key);
    let video_retry_store_key = wa_core::media_retry_event_store_key(&video_retry);
    let document_retry_store_key = wa_core::media_retry_event_store_key(&document_retry);
    let restored_client = Client::builder(store.clone()).connect().await.unwrap();
    let transport = ClientMediaUploadTransport::default();
    transport.downloads.lock().unwrap().insert(
        "https://media.test/stored-video/new".to_owned(),
        encrypted_video.ciphertext_with_mac.clone(),
    );
    transport.downloads.lock().unwrap().insert(
        "https://media.test/stored-document/new".to_owned(),
        encrypted_document.ciphertext_with_mac.clone(),
    );
    let transfer = wa_core::MediaTransfer::new(transport);

    let outcome = restored_client
        .handle_stored_media_retry_events(&transfer)
        .await
        .unwrap();

    assert_eq!(outcome.downloads.len(), 2);
    let mut plaintexts = outcome
        .downloads
        .iter()
        .map(|download| download.plaintext.as_slice())
        .collect::<Vec<_>>();
    plaintexts.sort_unstable();
    assert_eq!(
        plaintexts,
        vec![
            b"stored retried document media".as_slice(),
            b"stored retried video media".as_slice(),
        ]
    );
    assert!(outcome.errors.is_empty());
    assert_eq!(outcome.ignored_without_pending, 0);
    assert!(
        store
            .get(KeyNamespace::PendingMediaRetry, &video_pending_store_key)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .get(KeyNamespace::PendingMediaRetry, &document_pending_store_key)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .get(KeyNamespace::MediaRetryEvent, &video_retry_store_key)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .get(KeyNamespace::MediaRetryEvent, &document_retry_store_key)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        restored_client
            .media_retry_coordinator()
            .pending(&video_key)
            .unwrap()
            .is_none()
    );
    assert!(
        restored_client
            .media_retry_coordinator()
            .pending(&document_key)
            .unwrap()
            .is_none()
    );
}

#[cfg(all(feature = "sqlite-store", feature = "noise"))]
#[tokio::test]
async fn sqlite_stored_media_retry_events_replay_after_reopen_and_retry_update() {
    let dir = test_client_sqlite_path("media-retry-replay");
    let db_path = dir.join("session.db");
    let video_key = wa_core::MessageEventKey::new("123@s.whatsapp.net", "sqlite-video", None);
    let document_key = wa_core::MessageEventKey::new("123@s.whatsapp.net", "sqlite-document", None);
    let video_media_key = [17u8; 32];
    let document_media_key = [18u8; 32];
    let encrypted_video = wa_crypto::encrypt_media_bytes_with_key(
        b"sqlite replay video media",
        wa_core::MediaKind::Video,
        &video_media_key,
    )
    .unwrap();
    let encrypted_document = wa_crypto::encrypt_media_bytes_with_key(
        b"sqlite replay document media",
        wa_core::MediaKind::Document,
        &document_media_key,
    )
    .unwrap();
    let video_pending_store_key = wa_core::pending_media_retry_store_key(&video_key);
    let document_pending_store_key = wa_core::pending_media_retry_store_key(&document_key);

    let video_retry = {
        let store = wa_store::SqliteAuthStore::open(&db_path).await.unwrap();
        let client = Client::builder(store.clone()).connect().await.unwrap();
        let video_media = wa_core::uploaded_media_from_encrypted(
            &encrypted_video,
            wa_core::UploadedMediaLocation::new().with_direct_path("/sqlite-video/old"),
        )
        .unwrap();
        let document_media = wa_core::uploaded_media_from_encrypted(
            &encrypted_document,
            wa_core::UploadedMediaLocation::new().with_direct_path("/sqlite-document/old"),
        )
        .unwrap();
        client
            .register_pending_media_retry_persisted(
                video_key.clone(),
                wa_core::PendingMediaRetry::new(video_media, wa_core::MediaKind::Video)
                    .with_fallback_host("media.test"),
            )
            .await
            .unwrap();
        client
            .register_pending_media_retry_persisted(
                document_key.clone(),
                wa_core::PendingMediaRetry::new(document_media, wa_core::MediaKind::Document)
                    .with_fallback_host("media.test"),
            )
            .await
            .unwrap();

        let video_notification = wa_proto::proto::MediaRetryNotification {
            stanza_id: Some(video_key.id.clone()),
            direct_path: Some("/sqlite-video/new".to_owned()),
            result: Some(wa_proto::proto::media_retry_notification::ResultType::Success as i32),
            message_secret: None,
        };
        let video_payload = wa_crypto::encrypt_media_retry_notification_with_iv(
            &video_notification,
            &video_media_key,
            &video_key.id,
            &[14u8; 12],
        )
        .unwrap();
        let video_retry = wa_core::MediaRetryEvent::new(video_key.clone(), false)
            .with_encrypted_payload(video_payload.ciphertext, video_payload.iv);
        let failed_document_retry = wa_core::MediaRetryEvent::new(document_key.clone(), false)
            .with_error(2, Some("retry failed".to_owned()), 404);
        persist_receive_events(
            &store,
            &[Event::MediaRetry(vec![
                video_retry.clone(),
                failed_document_retry,
            ])],
        )
        .await
        .unwrap();
        video_retry
    };
    let video_retry_store_key = wa_core::media_retry_event_store_key(&video_retry);
    let document_retry_store_key = wa_core::media_retry_event_store_key(
        &wa_core::MediaRetryEvent::new(document_key.clone(), false),
    );

    let replay_store = wa_store::SqliteAuthStore::open(&db_path).await.unwrap();
    let replay_client = Client::builder(replay_store.clone())
        .connect()
        .await
        .unwrap();
    let transport = ClientMediaUploadTransport::default();
    transport.downloads.lock().unwrap().insert(
        "https://media.test/sqlite-video/new".to_owned(),
        encrypted_video.ciphertext_with_mac.clone(),
    );
    let transfer = wa_core::MediaTransfer::new(transport);

    let first_outcome = replay_client
        .handle_stored_media_retry_events(&transfer)
        .await
        .unwrap();

    assert_eq!(first_outcome.downloads.len(), 1);
    assert_eq!(
        first_outcome.downloads[0].plaintext,
        b"sqlite replay video media"
    );
    assert_eq!(first_outcome.errors.len(), 1);
    assert_eq!(first_outcome.errors[0].key, document_key);
    assert_eq!(first_outcome.ignored_without_pending, 0);
    assert!(
        replay_store
            .get(KeyNamespace::PendingMediaRetry, &video_pending_store_key)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        replay_store
            .get(KeyNamespace::MediaRetryEvent, &video_retry_store_key)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        replay_store
            .get(KeyNamespace::PendingMediaRetry, &document_pending_store_key)
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        replay_store
            .get(KeyNamespace::MediaRetryEvent, &document_retry_store_key)
            .await
            .unwrap()
            .is_some()
    );
    drop(replay_client);
    drop(replay_store);

    let document_success_retry = {
        let store = wa_store::SqliteAuthStore::open(&db_path).await.unwrap();
        let document_notification = wa_proto::proto::MediaRetryNotification {
            stanza_id: Some(document_key.id.clone()),
            direct_path: Some("/sqlite-document/new".to_owned()),
            result: Some(wa_proto::proto::media_retry_notification::ResultType::Success as i32),
            message_secret: None,
        };
        let document_payload = wa_crypto::encrypt_media_retry_notification_with_iv(
            &document_notification,
            &document_media_key,
            &document_key.id,
            &[15u8; 12],
        )
        .unwrap();
        let document_success_retry = wa_core::MediaRetryEvent::new(document_key.clone(), false)
            .with_encrypted_payload(document_payload.ciphertext, document_payload.iv);
        persist_receive_events(
            &store,
            &[Event::MediaRetry(vec![document_success_retry.clone()])],
        )
        .await
        .unwrap();
        document_success_retry
    };
    let document_success_store_key = wa_core::media_retry_event_store_key(&document_success_retry);
    assert_eq!(document_retry_store_key, document_success_store_key);

    let final_store = wa_store::SqliteAuthStore::open(&db_path).await.unwrap();
    let final_client = Client::builder(final_store.clone())
        .connect()
        .await
        .unwrap();
    let transport = ClientMediaUploadTransport::default();
    transport.downloads.lock().unwrap().insert(
        "https://media.test/sqlite-document/new".to_owned(),
        encrypted_document.ciphertext_with_mac.clone(),
    );
    let transfer = wa_core::MediaTransfer::new(transport);

    let second_outcome = final_client
        .handle_stored_media_retry_events(&transfer)
        .await
        .unwrap();

    assert_eq!(second_outcome.downloads.len(), 1);
    assert_eq!(
        second_outcome.downloads[0].plaintext,
        b"sqlite replay document media"
    );
    assert!(second_outcome.errors.is_empty());
    assert_eq!(second_outcome.ignored_without_pending, 0);
    assert!(
        final_store
            .get(KeyNamespace::PendingMediaRetry, &document_pending_store_key)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        final_store
            .get(KeyNamespace::MediaRetryEvent, &document_success_store_key)
            .await
            .unwrap()
            .is_none()
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(all(feature = "sqlite-store", feature = "noise"))]
#[tokio::test]
async fn sqlite_stored_media_retry_events_retain_success_response_after_download_failure() {
    let dir = test_client_sqlite_path("media-retry-download-failure");
    let db_path = dir.join("session.db");
    let key =
        wa_core::MessageEventKey::new("123@s.whatsapp.net", "sqlite-transient-download", None);
    let media_key = [22u8; 32];
    let encrypted = wa_crypto::encrypt_media_bytes_with_key(
        b"sqlite transient retry media",
        wa_core::MediaKind::Image,
        &media_key,
    )
    .unwrap();
    let pending_store_key = wa_core::pending_media_retry_store_key(&key);

    let retry = {
        let store = wa_store::SqliteAuthStore::open(&db_path).await.unwrap();
        let client = Client::builder(store.clone()).connect().await.unwrap();
        let media = wa_core::uploaded_media_from_encrypted(
            &encrypted,
            wa_core::UploadedMediaLocation::new().with_direct_path("/sqlite-transient/old"),
        )
        .unwrap();
        client
            .register_pending_media_retry_persisted(
                key.clone(),
                wa_core::PendingMediaRetry::new(media, wa_core::MediaKind::Image)
                    .with_fallback_host("media.test"),
            )
            .await
            .unwrap();

        let notification = wa_proto::proto::MediaRetryNotification {
            stanza_id: Some(key.id.clone()),
            direct_path: Some("/sqlite-transient/new".to_owned()),
            result: Some(wa_proto::proto::media_retry_notification::ResultType::Success as i32),
            message_secret: None,
        };
        let payload = wa_crypto::encrypt_media_retry_notification_with_iv(
            &notification,
            &media_key,
            &key.id,
            &[19u8; 12],
        )
        .unwrap();
        let retry = wa_core::MediaRetryEvent::new(key.clone(), false)
            .with_encrypted_payload(payload.ciphertext, payload.iv);
        persist_receive_events(&store, &[Event::MediaRetry(vec![retry.clone()])])
            .await
            .unwrap();
        retry
    };
    let retry_store_key = wa_core::media_retry_event_store_key(&retry);

    let replay_store = wa_store::SqliteAuthStore::open(&db_path).await.unwrap();
    let replay_client = Client::builder(replay_store.clone())
        .connect()
        .await
        .unwrap();
    let missing_transport = ClientMediaUploadTransport::default();
    let transfer = wa_core::MediaTransfer::new(missing_transport);

    let first_outcome = replay_client
        .handle_stored_media_retry_events(&transfer)
        .await
        .unwrap();

    assert!(first_outcome.downloads.is_empty());
    assert_eq!(first_outcome.errors.len(), 1);
    assert_eq!(first_outcome.errors[0].key, key);
    assert!(
        first_outcome.errors[0]
            .reason
            .contains("missing media file: https://media.test/sqlite-transient/new")
    );
    assert_eq!(first_outcome.ignored_without_pending, 0);
    assert_eq!(first_outcome.malformed_stored_records, 0);
    assert!(
        replay_store
            .get(KeyNamespace::PendingMediaRetry, &pending_store_key)
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        replay_store
            .get(KeyNamespace::MediaRetryEvent, &retry_store_key)
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        replay_client
            .media_retry_coordinator()
            .pending(&key)
            .unwrap()
            .is_some()
    );
    drop(replay_client);
    drop(replay_store);

    let final_store = wa_store::SqliteAuthStore::open(&db_path).await.unwrap();
    let final_client = Client::builder(final_store.clone())
        .connect()
        .await
        .unwrap();
    let transport = ClientMediaUploadTransport::default();
    transport.downloads.lock().unwrap().insert(
        "https://media.test/sqlite-transient/new".to_owned(),
        encrypted.ciphertext_with_mac.clone(),
    );
    let transfer = wa_core::MediaTransfer::new(transport);

    let second_outcome = final_client
        .handle_stored_media_retry_events(&transfer)
        .await
        .unwrap();

    assert_eq!(second_outcome.downloads.len(), 1);
    assert_eq!(
        second_outcome.downloads[0].plaintext,
        b"sqlite transient retry media"
    );
    assert!(second_outcome.errors.is_empty());
    assert_eq!(second_outcome.ignored_without_pending, 0);
    assert_eq!(second_outcome.malformed_stored_records, 0);
    assert!(
        final_store
            .get(KeyNamespace::PendingMediaRetry, &pending_store_key)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        final_store
            .get(KeyNamespace::MediaRetryEvent, &retry_store_key)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        final_client
            .media_retry_coordinator()
            .pending(&key)
            .unwrap()
            .is_none()
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(all(feature = "sqlite-store", feature = "noise"))]
#[tokio::test]
async fn sqlite_stored_media_retry_events_replay_paginates_after_reopen() {
    let dir = test_client_sqlite_path("media-retry-pagination");
    let db_path = dir.join("session.db");
    let total_retries = MEDIA_RETRY_EVENT_STORE_PAGE_SIZE + 3;
    let media_key = [19u8; 32];
    let encrypted = wa_crypto::encrypt_media_bytes_with_key(
        b"sqlite paged retry media",
        wa_core::MediaKind::Document,
        &media_key,
    )
    .unwrap();
    let media = wa_core::uploaded_media_from_encrypted(
        &encrypted,
        wa_core::UploadedMediaLocation::new().with_direct_path("/sqlite-paged/old"),
    )
    .unwrap();
    let mut pending_store_keys = Vec::with_capacity(total_retries);
    let mut retry_store_keys = Vec::with_capacity(total_retries);

    {
        let store = wa_store::SqliteAuthStore::open(&db_path).await.unwrap();
        let client = Client::builder(store.clone()).connect().await.unwrap();
        let mut retries = Vec::with_capacity(total_retries);
        for index in 0..total_retries {
            let message_id = format!("sqlite-paged-{index:04}");
            let key = wa_core::MessageEventKey::new("123@s.whatsapp.net", message_id, None);
            client
                .register_pending_media_retry_persisted(
                    key.clone(),
                    wa_core::PendingMediaRetry::new(media.clone(), wa_core::MediaKind::Document)
                        .with_fallback_host("media.test"),
                )
                .await
                .unwrap();

            let notification = wa_proto::proto::MediaRetryNotification {
                stanza_id: Some(key.id.clone()),
                direct_path: Some("/sqlite-paged/new".to_owned()),
                result: Some(wa_proto::proto::media_retry_notification::ResultType::Success as i32),
                message_secret: None,
            };
            let mut iv = [0u8; 12];
            iv[8..].copy_from_slice(&(index as u32).to_be_bytes());
            let payload = wa_crypto::encrypt_media_retry_notification_with_iv(
                &notification,
                &media_key,
                &key.id,
                &iv,
            )
            .unwrap();
            let retry = wa_core::MediaRetryEvent::new(key.clone(), false)
                .with_encrypted_payload(payload.ciphertext, payload.iv);
            pending_store_keys.push(wa_core::pending_media_retry_store_key(&key));
            retry_store_keys.push(wa_core::media_retry_event_store_key(&retry));
            retries.push(retry);
        }
        persist_receive_events(&store, &[Event::MediaRetry(retries)])
            .await
            .unwrap();
    }

    let replay_store = wa_store::SqliteAuthStore::open(&db_path).await.unwrap();
    let first_page = replay_store
        .list_keys(
            KeyNamespace::MediaRetryEvent,
            None,
            MEDIA_RETRY_EVENT_STORE_PAGE_SIZE,
        )
        .await
        .unwrap();
    assert_eq!(first_page.len(), MEDIA_RETRY_EVENT_STORE_PAGE_SIZE);
    let second_page = replay_store
        .list_keys(
            KeyNamespace::MediaRetryEvent,
            first_page.last().map(String::as_str),
            MEDIA_RETRY_EVENT_STORE_PAGE_SIZE,
        )
        .await
        .unwrap();
    assert_eq!(second_page.len(), 3);

    let replay_client = Client::builder(replay_store.clone())
        .connect()
        .await
        .unwrap();
    let transport = ClientMediaUploadTransport::default();
    transport.downloads.lock().unwrap().insert(
        "https://media.test/sqlite-paged/new".to_owned(),
        encrypted.ciphertext_with_mac.clone(),
    );
    let transfer = wa_core::MediaTransfer::new(transport);

    let outcome = replay_client
        .handle_stored_media_retry_events(&transfer)
        .await
        .unwrap();

    assert_eq!(outcome.downloads.len(), total_retries);
    assert!(outcome.errors.is_empty());
    assert_eq!(outcome.ignored_without_pending, 0);
    assert!(
        outcome
            .downloads
            .iter()
            .all(|download| { download.plaintext.as_slice() == b"sqlite paged retry media" })
    );
    assert!(
        replay_store
            .list_keys(KeyNamespace::MediaRetryEvent, None, 1)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        replay_store
            .list_keys(KeyNamespace::PendingMediaRetry, None, 1)
            .await
            .unwrap()
            .is_empty()
    );
    for store_key in retry_store_keys {
        assert!(
            replay_store
                .get(KeyNamespace::MediaRetryEvent, &store_key)
                .await
                .unwrap()
                .is_none()
        );
    }
    for store_key in pending_store_keys {
        assert!(
            replay_store
                .get(KeyNamespace::PendingMediaRetry, &store_key)
                .await
                .unwrap()
                .is_none()
        );
    }

    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(all(feature = "sqlite-store", feature = "noise"))]
#[tokio::test]
async fn sqlite_stored_media_retry_events_delete_malformed_record_and_continue() {
    let dir = test_client_sqlite_path("media-retry-corrupt-event");
    let db_path = dir.join("session.db");
    let key = wa_core::MessageEventKey::new("123@s.whatsapp.net", "sqlite-corrupt-valid", None);
    let media_key = [20u8; 32];
    let encrypted = wa_crypto::encrypt_media_bytes_with_key(
        b"sqlite retry after corrupt row",
        wa_core::MediaKind::Image,
        &media_key,
    )
    .unwrap();
    let media = wa_core::uploaded_media_from_encrypted(
        &encrypted,
        wa_core::UploadedMediaLocation::new().with_direct_path("/sqlite-corrupt/old"),
    )
    .unwrap();

    let retry = {
        let store = wa_store::SqliteAuthStore::open(&db_path).await.unwrap();
        let client = Client::builder(store.clone()).connect().await.unwrap();
        client
            .register_pending_media_retry_persisted(
                key.clone(),
                wa_core::PendingMediaRetry::new(media, wa_core::MediaKind::Image)
                    .with_fallback_host("media.test"),
            )
            .await
            .unwrap();
        let notification = wa_proto::proto::MediaRetryNotification {
            stanza_id: Some(key.id.clone()),
            direct_path: Some("/sqlite-corrupt/new".to_owned()),
            result: Some(wa_proto::proto::media_retry_notification::ResultType::Success as i32),
            message_secret: None,
        };
        let payload = wa_crypto::encrypt_media_retry_notification_with_iv(
            &notification,
            &media_key,
            &key.id,
            &[16u8; 12],
        )
        .unwrap();
        let retry = wa_core::MediaRetryEvent::new(key.clone(), false)
            .with_encrypted_payload(payload.ciphertext, payload.iv);
        persist_receive_events(&store, &[Event::MediaRetry(vec![retry.clone()])])
            .await
            .unwrap();
        store
            .set(
                KeyNamespace::MediaRetryEvent,
                "123@s.whatsapp.net|sqlite-corrupt-bad",
                b"corrupt media retry row",
            )
            .await
            .unwrap();
        retry
    };

    let pending_store_key = wa_core::pending_media_retry_store_key(&key);
    let retry_store_key = wa_core::media_retry_event_store_key(&retry);
    let replay_store = wa_store::SqliteAuthStore::open(&db_path).await.unwrap();
    assert!(
        replay_store
            .get(
                KeyNamespace::MediaRetryEvent,
                "123@s.whatsapp.net|sqlite-corrupt-bad"
            )
            .await
            .unwrap()
            .is_some()
    );
    let replay_client = Client::builder(replay_store.clone())
        .connect()
        .await
        .unwrap();
    let transport = ClientMediaUploadTransport::default();
    transport.downloads.lock().unwrap().insert(
        "https://media.test/sqlite-corrupt/new".to_owned(),
        encrypted.ciphertext_with_mac.clone(),
    );
    let transfer = wa_core::MediaTransfer::new(transport);

    let outcome = replay_client
        .handle_stored_media_retry_events(&transfer)
        .await
        .unwrap();

    assert_eq!(outcome.downloads.len(), 1);
    assert_eq!(
        outcome.downloads[0].plaintext,
        b"sqlite retry after corrupt row"
    );
    assert!(outcome.errors.is_empty());
    assert_eq!(outcome.ignored_without_pending, 0);
    assert_eq!(outcome.malformed_stored_records, 1);
    assert!(
        replay_store
            .get(KeyNamespace::PendingMediaRetry, &pending_store_key)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        replay_store
            .get(KeyNamespace::MediaRetryEvent, &retry_store_key)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        replay_store
            .get(
                KeyNamespace::MediaRetryEvent,
                "123@s.whatsapp.net|sqlite-corrupt-bad"
            )
            .await
            .unwrap()
            .is_none()
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(all(feature = "sqlite-store", feature = "noise"))]
#[tokio::test]
async fn sqlite_stored_media_retry_events_delete_malformed_pending_and_continue() {
    let dir = test_client_sqlite_path("media-retry-corrupt-pending");
    let db_path = dir.join("session.db");
    let valid_key =
        wa_core::MessageEventKey::new("123@s.whatsapp.net", "sqlite-corrupt-pending-valid", None);
    let malformed_key =
        wa_core::MessageEventKey::new("123@s.whatsapp.net", "sqlite-corrupt-pending-bad", None);
    let media_key = [21u8; 32];
    let encrypted = wa_crypto::encrypt_media_bytes_with_key(
        b"sqlite retry with corrupt pending",
        wa_core::MediaKind::Image,
        &media_key,
    )
    .unwrap();
    let media = wa_core::uploaded_media_from_encrypted(
        &encrypted,
        wa_core::UploadedMediaLocation::new().with_direct_path("/sqlite-corrupt-pending/old"),
    )
    .unwrap();

    let (valid_retry, malformed_retry) = {
        let store = wa_store::SqliteAuthStore::open(&db_path).await.unwrap();
        let client = Client::builder(store.clone()).connect().await.unwrap();
        client
            .register_pending_media_retry_persisted(
                valid_key.clone(),
                wa_core::PendingMediaRetry::new(media, wa_core::MediaKind::Image)
                    .with_fallback_host("media.test"),
            )
            .await
            .unwrap();

        let valid_notification = wa_proto::proto::MediaRetryNotification {
            stanza_id: Some(valid_key.id.clone()),
            direct_path: Some("/sqlite-corrupt-pending/new".to_owned()),
            result: Some(wa_proto::proto::media_retry_notification::ResultType::Success as i32),
            message_secret: None,
        };
        let valid_payload = wa_crypto::encrypt_media_retry_notification_with_iv(
            &valid_notification,
            &media_key,
            &valid_key.id,
            &[17u8; 12],
        )
        .unwrap();
        let valid_retry = wa_core::MediaRetryEvent::new(valid_key.clone(), false)
            .with_encrypted_payload(valid_payload.ciphertext, valid_payload.iv);

        let malformed_notification = wa_proto::proto::MediaRetryNotification {
            stanza_id: Some(malformed_key.id.clone()),
            direct_path: Some("/sqlite-corrupt-pending/later".to_owned()),
            result: Some(wa_proto::proto::media_retry_notification::ResultType::Success as i32),
            message_secret: None,
        };
        let malformed_payload = wa_crypto::encrypt_media_retry_notification_with_iv(
            &malformed_notification,
            &media_key,
            &malformed_key.id,
            &[18u8; 12],
        )
        .unwrap();
        let malformed_retry = wa_core::MediaRetryEvent::new(malformed_key.clone(), false)
            .with_encrypted_payload(malformed_payload.ciphertext, malformed_payload.iv);
        persist_receive_events(
            &store,
            &[Event::MediaRetry(vec![
                valid_retry.clone(),
                malformed_retry.clone(),
            ])],
        )
        .await
        .unwrap();
        store
            .set(
                KeyNamespace::PendingMediaRetry,
                &wa_core::pending_media_retry_store_key(&malformed_key),
                b"corrupt pending media retry row",
            )
            .await
            .unwrap();
        (valid_retry, malformed_retry)
    };

    let valid_pending_store_key = wa_core::pending_media_retry_store_key(&valid_key);
    let malformed_pending_store_key = wa_core::pending_media_retry_store_key(&malformed_key);
    let valid_retry_store_key = wa_core::media_retry_event_store_key(&valid_retry);
    let malformed_retry_store_key = wa_core::media_retry_event_store_key(&malformed_retry);
    let replay_store = wa_store::SqliteAuthStore::open(&db_path).await.unwrap();
    assert!(
        replay_store
            .get(
                KeyNamespace::PendingMediaRetry,
                &malformed_pending_store_key
            )
            .await
            .unwrap()
            .is_some()
    );
    let replay_client = Client::builder(replay_store.clone())
        .connect()
        .await
        .unwrap();
    let transport = ClientMediaUploadTransport::default();
    transport.downloads.lock().unwrap().insert(
        "https://media.test/sqlite-corrupt-pending/new".to_owned(),
        encrypted.ciphertext_with_mac.clone(),
    );
    let transfer = wa_core::MediaTransfer::new(transport);

    let outcome = replay_client
        .handle_stored_media_retry_events(&transfer)
        .await
        .unwrap();

    assert_eq!(outcome.downloads.len(), 1);
    assert_eq!(
        outcome.downloads[0].plaintext,
        b"sqlite retry with corrupt pending"
    );
    assert!(outcome.errors.is_empty());
    assert_eq!(outcome.ignored_without_pending, 1);
    assert_eq!(outcome.malformed_stored_records, 1);
    assert!(
        replay_store
            .get(KeyNamespace::PendingMediaRetry, &valid_pending_store_key)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        replay_store
            .get(
                KeyNamespace::PendingMediaRetry,
                &malformed_pending_store_key
            )
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        replay_store
            .get(KeyNamespace::MediaRetryEvent, &valid_retry_store_key)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        replay_store
            .get(KeyNamespace::MediaRetryEvent, &malformed_retry_store_key)
            .await
            .unwrap()
            .is_some()
    );

    let _ = std::fs::remove_dir_all(&dir);
}
